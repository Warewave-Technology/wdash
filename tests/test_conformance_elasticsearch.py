"""
The Elasticsearch adapters against the shared conformance suite.

Elasticsearch is where every one of those checks was learned, so it had better
pass them. Running the reference adapter through the suite is also what keeps
the suite honest: a check that the known-good adapter cannot satisfy is a bug
in the check, not a finding.
"""

import inspect
import json
import os
import sys
import unittest

from elasticsearch import Elasticsearch as RealElasticsearch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conformance import (  # noqa: E402
    Harness, LogSourceConformance, TraceSourceConformance,
)
from tests.test_otel_shapes import COLLECTOR_SPAN_MAPPING, collector_span  # noqa: E402
from wdash.hub.adapters import (  # noqa: E402
    ElasticsearchLogSource, ElasticsearchTraceSource,
)

TIMESTAMP = "2026-08-04T11:30:00.000Z"

#: What the installed client will actually accept. Read from the library so
#: the fake cannot drift into accepting something the real one refuses.
_SEARCH_PARAMETERS = frozenset(
    inspect.signature(RealElasticsearch.search).parameters) - {"self"}


def _value_at(source, field):
    """A document's value for a dotted field name, literal keys included.

    `resource.attributes` is a nested object whose KEY is the dotted string
    `service.name`, so walking every dot blindly finds nothing where the
    document plainly has something.
    """
    if not isinstance(source, dict) or not field:
        return None
    if field in source:
        return source[field]
    head, _, rest = field.partition(".")
    return _value_at(source.get(head), rest) if rest else None


class FakeElasticsearch(Harness):
    """Records every request and can be told to fail the next one."""

    INDICES = ["app-logs-000001", "infra-logs-000001"]
    TRACE_INDICES = ["otel-traces-000001"]

    def __init__(self, trace_mode=False):
        self._requests = []
        self._fail_next = False
        self.trace_mode = trace_mode

    # --- harness contract ---

    def requests(self):
        return list(self._requests)

    def reset(self):
        self._requests = []

    def containers(self):
        return self.TRACE_INDICES if self.trace_mode else self.INDICES

    def fail_next(self):
        self._fail_next = True

    def mentions(self, request, text):
        return text in json.dumps(request, default=str)

    # --- the bits the adapter calls ---

    def ping(self):
        return True

    @property
    def cat(self):
        outer = self

        class Cat:
            def indices(self, **kwargs):
                return [{"index": name, "creation.date": str(100 + index)}
                        for index, name in enumerate(outer.containers())]
        return Cat()

    @property
    def indices(self):
        outer = self

        class Indices:
            def get_mapping(self, index=None, **kwargs):
                properties = (COLLECTOR_SPAN_MAPPING
                              if outer.trace_mode else
                              {"level": {"type": "keyword"},
                               "service": {"type": "keyword"},
                               "message": {"type": "text"}})
                return {name: {"mappings": {"properties": properties}}
                        for name in (index or "").split(",") if name}
        return Indices()

    def _guard(self):
        if self._fail_next:
            self._fail_next = False
            raise RuntimeError("simulated backend failure")

    #: Client keyword arguments that are NOT part of the request body, and
    #: the one whose name differs from the body field it becomes.
    OPTIONS = ("timeout", "request_cache", "error_trace", "filter_path",
               "human", "pretty", "routing", "preference")
    KEYWORD_TO_BODY = {"source": "_source"}

    def search(self, index=None, **kwargs):
        """Mimics elasticsearch-py 8.x: body fields arrive as KEYWORDS.

        Rebuilt into a body here so the recorded request keeps the shape the
        assertions are written against — but rebuilt from what the real
        client would accept, not from a `body=` the real client no longer
        takes. A fake that accepts an argument the real one rejects turns
        every test using it into a test of the fake.
        """
        assert "body" not in kwargs, (
            "elasticsearch-py deprecated body=; pass the fields as keywords")
        # Every name checked against the REAL client. Without this the fake
        # accepts `_source=`, which elasticsearch-py rejects with a
        # TypeError — and the adapter's translation table could be deleted
        # with every test still green.
        unknown = sorted(set(kwargs) - _SEARCH_PARAMETERS)
        assert not unknown, (
            f"elasticsearch-py's search() has no parameter(s) {unknown}. "
            f"A body field whose name differs from the keyword has to be "
            f"translated in the adapter.")
        body = {self.KEYWORD_TO_BODY.get(key, key): value
                for key, value in kwargs.items() if key not in self.OPTIONS}
        self._requests.append({"index": index, "body": body})
        self._guard()
        return self._answer(body)

    def msearch(self, searches=None, **kwargs):
        payload = list(searches or [])
        self._requests.append({"msearch": payload})
        self._guard()
        return {"responses": [self._answer(payload[i + 1])
                              for i in range(0, len(payload), 2)]}

    def get(self, index=None, id=None, **kwargs):
        self._requests.append({"get": {"index": index, "id": id}})
        self._guard()
        raise Exception("not_found_exception")

    @staticmethod
    def _asks_for(body, text):
        return text in json.dumps(body, default=str)

    def _answer(self, body):
        # Behave like the backend: a query for something that is not there
        # returns nothing. A fake that answers every question with the same
        # row cannot tell "found" from "not found", which is exactly the
        # distinction the suite is checking.
        if self._asks_for(body, "no-such-trace-id"):
            return {"took": 1, "timed_out": False,
                    "hits": {"total": {"value": 0}, "hits": []},
                    "aggregations": {}}

        if self.trace_mode:
            hits = [{"_index": self.TRACE_INDICES[0], "_id": "s1",
                     "_source": {"@timestamp": TIMESTAMP,
                                 "trace_id": "trace-1", "span_id": "span-1",
                                 "name": "GET /checkout", "kind": "Server",
                                 "duration": 5_000_000,
                                 "status": {"code": "Ok"},
                                 "resource": {"attributes": {
                                     "service.name": "api-gateway"}}}}]
        else:
            hits = [{"_index": self.INDICES[0], "_id": "d1", "_score": None,
                     "sort": [1754305800000, 1],
                     "_source": {"@timestamp": TIMESTAMP, "level": "INFO",
                                 "message": "hello", "service": "api-gateway",
                                 "host": "node-1"}}]

        # Grouped by the field each aggregation NAMES, over the document
        # this fake holds. It used to answer every aggregation with one
        # hardcoded `api-gateway` bucket, so a terms on `level` came back as
        # a service and an adapter that sent the wrong field — or no field —
        # was indistinguishable from one that sent the right one. The comment
        # above says as much about hits and was true only of them.
        #
        # A field the document does not carry gets no buckets, which is what
        # the backend does: "not there" and "there, and this is it" are
        # different answers.
        aggregations = {
            name: {"buckets": [
                {"key": value, "doc_count": 3, "failed": {"doc_count": 0}}
                for value in [_value_at(hit["_source"],
                                        (node.get("terms") or {}).get("field"))
                              for hit in hits]
                if value]}
            for name, node in (body.get("aggs") or {}).items()
        }
        return {"took": 3, "timed_out": False,
                "hits": {"total": {"value": len(hits)}, "hits": hits},
                "aggregations": aggregations}


class ElasticsearchLogConformanceTest(LogSourceConformance, unittest.TestCase):
    def build(self):
        harness = FakeElasticsearch()
        return ElasticsearchLogSource(harness, name="es-logs"), harness


class ElasticsearchTraceConformanceTest(TraceSourceConformance, unittest.TestCase):
    def build(self):
        harness = FakeElasticsearch(trace_mode=True)
        return (ElasticsearchTraceSource(harness, name="es-traces",
                                         patterns=("*traces*",)),
                harness)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class HealthDetailTest(unittest.TestCase):
    """What a failed ping says about itself.

    `ping()` returns False for an unreachable cluster rather than raising, so
    a `health()` that returns a constant detail describes a failure with the
    word for success. The log line read

        WARNING health: elasticsearch-traces: ok

    which is the failure and the word "ok" on one line — and /health showed
    "unreachable" at the same moment. Whoever grepped the log first concluded
    the probe was wrong.
    """

    class _Client:
        def __init__(self, answer):
            self._answer = answer

        def ping(self):
            if isinstance(self._answer, Exception):
                raise self._answer
            return self._answer

    def _sources(self, answer):
        client = self._Client(answer)
        return (ElasticsearchLogSource(client, name="logs"),
                ElasticsearchTraceSource(client, name="traces"))

    def test_a_reachable_cluster_is_healthy(self):
        for source in self._sources(True):
            self.assertEqual(source.health(), (True, "ok"))

    def test_a_failed_ping_does_not_describe_itself_as_ok(self):
        """Both adapters. They are separate classes with separate copies of
        this method, so fixing one leaves the other saying "ok"."""
        for source in self._sources(False):
            healthy, detail = source.health()
            self.assertFalse(healthy)
            self.assertNotEqual(detail, "ok")
            self.assertIn("ping", detail.lower())

    def test_an_exception_still_carries_its_own_message(self):
        for source in self._sources(RuntimeError("no route to host")):
            healthy, detail = source.health()
            self.assertFalse(healthy)
            self.assertIn("no route to host", detail)


class RequestBodyTest(unittest.TestCase):
    """How the adapters hand a request to elasticsearch-py.

    `body=` is deprecated: the client warns on every call and a future major
    removes it. Fields go as keyword arguments instead — which is stricter,
    because the client validates every name.

    One of them is not called what the JSON body calls it. `_source` in the
    body is `source` in the signature, so an untranslated `**body` raises

        TypeError: search() got an unexpected keyword argument '_source'

    at the one call site that uses it: fetching the surrounding lines for a
    log record, which is the log-to-trace jump.
    """

    def test_source_is_translated_to_the_parameter_name(self):
        from wdash.hub.adapters.elasticsearch import _as_keywords
        keywords = _as_keywords({"query": {}, "_source": ["a", "b"], "size": 5})
        self.assertEqual(keywords, {"query": {}, "source": ["a", "b"], "size": 5})

    def test_everything_else_is_left_alone(self):
        """A translation table that rewrites more than it must is its own bug."""
        from wdash.hub.adapters.elasticsearch import _as_keywords
        body = {"query": {}, "sort": [], "size": 1, "track_total_hits": True,
                "aggs": {}, "search_after": [1]}
        self.assertEqual(_as_keywords(body), body)

    def test_every_translated_name_is_a_real_parameter(self):
        """The table is only useful if what it produces is accepted."""
        from wdash.hub.adapters.elasticsearch import _BODY_TO_KEYWORD
        for body_field, keyword in _BODY_TO_KEYWORD.items():
            self.assertIn(keyword, _SEARCH_PARAMETERS)
            self.assertNotIn(body_field, _SEARCH_PARAMETERS,
                             f"{body_field} needs no translation any more")

    def test_no_adapter_still_calls_the_deprecated_form(self):
        """Grepped rather than exercised: a call site reached by no test is
        exactly the one that would keep `body=` and only fail on the day the
        client drops it."""
        path = os.path.join(os.path.dirname(__file__), "..", "src", "wdash",
                            "hub", "adapters", "elasticsearch.py")
        with open(path) as handle:
            source = handle.read()
        offenders = [line.strip() for line in source.splitlines()
                     if "body=body" in line and not line.strip().startswith("#")]
        self.assertEqual(offenders, [])

    def test_the_client_is_only_talked_to_in_two_places(self):
        """`_search` and `_multi_search`. More would mean more than one
        translation table, and the second one is always the stale one."""
        path = os.path.join(os.path.dirname(__file__), "..", "src", "wdash",
                            "hub", "adapters", "elasticsearch.py")
        with open(path) as handle:
            lines = [l for l in handle if ".search(" in l and "msearch" not in l
                     and not l.strip().startswith("#")]
        direct = [l.strip() for l in lines if "_es.search(" in l or "es.search(" in l]
        self.assertEqual(len(direct), 1, direct)


# ---------------------------------------------------------------------------
# The trace source when part of the cluster cannot answer
# ---------------------------------------------------------------------------

from collections import Counter  # noqa: E402

from tests.support import ModelledES  # noqa: E402
from wdash.hub import Scope, TimeWindow  # noqa: E402
from wdash.hub.query import TraceQuery  # noqa: E402

OTEL, APM = "otel-traces-000001", "apm-traces-000001"

APM_MAPPING = {"trace": {"properties": {"id": {"type": "keyword"}}},
               "parent": {"properties": {"id": {"type": "keyword"}}},
               "processor": {"properties": {"event": {"type": "keyword"}}},
               "service": {"properties": {"name": {"type": "keyword"}}},
               "transaction": {"properties": {"id": {"type": "keyword"}}}}


def _apm_transaction(trace, span_id, service, parent=None, seconds_ago=60):
    import datetime as dt
    stamp = (dt.datetime.now(dt.timezone.utc)
             - dt.timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    doc = {"_id": span_id, "@timestamp": stamp, "trace": {"id": trace},
           "service": {"name": service}, "event": {"outcome": "success"},
           "processor": {"event": "transaction"},
           "transaction": {"id": span_id, "name": f"{service} op",
                           "duration": {"us": 1000}}}
    if parent:
        doc["parent"] = {"id": parent}
    return doc


class PartlyBrokenCluster(ModelledES):
    """A cluster in which some indices refuse searches and a mapping can
    fail to be read, the rest answering what they are asked."""

    def __init__(self, indices, refusing=(), mapping_failures=None):
        super().__init__(indices)
        self.refusing = set(refusing)
        self.mapping_failures = dict(mapping_failures or {})
        self.mapping_calls = Counter()

    @property
    def indices(self):
        outer, real = self, ModelledES.indices.fget(self)

        class Indices:
            def get_mapping(self, index=None, **kwargs):
                outer.mapping_calls[index] += 1
                if outer.mapping_failures.get(index, 0) > 0:
                    outer.mapping_failures[index] -= 1
                    raise ConnectionError(f"the mapping request timed out")
                return real.get_mapping(index=index, **kwargs)
        return Indices()

    def search(self, index=None, **kwargs):
        if set(str(index).split(",")) & self.refusing:
            raise ConnectionError(f"{index}: connection reset")
        return super().search(index=index, **kwargs)

    def msearch(self, searches=None, **kwargs):
        responses = []
        for header, body in zip(searches[0::2], searches[1::2]):
            if set(header["index"].split(",")) & self.refusing:
                responses.append({"status": 503, "error": {
                    "type": "search_phase_execution_exception",
                    "reason": "all shards failed"}})
            else:
                responses.append(self.search(index=header["index"], **body))
        return {"responses": responses}


def _cluster(**broken):
    """t1 in both schemas, t2 only in the APM copy."""
    return PartlyBrokenCluster({
        OTEL: (COLLECTOR_SPAN_MAPPING, [
            collector_span("t1", "gw", "api-gateway", seconds_ago=120),
            collector_span("t1", "pay", "payment-service", parent="gw",
                           seconds_ago=119)]),
        APM: (APM_MAPPING, [
            _apm_transaction("t1", "gw", "api-gateway", seconds_ago=120),
            _apm_transaction("t1", "pay", "payment-service", parent="gw",
                             seconds_ago=119),
            _apm_transaction("t2", "t2-gw", "api-gateway", seconds_ago=30)]),
    }, **broken)


class TraceSearchFailureTest(unittest.TestCase):
    """A schema group whose search failed was skipped without a word.

    Each group's request that failed came back as None and was passed over,
    so an index refusing searches read as an index with nothing in it: the
    list was shorter, the service counts lower, and a trace held only there
    was "not found". Measured through a proxy that forwards the lab
    cluster's catalogue and mappings and refuses every search: search [],
    services [], a trace link 404.
    """

    def setUp(self):
        self.window = TimeWindow.of("1h")
        self.scope = Scope.unrestricted()

    def _source(self, cluster):
        from wdash.hub.adapters import ElasticsearchTraceSource
        return ElasticsearchTraceSource(cluster, name="es")

    def test_a_refusing_index_beside_a_readable_one_is_named(self):
        source = self._source(_cluster(refusing={APM}))
        found = source.search(TraceQuery(window=self.window, limit=10), self.scope)
        self.assertEqual([row.trace_id for row in found], ["t1"])
        self.assertTrue(found.partial)
        self.assertEqual(len(found.warnings), 1)
        self.assertIn(APM, found.warnings[0])
        self.assertIn("all shards failed", found.warnings[0])

        services = source.services(self.window, self.scope)
        self.assertEqual({s.name for s in services}, {"api-gateway", "payment-service"})
        self.assertTrue(services.partial)
        self.assertIn(APM, services.warnings[0])

        trace = source.trace("t1", self.window, self.scope)
        self.assertEqual(len(trace.spans), 2)
        self.assertTrue(trace.partial)
        self.assertIn(APM, trace.warnings[0])

    def test_a_complete_answer_is_not_partial(self):
        source = self._source(_cluster())
        found = source.search(TraceQuery(window=self.window, limit=10), self.scope)
        self.assertEqual(sorted(row.trace_id for row in found), ["t1", "t2"])
        self.assertFalse(found.partial)
        self.assertFalse(source.services(self.window, self.scope).partial)
        trace = source.trace("t1", self.window, self.scope)
        self.assertFalse(trace.partial)
        self.assertEqual(trace.warnings, ())

    def test_a_trace_only_the_refusing_index_may_hold_is_not_called_missing(self):
        with self.assertRaises(RuntimeError) as caught:
            self._source(_cluster(refusing={APM})).trace("t2", self.window, self.scope)
        self.assertIn(APM, str(caught.exception))

    def test_a_trace_nobody_holds_is_none_when_everything_answered(self):
        self.assertIsNone(self._source(_cluster()).trace("nope", self.window,
                                                         self.scope))

    def test_every_index_refusing_raises(self):
        source = self._source(_cluster(refusing={OTEL, APM}))
        for call in (
                lambda: source.search(TraceQuery(window=self.window), self.scope),
                lambda: source.services(self.window, self.scope),
                lambda: source.trace("t1", self.window, self.scope)):
            with self.assertRaises(RuntimeError) as caught:
                call()
            self.assertIn("all shards failed", str(caught.exception))

    def test_a_single_request_s_failure_carries_its_reason(self):
        """One group goes as a plain search rather than a batch, and has its
        own path for failing."""
        from wdash.hub.adapters import ElasticsearchTraceSource
        cluster = _cluster(refusing={OTEL})
        source = ElasticsearchTraceSource(cluster, patterns=("otel-*",))
        with self.assertRaises(RuntimeError) as caught:
            source.search(TraceQuery(window=self.window), self.scope)
        self.assertIn("connection reset", str(caught.exception))


class MappingFailureTest(unittest.TestCase):
    """An index whose mapping could not be read once was gone for good.

    The failure was taken for "no recognisable schema", that None was
    cached, and the index dropped out of search, lookup and the service
    list for the life of the process, with nothing logged. Measured: a
    mapping request that failed once and then worked, three calls, the index
    never came back and the mapping was asked for once.
    """

    def setUp(self):
        self.window = TimeWindow.of("1h")
        self.scope = Scope.unrestricted()

    def _search(self, source):
        return source.search(TraceQuery(window=self.window, limit=10), self.scope)

    def test_a_mapping_that_failed_is_asked_for_again(self):
        from wdash.hub.adapters import ElasticsearchTraceSource
        cluster = _cluster(mapping_failures={OTEL: 1})
        source = ElasticsearchTraceSource(cluster, patterns=("otel-*",))
        with self.assertRaises(RuntimeError) as caught:
            self._search(source)
        self.assertIn(OTEL, str(caught.exception))
        self.assertIn("timed out", str(caught.exception))
        self.assertEqual([row.trace_id for row in self._search(source)], ["t1"])
        self.assertEqual(cluster.mapping_calls[OTEL], 2)

    def test_the_failure_is_logged_with_the_index_it_cost(self):
        from wdash.hub.adapters import ElasticsearchTraceSource
        source = ElasticsearchTraceSource(_cluster(mapping_failures={OTEL: 1}),
                                          patterns=("otel-*",))
        with self.assertLogs("wdash.hub.adapters.elasticsearch", "WARNING") as logged:
            with self.assertRaises(RuntimeError):
                self._search(source)
        self.assertTrue(any(OTEL in line and "timed out" in line
                            for line in logged.output), logged.output)

    def test_a_failed_mapping_beside_a_readable_index_is_named(self):
        from wdash.hub.adapters import ElasticsearchTraceSource
        source = ElasticsearchTraceSource(_cluster(mapping_failures={APM: 1}))
        found = self._search(source)
        self.assertEqual([row.trace_id for row in found], ["t1"])
        self.assertTrue(found.partial)
        self.assertIn(APM, found.warnings[0])
        self.assertIn("mapping", found.warnings[0])

    def test_an_index_that_is_no_trace_store_is_not_asked_on_every_request(self):
        """Every other request would otherwise ask for its mapping again."""
        from wdash.hub.adapters import ElasticsearchTraceSource
        cluster = _cluster()
        cluster._indices["notes-traces-1"] = ({"message": {"type": "text"}}, [])
        source = ElasticsearchTraceSource(cluster)
        for _ in range(3):
            self.assertFalse(self._search(source).partial)
        self.assertEqual(cluster.mapping_calls["notes-traces-1"], 1)

    def test_an_index_left_out_is_said_to_be_left_out_once(self):
        """A pattern that reaches something other than spans is a
        configuration to fix, and was invisible: the index was skipped and
        nothing said so."""
        from wdash.hub.adapters import ElasticsearchTraceSource
        cluster = _cluster()
        cluster._indices["notes-traces-1"] = ({"message": {"type": "text"}}, [])
        source = ElasticsearchTraceSource(cluster)
        with self.assertLogs("wdash.hub.adapters.elasticsearch", "WARNING") as logged:
            self._search(source)
            self._search(source)
            # Asked again once the answer is stale, and still not repeated.
            source._UNRECOGNISED_TTL = 0
            self._search(source)
        self.assertEqual(cluster.mapping_calls["notes-traces-1"], 2)
        said = [line for line in logged.output if "notes-traces-1" in line]
        self.assertEqual(len(said), 1, logged.output)
        self.assertIn("left out", said[0])

    def test_an_index_listed_before_its_first_span_is_read_once_one_lands(self):
        from wdash.hub.adapters import ElasticsearchTraceSource
        cluster = PartlyBrokenCluster({OTEL: ({}, [])})
        source = ElasticsearchTraceSource(cluster)
        self.assertEqual(self._search(source), [])
        # The collector writes its first span; the index now has a mapping.
        cluster._indices[OTEL] = (COLLECTOR_SPAN_MAPPING, [
            {"_index": OTEL, "_id": "gw",
             "_source": {k: v for k, v in collector_span(
                 "t1", "gw", "api-gateway", seconds_ago=5).items() if k != "_id"}}])
        source._UNRECOGNISED_TTL = 0
        self.assertEqual([row.trace_id for row in self._search(source)], ["t1"])
