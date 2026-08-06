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
from wdash.hub.adapters import (  # noqa: E402
    ElasticsearchLogSource, ElasticsearchTraceSource,
)

TIMESTAMP = "2026-08-04T11:30:00.000Z"

#: What the installed client will actually accept. Read from the library so
#: the fake cannot drift into accepting something the real one refuses.
_SEARCH_PARAMETERS = frozenset(
    inspect.signature(RealElasticsearch.search).parameters) - {"self"}


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
                properties = ({"trace_id": {"type": "keyword"},
                               "span_id": {"type": "keyword"},
                               "resource": {"properties": {"attributes": {
                                   "properties": {
                                       "service.name": {"type": "keyword"}}}}}}
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

        aggregations = {
            name: {"buckets": [{"key": "api-gateway", "doc_count": 3,
                                "failed": {"doc_count": 0}}]}
            for name in (body.get("aggs") or {})
        }
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
