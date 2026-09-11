"""
Hub tests.

The core claim: the same logical span resolves to the SAME neutral Span
whether it comes from one Elasticsearch schema or the other. If that does not
hold, the hub abstraction is lying and adding a second backend becomes a
rewrite.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub import (  # noqa: E402
    Capability, Hub, LogQuery, Scope, Span, TimeWindow, Trace, normalise_severity,
)
from wdash.hub.adapters import (  # noqa: E402
    ApmSpanSchema, ElasticsearchLogSource, ElasticsearchTraceSource,
    OtelSpanSchema, detect_schema,
)
from wdash.hub.models import STATUS_ERROR, STATUS_OK, SourceRef  # noqa: E402

TS = "2026-08-04T10:00:00.000Z"

# The same logical span, expressed in two different schemas
OTEL_HIT = {
    "_index": "otel-traces-000001", "_id": "o1",
    "_source": {
        "@timestamp": TS,
        "trace_id": "abc123", "span_id": "span1", "parent_span_id": None,
        "name": "GET /checkout", "kind": "SPAN_KIND_SERVER",
        "duration_ns": 145_000_000, "status_code": "OK",
        "resource": {"service.name": "api-gateway", "service.version": "1.4.2"},
        "attributes": {"http.request.method": "GET"},
    },
}

APM_HIT = {
    "_index": "apm-traces-000001", "_id": "a1",
    "_source": {
        "@timestamp": TS,
        "trace": {"id": "abc123"},
        "transaction": {"id": "span1", "name": "GET /checkout", "type": "request",
                        "duration": {"us": 145_000}},
        "service": {"name": "api-gateway", "version": "1.4.2"},
        "event": {"outcome": "success"},
        "processor": {"event": "transaction"},
    },
}


class SchemaEquivalenceTest(unittest.TestCase):
    """The test that decides whether the hub abstraction holds."""

    def setUp(self):
        self.otel = OtelSpanSchema().to_span(OTEL_HIT)
        self.apm = ApmSpanSchema().to_span(APM_HIT)

    def test_both_schemas_resolve(self):
        self.assertIsNotNone(self.otel)
        self.assertIsNotNone(self.apm)

    def test_identity_fields_match(self):
        for attribute in ("trace_id", "span_id", "parent_span_id", "name", "service"):
            self.assertEqual(getattr(self.otel, attribute), getattr(self.apm, attribute),
                             f"{attribute} resolved differently between the two schemas")

    def test_duration_normalised_to_microseconds(self):
        """OTel carries nanoseconds and APM microseconds; the model uses microseconds."""
        self.assertEqual(self.otel.duration_us, 145_000)
        self.assertEqual(self.apm.duration_us, 145_000)

    def test_kind_normalised(self):
        self.assertEqual(self.otel.kind, "SERVER")
        self.assertEqual(self.apm.kind, "SERVER")

    def test_status_normalised(self):
        self.assertEqual(self.otel.status, STATUS_OK)
        self.assertEqual(self.apm.status, STATUS_OK)

    def test_timestamps_match(self):
        self.assertEqual(self.otel.start, self.apm.start)
        self.assertEqual(self.otel.start.tzinfo, timezone.utc)

    def test_source_ref_preserves_backend_handle(self):
        """The neutral model carries no backend detail but must still find the record."""
        self.assertEqual(self.otel.ref.container, "otel-traces-000001")
        self.assertEqual(self.apm.ref.container, "apm-traces-000001")
        self.assertEqual(SourceRef.parse(self.otel.ref.as_token()), self.otel.ref)


class SchemaDetectionTest(unittest.TestCase):
    def test_detects_otel(self):
        properties = {"trace_id": {"type": "keyword"}, "span_id": {"type": "keyword"}}
        self.assertIsInstance(detect_schema(properties), OtelSpanSchema)

    def test_detects_apm(self):
        properties = {"trace": {"properties": {"id": {"type": "keyword"}}},
                      "transaction": {"properties": {}}}
        self.assertIsInstance(detect_schema(properties), ApmSpanSchema)

    def test_unknown_schema_returns_none(self):
        self.assertIsNone(detect_schema({"message": {"type": "text"}}))
        self.assertIsNone(detect_schema({}))
        self.assertIsNone(detect_schema(None))


class ApmSpanKindTest(unittest.TestCase):
    def test_span_documents_become_client_spans(self):
        hit = {
            "_index": "apm-traces-000001", "_id": "a2",
            "_source": {
                "@timestamp": TS,
                "trace": {"id": "abc123"},
                "span": {"id": "span2", "name": "SELECT orders", "type": "db",
                         "subtype": "postgresql", "duration": {"us": 4200}},
                "parent": {"id": "span1"},
                "service": {"name": "payment-service"},
                "event": {"outcome": "failure"},
                "processor": {"event": "span"},
            },
        }
        span = ApmSpanSchema().to_span(hit)
        self.assertEqual(span.kind, "CLIENT")
        self.assertEqual(span.parent_span_id, "span1")
        self.assertEqual(span.status, STATUS_ERROR)
        self.assertEqual(span.attributes["span.type"], "db")


class ScopeTest(unittest.TestCase):
    def test_pattern_matching(self):
        scope = Scope(principal="dev", containers=("app-*", "service-*"))
        self.assertTrue(scope.allows_container("app-logs-000001"))
        self.assertTrue(scope.allows_container("service-logs-000001"))
        self.assertFalse(scope.allows_container("infra-logs-000001"))

    def test_resolve_filters_list(self):
        scope = Scope(principal="dev", containers=("app-*",))
        self.assertEqual(
            scope.resolve(["app-a", "infra-b", "app-c"]), ["app-a", "app-c"])

    def test_empty_scope_is_detectable(self):
        """An empty scope must not reach Elasticsearch as '*'; adapters check this."""
        self.assertTrue(Scope.nothing().is_empty)
        self.assertFalse(Scope.unrestricted().is_empty)
        self.assertEqual(Scope.nothing().resolve(["anything"]), [])

    def test_services_none_means_unrestricted(self):
        self.assertTrue(Scope(containers=("*",), services=None).allows_service("anything"))

    def test_service_restriction(self):
        scope = Scope(containers=("*",), services=("payment-*",))
        self.assertTrue(scope.allows_service("payment-service"))
        self.assertFalse(scope.allows_service("auth-service"))

    def test_a_service_exclusion_beats_the_wildcard(self):
        """Each service pattern was matched bare, so `-payments` was the
        literal name "-payments": a role of `*` with it saw payments in every
        trace store but the one Elasticsearch search that rendered it."""
        scope = Scope(containers=("*",), services=("*", "-payments"))
        self.assertTrue(scope.allows_service("billing-api"))
        self.assertFalse(scope.allows_service("payments"))
        self.assertEqual(scope.filter_services(["payments", "billing-api"]),
                         ["billing-api"])

    def test_a_service_rule_can_be_held_to_one_source(self):
        scope = Scope(containers=("*",), services=("lab-tempo:payments",))
        self.assertTrue(scope.allows_service("payments", source="lab-tempo"))
        self.assertFalse(scope.allows_service("payments", source="lab-jaeger"))
        self.assertFalse(scope.allows_service("payments"))

    def test_the_configured_names_decide_what_a_colon_means(self):
        class Named:
            username = "u"
            allowed_indices = ["*"]
            allowed_trace_indices = ["*"]
            allowed_services = ["unknown_service:java"]
            permissions = []

        scope = Scope.from_user(Named(), sources=["lab-tempo"])
        self.assertEqual(scope.sources, frozenset({"lab-tempo"}))
        self.assertTrue(scope.allows_service("unknown_service:java",
                                             source="lab-tempo"))
        self.assertFalse(Scope.from_user(Named()).allows_service(
            "unknown_service:java", source="lab-tempo"))

    def test_a_service_exclusion_for_one_source_holds_where_it_is_unknown(self):
        scope = Scope(containers=("*",), services=("*", "-lab-tempo:payments"))
        self.assertFalse(scope.allows_service("payments", source="lab-tempo"))
        self.assertTrue(scope.allows_service("payments", source="lab-jaeger"))
        self.assertFalse(scope.allows_service("payments"))

    def test_from_user_bridges_existing_rbac(self):
        class FakeUser:
            username = "yigit"
            allowed_indices = ["app-*"]
            permissions = ["logs:read"]

        scope = Scope.from_user(FakeUser())
        self.assertEqual(scope.principal, "yigit")
        self.assertTrue(scope.allows_container("app-x"))
        self.assertTrue(scope.has("logs:read"))
        self.assertIsNone(scope.services)

    def test_scope_is_immutable(self):
        with self.assertRaises(Exception):
            Scope.unrestricted().principal = "someone-else"


class SeverityTest(unittest.TestCase):
    def test_aliases_map_to_otel_names(self):
        self.assertEqual(normalise_severity("WARNING"), "WARN")
        self.assertEqual(normalise_severity("critical"), "FATAL")
        self.assertEqual(normalise_severity("err"), "ERROR")

    def test_passthrough_and_unknown(self):
        self.assertEqual(normalise_severity("ERROR"), "ERROR")
        self.assertEqual(normalise_severity("banana"), "UNSPECIFIED")
        self.assertEqual(normalise_severity(None), "UNSPECIFIED")


def _span(span_id, parent, start_offset=0, service="svc"):
    return Span(trace_id="t", span_id=span_id, parent_span_id=parent,
                name=span_id, service=service,
                start=datetime(2026, 8, 4, tzinfo=timezone.utc) + timedelta(seconds=start_offset),
                duration_us=1000)


class TraceTest(unittest.TestCase):
    def test_waterfall_orders_by_hierarchy(self):
        trace = Trace(trace_id="t", spans=[
            _span("c", "a", 2), _span("a", None, 0), _span("b", "a", 1),
        ])
        self.assertEqual([(s.span_id, d) for s, d in trace.waterfall()],
                         [("a", 0), ("b", 1), ("c", 1)])

    def test_waterfall_survives_cyclic_parents(self):
        """Broken parent chains occur in real data; this must not loop forever."""
        trace = Trace(trace_id="t", spans=[_span("a", "b"), _span("b", "a", 1)])
        rows = trace.waterfall()
        self.assertEqual(len(rows), 2)

    def test_orphan_spans_are_not_lost(self):
        """Spans unreachable from the root (sampling) must still be reported."""
        trace = Trace(trace_id="t", spans=[
            _span("a", None, 0), _span("orphan", "missing-parent", 5),
        ])
        self.assertEqual(len(trace.waterfall()), 2)

    def test_root_falls_back_to_earliest_when_missing(self):
        trace = Trace(trace_id="t", spans=[_span("x", "gone", 5), _span("y", "gone", 1)])
        self.assertEqual(trace.root.span_id, "y")

    def test_services_and_errors(self):
        error_span = _span("b", "a", 1, service="db")
        error_span.status = STATUS_ERROR
        trace = Trace(trace_id="t", spans=[_span("a", None, 0, service="api"), error_span])
        self.assertEqual(trace.services, ["api", "db"])
        self.assertTrue(trace.has_error)

    def test_empty_trace_is_safe(self):
        trace = Trace(trace_id="t", spans=[])
        self.assertIsNone(trace.root)
        self.assertEqual(trace.duration_us, 0)
        self.assertEqual(trace.waterfall(), [])


class FakeES:
    """Records every call, so tests can prove no query was issued."""

    def __init__(self):
        self.searches = []

    def cat_indices(self, **kw):
        return [{"index": "app-logs-000001"}, {"index": "infra-logs-000001"}]

    @property
    def cat(self):
        outer = self

        class Cat:
            def indices(self, **kw):
                return outer.cat_indices(**kw)
        return Cat()

    def search(self, **kw):
        self.searches.append(kw)
        return {"hits": {"hits": [], "total": {"value": 0}}, "took": 1}

    def ping(self):
        return True


class RolledOverIndexTest(unittest.TestCase):
    """A record in an index created after this worker last listed them.

    Every worker holds its own 30-second index list. The record views read
    only a name that list holds, so a record the search had just shown —
    listed through another worker — was "not found" through this one.
    """

    class Rolling(FakeES):
        def __init__(self):
            super().__init__()
            self.names = ["app-logs-000001"]
            self.listings = 0

        def cat_indices(self, **kw):
            self.listings += 1
            return [{"index": name} for name in self.names]

        def get(self, index=None, id=None, **kw):
            return {"_index": index, "_id": id, "found": True,
                    "_source": {"@timestamp": TS, "message": "m"}}

    def setUp(self):
        self.es = self.Rolling()
        self.source = ElasticsearchLogSource(self.es)
        self.scope = Scope(principal="dev", containers=("app-*",))
        self.source.containers(self.scope)

    def fetch(self, container):
        return self.source.fetch(SourceRef("elasticsearch", container, "d1"),
                                 self.scope)

    def test_a_record_in_a_newer_index_is_found(self):
        self.es.names.append("app-logs-000002")
        self.source._catalogue._fetched_at -= 5     # a few seconds later
        self.assertIsNotNone(self.fetch("app-logs-000002"))

    def test_a_name_that_does_not_exist_is_still_refused(self):
        self.source._catalogue._fetched_at -= 5
        self.assertIsNone(self.fetch("app-logs-000009"))

    def test_asking_for_missing_names_does_not_list_the_cluster_each_time(self):
        self.source._catalogue._fetched_at -= 5
        self.fetch("app-logs-000009")
        listed = self.es.listings
        for _ in range(5):
            self.fetch("app-logs-000009")
        self.assertEqual(self.es.listings, listed)


class ScopeEnforcementTest(unittest.TestCase):
    """Prove that an empty scope issues no query.

    An empty index list sent to Elasticsearch means '*' — a user with access to
    nothing would see EVERYTHING. The adapter must return early to avoid that
    silent disaster.
    """

    def test_empty_scope_issues_no_query(self):
        es = FakeES()
        source = ElasticsearchLogSource(es)
        page = source.search(
            LogQuery(window=TimeWindow.of("1h")), Scope.nothing())

        self.assertEqual(es.searches, [], "no query must be issued with an empty scope")
        self.assertEqual(page.records, [])
        self.assertTrue(page.warnings)

    def test_scope_narrows_queried_indices(self):
        es = FakeES()
        source = ElasticsearchLogSource(es)
        scope = Scope(principal="dev", containers=("app-*",))
        source.search(LogQuery(window=TimeWindow.of("1h")), scope)

        self.assertEqual(len(es.searches), 1)
        self.assertEqual(es.searches[0]["index"], "app-logs-000001")

    def test_fetch_refuses_out_of_scope_container(self):
        source = ElasticsearchLogSource(FakeES())
        ref = SourceRef(backend="elasticsearch", container="infra-logs-000001", id="1")
        self.assertIsNone(source.fetch(ref, Scope(containers=("app-*",))))


class MultiAggregateTest(unittest.TestCase):
    """Several aggregations, one round trip.

    Batching only pays if it is genuinely one call AND a single bad sub-query
    cannot take the others down with it — Elasticsearch reports per-sub-query
    errors inside a 200 response, which is easy to miss.
    """

    def setUp(self):
        import datetime as dt
        from wdash.hub.aggregation import Terms
        from wdash.hub.query import LogQuery, TimeWindow

        self.Terms = Terms
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        window = TimeWindow.exact(now - dt.timedelta(hours=1), now)
        self.query = LogQuery(window=window, text="*", containers=("app-logs-000001",))
        self.scope = Scope(containers=("app-logs-000001",),
                           permissions=frozenset({"logs:read"}))

    def _source(self, es):
        return ElasticsearchLogSource(es)

    def test_three_aggregations_take_one_round_trip(self):
        class BatchingES(FakeES):
            def __init__(self):
                super().__init__()
                self.msearches = 0

            def msearch(self, searches=None, **kw):
                self.msearches += 1
                bodies = len(list(searches or [])) // 2
                return {"responses": [
                    {"took": 1, "hits": {"total": {"value": 7}, "hits": []},
                     "aggregations": {"levels": {"buckets": []}}}
                    for _ in range(bodies)]}

        es = BatchingES()
        requests = [(self.query, [self.Terms(name="levels", field="severity")])] * 3
        results = self._source(es).multi_aggregate(requests, self.scope)

        self.assertEqual(es.msearches, 1, "three aggregations, one call")
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.total == 7 for r in results))

    def test_a_failed_sub_query_becomes_none_and_spares_the_others(self):
        class HalfBrokenES(FakeES):
            def msearch(self, searches=None, **kw):
                return {"responses": [
                    {"error": {"type": "search_phase_execution_exception"}},
                    {"took": 1, "hits": {"total": {"value": 3}, "hits": []},
                     "aggregations": {"levels": {"buckets": []}}},
                ]}

        requests = [(self.query, [self.Terms(name="levels", field="severity")])] * 2
        results = self._source(HalfBrokenES()).multi_aggregate(requests, self.scope)

        self.assertTrue(results[0].failed,
                        "a failed sub-query must not pass as a real zero")
        self.assertEqual(results[1].total, 3, "the healthy sub-query still lands")
        self.assertFalse(results[1].failed)

    def test_a_single_request_does_not_pay_for_msearch(self):
        class CountingES(FakeES):
            def msearch(self, searches=None, **kw):
                raise AssertionError("one aggregation should use a plain search")

        es = CountingES()
        results = self._source(es).multi_aggregate(
            [(self.query, [self.Terms(name="levels", field="severity")])], self.scope)

        self.assertEqual(len(es.searches), 1)
        self.assertEqual(len(results), 1)

    def test_an_empty_scope_still_issues_nothing(self):
        """The batching path must honour the same fail-closed rule."""
        class ExplodingES(FakeES):
            def msearch(self, **kw):
                raise AssertionError("query issued for a user with no access")

            def search(self, **kw):
                raise AssertionError("query issued for a user with no access")

        empty = Scope(containers=(), permissions=frozenset({"logs:read"}))
        requests = [(self.query, [self.Terms(name="levels", field="severity")])] * 2
        results = self._source(ExplodingES()).multi_aggregate(requests, empty)
        self.assertTrue(all(r.total == 0 for r in results))
        self.assertFalse(any(r.failed for r in results),
                         "no access is a real answer, not a failure")


class HubRegistryTest(unittest.TestCase):
    def test_returns_registered_sources(self):
        es = FakeES()
        hub = Hub()
        logs = hub.add_logs(ElasticsearchLogSource(es, name="es-logs"))
        traces = hub.add_traces(ElasticsearchTraceSource(es, name="es-traces"))

        self.assertIs(hub.logs(), logs)
        self.assertIs(hub.traces(), traces)
        self.assertIs(hub.logs("es-logs"), logs)

    def test_empty_hub_returns_none(self):
        self.assertIsNone(Hub().logs())
        self.assertIsNone(Hub().traces())

    def test_unknown_name_raises(self):
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(FakeES(), name="a"))
        with self.assertRaises(KeyError):
            hub.logs("nope")

    def test_capabilities_are_declared(self):
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(FakeES()))
        hub.add_traces(ElasticsearchTraceSource(FakeES()))
        capabilities = hub.capabilities()
        self.assertIn(Capability.SEARCH, capabilities)
        self.assertIn(Capability.TRACE_LOOKUP, capabilities)

    def test_unsupported_capability_raises_clearly(self):
        """An optional method a source does not implement must refuse loudly.

        Both Elasticsearch adapters are complete today, so this exercises the
        base-class contract directly — that is what a future adapter relies on.
        """
        from wdash.hub.source import LogSource

        class Minimal(LogSource):
            name = "minimal"

            def health(self):
                return True, "ok"

            def containers(self, scope):
                return []

            def search(self, query, scope):
                return None

            def fetch(self, ref, scope):
                return None

        source = Minimal()
        self.assertFalse(source.supports(Capability.CONTEXT))
        for call in (lambda: source.field_stats(None, Scope.unrestricted()),
                     lambda: source.context(None, Scope.unrestricted()),
                     lambda: source.histogram(None, Scope.unrestricted()),
                     lambda: source.aggregate(None, [], Scope.unrestricted())):
            with self.assertRaises(NotImplementedError):
                call()


class TimeWindowTest(unittest.TestCase):
    def test_window_is_aligned(self):
        window = TimeWindow.of("1h")
        self.assertEqual(window.start.second, 0)
        self.assertEqual(window.start.microsecond, 0)

    def test_interval_scales_with_window(self):
        self.assertEqual(TimeWindow.of("15m").suggest_interval(), "1m")
        self.assertEqual(TimeWindow.of("24h").suggest_interval(), "1h")
        self.assertEqual(TimeWindow.of("7d").suggest_interval(), "6h")

    def test_es_range_is_second_precision(self):
        rendered = TimeWindow.of("1h").as_es_range()
        self.assertTrue(rendered["gte"].endswith("Z"))
        self.assertNotIn(".", rendered["gte"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


# --------------------------------------------------------------------------
# Canli lab entegrasyonu - ES yoksa atlanir
# --------------------------------------------------------------------------

#: Where the integration tests below look for a cluster.
#:
#: NOT `ELASTICSEARCH_URL`, which is what this read until it was noticed.
#: `tests/__init__.py` forces that one empty on purpose — the suite must not
#: talk to a cluster nobody declared — so `os.environ.get(name, default)`
#: returned the empty string rather than the default, the client refused to
#: build, and these tests skipped every single run. Including the runs with
#: the lab up, while printing a message telling you to start it.
#:
#: A variable of their own means the two statements stop fighting: "the
#: application has no cluster" and "the integration tests have one over
#: here".
LAB_URL = os.environ.get("WDASH_LAB_URL") or "http://localhost:9200"

#: Set by CI. A job that exists to run these tests and reports success
#: because it skipped them is worse than no job.
LAB_REQUIRED = os.environ.get("WDASH_REQUIRE_LAB") == "1"


def _lab_client():
    """Lab ayaktaysa ES istemcisi, degilse None."""
    try:
        from elasticsearch import Elasticsearch
        client = Elasticsearch(hosts=[LAB_URL], request_timeout=5)
        return client if client.ping() else None
    except Exception:
        return None


LAB = _lab_client()


class LabIsReachableTest(unittest.TestCase):
    """The guard on the skip below.

    A skip is the right answer on a laptop with nothing running and the wrong
    answer in a job whose whole purpose is these four tests. `WDASH_REQUIRE_LAB=1`
    turns the one into the other.
    """

    @unittest.skipUnless(LAB_REQUIRED, "only asserted where a lab is promised")
    def test_the_lab_is_there_when_it_was_promised(self):
        self.assertIsNotNone(
            LAB, f"WDASH_REQUIRE_LAB is set but nothing answered at {LAB_URL}")


@unittest.skipIf(LAB is None,
                 f"no Elasticsearch at {LAB_URL} — `cd lab && ./lab.sh up`, "
                 f"or set WDASH_LAB_URL")
class LiveSchemaEquivalenceTest(unittest.TestCase):
    """Verify the hub's central claim against real data.

    The lab holds the same traces in both the OTel and the Elastic APM schema.
    If the traces read from each are not identical in the neutral model, the
    abstraction is useless.
    """

    SAMPLE = 25

    @classmethod
    def setUpClass(cls):
        cls.source = ElasticsearchTraceSource(LAB)
        cls.window = TimeWindow.of("30d")
        cls.otel_scope = Scope(principal="test", trace_containers=("otel-traces-*",))
        cls.apm_scope = Scope(principal="test", trace_containers=("apm-traces-*",))

    @staticmethod
    def _signature(trace):
        return sorted((s.span_id, s.service, s.kind, s.status, s.name,
                       s.duration_us, s.parent_span_id) for s in trace.spans)

    def _trace_ids(self, limit):
        """Root spans, whichever spelling of `kind` the writer used.

        The collector writes "Server"; an older pipeline writes
        "SPAN_KIND_SERVER". Pinning this to one of them made the helper return
        nothing the moment the lab started producing the real shape — and an
        empty list reads as a passing test right up until you index it.
        """
        hits = LAB.search(
            index="otel-traces-000001", size=limit,
            query={"terms": {"kind": ["Server", "SPAN_KIND_SERVER"]}}
        )["hits"]["hits"]
        ids = [h["_source"]["trace_id"] for h in hits]
        self.assertTrue(ids, "no root spans in the lab; reseed it")
        return ids

    def test_both_schemas_are_detected(self):
        detected = {index: self.source._schema_for(index).name
                    for index in self.source.containers(Scope.unrestricted())
                    if self.source._schema_for(index)}
        self.assertIn("otel", detected.values())
        self.assertIn("apm", detected.values())

    def test_same_trace_resolves_identically_from_both_schemas(self):
        mismatches = []
        for trace_id in self._trace_ids(self.SAMPLE):
            otel = self.source.trace(trace_id, self.window, self.otel_scope)
            apm = self.source.trace(trace_id, self.window, self.apm_scope)
            self.assertIsNotNone(otel, f"{trace_id} could not be read from the OTel schema")
            self.assertIsNotNone(apm, f"{trace_id} could not be read from the APM schema")
            if self._signature(otel) != self._signature(apm):
                mismatches.append(trace_id)

        self.assertEqual(mismatches, [],
                         f"{len(mismatches)}/{self.SAMPLE} traces resolved differently between schemas")

    def test_reading_both_schemas_merges_rather_than_duplicates(self):
        """An unrestricted scope reads both schemas but must yield ONE trace.

        This assertion used to expect twice the spans, which encoded a bug:
        duplicated children make every parent report zero self time.
        """
        trace_id = self._trace_ids(1)[0]
        otel = self.source.trace(trace_id, self.window, self.otel_scope)
        merged = self.source.trace(trace_id, self.window, Scope.unrestricted())

        self.assertEqual(len(merged.spans), len(otel.spans))
        self.assertEqual(len({s.span_id for s in merged.spans}), len(merged.spans))

    def test_self_time_survives_reading_both_schemas(self):
        """The parent must still report time of its own after the merge."""
        trace_id = self._trace_ids(1)[0]
        merged = self.source.trace(trace_id, self.window, Scope.unrestricted())
        root = merged.root
        self.assertGreater(merged.self_time_us(root), 0)

    def test_services_merge_across_schemas(self):
        services = self.source.services(self.window, Scope.unrestricted())
        self.assertTrue(services)
        names = {s.name for s in services}
        self.assertIn("api-gateway", names)
        self.assertTrue(any(s.error_rate > 0 for s in services))

    def test_log_source_respects_scope(self):
        source = ElasticsearchLogSource(LAB)
        page = source.search(
            LogQuery(window=TimeWindow.of("30d"), text="level:ERROR", limit=5),
            Scope(principal="dev", containers=("app-*",)))
        self.assertEqual(page.containers, ("app-logs-000001",))
        self.assertTrue(page.records)
        for record in page.records:
            self.assertEqual(record.severity, "ERROR")
            self.assertEqual(record.ref.backend, "elasticsearch")


class TraceScopeTest(unittest.TestCase):
    """Verify the trace boundary is separate from the log one and fails closed."""

    def test_trace_containers_are_separate_from_log_containers(self):
        """Access to log indices does not imply access to trace stores."""
        scope = Scope(principal="dev", containers=("app-*",))
        self.assertTrue(scope.allows_container("app-logs-000001"))
        self.assertFalse(scope.allows_trace_container("otel-traces-000001"))
        self.assertTrue(scope.trace_is_empty)

    def test_trace_source_issues_no_query_without_trace_access(self):
        es = FakeES()
        source = ElasticsearchTraceSource(es)
        scope = Scope(principal="dev", containers=("app-*",))   # trace yok

        self.assertEqual(source.containers(scope), [])
        self.assertIsNone(source.trace("abc", TimeWindow.of("1h"), scope))
        self.assertEqual(es.searches, [], "no query must be issued without trace access")

    def test_missing_attribute_denies_traces(self):
        """A legacy User object without trace fields sees no traces."""
        class LegacyUser:
            username = "old"
            allowed_indices = ["*"]
            permissions = ["logs:read"]

        scope = Scope.from_user(LegacyUser())
        self.assertTrue(scope.allows_container("anything"))     # logs unaffected
        self.assertTrue(scope.trace_is_empty)                   # traces closed

    def test_empty_service_list_denies_everything(self):
        """The `[] or None` trap: an empty list must NOT mean "unrestricted"."""
        class NoServices:
            username = "u"
            allowed_indices = ["*"]
            allowed_trace_indices = ["*"]
            allowed_services = []
            permissions = []

        scope = Scope.from_user(NoServices())
        self.assertEqual(scope.services, ())
        self.assertFalse(scope.allows_service("api-gateway"))

    def test_missing_service_list_means_unrestricted(self):
        class NoServiceField:
            username = "u"
            allowed_indices = ["*"]
            allowed_trace_indices = ["*"]
            permissions = []

        scope = Scope.from_user(NoServiceField())
        self.assertIsNone(scope.services)
        self.assertTrue(scope.allows_service("anything"))

    def test_from_user_carries_all_boundaries(self):
        class FullUser:
            username = "dev"
            allowed_indices = ["app-*"]
            allowed_trace_indices = ["otel-*"]
            allowed_services = ["api-gateway", "payment-*"]
            permissions = ["traces:read"]

        scope = Scope.from_user(FullUser())
        self.assertTrue(scope.allows_container("app-logs-1"))
        self.assertTrue(scope.allows_trace_container("otel-traces-1"))
        self.assertFalse(scope.allows_trace_container("apm-traces-1"))
        self.assertTrue(scope.allows_service("payment-service"))
        self.assertFalse(scope.allows_service("postgres"))
        self.assertTrue(scope.has("traces:read"))


def _service_doc(field, name):
    """A span document whose service is `name`, or one with no service
    field at all when `name` is None."""
    doc = {}
    if name is not None:
        node = doc
        parts = field.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = name
    return doc


class ServiceFilterPushDownTest(unittest.TestCase):
    """The service clause put into a trace search means what the check means.

    The clause is evaluated against a model of term, wildcard and bool
    queries, and compared with `Scope.allows_service` for the same source.
    Where they disagree, either rows the role may see never come back, or the
    query fills a page with rows the check then throws away.
    """

    SOURCE = "es-traces"

    def clause(self, services):
        return ElasticsearchTraceSource._scope_service_filter(
            OtelSpanSchema(), Scope(containers=("*",), services=services),
            self.SOURCE)

    def test_the_query_and_the_check_agree(self):
        """None is a span with no service field: the reader calls its
        service "", the check lets `*` have it, and the query must too."""
        from tests.support import es_query_matches
        field = OtelSpanSchema().service_field
        lists = [(), ("*",), ("*", "-payments"), ("-payments",),
                 ("*", "-*pay?*"), ("pay*", "-pay*s"), ("p*y*",),
                 ("a\\b*",), ("es-traces:payments",),
                 ("other:payments", "billing-api"), ("*", "-other:payments"),
                 ("*", "-es-traces:payments"), ("*", "es-traces:-payments"),
                 ("*", "api-*"), ("-*",), ("*", "-*")]
        names = ["payments", "pay?ments", "billing-api", "p*yroll",
                 "pxyroll", "a\\bc", "abc", None]
        for services in lists:
            scope = Scope(containers=("*",), services=services)
            clause = self.clause(services)
            for name in names:
                self.assertEqual(
                    es_query_matches(clause, _service_doc(field, name)),
                    scope.allows_service(name or "", source=self.SOURCE),
                    f"{services} {name}: {clause}")

    def test_a_granted_name_with_a_colon_is_in_the_query(self):
        from tests.support import es_query_matches
        field = OtelSpanSchema().service_field
        clause = ElasticsearchTraceSource._scope_service_filter(
            OtelSpanSchema(),
            Scope(containers=("*",), services=("unknown_service:java",),
                  sources=frozenset({self.SOURCE})),
            self.SOURCE)
        self.assertTrue(es_query_matches(
            clause, _service_doc(field, "unknown_service:java")))

    def test_an_exclusion_beside_the_wildcard_is_in_the_query(self):
        """It returned early on `*` and left `-payments` to the filter on the
        way out: a short page rather than a boundary in the query."""
        self.assertIn("must_not", self.clause(("*", "-payments"))["bool"])

    def test_the_search_asks_with_its_own_name(self):
        """A rule held to this source reaches the query only if the adapter
        says which source it is."""
        import json

        class Recording(FakeES):
            @property
            def indices(self):
                class Indices:
                    def get_mapping(self, index=None, **kw):
                        return {"otel-traces-000001": {"mappings": {"properties": {
                            "trace_id": {"type": "keyword"},
                            "span_id": {"type": "keyword"}}}}}
                return Indices()

            @property
            def cat(self):
                class Cat:
                    def indices(self, **kw):
                        return [{"index": "otel-traces-000001"}]
                return Cat()

        from wdash.hub.query import TraceQuery
        es = Recording()
        source = ElasticsearchTraceSource(es, name=self.SOURCE)
        source.search(TraceQuery(window=TimeWindow.of("1h"), limit=10),
                      Scope(containers=(), trace_containers=("*",),
                            services=("es-traces:payments",)))
        sent = json.dumps(es.searches)
        self.assertIn('"payments"', sent)
        self.assertNotIn("match_none", sent)


class DuplicateSpanTest(unittest.TestCase):
    """The same logical span can arrive from two schemas at once.

    Left unmerged it doubles the waterfall and breaks self time: children get
    counted twice, so every parent reports zero time of its own.
    """

    def test_self_time_is_wrong_when_children_are_duplicated(self):
        """Show the failure the de-duplication prevents."""
        parent = _span("p", None, 0)
        parent.duration_us = 100
        child_a = _span("c", "p", 1)
        child_a.duration_us = 60
        duplicate = _span("c", "p", 1)      # same span id, second schema
        duplicate.duration_us = 60

        healthy = Trace(trace_id="t", spans=[parent, child_a])
        doubled = Trace(trace_id="t", spans=[parent, child_a, duplicate])

        self.assertEqual(healthy.self_time_us(parent), 40)
        self.assertEqual(doubled.self_time_us(parent), 0)   # the bug, if unmerged

    def test_adapter_deduplicates_across_schemas(self):
        from wdash.hub.adapters.es_trace_schema import OtelSpanSchema

        class DoubledES(FakeES):
            """Returns the same span from both schema groups."""

            @property
            def indices(self):
                class Indices:
                    def get_mapping(self, index=None, **kw):
                        return {"otel-traces-000001": {"mappings": {"properties": {
                            "trace_id": {"type": "keyword"},
                            "span_id": {"type": "keyword"}}}}}
                return Indices()

            @property
            def cat(self):
                class Cat:
                    def indices(self, **kw):
                        return [{"index": "otel-traces-000001"}]
                return Cat()

            def search(self, **kw):
                return {"hits": {"hits": [OTEL_HIT, OTEL_HIT], "total": {"value": 2}}}

        source = ElasticsearchTraceSource(DoubledES())
        trace = source.trace("abc123", TimeWindow.of("1h"), Scope.unrestricted())
        self.assertEqual(len(trace.spans), 1, "duplicate span ids must be merged")
