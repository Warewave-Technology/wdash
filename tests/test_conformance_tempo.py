"""
Tempo against the trace contract, plus what is its own problem.

Every shape below was copied from a running Tempo. Two of them would have
produced a page that looked like it worked and was wrong: the trace endpoint
returns ids base64-encoded while the search endpoint returns the same ids as
hex, and the enums are strings rather than the integers OTLP uses on the wire.
"""

import base64
import datetime as dt
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conformance import Harness, TraceSourceConformance  # noqa: E402

from wdash.hub import Scope  # noqa: E402
from wdash.hub.adapters.tempo import TempoTraceSource  # noqa: E402
from wdash.hub.source import Capability  # noqa: E402

SERVICES = ["billing-api", "edge-router", "payments"]

TRACE_ID = "f9f7db6d3e441d9071714f6f50f38f77"
ROOT_SPAN = "8c5e6082ebf32ceb"
CHILD_SPAN = "e017557abdcac414"


def _b64(hex_id):
    """Ids come back as protobuf `bytes`, which JSON maps to base64."""
    return base64.b64encode(bytes.fromhex(hex_id)).decode()


#: `/api/traces/{id}` — OTLP JSON, base64 ids, string enums.
TRACE = {
    "batches": [
        {"resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "edge-router"}}]},
         "scopeSpans": [{"scope": {}, "spans": [{
             "traceId": _b64(TRACE_ID), "spanId": _b64(ROOT_SPAN),
             "name": "GET /checkout", "kind": "SPAN_KIND_SERVER",
             "startTimeUnixNano": "1785961664084674048",
             "endTimeUnixNano": "1785961664204674048",
             "attributes": [{"key": "http.route",
                             "value": {"stringValue": "/checkout"}}],
             "status": {"code": "STATUS_CODE_OK"}}]}]},
        {"resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "billing-api"}}]},
         "scopeSpans": [{"scope": {}, "spans": [{
             "traceId": _b64(TRACE_ID), "spanId": _b64(CHILD_SPAN),
             "parentSpanId": _b64(ROOT_SPAN),
             "name": "POST /charge", "kind": "SPAN_KIND_CLIENT",
             "startTimeUnixNano": "1785961664104674048",
             "endTimeUnixNano": "1785961664184674048",
             "attributes": [],
             "status": {"code": "STATUS_CODE_ERROR", "message": "declined"}}]}]},
    ]
}

#: `/api/search` — hex ids, and `serviceStats` per trace per service.
SEARCH = {
    "traces": [{
        "traceID": TRACE_ID,
        "rootServiceName": "edge-router",
        "rootTraceName": "GET /checkout",
        "startTimeUnixNano": "1785961664084674048",
        "durationMs": 120,
        "serviceStats": {"billing-api": {"spanCount": 1, "errorCount": 1},
                         "edge-router": {"spanCount": 1}},
        # The spans the query matched, as Tempo 2.6 returns them: here the
        # billing-api call, 20 ms into the trace and 80 ms long.
        "spanSets": [{"spans": [{"spanID": "b36502ca8950f78d",
                                 "startTimeUnixNano": "1785961664104674048",
                                 "durationNanos": "80000000"}],
                      "matched": 1}],
    }],
    "metrics": {},
}


class FakeResponse:
    def __init__(self, payload=None, status_code=200, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else json.dumps(payload or {})

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeTempo(Harness):
    """Tempo's query API, enough of it."""

    def __init__(self):
        self._requests = []
        self._fail_next = False
        self._trace_found = True
        self._reject_query = False

    # --- harness contract ---

    def requests(self):
        # Tag lookups are how the adapter learns what exists; they are not
        # data queries, and counting them would make "issued no query"
        # impossible to state.
        return [request for request in self._requests
                if "/search/tag/" not in request["path"]]

    def reset(self):
        self._requests = []

    def containers(self):
        return ["tempo"]

    def fail_next(self):
        self._fail_next = True

    def no_trace(self):
        self._trace_found = False

    def reject_query(self):
        self._reject_query = True

    def mentions(self, request, text):
        return text in json.dumps(request, default=str)

    def carries_window(self, request, window):
        params = request.get("params") or {}
        start = params.get("start")
        if not start:
            return False
        # Seconds. Nanoseconds are accepted and match nothing, which is an
        # empty page with no error.
        return abs(int(start) - window.start.timestamp()) < 2

    # --- the requests session the adapter holds ---

    def get(self, url, params=None, headers=None, auth=None, timeout=None,
            verify=None):
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1]
        self._requests.append({"path": path, "params": dict(params or {}),
                               "headers": dict(headers or {})})

        if self._fail_next:
            self._fail_next = False
            return FakeResponse(status_code=503, text="unavailable")

        if path.endswith("/ready"):
            return FakeResponse(text="ready")

        if "/search/tag/" in path:
            return FakeResponse({"tagValues": [{"type": "string", "value": name}
                                               for name in SERVICES]})

        if "/api/traces/" in path:
            requested = path.rsplit("/", 1)[-1]
            if not self._trace_found or requested != TRACE_ID:
                return FakeResponse(status_code=404, text="trace not found")
            return FakeResponse(TRACE)

        if path.endswith("/api/search"):
            if self._reject_query:
                return FakeResponse(
                    status_code=400,
                    text="invalid TraceQL query: parse error at line 1, col 3")
            return FakeResponse(SEARCH)

        return FakeResponse({})


class TempoConformanceTest(TraceSourceConformance, unittest.TestCase):
    def build(self):
        harness = FakeTempo()
        return TempoTraceSource("http://tempo:3200", name="tempo",
                                session=harness), harness


class TempoSpecificTest(unittest.TestCase):
    """The parts that are Tempo's own problem rather than the hub's."""

    def setUp(self):
        self.harness = FakeTempo()
        self.source = TempoTraceSource("http://tempo:3200", name="tempo",
                                       session=self.harness)
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        from wdash.hub import TimeWindow
        self.window = TimeWindow.exact(now - dt.timedelta(hours=1), now)

    def _query(self, **overrides):
        from wdash.hub.query import TraceQuery
        arguments = {"window": self.window, "limit": 10}
        arguments.update(overrides)
        return TraceQuery(**arguments)

    def _search(self, scope=None, **overrides):
        return self.source.search(self._query(**overrides),
                                  scope or Scope.unrestricted())

    def _traceql(self):
        return next(r["params"]["q"] for r in reversed(self.harness._requests)
                    if r["path"].endswith("/api/search"))

    # --- the two id encodings ---

    def test_base64_ids_are_decoded(self):
        """The trace endpoint returns protobuf `bytes`, which JSON maps to
        base64. Read as hex they are garbage."""
        trace = self.source.trace(TRACE_ID, self.window, Scope.unrestricted())
        self.assertEqual(sorted(span.span_id for span in trace.spans),
                         sorted([ROOT_SPAN, CHILD_SPAN]))

    def test_the_parent_link_survives_the_decoding(self):
        """Get this wrong and every parent dangles: the waterfall comes out
        flat, which looks like missing instrumentation rather than a bug."""
        trace = self.source.trace(TRACE_ID, self.window, Scope.unrestricted())
        child = next(s for s in trace.spans if s.name == "POST /charge")
        self.assertEqual(child.parent_span_id, ROOT_SPAN)
        self.assertEqual(len(trace.waterfall()), 2)

    def test_hex_ids_are_left_alone(self):
        """The SEARCH endpoint returns the same ids as hex. Decoding those as
        base64 produces nonsense, so both shapes have to be handled."""
        from wdash.hub.adapters.tempo import _hex_id
        self.assertEqual(_hex_id(TRACE_ID), TRACE_ID)
        self.assertEqual(_hex_id(ROOT_SPAN), ROOT_SPAN)
        self.assertEqual(self._search()[0].trace_id, TRACE_ID)

    # --- string enums ---

    def test_the_status_enum_is_a_string(self):
        """`STATUS_CODE_ERROR`, not the integer OTLP puts on the wire."""
        trace = self.source.trace(TRACE_ID, self.window, Scope.unrestricted())
        self.assertTrue(trace.has_error)
        self.assertEqual([s.name for s in trace.spans if s.failed],
                         ["POST /charge"])

    def test_the_kind_loses_the_backend_prefix(self):
        """The neutral model does not carry one backend's spelling."""
        trace = self.source.trace(TRACE_ID, self.window, Scope.unrestricted())
        self.assertEqual({s.kind for s in trace.spans}, {"SERVER", "CLIENT"})

    def test_durations_come_from_the_two_timestamps(self):
        trace = self.source.trace(TRACE_ID, self.window, Scope.unrestricted())
        self.assertEqual(trace.root.duration_us, 120_000)

    # --- serviceStats ---

    def test_the_error_flag_comes_from_service_stats(self):
        """No second request. Jaeger has to fetch the whole trace to know."""
        self.assertTrue(self._search()[0].has_error)

    def test_the_span_count_comes_from_service_stats(self):
        self.assertEqual(self._search()[0].span_count, 2)

    def test_a_trace_with_no_errors_is_not_flagged(self):
        quiet = json.loads(json.dumps(SEARCH))
        quiet["traces"][0]["serviceStats"] = {"edge-router": {"spanCount": 1}}
        self.harness.get = (lambda *a, **k: FakeResponse(quiet))
        self.assertFalse(self.source.search(
            self._query(), Scope.unrestricted())[0].has_error)

    # --- TraceQL ---

    def test_an_unfiltered_search_is_the_empty_selector(self):
        self._search()
        self.assertEqual(self._traceql(), "{}")

    def test_a_service_reaches_the_query(self):
        self._search(service="billing-api")
        self.assertIn('resource.service.name = "billing-api"', self._traceql())

    def test_errors_only_reaches_the_query(self):
        """A limit applied by Tempo has already chosen its traces, so
        filtering afterwards returns a short page of the wrong ones."""
        self._search(only_errors=True)
        self.assertIn("status = error", self._traceql())

    def test_a_minimum_duration_reaches_the_query(self):
        self._search(min_duration_us=250_000)
        self.assertIn("duration > 250000us", self._traceql())

    def test_clauses_combine_rather_than_replace(self):
        self._search(service="billing-api", only_errors=True)
        rendered = self._traceql()
        self.assertIn("&&", rendered)
        self.assertIn("status = error", rendered)
        self.assertIn("billing-api", rendered)

    def test_a_quote_in_a_value_cannot_end_the_string(self):
        """Unescaped, `"} || {"` would be a way to widen the query past the
        scope rather than merely a syntax error."""
        self._search(service='evil" || {')
        rendered = self._traceql()
        self.assertIn('\\"', rendered)
        self.assertEqual(rendered.count("||"), 1)

    def test_an_exact_scope_service_list_is_pushed_down(self):
        self._search(scope=Scope(principal="p", containers=("*",),
                                 trace_containers=("*",),
                                 services=("billing-api", "payments"),
                                 permissions=frozenset({"traces:read"})))
        rendered = self._traceql()
        self.assertIn("billing-api", rendered)
        self.assertIn("payments", rendered)

    def test_a_pattern_scope_is_resolved_to_names_not_a_regex(self):
        """TraceQL has `=~`, and turning a glob into a regular expression
        would be a second pattern language — the thing this codebase already
        unified once. The pattern is matched against the names Tempo lists,
        by the one pattern language, and those names are pushed."""
        self._search(scope=Scope(principal="p", containers=("*",),
                                 trace_containers=("*",), services=("billing-*",),
                                 permissions=frozenset({"traces:read"})))
        self.assertEqual(self._traceql(),
                         '{ resource.service.name = "billing-api" }')

    def test_a_pattern_scope_still_filters(self):
        """Not pushing it down must not mean not applying it."""
        found = self._search(scope=Scope(principal="p", containers=("*",),
                                         trace_containers=("*",),
                                         services=("nothing-*",),
                                         permissions=frozenset({"traces:read"})))
        self.assertEqual(found, [])

    def test_a_query_tempo_refuses_is_raised_not_swallowed(self):
        """An empty list would read as "no traces match", and somebody would
        go looking for missing data instead of a broken query."""
        from wdash.hub.adapters.tempo import TempoQueryError
        self.harness.reject_query()
        with self.assertRaises(TempoQueryError):
            self._search()

    def test_the_refusal_carries_tempo_s_own_message(self):
        """"parse error at line 1, col 3" tells somebody what to fix."""
        from wdash.hub.adapters.tempo import TempoQueryError
        self.harness.reject_query()
        try:
            self._search()
        except TempoQueryError as exc:
            self.assertIn("parse error", str(exc))

    # --- windows ---

    def test_the_window_is_sent_in_seconds(self):
        self._search()
        params = next(r["params"] for r in self.harness._requests
                      if r["path"].endswith("/api/search"))
        self.assertAlmostEqual(int(params["start"]),
                               self.window.start.timestamp(), delta=2)

    # --- services ---

    def test_the_service_list_does_not_invent_span_counts(self):
        """Per-service volume needs the metrics-generator writing to
        Prometheus. A count aggregated from a bounded search would describe
        the traces that came back, not the service."""
        services = self.source.services(self.window, Scope.unrestricted())
        self.assertEqual(sorted(s.name for s in services), sorted(SERVICES))
        self.assertEqual({s.span_count for s in services}, {0})

    def test_the_scope_narrows_the_service_list(self):
        services = self.source.services(
            self.window,
            Scope(principal="p", containers=("*",), trace_containers=("*",),
                  services=("billing-*",),
                  permissions=frozenset({"traces:read"})))
        self.assertEqual([s.name for s in services], ["billing-api"])

    # --- absence and failure ---

    def test_a_missing_trace_is_none_rather_than_an_empty_one(self):
        self.harness.no_trace()
        self.assertIsNone(self.source.trace(TRACE_ID, self.window,
                                            Scope.unrestricted()))

    def test_a_trace_whose_spans_the_scope_hides_is_none(self):
        self.assertIsNone(self.source.trace(
            TRACE_ID, self.window,
            Scope(principal="p", containers=("*",), trace_containers=("*",),
                  services=("nothing-matches",),
                  permissions=frozenset({"traces:read"}))))

    def test_a_starting_tempo_is_not_called_healthy(self):
        """`/ready` answers 200 with "Ingester not ready: …" while it starts.
        A status code alone would call that healthy."""
        class Starting(FakeTempo):
            def get(self, url, **kwargs):
                return FakeResponse(text="Ingester not ready: waiting for 15s")

        source = TempoTraceSource("http://tempo:3200", session=Starting())
        healthy, detail = source.health()
        self.assertFalse(healthy)
        self.assertIn("not ready", detail)

    def test_a_backend_error_is_raised_rather_than_answered_as_nothing(self):
        """This asserted `services(...) == []` after a 503. Only a query
        TraceQL refused was raised; every other failure was an empty list,
        so a Tempo that was down read as a quiet hour on the list and as
        "not found, widen the time range" on a trace link."""
        from wdash.hub.adapters.tempo import TempoError
        for call in (
                lambda: self.source.services(self.window, Scope.unrestricted()),
                lambda: self._search(),
                lambda: self.source.trace(TRACE_ID, self.window,
                                          Scope.unrestricted())):
            self.harness.fail_next()
            with self.assertRaises(TempoError):
                call()

    def test_a_failed_service_lookup_for_a_search_is_raised(self):
        """A pattern grant asks Tempo for its service names first, and that
        request failing was an empty page too."""
        from wdash.hub.adapters.tempo import TempoError
        self.harness.fail_next()
        with self.assertRaises(TempoError):
            self._search(scope=self._role(services=("billing-*",)))

    def test_an_unreachable_tempo_raises_too(self):
        class Refused:
            def get(self, url, **kwargs):
                raise ConnectionError("connection refused")

        source = TempoTraceSource("http://127.0.0.1:9", session=Refused())
        for call in (lambda: source.services(self.window, Scope.unrestricted()),
                     lambda: source.search(self._query(), Scope.unrestricted()),
                     lambda: source.trace(TRACE_ID, self.window,
                                          Scope.unrestricted())):
            with self.assertRaises(ConnectionError):
                call()

    # --- the store boundary ---

    @staticmethod
    def _role(stores=("*",), services=None, containers=()):
        return Scope(principal="p", containers=containers,
                     trace_containers=stores, services=services,
                     permissions=frozenset({"traces:read"}))

    def test_a_role_granted_only_elasticsearch_indices_reads_nothing_here(self):
        """Tempo asked whether the role had any LOG container, so a role
        granted `otel-traces-*` and every log index read every trace in
        Tempo, while the role preview, which matches the name, said none."""
        role = self._role(stores=("otel-traces-*",), containers=("*",))
        self.assertEqual(self.source.containers(role), [])
        self.assertEqual(self.source.services(self.window, role), [])
        self.assertEqual(self._search(scope=role), [])
        self.assertIsNone(self.source.trace(TRACE_ID, self.window, role))
        self.assertEqual(self.harness._requests, [],
                         "Tempo was asked on behalf of a role it is closed to")

    def test_the_store_is_granted_by_the_source_name(self):
        for stores in (("*",), ("tempo",), ("tem*",), ("tempo:*",)):
            role = self._role(stores=stores)
            self.assertEqual(self.source.containers(role), ["tempo"], stores)
            self.assertEqual([s.trace_id for s in self._search(scope=role)],
                             [TRACE_ID], stores)

    def test_an_exclusion_of_the_store_holds(self):
        role = self._role(stores=("*", "-tempo"))
        self.assertEqual(self._search(scope=role), [])
        self.assertIsNone(self.source.trace(TRACE_ID, self.window, role))

    def test_a_role_with_trace_stores_and_no_log_index_can_search(self):
        """Search asked `is_empty`, which is about LOG containers: a
        trace-only role got an empty page from Tempo and no error."""
        role = self._role(stores=("tempo",), containers=())
        self.assertEqual([s.trace_id for s in self._search(scope=role)],
                         [TRACE_ID])

    # --- the service boundary ---

    def test_a_trace_entering_through_a_hidden_service_is_still_found(self):
        """Every trace whose ROOT was out of scope was dropped — after
        TraceQL had chosen it for a service that was in scope. A role allowed
        `billing-api` saw nothing for calls entering through the gateway."""
        found = self._search(scope=self._role(services=("billing-api",)))
        self.assertEqual(len(found), 1)
        summary = found[0]
        self.assertEqual(summary.service, "billing-api")
        self.assertEqual(summary.name, "",
                         "the hidden root's operation was shown")
        self.assertEqual(summary.span_count, 1)
        self.assertTrue(summary.has_error)

    def test_a_hidden_services_spans_are_not_counted(self):
        summary = self._search(scope=self._role(services=("edge-router",)))[0]
        self.assertEqual(summary.service, "edge-router")
        self.assertEqual(summary.name, "GET /checkout")
        self.assertEqual(summary.span_count, 1)
        self.assertFalse(summary.has_error,
                         "an error in a service the role cannot see was shown")

    def test_a_trace_with_no_visible_service_is_not_listed(self):
        self.assertEqual(
            self._search(scope=self._role(services=("payments",))), [])

    def test_a_service_exclusion_holds_in_every_answer(self):
        role = self._role(services=("*", "-billing-api"))
        self.assertEqual(
            [s.name for s in self.source.services(self.window, role)],
            ["edge-router", "payments"])
        trace = self.source.trace(TRACE_ID, self.window, role)
        self.assertEqual({span.service for span in trace.spans}, {"edge-router"})
        summary = self._search(scope=role)[0]
        self.assertFalse(summary.has_error)
        self.assertEqual(summary.span_count, 1)

    # --- choosing traces only by what the role may see ---

    def test_a_named_service_this_source_excludes_is_not_asked_for(self):
        """The route lets a service through when ANY source allows it, and
        Tempo pushed it as it came: a merged view listed the Tempo traces a
        service ran in where a rule excluded it in Tempo alone."""
        found = self._search(scope=self._role(services=("*", "-tempo:payments")),
                             service="payments")
        self.assertEqual(found, [])
        self.assertFalse([r for r in self.harness._requests
                          if r["path"].endswith("/api/search")])

    def test_every_condition_is_evaluated_on_a_visible_span(self):
        """TraceQL evaluates a `{ }` on one span. `status = error` alone
        matched an error in a service the role cannot see, and that trace was
        listed — as error-free — in the errors-only list."""
        self._search(scope=self._role(services=("*", "-billing-api")),
                     only_errors=True)
        self.assertEqual(
            self._traceql(),
            '{ (resource.service.name = "edge-router" || '
            'resource.service.name = "payments") && status = error }')

    def test_an_errors_only_row_needs_a_visible_error(self):
        """If Tempo ever answers with a trace whose only error is hidden,
        it is not listed as an error-free row of the errors-only list."""
        found = self._search(scope=self._role(services=("*", "-billing-api")),
                             only_errors=True)
        self.assertEqual(found, [])
        self.assertEqual(
            len(self._search(scope=self._role(), only_errors=True)), 1)

    def test_exact_grants_are_pushed_without_asking_tempo_for_names(self):
        self._search(scope=self._role(
            services=("billing-api", "payments", "-payments")))
        self.assertEqual(self._traceql(),
                         '{ resource.service.name = "billing-api" }')
        self.assertFalse([r for r in self.harness._requests
                          if "/search/tag/" in r["path"]])

    def test_a_granted_name_with_a_colon_is_pushed_as_a_name(self):
        """No source is called `unknown_service`, so the colon is part of
        the name — which only the configured names can tell."""
        scope = Scope(principal="p", containers=(), trace_containers=("*",),
                      services=("unknown_service:java", "billing-api"),
                      sources=frozenset({"tempo"}))
        self._search(scope=scope)
        self.assertEqual(
            self._traceql(),
            '{ (resource.service.name = "billing-api" || '
            'resource.service.name = "unknown_service:java") }')

    def test_the_matched_spans_are_asked_for(self):
        self._search()
        search = next(r for r in self.harness._requests
                      if r["path"].endswith("/api/search"))
        self.assertEqual(search["params"]["spss"], 100)

    def test_a_row_whose_root_is_hidden_is_timed_by_what_it_shows(self):
        """The trace's own start and duration are the root's: the list said
        120 ms for a trace whose visible part took 80, and ranked
        "slowest" by the hidden service's time."""
        summary = self._search(scope=self._role(services=("billing-api",)))[0]
        self.assertEqual(summary.duration_us, 80_000)
        self.assertEqual(summary.start,
                         dt.datetime.fromtimestamp(1785961664104674048 / 1e9,
                                                   tz=dt.timezone.utc))
        visible_root = self._search(scope=self._role())[0]
        self.assertEqual(visible_root.duration_us, 120_000)

    def test_an_older_tempo_s_single_spanset_times_it_too(self):
        from wdash.hub.adapters.tempo import _extent
        start, duration = _extent({"spanSet": {"spans": [
            {"startTimeUnixNano": "1000000000", "durationNanos": "5000000"},
            {"startTimeUnixNano": "1002000000", "durationNanos": "9000000"}]}})
        self.assertEqual(duration, 11_000)
        self.assertEqual(start.timestamp(), 1.0)

    def test_a_trace_says_how_many_spans_the_scope_hid(self):
        hidden = self.source.trace(TRACE_ID, self.window,
                                   self._role(services=("*", "-billing-api")))
        self.assertEqual(hidden.hidden, 1)
        self.assertEqual(self.source.trace(TRACE_ID, self.window,
                                           self._role()).hidden, 0)

    def test_a_service_rule_held_to_this_source_applies_in_every_answer(self):
        role = self._role(services=("tempo:billing-api",))
        self.assertEqual(
            [s.name for s in self.source.services(self.window, role)],
            ["billing-api"])
        trace = self.source.trace(TRACE_ID, self.window, role)
        self.assertEqual({span.service for span in trace.spans}, {"billing-api"})
        self.assertEqual([s.service for s in self._search(scope=role)],
                         ["billing-api"])

    def test_a_service_rule_for_another_source_is_not_pushed_down(self):
        self._search(scope=self._role(services=("billing-api", "jaeger:payments")))
        rendered = self._traceql()
        self.assertIn('"billing-api"', rendered)
        self.assertNotIn("payments", rendered)

    def test_a_service_rule_for_this_source_is_pushed_down_bare(self):
        self._search(scope=self._role(services=("tempo:payments",)))
        rendered = self._traceql()
        self.assertIn('= "payments"', rendered)
        self.assertNotIn("tempo:", rendered)

    def test_an_exact_grant_is_pushed_down_beside_an_exclusion(self):
        """The exclusion is left to the filter on the way out; the query
        asks for a superset of what the role may see, never a subset."""
        self._search(scope=self._role(services=("billing-api", "-payments")))
        rendered = self._traceql()
        self.assertIn('= "billing-api"', rendered)
        self.assertNotIn("payments", rendered)


if __name__ == "__main__":
    unittest.main()
