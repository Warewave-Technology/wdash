"""
Jaeger against the trace contract, plus what is its own problem.

Every shape in the fixture below was copied from a running Jaeger, not from
memory. The last time a schema in this codebase was written from belief, every
field came back empty and the fixture agreed with it.
"""

import datetime as dt
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conformance import Harness, TraceSourceConformance  # noqa: E402

from wdash.hub import Scope  # noqa: E402
from wdash.hub.adapters.jaeger import JaegerTraceSource  # noqa: E402
from wdash.hub.source import Capability  # noqa: E402

SERVICES = ["billing-api", "edge-router", "payments"]

#: One trace as Jaeger returns it. Note where the service name is, and what
#: unit the times are in — both were adapter bugs waiting to happen.
TRACE = {
    "traceID": "32dcca60c81e511ea65f2a2807837dda",
    "spans": [
        {"traceID": "32dcca60c81e511ea65f2a2807837dda",
         "spanID": "4fb07d2b22021d45",
         "operationName": "GET /checkout",
         "references": [],
         "startTime": 1785960193271375,     # microseconds
         "duration": 120001,                # microseconds
         "tags": [{"key": "http.route", "type": "string", "value": "GET /checkout"},
                  {"key": "otel.status_code", "type": "string", "value": "OK"},
                  {"key": "span.kind", "type": "string", "value": "server"}],
         "logs": [], "processID": "p1", "warnings": None},
        {"traceID": "32dcca60c81e511ea65f2a2807837dda",
         "spanID": "b36502ca8950f78d",
         "operationName": "POST /charge",
         "references": [{"refType": "CHILD_OF",
                         "traceID": "32dcca60c81e511ea65f2a2807837dda",
                         "spanID": "4fb07d2b22021d45"}],
         "startTime": 1785960193281375,
         "duration": 80000,
         "tags": [{"key": "error", "type": "bool", "value": True},
                  {"key": "otel.status_code", "type": "string", "value": "ERROR"},
                  {"key": "span.kind", "type": "string", "value": "client"}],
         "logs": [], "processID": "p2", "warnings": None},
    ],
    # The service name lives HERE, not on the span.
    "processes": {"p1": {"serviceName": "edge-router", "tags": []},
                  "p2": {"serviceName": "billing-api", "tags": []}},
    "warnings": None,
}


class FakeResponse:
    def __init__(self, payload=None, status_code=200, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload or {})

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeJaeger(Harness):
    """Jaeger's query API, enough of it."""

    def __init__(self):
        self._requests = []
        self._fail_next = False
        self._trace_found = True

    # --- harness contract ---

    def requests(self):
        # The service list is how the adapter learns what exists; it is not a
        # data query, and counting it would make "issued no query" impossible
        # to state.
        return [request for request in self._requests
                if not request["path"].endswith("/api/services")]

    def reset(self):
        self._requests = []

    def containers(self):
        return ["jaeger"]

    def fail_next(self):
        self._fail_next = True

    def no_trace(self):
        self._trace_found = False

    def mentions(self, request, text):
        return text in json.dumps(request, default=str)

    def carries_window(self, request, window):
        params = request.get("params") or {}
        start = params.get("start")
        if not start:
            return False
        # Microseconds. Nanoseconds would be a thousand times too large and
        # produce an empty window rather than an error.
        return abs(int(start) / 1_000_000 - window.start.timestamp()) < 2

    # --- the requests session the adapter holds ---

    def get(self, url, params=None, headers=None, auth=None, timeout=None,
            verify=None):
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1]
        self._requests.append({"path": path, "params": dict(params or {}),
                               "headers": dict(headers or {})})

        if self._fail_next:
            self._fail_next = False
            return FakeResponse(status_code=503, text="unavailable")

        if path.endswith("/api/services"):
            return FakeResponse({"data": list(SERVICES), "total": len(SERVICES)})

        if "/api/traces/" in path:
            # Real Jaeger answers 404 for an id it does not hold, and the
            # first version of this fake returned the fixture for ANY id —
            # which made "a missing trace is None" impossible to fail.
            requested = path.rsplit("/", 1)[-1]
            if not self._trace_found or requested != TRACE["traceID"]:
                return FakeResponse(
                    status_code=404,
                    payload={"data": None,
                             "errors": [{"code": 404, "msg": "trace not found"}]})
            return FakeResponse({"data": [TRACE], "total": 1})

        if path.endswith("/api/traces"):
            service = (params or {}).get("service")
            if not service:
                # Jaeger's actual behaviour, and the reason the adapter fans
                # out rather than sending an unqualified query.
                return FakeResponse(
                    status_code=400,
                    text="parameter 'service' is required")
            return FakeResponse({"data": [TRACE], "total": 1})

        return FakeResponse({"data": []})


class JaegerConformanceTest(TraceSourceConformance, unittest.TestCase):
    def build(self):
        harness = FakeJaeger()
        return JaegerTraceSource("http://jaeger:16686", name="jaeger",
                                 session=harness), harness


class JaegerSpecificTest(unittest.TestCase):
    """The parts that are Jaeger's own problem rather than the hub's."""

    def setUp(self):
        self.harness = FakeJaeger()
        self.source = JaegerTraceSource("http://jaeger:16686", name="jaeger",
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

    def _sent(self):
        return [r for r in self.harness._requests
                if r["path"].endswith("/api/traces")]

    # --- the mandatory service ---

    def test_an_unqualified_search_never_asks_without_a_service(self):
        """Jaeger answers HTTP 400 to `/api/traces` with no service. Sending
        one anyway would turn every unfiltered page load into an error."""
        self._search()
        self.assertTrue(self._sent())
        for request in self._sent():
            self.assertTrue(request["params"].get("service"),
                            "a query went out with no service")

    def test_an_unqualified_search_covers_every_service(self):
        self._search()
        asked = {r["params"]["service"] for r in self._sent()}
        self.assertEqual(asked, set(SERVICES))

    def test_the_service_fan_out_is_bounded(self):
        """An installation with hundreds of services would otherwise turn one
        page load into hundreds of round trips."""
        source = JaegerTraceSource("http://jaeger:16686", session=self.harness,
                                   service_fanout=2)
        source.search(self._query(), Scope.unrestricted())
        self.assertEqual(len(self._sent()), 2)

    def test_a_named_service_asks_once(self):
        self._search(service="billing-api")
        self.assertEqual([r["params"]["service"] for r in self._sent()],
                         ["billing-api"])

    def test_a_service_the_scope_forbids_is_not_asked_for(self):
        """Asking and filtering afterwards leaks the fact that it exists, and
        wastes a round trip proving it."""
        self._search(service="billing-api",
                     scope=Scope(principal="p", containers=("*",),
                                 trace_containers=("*",),
                                 services=("edge-*",),
                                 permissions=frozenset({"traces:read"})))
        self.assertEqual(self._sent(), [])

    # --- the shapes that were bugs waiting to happen ---

    def test_the_service_comes_from_the_process(self):
        """It is not on the span. Reading it there gets an empty string."""
        trace = self.source.trace(TRACE["traceID"], self.window,
                                  Scope.unrestricted())
        self.assertEqual(sorted(span.service for span in trace.spans),
                         ["billing-api", "edge-router"])

    def test_times_are_read_as_microseconds(self):
        """Nanoseconds would put every span in 1970 and every duration into
        the thousands of seconds."""
        trace = self.source.trace(TRACE["traceID"], self.window,
                                  Scope.unrestricted())
        root = trace.root
        self.assertEqual(root.duration_us, 120001)
        self.assertEqual(root.start.year, 2026)

    def test_the_window_is_sent_in_microseconds(self):
        self._search()
        params = self._sent()[0]["params"]
        self.assertAlmostEqual(int(params["start"]) / 1_000_000,
                               self.window.start.timestamp(), delta=2)

    def test_the_parent_link_comes_from_the_references(self):
        """A flat list of spans is a waterfall with no shape."""
        trace = self.source.trace(TRACE["traceID"], self.window,
                                  Scope.unrestricted())
        child = next(s for s in trace.spans if s.name == "POST /charge")
        self.assertEqual(child.parent_span_id, "4fb07d2b22021d45")
        self.assertEqual(len(trace.waterfall()), 2)

    def test_a_failed_span_is_recognised(self):
        trace = self.source.trace(TRACE["traceID"], self.window,
                                  Scope.unrestricted())
        self.assertTrue(trace.has_error)
        failed = [s.name for s in trace.spans if s.failed]
        self.assertEqual(failed, ["POST /charge"])

    def test_a_native_jaeger_error_tag_is_enough(self):
        """A store fed by a Jaeger client has `error: true` and no
        `otel.status_code`."""
        self.assertEqual(
            self.source._status({"error": True}), "ERROR")
        self.assertEqual(
            self.source._status({"error": "true"}), "ERROR")

    # --- volume ---

    def test_the_service_list_does_not_invent_span_counts(self):
        """`/api/metrics/calls` answers HTTP 501 unless a metrics backend is
        wired up. A count derived from a sample of fetched traces, presented
        as the volume of a service, is worse than no count."""
        services = self.source.services(self.window, Scope.unrestricted())
        self.assertEqual(sorted(s.name for s in services), sorted(SERVICES))
        self.assertEqual({s.span_count for s in services}, {0})

    def test_a_search_result_carries_a_real_span_count(self):
        """Unlike Elasticsearch, Jaeger returns whole traces from a search,
        so this one is known rather than None."""
        self.assertEqual(self._search()[0].span_count, 2)

    # --- errors and absence ---

    def test_a_missing_trace_is_none_rather_than_an_empty_one(self):
        """An empty waterfall reads as "this request did nothing"."""
        self.harness.no_trace()
        self.assertIsNone(self.source.trace(TRACE["traceID"], self.window,
                                            Scope.unrestricted()))

    def test_a_missing_trace_is_not_logged_as_a_failure(self):
        """404 is Jaeger saying "I do not hold that", which is an answer.

        Treated as an error it still returns None — so the return value cannot
        tell the two apart — but every mistyped trace id in the URL bar writes
        an ERROR line, and a log full of non-problems is a log nobody reads.
        """
        self.harness.no_trace()
        with self.assertNoLogs("wdash.hub.adapters.jaeger", level="ERROR"):
            self.source.trace(TRACE["traceID"], self.window,
                              Scope.unrestricted())

    def test_a_trace_whose_spans_the_scope_hides_is_none(self):
        trace = self.source.trace(
            TRACE["traceID"], self.window,
            Scope(principal="p", containers=("*",), trace_containers=("*",),
                  services=("nothing-matches",),
                  permissions=frozenset({"traces:read"})))
        self.assertIsNone(trace)

    def test_a_backend_error_does_not_take_the_page_down(self):
        self.harness.fail_next()
        self.assertEqual(self.source.services(self.window,
                                              Scope.unrestricted()), [])

    def test_health_reports_the_reason(self):
        self.harness.fail_next()
        healthy, detail = self.source.health()
        self.assertFalse(healthy)
        self.assertTrue(detail)

    def test_something_that_is_not_jaeger_is_not_called_healthy(self):
        """Pointing a Jaeger source at another service that answers 200 would
        otherwise look configured and fail on every query."""
        class NotJaeger(FakeJaeger):
            def get(self, url, **kwargs):
                return FakeResponse({"status": "ok"})

        source = JaegerTraceSource("http://something:16686", session=NotJaeger())
        healthy, _ = source.health()
        self.assertFalse(healthy)

    # --- what the backend is asked to do rather than what we do after ---

    def test_errors_only_is_pushed_into_the_query(self):
        """A limit applied by Jaeger has already chosen its traces, so
        filtering afterwards returns a short page of the wrong ones."""
        self._search(only_errors=True)
        tags = self._sent()[0]["params"].get("tags")
        self.assertEqual(json.loads(tags), {"error": "true"})

    def test_a_minimum_duration_is_pushed_into_the_query(self):
        self._search(min_duration_us=250000)
        self.assertEqual(self._sent()[0]["params"]["minDuration"], "250000us")

    def test_an_operation_name_is_pushed_into_the_query(self):
        self._search(name="GET /checkout")
        self.assertEqual(self._sent()[0]["params"]["operation"], "GET /checkout")

    def test_the_merged_list_is_sorted_and_limited(self):
        """Each service's request honours the limit on its own, so the merged
        list is as many times too long as there are services."""
        found = self._search(limit=2)
        self.assertEqual(len(found), 2)

    # --- the store and service boundaries ---

    @staticmethod
    def _role(stores=("*",), services=None, containers=()):
        return Scope(principal="p", containers=containers,
                     trace_containers=stores, services=services,
                     permissions=frozenset({"traces:read"}))

    def test_a_role_granted_only_elasticsearch_indices_reads_nothing_here(self):
        """Jaeger asked whether the role had any LOG container, so a role
        granted `otel-traces-*` and every log index read all of Jaeger."""
        role = self._role(stores=("otel-traces-*",), containers=("*",))
        self.assertEqual(self.source.containers(role), [])
        self.assertEqual(self.source.services(self.window, role), [])
        self.assertEqual(self._search(scope=role), [])
        self.assertIsNone(self.source.trace(TRACE["traceID"], self.window, role))
        self.assertEqual(self.harness._requests, [],
                         "Jaeger was asked on behalf of a role it is closed to")

    def test_the_store_is_granted_by_the_source_name(self):
        for stores in (("*",), ("jaeger",), ("jae*",), ("jaeger:*",)):
            role = self._role(stores=stores)
            self.assertEqual(self.source.containers(role), ["jaeger"], stores)
            self.assertTrue(self._search(scope=role), stores)

    def test_an_exclusion_of_the_store_holds(self):
        role = self._role(stores=("*", "-jaeger"))
        self.assertEqual(self._search(scope=role), [])
        self.assertIsNone(self.source.trace(TRACE["traceID"], self.window, role))

    def test_a_service_exclusion_holds_in_every_answer(self):
        role = self._role(services=("*", "-billing-api"))
        self.assertEqual(
            [s.name for s in self.source.services(self.window, role)],
            ["edge-router", "payments"])
        trace = self.source.trace(TRACE["traceID"], self.window, role)
        self.assertEqual({span.service for span in trace.spans}, {"edge-router"})
        self._search(scope=role)
        self.assertEqual({r["params"]["service"] for r in self._sent()},
                         {"edge-router", "payments"})

    def test_a_named_service_the_role_excludes_is_not_asked_for(self):
        self._search(scope=self._role(services=("*", "-payments")),
                     service="payments")
        self.assertEqual(self._sent(), [])

    def test_a_trace_says_how_many_spans_the_scope_hid(self):
        hidden = self.source.trace(TRACE["traceID"], self.window,
                                   self._role(services=("*", "-billing-api")))
        self.assertEqual(hidden.hidden, 1)
        self.assertEqual(self.source.trace(TRACE["traceID"], self.window,
                                           self._role()).hidden, 0)

    def test_a_named_service_granted_for_this_source_is_asked_for(self):
        self._search(scope=self._role(services=("jaeger:payments",)),
                     service="payments")
        self.assertEqual([r["params"]["service"] for r in self._sent()],
                         ["payments"])

    def test_a_service_rule_held_to_this_source_applies_in_every_answer(self):
        role = self._role(services=("jaeger:billing-api",))
        self.assertEqual(
            [s.name for s in self.source.services(self.window, role)],
            ["billing-api"])
        trace = self.source.trace(TRACE["traceID"], self.window, role)
        self.assertEqual({span.service for span in trace.spans}, {"billing-api"})
        self.assertEqual({s.service for s in self._search(scope=role)},
                         {"billing-api"})

    def test_a_service_rule_for_another_source_does_not_apply(self):
        role = self._role(services=("tempo:billing-api", "edge-router"))
        self.assertEqual(
            [s.name for s in self.source.services(self.window, role)],
            ["edge-router"])


if __name__ == "__main__":
    unittest.main()
