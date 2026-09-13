"""
Trace endpoint tests.

The source is NOT mocked: a fake Elasticsearch is used so the real adapter and
the real Scope logic run. Mocking the source would skip the very thing under
test — authorization filtering.

The roles are the built-in ones a new installation is given, read from its
store for real, so the whole chain from the stored role to the resolver to
User to Scope to adapter is exercised.
"""

import os
import sys
import unittest

from tests.support import ModelledES, grant, use_role
from tests.test_otel_shapes import COLLECTOR_SPAN_MAPPING, collector_span

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402

# Services mirroring the lab topology: application services plus infrastructure
APP_SERVICES = ["api-gateway", "auth-service", "payment-service"]
INFRA_SERVICES = ["postgres", "redis"]

LOG_MAPPING = {"@timestamp": {"type": "date"}, "message": {"type": "text"},
               "level": {"type": "keyword"}, "trace_id": {"type": "keyword"}}


def _hit(span_id, service, parent=None, status="Ok"):
    """One span of trace-1, in the shape the collector writes.

    It was `kind: SPAN_KIND_SERVER`, `duration_ns`, `status_code` and a flat
    `resource` — the shape no collector writes, which the trace search's
    own clauses assumed, so the two agreed with each other here and with
    nothing on a real cluster."""
    kind = "Client" if service in INFRA_SERVICES else "Server"
    return collector_span("trace-1", span_id, service, parent=parent, kind=kind,
                          code=status, duration_ms=1, seconds_ago=600,
                          name=f"{service} op")


class FakeES(ModelledES):
    """The lab's topology, answering the query it is sent.

    It returned every span whatever it was asked: the listing tests read the
    fixture back, not what a search would find.
    """

    TRACES = "otel-traces-000001"

    def __init__(self):
        super().__init__({
            self.TRACES: (COLLECTOR_SPAN_MAPPING, [_hit("root", "api-gateway")] + [
                _hit(f"s{i}", svc, parent="root")
                for i, svc in enumerate(APP_SERVICES[1:] + INFRA_SERVICES)]),
            "app-logs-000001": (LOG_MAPPING, []),
        })

    @property
    def spans(self):
        return self._indices[self.TRACES][1]

    @spans.setter
    def spans(self, hits):
        self._indices[self.TRACES][1][:] = hits


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "trace-test"


def session_for(role_name):
    """The identity a session carries, and nothing else.

    What the person may do is not in the cookie: it is resolved from the
    store on every request, through the mapping `use_role` or `grant` writes.
    """
    return {"id": "id-1", "email": f"{role_name}@example.com",
            "username": role_name, "groups": []}


class TraceRouteTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        # Point the hub at the fake cluster; adapter and scope stay REAL
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource
        fake = FakeES()
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(fake))
        hub.add_traces(ElasticsearchTraceSource(fake))
        self.app.hub = hub
        self.client = self.app.test_client()

    def login(self, role):
        # Authorization comes from the store, so the role has to exist there
        # — which it does: admin, developer and viewer are the built-in roles.
        use_role(self.app, role, role)
        data = session_for(role)
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]
        return data

    def services_for(self, role):
        self.login(role)
        response = self.client.get("/api/traces/services")
        self.assertEqual(response.status_code, 200)
        return {s["name"] for s in response.get_json()["services"]}

    # ---------- identity and permissions ----------

    def test_requires_authentication(self):
        for path in ("/traces", "/api/traces/services", "/api/traces/abc"):
            self.assertEqual(self.client.get(path).status_code, 302, path)

    def test_permission_gate(self):
        grant(self.app, "viewer", permissions=["logs:read"])   # no traces:read
        data = session_for("viewer")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]

        self.assertEqual(self.client.get("/api/traces/services").status_code, 403)
        self.assertEqual(self.client.get("/api/traces/abc").status_code, 403)
        self.assertEqual(self.client.get("/traces").status_code, 302)

    # ---------- service-level authorization ----------

    def test_admin_sees_every_service(self):
        seen = self.services_for("admin")
        for service in APP_SERVICES + INFRA_SERVICES:
            self.assertIn(service, seen)

    def test_developer_cannot_see_infrastructure_services(self):
        """The built-in developer role must not see infrastructure spans."""
        seen = self.services_for("developer")
        for service in APP_SERVICES:
            self.assertIn(service, seen, f"developer should have seen {service}")
        for service in INFRA_SERVICES:
            self.assertNotIn(service, seen, f"developer should NOT have seen {service}")

    def test_viewer_sees_only_its_single_service(self):
        self.assertEqual(self.services_for("viewer"), {"api-gateway"})

    def test_trace_spans_are_filtered_by_service(self):
        """Filtering must apply to spans as well as the service list."""
        self.login("developer")
        payload = self.client.get("/api/traces/trace-1").get_json()
        services = {s["service"] for s in payload["spans"]}
        self.assertTrue(services <= set(APP_SERVICES), f"leaked services: {services}")
        self.assertTrue(payload["scoped"], "a restricted scope must be reported to the user")

    def test_admin_trace_is_not_marked_scoped(self):
        self.login("admin")
        payload = self.client.get("/api/traces/trace-1").get_json()
        self.assertFalse(payload["scoped"])
        self.assertEqual(len(payload["spans"]), len(APP_SERVICES) + len(INFRA_SERVICES))

    def test_no_trace_stores_is_reported_not_silently_empty(self):
        grant(self.app, "developer", permissions=["traces:read", "logs:read"],
              trace_indices=[])
        data = session_for("developer")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]

        payload = self.client.get("/api/traces/services").get_json()
        self.assertEqual(payload["services"], [])
        self.assertEqual(payload["error_type"], "no_accessible_trace_stores")
        self.assertIn("suggestion", payload)

    # ---------- content ----------

    def test_waterfall_is_computed_server_side(self):
        self.login("admin")
        payload = self.client.get("/api/traces/trace-1").get_json()
        self.assertIn("waterfall", payload)
        self.assertEqual(payload["waterfall"][0]["depth"], 0)
        self.assertEqual(len(payload["waterfall"]), len(payload["spans"]))

    def test_missing_trace_returns_404_with_guidance(self):
        self.login("admin")

        # A search that returns nothing
        self.app.hub.traces()._es.spans = []
        response = self.client.get("/api/traces/nope")
        self.assertEqual(response.status_code, 404)
        payload = response.get_json()
        self.assertEqual(payload["error_type"], "trace_not_found")
        self.assertIn("suggestion", payload)

    def test_capabilities_are_declared(self):
        self.login("admin")
        payload = self.client.get("/api/traces/capabilities").get_json()
        self.assertTrue(payload["available"])
        self.assertIn("trace_lookup", payload["capabilities"])

    def test_page_renders_for_permitted_role(self):
        self.login("developer")
        response = self.client.get("/traces")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Traces", response.data)
        # A restricted scope must be visible; silent filtering is poor UX
        self.assertIn(b"payment-*", response.data)

    def test_missing_trace_source_is_reported(self):
        from wdash.hub import Hub
        self.app.hub = Hub()          # no registered source
        self.login("admin")
        response = self.client.get("/api/traces/services")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error_type"], "no_trace_source")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TraceSearchTest(TraceRouteTest):
    """Trace search — the thing that makes the page usable.

    Without it a user would have to already know a trace id, which is exactly
    what made the screen useless before.
    """

    def search(self, role, **params):
        self.login(role)
        query = "&".join(f"{k}={v}" for k, v in params.items())
        response = self.client.get("/api/traces" + (f"?{query}" if query else ""))
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def test_lists_traces_without_knowing_an_id(self):
        payload = self.search("admin")
        self.assertTrue(payload["traces"])
        self.assertIn("trace_id", payload["traces"][0])

    def test_summary_shape(self):
        """The wire contract. `source` names which backend answered — with
        several configured, "this trace is missing" and "you are looking at
        the wrong store" are different problems."""
        summary = self.search("admin")["traces"][0]
        self.assertEqual(
            sorted(summary),
            ["duration_us", "has_error", "name", "service", "source",
             "span_count", "start", "trace_id"])

    def test_service_filter_is_applied(self):
        payload = self.search("admin", service="api-gateway")
        self.assertEqual(payload["service"], "api-gateway")
        for trace in payload["traces"]:
            self.assertEqual(trace["service"], "api-gateway")

    def test_service_outside_scope_is_refused(self):
        """Asking for a service the role cannot see must not silently return all."""
        self.login("viewer")
        response = self.client.get("/api/traces?service=postgres")
        self.assertEqual(response.status_code, 403)

    def test_scope_filters_the_listing(self):
        """A viewer may only reach its own service, even without a filter."""
        for trace in self.search("viewer")["traces"]:
            self.assertEqual(trace["service"], "api-gateway")

    def test_permission_gate(self):
        grant(self.app, "viewer", permissions=["logs:read"])
        data = session_for("viewer")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]
        self.assertEqual(self.client.get("/api/traces").status_code, 403)

    def test_sort_is_validated(self):
        """An unknown sort must fall back rather than reaching the backend."""
        self.assertEqual(self.search("admin", sort="nonsense")["sort"], "recent")
        self.assertEqual(self.search("admin", sort="slowest")["sort"], "slowest")

    def test_limit_is_capped(self):
        self.assertLessEqual(len(self.search("admin", limit=9999)["traces"]), 100)

    def test_no_trace_stores_is_reported(self):
        grant(self.app, "developer", permissions=["traces:read", "logs:read"],
              trace_indices=[])
        data = session_for("developer")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]
        payload = self.client.get("/api/traces").get_json()
        self.assertEqual(payload["traces"], [])
        self.assertEqual(payload["error_type"], "no_accessible_trace_stores")

    def test_search_capability_is_declared(self):
        self.login("admin")
        payload = self.client.get("/api/traces/capabilities").get_json()
        self.assertTrue(payload["supports_search"])
        self.assertIn("trace_search", payload["capabilities"])

    def test_page_offers_the_listing(self):
        self.login("admin")
        page = self.client.get("/traces")
        self.assertIn(b"Recent traces", page.data)
        self.assertIn(b"service-row", page.data)      # services are clickable
        self.assertIn(b"trace-row", page.data)        # traces are clickable

    def test_listing_page_carries_no_detail_view(self):
        """Detail lives on its own page; duplicating it here would be dead weight."""
        self.login("admin")
        page = self.client.get("/traces")
        for gone in (b"Trace detail", b"traceResult", b"spanDetail"):
            self.assertNotIn(gone, page.data)


class TraceDetailPageTest(TraceRouteTest):
    """The dedicated trace page and the extra detail it carries."""

    def test_page_requires_permission(self):
        grant(self.app, "viewer", permissions=["logs:read"])
        data = session_for("viewer")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]
        self.assertEqual(self.client.get("/traces/trace-1").status_code, 302)

    def test_page_renders_with_the_trace_id(self):
        self.login("admin")
        page = self.client.get("/traces/trace-1")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"trace-1", page.data)
        self.assertIn(b"Where the time went", page.data)
        self.assertIn(b"Waterfall", page.data)
        self.assertIn(b"Span ID", page.data)          # span ids live here now

    def test_correlated_logs_section_follows_the_log_permission(self):
        """A user without logs:read must not be shown a log panel at all."""
        grant(self.app, "admin", permissions=["traces:read"])   # no logs:read
        data = session_for("admin")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]
        self.assertNotIn(b"Correlated logs", self.client.get("/traces/trace-1").data)

        self.login("admin")                            # has both
        self.assertIn(b"Correlated logs", self.client.get("/traces/trace-1").data)

    def test_correlated_logs_need_both_permissions(self):
        grant(self.app, "admin", permissions=["traces:read"])
        data = session_for("admin")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]
        self.assertEqual(
            self.client.get("/api/traces/trace-1/logs").status_code, 403)

    def test_service_breakdown_is_returned(self):
        self.login("admin")
        payload = self.client.get("/api/traces/trace-1").get_json()
        self.assertIn("service_breakdown", payload)
        rows = payload["service_breakdown"]
        self.assertTrue(rows)
        self.assertEqual(sorted(rows[0]),
                         ["error_count", "self_time_us", "service", "share", "span_count"])
        # Largest share first — the point of the panel is "look here".
        shares = [r["share"] for r in rows]
        self.assertEqual(shares, sorted(shares, reverse=True))

    def test_breakdown_shares_sum_to_one(self):
        self.login("admin")
        rows = self.client.get("/api/traces/trace-1").get_json()["service_breakdown"]
        self.assertAlmostEqual(sum(r["share"] for r in rows), 1.0, places=5)

    def test_unknown_trace_returns_404_for_logs(self):
        self.login("admin")
        self.app.hub.traces()._es.spans = []
        response = self.client.get("/api/traces/nope/logs")
        self.assertEqual(response.status_code, 404)


class TraceLookupAcrossSourcesTest(TraceRouteTest):
    """Looking a trace up BY ID must not depend on which source is first.

    A trace id is globally unique by construction, and nobody pasting one — or
    clicking a row in a merged list — knows which backend holds it. Answering
    from whichever source happened to be registered first reported a Jaeger
    trace as "not found in the selected time range" while it sat in the store
    next door.
    """

    class _Holder:
        """A trace source that holds exactly one trace."""

        backend = "stub"

        def __init__(self, name, trace_id, spans=1):
            from wdash.hub.source import Capability
            self.name = name
            self._trace_id = trace_id
            self._spans = spans
            self.capabilities = frozenset({Capability.TRACE_LOOKUP,
                                           Capability.TRACE_SEARCH,
                                           Capability.SERVICE_LIST})
            self.asked = []

        def supports(self, capability):
            return capability in self.capabilities

        def health(self):
            return True, "ok"

        def containers(self, scope):
            return [self.name]

        def services(self, window, scope):
            return []

        def search(self, query, scope):
            return []

        def trace(self, trace_id, window, scope):
            import datetime as dt

            from wdash.hub.models import Span, Trace
            self.asked.append(trace_id)
            if trace_id != self._trace_id:
                return None
            now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
            return Trace(trace_id=trace_id, spans=[
                Span(trace_id=trace_id, span_id=f"s{i}", name="op",
                     service=self.name, start=now, duration_us=100)
                for i in range(self._spans)])

    def _hub(self, *sources):
        from wdash.hub import Hub
        hub = Hub()
        for source in sources:
            hub.add_traces(source)
        self.app.hub = hub
        return hub

    def test_a_trace_in_the_second_source_is_found(self):
        first = self._Holder("first", "not-this-one")
        second = self._Holder("second", "wanted")
        self._hub(first, second)
        self.login("admin")

        response = self.client.get("/api/traces/wanted?time_range=24h")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["spans"]), 1)

    def test_every_source_is_asked(self):
        first = self._Holder("first", "not-this-one")
        second = self._Holder("second", "wanted")
        self._hub(first, second)
        self.login("admin")
        self.client.get("/api/traces/wanted?time_range=24h")
        self.assertEqual(first.asked, ["wanted"])
        self.assertEqual(second.asked, ["wanted"])

    def test_a_named_source_is_the_only_one_asked(self):
        """The click-through carries the source it came from, and honouring it
        keeps a merged page from fanning out on every row."""
        first = self._Holder("first", "wanted")
        second = self._Holder("second", "wanted")
        self._hub(first, second)
        self.login("admin")
        self.client.get("/api/traces/wanted?time_range=24h&source=second")
        self.assertEqual(first.asked, [])
        self.assertEqual(second.asked, ["wanted"])

    def test_a_trace_no_source_holds_is_still_not_found(self):
        """The fan-out must not turn absence into a blank success."""
        self._hub(self._Holder("first", "a"), self._Holder("second", "b"))
        self.login("admin")
        response = self.client.get("/api/traces/nowhere?time_range=24h")
        self.assertEqual(response.status_code, 404)

    def test_listing_without_a_source_asks_every_store_too(self):
        """A list that names no source is every store's list, as a lookup
        by id has always been every store's lookup. The page's picker starts
        on "All sources" and sends `*`, so this is the question the page
        asks; a request that named nothing used to be answered from
        whichever store was registered first, which is a shorter list with
        nothing to say it is short.
        """
        first = self._Holder("first", "a")
        second = self._Holder("second", "b")
        self._hub(first, second)
        self.login("admin")

        searched = []
        for holder in (first, second):
            holder.search = (lambda query, scope, name=holder.name:
                             searched.append(name) or [])

        self.client.get("/api/traces?time_range=24h")
        self.assertEqual(sorted(searched), ["first", "second"],
                         "an unfiltered list read one store")

    def test_a_split_trace_comes_back_whole(self):
        """Two backends holding halves of one trace is the case the fan-out
        exists for, and by-id lookup is where somebody meets it."""
        self._hub(self._Holder("first", "wanted", spans=2),
                  self._Holder("second", "wanted", spans=2))
        self.login("admin")
        payload = self.client.get(
            "/api/traces/wanted?time_range=24h").get_json()
        # Span ids collide between the two stubs, so the dedup leaves two.
        self.assertEqual(len(payload["spans"]), 2)


APM_PROPERTIES = {
    "trace": {"properties": {"id": {"type": "keyword"}}},
    "parent": {"properties": {"id": {"type": "keyword"}}},
    "processor": {"properties": {"event": {"type": "keyword"}}},
    "service": {"properties": {"name": {"type": "keyword"}}},
    "transaction": {"properties": {"id": {"type": "keyword"}}},
}


def _apm(trace, span_id, service, parent=None, entry=True, failed=False,
         seconds_ago=60, duration_us=1000):
    """One APM document, in the shape the lab's cluster holds. A transaction
    is a request a service handled; a span is a call it made."""
    import datetime as dt
    stamp = (dt.datetime.now(dt.timezone.utc)
             - dt.timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    kind = "transaction" if entry else "span"
    doc = {"_id": span_id, "@timestamp": stamp, "trace": {"id": trace},
           "service": {"name": service},
           "event": {"outcome": "failure" if failed else "success"},
           "processor": {"event": kind},
           kind: {"id": span_id, "name": f"{service} op",
                  "duration": {"us": duration_us}}}
    if parent:
        doc["parent"] = {"id": parent}
    return doc


def _apm_cluster():
    """trace-1 enters through the gateway, which calls auth and payments;
    payments calls postgres and redis. trace-2 is the same request with the
    payments transaction failing and the gateway not."""
    docs = []
    for trace, age, payments_failed in (("trace-1", 120, False),
                                        ("trace-2", 60, True)):
        root = f"{trace}-gw"
        docs += [
            _apm(trace, root, "api-gateway", seconds_ago=age, duration_us=9000),
            _apm(trace, f"{trace}-auth", "auth-service", root, seconds_ago=age - 1),
            _apm(trace, f"{trace}-pay", "payment-service", root,
                 failed=payments_failed, seconds_ago=age - 2, duration_us=4000),
            _apm(trace, f"{trace}-pg", "postgres", f"{trace}-pay", entry=False,
                 seconds_ago=age - 3),
            _apm(trace, f"{trace}-redis", "redis", f"{trace}-pay", entry=False,
                 seconds_ago=age - 3),
            # OpenTelemetry's name for a service that set none.
            _apm(trace, f"{trace}-unnamed", "unknown_service:java", root,
                 seconds_ago=age - 4),
        ]
    from tests.support import ModelledES
    return ModelledES({"apm-traces-000001": (APM_PROPERTIES, docs)})


class ServiceRuleTest(unittest.TestCase):
    """Service rules in the pattern language, as the routes apply them.

    Against a fake cluster that ANSWERS THE QUERY. The one the rest of this
    file uses returns every span whatever it is asked, and a test here
    asserted rows for a role allowed only a downstream service — rows a real
    cluster did not return, because the search required the root span beside
    the service rule.
    """

    def setUp(self):
        self.app = create_app(TestConfig)
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchTraceSource
        self.es = _apm_cluster()
        hub = Hub()
        hub.add_traces(ElasticsearchTraceSource(self.es))
        self.app.hub = hub
        self.client = self.app.test_client()

    def as_role(self, **boundaries):
        grant(self.app, "developer", permissions=["traces:read", "logs:read"],
              **boundaries)
        data = session_for("developer")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]

    def listed(self):
        return {s["name"] for s in
                self.client.get("/api/traces/services").get_json()["services"]}

    def rows(self, query=""):
        return self.client.get("/api/traces" + query).get_json()["traces"]

    # --- the service rules ---

    def test_a_service_the_role_excludes_is_refused(self):
        self.as_role(services=["*", "-postgres"])
        self.assertEqual(
            self.client.get("/api/traces?service=postgres").status_code, 403)
        self.assertEqual(
            self.client.get("/api/traces?service=redis").status_code, 200)

    def test_a_service_rule_counts_for_the_source_it_names(self):
        self.as_role(services=["elasticsearch-traces:postgres"])
        self.assertEqual(
            self.client.get("/api/traces?service=postgres").status_code, 200)
        self.as_role(services=["jaeger:postgres"])
        self.assertEqual(
            self.client.get("/api/traces?service=postgres").status_code, 403)

    def test_an_excluded_service_is_not_listed(self):
        self.as_role(services=["*", "-postgres"])
        names = self.listed()
        self.assertNotIn("postgres", names)
        self.assertIn("redis", names)

    def test_a_service_rule_held_to_this_source_applies_in_every_answer(self):
        self.as_role(services=["elasticsearch-traces:payment-service"])
        self.assertEqual(self.listed(), {"payment-service"})
        spans = self.client.get("/api/traces/trace-1").get_json()["spans"]
        self.assertEqual({s["service"] for s in spans}, {"payment-service"})
        rows = self.rows()
        self.assertEqual({t["trace_id"] for t in rows}, {"trace-1", "trace-2"})
        self.assertEqual({t["service"] for t in rows}, {"payment-service"})

    def test_a_service_name_with_a_colon_is_granted_by_its_name(self):
        """A colon qualifies a rule only when a source has that name, and no
        source is called `unknown_service`. The route has to pass the
        configured names for that to be known."""
        self.as_role(services=["unknown_service:java"])
        self.assertEqual(self.listed(), {"unknown_service:java"})
        self.assertEqual({t["service"] for t in self.rows()},
                         {"unknown_service:java"})

    def test_such_names_are_excluded_by_their_name_too(self):
        self.as_role(services=["*", "-unknown_service:*"])
        self.assertNotIn("unknown_service:java", self.listed())
        self.assertIn("redis", self.listed())

    # --- a trace whose root the role cannot see ---

    def test_a_trace_entering_through_a_hidden_service_is_listed(self):
        """The search required the ROOT span beside the service rule, so a
        role that may not see the gateway got no trace at all — every
        request enters through it. Measured on the lab cluster: 0 rows for
        `payment-service` before, 50 after."""
        self.as_role(services=["*", "-api-gateway"])
        rows = self.rows()
        self.assertEqual({t["trace_id"] for t in rows}, {"trace-1", "trace-2"})
        self.assertNotIn("api-gateway", {t["service"] for t in rows})

    def test_such_a_trace_is_described_by_its_earliest_visible_entry(self):
        self.as_role(services=["payment-service", "auth-service"])
        rows = {t["trace_id"]: t for t in self.rows()}
        # auth-service starts a second before payment-service in both.
        self.assertEqual(rows["trace-1"]["service"], "auth-service")

    def test_the_root_still_describes_a_trace_when_it_is_visible(self):
        self.as_role(services=["api-gateway", "payment-service"])
        self.assertEqual({t["service"] for t in self.rows()}, {"api-gateway"})

    def test_errors_only_finds_a_visible_failure_below_a_hidden_root(self):
        self.as_role(services=["payment-service"])
        rows = self.rows("?errors=1")
        self.assertEqual([t["trace_id"] for t in rows], ["trace-2"])
        self.assertTrue(rows[0]["has_error"])

    # --- saying what was hidden ---

    def test_a_trace_an_exclusion_narrowed_says_so(self):
        """It asked whether `*` was in the list, so a role of `*` beside
        `-postgres` lost every postgres span and was told nothing was
        hidden."""
        self.as_role(services=["*", "-postgres"])
        payload = self.client.get("/api/traces/trace-1").get_json()
        self.assertNotIn("postgres", {s["service"] for s in payload["spans"]})
        self.assertTrue(payload["scoped"])

    def test_a_rule_that_hid_nothing_here_does_not_say_so(self):
        """A rule that could hide something is not a trace that lost
        spans: the flag guessed from the rules, so `-mongo` on a trace
        without mongo said spans were hidden."""
        self.as_role(services=["*", "-mongo"])
        self.assertFalse(
            self.client.get("/api/traces/trace-1").get_json()["scoped"])

    def test_a_trace_nothing_narrowed_does_not_say_so(self):
        self.as_role(services=["*"])
        self.assertFalse(
            self.client.get("/api/traces/trace-1").get_json()["scoped"])

    def test_the_page_says_an_exclusion_narrows_it(self):
        self.as_role(services=["*", "-postgres"])
        page = self.client.get("/traces").data
        self.assertIn(b"Your role can see spans from", page)
        self.assertIn(b"-postgres", page)

    def test_the_page_says_an_exclusion_of_colon_names_narrows_it(self):
        self.as_role(services=["*", "-unknown_service:*"])
        self.assertIn(b"Your role can see spans from",
                      self.client.get("/traces").data)

    def test_the_page_says_so_when_the_role_sees_no_service(self):
        self.as_role(services=[])
        self.assertIn(b"can see spans from:\n    no service",
                      self.client.get("/traces").data)

    def test_the_page_does_not_call_every_service_narrowed(self):
        for services in (["*"], ["*", "api-*"]):
            self.as_role(services=services)
            self.assertNotIn(b"Your role can see spans from",
                             self.client.get("/traces").data, services)

    # --- empty answers ---

    def test_a_store_the_role_cannot_reach_is_explained(self):
        """A role whose trace stores match nothing here got an empty list,
        which reads as a quiet time range."""
        self.as_role(trace_indices=["otel-*"])
        for path, key in (("/api/traces/services", "services"),
                          ("/api/traces", "traces")):
            payload = self.client.get(path).get_json()
            self.assertEqual(payload[key], [], path)
            self.assertEqual(payload["error_type"],
                             "no_accessible_trace_stores", path)
            self.assertIn("elasticsearch-traces", payload["suggestion"], path)

    def test_a_source_with_no_store_at_all_is_not_blamed_on_the_role(self):
        """A cluster with no trace index yet, or whose index list could not
        be read, answers an empty store list too. That told an administrator
        to go and fix a role that was fine."""
        self.es._indices.clear()
        self.as_role(trace_indices=["*"])
        for path in ("/api/traces/services", "/api/traces"):
            self.assertNotIn("error_type", self.client.get(path).get_json(), path)

    def test_an_empty_answer_from_a_reachable_store_is_not_blamed_on_the_role(self):
        self.as_role(services=["nothing-*"])
        for path in ("/api/traces/services", "/api/traces"):
            self.assertNotIn("error_type", self.client.get(path).get_json(), path)

    def test_a_role_with_no_trace_store_is_told_so_by_the_trace_list_too(self):
        """That branch sent no suggestion, so the list said "No traces
        match." beside a service list that explained itself."""
        self.as_role(trace_indices=[])
        payload = self.client.get("/api/traces").get_json()
        self.assertEqual(payload["error_type"], "no_accessible_trace_stores")
        self.assertIn("no trace stores", payload["suggestion"])


class _Refused:
    """A requests session for a backend nothing answers on."""

    def get(self, url, **kwargs):
        raise ConnectionError(f"connection refused: {url}")


class _SameApp(unittest.TestCase):
    """TraceRouteTest's application and sign-in, without running its tests
    again under another name."""

    setUp = TraceRouteTest.setUp
    login = TraceRouteTest.login


class FailureReachesThePageTest(_SameApp):
    """A trace backend that could not answer, as the page is told it.

    Jaeger and Tempo caught their own failures and answered with what
    nothing looks like, so the route's 503 could not fire. Measured with each
    pointed at a closed port: the service list 200 [], the trace list 200 [],
    and a trace link 404 "Trace not found in the selected time range" —
    advice to widen a time range during an outage.
    """

    def _only(self, *sources):
        from wdash.hub import Hub
        hub = Hub()
        for source in sources:
            hub.add_traces(source)
        self.app.hub = hub
        self.login("admin")

    @staticmethod
    def _down():
        from wdash.hub.adapters.jaeger import JaegerTraceSource
        from wdash.hub.adapters.tempo import TempoTraceSource
        return (JaegerTraceSource("http://127.0.0.1:9", name="down-jaeger",
                                  session=_Refused()),
                TempoTraceSource("http://127.0.0.1:9", name="down-tempo",
                                 session=_Refused()))

    def test_a_single_backend_that_is_down_is_a_503_everywhere(self):
        for down in self._down():
            self._only(down)
            for path in ("/api/traces/services", "/api/traces",
                         "/api/traces/0af7651916cd43dd8448eb211c80319c"):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 503, (down.name, path))
                body = response.get_json()
                self.assertEqual(body["error_type"], "trace_source_error")
                self.assertIn("connection refused", body["details"])

    def test_the_logs_of_a_trace_that_could_not_be_looked_up_are_a_503(self):
        """The lookup ran outside any handler here: once the adapter
        raised, the page would have had a 500 with no body to read."""
        from wdash.hub.adapters import ElasticsearchLogSource
        jaeger, _ = self._down()
        self._only(jaeger)
        self.app.hub.add_logs(ElasticsearchLogSource(FakeES()))
        response = self.client.get(
            "/api/traces/0af7651916cd43dd8448eb211c80319c/logs")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error_type"], "trace_source_error")
        self.assertIn("connection refused", response.get_json()["details"])

    def _beside_a_live_source(self):
        from wdash.hub.adapters import ElasticsearchTraceSource
        live = ElasticsearchTraceSource(FakeES(), name="live")
        jaeger, _ = self._down()
        self._only(live, jaeger)

    def test_a_merged_list_says_which_backend_is_missing(self):
        self._beside_a_live_source()
        for path, key in (("/api/traces/services?source=*", "services"),
                          ("/api/traces?source=*", "traces")):
            body = self.client.get(path).get_json()
            self.assertTrue(body[key], path)
            self.assertTrue(body["partial"], path)
            self.assertTrue(any("down-jaeger" in w and "connection refused" in w
                                for w in body["warnings"]), body["warnings"])

    def test_a_complete_answer_says_it_is_complete(self):
        self.login("admin")
        for path in ("/api/traces/services", "/api/traces"):
            body = self.client.get(path).get_json()
            self.assertFalse(body["partial"], path)
            self.assertEqual(body["warnings"], [], path)

    def test_a_split_trace_with_a_backend_down_says_so(self):
        self._beside_a_live_source()
        body = self.client.get("/api/traces/trace-1").get_json()
        self.assertEqual(len(body["spans"]), 5)
        self.assertTrue(body["partial"])
        self.assertTrue(any("down-jaeger" in w for w in body["warnings"]))

    def test_a_trace_the_down_backend_may_hold_is_not_called_missing(self):
        self._beside_a_live_source()
        response = self.client.get("/api/traces/0af7651916cd43dd8448eb211c80319c")
        self.assertEqual(response.status_code, 503)
        self.assertIn("down-jaeger", response.get_json()["details"])

    def test_every_backend_down_is_a_503_not_an_empty_merge(self):
        self._only(*self._down())
        for path in ("/api/traces/services?source=*", "/api/traces?source=*",
                     "/api/traces/0af7651916cd43dd8448eb211c80319c"):
            self.assertEqual(self.client.get(path).status_code, 503, path)


class MergedSlowestRouteTest(_SameApp):
    def test_slowest_over_every_source_is_the_slowest(self):
        """The picker's first choice is every source."""
        import datetime as dt

        from wdash.hub import Hub
        from wdash.hub.models import TraceSummary
        from tests.test_trace_fanout import StubTraceSource
        now = dt.datetime.now(dt.timezone.utc)
        slow = TraceSummary(trace_id="slow", service="batch", name="op",
                            start=now - dt.timedelta(minutes=30),
                            duration_us=9_000_000)
        fast = TraceSummary(trace_id="fast", service="edge", name="op",
                            start=now, duration_us=10)
        hub = Hub()
        hub.add_traces(StubTraceSource("m1", summaries=[slow]))
        hub.add_traces(StubTraceSource("m2", summaries=[fast]))
        self.app.hub = hub
        self.login("admin")
        body = self.client.get("/api/traces?source=*&sort=slowest&limit=1").get_json()
        self.assertEqual([t["trace_id"] for t in body["traces"]], ["slow"])


class CorrelatedLogFailureTest(_SameApp):
    """The logs of a trace, when the log search could not run.

    The adapter turns a failed search into a page marked partial with the
    reason, and the route dropped both: 200 with no records, which the page
    words as "No log records carry this trace id. Logs need a trace_id
    field" — a failure explained as a missing field.
    """

    class _LogsDown(ModelledES):
        def search(self, index=None, **kwargs):
            raise ConnectionError("log cluster unreachable")

    def setUp(self):
        TraceRouteTest.setUp(self)
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource
        hub = Hub()
        hub.add_traces(ElasticsearchTraceSource(FakeES()))
        hub.add_logs(ElasticsearchLogSource(self._LogsDown(
            {"app-logs-000001": (LOG_MAPPING, [])})))
        self.app.hub = hub
        self.login("admin")

    def test_a_failed_log_search_says_it_failed(self):
        body = self.client.get("/api/traces/trace-1/logs").get_json()
        self.assertEqual(body["records"], [])
        self.assertTrue(body["partial"])
        self.assertTrue(any("log cluster unreachable" in w for w in body["warnings"]),
                        body["warnings"])

    def test_a_search_that_ran_is_not_partial(self):
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource
        hub = Hub()
        hub.add_traces(ElasticsearchTraceSource(FakeES()))
        hub.add_logs(ElasticsearchLogSource(StubLogCluster()))
        self.app.hub = hub
        body = self.client.get("/api/traces/trace-1/logs").get_json()
        self.assertFalse(body["partial"])
        self.assertEqual(body["warnings"], [])


class StubLogCluster(ModelledES):
    """A log index that answers, with no records: the query model knows no
    `match`, which a log search sends, so the answer is fixed."""

    def __init__(self):
        super().__init__({"app-logs-000001": (LOG_MAPPING, [])})

    def search(self, index=None, **kwargs):
        return {"took": 1, "timed_out": False,
                "hits": {"total": {"value": 0}, "hits": []}}
