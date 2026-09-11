"""
Trace endpoint tests.

The source is NOT mocked: a fake Elasticsearch is used so the real adapter and
the real Scope logic run. Mocking the source would skip the very thing under
test — authorization filtering.

Roles are loaded from `config/rbac.yaml` for real, so the whole chain from yaml
to User to session to Scope to adapter is exercised.
"""

import os
import sys
import unittest

from tests.support import grant, use_role, search_body

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.models import User  # noqa: E402

RBAC = os.path.join(os.path.dirname(__file__), "..", "config", "rbac.yaml")

# Services mirroring the lab topology: application services plus infrastructure
APP_SERVICES = ["api-gateway", "auth-service", "payment-service"]
INFRA_SERVICES = ["postgres", "redis"]

OTEL_MAPPING = {
    "otel-traces-000001": {"mappings": {"properties": {
        "trace_id": {"type": "keyword"}, "span_id": {"type": "keyword"},
    }}}
}


def _hit(span_id, service, parent=None, status="OK"):
    return {
        "_index": "otel-traces-000001", "_id": span_id,
        "_source": {
            "@timestamp": "2026-08-04T10:00:00.000Z",
            "trace_id": "trace-1", "span_id": span_id, "parent_span_id": parent,
            "name": f"{service} op", "kind": "SPAN_KIND_SERVER",
            "duration_ns": 1_000_000, "status_code": status,
            "resource": {"service.name": service}, "attributes": {},
        },
    }


class FakeES:
    """A fake cluster returning a fixed trace and service distribution."""

    def __init__(self):
        self.spans = [_hit("root", "api-gateway")] + [
            _hit(f"s{i}", svc, parent="root")
            for i, svc in enumerate(APP_SERVICES[1:] + INFRA_SERVICES)
        ]

    def ping(self):
        return True

    @property
    def cat(self):
        class Cat:
            def indices(self, **kw):
                return [{"index": "otel-traces-000001"}, {"index": "app-logs-000001"}]
        return Cat()

    @property
    def indices(self):
        class Indices:
            def get_mapping(self, index=None, **kw):
                return OTEL_MAPPING
        return Indices()

    def search(self, index=None, **kwargs):
        body = search_body(kwargs)
        if body.get("size") == 0:
            # service aggregation
            counts = {}
            for hit in self.spans:
                name = hit["_source"]["resource"]["service.name"]
                counts[name] = counts.get(name, 0) + 1
            return {"hits": {"total": {"value": 0}, "hits": []},
                    "aggregations": {"services": {"buckets": [
                        {"key": n, "doc_count": c, "failed": {"doc_count": 0}}
                        for n, c in sorted(counts.items())
                    ]}}}
        return {"hits": {"hits": self.spans, "total": {"value": len(self.spans)}}, "took": 1}


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "trace-test"
    RBAC_CONFIG_FILE = RBAC


def session_for(role_name):
    """Build session data from a real role in rbac.yaml."""
    user = User("id-1", f"{role_name}@example.com", role_name, groups=[])
    user.load_rbac_config(RBAC)
    assert user.role is not None
    # Pick the role directly, without relying on the user mapping
    import yaml
    with open(RBAC) as fh:
        config = yaml.safe_load(fh)
    role = config["roles"][role_name]
    return {
        "id": "id-1", "email": f"{role_name}@example.com", "username": role_name,
        "groups": [], "role": role_name,
        "permissions": role.get("permissions", []),
        "allowed_indices": role.get("indices", []),
        "allowed_trace_indices": role.get("trace_indices", []),
        "allowed_services": role.get("services", []),
    }


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
        # Authorization comes from the store now, so the role has to exist
        # there — which it does: the store seeds from the same rbac.yaml.
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
        """The developer role in rbac.yaml must not see infrastructure spans."""
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

    def test_listing_without_a_source_does_not_fan_out(self):
        """The distinction is deliberate, and it is not symmetric.

        Looking a trace up BY ID has one right answer wherever it lives, so
        the lookup asks everywhere. A LIST has no such id: fanning out by
        default would make every unfiltered page load query every backend,
        and the picker sends a source as soon as there is more than one to
        choose from.
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
        self.assertEqual(searched, ["first"],
                         "an unfiltered list queried every backend")

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


class ServiceRuleTest(unittest.TestCase):
    """Service rules in the pattern language, as the routes apply them."""

    setUp = TraceRouteTest.setUp

    def as_role(self, **boundaries):
        grant(self.app, "developer", permissions=["traces:read", "logs:read"],
              **boundaries)
        data = session_for("developer")
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = data["id"]

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

    def test_a_service_rule_held_to_this_source_applies_in_every_answer(self):
        self.as_role(services=["elasticsearch-traces:postgres"])
        names = {s["name"] for s in
                 self.client.get("/api/traces/services").get_json()["services"]}
        self.assertEqual(names, {"postgres"})
        spans = self.client.get("/api/traces/trace-1").get_json()["spans"]
        self.assertEqual({s["service"] for s in spans}, {"postgres"})
        traces = self.client.get("/api/traces").get_json()["traces"]
        self.assertTrue(traces)
        self.assertEqual({t["service"] for t in traces}, {"postgres"})

    def test_an_excluded_service_is_not_listed(self):
        self.as_role(services=["*", "-postgres"])
        names = {s["name"] for s in
                 self.client.get("/api/traces/services").get_json()["services"]}
        self.assertNotIn("postgres", names)
        self.assertIn("redis", names)

    def test_a_trace_an_exclusion_narrowed_says_so(self):
        """It asked whether `*` was in the list, so a role of `*` beside
        `-postgres` lost every postgres span and was told nothing was
        hidden."""
        self.as_role(services=["*", "-postgres"])
        payload = self.client.get("/api/traces/trace-1").get_json()
        self.assertNotIn("postgres", {s["service"] for s in payload["spans"]})
        self.assertTrue(payload["scoped"])

    def test_a_trace_nothing_narrowed_does_not_say_so(self):
        self.as_role(services=["*"])
        self.assertFalse(
            self.client.get("/api/traces/trace-1").get_json()["scoped"])

    def test_a_store_the_role_cannot_reach_is_explained(self):
        """A role whose trace stores match nothing here got an empty list,
        which reads as a quiet time range."""
        self.as_role(trace_indices=["apm-*"])
        for path, key in (("/api/traces/services", "services"),
                          ("/api/traces", "traces")):
            payload = self.client.get(path).get_json()
            self.assertEqual(payload[key], [], path)
            self.assertEqual(payload["error_type"],
                             "no_accessible_trace_stores", path)
            self.assertIn("elasticsearch-traces", payload["suggestion"], path)

    def test_an_empty_answer_from_a_reachable_store_is_not_blamed_on_the_role(self):
        self.as_role(services=["nothing-*"])
        for path in ("/api/traces/services", "/api/traces"):
            self.assertNotIn("error_type", self.client.get(path).get_json(), path)

    def test_the_page_says_an_exclusion_narrows_it(self):
        self.as_role(services=["*", "-postgres"])
        page = self.client.get("/traces").data
        self.assertIn(b"Your role can see spans from", page)
        self.assertIn(b"-postgres", page)

    def test_the_page_does_not_call_every_service_narrowed(self):
        self.as_role(services=["*"])
        self.assertNotIn(b"Your role can see spans from",
                         self.client.get("/traces").data)
