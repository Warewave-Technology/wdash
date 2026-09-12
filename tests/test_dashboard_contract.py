"""
Wire contract for the dashboard endpoints.

Bucket shape is the neutral model (`key` / `count` / `key_text` / `sub`); if
the contract breaks, charts silently go blank. The source is not mocked — the
real adapter runs against a fake Elasticsearch.
"""

import os
import sys
import unittest

from tests.support import search_body

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.config import Config  # noqa: E402
from wdash.app import create_app  # noqa: E402
from wdash.models import Dashboard  # noqa: E402


class FakeES:
    """Log indices use keyword mappings, so `service.keyword` does NOT exist.

    The previous code aggregated on `service.keyword` regardless; with the field
    missing, `missing: "unknown"` swept every document into a single bucket.
    This fixture reproduces that trap on purpose.
    """

    def __init__(self):
        # Every query issued, in order. `searches[0]` is the main aggregation.
        self.searches = []
        # Network calls. One _msearch carrying three queries is ONE round trip,
        # and the round trip is what the latency contract is actually about.
        self.round_trips = 0

    def ping(self):
        return True

    @property
    def cat(self):
        class Cat:
            def indices(self, **kw):
                return [{"index": "app-logs-000001", "creation.date": "200"},
                        {"index": "infra-logs-000001", "creation.date": "100"}]
        return Cat()

    @property
    def indices(self):
        class Indices:
            def get_mapping(self, index=None, **kw):
                props = {"level": {"type": "keyword"},
                         "service": {"type": "keyword"},
                         "host": {"type": "keyword"},
                         "message": {"type": "text"}}
                return {name: {"mappings": {"properties": props}}
                        for name in (index or "app-logs-000001").split(",")}
        return Indices()

    def search(self, index=None, **kwargs):
        # Keywords in, body rebuilt — the shape elasticsearch-py 8.x takes.
        self.round_trips += 1
        return self._run(index, search_body(kwargs))

    def msearch(self, searches=None, **kw):
        """Header/body pairs in, one response per sub-query out."""
        self.round_trips += 1
        payload = list(searches or [])
        responses = [self._run(payload[i].get("index"), payload[i + 1])
                     for i in range(0, len(payload), 2)]
        return {"responses": responses}

    def _run(self, index=None, body=None):
        self.searches.append({"index": index, "body": body})
        aggs = (body or {}).get("aggs") or {}
        out = {}
        for name, node in aggs.items():
            if "date_histogram" in node:
                # Nested aggregations come back under the name they were asked
                # for; hardcoding one here hid a rename in the panel work.
                nested = {
                    sub_name: {"buckets": [{"key": "ERROR", "doc_count": 4},
                                           {"key": "INFO", "doc_count": 36}]}
                    for sub_name in (node.get("aggs") or {})
                }
                out[name] = {"buckets": [
                    {"key": 1754300000000, "key_as_string": "2026-08-04T09:00:00.000Z",
                     "doc_count": 40, **nested},
                ]}
            else:
                field = node["terms"]["field"]
                if field == "level":
                    out[name] = {"buckets": [{"key": "INFO", "doc_count": 80},
                                             {"key": "WARN", "doc_count": 12},
                                             {"key": "ERROR", "doc_count": 6},
                                             {"key": "FATAL", "doc_count": 2}]}
                elif field == "service":
                    out[name] = {"buckets": [{"key": "payment-service", "doc_count": 60},
                                             {"key": "api-gateway", "doc_count": 40}]}
                else:
                    out[name] = {"buckets": []}
        return {"took": 7, "timed_out": False,
                "hits": {"total": {"value": 100}, "hits": []},
                "aggregations": out}


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "dash-contract"


DASH_ID = "test-dash-1"


class DashboardContractTest(unittest.TestCase):
    def setUp(self):
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource

        self.es = FakeES()
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.es))
        hub.add_traces(ElasticsearchTraceSource(self.es))
        self.app.hub = hub

        dashboard = Dashboard(dashboard_id=DASH_ID, name="Test", description="",
                              query="*", created_by="u", index_patterns=["app-*"])
        self.app.dashboard_manager.dashboards[DASH_ID] = dashboard

        self.client = self.app.test_client()
        self.login(["dashboard:view"])

    def login(self, permissions, indices=("*",)):
        from tests.support import grant
        grant(self.app, "u", permissions, indices)
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": list(permissions),
                "allowed_indices": list(indices),
                "allowed_trace_indices": ["*"], "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def get(self, suffix, **params):
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return self.client.get(f"/api/dashboard/{DASH_ID}/{suffix}"
                               + (f"?{query}" if query else ""))

    def panel(self, payload, panel_id):
        """One panel out of the response, by id."""
        for panel in payload["panels"]:
            if panel["id"] == panel_id:
                return panel
        self.fail(f"no panel '{panel_id}' in {[p['id'] for p in payload['panels']]}")

    # ---------- combined /data ----------

    def test_data_has_every_key_wdash_js_reads(self):
        payload = self.get("data").get_json()
        for key in ("total_hits", "panels",
                    "dashboard_patterns", "resolved_containers",
                    "accessible_containers", "queried_containers",
                    "total_accessible_containers"):
            self.assertIn(key, payload, f"the client reads '{key}'")

    def test_buckets_carry_no_elasticsearch_shape(self):
        payload = self.get("data").get_json()
        bucket = self.panel(payload, "default-volume")["buckets"][0]
        for leaked in ("doc_count", "key_as_string"):
            self.assertNotIn(leaked, bucket, f"'{leaked}' is still leaking")

    def test_data_runs_a_single_elasticsearch_round_trip(self):
        """Four panels plus the baseline comparison, one round trip.

        The baseline covers a different time window so it cannot share the
        main query — but it can share the trip, and that is what costs.
        """
        self.get("data")
        self.assertEqual(self.es.round_trips, 1,
                         f"{self.es.round_trips} round trips, expected 1")
        self.assertEqual(sorted(self.es.searches[0]["body"]["aggs"]),
                         ["_levels", "default-levels", "default-services",
                          "default-volume"])

    def test_baseline_covers_the_window_before_this_one(self):
        """The comparison window must abut the current one, same length."""
        self.get("data")
        self.assertEqual(len(self.es.searches), 2, "expected main + baseline")

        def bounds(body):
            for clause in body["query"]["bool"]["must"]:
                if "range" in clause:
                    return next(iter(clause["range"].values()))
            self.fail("no time range in the query")

        now, before = bounds(self.es.searches[0]["body"]), bounds(self.es.searches[1]["body"])
        self.assertEqual(before["lte"], now["gte"], "the windows must abut")
        self.assertLess(before["gte"], before["lte"])

    def test_bucket_shape_is_neutral(self):
        payload = self.get("data").get_json()
        bucket = self.panel(payload, "default-levels")["buckets"][0]
        self.assertEqual(sorted(bucket), ["count", "key"])
        self.assertEqual(bucket["count"], 80)
        self.assertEqual(bucket["key"], "INFO")

    def test_date_bucket_carries_a_readable_key(self):
        """Time buckets need both the epoch key and a printable form."""
        payload = self.get("data").get_json()
        bucket = self.panel(payload, "default-volume")["buckets"][0]
        self.assertEqual(bucket["key"], 1754300000000)
        self.assertEqual(bucket["key_text"], "2026-08-04T09:00:00.000Z")
        self.assertEqual(bucket["count"], 40)

    def test_nested_buckets_live_under_sub(self):
        """Nested aggregations live under `sub`, without the `{buckets: []}` wrapper."""
        payload = self.get("data").get_json()
        bucket = self.panel(payload, "default-volume")["buckets"][0]
        levels = bucket["sub"]["split"]
        self.assertEqual(levels[0], {"key": "ERROR", "count": 4})

    def test_total_hits_is_not_capped(self):
        """The previous code did not set track_total_hits and capped at 10000."""
        self.get("data")
        self.assertTrue(self.es.searches[0]["body"].get("track_total_hits"))

    # ---------- field resolution ----------

    def test_service_field_is_resolved_from_the_mapping(self):
        """The previous code assumed 'service.keyword'; with the field absent
        every document fell into the 'unknown' bucket and the panel showed a
        single meaningless bar."""
        self.get("services")
        agg = self.es.searches[-1]["body"]["aggs"]["services"]["terms"]
        self.assertEqual(agg["field"], "service")

        services = self.get("services").get_json()["services"]
        self.assertEqual(services[0]["key"], "payment-service")
        self.assertNotEqual(services[0]["key"], "unknown")

    def test_dashboard_patterns_narrow_the_queried_indices(self):
        self.get("data")
        self.assertEqual(self.es.searches[-1]["index"], "app-logs-000001")

    def test_scope_still_applies_on_top_of_patterns(self):
        """A pattern narrows scope; the scope itself always wins."""
        self.login(["dashboard:view"], indices=["infra-*"])
        payload = self.get("data").get_json()
        self.assertEqual(payload["queried_containers"], [])
        self.assertEqual(payload["error_type"], "no_accessible_containers")

    # ---------- per-panel endpoints ----------

    def test_stats_shape(self):
        payload = self.get("stats").get_json()
        self.assertEqual(payload["total_hits"], 100)
        self.assertEqual(payload["error_count"], 8)     # ERROR 6 + FATAL 2
        self.assertEqual(payload["warn_count"], 12)
        self.assertEqual(payload["info_count"], 80)
        self.assertIn("queried_containers", payload)

    def test_timeline_interval_matches_previous_behaviour(self):
        for time_range, expected in (("1h", "5m"), ("24h", "1h"), ("7d", "6h")):
            self.es.searches.clear()
            self.get("timeline", time_range=time_range)
            agg = self.es.searches[0]["body"]["aggs"]["timeline"]["date_histogram"]
            self.assertEqual(agg["fixed_interval"], expected, time_range)
            self.assertEqual(agg["min_doc_count"], 0)   # Elasticsearch side

    def test_panel_endpoints_return_their_key(self):
        for suffix, key in (("log-levels", "log_levels"),
                            ("services", "services"), ("heatmap", "heatmap_data")):
            payload = self.get(suffix).get_json()
            self.assertIn(key, payload, suffix)
            self.assertIsInstance(payload[key], list)

    def test_recent_logs_is_time_bounded(self):
        """The previous version had no time range here and scanned in full."""
        self.get("recent-logs")
        clauses = self.es.searches[-1]["body"]["query"]["bool"]["must"]
        self.assertTrue(any("range" in c for c in clauses),
                        "recent-logs runs without a time range")

    # ---------- permissions and errors ----------

    def test_permission_gate_on_every_endpoint(self):
        self.login(["logs:read"])
        for suffix in ("data", "stats", "timeline", "log-levels", "services",
                       "heatmap", "recent-logs", "patterns"):
            self.assertEqual(self.get(suffix).status_code, 403, suffix)

    def test_unknown_dashboard(self):
        response = self.client.get("/api/dashboard/nope/data")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error_type"], "dashboard_not_found")

    def test_unknown_dashboard_on_panels(self):
        for suffix in ("stats", "timeline", "log-levels", "services", "heatmap"):
            response = self.client.get(f"/api/dashboard/nope/{suffix}")
            self.assertEqual(response.status_code, 404, suffix)

    def test_patterns_shape(self):
        payload = self.get("patterns").get_json()
        self.assertEqual(payload["index_patterns"], ["app-*"])
        self.assertEqual(payload["resolved_containers"], ["app-logs-000001"])
        self.assertEqual(payload["total_accessible"], 1)

    def test_unaggregatable_field_degrades_instead_of_500(self):
        """When a field is not aggregatable the panel returns empty with a
        reason; the previous code returned a 500."""
        class TextMappingES(FakeES):
            @property
            def indices(self):
                class Indices:
                    def get_mapping(self, index=None, **kw):
                        return {"app-logs-000001": {"mappings": {"properties": {
                            "service": {"type": "text"}}}}}
                return Indices()

        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(TextMappingES()))
        self.app.hub = hub

        response = self.get("services")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["services"], [])

    # ---------- pages ----------

    def test_pages_render(self):
        self.login(["dashboard:view", "dashboard:create"])
        self.assertEqual(self.client.get("/dashboards").status_code, 200)
        self.assertEqual(self.client.get(f"/dashboard/{DASH_ID}").status_code, 200)
        self.assertEqual(self.client.get("/dashboard/create").status_code, 200)

    def test_delete_requires_permission(self):
        self.assertEqual(
            self.client.post(f"/dashboard/{DASH_ID}/delete").status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class SinglePanelRequestTest(DashboardContractTest):
    """The UI now calls only /data, so that response must feed every panel."""

    def test_data_feeds_the_stat_cards(self):
        """The stat cards must not require a separate /stats call."""
        payload = self.get("data").get_json()
        self.assertEqual(payload["total_hits"], 100)
        self.assertEqual(payload["error_count"], 8)     # ERROR 6 + FATAL 2
        self.assertEqual(payload["warn_count"], 12)
        self.assertEqual(payload["info_count"], 80)

    def test_data_matches_the_dedicated_stats_endpoint(self):
        """Both paths must agree — otherwise which one do we trust?"""
        combined = self.get("data").get_json()
        separate = self.get("stats").get_json()
        for key in ("total_hits", "error_count", "warn_count", "info_count"):
            self.assertEqual(combined[key], separate[key], key)

    def test_bucket_size_scales_with_the_window(self):
        """A fixed five-minute bucket would produce ~2000 bars over seven days."""
        for time_range, expected in (("1h", "5m"), ("24h", "1h"), ("7d", "6h")):
            self.es.searches.clear()
            self.get("data", time_range=time_range)
            agg = self.es.searches[0]["body"]["aggs"]["default-volume"]["date_histogram"]
            self.assertEqual(agg["fixed_interval"], expected, time_range)

    def test_data_fills_empty_buckets(self):
        """Empty buckets must be returned so the chart axis stays continuous."""
        self.get("data")
        aggs = self.es.searches[0]["body"]["aggs"]
        self.assertEqual(aggs["default-volume"]["date_histogram"]["min_doc_count"], 0)

    def test_the_axis_spans_the_whole_window_even_with_no_data(self):
        """min_doc_count only fills gaps BETWEEN buckets that exist.

        Without extended bounds a window containing nothing comes back empty
        and the panel renders blank — which looks exactly like a failure.
        """
        self.get("data")
        for panel in ("default-volume",):
            histogram = self.es.searches[0]["body"]["aggs"][panel]["date_histogram"]
            self.assertIn("extended_bounds", histogram, panel)
            bounds = histogram["extended_bounds"]
            time_range = self.es.searches[0]["body"]["query"]["bool"]["must"]
            window = next(next(iter(c["range"].values()))
                          for c in time_range if "range" in c)
            self.assertEqual(bounds["min"], window["gte"], panel)
            self.assertEqual(bounds["max"], window["lte"], panel)

    def test_every_offered_time_range_produces_a_readable_chart(self):
        """The picker and the bucket size must not drift apart.

        The interval used to come from a hardcoded map keyed by the range
        string. Adding "15m" and "6h" to the picker without touching the map
        left both falling through to the default, so a fifteen-minute window
        was drawn as a single bucket — one dot, no chart.
        """
        import re

        with open(os.path.join(os.path.dirname(__file__), "..", "templates",
                               "dashboard_view.html"), encoding="utf-8") as handle:
            markup = handle.read()
        offered = re.findall(r'<option value="([^"]+)"', markup)
        self.assertIn("15m", offered, "the picker no longer offers 15m")

        units = {"m": 60, "h": 3600, "d": 86400}
        for time_range in offered:
            self.es.searches.clear()
            self.get("data", time_range=time_range)
            for panel in ("default-volume",):
                interval = (self.es.searches[0]["body"]["aggs"][panel]
                            ["date_histogram"]["fixed_interval"])
                size = int(interval[:-1]) * units[interval[-1]]
                span = int(time_range[:-1]) * units[time_range[-1]]
                buckets = span / size
                self.assertGreaterEqual(
                    buckets, 8,
                    f"{time_range} {panel}: {buckets:.0f} buckets is not a chart")
                self.assertLessEqual(
                    buckets, 200,
                    f"{time_range} {panel}: {buckets:.0f} buckets is unreadable")

    def test_data_matches_the_dedicated_panel_endpoints(self):
        """The legacy per-panel endpoints must still agree with the panels."""
        combined = self.get("data", time_range="24h").get_json()
        for suffix, key, panel_id in (
                ("log-levels", "log_levels", "default-levels"),
                ("services", "services", "default-services"),
                ("heatmap", "heatmap_data", "default-volume")):
            separate = self.get(suffix, time_range="24h").get_json()
            combined_buckets = self.panel(combined, panel_id)["buckets"]
            self.assertEqual(
                [(b["key"], b["count"]) for b in combined_buckets],
                [(b["key"], b["count"]) for b in separate[key]], suffix)

    def test_data_carries_the_error_rate(self):
        """A share, not just a count: 8 errors in 100 is 8%, in 100k it is not."""
        payload = self.get("data").get_json()
        self.assertAlmostEqual(payload["error_rate"], 0.08)

    def test_previous_period_has_everything_the_cards_render(self):
        previous = self.get("data").get_json()["previous_period"]
        for key in ("total_hits", "error_count", "warn_count", "info_count",
                    "error_rate", "change", "window"):
            self.assertIn(key, previous, key)
        for key in ("total_hits", "error_count", "warn_count", "info_count"):
            self.assertIn(key, previous["change"], key)

    def test_change_is_none_rather_than_infinite_against_a_zero_baseline(self):
        """Dividing by a zero baseline would print a meaningless '+100%'."""
        import datetime as dt
        from wdash.api.dashboard_routes import _compare
        from wdash.hub.aggregation import Bucket
        from wdash.hub.query import TimeWindow

        class Aggregation:
            def __init__(self, total, levels):
                self.total = total
                self._levels = levels

            def get(self, _name):
                return self._levels

        now = Aggregation(100, [Bucket(key="ERROR", count=6)])
        empty = Aggregation(0, [])
        moment = dt.datetime(2026, 8, 4, tzinfo=dt.timezone.utc)
        baseline = type("Q", (), {"window": TimeWindow.exact(moment, moment)})()

        compared = _compare(now, empty, baseline)
        self.assertEqual(compared["total_hits"], 0)
        self.assertEqual(compared["error_rate"], 0.0, "0/0 must not raise")
        self.assertTrue(all(v is None for v in compared["change"].values()),
                        "no baseline means no percentage")

    def test_comparison_is_omitted_when_its_sub_query_fails(self):
        """A broken baseline must cost the comparison, not the dashboard.

        And it must NOT be shown as a real zero: a baseline that did not run,
        rendered as 0, reads as '-100%, all traffic stopped'.
        """
        from wdash.hub.adapters import ElasticsearchLogSource
        from wdash.hub.aggregation import AggregationResult

        original = ElasticsearchLogSource.multi_aggregate
        try:
            ElasticsearchLogSource.multi_aggregate = (
                lambda self, requests, scope: [
                    original(self, requests, scope)[0],
                    AggregationResult(warnings=("query failed",), failed=True)])
            payload = self.get("data").get_json()
        finally:
            ElasticsearchLogSource.multi_aggregate = original

        self.assertEqual(payload["total_hits"], 100, "the dashboard still renders")
        self.assertIsNone(payload["previous_period"])

    def test_a_genuinely_empty_baseline_is_still_compared(self):
        """A window that really had no logs is a fact, and must be shown."""
        from wdash.hub.adapters import ElasticsearchLogSource
        from wdash.hub.aggregation import AggregationResult

        original = ElasticsearchLogSource.multi_aggregate
        try:
            ElasticsearchLogSource.multi_aggregate = (
                lambda self, requests, scope: [
                    original(self, requests, scope)[0], AggregationResult(total=0)])
            payload = self.get("data").get_json()
        finally:
            ElasticsearchLogSource.multi_aggregate = original

        self.assertIsNotNone(payload["previous_period"])
        self.assertEqual(payload["previous_period"]["total_hits"], 0)


class SharedViewTest(DashboardContractTest):
    """A dashboard link should reproduce the view, not just the page.

    Time range and ad-hoc filter travel in the query string; the server echoes
    back what it actually ran so the client can drill down consistently.
    """

    def test_the_filter_narrows_rather_than_replaces(self):
        """Substituting would show data the dashboard was never scoped to."""
        self.app.dashboard_manager.dashboards[DASH_ID].query = "level:ERROR"
        self.get("data", q='service:"api"')
        clauses = self.es.searches[0]["body"]["query"]["bool"]["must"]
        rendered = str(clauses)
        self.assertIn("ERROR", rendered, "the dashboard's own query was dropped")
        self.assertIn("api", rendered, "the filter was not applied")

    def test_a_filter_cannot_close_the_group_it_is_put_in(self):
        """Joined as text, `service:none) OR (*` closed the parenthesis
        around it: `(level:ERROR) AND (service:none) OR (*)` counts
        everything, and the filter replaced the dashboard's query instead of
        narrowing it."""
        self.app.dashboard_manager.dashboards[DASH_ID].query = "level:ERROR"
        response = self.get("data", q="service%3Anone)%20OR%20(*")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid filter", response.get_json()["error"])
        self.assertEqual(self.es.searches, [])

    def test_the_effective_query_is_echoed(self):
        payload = self.get("data", q='service:"api"').get_json()
        self.assertEqual(payload["filter"], 'service:"api"')
        self.assertEqual(payload["time_range"], "1h")
        self.assertIn("api", payload["effective_query"])

    def test_the_baseline_is_narrowed_too(self):
        """Comparing a filtered window against an unfiltered one is nonsense."""
        self.get("data", q='service:"api"')
        self.assertEqual(len(self.es.searches), 2)
        for search in self.es.searches:
            self.assertIn("api", str(search["body"]["query"]),
                          "one of the two windows was not filtered")

    def test_a_broken_filter_blames_the_filter(self):
        response = self.get("data", q="service:")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid filter", response.get_json()["error"])

    def test_an_empty_filter_changes_nothing(self):
        plain = self.get("data").get_json()
        with_star = self.get("data", q="*").get_json()
        self.assertEqual(plain["effective_query"], with_star["effective_query"])

    def test_the_page_carries_the_controls_the_client_drives(self):
        response = self.client.get(f"/dashboard/{DASH_ID}")
        for element_id in ("dashboardFilter", "shareBtn", "clearFilterBtn",
                           "timeRange"):
            self.assertIn(f'id="{element_id}"'.encode(), response.data, element_id)


class RecentLogsShapeTest(DashboardContractTest):
    def test_recent_logs_returns_neutral_records(self):
        payload = self.get("recent-logs").get_json()
        self.assertIn("records", payload)
        self.assertNotIn("hits", payload)


class DrillDownScopeTest(unittest.TestCase):
    """A chart opens the records BEHIND it, not every record the role allows.

    The dashboard queries its index patterns intersected with the viewer's
    scope; the click-through sent only the query and the window, and
    /api/search with no dashboard searches every container the scope allows.
    So a dashboard over `app-logs-*`, read by a role holding `*-logs-*`,
    counted one index and its stat card opened five. Measured against the
    lab: 30,576 records over seven days on the dashboard, 91,407 on the
    drill-down; 30,565 after the fix.

    Modelled rather than faked: the fake cluster evaluates the query and
    answers per index, so the narrowing is actually exercised.
    """

    WINDOW = ("start_time=2026-09-01T09:00:00Z&end_time=2026-09-01T11:00:00Z")

    def setUp(self):
        from tests.support import ModelledES
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource

        class Cluster(ModelledES):
            """The modelled cluster, plus the date histogram the Logs search
            asks for on a first page. What the histogram holds is not what
            these tests are about; that the SEARCH is evaluated, per index,
            is."""

            def _aggregate(self, spec, hits):
                if "date_histogram" in spec:
                    return {"buckets": []}
                return super()._aggregate(spec, hits)

        fields = {"@timestamp": {"type": "date"}, "message": {"type": "text"},
                  "level": {"type": "keyword"}, "service": {"type": "keyword"}}

        def record(prefix, number, level="ERROR"):
            return {"_id": f"{prefix}-{number}",
                    "@timestamp": "2026-09-01T10:00:00Z", "level": level,
                    "service": "api", "message": f"failure {number}"}

        # The severity VARIANTS a stat card groups together. The error card
        # counts ERROR and FATAL as one number and the warn card WARN and
        # WARNING, so a cluster holding only ERROR cannot tell whether the
        # click under the number asks for the same thing the number counted.
        app = [record("app", n) for n in range(3)]
        app += [record("app-fatal", n, "FATAL") for n in range(2)]
        app += [record("app-warn", 0, "WARN"),
                record("app-warning", 0, "WARNING"),
                record("app-info", 0, "INFO")]

        self.cluster, self.fields = Cluster, fields
        self.es = Cluster({
            "app-logs-000001": (fields, app),
            "infra-logs-000001": (fields, [record("infra", n) for n in range(7)]),
        })
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.es))
        self.app.hub = hub

        self.dashboard = Dashboard(dashboard_id=DASH_ID, name="App board",
                                   description="", query="*", created_by="u",
                                   index_patterns=["app-logs-*"])
        self.app.dashboard_manager.dashboards[DASH_ID] = self.dashboard

        self.client = self.app.test_client()
        permissions = ["dashboard:view", "logs:read"]
        from tests.support import grant
        grant(self.app, "u", permissions, ["*-logs-*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": permissions,
                "allowed_indices": ["*-logs-*"],
                "allowed_trace_indices": [], "allowed_services": []}
            session["_user_id"] = "1"

    def search(self, **params):
        from urllib.parse import quote
        query = "&".join(f"{key}={quote(str(value))}"
                         for key, value in params.items())
        return self.client.get(f"/api/search?{self.WINDOW}&{query}").get_json()

    def card_counts(self):
        """The stat cards as the dashboard page draws them.

        `30d` rather than `1h` only because the modelled records sit at a
        fixed instant; it covers exactly the same records as `WINDOW`, which
        the first assertion of the test below checks rather than assumes.
        """
        return self.client.get(
            f"/api/dashboard/{DASH_ID}/data?time_range=30d").get_json()

    def test_the_role_really_does_reach_both_indices(self):
        """Otherwise the scoped numbers below would be right by accident."""
        payload = self.search(q="level:ERROR")
        self.assertEqual(payload["total"], 10)
        self.assertEqual(sorted(payload["accessible_containers"]),
                         ["app-logs-000001", "infra-logs-000001"])

    def test_a_drill_down_reaches_only_what_the_dashboard_counted(self):
        dashboard_total = self.client.get(
            f"/api/dashboard/{DASH_ID}/data?time_range=1h").get_json()
        payload = self.search(q="level:ERROR", dashboard=DASH_ID)
        self.assertEqual(payload["total"], 3)
        self.assertEqual(payload["dashboard"]["containers"],
                         ["app-logs-000001"])
        self.assertEqual(sorted(payload["dashboard"]["containers"]),
                         sorted(dashboard_total["queried_containers"]))

    def test_it_says_on_the_page_that_it_is_scoped(self):
        """A narrowed result set that does not say it is narrowed is a wrong
        number to whoever came here from a chart."""
        payload = self.search(q="level:ERROR", dashboard=DASH_ID)
        self.assertEqual(payload["dashboard"]["name"], "App board")
        self.assertEqual(payload["dashboard"]["id"], DASH_ID)

    def test_a_plain_search_is_unchanged(self):
        payload = self.search(q="level:ERROR")
        self.assertNotIn("dashboard", payload)

    def test_a_dashboard_that_is_not_there_is_not_a_wider_search(self):
        reply = self.client.get(
            f"/api/search?{self.WINDOW}&q=*&dashboard=no-such-board")
        self.assertEqual(reply.status_code, 404)
        self.assertEqual(reply.get_json()["error_type"], "dashboard_not_found")

    def test_a_dashboard_you_may_not_see_answers_the_same_way(self):
        """Otherwise the parameter becomes a way to find out what exists."""
        from wdash.dashboard.visibility import PRIVATE
        private = Dashboard(dashboard_id="private-1", name="Fraud",
                            description="", query="*", created_by="alice",
                            index_patterns=["app-logs-*"], visibility=PRIVATE)
        self.app.dashboard_manager.dashboards["private-1"] = private
        before = len(self.es.requests)
        reply = self.client.get(
            f"/api/search?{self.WINDOW}&q=*&dashboard=private-1")
        self.assertEqual(reply.status_code, 404)
        self.assertEqual(len(self.es.requests), before,
                         "somebody else's private query was run")

    def test_a_stat_card_opens_exactly_the_records_it_counted(self):
        """WHERE the drill-down looked was fixed; WHAT it asked for was not.

        `_level_counts` sums ERROR and FATAL into one error card and WARN and
        WARNING into one warn card, and the click under the card asked for
        `level:ERROR` and `level:WARN`. So the card still opened fewer records
        than it showed — the same defect, on the same button. Measured against
        the lab: the card read 3,093 and the drill-down returned 2,772, the
        missing 321 being the FATAL records the card had counted.

        The query travels WITH the counts now, derived from the same table,
        so the two cannot be changed apart.
        """
        cards = self.card_counts()
        # The two windows hold the same records: if they ever stop doing so,
        # this says it rather than the numbers below quietly drifting.
        self.assertEqual(self.search(q="*", dashboard=DASH_ID)["total"],
                         cards["total_hits"])

        expected = {"error": 5, "warn": 2, "info": 1}
        for card, count in expected.items():
            with self.subTest(card=card):
                self.assertEqual(cards[f"{card}_count"], count)
                opened = self.search(q=cards["level_queries"][card],
                                     dashboard=DASH_ID)
                self.assertEqual(opened["total"], count,
                                 f"the {card} card counted {count} and opened "
                                 f"{opened['total']}")

    def test_the_severity_the_card_counts_is_more_than_its_first_name(self):
        """Stated on its own, so the test above cannot pass by the grouping
        being dropped from both halves at once."""
        cards = self.card_counts()
        narrow = self.search(q="level:ERROR", dashboard=DASH_ID)
        self.assertLess(narrow["total"], cards["error_count"])
        self.assertIn("FATAL", cards["level_queries"]["error"])
        self.assertIn("WARNING", cards["level_queries"]["warn"])

    def second_source(self):
        """A second store, and a dashboard pinned to it — which a dashboard
        may be since the source field exists."""
        from wdash.hub.adapters import ElasticsearchLogSource

        archive = self.cluster({"app-logs-000001": (self.fields, [
            {"_id": f"old-{n}", "@timestamp": "2026-09-01T10:00:00Z",
             "level": "ERROR", "service": "api", "message": "archived"}
            for n in range(4)])})
        self.app.hub.add_logs(
            ElasticsearchLogSource(archive, name="archive"))
        board = Dashboard(dashboard_id="archive-1", name="Archive board",
                          description="", query="*", created_by="u",
                          index_patterns=["app-logs-*"], source="archive")
        self.app.dashboard_manager.dashboards["archive-1"] = board
        return archive

    def test_a_drill_down_says_which_source_answered_it(self):
        """The Logs page's own source picker sits on its first option and is
        re-sent with every later search from that page, where `api_search`
        silently prefers the dashboard's source — so the control said one
        store, the answer came from another, and nothing on screen corrected
        it. The badge can only name the source if the source travels.
        """
        archive = self.second_source()
        payload = self.search(q="*", dashboard="archive-1")

        self.assertEqual(payload["total"], 4, payload)
        self.assertEqual(payload["dashboard"]["source"], "archive")
        # The same name the rest of the payload already carried, so the badge
        # and the per-record source badges cannot disagree.
        self.assertEqual(payload["source"], "archive")
        self.assertGreater(len(archive.requests), 0,
                           "the pinned source was not the one asked")

    def test_an_unpinned_dashboard_still_names_the_source_it_used(self):
        """Otherwise the badge would fall silent on exactly the installations
        that have more than one store and only some dashboards pinned."""
        self.second_source()
        payload = self.search(q="*", dashboard=DASH_ID)
        self.assertEqual(payload["dashboard"]["source"],
                         self.app.hub.logs().name)

    def shared_board(self):
        """A dashboard somebody else wrote and shared — the ordinary case for
        a drill-down, and the only one the outage below shows up on."""
        board = Dashboard(dashboard_id="shared-1", name="Theirs",
                          description="", query="*", created_by="someone-else",
                          index_patterns=["app-logs-*"])
        self.app.dashboard_manager.dashboards["shared-1"] = board
        return board

    def source_is_down(self):
        source = self.app.hub.logs()
        original = source.containers

        def failing(scope, *args, **kwargs):
            raise ConnectionError("cluster unreachable")
        source.containers = failing
        self.addCleanup(setattr, source, "containers", original)

    def test_a_source_that_is_down_is_not_a_dashboard_that_is_not_there(self):
        """The same request, with and without the parameter, at the same
        moment, disagreed about what was wrong.

        The visibility check reads the dashboard's reach to decide, and an
        exception there left it with an empty reach — which for a shared
        dashboard is indistinguishable from "none of its data is within your
        access", so the drill-down answered 404 "Dashboard not found." while
        the log store was merely down. The unscoped search, one line later,
        answered 503 and named the source. A failure must not arrive wearing
        the clothes of a boundary.
        """
        self.shared_board()
        self.source_is_down()

        scoped = self.client.get(
            f"/api/search?{self.WINDOW}&q=*&dashboard=shared-1")
        plain = self.client.get(f"/api/search?{self.WINDOW}&q=*")

        self.assertEqual(plain.status_code, 503)
        self.assertEqual(scoped.status_code, 503, scoped.get_json())
        payload = scoped.get_json()
        self.assertEqual(payload["error_type"], "elasticsearch_connection")
        self.assertEqual(payload["source"], plain.get_json()["source"])
        self.assertIn(payload["source"], payload["error"])

    def test_a_dashboard_you_may_not_see_is_still_not_there_in_an_outage(self):
        """The outage must not become a way to find out what exists: a
        dashboard the rule hides is hidden for a reason the backend coming
        back will not change, and it answers exactly as it did before."""
        from wdash.dashboard.visibility import PRIVATE
        private = Dashboard(dashboard_id="private-2", name="Fraud",
                            description="", query="*", created_by="alice",
                            index_patterns=["app-logs-*"], visibility=PRIVATE)
        self.app.dashboard_manager.dashboards["private-2"] = private
        self.source_is_down()

        for dashboard_id in ("private-2", "no-such-board"):
            with self.subTest(dashboard=dashboard_id):
                reply = self.client.get(
                    f"/api/search?{self.WINDOW}&q=*&dashboard={dashboard_id}")
                self.assertEqual(reply.status_code, 404)
                self.assertEqual(reply.get_json()["error_type"],
                                 "dashboard_not_found")

    def test_your_own_dashboard_answered_the_same_way_all_along(self):
        """It did, which is what made the difference visible: the author got
        503 from the very same outage that told everybody else 404."""
        self.source_is_down()
        reply = self.client.get(
            f"/api/search?{self.WINDOW}&q=*&dashboard={DASH_ID}")
        self.assertEqual(reply.status_code, 503)

    def test_the_page_and_the_server_group_severities_the_same_way(self):
        """The client keeps a copy for a click made before the first response
        has landed. A copy that drifts is the defect again, arriving by a
        different road, so the two are compared rather than trusted."""
        import json
        import re

        source = os.path.join(os.path.dirname(__file__), "..", "static", "js",
                              "async-dashboard.js")
        with open(source) as handle:
            text = handle.read()
        block = re.search(r"const LEVEL_GROUPS = (\{.*?\});", text, re.S)
        self.assertIsNotNone(block, "the client's fallback grouping is gone")
        client_side = json.loads(
            re.sub(r"(\w+):", r'"\1":', block.group(1)).replace("'", '"')
            .replace(",\n}", "\n}").replace(",]", "]"))

        from wdash.api.dashboard_routes import LEVEL_GROUPS
        self.assertEqual({group: list(levels)
                          for group, levels in LEVEL_GROUPS.items()},
                         client_side)

    def test_a_dashboard_over_data_outside_your_access_says_which(self):
        """Not 'your role has no access to any indices': the role reaches
        plenty, and this dashboard's patterns reach none of it."""
        elsewhere = Dashboard(dashboard_id="far-1", name="Far", description="",
                              query="*", created_by="u",
                              index_patterns=["nothing-here-*"])
        self.app.dashboard_manager.dashboards["far-1"] = elsewhere
        reply = self.client.get(f"/api/search?{self.WINDOW}&q=*&dashboard=far-1")
        self.assertEqual(reply.status_code, 403)
        payload = reply.get_json()
        self.assertEqual(payload["error_type"], "no_accessible_containers")
        self.assertIn("nothing-here-*", payload["error"])
        self.assertEqual(payload["dashboard"], "Far")
