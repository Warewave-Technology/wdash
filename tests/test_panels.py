"""
Dashboard panels.

A dashboard used to be one query rendered four fixed ways. These tests hold the
two properties that make an arbitrary panel list safe:

  * a panel that gets past validation is renderable — no half-specified panel
    reaches the query builder or the template
  * adding panels costs aggregations, not round trips

and the compatibility promise: dashboards stored before panels existed keep
rendering exactly as they did.
"""

import json
import os
import sys
import unittest

from tests.support import grant

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.panels import (  # noqa: E402
    AGGREGATABLE_FIELDS, MAX_SIZE, PanelError, default_panels, normalise,
    normalise_all,
)
from wdash.models import Dashboard  # noqa: E402


class ValidationTest(unittest.TestCase):
    def test_a_complete_panel_survives_unchanged(self):
        panel = normalise({"type": "terms", "title": "Services",
                           "field": "service", "size": 5, "width": 4})
        self.assertEqual(panel["type"], "terms")
        self.assertEqual(panel["field"], "service")
        self.assertEqual(panel["size"], 5)
        self.assertEqual(panel["width"], 4)
        self.assertTrue(panel["id"])

    def test_every_panel_comes_back_complete(self):
        """The point of validating: nothing downstream needs .get() guards."""
        panel = normalise({"type": "terms", "field": "service"})
        for key in ("id", "type", "title", "width", "field", "size"):
            self.assertIn(key, panel, key)

        series = normalise({"type": "timeseries"})
        for key in ("id", "type", "title", "width", "split_by"):
            self.assertIn(key, series, key)

    def test_an_unknown_type_is_refused(self):
        with self.assertRaises(PanelError):
            normalise({"type": "pie-of-pie", "field": "service"})

    def test_a_field_that_cannot_be_aggregated_is_refused(self):
        """An analysed text field returns tokenised nonsense, not an error."""
        with self.assertRaises(PanelError) as caught:
            normalise({"type": "terms", "field": "body"})
        self.assertIn("body", str(caught.exception))
        for field in AGGREGATABLE_FIELDS:
            self.assertIn(field, str(caught.exception),
                          "the message must say what IS allowed")

    def test_a_terms_panel_needs_a_field(self):
        with self.assertRaises(PanelError):
            normalise({"type": "terms"})

    def test_a_timeseries_panel_may_have_no_split(self):
        self.assertIsNone(normalise({"type": "timeseries"})["split_by"])

    def test_a_bad_split_field_is_refused(self):
        with self.assertRaises(PanelError):
            normalise({"type": "timeseries", "split_by": "body"})

    def test_size_and_width_are_clamped_not_rejected(self):
        """A silly number is a slider that went too far, not an error."""
        panel = normalise({"type": "terms", "field": "service",
                           "size": 5000, "width": 99})
        self.assertEqual(panel["size"], MAX_SIZE)
        self.assertEqual(panel["width"], 12)

        narrow = normalise({"type": "terms", "field": "service",
                            "size": 0, "width": 1})
        self.assertEqual(narrow["size"], 1)
        self.assertEqual(narrow["width"], 3)

    def test_a_non_numeric_size_is_an_error_not_a_crash(self):
        with self.assertRaises(PanelError):
            normalise({"type": "terms", "field": "service", "size": "lots"})

    def test_a_missing_title_falls_back_to_the_type_label(self):
        self.assertTrue(normalise({"type": "timeseries"})["title"])

    def test_duplicate_ids_are_broken_apart(self):
        """Results are keyed by id, so a duplicate would overwrite a panel."""
        panels = normalise_all([
            {"id": "same", "type": "terms", "field": "service"},
            {"id": "same", "type": "terms", "field": "host"},
        ])
        self.assertNotEqual(panels[0]["id"], panels[1]["id"])

    def test_an_empty_list_is_refused(self):
        with self.assertRaises(PanelError):
            normalise_all([])

    def test_none_means_the_default_set(self):
        self.assertEqual([p["id"] for p in normalise_all(None)],
                         [p["id"] for p in default_panels()])


class BackwardCompatibilityTest(unittest.TestCase):
    """Dashboards saved before panels existed must not change appearance."""

    def test_a_dashboard_without_panels_gets_the_default_set(self):
        dashboard = Dashboard("d1", "Old", "", "*", "u")
        panels = dashboard.get_panels()
        self.assertEqual([p["id"] for p in panels],
                         ["default-volume", "default-levels", "default-services"])

    def test_an_untouched_dashboard_stores_no_panel_list(self):
        """Freezing today's defaults would stop it following future changes."""
        dashboard = Dashboard("d1", "Old", "", "*", "u")
        self.assertNotIn("panels", dashboard.to_dict())

    def test_a_customised_dashboard_round_trips(self):
        custom = [normalise({"type": "terms", "field": "host", "size": 3})]
        dashboard = Dashboard("d1", "New", "", "*", "u", panels=custom)

        restored = Dashboard.from_dict(json.loads(json.dumps(dashboard.to_dict())))
        panels = restored.get_panels()
        self.assertEqual(len(panels), 1)
        self.assertEqual(panels[0]["field"], "host")
        self.assertEqual(panels[0]["size"], 3)


class TracePanelTest(unittest.TestCase):
    """Trace panels come from a different source, with an honest extra cost."""

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource
        from tests.test_dashboard_contract import FakeES

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "trace-panels"

        self.es = FakeES()
        self.app = create_app(TestConfig)
        self.hub = Hub()
        self.hub.add_logs(ElasticsearchLogSource(self.es))
        self.hub.add_traces(ElasticsearchTraceSource(self.es))
        self.app.hub = self.hub

        self.dashboard = Dashboard("t1", "Traces", "", "*", "u",
                                   index_patterns=["app-*"])
        self.app.dashboard_manager.dashboards["t1"] = self.dashboard
        self.client = self.app.test_client()
        grant(self.app, "u", permissions=["dashboard:view"], indices=["*"], trace_indices=["*"], services=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": ["dashboard:view"],
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def panel(self, **overrides):
        definition = {"type": "trace_services", "sort": "spans", "size": 5}
        definition.update(overrides)
        self.dashboard.panels = normalise_all([definition])
        payload = self.client.get("/api/dashboard/t1/data").get_json()
        return payload["panels"][0]

    def test_a_trace_panel_returns_rows_not_buckets(self):
        """Three numbers per service; buckets would carry only one."""
        panel = self.panel()
        self.assertIn("rows", panel)
        self.assertNotIn("buckets", panel)

    def test_the_sort_is_validated(self):
        with self.assertRaises(PanelError):
            normalise({"type": "trace_services", "sort": "whatever"})

    def test_a_log_only_dashboard_stays_at_one_round_trip(self):
        """The trace cost must be paid only by dashboards that ask for it."""
        from wdash.dashboard.panels import signals

        self.dashboard.panels = normalise_all(
            [{"type": "terms", "field": "service"}])
        self.assertEqual(signals(self.dashboard.get_panels()), {"logs"})

        self.es.round_trips = 0
        self.client.get("/api/dashboard/t1/data")
        self.assertEqual(self.es.round_trips, 1)

    def test_trace_panels_do_not_multiply_round_trips(self):
        """Three trace panels must cost what one costs: the sources are asked
        once each, and the panels are cut from the same answer."""
        def cost(panels):
            self.dashboard.panels = normalise_all(panels)
            self.es.round_trips = 0
            payload = self.client.get("/api/dashboard/t1/data").get_json()
            return self.es.round_trips, payload

        one, _ = cost([{"type": "terms", "field": "service"},
                       {"type": "trace_services", "sort": "spans"}])
        three, payload = cost([{"type": "terms", "field": "service"},
                               {"type": "trace_services", "sort": "spans"},
                               {"type": "trace_services", "sort": "errors"},
                               {"type": "trace_services", "sort": "error_rate"}])

        self.assertEqual(len(payload["panels"]), 4)
        self.assertEqual(three, one,
                         f"{one} round trips for one trace panel, {three} for three")

    def test_each_trace_panel_is_sorted_independently(self):
        """One query, three orderings — the sort is applied after the fetch."""
        from wdash.hub.models import Service

        self.hub.traces().services = lambda window, scope: [
            Service(name="busy", span_count=1000, error_count=1),
            Service(name="broken", span_count=10, error_count=9),
        ]
        self.dashboard.panels = normalise_all([
            {"id": "by-spans", "type": "trace_services", "sort": "spans"},
            {"id": "by-rate", "type": "trace_services", "sort": "error_rate"},
        ])
        panels = {p["id"]: p for p in
                  self.client.get("/api/dashboard/t1/data").get_json()["panels"]}

        self.assertEqual(panels["by-spans"]["rows"][0]["name"], "busy")
        self.assertEqual(panels["by-rate"]["rows"][0]["name"], "broken")

    def test_a_missing_trace_backend_costs_the_panel_not_the_page(self):
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource

        logs_only = Hub()
        logs_only.add_logs(ElasticsearchLogSource(self.es))
        self.app.hub = logs_only

        self.dashboard.panels = normalise_all([
            {"type": "terms", "field": "service", "title": "Still here"},
            {"type": "trace_services"},
        ])
        response = self.client.get("/api/dashboard/t1/data")
        self.assertEqual(response.status_code, 200)

        panels = response.get_json()["panels"]
        self.assertIn("buckets", panels[0], "the log panel must still render")
        self.assertIn("error", panels[1])

    def test_a_failing_trace_backend_costs_the_panel_not_the_page(self):
        def explode(*args, **kwargs):
            raise ConnectionError("trace store unreachable")

        self.hub.traces().services = explode

        self.dashboard.panels = normalise_all([
            {"type": "terms", "field": "service"},
            {"type": "trace_services"},
        ])
        response = self.client.get("/api/dashboard/t1/data")
        self.assertEqual(response.status_code, 200)
        self.assertIn("error", response.get_json()["panels"][1])

    def half_an_answer(self):
        """A fan-out that lost one backend: the shape `FanOutTraceSource`
        returns when one member did not reply."""
        from wdash.hub.models import PartialList, Service

        def half(window, scope):
            return PartialList(
                [Service(name="api", span_count=10, error_count=1)],
                partial=True,
                warnings=["jaeger did not answer the service list"])
        self.hub.traces().services = half

    def test_a_service_list_missing_a_backend_says_so(self):
        """Half a service list drawn as a whole one reads as services having
        gone quiet — which is the one reading this panel exists to support.
        The fan-out marks the answer `partial`; the panel threw it away."""
        self.half_an_answer()
        panel = self.panel()
        self.assertTrue(panel["partial"])
        self.assertEqual(panel["warnings"],
                         ["jaeger did not answer the service list"])
        self.assertEqual([row["name"] for row in panel["rows"]], ["api"],
                         "the rows that did arrive must still be drawn")

    def test_a_whole_service_list_is_not_marked(self):
        """Otherwise every panel carries a caveat and nobody reads any."""
        panel = self.panel()
        self.assertNotIn("partial", panel)
        self.assertNotIn("warnings", panel)


class WireTest(unittest.TestCase):
    """/data must answer any panel list in a single round trip."""

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource
        from tests.test_dashboard_contract import FakeES

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "panels"

        self.es = FakeES()
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.es))
        self.app.hub = hub

        self.dashboard = Dashboard("p1", "Panels", "", "*", "u",
                                   index_patterns=["app-*"])
        self.app.dashboard_manager.dashboards["p1"] = self.dashboard

        self.client = self.app.test_client()
        grant(self.app, "u", permissions=["dashboard:view"], indices=["*"], trace_indices=["*"], services=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": ["dashboard:view"],
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def data(self):
        return self.client.get("/api/dashboard/p1/data").get_json()

    def test_panels_come_back_with_their_definition_and_buckets(self):
        panel = self.data()["panels"][0]
        for key in ("id", "type", "title", "width", "buckets"):
            self.assertIn(key, panel, key)

    def test_ten_panels_still_take_one_round_trip(self):
        """Adding a panel must cost an aggregation, not a request."""
        self.dashboard.panels = normalise_all(
            [{"type": "timeseries", "split_by": "severity"}]
            + [{"type": "terms", "field": f, "title": f"{f} {i}"}
               for i, f in enumerate(AGGREGATABLE_FIELDS * 3)])

        self.es.round_trips = 0
        payload = self.data()

        self.assertEqual(len(payload["panels"]), 13)
        self.assertEqual(self.es.round_trips, 1,
                         f"{self.es.round_trips} round trips for 13 panels")

    def test_each_panel_gets_its_own_aggregation_named_after_it(self):
        self.dashboard.panels = normalise_all([
            {"id": "a", "type": "terms", "field": "service"},
            {"id": "b", "type": "terms", "field": "host"},
        ])
        self.data()
        aggregations = self.es.searches[0]["body"]["aggs"]
        self.assertIn("a", aggregations)
        self.assertIn("b", aggregations)

    def test_the_summary_counts_survive_an_arbitrary_panel_list(self):
        """The stat cards are not a panel and must not depend on one."""
        self.dashboard.panels = normalise_all(
            [{"type": "terms", "field": "host", "title": "Only hosts"}])
        payload = self.data()
        self.assertEqual(payload["total_hits"], 100)
        self.assertEqual(payload["error_count"], 8)
        self.assertEqual(payload["warn_count"], 12)

    def test_a_corrupt_stored_panel_list_reports_rather_than_500s(self):
        self.dashboard.panels = [{"type": "nonsense"}]
        response = self.client.get("/api/dashboard/p1/data")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error_type"], "invalid_panels")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class SourceBindingTest(unittest.TestCase):
    """A dashboard may name the source it reads from."""

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource
        from tests.support import grant
        from tests.test_dashboard_contract import FakeES

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "source-binding"

        self.primary = FakeES()
        self.secondary = FakeES()
        self.app = create_app(TestConfig)

        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.primary, name="primary"))
        hub.add_logs(ElasticsearchLogSource(self.secondary, name="secondary"))
        self.app.hub = hub

        self.dashboard = Dashboard("s1", "Bound", "", "*", "u",
                                   index_patterns=["app-*"])
        self.app.dashboard_manager.dashboards["s1"] = self.dashboard

        self.client = self.app.test_client()
        grant(self.app, "u", ["dashboard:view"])
        with self.client.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": "u@x", "username": "u",
                                    "groups": []}
            session["_user_id"] = "1"

    def data(self):
        return self.client.get("/api/dashboard/s1/data")

    def test_no_source_named_means_the_default(self):
        self.data()
        self.assertGreater(self.primary.round_trips, 0)
        self.assertEqual(self.secondary.round_trips, 0)

    def test_a_named_source_is_the_one_queried(self):
        self.dashboard.source = "secondary"
        self.data()
        self.assertEqual(self.primary.round_trips, 0)
        self.assertGreater(self.secondary.round_trips, 0)

    def test_naming_a_source_that_is_gone_says_so(self):
        """Quietly answering from the default is how somebody concludes their
        data has disappeared."""
        self.dashboard.source = "retired"
        response = self.data()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error_type"], "source_missing")
        self.assertIn("retired", response.get_json()["error"])
        self.assertEqual(self.primary.round_trips, 0,
                         "it fell back to the default instead of reporting")


class SourceFormTest(unittest.TestCase):
    """Choosing that source, which is the half that did not exist.

    The README said a dashboard may name the source it reads from. The create
    and edit forms had no field for it, `_dashboard_form` returned no key for
    it, and `models.Dashboard` had no attribute for it — so on the default
    (file) store there was nowhere to put one even if there had been. Measured
    before: POST /dashboard/create with source=secondary returned 302 and
    stored a dashboard with no source at all, and every dashboard read from
    the first registered source.
    """

    STORAGE = "file"

    def setUp(self):
        import tempfile
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource
        from tests.support import grant
        from tests.test_dashboard_contract import FakeES

        self.directory = tempfile.mkdtemp(prefix="wdash-source-form-")
        storage = os.path.join(self.directory, "dashboards.json")
        database = os.path.join(self.directory, "wdash.db")
        backend = self.STORAGE

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "source-form"
            DASHBOARD_STORAGE_FILE = storage
            DASHBOARD_STORAGE = backend
            DATABASE_URL = f"sqlite:///{database}"

        self.primary = FakeES()
        self.secondary = FakeES()
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.primary, name="primary"))
        hub.add_logs(ElasticsearchLogSource(self.secondary, name="secondary"))
        self.app.hub = hub

        self.client = self.app.test_client()
        permissions = ["dashboard:view", "dashboard:create", "dashboard:edit"]
        grant(self.app, "u", permissions)
        with self.client.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": "u@x", "username": "u",
                                    "groups": []}
            session["_user_id"] = "1"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def create(self, **overrides):
        form = {"name": "Board", "query": "*", "description": "",
                "index_patterns": ["*"]}
        form.update(overrides)
        return self.client.post("/dashboard/create", data=form,
                                follow_redirects=True)

    def stored(self):
        manager = self.app.dashboard_manager
        manager.refresh_cache()
        return next(d for d in manager.get_all_dashboards() if d.name == "Board")

    def test_the_create_form_offers_the_configured_sources(self):
        page = self.client.get("/dashboard/create").data.decode()
        self.assertIn('name="source"', page)
        self.assertIn("secondary", page)

    def test_a_chosen_source_is_stored(self):
        self.create(source="secondary")
        self.assertEqual(self.stored().source, "secondary")

    def test_it_is_the_source_the_panels_are_answered_from(self):
        """The point of storing it at all."""
        self.create(source="secondary")
        self.client.get(f"/api/dashboard/{self.stored().id}/data")
        self.assertEqual(self.primary.round_trips, 0)
        self.assertGreater(self.secondary.round_trips, 0)

    def test_choosing_nothing_leaves_it_on_the_default(self):
        self.create()
        self.assertIsNone(self.stored().source)

    def test_a_source_that_is_not_configured_is_refused_where_it_was_typed(self):
        """Stored, it would be reported to every reader for ever."""
        response = self.create(source="nowhere")
        self.assertIn(b"no log source called", response.data)
        manager = self.app.dashboard_manager
        manager.refresh_cache()
        self.assertEqual([d.name for d in manager.get_all_dashboards()], [])

    def test_the_edit_form_carries_the_current_source_and_can_change_it(self):
        self.create(source="secondary")
        board = self.stored()
        page = self.client.get(f"/dashboard/{board.id}/edit").data.decode()
        self.assertIn('name="source"', page)

        self.client.post(f"/dashboard/{board.id}/edit",
                         data={"name": "Board", "query": "*", "description": "",
                               "index_patterns": ["*"], "source": "primary"},
                         follow_redirects=True)
        self.assertEqual(self.stored().source, "primary")

    def test_it_can_be_put_back_on_the_default(self):
        self.create(source="secondary")
        board = self.stored()
        self.client.post(f"/dashboard/{board.id}/edit",
                         data={"name": "Board", "query": "*", "description": "",
                               "index_patterns": ["*"], "source": ""},
                         follow_redirects=True)
        self.assertIsNone(self.stored().source)

    def test_it_survives_a_round_trip_through_the_store(self):
        self.create(source="secondary")
        from wdash.models import Dashboard
        board = self.stored()
        self.assertEqual(Dashboard.from_dict(board.to_dict()).source,
                         "secondary")


class DatabaseSourceFormTest(SourceFormTest):
    """The same, on the store a deployment with two sources will be using."""

    STORAGE = "database"
