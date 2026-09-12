"""
What a panel may be grouped by, and who decides.

Four names — `severity`, `service`, `host`, `environment` — were offered to
every backend by the editor and enforced by `normalise`, and they were a UI
constant rather than a backend limit. Measured on the lab:

  * Elasticsearch's `app-logs-000001` maps ten fields that group cleanly
    (`correlation_id`, `duration_ms`, `environment`, `host`, `http_status`,
    `level`, `request_id`, `service`, `trace_id`, `user_id`) and answered
    `http_status` with 200: 878, 404: 326, 201: 296, 503: 295, 400: 291 —
    a panel nothing could store, because `normalise` refused the field;
  * Loki carries four labels (`detected_level`, `level`, `service_name`,
    `severity`) and answered `host` and `environment` with no rows at all;
  * VictoriaLogs writes `env`, not `environment`.

So the offer comes from the SOURCE. What it must not become is a fence:
`models.Dashboard.get_panels` calls `normalise_all` on every READ, and a
PanelError there is a 400 for the whole dashboard — so a source-specific
check there would make a re-pointed board, or a board whose cluster is down
for a minute, fail to open at all. The rule is split in two and this file
holds both halves:

  * `normalise` validates the SHAPE, offline and forever;
  * the source refuses what it cannot answer, per panel, with a reason.
"""

import os
import sys
import unittest

from tests.support import ModelledES, grant, install_dashboard

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.dashboard.panels import (  # noqa: E402
    AGGREGATABLE_FIELDS, PanelError, normalise, normalise_all,
)
from wdash.models import Dashboard  # noqa: E402

#: The lab's `app-logs-000001`, as its mapping actually reads.
LAB_MAPPING = {
    "@timestamp": {"type": "date"},
    "level": {"type": "keyword"},
    "service": {"type": "keyword"},
    "host": {"type": "keyword"},
    "environment": {"type": "keyword"},
    "http_status": {"type": "integer"},
    "user_id": {"type": "keyword"},
    "correlation_id": {"type": "keyword"},
    "request_id": {"type": "keyword"},
    "duration_ms": {"type": "integer"},
    "trace_id": {"type": "keyword"},
    # Analysed, with no keyword sub-field: aggregating on it returns one
    # bucket per WORD, which is the reason a closed list existed at all.
    "message": {"type": "text"},
    "note": {"type": "text"},
}


class StaticVocabularyTest(unittest.TestCase):
    """`normalise` decides the shape and nothing else."""

    def test_a_field_the_four_names_do_not_hold_is_kept(self):
        """The ceiling: `http_status` could not be stored on any board.

        Measured on the lab's Elasticsearch, which answers it with five
        buckets — the panel was unbuildable, not unanswerable.
        """
        panel = normalise({"type": "terms", "field": "http_status"})
        self.assertEqual(panel["field"], "http_status")
        self.assertEqual(
            normalise({"type": "timeseries", "split_by": "user_id"})["split_by"],
            "user_id")

    def test_the_log_line_is_still_refused(self):
        """An analysed body is one bucket per word, on every backend."""
        for field in ("body", "message", "_msg"):
            with self.assertRaises(PanelError, msg=field) as caught:
                normalise({"type": "terms", "field": field})
            self.assertIn(field, str(caught.exception))
        with self.assertRaises(PanelError):
            normalise({"type": "timeseries", "split_by": "body"})

    def test_a_name_that_is_not_a_field_name_is_refused(self):
        """And this is a security boundary, not tidiness.

        The name is interpolated into a LogQL `sum by (...)` clause and a
        LogsQL filter. A closed list of four could not carry a quote or a
        brace out of the editor; a field somebody types can.
        """
        for field in ('level"} | label_format bad="', "a b", "", "1st",
                      "x" * 200, "sum by (level)", "level;drop"):
            with self.assertRaises(PanelError, msg=repr(field)) as caught:
                normalise({"type": "terms", "field": field})
            # And the refusal has to leave somebody able to fix it: a rule
            # with no example is a form that says no and nothing else.
            self.assertTrue(
                any(name in str(caught.exception)
                    for name in AGGREGATABLE_FIELDS),
                f"the refusal of {field!r} names no field that does work: "
                f"{caught.exception}")

    def test_the_refusal_still_names_fields_that_do_work(self):
        with self.assertRaises(PanelError) as caught:
            normalise({"type": "terms", "field": "body"})
        for field in AGGREGATABLE_FIELDS:
            self.assertIn(field, str(caught.exception),
                          "the message must say what IS allowed")

    def test_normalise_asks_no_source_anything(self):
        """The whole reason the check is a shape.

        `normalise_all` runs on every read of every dashboard. A rule that
        consulted a backend would make a board unopenable whenever that
        backend was slow, down, or simply re-pointed — and unopenable as a
        400 for the WHOLE board, not one panel.
        """
        panels = normalise_all([
            {"id": "a", "type": "terms", "field": "http_status", "size": 5},
            {"id": "b", "type": "timeseries", "split_by": "not_a_field_here"},
        ])
        self.assertEqual([panel["field"] for panel in panels if "field" in panel],
                         ["http_status"])
        self.assertEqual(panels[1]["split_by"], "not_a_field_here")


class ElasticsearchOfferTest(unittest.TestCase):
    """Discovery is real on Elasticsearch, and it is the mapping's answer."""

    def source(self, mapping=None):
        from wdash.hub.adapters import ElasticsearchLogSource
        client = ModelledES({"app-logs-000001": (mapping or LAB_MAPPING, [])})
        return ElasticsearchLogSource(client, name="es-lab")

    def offered(self, mapping=None):
        from wdash.hub import Scope
        return self.source(mapping).group_by_fields(Scope.unrestricted())

    def test_every_mapped_field_that_groups_is_offered(self):
        self.assertEqual(
            sorted(self.offered()),
            ["correlation_id", "duration_ms", "environment", "host",
             "http_status", "request_id", "service", "severity", "trace_id",
             "user_id"])

    def test_an_analysed_field_is_not_offered(self):
        """`message` and `note` are text with no keyword sub-field: they are
        the one thing the closed list of four was protecting against."""
        offered = self.offered()
        self.assertNotIn("message", offered)
        self.assertNotIn("note", offered)
        self.assertNotIn("body", offered)

    def test_a_body_under_another_name_is_not_offered(self):
        """`body_text` is a keyword field, so discovery finds it — and it is
        the log line, which `normalise` refuses.

        A select offering a value the save refuses is not a warning: a
        refused save re-renders from the STORED list, so it is the author's
        whole panel list thrown away.
        """
        mapping = dict(LAB_MAPPING)
        mapping["body_text"] = {"type": "keyword"}
        offered = self.offered(mapping)
        self.assertNotIn("body", offered)
        self.assertNotIn("body_text", offered)
        for field in offered:
            normalise({"type": "terms", "field": field})

    def test_a_text_field_with_a_keyword_is_offered(self):
        """Because it CAN be grouped by — on `.keyword`, which the adapter
        resolves. Refusing it would be the closed list again, in a mapping."""
        mapping = dict(LAB_MAPPING)
        mapping["tenant"] = {"type": "text",
                             "fields": {"keyword": {"type": "keyword"}}}
        self.assertIn("tenant", self.offered(mapping))

    def test_a_clusters_own_spelling_is_offered_as_the_neutral_name(self):
        """`level` is offered as `severity`.

        The panel stores what the select says, and `severity` is what the
        other two backends answer too: a board built here still means the
        same question if it is re-pointed at Loki.
        """
        offered = self.offered()
        self.assertIn("severity", offered)
        self.assertNotIn("level", offered)

    def test_the_offer_is_the_indices_the_scope_reaches(self):
        from wdash.hub import Scope
        from wdash.hub.adapters import ElasticsearchLogSource
        client = ModelledES({
            "app-logs-000001": (LAB_MAPPING, []),
            "secret-logs-000001": ({"passport_number": {"type": "keyword"}}, []),
        })
        source = ElasticsearchLogSource(client, name="es-lab")

        everything = source.group_by_fields(Scope.unrestricted())
        self.assertIn("passport_number", everything)

        narrow = source.group_by_fields(
            Scope(principal="narrow", containers=("app-logs-*",)))
        self.assertNotIn("passport_number", narrow,
                         "a field only a forbidden index maps was disclosed")
        self.assertIn("http_status", narrow)

    def test_a_scope_that_permits_nothing_is_offered_nothing(self):
        from wdash.hub import Scope
        self.assertEqual(self.source().group_by_fields(Scope.nothing()), [])

    def test_an_unreadable_mapping_raises_rather_than_answering_empty(self):
        """[] is "there is nothing to group by", which is a different fact.

        The route turns the raised reason into a sentence beside the select;
        an empty list there would be a source with nothing to offer.
        """
        from wdash.hub import Scope
        from wdash.hub.adapters import ElasticsearchLogSource

        class Unreadable(ModelledES):
            @property
            def indices(self):
                class Indices:
                    def get_mapping(self, index=None, **kw):
                        raise RuntimeError("no view_index_metadata")
                return Indices()

        source = ElasticsearchLogSource(
            Unreadable({"app-logs-000001": (LAB_MAPPING, [])}), name="es-lab")
        with self.assertRaises(RuntimeError):
            source.group_by_fields(Scope.unrestricted())


class VictoriaLogsOfferTest(unittest.TestCase):
    """The sidebar's raw field list and a panel's offer are not the same list."""

    def build(self, names=("_msg", "_time", "_stream", "env", "host", "level",
                           "log.level", "service", "severity",
                           "severity_text", "trace_id")):
        from tests.test_conformance_victorialogs import FakeVictoriaLogs
        from wdash.hub.adapters.victorialogs import VictoriaLogsSource

        harness = FakeVictoriaLogs()
        harness.field_names = list(names)
        return VictoriaLogsSource("http://vl:9428", name="vl",
                                  session=harness), harness

    def test_the_four_severity_spellings_are_one_field_to_group_by(self):
        """Measured on the lab: eight names in the sidebar, five to group by.

        `_severity_terms` counts `level`, `severity`, `log.level` and
        `severity_text` together, so offering them separately would be four
        selects for one question — three of which answer a part of it.
        """
        from wdash.hub import Scope
        source, _ = self.build()
        self.assertEqual(source.group_by_fields(Scope.unrestricted()),
                         ["env", "host", "service", "severity", "trace_id"])

    def test_the_stores_own_fields_are_not_offered(self):
        from wdash.hub import Scope
        source, _ = self.build()
        offered = source.group_by_fields(Scope.unrestricted())
        for reserved in ("_msg", "_time", "_stream"):
            self.assertNotIn(reserved, offered)

    def test_the_offer_is_asked_within_the_scope(self):
        """`fields()` asks `*` over the whole store, which is right for the
        sidebar and wrong for a select that must not name a container the
        caller may not read."""
        from wdash.hub import Scope
        source, harness = self.build()
        source.group_by_fields(Scope(principal="narrow",
                                     containers=("api-gateway",)))
        asked = [request for request in harness._requests
                 if "field_names" in request["path"]]
        self.assertTrue(asked, "no field_names request was made")
        self.assertIn("api-gateway", asked[-1]["params"]["query"])
        self.assertNotIn("*", asked[-1]["params"]["query"])

    def test_a_read_that_fails_raises_rather_than_answering_empty(self):
        from wdash.hub import Scope
        from wdash.hub.adapters.victorialogs import VictoriaLogsError
        source, harness = self.build()
        harness.fail_next()
        with self.assertRaises(VictoriaLogsError):
            source.group_by_fields(Scope.unrestricted())


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "group-by-fields"
    DATABASE_URL = "sqlite:///:memory:"
    ELASTICSEARCH_URL = ""
    DASHBOARD_STORAGE = "database"


class EditorOfferRouteTest(unittest.TestCase):
    """What the editor is handed, and what happens when nobody can answer."""

    def setUp(self):
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource

        self.app = create_app(TestConfig)
        self.hub = Hub()
        self.hub.add_logs(ElasticsearchLogSource(
            ModelledES({"app-logs-000001": (LAB_MAPPING, [])}), name="es-lab"))
        self.app.hub = self.hub
        self.client = self.app.test_client()
        self.login(["dashboard:view", "dashboard:edit", "dashboard:create"])

    def login(self, permissions, indices=("*",)):
        grant(self.app, "u", permissions, indices)
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": list(permissions),
                "allowed_indices": list(indices),
                "allowed_trace_indices": ["*"], "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def ask(self, source=""):
        return self.client.get(
            f"/api/dashboard/group-by-fields?source={source}")

    def test_the_default_source_answers_with_its_own_fields(self):
        payload = self.ask().get_json()
        self.assertIn("http_status", payload["fields"])
        self.assertIn("severity", payload["fields"])
        self.assertIsNone(payload["reason"])

    def test_a_source_named_by_the_form_is_the_one_asked(self):
        from wdash.hub.adapters.loki import LokiLogSource

        class Labels:
            def get(self, url, params=None, **kw):
                class Response:
                    status_code = 200
                    text = ""

                    @staticmethod
                    def json():
                        if "/labels" in url:
                            return {"data": ["level", "service_name"]}
                        return {"data": ["billing"]}
                return Response()

        self.hub.add_logs(LokiLogSource("http://loki:3100", name="loki-lab",
                                        session=Labels()))
        payload = self.ask("loki-lab").get_json()
        self.assertEqual(payload["fields"], ["service", "severity"])
        self.assertIsNone(payload["reason"])
        # And the four names are still on the wire, because the editor needs
        # something to fall back to when the next source cannot answer.
        self.assertEqual(payload["standard"], list(AGGREGATABLE_FIELDS))

    def test_a_source_that_cannot_be_read_answers_with_a_reason(self):
        """The failure that must never look like emptiness.

        A blank select and a source with nothing to group by look identical,
        and only one of them is worth waiting out.
        """
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource

        class Down(ModelledES):
            @property
            def indices(self):
                class Indices:
                    def get_mapping(self, index=None, **kw):
                        raise RuntimeError("connection refused")
                return Indices()

        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(
            Down({"app-logs-000001": (LAB_MAPPING, [])}), name="es-lab"))
        self.app.hub = hub

        payload = self.ask().get_json()
        self.assertEqual(payload["fields"], list(AGGREGATABLE_FIELDS))
        self.assertIn("connection refused", payload["reason"])
        self.assertIn("es-lab", payload["reason"])

    def test_a_source_that_does_not_list_its_fields_says_that(self):
        from tests.support import StubLogSource
        from wdash.hub import Hub

        hub = Hub()
        hub.add_logs(StubLogSource(name="stub-logs"))
        self.app.hub = hub

        payload = self.ask().get_json()
        self.assertEqual(payload["fields"], list(AGGREGATABLE_FIELDS))
        self.assertIn("does not list", payload["reason"])

    def test_a_source_that_is_not_configured_says_so(self):
        payload = self.ask("gone").get_json()
        self.assertEqual(payload["fields"], list(AGGREGATABLE_FIELDS))
        self.assertIn("not configured", payload["reason"])

    def test_the_offer_needs_permission_to_edit_a_dashboard(self):
        self.login(["dashboard:view"])
        self.assertEqual(self.ask().status_code, 403)

    def test_the_editor_page_carries_the_offer_already(self):
        """Rendered with the form rather than fetched after it, so the select
        is never briefly showing four names that do not apply."""
        response = self.client.get("/dashboard/create")
        self.assertEqual(response.status_code, 200)
        self.assertIn("http_status", response.get_data(as_text=True))


class OnePanelRefusedNotTheBoardTest(unittest.TestCase):
    """The critique's warning, measured end to end.

    A board grouping by a field its source cannot answer must open, draw the
    panels that do answer, and put the reason on the one that does not.
    """

    def setUp(self):
        import datetime as dt

        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource

        # Inside whatever window the dashboard defaults to: a document a month
        # old would leave both panels empty and the test would pass for the
        # wrong reason.
        recent = (dt.datetime.now(dt.timezone.utc)
                  - dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(
            ModelledES({"app-logs-000001": (LAB_MAPPING, [
                {"_id": "1", "@timestamp": recent,
                 "level": "ERROR", "service": "pay", "http_status": 500,
                 "message": "boom"}])}), name="es-lab"))
        self.app.hub = hub

        install_dashboard(self.app, Dashboard(
            dashboard_id="board", name="Board", description="", query="*",
            created_by="u", index_patterns=["app-*"],
            panels=[
                {"id": "answerable", "type": "terms", "field": "http_status",
                 "size": 5, "width": 6, "height": 300},
                {"id": "unanswerable", "type": "terms",
                 "field": "passport_number", "size": 5, "width": 6,
                 "height": 300},
            ]))

        self.client = self.app.test_client()
        grant(self.app, "u", ["dashboard:view"], ("*",))
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": ["dashboard:view"],
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def panels(self, payload):
        return {panel["id"]: panel for panel in payload["panels"]}

    def test_the_board_opens_and_only_one_panel_carries_the_reason(self):
        response = self.client.get("/api/dashboard/board/data")
        self.assertEqual(response.status_code, 200,
                         "one unanswerable field failed the whole board")
        panels = self.panels(response.get_json())

        self.assertTrue(panels["answerable"]["buckets"],
                        "the panel that could be answered was not")
        self.assertEqual(panels["unanswerable"]["buckets"], [])
        self.assertTrue(panels["unanswerable"].get("partial"))
        self.assertIn("passport_number",
                      " ".join(panels["unanswerable"]["warnings"]))

    def test_the_edit_page_of_such_a_board_still_opens(self):
        """`normalise_all` runs there too, and a 400 would be the board."""
        grant(self.app, "u", ["dashboard:view", "dashboard:edit"], ("*",))
        with self.client.session_transaction() as session:
            session["user_data"]["permissions"] = ["dashboard:view",
                                                   "dashboard:edit"]
        self.assertEqual(self.client.get("/dashboard/board/edit").status_code,
                         200)


if __name__ == "__main__":
    unittest.main()
