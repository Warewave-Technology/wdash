"""
Why a panel is empty, and whose fault an empty page is.

Two halves of one honesty problem.

A panel that could not be answered drew "No data in this window" — a literal
in the client — while the reason sat in the page-level alert, which names the
source and not the panel. Matching the two by text does not work and these
tests hold the measurements that say so: only Loki puts the aggregation's name
in front of its reasons, Elasticsearch's commonest one names the FIELD (so two
panels grouping by the same field produce one indistinguishable sentence), and
a fan-out puts the SOURCE name in front of everything, which defeats a prefix
test outright. The reason travels under the aggregation's own name instead,
and every aggregation is named after the panel that asked for it.

The other half is which panels an empty page takes down with it. One route
fills every panel and it resolved the LOG source's containers before filling
any of them, so a trace panel — whose backend is a different one, and which
needs only the window and the caller's scope — went down with an Elasticsearch
outage, in the outage it exists for.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from tests.support import ModelledES, grant, install_dashboard

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.panels import normalise_all  # noqa: E402
from wdash.hub import LogQuery, Scope, Terms, TimeWindow  # noqa: E402
from wdash.hub.adapters import ElasticsearchLogSource  # noqa: E402
from wdash.models import Dashboard  # noqa: E402

WINDOW = TimeWindow.of("1h")

#: A keyword index and a text one, the shape the lab reproduces on purpose:
#: `bad-logs-000001` maps `level` as text, so `terms` on it cannot run while
#: everything else on the same board can.
KEYWORD_MAPPING = {"@timestamp": {"type": "date"},
                   "level": {"type": "keyword"},
                   "service": {"type": "keyword"},
                   "message": {"type": "text"}}
TEXT_LEVEL_MAPPING = {"@timestamp": {"type": "date"},
                      "level": {"type": "text"},
                      "service": {"type": "keyword"},
                      "message": {"type": "text"}}


def _records(count, service="payments"):
    """Records inside the window the route asks for by default.

    Dated from now rather than pinned: `ModelledES` evaluates the range
    clause, so a fixed date drifts out of the default hour and the panel that
    is supposed to ANSWER comes back empty — which is the very state these
    tests are distinguishing from a panel that could not be asked.
    """
    stamp = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    return [{"_id": f"r{i}", "@timestamp": stamp,
             "level": "ERROR", "service": service, "message": "boom"}
            for i in range(count)]


class _Board(unittest.TestCase):
    """One dashboard over one index, on a cluster that answers what it is
    asked. `ModelledES` evaluates the query and reads the mapping, so a field
    that is text really is refused rather than refused by a fixture."""

    MAPPING = TEXT_LEVEL_MAPPING

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "panel-reasons"
            DASHBOARD_STORAGE = "database"

        self.es = ModelledES({"app-logs-000001": (self.MAPPING, _records(7))})
        self.app = create_app(TestConfig)
        self.hub = Hub()
        self.hub.add_logs(ElasticsearchLogSource(self.es))
        self.app.hub = self.hub

        self.dashboard = install_dashboard(
            self.app, Dashboard("b1", "Board", "", "*", "u",
                                index_patterns=["app-*"]))
        self.client = self.app.test_client()
        grant(self.app, "u", permissions=["dashboard:view"], indices=["*"],
              trace_indices=["*"], services=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": ["dashboard:view"],
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def board(self, panels):
        from tests.support import change_dashboard
        change_dashboard(self.app, self.dashboard, panels=normalise_all(panels))
        response = self.client.get("/api/dashboard/b1/data")
        return response, response.get_json()

    def panels_by_id(self, payload):
        return {panel["id"]: panel for panel in payload["panels"]}


class UnanswerablePanelTest(_Board):
    """The panel that could not be asked says so where its chart would be."""

    def test_a_panel_whose_field_cannot_be_aggregated_carries_the_reason(self):
        """Measured before: the response for this board carried the sentence
        once, in the page-level `warnings`, and the panel itself carried
        `buckets: []` and nothing else — which the client draws as "No data in
        this window". The cluster holds 7 records; the panel is not empty, it
        is unanswerable."""
        _, payload = self.board([
            {"id": "by-level", "type": "terms", "field": "severity"},
            {"id": "by-service", "type": "terms", "field": "service"}])
        panels = self.panels_by_id(payload)

        reasons = panels["by-level"].get("warnings") or []
        self.assertTrue(reasons, "the panel carried no reason of its own")
        self.assertIn("cannot be aggregated", " ".join(reasons))
        self.assertTrue(panels["by-level"]["partial"])
        self.assertEqual(panels["by-level"]["buckets"], [])

    def test_the_panel_that_could_answer_is_untouched(self):
        """Otherwise every panel carries a caveat and nobody reads any."""
        _, payload = self.board([
            {"id": "by-level", "type": "terms", "field": "severity"},
            {"id": "by-service", "type": "terms", "field": "service"}])
        answered = self.panels_by_id(payload)["by-service"]

        self.assertEqual([bucket["count"] for bucket in answered["buckets"]], [7])
        self.assertNotIn("warnings", answered)
        self.assertNotIn("partial", answered)

    def test_two_panels_over_the_same_field_are_told_apart(self):
        """The reason names the FIELD and not the panel, so the page-level
        line is the same sentence for both. Keyed by the aggregation's name —
        which is the panel's id — each of them gets its own copy."""
        _, payload = self.board([
            {"id": "left", "type": "terms", "field": "severity", "size": 5},
            {"id": "right", "type": "terms", "field": "severity", "size": 9}])
        panels = self.panels_by_id(payload)

        for panel_id in ("left", "right"):
            with self.subTest(panel=panel_id):
                self.assertIn("cannot be aggregated",
                              " ".join(panels[panel_id].get("warnings") or []),
                              f"'{panel_id}' was left with no reason")

    def test_the_page_still_carries_the_reason_too(self):
        """A reader looking at the alert above the grid needs it as well; the
        panel copy is an addition, not a move."""
        _, payload = self.board([
            {"id": "by-level", "type": "terms", "field": "severity"}])
        self.assertIn("cannot be aggregated", " ".join(payload["warnings"]))


class KeywordBoardTest(_Board):
    """The same board on a cluster that can answer it: nothing is marked."""

    MAPPING = KEYWORD_MAPPING

    def test_an_answerable_board_carries_no_panel_warnings(self):
        _, payload = self.board([
            {"id": "by-level", "type": "terms", "field": "severity"},
            {"id": "by-service", "type": "terms", "field": "service"}])
        for panel in payload["panels"]:
            with self.subTest(panel=panel["id"]):
                self.assertNotIn("warnings", panel)
                self.assertNotIn("partial", panel)


class AdapterAttributionTest(unittest.TestCase):
    """Each adapter files a per-aggregation reason under that aggregation."""

    def test_elasticsearch_files_the_field_refusal_under_the_panel(self):
        es = ModelledES({"app-logs-000001": (TEXT_LEVEL_MAPPING, _records(3))})
        source = ElasticsearchLogSource(es)
        result = source.aggregate(
            LogQuery(window=WINDOW, text="*", containers=("app-logs-000001",)),
            [Terms(name="panel-a", field="severity", size=10),
             Terms(name="panel-b", field="service", size=10)],
            Scope.unrestricted())

        self.assertEqual(list(result.notes), ["panel-a"])
        self.assertIn("cannot be aggregated", result.reasons("panel-a")[0])
        self.assertEqual(result.reasons("panel-b"), ())

    def test_a_split_that_cannot_be_translated_belongs_to_its_panel(self):
        """A sub-aggregation is not on screen; the panel that carries it is.
        Filed under `split` it would reach no panel at all."""
        from wdash.hub import DateHistogram

        es = ModelledES({"app-logs-000001": (TEXT_LEVEL_MAPPING, _records(3))})
        source = ElasticsearchLogSource(es)
        result = source.aggregate(
            LogQuery(window=WINDOW, text="*", containers=("app-logs-000001",)),
            [DateHistogram(name="panel-c", interval="5m", min_count=0,
                           sub=(Terms(name="split", field="severity", size=10),))],
            Scope.unrestricted())

        self.assertEqual(list(result.notes), ["panel-c"])

    def test_a_scope_message_stays_on_the_page(self):
        """It is about the request, not about one panel. Attributing it would
        put the same sentence on every card."""
        source = ElasticsearchLogSource(
            ModelledES({"app-logs-000001": (KEYWORD_MAPPING, _records(1))}))
        result = source.aggregate(
            LogQuery(window=WINDOW, text="*", containers=("nothing-here",)),
            [Terms(name="panel-a", field="service", size=10)],
            Scope.unrestricted())

        self.assertEqual(result.notes, {})
        self.assertTrue(result.warnings)

    def test_a_shard_failure_stays_on_the_page(self):
        """The same rule, for the reason the lab produces live: five of
        fifteen shards failing on `Fielddata is disabled on [host] in
        [bad-logs-000001]` is one fact about the request, and every panel in
        the batch would wear it. The page is where it belongs, and the page
        already prints it."""
        class ShardsFail(ModelledES):
            def search(self, index=None, **kwargs):
                response = super().search(index=index, **kwargs)
                response["_shards"] = {
                    "total": 6, "failed": 5,
                    "failures": [{"reason": {"type": "illegal_argument_exception",
                                             "reason": "Fielddata is disabled"}}]}
                return response

        source = ElasticsearchLogSource(
            ShardsFail({"app-logs-000001": (KEYWORD_MAPPING, _records(2))}))
        result = source.aggregate(
            LogQuery(window=WINDOW, text="*", containers=("app-logs-000001",)),
            [Terms(name="panel-a", field="service", size=10),
             Terms(name="panel-b", field="service", size=10)],
            Scope.unrestricted())

        self.assertIn("5 of 6 shards failed", " ".join(result.warnings))
        self.assertEqual(result.notes, {},
                         "a request-level failure was pinned to a panel")


class LokiAttributionTest(unittest.TestCase):
    """Loki already named the aggregation in its warning text. That prefix is
    what the join was priced on, and it still has to survive as a key — and
    the page's own sentence has to survive unchanged beside it."""

    def build(self):
        from tests.test_conformance_loki import FakeLoki
        from wdash.hub.adapters.loki import LokiLogSource

        self.harness = FakeLoki()
        return LokiLogSource("http://loki:3100", name="loki",
                             session=self.harness)

    def aggregate(self, *aggregations):
        import datetime as dt

        source = self.build()
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        self.harness.vector = [{"metric": {}, "value": [0, "12"]}]
        return source.aggregate(
            LogQuery(window=TimeWindow.exact(now - dt.timedelta(hours=1), now),
                     text="*"),
            list(aggregations), Scope.unrestricted())

    def test_a_field_that_is_not_a_label_is_filed_under_its_panel(self):
        result = self.aggregate(Terms(name="panel-9", field="host", size=10))

        self.assertIn("not a Loki label", result.reasons("panel-9")[0])
        self.assertFalse(result.reasons("panel-9")[0].startswith("panel-9"),
                         "the panel does not need to be told which panel it is")

    def test_the_pages_own_sentence_is_unchanged(self):
        """It is the sentence the page-level alert has always printed, and
        moving the reason onto the panel must not rewrite it."""
        result = self.aggregate(Terms(name="panel-9", field="host", size=10))

        self.assertEqual(result.warnings, (
            "panel-9: 'host' is not a Loki label on these streams and cannot "
            "be counted by value",))

    def test_an_unsplittable_series_is_filed_under_its_panel(self):
        from wdash.hub import DateHistogram

        result = self.aggregate(DateHistogram(
            name="panel-8", sub=(Terms(name="split", field="severity"),)))

        self.assertIn("does not split", result.reasons("panel-8")[0])
        self.assertEqual(result.warnings,
                         ("panel-8: Loki does not split this series; it is "
                          "the total",))

    def test_a_panel_loki_could_answer_is_not_marked(self):
        result = self.aggregate(Terms(name="panel-7", field="severity", size=10))
        self.assertEqual(result.notes, {})


class VictoriaLogsAttributionTest(unittest.TestCase):
    """The adapter that prefixed nothing at all."""

    def test_an_unsupported_aggregation_is_filed_under_its_panel(self):
        import datetime as dt

        from tests.test_conformance_victorialogs import FakeVictoriaLogs
        from wdash.hub.adapters.victorialogs import VictoriaLogsSource

        class Unknown:
            name = "panel-6"

        source = VictoriaLogsSource("http://vl:9428", name="victorialogs",
                                    session=FakeVictoriaLogs())
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        result = source.aggregate(
            LogQuery(window=TimeWindow.exact(now - dt.timedelta(hours=1), now),
                     text="*"),
            [Unknown()], Scope.unrestricted())

        self.assertIn("not supported", result.reasons("panel-6")[0])
        self.assertTrue(result.warnings)


class FanOutAttributionTest(unittest.TestCase):
    """A fan-out keeps the panel and adds the source, rather than replacing
    the panel with the source."""

    def build(self):
        from wdash.hub.aggregation import AggregationResult, Bucket
        from wdash.hub.fanout import FanOutLogSource

        class Refuses:
            name = "loki-b"
            backend = "loki"
            capabilities = frozenset(ElasticsearchLogSource(
                ModelledES({})).capabilities)

            def containers(self, scope):
                return ["stream-1"]

            def aggregate(self, query, aggregations, scope):
                return AggregationResult(
                    total=0,
                    buckets={agg.name: [] for agg in aggregations},
                    warnings=tuple(
                        f"{agg.name}: 'host' is not a Loki label on these "
                        f"streams and cannot be counted by value"
                        for agg in aggregations),
                    notes={agg.name: ["'host' is not a Loki label on these "
                                      "streams and cannot be counted by value"]
                           for agg in aggregations})

        class Answers(Refuses):
            name = "es-a"
            backend = "elasticsearch"

            def containers(self, scope):
                return ["app-logs-000001"]

            def aggregate(self, query, aggregations, scope):
                return AggregationResult(
                    total=4,
                    buckets={agg.name: [Bucket(key="h1", count=4)]
                             for agg in aggregations})

        return FanOutLogSource([Answers(), Refuses()], name="everything")

    def test_the_panel_key_survives_the_fan_out(self):
        """The page-level list reads "loki-b: panel-1: 'host' is not …", so a
        `startswith(panel_id)` test finds nothing there. The key is what
        survives."""
        result = self.build().aggregate(
            LogQuery(window=WINDOW, text="*", containers=()),
            [Terms(name="panel-1", field="host", size=10)],
            Scope.unrestricted())

        self.assertEqual(list(result.notes), ["panel-1"])
        self.assertFalse(any(note.startswith("panel-1")
                             for note in result.warnings),
                         "the page-level warning was matchable by prefix "
                         "after all — this test is measuring nothing")

    def test_the_refusing_member_is_named_in_the_panel_reason(self):
        """One member of a fan-out refusing a panel the other answered is the
        whole reason for saying which."""
        result = self.build().aggregate(
            LogQuery(window=WINDOW, text="*", containers=()),
            [Terms(name="panel-1", field="host", size=10)],
            Scope.unrestricted())

        self.assertEqual(len(result.reasons("panel-1")), 1)
        self.assertTrue(result.reasons("panel-1")[0].startswith("loki-b: "),
                        result.reasons("panel-1"))


class LogOutageTest(_Board):
    """A board whose log source is down answers what it can."""

    MAPPING = KEYWORD_MAPPING

    def source_is_down(self):
        source = self.hub.logs()
        original = source.containers

        def failing(scope, *args, **kwargs):
            raise ConnectionError("cluster unreachable")
        source.containers = failing
        self.addCleanup(setattr, source, "containers", original)

    def with_traces(self):
        from wdash.hub.models import Service
        self.hub.add_traces(_Traces())
        self.hub.traces().services = lambda window, scope: [
            Service(name="payments", span_count=12, error_count=1)]

    def test_a_trace_panel_survives_a_log_backend_that_is_down(self):
        """Measured before: 503 for the whole page, and `showLoadError` then
        wipes the grid — so the panel whose own backend was healthy went down
        with the one that was not, in the outage it exists for."""
        self.with_traces()
        self.source_is_down()
        response, payload = self.board([
            {"id": "logs-1", "type": "terms", "field": "service"},
            {"id": "traces-1", "type": "trace_services", "sort": "spans"}])

        self.assertEqual(response.status_code, 200, payload)
        panels = self.panels_by_id(payload)
        self.assertEqual([row["name"] for row in panels["traces-1"]["rows"]],
                         ["payments"])

    def test_the_log_panels_say_why_rather_than_going_blank(self):
        self.with_traces()
        self.source_is_down()
        _, payload = self.board([
            {"id": "logs-1", "type": "terms", "field": "service"},
            {"id": "traces-1", "type": "trace_services", "sort": "spans"}])

        blamed = self.panels_by_id(payload)["logs-1"]["error"]
        self.assertIn("Unable to connect", blamed)
        self.assertIn(payload["source"], blamed)

    def test_the_page_still_says_the_source_is_down(self):
        """The panels that answered must not make the outage look like a
        complete page."""
        self.with_traces()
        self.source_is_down()
        response, payload = self.board([
            {"id": "logs-1", "type": "terms", "field": "service"},
            {"id": "traces-1", "type": "trace_services", "sort": "spans"}])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["error_type"], "elasticsearch_connection")
        self.assertIn(payload["source"], payload["error"])

    def test_the_counts_are_absent_rather_than_zero(self):
        """`total_hits: 0` under a backend that did not answer is the same
        failure-as-emptiness the panels were just stopped from telling. The
        client prints an em dash for a count that is not there."""
        self.with_traces()
        self.source_is_down()
        response, payload = self.board([
            {"id": "logs-1", "type": "terms", "field": "service"},
            {"id": "traces-1", "type": "trace_services", "sort": "spans"}])

        self.assertEqual(response.status_code, 200, "the page did not open at "
                         "all, so this measures nothing")
        self.assertEqual(len(payload["panels"]), 2)
        for key in ("total_hits", "error_count", "warn_count", "info_count",
                    "error_rate"):
            with self.subTest(key=key):
                self.assertNotIn(key, payload)

    def test_a_board_of_log_panels_alone_still_fails_loudly(self):
        """There is nothing to show, and the status line is where the client
        reads that. A 200 carrying an empty grid would be worse."""
        self.with_traces()
        self.source_is_down()
        response, _ = self.board([
            {"id": "logs-1", "type": "terms", "field": "service"}])
        self.assertEqual(response.status_code, 503)

    def test_a_source_that_is_gone_costs_the_log_panels_only(self):
        """A dashboard naming a source that is not configured is a
        configuration error for the panels that read it, not for the trace
        panel beside them."""
        from tests.support import change_dashboard

        self.with_traces()
        change_dashboard(self.app, self.dashboard, source="retired")
        response, payload = self.board([
            {"id": "logs-1", "type": "terms", "field": "service"},
            {"id": "traces-1", "type": "trace_services", "sort": "spans"}])

        self.assertEqual(response.status_code, 200, payload)
        self.assertEqual(payload["error_type"], "source_missing")
        panels = self.panels_by_id(payload)
        self.assertIn("retired", panels["logs-1"]["error"])
        self.assertEqual(len(panels["traces-1"]["rows"]), 1)

    def test_a_scope_reaching_no_container_still_draws_the_trace_panel(self):
        """es_monitors and the trace source decide their own visibility; the
        log scope is about log data. This board's patterns reach nothing this
        caller may read, and that is not a fact about traces."""
        self.with_traces()
        from tests.support import change_dashboard
        change_dashboard(self.app, self.dashboard,
                         index_patterns=["nothing-here-*"])
        response, payload = self.board([
            {"id": "logs-1", "type": "terms", "field": "service"},
            {"id": "traces-1", "type": "trace_services", "sort": "spans"}])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["error_type"], "no_accessible_containers")
        panels = self.panels_by_id(payload)
        self.assertEqual(len(panels["traces-1"]["rows"]), 1)
        self.assertIn("No accessible indices", panels["logs-1"]["error"])

    def test_no_accessible_container_gives_every_panel_a_reason(self):
        """It used to answer `panels: []` — an empty grid under one sentence,
        which is the forbidden failure drawn at page size."""
        from tests.support import change_dashboard
        change_dashboard(self.app, self.dashboard,
                         index_patterns=["nothing-here-*"])
        response, payload = self.board([
            {"id": "logs-1", "type": "terms", "field": "service"},
            {"id": "logs-2", "type": "terms", "field": "host"}])

        self.assertEqual(response.status_code, 200)
        panels = self.panels_by_id(payload)
        self.assertEqual(sorted(panels), ["logs-1", "logs-2"])
        for panel_id in ("logs-1", "logs-2"):
            self.assertIn("No accessible indices", panels[panel_id]["error"])
        self.assertEqual(payload["total_hits"], 0,
                         "no container was queried, so zero is the answer")


class _Traces:
    """The smallest trace source the panel filler will accept."""

    name = "traces"
    backend = "test"

    def __init__(self):
        from wdash.hub import Capability
        self.capabilities = frozenset({Capability.SERVICE_LIST})

    def supports(self, capability):
        return capability in self.capabilities

    def services(self, window, scope):
        return []
