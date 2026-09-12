"""
The two tables people keep asking a dashboard for.

A records panel and a trace-list panel, and the two honesty rules they each
carry.

RECORDS. The endpoint that lists a dashboard's newest records has existed,
gated and time-bounded, since the access bugs in its docstring were fixed, and
nothing on any page called it. On the board it has to agree with the charts
beside it — the same query, the same ad-hoc filter, the same window — because
a table of records that disagrees with the bars above it is worse than no
table. And its footer is a claim about the backend rather than about the
numbers: Elasticsearch and VictoriaLogs report a match count, Loki returns up
to a limit and stops, so "10 of 10" from Loki would be a total nobody
measured.

TRACES. A trace list is not a branch inside the panel that already exists: it
calls a different adapter method and takes a round trip of its own, and on
Jaeger with no service named it fans out one request per service. Measured on
the lab's 7-service Jaeger at 24h: 8 HTTP requests and 52 ms with no service
named, 1 and 3 ms with one. So the panel names a service — which also makes
the service boundary the Traces page already applies the natural check here,
in a route that asks about `dashboard:*` and never about traces at all.

Both panels are filled per panel with a reason when they cannot be answered:
a failure must never look like an empty window.
"""

import copy
import os
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone

from tests.support import (
    ModelledES, change_dashboard, grant, install_dashboard,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.panels import (  # noqa: E402
    MAX_RECORDS, PANEL_TYPES, PanelError, TRACE_LIST_VIEWS, normalise,
    normalise_all,
)
from wdash.hub import Capability, SORT_RECENT, SORT_SLOWEST  # noqa: E402
from wdash.hub.adapters import ElasticsearchLogSource  # noqa: E402
from wdash.hub.models import PartialList, TraceSummary  # noqa: E402
from wdash.models import Dashboard  # noqa: E402

KEYWORD_MAPPING = {"@timestamp": {"type": "date"},
                   "level": {"type": "keyword"},
                   "service": {"type": "keyword"},
                   "message": {"type": "text"}}


def _record(index, service="payments", level="ERROR", message="boom",
            minutes_ago=5):
    stamp = (datetime.now(timezone.utc)
             - timedelta(minutes=minutes_ago)).isoformat()
    return {"_id": f"r{index}", "@timestamp": stamp, "level": level,
            "service": service, "message": message}


def _cluster(records):
    return ModelledES({"app-logs-000001": (KEYWORD_MAPPING, records)})


class _CountingLogs(ElasticsearchLogSource):
    """The real adapter, counting the round trips it takes.

    A records panel is a SEARCH and the charts are an aggregation batch, so
    "how many requests does this board cost" is a question about this class
    and not about the cluster underneath it.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.searches = []
        self.batches = []

    def search(self, query, scope):
        self.searches.append(query)
        return super().search(query, scope)

    def multi_aggregate(self, batch, scope):
        self.batches.append(batch)
        return super().multi_aggregate(batch, scope)


class _Traces:
    """A trace source that answers the query it is asked.

    Deliberately not a fixture that returns the same rows whatever it is
    given: the service filter, the error filter, the sort and the limit are
    all applied here, so a panel that asked for the wrong thing comes back
    with the wrong rows rather than with the right ones by accident.
    """

    name = "test-traces"
    backend = "test"

    def __init__(self, summaries=(), fail=None, partial=()):
        self.capabilities = frozenset({Capability.TRACE_SEARCH,
                                       Capability.SERVICE_LIST})
        self._summaries = list(summaries)
        self.fail = fail
        self.partial = tuple(partial)
        self.queries = []

    def supports(self, capability):
        return capability in self.capabilities

    def services(self, window, scope):
        return []

    def search(self, query, scope):
        self.queries.append(query)
        if self.fail:
            raise self.fail
        rows = [s for s in self._summaries
                if not query.service or s.service == query.service]
        if query.only_errors:
            rows = [s for s in rows if s.has_error]
        if query.sort == SORT_SLOWEST:
            rows.sort(key=lambda s: s.duration_us, reverse=True)
        else:
            rows.sort(key=lambda s: s.start, reverse=True)
        return PartialList(rows[:query.limit], partial=bool(self.partial),
                           warnings=self.partial)


def _summary(trace_id, service="payments", duration_us=1000,
             has_error=False, minutes_ago=5):
    return TraceSummary(
        trace_id=trace_id, service=service, name=f"GET /{service}",
        start=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        duration_us=duration_us, has_error=has_error)


class _Board(unittest.TestCase):
    """One dashboard over one index on a cluster that answers what it is
    asked."""

    RECORDS = [_record(0, service="payments", level="ERROR", message="boom"),
               _record(1, service="payments", level="INFO", message="fine"),
               _record(2, service="search", level="WARN", message="slow"),
               _record(3, service="search", level="INFO", message="ok")]
    PERMISSIONS = ["dashboard:view", "traces:read"]
    SERVICES = ["*"]

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "dashboard-tables"
            DASHBOARD_STORAGE = "database"

        # Deep-copied: `ModelledES` takes each document's `_id` out of the
        # dict it is given, so a shared class attribute survives exactly one
        # test.
        self.es = _cluster(copy.deepcopy(self.RECORDS))
        self.app = create_app(TestConfig)
        self.hub = Hub()
        self.logs = _CountingLogs(self.es)
        self.hub.add_logs(self.logs)
        self.app.hub = self.hub

        self.dashboard = install_dashboard(
            self.app, Dashboard("b1", "Board", "", "*", "u",
                                index_patterns=["app-*"]))
        self.client = self.app.test_client()
        grant(self.app, "u", permissions=self.PERMISSIONS, indices=["*"],
              trace_indices=["*"], services=self.SERVICES)
        with self.client.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": "u@x", "username": "u",
                                    "groups": []}
            session["_user_id"] = "1"

    def with_traces(self, source):
        self.hub.add_traces(source)
        return source

    def board(self, panels, narrow=None, **fields):
        if fields:
            change_dashboard(self.app, self.dashboard, **fields)
        change_dashboard(self.app, self.dashboard, panels=normalise_all(panels))
        url = "/api/dashboard/b1/data"
        if narrow is not None:
            url += f"?q={narrow}"
        response = self.client.get(url)
        return response, response.get_json()

    def panels_by_id(self, payload):
        return {panel["id"]: panel for panel in payload["panels"]}


# ---------------------------------------------------------------------------
# D6 — the records panel
# ---------------------------------------------------------------------------

class RecordsPanelTest(_Board):
    """The newest records, on the board."""

    PANEL = {"id": "recs", "type": "records", "size": 10}

    def test_a_records_panel_lists_the_records(self):
        """Before: `records` was not a panel type at all, and the route that
        could answer it was called by nothing in static/ or templates/."""
        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["recs"]

        self.assertEqual(len(panel["rows"]), 4, panel)
        row = panel["rows"][0]
        for key in ("timestamp", "severity", "service", "body"):
            self.assertIn(key, row, "the row is missing a column the table draws")

    def test_the_rows_honour_the_ad_hoc_filter(self):
        """The filter narrows the charts. A table beside them listing records
        the bars do not count is the disagreement this panel exists to
        remove: the cluster holds 4 records and 2 of them are payments."""
        _, payload = self.board([self.PANEL], narrow="service:payments")
        panel = self.panels_by_id(payload)["recs"]

        self.assertEqual([r["service"] for r in panel["rows"]],
                         ["payments", "payments"], panel["rows"])
        self.assertEqual(panel["total"], 2)

    def test_the_rows_honour_the_dashboards_own_query(self):
        """And the dashboard's query is ANDed with the filter, never replaced
        — the one record that is both a payments record and an error."""
        _, payload = self.board([self.PANEL], narrow="service:payments",
                                query="level:ERROR")
        panel = self.panels_by_id(payload)["recs"]

        self.assertEqual(len(panel["rows"]), 1, panel["rows"])
        self.assertEqual(panel["rows"][0]["severity"], "ERROR")

    def test_the_footer_reads_the_count_off_the_source(self):
        """`total` is the match count and `counted` says it is one. The panel
        shows 2 of 4: a footer built from the rows alone would say 2 of 2."""
        _, payload = self.board([{**self.PANEL, "size": 2}])
        panel = self.panels_by_id(payload)["recs"]

        self.assertEqual(len(panel["rows"]), 2)
        self.assertEqual(panel["total"], 4)
        self.assertIs(panel["counted"], True)

    def test_two_records_panels_cost_one_search(self):
        """They ask the same question and differ only in how many rows they
        show, so the search runs once at the larger size and is sliced. One
        search per panel would double the cost of the cheapest new panel
        there is."""
        _, payload = self.board([{**self.PANEL, "size": 2},
                                 {**self.PANEL, "id": "recs2", "size": 4}])
        panels = self.panels_by_id(payload)

        self.assertEqual(len(self.logs.searches), 1,
                         f"{len(self.logs.searches)} searches for two panels")
        self.assertEqual(len(panels["recs"]["rows"]), 2)
        self.assertEqual(len(panels["recs2"]["rows"]), 4)

    def test_the_search_asks_for_the_window_the_charts_were_drawn_from(self):
        """Not a window of its own. `TimeWindow.of` widens a range by up to
        one bucket and `query.py` says to use `exact` when listing raw
        records — right for a page of records on its own, wrong for a table
        beside four charts: measured on the lab at 24h the aligned window
        holds 5,015 records and the exact one 5,005, and every bar counts
        those ten."""
        self.board([self.PANEL,
                    {"id": "chart", "type": "terms", "field": "service"}])
        charted = self.batches_window()

        self.assertEqual(self.logs.searches[0].window, charted)
        self.assertEqual(self.logs.searches[0].text, self.batches_text())

    def batches_window(self):
        return self.logs.batches[0][0][0].window

    def batches_text(self):
        return self.logs.batches[0][0][0].text

    def test_a_search_that_fails_is_not_an_empty_table(self):
        """The aggregation batch has already answered, so the charts are on
        screen; a card reading "no records" beside them would be read as a
        quiet window."""
        def failing(query, scope):
            raise ConnectionError("cluster unreachable")
        self.logs.search = failing

        response, payload = self.board([
            {"id": "chart", "type": "terms", "field": "service"}, self.PANEL])
        panels = self.panels_by_id(payload)

        self.assertEqual(response.status_code, 200, payload)
        self.assertIn("could not be read", panels["recs"].get("error", ""))
        self.assertEqual(len(panels["chart"]["buckets"]), 2)

    def test_the_panel_says_why_in_a_log_outage(self):
        """A records panel is a LOG panel: it needs the containers, and in an
        outage it must say so rather than drawing an empty table. Measured
        beside a panel that CAN still be answered, which is the board an
        operator opens during one."""
        self.with_traces(_Traces([_summary("aaa", "payments")]))

        def failing(scope, *args, **kwargs):
            raise ConnectionError("cluster unreachable")
        self.logs.containers = failing

        response, payload = self.board([
            self.PANEL,
            {"id": "traces", "type": "trace_list", "service": "payments"}])
        panel = self.panels_by_id(payload)["recs"]

        self.assertEqual(response.status_code, 200, payload)
        self.assertIn("Unable to connect", panel.get("error", ""))
        self.assertNotIn("rows", panel)

    def test_the_panel_says_why_when_no_container_can_be_read(self):
        """The other half: the source answered and the scope reaches none of
        the dashboard's containers. Nothing was queried, so an empty table
        here is a claim about a window nobody looked at."""
        self.logs.containers = lambda scope, *a, **kw: ()

        response, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["recs"]

        self.assertEqual(response.status_code, 200, payload)
        self.assertIn("No accessible indices", panel.get("error", ""))
        self.assertNotIn("rows", panel)

    def test_the_row_count_is_bounded(self):
        """A record is 381 bytes of JSON against 41 for a bucket, measured on
        the lab; a panel asking for a thousand is a card nobody can load."""
        panel = normalise({"type": "records", "size": 1000})
        self.assertEqual(panel["size"], MAX_RECORDS)


class UncountedRecordsTest(_Board):
    """A backend that does not report a match count.

    Loki answers a range query by returning up to a limit and stopping, so its
    total is the number returned. Measured against the lab at 24h: Loki 10
    records, total 10, counted False, warned "Loki reports no match count";
    Elasticsearch 10 of 5,015 and VictoriaLogs 10 of 681, both counted. The
    footer has to read the flag, because `len(rows) == total` is also what a
    quiet hour on Elasticsearch looks like.
    """

    def uncounted(self):
        from wdash.hub.models import LogPage
        real = self.logs.search

        def stopping(query, scope):
            page = real(query, scope)
            return LogPage(records=page.records, total=len(page.records),
                           counted=False, containers=page.containers,
                           warnings=("Loki reports no match count; the total "
                                     "shown is the number returned",))
        self.logs.search = stopping

    def test_a_source_that_does_not_count_says_so(self):
        self.uncounted()
        _, payload = self.board([{"id": "recs", "type": "records", "size": 2}])
        panel = self.panels_by_id(payload)["recs"]

        self.assertIs(panel["counted"], False)
        self.assertEqual(panel["total"], 2)
        self.assertIn("no match count", " ".join(panel.get("warnings") or []))

    def test_a_counting_source_is_not_marked(self):
        """Otherwise every board carries the caveat and nobody reads any."""
        _, payload = self.board([{"id": "recs", "type": "records", "size": 2}])
        panel = self.panels_by_id(payload)["recs"]

        self.assertIs(panel["counted"], True)
        self.assertNotIn("warnings", panel)


# ---------------------------------------------------------------------------
# D9 — the trace list panel
# ---------------------------------------------------------------------------

class TraceListPanelTest(_Board):
    """Individual traces for one service."""

    PANEL = {"id": "traces", "type": "trace_list", "service": "payments",
             "view": "slowest", "size": 5}
    SUMMARIES = (_summary("aaa", "payments", 5_000, has_error=False,
                          minutes_ago=30),
                 _summary("bbb", "payments", 9_000, has_error=True,
                          minutes_ago=20),
                 _summary("ccc", "payments", 1_000, has_error=False,
                          minutes_ago=1),
                 _summary("ddd", "search", 99_000, has_error=True,
                          minutes_ago=2))

    def setUp(self):
        super().setUp()
        self.traces = self.with_traces(_Traces(self.SUMMARIES))

    def test_a_trace_list_panel_lists_traces(self):
        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["traces"]

        self.assertEqual([r["trace_id"] for r in panel["rows"]],
                         ["bbb", "aaa", "ccc"], panel["rows"])

    def test_the_row_carries_what_the_waterfall_link_needs(self):
        """The click opens the trace's own page, and that page needs the id
        and the store that answered — without the source it looks in
        whichever store is first and reports the trace as missing."""
        _, payload = self.board([self.PANEL])
        row = self.panels_by_id(payload)["traces"]["rows"][0]

        self.assertEqual(row["source"], "test-traces")
        self.assertTrue(row["trace_id"])
        self.assertEqual(row["duration_us"], 9_000)
        self.assertIs(row["has_error"], True)

    def test_each_view_asks_the_query_it_names(self):
        """"errors" is not an ordering: it is the newest list with the
        successful requests taken out. A view that mapped to the wrong pair
        would still draw a table, which is why this reads the query."""
        wanted = {"slowest": (SORT_SLOWEST, False),
                  "recent": (SORT_RECENT, False),
                  "errors": (SORT_RECENT, True)}
        self.assertEqual(sorted(wanted), sorted(TRACE_LIST_VIEWS))

        for view, (sort, only_errors) in wanted.items():
            with self.subTest(view=view):
                self.traces.queries.clear()
                self.board([{**self.PANEL, "view": view}])
                asked = self.traces.queries[-1]
                self.assertEqual(asked.sort, sort)
                self.assertEqual(asked.only_errors, only_errors)
                self.assertEqual(asked.service, "payments")

    def test_the_errors_view_lists_only_failures(self):
        _, payload = self.board([{**self.PANEL, "view": "errors"}])
        rows = self.panels_by_id(payload)["traces"]["rows"]

        self.assertEqual([r["trace_id"] for r in rows], ["bbb"])

    def test_two_panels_asking_the_same_question_cost_one_request(self):
        """A trace list cannot ride the service panel's call — it is a
        different adapter method — so the only saving available is not asking
        the same question twice. And both panels are answered from it: a
        share that leaves one of them empty has drawn "no traces" over a
        question that was asked and answered."""
        _, payload = self.board([self.PANEL, {**self.PANEL, "id": "traces2"}])
        panels = self.panels_by_id(payload)

        self.assertEqual(len(self.traces.queries), 1,
                         f"{len(self.traces.queries)} requests for one question")
        self.assertEqual(len(panels["traces"].get("rows") or []), 3)
        self.assertEqual(len(panels["traces2"].get("rows") or []), 3)

    def test_two_panels_asking_different_questions_cost_two(self):
        """And the cost is stated rather than hidden: a board with two
        different trace lists on it takes two round trips."""
        self.board([self.PANEL, {**self.PANEL, "id": "traces2",
                                 "view": "errors"}])
        self.assertEqual(len(self.traces.queries), 2)

    def test_a_backend_that_refuses_the_window_says_why(self):
        """Tempo refuses a range over 168 hours, and the dashboard's own
        "Last 7 days" is 168.25. Measured against the lab: HTTP 400 "range
        specified by start and end exceeds 168h0m0s". An empty table would
        send the reader looking for a service that had stopped."""
        self.traces.fail = RuntimeError(
            "range specified by start and end exceeds 168h0m0s")

        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["traces"]

        self.assertIn("168h0m0s", panel.get("error", ""))
        self.assertNotIn("rows", panel)

    def test_a_store_that_answered_short_is_marked(self):
        """Tempo and Jaeger sort the rows they fetched rather than the
        window, and a fan-out member that did not reply is not a quieter
        hour."""
        self.traces.partial = ("lab-tempo did not answer",)

        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["traces"]

        self.assertIs(panel.get("partial"), True, panel)
        self.assertIn("lab-tempo", " ".join(panel.get("warnings") or []))

    def test_no_trace_backend_is_a_reason_not_an_empty_table(self):
        hub_traces = self.hub.traces
        self.hub.traces = lambda name=None: None

        _, payload = self.board([self.PANEL])
        self.hub.traces = hub_traces
        panel = self.panels_by_id(payload)["traces"]

        self.assertIn("No trace backend", panel.get("error", ""))

    def test_a_source_that_cannot_search_says_so(self):
        """A trace source with a service list and no search — the shape the
        capability flag exists for — must not draw an empty list."""
        self.traces.capabilities = frozenset({Capability.SERVICE_LIST})

        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["traces"]

        self.assertIn("No trace backend", panel.get("error", ""))

    def test_the_panel_survives_a_log_outage(self):
        """Its question never goes to the log source. An operator opens a
        board in an Elasticsearch outage to find out what is still moving."""
        def failing(scope, *args, **kwargs):
            raise ConnectionError("cluster unreachable")
        self.logs.containers = failing

        response, payload = self.board([
            {"id": "chart", "type": "terms", "field": "service"}, self.PANEL])
        panels = self.panels_by_id(payload)

        self.assertEqual(response.status_code, 200, payload)
        self.assertEqual(len(panels["traces"]["rows"]), 3)
        self.assertIn("Unable to connect", panels["chart"].get("error", ""))


class TraceListBoundaryTest(_Board):
    """What a role may reach is decided per service, and this route never
    asked.

    `dashboard_routes` checks `dashboard:*` and nothing else — the traces page
    refuses a service through `_may_see_service` and a dashboard was a way
    round it. Both halves are refused HERE, at panel-fill time, so the rest of
    the board is unaffected.
    """

    PANEL = {"id": "traces", "type": "trace_list", "service": "payments",
             "view": "recent", "size": 5}
    PERMISSIONS = ["dashboard:view"]          # no traces:read
    SERVICES = ["*"]

    def setUp(self):
        super().setUp()
        self.traces = self.with_traces(_Traces([_summary("aaa", "payments")]))

    def test_a_role_without_traces_read_is_refused_this_panel(self):
        _, payload = self.board([
            {"id": "chart", "type": "terms", "field": "service"}, self.PANEL])
        panels = self.panels_by_id(payload)

        self.assertIn("traces:read", panels["traces"].get("error", ""))
        self.assertEqual(self.traces.queries, [],
                         "the search ran anyway")
        self.assertEqual(len(panels["chart"]["buckets"]), 2,
                         "the rest of the board was taken down with it")


class TraceListServiceRuleTest(_Board):
    """A service the role may not see."""

    PANEL = {"id": "traces", "type": "trace_list", "service": "payments",
             "view": "recent", "size": 5}
    PERMISSIONS = ["dashboard:view", "traces:read"]
    SERVICES = ["search"]

    def setUp(self):
        super().setUp()
        self.traces = self.with_traces(_Traces([_summary("aaa", "payments")]))

    def test_a_service_outside_the_rule_is_refused_by_name(self):
        """Named, because the reader is the person who has to ask for it. An
        empty table would read as "that service ran nothing"."""
        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["traces"]

        self.assertIn("payments", panel.get("error", ""))
        self.assertIn("boundary", panel.get("error", ""))
        self.assertEqual(self.traces.queries, [],
                         "the search was issued for a service the role "
                         "cannot see")

    def test_a_service_inside_the_rule_still_answers(self):
        _, payload = self.board([{**self.PANEL, "service": "search"}])
        panel = self.panels_by_id(payload)["traces"]

        self.assertNotIn("error", panel)


# ---------------------------------------------------------------------------
# The panel definitions themselves
# ---------------------------------------------------------------------------

class PanelDefinitionTest(unittest.TestCase):

    def test_a_trace_list_must_name_a_service(self):
        """Not a default. With no service Jaeger searches every service it
        knows — 8 HTTP requests against the lab's 7-service Jaeger versus 1
        — on every load and every 30-second refresh."""
        with self.assertRaises(PanelError) as caught:
            normalise({"type": "trace_list", "view": "slowest"})
        self.assertIn("service", str(caught.exception))

    def test_a_trace_list_view_is_one_of_three(self):
        with self.assertRaises(PanelError) as caught:
            normalise({"type": "trace_list", "service": "payments",
                       "view": "oldest"})
        self.assertIn("oldest", str(caught.exception))

    def test_a_trace_list_defaults_to_the_slowest(self):
        panel = normalise({"type": "trace_list", "service": "payments"})
        self.assertEqual(panel["view"], "slowest")
        self.assertEqual(panel["size"], 5)

    def test_the_new_panels_declare_a_signal_that_is_filled(self):
        """A row with no filler reads as "No data in this window", which is a
        claim about the data made about a question nobody asked."""
        from wdash.api.dashboard_routes import FILLED_SIGNALS

        for kind in ("records", "trace_list"):
            with self.subTest(kind=kind):
                self.assertIn(PANEL_TYPES[kind]["signal"], FILLED_SIGNALS)

    def test_a_records_panel_asks_the_log_source(self):
        """It is a log panel and must share the log source's fate: a table of
        records drawn through an Elasticsearch outage would be empty and
        silent."""
        from wdash.dashboard.panels import needs_logs

        self.assertTrue(needs_logs({"type": "records"}))
        self.assertFalse(needs_logs({"type": "trace_list"}))

    def test_every_panel_type_has_a_hint_the_client_can_draw(self):
        """The header hint is looked up by panel type and falls back to the
        empty string, so a new panel type ships with a blank caption — and
        before the table existed, with "Click a value to filter by it", a
        promise nothing kept. One entry per type, checked here because the
        two files cannot see each other."""
        source = open(os.path.join(os.path.dirname(__file__), "..",
                                   "static", "js", "async-dashboard.js"),
                      encoding="utf-8").read()
        block = re.search(r"const PANEL_HINTS = [^;]+?\}\);", source, re.S)
        self.assertIsNotNone(block, "PANEL_HINTS is not where it was")
        named = set(re.findall(r"^\s{4}(\w+):", block.group(0), re.M))

        self.assertEqual(sorted(set(PANEL_TYPES) - named), [],
                         "a panel type the client has no caption for")


# ---------------------------------------------------------------------------
# The same two questions against the real backends
# ---------------------------------------------------------------------------

def _reachable(url, path):
    try:
        import requests
        return requests.get(f"{url}{path}", timeout=3).status_code < 500
    except Exception:
        return False


LAB_ES = os.environ.get("WDASH_LAB_URL") or "http://localhost:9200"
LAB_LOKI = os.environ.get("WDASH_LAB_LOKI") or "http://localhost:3100"
LAB_VL = os.environ.get("WDASH_LAB_VICTORIALOGS") or "http://localhost:9428"
LAB_TEMPO = os.environ.get("WDASH_LAB_TEMPO") or "http://localhost:3200"
LAB_JAEGER = os.environ.get("WDASH_LAB_JAEGER") or "http://localhost:16686"

LOGS_UP = (_reachable(LAB_ES, "/") and _reachable(LAB_LOKI, "/ready")
           and _reachable(LAB_VL, "/health"))
TRACES_UP = (_reachable(LAB_ES, "/") and _reachable(LAB_TEMPO, "/ready")
             and _reachable(LAB_JAEGER, "/api/services"))

_NO_LOGS = f"needs the lab's three log backends ({LAB_ES}, {LAB_LOKI}, {LAB_VL})"
_NO_TRACES = f"needs the lab's three trace backends ({LAB_ES}, {LAB_TEMPO}, {LAB_JAEGER})"


@unittest.skipUnless(LOGS_UP, _NO_LOGS)
class RecordsAgainstEveryLogBackendTest(unittest.TestCase):
    """One renderer serves all three, and the footer is where they differ."""

    def sources(self):
        from elasticsearch import Elasticsearch
        from wdash.hub.adapters import LokiLogSource, VictoriaLogsSource
        return [ElasticsearchLogSource(Elasticsearch(LAB_ES)),
                LokiLogSource(LAB_LOKI),
                VictoriaLogsSource(LAB_VL)]

    def test_each_backend_answers_a_records_panel_in_the_same_shape(self):
        from wdash.hub import LogQuery, Scope, TimeWindow
        from wdash.hub.query import DEFAULT_LOG_FIELDS

        window = TimeWindow.of("24h")
        for source in self.sources():
            with self.subTest(source=source.name):
                page = source.search(
                    LogQuery(window=window, text="*", limit=10,
                             fields=DEFAULT_LOG_FIELDS),
                    Scope.unrestricted())
                self.assertTrue(page.records, "the lab window held no record")
                row = page.records[0].to_dict()
                for key in ("timestamp", "severity", "service", "body"):
                    self.assertIn(key, row)
                self.assertIsInstance(page.counted, bool)
                if not page.counted:
                    # The one honest difference, and the footer's whole job.
                    self.assertEqual(page.total, len(page.records))


@unittest.skipUnless(TRACES_UP, _NO_TRACES)
class TraceListAgainstEveryTraceBackendTest(unittest.TestCase):
    """All three can answer a trace list for a named service, and naming one
    is what makes Jaeger affordable."""

    def sources(self):
        from elasticsearch import Elasticsearch
        from wdash.hub.adapters import (
            ElasticsearchTraceSource, JaegerTraceSource, TempoTraceSource,
        )
        return [ElasticsearchTraceSource(Elasticsearch(LAB_ES)),
                TempoTraceSource(LAB_TEMPO),
                JaegerTraceSource(LAB_JAEGER)]

    def test_each_backend_answers_a_named_service(self):
        from wdash.hub import Scope, TimeWindow, TraceQuery

        window = TimeWindow.of("24h")
        for source in self.sources():
            with self.subTest(source=source.name):
                self.assertTrue(source.supports(Capability.TRACE_SEARCH))
                services = [s.name for s in source.services(window,
                                                            Scope.unrestricted())]
                self.assertTrue(services, "the lab holds no service here")
                rows = source.search(
                    TraceQuery(window=window, service=services[0], limit=5,
                               sort=SORT_SLOWEST), Scope.unrestricted())
                for row in rows:
                    summary = row.to_dict()
                    self.assertTrue(summary["trace_id"])
                    self.assertIsInstance(summary["duration_us"], int)

    def test_naming_a_service_is_what_keeps_jaeger_to_one_request(self):
        """The measurement the panel's required `service` is priced on. With
        no service Jaeger lists the services and searches each one; the lab
        holds 7, so one panel costs 8 requests per refresh."""
        import requests
        from wdash.hub import Scope, TimeWindow, TraceQuery
        from wdash.hub.adapters import JaegerTraceSource

        window = TimeWindow.of("24h")
        counted = {"n": 0}
        session = requests.Session()
        real = session.request

        def counting(*args, **kwargs):
            counted["n"] += 1
            return real(*args, **kwargs)
        session.request = counting

        jaeger = JaegerTraceSource(LAB_JAEGER, session=session)
        services = [s.name for s in jaeger.services(window, Scope.unrestricted())]
        counted["n"] = 0
        jaeger.search(TraceQuery(window=window, limit=5, sort=SORT_SLOWEST),
                      Scope.unrestricted())
        fanned = counted["n"]

        counted["n"] = 0
        jaeger.search(TraceQuery(window=window, service=services[0], limit=5,
                                 sort=SORT_SLOWEST), Scope.unrestricted())
        named = counted["n"]

        self.assertEqual(named, 1, "a named service took more than one request")
        self.assertGreaterEqual(fanned, len(services),
                                f"{fanned} requests for {len(services)} services")


if __name__ == "__main__":
    unittest.main()
