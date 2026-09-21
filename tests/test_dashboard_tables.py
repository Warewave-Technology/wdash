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

    def __init__(self, summaries=(), fail=None, partial=(), lists=(),
                 stores=("traces-000001",)):
        self.capabilities = frozenset({Capability.TRACE_SEARCH,
                                       Capability.SERVICE_LIST})
        self._summaries = list(summaries)
        self.fail = fail
        self.partial = tuple(partial)
        self.queries = []
        #: The services this source says it HOLDS, which is a different
        #: question from which of them it can list traces for: on the lab's
        #: Elasticsearch trace indices four of the nine services it ranks by
        #: traffic answer a trace list with nothing at all, because every
        #: span they emit is a Client span.
        self._lists = tuple(lists)
        self._stores = tuple(stores)
        self.service_calls = []

    def supports(self, capability):
        return capability in self.capabilities

    def containers(self, scope):
        """The trace stores this role reaches.

        Filtered through the scope the way an adapter does it, because
        `trace_routes._reaches_no_store` asks TWICE — once through the role,
        once unrestricted — and a double that answered the same list both
        times could not tell a role boundary from a source with no stores.
        """
        return list(scope.resolve_traces(self._stores, source=self.name))

    def services(self, window, scope):
        self.service_calls.append(window)
        from wdash.hub.models import Service
        return [Service(name=name, span_count=100) for name in self._lists]

    def search(self, query, scope):
        self.queries.append(query)
        if self.fail:
            raise self.fail
        if not self.containers(scope):
            # A source that reaches no store finds nothing IN it. Answering
            # rows here would hide the role boundary behind data the role
            # cannot see, which is the thing being tested.
            return PartialList([], partial=bool(self.partial),
                               warnings=self.partial)
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
    #: What a role may reach is decided per source, container AND service.
    #: The trace-store half is the one a trace list never asked about.
    TRACE_STORES = ["*"]

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
              trace_indices=self.TRACE_STORES, services=self.SERVICES)
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
        # And it says what the BACKEND said. Asserting only the wrapper
        # phrase passed while the reason was logged and dropped: the trace
        # filler beside this one repeats Tempo's own refusal, and a reader
        # told "the records could not be read" has nothing to act on where
        # Loki would have told them their range exceeds its 30-day limit.
        self.assertIn("cluster unreachable", panels["recs"].get("error", ""))
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


class _FieldDataDisabled(ModelledES):
    """A cluster holding one index a terms aggregation cannot read.

    The lab reproduces this on purpose: `bad-logs-000001` maps `level` as
    text, so `terms` on it cannot run. Elasticsearch does not fail such a
    search — it answers 200 from the shards that worked, says so in `_shards`,
    and its `hits.total` counts only those shards, while the SAME query
    without an aggregation reads every index and counts them all.

    Modelled rather than stubbed, because the disagreement being tested is
    between two REQUESTS: the aggregation request really does lose the index
    here and the records search really does keep it, so a fix that passed the
    wrong one of the two numbers around would be caught.
    """

    BROKEN = "bad-logs-000001"

    def search(self, index=None, **kwargs):
        from tests.support import search_body
        names = [name for name in str(index or "").split(",") if name]
        if search_body(kwargs).get("aggs") and self.BROKEN in names:
            healthy = ",".join(n for n in names if n != self.BROKEN)
            response = super().search(index=healthy, **kwargs)
            response["_shards"] = {
                "total": 9, "failed": 5,
                "failures": [{"reason": {
                    "type": "illegal_argument_exception",
                    "reason": (f"Fielddata is disabled on [level] in "
                               f"[{self.BROKEN}]")}}]}
            return response
        return super().search(index=index, **kwargs)


class BoardCountDisagreementTest(unittest.TestCase):
    """Two exact-looking answers to one question, on one board.

    The footer's "of N" comes from this panel's search; the total hits on the
    stat card above it come from the aggregation batch. They are the same
    query over the same window, so on a healthy backend they agree — and the
    panel exists so that the table and the bars cannot disagree. When an index
    drops out of the aggregation and not out of the search they do disagree,
    and neither card said a word about it: measured on the lab over
    `*-logs-*` at 24h, total_hits 13,898 against a records footer reading
    14,998, with `counted: True` and no warning on the panel at all.
    """

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "dashboard-tables"
            DASHBOARD_STORAGE = "database"

        healthy = [_record(i, service="payments") for i in range(4)]
        broken = [_record(100 + i, service="search") for i in range(3)]
        self.es = _FieldDataDisabled({
            "app-logs-000001": (KEYWORD_MAPPING, healthy),
            "bad-logs-000001": (KEYWORD_MAPPING, broken)})
        self.app = create_app(TestConfig)
        self.hub = Hub()
        self.logs = _CountingLogs(self.es)
        self.hub.add_logs(self.logs)
        self.app.hub = self.hub

        self.dashboard = install_dashboard(
            self.app, Dashboard("b1", "Board", "", "*", "u",
                                index_patterns=["*-logs-*"]))
        self.client = self.app.test_client()
        grant(self.app, "u", permissions=["dashboard:view"], indices=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": "u@x", "username": "u",
                                    "groups": []}
            session["_user_id"] = "1"

    def board(self, patterns=("*-logs-*",)):
        change_dashboard(self.app, self.dashboard,
                         index_patterns=list(patterns),
                         panels=normalise_all([
                             {"id": "recs", "type": "records", "size": 10}]))
        payload = self.client.get("/api/dashboard/b1/data").get_json()
        return payload, {p["id"]: p for p in payload["panels"]}["recs"]

    def test_the_two_counts_really_do_differ(self):
        """The ground first: without it the rest of this class could pass
        over a cluster that never disagreed with itself."""
        payload, panel = self.board()

        self.assertEqual(payload["total_hits"], 4,
                         "the aggregation kept the index it cannot read")
        self.assertEqual(panel["total"], 7,
                         "the search lost the index the aggregation lost")

    def test_a_footer_that_disagrees_with_the_board_says_so(self):
        _, panel = self.board()
        said = " ".join(panel.get("warnings") or [])

        self.assertIn("7", said, f"the card said {said!r}")
        self.assertIn("4", said, f"the card said {said!r}")
        self.assertIn("Fielddata is disabled", said,
                      "the reason the aggregation gave was dropped")

    def test_the_panel_does_not_claim_its_own_answer_is_short(self):
        """It is the BOARD's count that came back short. Marking this panel
        partial would trade one wrong number for another, and `partial` is
        read elsewhere as "some containers did not answer"."""
        _, panel = self.board()

        self.assertNotIn("partial", panel)
        self.assertIs(panel["counted"], True)
        self.assertEqual(len(panel["rows"]), 7)

    def test_a_board_whose_counts_agree_carries_no_caveat(self):
        """Otherwise every board wears the sentence and nobody reads any."""
        payload, panel = self.board(patterns=["app-logs-*"])

        self.assertEqual(payload["total_hits"], panel["total"])
        self.assertNotIn("warnings", panel)

    def test_a_total_that_is_a_floor_is_not_compared(self):
        """Loki returns up to a limit and stops, so its total is "at least
        this many" and the footer never claims "of N" for it. Comparing a
        floor against a count would print the caveat on every Loki board."""
        from wdash.hub.models import LogPage
        real = self.logs.search

        def stopping(query, scope):
            page = real(query, scope)
            return LogPage(records=page.records, total=len(page.records),
                           counted=False, containers=page.containers)
        self.logs.search = stopping

        payload, panel = self.board()

        self.assertIs(panel["counted"], False)
        self.assertNotEqual(payload["total_hits"], panel["total"],
                            "the two numbers agreed, so nothing was proved")
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


class TraceListStoreScopeTest(_Board):
    """The third boundary: which trace STORES a role reaches.

    `traces:read` says whether a role may read traces at all; the service rule
    says which services; this says which stores, and it is the one the panel
    shipped without. A role with no trace store assigned got rows=0 and no
    error, so the card drew "No trace through payments in this window" — a
    role boundary rendered as a quiet service, which is the failure the whole
    of this file exists to prevent. The traces page has answered the same role
    with a sentence about its role all along.
    """

    PANEL = {"id": "traces", "type": "trace_list", "service": "payments",
             "view": "recent", "size": 5}
    TRACE_STORES = []

    def setUp(self):
        super().setUp()
        self.traces = self.with_traces(_Traces([_summary("aaa", "payments")]))

    def test_a_role_with_no_trace_store_is_told_so(self):
        _, payload = self.board([
            {"id": "chart", "type": "terms", "field": "service"}, self.PANEL])
        panels = self.panels_by_id(payload)

        self.assertIn("no trace stores assigned",
                      panels["traces"].get("error", "").lower())
        self.assertNotIn("rows", panels["traces"])
        self.assertEqual(self.traces.queries, [],
                         "a search was issued for a role with nowhere to "
                         "search")
        self.assertEqual(len(panels["chart"]["buckets"]), 2,
                         "the rest of the board was taken down with it")


class TraceListUnreachableStoreTest(_Board):
    """A role WITH stores assigned that match nothing in this source.

    Not the same sentence and not the same fix: the role has a rule, it simply
    reaches none of the stores this source holds. `api_search_traces` says
    exactly this after an empty answer, and it is asked only then — a source
    whose store list costs a round trip pays for it when there is something to
    explain.
    """

    PANEL = {"id": "traces", "type": "trace_list", "service": "payments",
             "view": "recent", "size": 5}
    TRACE_STORES = ["nothing-*"]

    def setUp(self):
        super().setUp()
        self.traces = self.with_traces(_Traces([_summary("aaa", "payments")]))

    def test_an_answer_no_store_could_have_filled_is_not_a_quiet_window(self):
        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["traces"]

        self.assertIn("reaches no trace store", panel.get("error", ""))
        self.assertIn("test-traces", panel.get("error", ""))
        self.assertNotIn("rows", panel)


class TraceListGapTest(_Board):
    """An empty list for a service the source itself says it holds.

    Requiring a service is the right call on cost — Jaeger fans out one
    request per service without one — but it turns an adapter limitation into
    an authored, saved panel. A trace list is built from the span where a
    request ENTERED a service, so a service only ever called by another one
    has none. Measured on the lab's Elasticsearch trace indices at 24h:
    postgres 2,579 spans, redis 1,794, elasticsearch 1,177 and stripe-api 873
    — every one of them a Client span, every one of them answering a trace
    list with nothing, while the trace_services panel on the SAME board ranks
    postgres first with 1,048. Four of nine services could not be listed at
    all and the card said "No trace through postgres in this window".
    """

    PANEL = {"id": "traces", "type": "trace_list", "service": "postgres",
             "view": "recent", "size": 5}

    def setUp(self):
        super().setUp()
        self.traces = self.with_traces(_Traces(
            [_summary("aaa", "api-gateway")],
            lists=("api-gateway", "postgres")))

    def test_a_service_the_source_lists_but_cannot_list_traces_for(self):
        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["traces"]

        self.assertIn("postgres", panel.get("error", ""))
        self.assertIn("gap", panel.get("error", ""))
        self.assertNotIn("rows", panel)

    def test_a_service_the_source_does_not_list_is_left_as_a_quiet_window(self):
        """Silence stays silence. A window in which nothing ran is a real
        answer, and dressing it as a fault is the same lie in the other
        direction."""
        _, payload = self.board([{**self.PANEL, "service": "ghost"}])
        panel = self.panels_by_id(payload)["traces"]

        self.assertNotIn("error", panel)
        self.assertEqual(panel["rows"], [])

    def test_the_service_list_is_only_asked_for_when_there_is_nothing(self):
        """The cost bargain `_reaches_no_store` already strikes: a board that
        works must not pay a round trip to be told it works."""
        _, payload = self.board([{**self.PANEL, "service": "api-gateway"}])
        panel = self.panels_by_id(payload)["traces"]

        self.assertEqual(self.traces.service_calls, [],
                         "the service list was fetched for a panel that had "
                         "its answer")
        self.assertEqual(len(panel.get("rows") or []), 1, panel)

    def test_two_empty_panels_share_one_service_list(self):
        """However many came back empty, the question is asked once."""
        self.board([self.PANEL,
                    {**self.PANEL, "id": "traces2", "service": "postgres",
                     "view": "slowest"}])

        self.assertEqual(len(self.traces.queries), 2,
                         "two different questions should be two searches")
        self.assertEqual(len(self.traces.service_calls), 1,
                         f"{len(self.traces.service_calls)} service lists "
                         f"for one dashboard load")


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

# Whether these may run is a question about DATA, not about ports: every
# window below is twenty-four hours, and a lab that is up and a week old
# answers nothing at all. Measured on 2026-09-20 — fourteen tests red on an
# untouched tree, saying the adapters returned nothing. See tests/lab.py.
from tests import lab  # noqa: E402

LAB_ES, LAB_LOKI, LAB_VL = lab.ES, lab.LOKI, lab.VICTORIALOGS
LAB_TEMPO, LAB_JAEGER = lab.TEMPO, lab.JAEGER

LOGS_UP, _NO_LOGS = lab.ready("es-logs", "loki", "victorialogs")
TRACES_UP, _NO_TRACES = lab.ready("es-traces", "tempo", "jaeger")


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
