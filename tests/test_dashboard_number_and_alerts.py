"""One number, and what the alerting did — two panel kinds a board could not ask for.

A dashboard could count records into bars and into a top-values list, and it
could not say ONE number. The four numbers on every board are Total, Errors,
Warnings and Info, hardcoded in the template with their aggregation appended
to every request whatever the board is about, so a board about one service or
about uptime carries four numbers that do not apply to it and cannot carry the
one that does.

The trap in a single number is where it comes from, and it is measured rather
than assumed. Against the lab at 24h over two Loki streams holding 170
records:

    search total                    1   (counted=False — the page size)
    date histogram, 15m buckets   181
    date histogram, 30m buckets   199
    date histogram, 1h buckets    240
    date histogram, 3h buckets    309
    date histogram, 6h buckets    565
    terms on service              170
    terms on severity             170

Elasticsearch answered 2,408 for the same board by search, by histogram and by
terms alike, and VictoriaLogs 122 by all three. So a number taken from a
search is a floor on Loki, a number taken from a histogram is whatever bucket
size the panel happened to use, and a number taken from a TERMS aggregation is
the count on all three. The panel is built on terms, and on the one thing
terms cannot do — report a value below its cut — it refuses rather than
answering zero.

The alert panels are the other half. WDash's own alerting writes every
transition it makes and whether the notification actually went out, and that
number lives on a page you only open once you already suspect something. The
gap was that `recent()` and `count()` had no time bound, so a board set to
"Last 1 hour" would have shown the last N alerts ever. Measured on rows five
minutes to four hours old, on SQLite and on Postgres, agreeing exactly: 5
rows, 3 in a one-hour window, 1 of them outstanding, and 1 row in an absolute
window that ended in the past.
"""

import os
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone

from tests.support import ModelledES, change_dashboard, grant, install_dashboard

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.panels import PanelError, normalise  # noqa: E402
from wdash.hub.adapters import (  # noqa: E402
    ElasticsearchLogSource, VictoriaLogsSource)
from wdash.models import Dashboard  # noqa: E402
from wdash.store.schema import alert_history, alert_rules  # noqa: E402

KEYWORD_MAPPING = {"@timestamp": {"type": "date"},
                   "level": {"type": "keyword"},
                   "service": {"type": "keyword"},
                   "host": {"type": "keyword"},
                   "message": {"type": "text"}}

#: The same index with `level` mapped as text: a terms aggregation on it
#: cannot run, which is how a panel gets a reason instead of a number.
TEXT_LEVEL_MAPPING = dict(KEYWORD_MAPPING, level={"type": "text"})


def _record(index, level="ERROR", service="payments", host="web-1"):
    stamp = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    return {"_id": f"r{index}", "@timestamp": stamp, "level": level,
            "service": service, "host": host, "message": "boom"}


class _CountingES(ModelledES):
    """The cluster, plus how many round trips the board cost it."""

    def __init__(self, indices):
        super().__init__(indices)
        self.msearches = 0

    def msearch(self, searches=None, **kw):
        self.msearches += 1
        return super().msearch(searches=searches, **kw)


class _Board(unittest.TestCase):
    """One board over one index, on a cluster that evaluates what it is asked."""

    MAPPING = KEYWORD_MAPPING
    PERMISSIONS = ("dashboard:view", "monitors:read")

    def records(self):
        """Built per test rather than once at import.

        Two reasons, both measured here: `ModelledES` pops `_id` out of the
        dicts it is handed, so a class attribute is consumed by the first
        test that uses it; and the timestamps have to fall inside the window
        the route asks for, which is anchored on now and not on import.
        """
        return []

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "number-and-alerts"
            DASHBOARD_STORAGE = "database"

        self.es = _CountingES({"app-logs-000001": (self.MAPPING,
                                                   self.records())})
        self.app = create_app(TestConfig)
        self.hub = Hub()
        self.hub.add_logs(ElasticsearchLogSource(self.es))
        self.app.hub = self.hub

        self.dashboard = install_dashboard(
            self.app, Dashboard("b1", "Board", "", "*", "u",
                                index_patterns=["app-*"]))
        self.client = self.app.test_client()
        grant(self.app, "u", permissions=list(self.PERMISSIONS),
              indices=["*"], trace_indices=["*"], services=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": list(self.PERMISSIONS),
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def board(self, panels, query=""):
        change_dashboard(self.app, self.dashboard,
                         panels=[normalise(p) for p in panels], query=query)
        response = self.client.get(f"/api/dashboard/{self.dashboard.id}/data")
        return response, response.get_json()

    def panels_by_id(self, payload):
        return {panel["id"]: panel for panel in payload["panels"]}

    def one(self, panels, panel_id, **kwargs):
        _, payload = self.board(panels, **kwargs)
        return self.panels_by_id(payload)[panel_id]


# ---------------------------------------------------------------------------
# D11 — one number
# ---------------------------------------------------------------------------

class SingleNumberTest(_Board):
    """Seven ERROR records and five INFO, in an index of twelve."""

    def records(self):
        return ([_record(i, level="ERROR") for i in range(7)] +
                [_record(100 + i, level="INFO") for i in range(5)])

    PANEL = {"id": "n1", "type": "count", "title": "Checkout errors",
             "field": "severity", "value": "ERROR"}

    def test_the_panel_answers_with_the_count_of_its_value(self):
        """Measured before: there was no panel to ask. The board carries 7
        ERROR records among 12."""
        panel = self.one([self.PANEL], "n1")
        self.assertEqual(panel["number"], 7)
        self.assertNotIn("error", panel)

    def test_the_panel_says_what_question_the_number_answers(self):
        """A big number under a title its author wrote — "Checkout errors" —
        is a number nobody else can check. The field, the value and the two
        things that narrowed it are on the panel."""
        panel = self.one([self.PANEL], "n1")
        self.assertIn("severity", panel["question"])
        self.assertIn("ERROR", panel["question"])
        self.assertIn("this window", panel["question"])
        self.assertIn("query", panel["question"])

    def test_the_number_is_the_panels_own_aggregation_not_the_boards_total(self):
        """The trap this panel is built around. The board's own total counts
        every record the query matched — 12 here — and on Loki it is whatever
        the largest aggregation in the batch summed to. Sourcing the number
        from it would have drawn 12 under the words "records where severity is
        ERROR"."""
        _, payload = self.board([self.PANEL])
        panel = self.panels_by_id(payload)["n1"]
        self.assertEqual(payload["total_hits"], 12)
        self.assertEqual(panel["number"], 7)

    def test_the_number_costs_no_round_trip_of_its_own(self):
        """It rides the batch every other counting panel rides: three panels,
        one request. A number fetched separately would cost a request per
        panel on Loki and VictoriaLogs, which is what makes a rich board
        unaffordable."""
        before = self.es.msearches
        self.board([self.PANEL,
                    {"id": "n2", "type": "count", "field": "service",
                     "value": "payments"},
                    {"id": "t1", "type": "terms", "field": "severity"}])
        self.assertEqual(self.es.msearches - before, 1)

    def test_a_second_number_over_the_same_field_is_counted_separately(self):
        """Aggregations are named after the panel that asked, so two numbers
        over one field are two answers rather than one shared by id."""
        _, payload = self.board([
            self.PANEL,
            {"id": "n2", "type": "count", "field": "severity",
             "value": "INFO"}])
        panels = self.panels_by_id(payload)
        self.assertEqual((panels["n1"]["number"], panels["n2"]["number"]),
                         (7, 5))

    def test_the_number_honours_the_boards_own_query(self):
        """It counts what the board counts. A number that ignored the query
        would disagree with every chart beside it."""
        panel = self.one([{"id": "n1", "type": "count", "field": "severity",
                           "value": "ERROR"}], "n1",
                         query="service:\"nothing-here\"")
        self.assertEqual(panel["number"], 0)

    def test_a_value_with_no_records_is_a_real_zero(self):
        """Four values of severity exist here and none is FATAL, so the terms
        list came back short of its ceiling: nothing was cut off, and zero is
        the measured answer rather than a guess."""
        panel = self.one([{"id": "n1", "type": "count", "field": "severity",
                           "value": "FATAL"}], "n1")
        self.assertEqual(panel["number"], 0)
        self.assertNotIn("error", panel)


class UncountableValueTest(_Board):
    """Sixty hosts, one record each — more values than a terms aggregation
    returns."""

    def records(self):
        return [_record(i, host=f"web-{i:03d}") for i in range(60)]

    def test_a_value_below_the_terms_cut_is_refused_rather_than_counted_as_zero(self):
        """The failure this panel would otherwise ship. `web-059` has a
        record; it is not among the fifty commonest hosts, so the aggregation
        does not mention it — exactly as a host with no records would not.
        Drawing a confident 0 would be the emptiness failure with a number on
        it."""
        panel = self.one([{"id": "n1", "type": "count", "field": "host",
                           "value": "web-059"}], "n1")
        self.assertNotIn("number", panel)
        self.assertIn("web-059", panel["error"])
        self.assertIn("50 commonest", panel["error"])
        self.assertIn("not a count of zero", panel["error"])

    def test_a_value_inside_the_cut_still_answers(self):
        """The refusal is about the cut, not about the field: a value the
        aggregation did return is counted."""
        panel = self.one([{"id": "n1", "type": "count", "field": "host",
                           "value": "web-000"}], "n1")
        self.assertEqual(panel["number"], 1)


class CaseVariantTest(_Board):
    """The casing this project already measured: Elasticsearch writes ERROR
    and Loki and VictoriaLogs write error for the same records."""

    def records(self):
        return [_record(i, level="ERROR") for i in range(3)]

    def test_a_value_that_differs_only_in_case_is_named_rather_than_zeroed(self):
        """`severity: error` here is arithmetically zero and practically a
        typo, and the two are indistinguishable on a card reading 0."""
        panel = self.one([{"id": "n1", "type": "count", "field": "severity",
                           "value": "error"}], "n1")
        self.assertNotIn("number", panel)
        self.assertIn("'ERROR'", panel["error"])
        self.assertIn("case", panel["error"])
        self.assertIn("3", panel["error"])

    def test_the_exact_value_is_preferred_to_the_variant(self):
        panel = self.one([{"id": "n1", "type": "count", "field": "severity",
                           "value": "ERROR"}], "n1")
        self.assertEqual(panel["number"], 3)


class UnaskableNumberTest(_Board):
    """`level` mapped as text, so the aggregation cannot run at all."""

    MAPPING = TEXT_LEVEL_MAPPING

    def records(self):
        return [_record(i, level="ERROR") for i in range(4)]

    def test_an_aggregation_that_could_not_run_is_a_reason_not_a_zero(self):
        """The cluster holds four ERROR records and cannot group by the
        field. A 0 here would be a claim about the data made about a question
        nobody could ask."""
        panel = self.one([{"id": "n1", "type": "count", "field": "severity",
                           "value": "ERROR"}], "n1")
        self.assertNotIn("number", panel)
        self.assertIn("aggregated", panel["error"])


class NumberInAnOutageTest(_Board):
    """A single number is a LOG panel and shares the log source's fate.

    It must not draw a confident 0 through an outage — the board's other
    panels are explaining themselves and the number would be the one card
    still asserting something.
    """

    def records(self):
        return [_record(0)]

    def setUp(self):
        super().setUp()
        install_rule(self.app.store)

    def test_the_panel_says_why_when_the_log_source_is_unreachable(self):
        class Dead:
            name = "elasticsearch"

            def __getattr__(self, item):
                def fail(*a, **k):
                    raise RuntimeError("cluster unreachable")
                return fail

        self.hub._logs["elasticsearch"] = Dead()          # noqa: SLF001
        # An alert panel beside it, so the page itself answers: a board of
        # log panels alone has nothing to show and says so in the status
        # line, which is a different behaviour and not this one.
        _, payload = self.board([
            {"id": "n1", "type": "count", "field": "severity",
             "value": "ERROR"},
            {"id": "a2", "type": "alerts_undelivered"}])
        panel = self.panels_by_id(payload)["n1"]
        self.assertNotIn("number", panel)
        self.assertTrue(panel["error"])


class NumberPanelDefinitionTest(unittest.TestCase):

    def test_a_number_must_name_the_value_it_counts(self):
        """Not a default. A terms aggregation counts values; a panel with no
        value would have to sum the list, which is "records whose service is
        one of the fifty commonest" under a label the author wrote."""
        with self.assertRaises(PanelError) as caught:
            normalise({"type": "count", "field": "severity"})
        self.assertIn("value", str(caught.exception))

    def test_a_number_must_name_a_field_the_source_can_group_by(self):
        with self.assertRaises(PanelError) as caught:
            normalise({"type": "count", "field": "message", "value": "boom"})
        self.assertIn("message", str(caught.exception))

    def test_a_number_asks_the_log_source(self):
        from wdash.dashboard.panels import needs_logs
        self.assertTrue(needs_logs({"type": "count"}))

    def test_the_new_panels_declare_a_signal_that_is_filled(self):
        """A row with no filler reads as "No data in this window", which is a
        claim about the data made about a question nobody asked."""
        from wdash.api.dashboard_routes import FILLED_SIGNALS
        from wdash.dashboard.panels import PANEL_TYPES

        for kind in ("count", "alerts", "alerts_undelivered"):
            with self.subTest(kind=kind):
                self.assertIn(PANEL_TYPES[kind]["signal"], FILLED_SIGNALS)

    def test_the_alert_panels_do_not_ask_the_log_source(self):
        """They read WDash's own store, so a deployment with no log backend
        can carry them and an outage does not take them down."""
        from wdash.dashboard.panels import needs_logs
        self.assertFalse(needs_logs({"type": "alerts"}))
        self.assertFalse(needs_logs({"type": "alerts_undelivered"}))


# ---------------------------------------------------------------------------
# D26 — what the alerting did
# ---------------------------------------------------------------------------

def install_rule(store, rule_id="f2-rule", name="Payments API"):
    now = datetime.now(timezone.utc)
    with store.engine.begin() as connection:
        connection.execute(alert_rules.insert().values(
            id=rule_id, name=name, kind="monitor_down", selector={},
            threshold=3, days_before=None, repeat_minutes=0,
            channel_id="f2-channel", enabled=True, created_by="u",
            created_at=now, updated_at=now))


def fired(store, minutes_ago, subject="checkout", delivered=False,
          rule_id="f2-rule", transition="firing", label=None, error=None):
    """One row in the history, at a time this test chose.

    `record()` stamps `_now()`, and every question here is about WHEN
    something fired.
    """
    with store.engine.begin() as connection:
        connection.execute(alert_history.insert().values(
            at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
            rule_id=rule_id, subject=subject,
            subject_label=label or subject, transition=transition,
            detail="", delivered=delivered, delivery_error=error))


class AlertPanelTest(_Board):

    LIST = {"id": "a1", "type": "alerts", "title": "What fired", "size": 10}
    NUMBER = {"id": "a2", "type": "alerts_undelivered",
              "title": "Nobody received"}

    def setUp(self):
        super().setUp()
        install_rule(self.app.store)

    def test_the_panel_lists_what_fired_in_this_window(self):
        fired(self.app.store, minutes_ago=5, subject="checkout")
        panel = self.one([self.LIST], "a1")
        self.assertEqual(len(panel["rows"]), 1)
        self.assertEqual(panel["rows"][0]["subject"], "checkout")

    def test_an_alert_older_than_the_window_is_not_listed(self):
        """The gap the menu named: `recent()` had no time bound, so a board
        set to "Last 1 hour" would have shown the last N alerts ever."""
        fired(self.app.store, minutes_ago=5, subject="checkout")
        fired(self.app.store, minutes_ago=90, subject="search")
        panel = self.one([self.LIST], "a1")
        self.assertEqual([row["subject"] for row in panel["rows"]],
                         ["checkout"])

    def test_the_panel_counts_what_fired_beyond_the_rows_it_shows(self):
        for index in range(4):
            fired(self.app.store, minutes_ago=5, subject=f"subject-{index}")
        panel = self.one([dict(self.LIST, size=2)], "a1")
        self.assertEqual(len(panel["rows"]), 2)
        self.assertEqual(panel["total"], 4)

    def test_a_row_names_the_rule_rather_than_its_uuid(self):
        """Borrowed from the Alerts page unchanged, so a row reads "Payments
        API" rather than a pair of uuids."""
        fired(self.app.store, minutes_ago=5, subject="checkout",
              label="Checkout probe")
        row = self.one([self.LIST], "a1")["rows"][0]
        self.assertEqual(row["rule"], "Payments API")
        self.assertEqual(row["subject"], "Checkout probe")

    def test_a_row_says_whether_anybody_received_it(self):
        fired(self.app.store, minutes_ago=5, delivered=False,
              error="webhook refused: 500")
        row = self.one([self.LIST], "a1")["rows"][0]
        self.assertFalse(row["delivered"])
        self.assertIn("500", row["delivery_error"])

    def test_the_number_counts_the_alerts_that_reached_nobody(self):
        fired(self.app.store, minutes_ago=5, subject="checkout",
              delivered=False)
        fired(self.app.store, minutes_ago=6, subject="payments",
              delivered=True)
        panel = self.one([self.NUMBER], "a2")
        self.assertEqual(panel["number"], 1)
        self.assertEqual(panel["fired"], 2)

    def test_an_undelivered_alert_outside_the_window_is_not_counted(self):
        """Without the bound this reads 1 on a board showing an hour in which
        nothing failed to arrive."""
        fired(self.app.store, minutes_ago=200, subject="search",
              delivered=False)
        panel = self.one([self.NUMBER], "a2")
        self.assertEqual(panel["number"], 0)
        self.assertEqual(panel["fired"], 0)

    def test_the_number_uses_the_alerts_pages_own_definition_of_outstanding(self):
        """"Never delivered" has to drain. A subject whose LAST word was a
        successful delivery is not outstanding, however many failures came
        before it — which is what the badge on /alerts counts, and a board
        that counted every failed row would disagree with it for ever."""
        fired(self.app.store, minutes_ago=9, subject="checkout",
              delivered=False)
        fired(self.app.store, minutes_ago=8, subject="checkout",
              delivered=False)
        fired(self.app.store, minutes_ago=7, subject="checkout",
              delivered=True)
        panel = self.one([self.NUMBER], "a2")
        self.assertEqual(panel["number"], 0)
        # ONE, not three. The three rows are one subject, and the number
        # above them counts subjects — a ratio needs one population.
        # Measured before this: a board where every delivery had failed read
        # "1 of the 12 alerts in this window reached nobody" beside a table
        # of twelve rows all marked undelivered.
        self.assertEqual(panel["fired"], 1)

    def test_the_number_and_what_it_is_out_of_are_one_population(self):
        """Every delivery failing must read as all of them, not one of N."""
        for minutes in (9, 8, 7):
            fired(self.app.store, minutes_ago=minutes, subject="checkout",
                  delivered=False)
        for minutes in (6, 5):
            fired(self.app.store, minutes_ago=minutes, subject="payments",
                  delivered=False)
        panel = self.one([self.NUMBER], "a2")
        self.assertEqual((panel["number"], panel["fired"]), (2, 2))
        self.assertIn("2 alerts", panel["question"])

    def test_the_number_says_what_it_is_out_of(self):
        fired(self.app.store, minutes_ago=5, delivered=False)
        panel = self.one([self.NUMBER], "a2")
        self.assertIn("1 alert", panel["question"])
        self.assertIn("reached nobody", panel["question"])

    def test_the_panels_add_no_request_to_the_board(self):
        """WDash's own store answers them, so they cost the log backend
        nothing: the board makes the one request it would have made without
        them. (That one request is the stat cards' own aggregation, which
        every board carries whatever its panels are.)"""
        fired(self.app.store, minutes_ago=5)
        before = self.es.msearches
        self.board([{"id": "t1", "type": "terms", "field": "severity"}])
        without = self.es.msearches - before

        before = self.es.msearches
        self.board([{"id": "t1", "type": "terms", "field": "severity"},
                    self.LIST, self.NUMBER])
        self.assertEqual(self.es.msearches - before, without)
        self.assertEqual(without, 1)

    def test_an_absolute_window_that_ended_excludes_what_fired_after_it(self):
        """A dashboard can be pointed at last Tuesday. A `since`-only filter
        would answer "from then until now"."""
        fired(self.app.store, minutes_ago=90, subject="then")
        fired(self.app.store, minutes_ago=5, subject="since")
        now = datetime.now(timezone.utc)
        change_dashboard(self.app, self.dashboard,
                         panels=[normalise(self.LIST)])
        response = self.client.get(
            f"/api/dashboard/{self.dashboard.id}/data",
            query_string={"start": (now - timedelta(minutes=120)).isoformat(),
                          "end": (now - timedelta(minutes=60)).isoformat()})
        panel = self.panels_by_id(response.get_json())["a1"]
        self.assertEqual([row["subject"] for row in panel["rows"]], ["then"])

    def test_the_number_and_the_table_agree_about_a_window_that_ended(self):
        """The two panels are read as one picture, so they may not disagree.

        Measured before the fix: the table drew ('checkout', delivered=False,
        'webhook refused: 500') while the number beside it read 0 under "of
        the 1 alert in this window reached nobody" — because the same rule
        and subject had spoken again after the window.
        """
        fired(self.app.store, minutes_ago=90, subject="checkout",
              delivered=False, error="webhook refused: 500")
        fired(self.app.store, minutes_ago=5, subject="checkout",
              delivered=False, error="webhook refused: 500")
        now = datetime.now(timezone.utc)
        change_dashboard(self.app, self.dashboard,
                         panels=[normalise(self.LIST), normalise(self.NUMBER)])
        response = self.client.get(
            f"/api/dashboard/{self.dashboard.id}/data",
            query_string={"start": (now - timedelta(minutes=120)).isoformat(),
                          "end": (now - timedelta(minutes=60)).isoformat()})
        panels = self.panels_by_id(response.get_json())
        self.assertEqual(
            [(row["subject"], row["delivered"]) for row in panels["a1"]["rows"]],
            [("checkout", False)])
        self.assertEqual(panels["a2"]["number"], 1)
        self.assertEqual(panels["a2"]["fired"], 1)

    def test_a_quiet_window_is_an_empty_list_rather_than_a_refusal(self):
        """A rule exists, so "nothing fired" is a real answer and the panel
        must not claim the question could not be asked."""
        panel = self.one([self.LIST], "a1")
        self.assertEqual(panel["rows"], [])
        self.assertNotIn("error", panel)


class AlertingNotConfiguredTest(_Board):
    """No rule at all — the reading a zero would hide."""

    def test_a_board_with_no_rule_is_told_so_rather_than_shown_a_zero(self):
        panel = self.one([{"id": "a2", "type": "alerts_undelivered"}], "a2")
        self.assertNotIn("number", panel)
        self.assertIn("No alert rule is configured", panel["error"])
        self.assertIn("not a quiet window", panel["error"])

    def test_the_list_panel_says_the_same(self):
        panel = self.one([{"id": "a1", "type": "alerts", "size": 10}], "a1")
        self.assertNotIn("rows", panel)
        self.assertIn("No alert rule is configured", panel["error"])


class AlertBoundaryTest(_Board):
    """Who may read alert history on a shared board."""

    PERMISSIONS = ("dashboard:view",)          # no monitors:read

    def records(self):
        return [_record(0)]

    def setUp(self):
        super().setUp()
        install_rule(self.app.store)
        fired(self.app.store, minutes_ago=5)

    def test_a_role_without_monitors_read_is_refused_these_panels(self):
        """The permission the Alerts page itself asks for, checked at
        panel-fill time. A shared dashboard must not become a way to read
        alert history a role was never granted."""
        _, payload = self.board([
            {"id": "a1", "type": "alerts", "size": 10},
            {"id": "a2", "type": "alerts_undelivered"}])
        panels = self.panels_by_id(payload)
        for panel_id in ("a1", "a2"):
            with self.subTest(panel=panel_id):
                self.assertIn("monitors:read", panels[panel_id]["error"])
                self.assertNotIn("rows", panels[panel_id])
                self.assertNotIn("number", panels[panel_id])

    def test_the_rest_of_the_board_is_unaffected(self):
        """It refuses THAT panel rather than widening the dashboard's
        visibility rule or failing the page."""
        response, payload = self.board([
            {"id": "a1", "type": "alerts", "size": 10},
            {"id": "t1", "type": "terms", "field": "severity"}])
        self.assertEqual(response.status_code, 200)
        panels = self.panels_by_id(payload)
        self.assertIn("monitors:read", panels["a1"]["error"])
        self.assertEqual(sum(b["count"] for b in panels["t1"]["buckets"]), 1)


class AlertPanelsInALogOutageTest(_Board):
    """The outage these panels exist for.

    An operator opens a board in an Elasticsearch outage precisely to find out
    whether anything is wrong, and what the alerting said is answerable with
    no log backend at all.
    """

    def setUp(self):
        super().setUp()
        install_rule(self.app.store)
        fired(self.app.store, minutes_ago=5, subject="checkout",
              delivered=False)

    def test_the_alert_panels_answer_while_the_log_source_is_down(self):
        class Dead:
            name = "elasticsearch"

            def __getattr__(self, item):
                def fail(*a, **k):
                    raise RuntimeError("cluster unreachable")
                return fail

        self.hub._logs["elasticsearch"] = Dead()          # noqa: SLF001
        response, payload = self.board([
            {"id": "a1", "type": "alerts", "size": 10},
            {"id": "a2", "type": "alerts_undelivered"},
            {"id": "t1", "type": "terms", "field": "severity"}])

        self.assertEqual(response.status_code, 200)
        panels = self.panels_by_id(payload)
        self.assertEqual(len(panels["a1"]["rows"]), 1)
        self.assertEqual(panels["a2"]["number"], 1)
        # And the log panel beside them still says why it is empty.
        self.assertTrue(panels["t1"]["error"])


# ---------------------------------------------------------------------------
# The store, on whichever dialect the suite is running
# ---------------------------------------------------------------------------

class AlertHistoryWindowTest(unittest.TestCase):
    """`since` and `until` on the repository itself.

    On SQLite `at` is a naive UTC string and on Postgres a timestamptz; the
    bind is an aware UTC datetime either way. Measured on both with the same
    five rows: 5 in all, 3 in the last hour, 3 outstanding in all, 1
    outstanding in the last hour, 1 in an absolute window that ended an hour
    ago.
    """

    def setUp(self):
        from wdash.store import Store
        from wdash.store.database import build_engine
        from wdash.store.migrations import migrate

        engine = build_engine("sqlite:///:memory:")
        migrate(engine)
        self.store = Store(engine)
        self.now = datetime.now(timezone.utc)
        for minutes, subject, delivered in ((5, "checkout", False),
                                            (20, "checkout", False),
                                            (30, "payments", True),
                                            (90, "search", False),
                                            (240, "ldap", False)):
            fired(self.store, minutes_ago=minutes, subject=subject,
                  delivered=delivered,
                  rule_id=f"f2-rule-{subject}")

    def history(self):
        return self.store.alert_history

    def test_without_a_bound_the_whole_history_is_still_answered(self):
        """The Alerts page asks for the last N ever and paginates them. That
        question is unchanged."""
        self.assertEqual(self.history().count(), 5)
        self.assertEqual(len(self.history().recent(limit=100)), 5)

    def test_since_bounds_both_the_rows_and_the_count(self):
        since = self.now - timedelta(hours=1)
        self.assertEqual(self.history().count(since=since), 3)
        self.assertEqual(len(self.history().recent(limit=100, since=since)), 3)

    def test_until_bounds_a_window_that_ended_in_the_past(self):
        rows = self.history().recent(
            limit=100, since=self.now - timedelta(minutes=100),
            until=self.now - timedelta(minutes=60))
        self.assertEqual([row["subject"] for row in rows], ["search"])
        self.assertEqual(self.history().count(
            since=self.now - timedelta(minutes=100),
            until=self.now - timedelta(minutes=60)), 1)

    def test_outstanding_is_the_last_word_per_subject_inside_the_window(self):
        """Three subjects are outstanding over all time; one of them last
        spoke inside the hour."""
        self.assertEqual(self.history().count(undelivered_only=True), 3)
        self.assertEqual(self.history().count(
            undelivered_only=True, since=self.now - timedelta(hours=1)), 1)

    def test_a_delivery_that_succeeded_later_drains_out_of_the_window(self):
        fired(self.store, minutes_ago=1, subject="checkout", delivered=True,
              rule_id="f2-rule-checkout")
        self.assertEqual(self.history().count(
            undelivered_only=True, since=self.now - timedelta(hours=1)), 0)

    def test_the_rows_come_back_newest_first(self):
        rows = self.history().recent(limit=100,
                                     since=self.now - timedelta(hours=1))
        self.assertEqual([row["subject"] for row in rows],
                         ["checkout", "checkout", "payments"])

    def test_what_reached_nobody_in_the_window_counts_in_the_window(self):
        """A later row must not empty an hour that was already broken.

        "The last word per (rule, subject)" was taken over ALL time and the
        window then applied to THAT row, so an alert that reached nobody
        inside the window stopped counting as soon as the same rule and
        subject spoke again after it — even when the later row failed too and
        the channel is still broken. Two undelivered rows for `checkout`, a
        window over the older one: the alerts table draws it with
        Delivered = no, and the number beside it read 0.
        """
        # `search` already reached nobody 90 minutes ago. It speaks again
        # now, and again nobody receives it — written AFTER, as the runner
        # writes it, so the newer row is the newer id too. (Inserting the
        # older row last hides the defect: `_outstanding` picks max(id) for
        # the reason its docstring gives, and a fixture out of order makes
        # the row inside the window the last word by accident.)
        fired(self.store, minutes_ago=1, subject="search",
              delivered=False, rule_id="f2-rule-search")
        since = self.now - timedelta(minutes=100)
        until = self.now - timedelta(minutes=60)

        rows = self.history().recent(limit=100, since=since, until=until)
        self.assertEqual([row["subject"] for row in rows], ["search"])
        self.assertEqual([bool(row["delivered"]) for row in rows], [False])
        self.assertEqual(self.history().count(undelivered_only=True,
                                              since=since, until=until), 1)
        # And the rows the count stands for, so the page that lists them and
        # the panel that counts them cannot come apart.
        self.assertEqual(
            [row["subject"] for row in self.history().recent(
                limit=100, undelivered_only=True, since=since, until=until)],
            ["search"])

    def test_a_delivery_after_the_window_does_not_quiet_the_window(self):
        """The other half of the same rule. Somebody fixing the webhook now
        does not make an hour last Tuesday one in which everybody was
        reached — while a success INSIDE the window still drains it, which is
        what the test above this one measures."""
        fired(self.store, minutes_ago=90, subject="webhooks",
              delivered=False, rule_id="f2-rule-webhooks")
        fired(self.store, minutes_ago=2, subject="webhooks",
              delivered=True, rule_id="f2-rule-webhooks")
        self.assertEqual(self.history().count(
            undelivered_only=True,
            since=self.now - timedelta(minutes=100),
            until=self.now - timedelta(minutes=60)), 2)


# ---------------------------------------------------------------------------
# The number, against the real backends
# ---------------------------------------------------------------------------

# Data, not ports: the number these ask for is a count over a window, and a
# lab that is up and a week old counts nothing. See tests/lab.py.
from tests import lab  # noqa: E402

LAB_ES, LAB_LOKI, LAB_VL = lab.ES, lab.LOKI, lab.VICTORIALOGS

LOGS_UP, _NO_LOGS = lab.ready("es-logs", "loki", "victorialogs")
VL_UP, _NO_VL = lab.ready("victorialogs")


@unittest.skipUnless(LOGS_UP, _NO_LOGS)
class NumberAgainstEveryLogBackendTest(unittest.TestCase):
    """The number a terms aggregation reports is the records it stands for.

    The panel's whole claim, checked on real data through two independent
    paths: the aggregation the panel is fed by, and the records the same
    source lists for the same window. A backend that quietly drops records
    from an aggregation would pass every check made against a fixture and
    fail here, which is the class of defect this project keeps finding.

    In practice this reaches Loki and VictoriaLogs and not Elasticsearch:
    the Elasticsearch adapter answers a search with at most 500 records, and
    every log index in the lab holds more than that over any window whose
    records have a severity at all — so there is no complete listing to
    compare an aggregation against. Elasticsearch is measured instead by
    `ModelledES` above, which evaluates the query and reads the mapping.
    Measured here on 2026-09-12: loki/billing-api INFO 65 = 65,
    victorialogs/auth-service INFO 49 = 49.
    """

    #: What a container may hold and still be listed whole.
    #:
    #: Asked for, not granted: `ElasticsearchLogSource.search` caps `size` at
    #: 500 however large a `limit` it is handed, so a container of 501 is
    #: skipped by the `len(records) == total` test below and a number this
    #: far above the real bound only hides which one is doing the work. Kept
    #: high all the same, because the cap is the ADAPTER's and the other two
    #: backends do not share it — lowering this would narrow what they can
    #: be checked over to no purpose.
    LIMIT = 2000

    def sources(self):
        from elasticsearch import Elasticsearch
        from wdash.hub.adapters import LokiLogSource, VictoriaLogsSource
        return [ElasticsearchLogSource(Elasticsearch(LAB_ES)),
                LokiLogSource(LAB_LOKI),
                VictoriaLogsSource(LAB_VL)]

    def a_container_with_records(self, source, window, scope):
        """One container this source counts exactly over the window.

        Exactly, because the check compares the aggregation against a LIST:
        a source that stopped at its limit would be compared against a
        number nobody measured. Loki says so itself (`counted=False`), and a
        container fuller than the limit is skipped rather than half-counted.
        """
        from wdash.hub import LogQuery, Terms
        from wdash.hub.query import DEFAULT_LOG_FIELDS

        for container in source.containers(scope):
            if "|" in container:
                # A name seeded to test regex injection, not a container
                # anybody would put on a board.
                continue
            page = source.search(
                LogQuery(window=window, text="*", containers=(container,),
                         limit=self.LIMIT, fields=DEFAULT_LOG_FIELDS), scope)
            records = [record.to_dict() for record in page.records]
            # The whole container, not a page of it: Elasticsearch answered
            # `synthetics-browser.screenshot-default` with 500 records of a
            # counted 6,142, and comparing an aggregation over 6,142 records
            # against 500 listed ones would fail for the wrong reason.
            if not (page.counted and 0 < len(records) == page.total):
                continue
            # And a container whose records carry the field at all. The lab's
            # synthetics indices hold screenshots: 298 records in an hour,
            # none of them with a `level` field, so an empty terms list there
            # is the truth and not a dropped aggregation. They read back as
            # severity "UNSPECIFIED" — the adapter's word for a record that
            # has none — which is why a truthiness test is not enough.
            if not any(record.get("severity") not in (None, "", "UNSPECIFIED")
                       for record in records):
                continue
            # And a container the source can actually GROUP BY. The lab holds
            # `bad-logs-000001` — 7,931 records with `level` mapped as text —
            # where the records carry a severity and the aggregation cannot
            # run at all: the adapter says so in a note rather than answering,
            # which is the UnaskableNumberTest case measured above through
            # ModelledES. It is not a listing an aggregation can be compared
            # against, and picking it failed this check for the one reason it
            # is not about. A bucket list that comes back empty with NO
            # reason still fails below, which is the emptiness this is for.
            if source.aggregate(
                    LogQuery(window=window, text="*", containers=(container,),
                             limit=1),
                    [Terms(name="probe", field="severity", size=1)],
                    scope).reasons("probe"):
                continue
            return container, records
        return None, []

    def test_the_number_is_the_records_it_stands_for(self):
        from wdash.hub import LogQuery, Scope, TimeWindow, Terms

        scope = Scope.unrestricted()
        checked, skipped = [], []
        for source in self.sources():
            # A window small enough that a container can be listed whole.
            # Which container that is differs by backend and by how recently
            # the lab was seeded, so it is found rather than named.
            #
            # A LADDER, and the rungs between an hour and a day are the
            # point. The lab's seeder writes its records backdated and then
            # stops, while Heartbeat goes on writing: an hour after a seed
            # the log indices hold nothing in `1h` and twenty-four thousand
            # in `24h`, and neither can be listed whole. Measured in that
            # state, `2h` held 359 records of `bad-logs-000001` — countable,
            # with levels — and the run that had only those two rungs failed
            # for the age of the lab rather than for anything about WDash.
            for span in ("1h", "2h", "3h", "6h", "12h", "24h"):
                window = TimeWindow.of(span)
                container, records = self.a_container_with_records(
                    source, window, scope)
                if container is not None:
                    break
            if container is None:
                skipped.append(f"{source.name}: no container it counts "
                               f"exactly")
                continue

            with self.subTest(source=source.name, container=container):
                result = source.aggregate(
                    LogQuery(window=window, text="*",
                             containers=(container,), limit=1),
                    [Terms(name="panel-1", field="severity", size=50)], scope)
                buckets = result.get("panel-1")
                self.assertTrue(
                    buckets,
                    f"{source.name} reported no severity at all over "
                    f"{container}, where it lists {len(records)} records")

                # The commonest value is the one a number panel would be
                # pointed at, and the one the terms list cannot have cut off.
                value = str(buckets[0].key)
                listed = sum(1 for record in records
                             if str(record.get("severity") or "") == value)
                self.assertEqual(
                    buckets[0].count, listed,
                    f"{source.name}: the aggregation counted "
                    f"{buckets[0].count} records with severity {value} over "
                    f"{container} and the source listed {listed}")
                checked.append(f"{source.name}/{container}:{value}="
                               f"{listed}")

        # A run in which every backend was skipped proves nothing, and would
        # read as a pass. Say so instead.
        self.assertTrue(
            checked,
            f"no backend could be checked: {skipped}. Every window from an "
            f"hour to a day was either empty or too full to list whole — "
            f"which is what an ageing lab looks like. `cd lab && ./lab.sh "
            f"demo` writes a fresh set and this passes again.")


class TheEditorKnowsTheNewPanels(unittest.TestCase):
    """The editor's own tables, for the three rows this package adds.

    `tests/test_panel_editor_types.py` already fails if a panel type has no
    button, no controls, no caption or no blank. What it cannot check is
    whether the row says the thing an author has to know BEFORE choosing it,
    which is different for each of these three.
    """

    def setUp(self):
        path = os.path.join(os.path.dirname(__file__), "..", "templates",
                            "_dashboard_editor_script.html")
        with open(path, encoding="utf-8") as handle:
            self.script = handle.read()
        self.captions = re.search(
            r"ROW_CAPTIONS = Object\.assign.*?^\}\);", self.script,
            re.S | re.M).group(0)

    def caption(self, key):
        found = re.search(r"^ {4}%s:(.*?)(?=^ {4}\w+:|^\}\);)" % key,
                          self.captions, re.S | re.M)
        self.assertIsNotNone(found, f"{key} has no row in ROW_CAPTIONS")
        return found.group(1)

    def test_the_number_row_says_the_count_is_bounded(self):
        """A value below the terms cut is refused, and an author choosing the
        panel should know that before they save a board around it."""
        said = self.caption("count")
        self.assertIn("50 commonest", said)
        self.assertIn("no extra request", said)

    def test_the_alert_rows_say_which_permission_they_need(self):
        """Both rows NAME it. "the same permission" is a back-reference to a
        caption an author who only wants the number never reads: the rows sit
        in a list and only the chosen one is shown."""
        self.assertIn("monitors:read", self.caption("alerts"))
        self.assertIn("monitors:read", self.caption("alerts_undelivered"))

    # What the form DOES about an emptied value box — warn on the row and
    # stop the submit — is measured where it happens, in
    # tests/dashboard_form_smoke.js ('clearing the value says so on the row'
    # and the two checks after it), against the script running in a DOM.


# ---------------------------------------------------------------------------
# What the review found: a zero the panel could not stand behind
# ---------------------------------------------------------------------------

#: What the lab's VictoriaLogs answers for
#: `… | stats by (host) count() as hits | sort by (hits desc) | limit N`,
#: measured on 2026-09-12 over 24h. The FIRST row carries no `host` at all —
#: 76 records in that window have none — and `limit` is applied by
#: VictoriaLogs, over rows, before the adapter ever sees them.
VICTORIALOGS_HOST_ROWS = (
    {"hits": "76"},
    {"hits": "24", "host": "checkout-api-2"},
    {"hits": "22", "host": "auth-service-2"},
    {"hits": "21", "host": "auth-service-3"},
    {"hits": "20", "host": "payment-service-2"},
)


class _VictoriaLogsOnTheWire(VictoriaLogsSource):
    """The shipped adapter, replaying the lab's own rows.

    Only the transport is replaced. `_terms` — the code that turns rows into
    buckets, and DROPS a row carrying no value for the grouped field — runs
    exactly as it ships, which is the point: a fake that returned buckets
    would model the bug away.
    """

    def __init__(self):
        super().__init__("http://victorialogs.invalid")

    def _container_values(self, window=None, ttl=30.0):
        return ["app"]

    def _lines(self, path, params):
        cut = re.search(r"\|\s*limit\s+(\d+)", params.get("query", "") or "")
        rows = [dict(row) for row in VICTORIALOGS_HOST_ROWS]
        return rows[:int(cut.group(1))] if cut else rows


class CountBelowTheCutOnASourceThatCutsRowsTest(unittest.TestCase):
    """A short bucket list is only a COMPLETE one when the source answered
    with a bucket for every row it was asked for.

    `len(buckets) >= COUNT_VALUES` reads "the list came back full" as "the
    list was cut", and the two are the same statement only on a source whose
    buckets are one-to-one with the rows it asked for. Elasticsearch's are
    and Loki's are (it counts every value and cuts locally). VictoriaLogs
    cuts server-side — `| sort by (hits desc) | limit N` — and the adapter
    then drops every returned row that carries no value for the field, so a
    CUT list comes back SHORT and the guard never fires. Measured on the lab
    at 24h through the panel filler: a host holding 25 records answered
    `{"number": 0}` under "records where host is …, in this window and this
    board's query".

    The fix is upstream of the guard: the panel's own aggregation asks for
    the valueless records to be LABELLED, exactly as the terms panel beside
    it already does, so every adapter returns one bucket per row it asked for
    and a short list means a short list. Measured on the lab, `host` at 24h:

        size   buckets, unlabelled   buckets, labelled
           2                     1                   2
           3                     2                   3
           5                     4                   5
          50                    15                  16   (15 real hosts)
    """

    def answer(self, value, cut):
        from unittest import mock

        from wdash.api import dashboard_routes as routes
        from wdash.hub import LogQuery, Scope, TimeWindow

        window = TimeWindow.of("24h")
        panel = normalise({"id": "p1", "type": "count", "field": "host",
                           "value": value, "title": "That host"})
        with mock.patch.object(routes, "COUNT_VALUES", cut):
            result = _VictoriaLogsOnTheWire().aggregate(
                LogQuery(window=window, text="*", containers=("app",),
                         limit=1),
                routes._panel_aggregations([panel], window),
                Scope.unrestricted())
            return result.get("p1"), routes._count_panels([panel], result)["p1"]

    def test_a_value_the_source_cut_off_is_refused_rather_than_zeroed(self):
        """auth-service-2 holds 22 records and is the third row. Asked for
        two, VictoriaLogs answers two rows — one of them valueless — and the
        panel used to read the short list as a complete one."""
        buckets, panel = self.answer("auth-service-2", cut=2)
        self.assertEqual(len(buckets), 2,
                         f"the source answered {[b.key for b in buckets]} "
                         f"for a list it cut at 2")
        self.assertNotIn("number", panel)
        self.assertIn("auth-service-2", panel["error"])
        self.assertIn("not a count of zero", panel["error"].lower())

    def test_a_value_inside_the_cut_still_answers_its_count(self):
        """The refusal must not swallow the panel: the number is still a
        number for a value the list really holds."""
        _, panel = self.answer("checkout-api-2", cut=2)
        self.assertEqual(panel["number"], 24)

    def test_a_value_with_no_records_is_still_a_measured_zero(self):
        """And a complete list still answers 0 — refusing every miss would
        make the panel useless for the question it is mostly asked."""
        buckets, panel = self.answer("f2-host-that-does-not-exist", cut=50)
        self.assertEqual(len(buckets), len(VICTORIALOGS_HOST_ROWS))
        self.assertEqual(panel["number"], 0)


@unittest.skipUnless(VL_UP, _NO_VL)
class NumberBelowTheCutAgainstVictoriaLogsTest(unittest.TestCase):
    """The same claim against the running server, not against its rows.

    The module's other live check only ever compares `buckets[0]` — the
    commonest value, the one value a terms list can never cut — so the
    refusal path was never exercised against real data. This is that path.
    """

    CUT = 2

    def source_and_query(self):
        from wdash.hub import LogQuery, Scope, TimeWindow
        from wdash.hub.adapters import VictoriaLogsSource

        source = VictoriaLogsSource(LAB_VL)
        scope = Scope.unrestricted()
        window = TimeWindow.of("24h")
        containers = tuple(source.containers(scope))
        return source, scope, window, LogQuery(
            window=window, text="*", containers=containers, limit=1)

    def test_a_host_below_the_cut_is_named_rather_than_counted_as_zero(self):
        from unittest import mock

        from wdash.api import dashboard_routes as routes
        from wdash.hub import Terms

        source, scope, window, query = self.source_and_query()
        whole = source.aggregate(
            query, [Terms(name="all", field="host", size=500,
                          missing="unknown")], scope).get("all")
        below = [bucket for bucket in whole[self.CUT:]
                 if str(bucket.key) != "unknown" and bucket.count > 0]
        if not below:
            self.skipTest(f"{LAB_VL} reports {len(whole)} values of host in "
                          f"this window, too few to cut at {self.CUT}")

        # The RAREST value, and only if it is strictly rarer than the last
        # one inside the cut. "Ranked below the cut" and "outside the top N"
        # are different sets when the boundary is a TIE, and which members
        # of a tie a backend returns for `size=N` is its own business: the
        # lab's three busiest hosts sit on the same count, so this picked
        # the third of them and the cut then included it. Measured before
        # this, against the seeded lab: three failures in three runs, each
        # naming a host holding exactly the count of the two above it.
        if below[-1].count >= whole[self.CUT - 1].count:
            self.skipTest(
                f"{LAB_VL} reports every value of host at "
                f"{whole[self.CUT - 1].count} records in this window, so "
                f"no value is unambiguously outside the top {self.CUT}")

        wanted = str(below[-1].key)
        panel = normalise({"id": "p1", "type": "count", "field": "host",
                           "value": wanted, "title": "That host"})
        with mock.patch.object(routes, "COUNT_VALUES", self.CUT):
            result = source.aggregate(
                query, routes._panel_aggregations([panel], window), scope)
            answered = routes._count_panels([panel], result)["p1"]

        self.assertNotIn(
            "number", answered,
            f"{LAB_VL} holds {below[-1].count} records with host {wanted} — "
            f"outside a top {self.CUT} whose last member holds "
            f"{whole[self.CUT - 1].count} — and the panel answered "
            f"{answered.get('number')!r}")
        self.assertIn(wanted, answered["error"])


class CountOnABoardThatMergesSourcesTest(_Board):
    """A board reading every source at once cannot claim a cut it never saw.

    `fanout.aggregate` merges the members' bucket lists by key, so the merged
    list is the UNION of up to one list per source and its LENGTH is nobody's
    cut: three sources returning twenty values each make sixty buckets with
    no member anywhere near its ceiling. Refusing is still the safe
    direction — a member that cut is invisible from here — but the sentence
    has to be about the merge, because "not among the N commonest values in
    this window" is a claim about a list that was never asked for.
    """

    def setUp(self):
        super().setUp()
        from wdash.hub.adapters import ElasticsearchLogSource

        self.second = ModelledES({"app-logs-000002": (
            KEYWORD_MAPPING,
            [_record(90 + n, host=f"east-{n}") for n in range(3)])})
        self.hub.add_logs(ElasticsearchLogSource(self.second, name="east"))
        change_dashboard(self.app, self.dashboard, source="*")

    def records(self):
        return [_record(n, host=f"west-{n}") for n in range(3)]

    def ask(self, value, cut=4):
        from unittest import mock

        from wdash.api import dashboard_routes as routes

        with mock.patch.object(routes, "COUNT_VALUES", cut):
            return self.one([{"id": "p1", "type": "count", "field": "host",
                              "value": value, "title": "Hosts"}], "p1")

    def test_the_refusal_does_not_blame_a_cut_that_did_not_happen(self):
        """Six values over two sources, neither of which returned four."""
        panel = self.ask("f2-host-nowhere")
        self.assertNotIn("number", panel)
        self.assertNotIn("commonest values of host", panel["error"])
        self.assertIn("merge", panel["error"])
        self.assertIn("2 sources", panel["error"])

    def test_a_value_one_member_holds_is_never_drawn_as_zero(self):
        """Counted when it survives the merged cut, refused BY NAME when it
        does not. Which of the two depends on the cut, and saying so is the
        honest answer: the merged list is `COUNT_VALUES` long, so whether a
        value holding one record is in it is a property of the cut and not
        of the data.

        Both were counted before the fan-out started applying the size it
        was asked for, because it returned every value every member had —
        more than the panel wanted, which is the same bug that drew a "top
        5" as nine bars. The capability was an accident of that bug; the
        refusal is the answer the single-source path has always given.
        """
        for value in ("east-1", "west-1"):
            with self.subTest(value=value):
                panel = self.ask(value)
                self.assertNotEqual(panel.get("number"), 0)
                if "number" not in panel:
                    self.assertIn("not a count of zero", panel["error"])
                    self.assertIn(value, panel["error"])


class AlertingSwitchedOffTest(_Board):
    """Every rule on the instance is disabled, so nothing can fire.

    The guard asked `rules.all()`, which returns disabled rules too, while
    the evaluator that writes the history runs `rules.all(enabled_only=True)`
    (alerts/runner.py:189). A board whose rules are all switched off
    therefore passed the guard and was shown a quiet window — rows [] drawn
    as "No alert fired in this window", and the number 0 — for a store in
    which nothing can fire. That is the reading D26's third condition exists
    to prevent, one step along.
    """

    def setUp(self):
        super().setUp()
        install_rule(self.app.store)
        with self.app.store.engine.begin() as connection:
            connection.execute(alert_rules.update().values(enabled=False))

    def test_the_number_says_the_rules_are_off_rather_than_reading_zero(self):
        panel = self.one([{"id": "a2", "type": "alerts_undelivered"}], "a2")
        self.assertNotIn("number", panel)
        self.assertIn("switched off", panel["error"])

    def test_the_list_panel_says_the_same(self):
        panel = self.one([{"id": "a1", "type": "alerts", "size": 10}], "a1")
        self.assertNotIn("rows", panel)
        self.assertIn("switched off", panel["error"])

    def test_one_enabled_rule_is_enough_for_the_panels_to_answer(self):
        """And the history a since-disabled rule wrote still reads by NAME:
        the guard changes which rules count as configured, not which names a
        row may be drawn with."""
        install_rule(self.app.store, rule_id="f2-rule-live", name="Still on")
        fired(self.app.store, minutes_ago=5, rule_id="f2-rule")
        panel = self.one([{"id": "a1", "type": "alerts", "size": 10}], "a1")
        self.assertNotIn("error", panel)
        self.assertEqual([row["rule"] for row in panel["rows"]],
                         ["Payments API"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
