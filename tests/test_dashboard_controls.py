"""
The board's own controls: which window, how tall, how often, and which board.

Six small things, and what they have in common is that each one used to have
exactly one answer nobody chose.

**The window.** A dashboard offered five relative ranges, so the one question
people open a dashboard twice to ask — "what happened last Tuesday between
14:00 and 15:00" — could not be asked at all. Both halves already existed:
`TimeWindow.between` builds an absolute aligned window, and the Logs screen
has parsed absolute bounds for as long as it has had a date picker. What was
missing was the route reading them, and the trap under it is D4's defect
again: `_baseline_query` rebuilt its window from the time_range STRING rather
than from the window the query actually used, so an absolute range would have
been compared against the hour before *now* — silently, because the whole
comparison is inside a try/except that logs and returns None.

**The height.** Every panel was exactly 300px because `dashboard_view.html`
said `height:300px` on the card template, so a one-row table left two thirds
of its card empty and a long one scrolled inside a box.

**The create form.** It had no panel list and no thresholds, so every
dashboard was born as the same three panels and its author's first act was to
open Edit. The controls are one include now; what is measured here is that
the create form renders them, and that an untouched default set still stores
as ABSENT rather than as today's defaults frozen into the record.

**Duplicate.** How anybody makes their thirteenth dashboard. Two things are
decided rather than inherited: the copy belongs to whoever pressed the button,
and it starts private whatever the original was.

**The list filter.** Applied in Python, after the per-user visibility pass and
before the page slice — a box that searches only the 24 cards already drawn is
worse than no box.
"""

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from tests.support import (ModelledES, change_dashboard, grant,
                           install_dashboard)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.panels import (  # noqa: E402
    DEFAULT_HEIGHT, MAX_HEIGHT, MIN_HEIGHT, PanelError, normalise, normalise_all,
)
from wdash.models import Dashboard  # noqa: E402

MAPPING = {"@timestamp": {"type": "date"},
           "level": {"type": "keyword"},
           "service": {"type": "keyword"},
           "message": {"type": "text"}}


def _at(stamp):
    """An Elasticsearch bound back into a datetime, for arithmetic on it."""
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _records(count, at=None):
    """Records stamped inside a window, so a query that MISSES the window
    comes back empty and a query that hits it does not."""
    stamp = (at or datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    return [{"_id": f"r{i}", "@timestamp": stamp, "level": "ERROR",
             "service": "payments", "message": "boom"}
            for i in range(count)]


class _Board(unittest.TestCase):
    """One board on a cluster that evaluates what it is asked.

    `ModelledES` records every request body, so the WINDOW a panel was asked
    over is a measurement rather than a claim about the code.

    The fixture board carries TERMS panels rather than the default set, which
    opens with a timeseries: `ModelledES` models the `terms` aggregation and
    not the date histogram, so a board carrying one answers `failed` and every
    assertion about a payload would be an assertion about the fixture. The one
    test here that is about a histogram reads the REQUEST body — which is
    recorded before the answer is computed — and says so.
    """

    PANELS = [{"id": "levels", "type": "terms", "field": "severity",
               "title": "Levels", "width": 6},
              {"id": "services", "type": "terms", "field": "service",
               "title": "Services", "width": 6}]

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "dashboard-controls"
            DASHBOARD_STORAGE = "database"

        self.es = ModelledES({"app-logs-000001": (MAPPING, _records(7))})
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.es))
        self.app.hub = hub

        self.dashboard = install_dashboard(
            self.app, Dashboard("b1", "Board", "", "*", "u",
                                index_patterns=["app-*"],
                                panels=normalise_all(self.PANELS)))
        self.client = self.app.test_client()
        self.permissions = ["dashboard:view", "dashboard:create",
                            "dashboard:edit"]
        grant(self.app, "u", permissions=self.permissions, indices=["*"],
              trace_indices=["*"], services=["*"])
        self.sign_in("u", self.permissions)

    def sign_in(self, username, permissions, admin=False):
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": f"{username}@x", "username": username,
                "groups": [], "role": "admin" if admin else "viewer",
                "permissions": list(permissions),
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def data(self, **args):
        query = "&".join(f"{key}={value}" for key, value in args.items())
        return self.client.get(f"/api/dashboard/b1/data?{query}")

    def windows(self):
        """The (gte, lte) of every search this request produced, in order.

        The first is the panels' own window; the second, when there is one, is
        the baseline the comparison is drawn against.
        """
        out = []
        for request in self.es.requests:
            clauses = request["body"]["query"]["bool"]["must"]
            bounds = next(c["range"]["@timestamp"] for c in clauses if "range" in c)
            out.append((bounds["gte"], bounds["lte"]))
        return out


class AbsoluteRangeTest(_Board):
    """"Last Tuesday 14:00 to 15:00", which no relative range can be pointed
    at."""

    START = "2026-09-08T14:00:00Z"
    END = "2026-09-08T15:00:00Z"

    def test_the_panels_are_asked_over_the_range_that_was_given(self):
        response = self.data(start=self.START, end=self.END)
        self.assertEqual(response.status_code, 200)

        gte, lte = self.windows()[0]
        self.assertTrue(gte.startswith("2026-09-08T14:00"), gte)
        self.assertTrue(lte.startswith("2026-09-08T15:0"), lte)

    def test_the_baseline_is_the_hour_before_that_hour(self):
        """The defect the critique found, and the one D4 already had once.

        `_baseline_query` used to do `TimeWindow.of(time_range)` — the STRING,
        which an absolute request does not send — so the comparison silently
        fell back to the default hour: the previous period became 13:00 to
        14:00 TODAY, an hour with no incident in it, under an Errors card
        reading "+180% vs previous period". Nothing said so, because the whole
        comparison is inside a try/except that logs and returns None.
        """
        self.data(start=self.START, end=self.END)

        windows = self.windows()
        self.assertEqual(len(windows), 2, "the baseline query did not run")
        (current_start, current_end), (baseline_start, baseline_end) = windows

        self.assertEqual(baseline_end, current_start,
                         "the baseline does not end where this window starts")
        # The hour before the hour that was asked for — on the eighth of
        # September, not on whatever day this test runs. Read off the date
        # rather than off the minute, because `TimeWindow.between` aligns the
        # end outwards and the baseline is as long as what it precedes.
        self.assertTrue(baseline_start.startswith("2026-09-08T1"),
                        f"the baseline began at {baseline_start}")
        self.assertEqual(_at(baseline_end) - _at(baseline_start),
                         _at(current_end) - _at(current_start),
                         "the baseline is not as long as the window it "
                         "is compared against")

    def test_the_baseline_of_a_relative_range_is_unchanged(self):
        """The other half: threading the window through must not move the
        case that was already right."""
        self.data(time_range="24h")

        (current_start, _), (baseline_start, baseline_end) = self.windows()
        self.assertEqual(baseline_end, current_start)
        span = (datetime.fromisoformat(baseline_end.replace("Z", "+00:00"))
                - datetime.fromisoformat(baseline_start.replace("Z", "+00:00")))
        self.assertGreaterEqual(span, timedelta(hours=24))
        self.assertLess(span, timedelta(hours=25))

    def test_the_window_asked_for_is_echoed_and_the_range_name_is_not_invented(self):
        payload = self.data(start=self.START, end=self.END).get_json()
        self.assertIsNone(payload["time_range"],
                          "an absolute window was given a relative name")
        self.assertTrue(payload["window"]["start"].startswith("2026-09-08T14:00"),
                        payload["window"])

    def test_a_relative_range_still_says_which_one(self):
        payload = self.data(time_range="24h").get_json()
        self.assertEqual(payload["time_range"], "24h")
        self.assertIn("start", payload["window"])

    def test_an_absolute_range_still_draws_a_chart(self):
        """The drift the picker's own check measures for the five relative
        options, for the option that names no span at all: a window somebody
        typed must not come back as one bucket or as four hundred.

        Read from the REQUEST rather than from the answer: the histogram
        interval is a property of the question, and `ModelledES` answers terms
        and not date histograms.
        """
        change_dashboard(self.app, self.dashboard, panels=normalise_all(
            [{"id": "volume", "type": "timeseries", "split_by": "severity"}]))

        units = {"m": 60, "h": 3600, "d": 86400}
        for hours in (1, 24, 24 * 6):
            with self.subTest(hours=hours):
                self.es.requests.clear()
                end = datetime(2026, 9, 8, 15, tzinfo=timezone.utc)
                start = end - timedelta(hours=hours)
                self.data(start=start.isoformat().replace("+00:00", "Z"),
                          end=end.isoformat().replace("+00:00", "Z"))
                interval = (self.es.requests[0]["body"]["aggs"]["volume"]
                            ["date_histogram"]["fixed_interval"])
                size = int(interval[:-1]) * units[interval[-1]]
                buckets = hours * 3600 / size
                self.assertGreaterEqual(buckets, 8, f"{buckets:.0f} buckets")
                self.assertLessEqual(buckets, 200, f"{buckets:.0f} buckets")


class RefusedRangeTest(_Board):
    """A window that cannot be built is said, never quietly replaced.

    Falling back to the default hour would draw a real hour of real data under
    a control reading "Between two times" — a plausible answer to a question
    nobody asked, which is worse than an empty page.
    """

    def test_half_a_range_is_refused_with_a_reason(self):
        response = self.data(start="2026-09-08T14:00:00Z")
        self.assertEqual(response.status_code, 400)
        self.assertIn("both a start and an end", response.get_json()["error"])
        self.assertEqual(self.es.requests, [], "it asked anyway")

    def test_a_range_that_runs_backwards_is_refused(self):
        response = self.data(start="2026-09-08T15:00:00Z",
                             end="2026-09-08T14:00:00Z")
        self.assertEqual(response.status_code, 400)
        self.assertIn("before its end", response.get_json()["error"])
        self.assertEqual(self.es.requests, [])

    def test_a_range_that_cannot_be_read_is_refused(self):
        response = self.data(start="last%20tuesday", end="2026-09-08T14:00:00Z")
        self.assertEqual(response.status_code, 400)
        self.assertIn("could not be read", response.get_json()["error"])
        self.assertEqual(self.es.requests, [])

    def test_the_refusal_names_itself(self):
        """`error_type` is what the client branches on; "invalid_query" would
        send the reader to the dashboard's query, which is fine."""
        payload = self.data(start="2026-09-08T14:00:00Z").get_json()
        self.assertEqual(payload["error_type"], "invalid_time_range")


class PanelHeightTest(unittest.TestCase):
    """One clamped int beside width. No migration: the record is JSON."""

    def test_a_panel_stored_before_heights_existed_gets_the_standard_one(self):
        panel = normalise({"type": "terms", "field": "service", "width": 6})
        self.assertEqual(panel["height"], DEFAULT_HEIGHT)

    def test_a_height_somebody_chose_survives(self):
        panel = normalise({"type": "terms", "field": "service", "height": 450})
        self.assertEqual(panel["height"], 450)

    def test_a_height_is_clamped_rather_than_refused(self):
        """A board is not made unopenable by a number somebody typed into
        JSON: `normalise_all` runs at READ time, and a raise here is a 400 for
        the whole dashboard. Width has always been clamped; so is this."""
        self.assertEqual(
            normalise({"type": "terms", "field": "service", "height": 5})["height"],
            MIN_HEIGHT)
        self.assertEqual(
            normalise({"type": "terms", "field": "service",
                       "height": 100000})["height"], MAX_HEIGHT)

    def test_a_height_that_is_not_a_number_is_a_named_error(self):
        with self.assertRaises(PanelError) as caught:
            normalise({"type": "terms", "field": "service", "height": "tall"})
        self.assertIn("height", str(caught.exception))

    def test_every_panel_kind_carries_one(self):
        """The client reads `panel.height` for every card; a kind that did not
        carry one would render a chart area of no height at all."""
        for panel in ({"type": "timeseries"}, {"type": "terms", "field": "service"},
                      {"type": "trace_services"}, {"type": "monitors"},
                      {"type": "monitor_certificates"}):
            with self.subTest(kind=panel["type"]):
                self.assertIsInstance(normalise(panel)["height"], int)


class CreateFormTest(_Board):
    """The create form is the same form as the edit form now."""

    def page(self):
        return self.client.get("/dashboard/create").get_data(as_text=True)

    def test_the_create_form_carries_the_panel_editor(self):
        """It contained no panel list at all and zero occurrences of
        "threshold"."""
        page = self.page()
        self.assertIn('id="panelList"', page)
        self.assertIn('id="panelsField"', page)
        self.assertIn("data-add-panel", page)

    def test_the_create_form_carries_the_thresholds(self):
        page = self.page()
        self.assertIn("threshold_error_rate_warning", page)
        self.assertIn("threshold_error_count_critical", page)

    def test_it_starts_from_the_default_panels_rather_than_from_nothing(self):
        page = self.page()
        self.assertIn("Volume by Severity", page)
        self.assertIn("Top Services", page)

    def test_it_knows_the_set_it_rendered_is_the_default_one(self):
        """What keeps the create form from freezing today's defaults into
        every dashboard ever made: the editor posts its field EMPTY while the
        list still matches what it was rendered with."""
        self.assertIn("const DEFAULTED = true", self.page())

    def test_the_edit_form_of_a_customised_board_does_not(self):
        change_dashboard(self.app, self.dashboard, panels=[
            normalise({"type": "terms", "field": "host", "title": "Hosts"})])
        page = self.client.get("/dashboard/b1/edit").get_data(as_text=True)
        self.assertIn("const DEFAULTED = false", page)

    def test_the_height_control_is_offered_on_both_forms(self):
        for url in ("/dashboard/create", "/dashboard/b1/edit"):
            with self.subTest(url=url):
                page = self.client.get(url).get_data(as_text=True)
                self.assertIn("const HEIGHTS =", page)
                self.assertIn('data-key="height"', page)

    def test_a_panel_list_posted_by_the_create_form_is_stored(self):
        self.client.post("/dashboard/create", data={
            "name": "Made here", "query": "*", "index_patterns": ["*"],
            "panels": json.dumps([{"type": "terms", "field": "host",
                                   "title": "Hosts", "height": 450}]),
            "threshold_error_count_warning": "5"}, follow_redirects=True)
        made = next(d for d in self.app.dashboard_manager.get_all_dashboards()
                    if d.name == "Made here")
        panels = made.get_panels()
        self.assertEqual(len(panels), 1)
        self.assertEqual(panels[0]["field"], "host")
        self.assertEqual(panels[0]["height"], 450)
        self.assertEqual(made.thresholds["error_count"]["warning"], 5)


class DuplicateTest(_Board):
    """A copy under a new name, and who it belongs to."""

    def duplicate(self, dashboard_id="b1"):
        return self.client.post(f"/dashboard/{dashboard_id}/duplicate",
                                follow_redirects=True)

    def copies(self):
        """What this route made, and nothing a fixture installed."""
        return [d for d in self.app.dashboard_manager.get_all_dashboards()
                if d.name.endswith("(copy)")]

    def test_a_board_can_be_copied(self):
        change_dashboard(self.app, self.dashboard, query="level:ERROR",
                         description="the payments board",
                         index_patterns=["app-*"],
                         thresholds={"error_count": {"warning": 5}})
        self.assertEqual(self.duplicate().status_code, 200)

        copy = self.copies()[0]
        self.assertEqual(copy.name, "Board (copy)")
        self.assertEqual(copy.query, "level:ERROR")
        self.assertEqual(copy.description, "the payments board")
        self.assertEqual(copy.index_patterns, ["app-*"])
        self.assertEqual(copy.thresholds, {"error_count": {"warning": 5}})
        self.assertNotEqual(copy.id, "b1")

    def test_the_copy_belongs_to_whoever_pressed_the_button(self):
        """Not to the original author. Carrying `created_by` over makes a
        board the duplicator cannot edit — `edit_dashboard` reads it — with
        somebody else's name on work they never did."""
        self.sign_in("colleague", ["dashboard:view", "dashboard:create"])
        grant(self.app, "colleague",
              permissions=["dashboard:view", "dashboard:create"],
              indices=["*"], trace_indices=["*"], services=["*"])
        self.duplicate()
        self.assertEqual(self.copies()[0].created_by, "colleague")

    def test_a_copy_of_a_shared_board_starts_private(self):
        """Visibility is never copied. A duplicate carries the original's
        query and patterns under a new name, and copying "shared" is how a
        draft ends up in front of a room nobody chose."""
        change_dashboard(self.app, self.dashboard, visibility="shared")
        self.duplicate()
        self.assertEqual(self.copies()[0].visibility, "private")

    def test_the_panel_list_is_copied_as_stored_rather_than_as_resolved(self):
        """A board nobody has customised has NO panel list, and must keep
        following the defaults. Copying `get_panels()` would freeze today's
        defaults into the copy the moment it was made."""
        plain = install_dashboard(self.app, Dashboard(
            "plain", "Plain", "", "*", "u", index_patterns=["app-*"]))
        self.assertIsNone(plain.panels)

        self.duplicate("plain")
        copy = self.copies()[0]
        self.assertEqual(copy.name, "Plain (copy)")
        self.assertIsNone(copy.panels)
        self.assertEqual(len(copy.get_panels()), 3)

    def test_a_customised_panel_list_is_copied_whole(self):
        chosen = [normalise({"type": "terms", "field": "host", "title": "Hosts",
                             "height": 450, "width": 8})]
        change_dashboard(self.app, self.dashboard, panels=chosen)
        self.duplicate()
        copied = self.copies()[0].get_panels()
        self.assertEqual(len(copied), 1)
        self.assertEqual(copied[0]["field"], "host")
        self.assertEqual(copied[0]["height"], 450)

    def test_the_original_is_left_alone(self):
        self.duplicate()
        original = self.app.dashboard_manager.get_dashboard("b1")
        self.assertEqual(original.name, "Board")
        self.assertEqual(original.created_by, "u")

    def test_a_board_this_person_may_not_see_answers_the_way_a_missing_one_does(self):
        """404-and-not-403, exactly as `view_dashboard` does it: a distinct
        refusal turns this route into a way to find out which dashboards
        exist."""
        install_dashboard(self.app, Dashboard(
            "secret", "Fraud", "", "*", "alice", index_patterns=["app-*"],
            visibility="private"))
        response = self.duplicate("secret")

        self.assertIn("Dashboard not found", response.get_data(as_text=True))
        self.assertEqual(self.copies(), [])

    def test_a_board_that_does_not_exist_says_the_same_thing(self):
        response = self.duplicate("no-such-board")
        self.assertIn("Dashboard not found", response.get_data(as_text=True))
        self.assertEqual(self.copies(), [])

    def test_it_needs_the_permission_to_create_a_dashboard(self):
        """Which is what it does. `dashboard:view` alone must not be a way to
        write into the store."""
        self.sign_in("u", ["dashboard:view"])
        grant(self.app, "u", permissions=["dashboard:view"], indices=["*"],
              trace_indices=["*"], services=["*"])
        response = self.duplicate()
        self.assertIn("Access denied", response.get_data(as_text=True))
        self.assertEqual(self.copies(), [])

    def test_the_list_offers_the_button(self):
        page = self.client.get("/dashboards").get_data(as_text=True)
        self.assertIn("/dashboard/b1/duplicate", page)


class ListFilterTest(_Board):
    """A box that narrows the list by name and description."""

    def setUp(self):
        super().setUp()
        for index in range(30):
            install_dashboard(self.app, Dashboard(
                f"d{index:02d}", f"board-{index:02d}",
                "payments" if index == 29 else "logging",
                "*", "u", index_patterns=["app-*"]))

    def listed(self, **args):
        """The names on the CARDS, and the page they came from.

        Read from the card titles rather than from the whole body: the filter
        box echoes the term back into its own `value`, so a plain scan reports
        a dashboard as listed on the strength of what was typed to look for
        it — which is a test that cannot fail.
        """
        import re
        query = "&".join(f"{key}={value}" for key, value in args.items())
        body = self.client.get(f"/dashboards?{query}").get_data(as_text=True)
        titles = re.findall(r'fa-chart-line"></i>\s*(board-\d{2})', body)
        return sorted(set(titles)), body

    def test_it_narrows_by_name(self):
        names, _ = self.listed(q="board-07")
        self.assertEqual(names, ["board-07"])

    def test_it_narrows_by_description_too(self):
        """What a card actually shows is the name AND the description, so
        searching one of the two is a box that half works."""
        names, _ = self.listed(q="payments")
        self.assertEqual(names, ["board-29"])

    def test_it_does_not_care_about_case(self):
        names, _ = self.listed(q="BOARD-07")
        self.assertEqual(names, ["board-07"])

    def test_it_filters_before_the_page_is_cut(self):
        """The measurement that separates this from a filter over the cards
        already on screen. `board-29` is on the SECOND page unfiltered — the
        page holds 24 — so a filter applied after the slice finds nothing and
        says "no dashboards", while the board it is looking for sits one page
        along with nothing on screen saying so.
        """
        unfiltered, _ = self.listed()
        self.assertEqual(len(unfiltered), 24, "the page is not full")
        beyond = next(f"board-{index:02d}" for index in range(30)
                      if f"board-{index:02d}" not in unfiltered)

        filtered, _ = self.listed(q=beyond)
        self.assertEqual(filtered, [beyond],
                         f"{beyond} is on page 2 and the filter did not reach it")

    def test_a_filter_that_matches_nothing_says_so_rather_than_looking_empty(self):
        """"Create your first dashboard to get started" under a filter box
        holding a typo is emptiness standing in for a search."""
        names, body = self.listed(q="no-such-board")
        self.assertEqual(names, [])
        self.assertIn("Nothing matches", body)
        self.assertNotIn("Create your first dashboard", body)

    def test_it_cannot_reach_past_the_visibility_rule(self):
        """The filter runs over what `_visible` produced, never over the
        store. A term that matches somebody else's private board must not
        list it — the rule lives in dashboard/visibility.py and this must not
        become a second place that answers the same question."""
        install_dashboard(self.app, Dashboard(
            "secret", "board-99", "alice's private one", "*", "alice",
            index_patterns=["app-*"], visibility="private"))

        names, body = self.listed(q="board-99")
        self.assertEqual(names, [])
        self.assertNotIn("alice", body)

    def test_the_pages_of_a_filtered_list_keep_the_filter(self):
        """EVERY pagination link, not whichever one happens to be checked.

        A page link that dropped the term shows the unfiltered list under a
        box still holding it — the reader reads the second page of a search
        that was never run. Asserted over all of them because the numbered
        links and the Previous/Next links are three separate pieces of markup
        and only one has to be forgotten.
        """
        import re
        _, body = self.listed(q="board")
        nav = re.search(r"<nav>.*?</nav>", body, re.S)
        self.assertIsNotNone(nav, "a filtered list of 30 is not paginated")
        links = re.findall(r'class="page-link"\s+href="([^"]+)"', nav.group(0))
        self.assertTrue(links, "no pagination links at all")
        self.assertEqual([link for link in links if "q=board" not in link], [],
                         f"pagination links without the filter: {links}")

    def test_the_count_of_hidden_boards_still_means_hidden(self):
        """A dashboard left out because it does not match has not been hidden
        from anybody, and folding the two into one number sends the reader to
        an administrator to ask for access they already have."""
        install_dashboard(self.app, Dashboard(
            "secret", "board-99", "", "*", "alice", index_patterns=["app-*"],
            visibility="private"))

        _, body = self.listed(q="board-07")
        collapsed = " ".join(body.split())
        self.assertIn("1 dashboard is not shown", collapsed)
        self.assertIn("do not match", collapsed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
