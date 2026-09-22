"""
Folding a monitor's results into hours, and what survives it.

The results table was measured comfortable at two million rows and unusable
at eight; fifty checks at fifteen seconds reach the second in a month, and
the only answer was "move to Postgres". Retention's answer was to delete,
which trades the history for a table that fits.

Rolling up keeps the part that can be kept EXACTLY. So these tests are
almost all one assertion asked different ways: the counts after folding are
the counts before it. A rollup that lost a percent would look fine on every
screen and be wrong in the only direction anybody would notice — downwards,
on availability, quietly.

What cannot survive is a percentile, and that is asserted too: the summary
stores no median and no p95, because the median of twelve hourly medians is
not the median of anything.
"""

import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wdash.store import Store  # noqa: E402
from wdash.store.monitoring import ROLLUP_SETTING, RETENTION_SETTING  # noqa: E402
from wdash.store.schema import monitor_summaries  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

HOUR = dt.timedelta(hours=1)


def _aware(value):
    """SQLite hands back naive datetimes; Postgres hands back aware ones."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=dt.timezone.utc)


def _store():
    return Store.open("sqlite:///:memory:",
                      secret_box=SecretBox(SecretBox.generate_key()))


class RollingUpTest(unittest.TestCase):
    def setUp(self):
        self.store = _store()
        self.agent, _ = self.store.agents.create("a")
        self.monitor = self.store.monitors.create(
            name="m", kind="http", target="http://x/",
            agent_ids=[self.agent["id"]])
        # A minute apart, ten days back, every eleventh one failing. Ten days
        # so there is plenty on both sides of any horizon here.
        self.now = dt.datetime.now(dt.timezone.utc).replace(
            minute=30, second=0, microsecond=0)
        self.store.results.record(self.agent["id"], [
            {"monitor_id": self.monitor["id"],
             "started_at": (self.now - dt.timedelta(minutes=m + 1)).isoformat(),
             "status": "down" if m % 11 == 0 else "up",
             "duration_us": 1000 + (m % 400)}
            for m in range(10 * 24 * 60)])
        self.window = (self.now - dt.timedelta(days=30), self.now)

    def totals(self):
        return self.store.results.totals(self.monitor["id"], *self.window)

    def test_the_counts_come_through_unchanged(self):
        before = self.totals()
        self.store.results.roll_up(2, now=self.now)
        after = self.totals()
        for key in ("checks", "up", "down"):
            with self.subTest(key=key):
                self.assertEqual(before[key], after[key])
        self.assertGreater(after["summarised"], 0, "nothing was folded")

    def test_the_rows_are_gone_and_the_table_is_smaller(self):
        rows = self.store.results.count()
        folded, written = self.store.results.roll_up(2, now=self.now)
        self.assertGreater(folded, 0)
        self.assertEqual(self.store.results.count(), rows - folded)
        self.assertLess(written, folded / 10,
                        "an hour of checks should be one row, not many")

    def test_running_it_twice_changes_nothing(self):
        self.store.results.roll_up(2, now=self.now)
        after = self.totals()
        summaries = self.store.results.summary_count()

        again = self.store.results.roll_up(2, now=self.now)
        self.assertEqual(again, (0, 0))
        self.assertEqual(self.store.results.summary_count(), summaries)
        self.assertEqual(self.totals()["checks"], after["checks"])

    def test_a_second_pass_at_a_wider_horizon_adds_rather_than_replaces(self):
        """An hour can be folded across two passes — a batch is a slice of
        one — so the second has to ADD. Replacing would keep the last slice
        and throw the rest away, which is an availability figure that
        silently drops most of its evidence."""
        before = self.totals()
        self.store.results.roll_up(5, now=self.now)
        self.store.results.roll_up(1, now=self.now)
        after = self.totals()
        self.assertEqual((before["checks"], before["up"], before["down"]),
                         (after["checks"], after["up"], after["down"]))

    def test_the_hour_in_progress_is_never_folded(self):
        """It is still being written into. A summary of it is a number that
        keeps changing while claiming to be final.

        Driven with a horizon INSIDE the current hour, which is the only way
        to reach that clamp — at a whole day or more the horizon is always
        earlier than the hour anyway, and the guard never runs.
        """
        self.store.results.roll_up(1.0 / 24 / 60, now=self.now)
        this_hour = self.now.replace(minute=0, second=0, microsecond=0)
        with self.store.engine.connect() as connection:
            hours = [row[0] for row in connection.execute(
                monitor_summaries.select().with_only_columns(
                    monitor_summaries.c.hour))]
        self.assertTrue(hours, "nothing was folded at all")
        for hour in hours:
            with self.subTest(hour=hour):
                self.assertLess(hour.replace(tzinfo=dt.timezone.utc)
                                if hour.tzinfo is None else hour, this_hour)

    def test_off_by_default_and_off_means_off(self):
        self.assertEqual(self.store.results.roll_up(0, now=self.now), (0, 0))
        self.assertEqual(self.store.results.summary_count(), 0)
        self.assertEqual(self.store.results.roll_up(None, now=self.now), (0, 0))

    def test_the_durations_it_keeps_are_exact(self):
        """Sum, count, smallest and largest — everything a mean needs and
        nothing a percentile would need, which is the point."""
        raw = self.store.results.series(
            self.monitor["id"], self.window[0], self.now)
        old = [r["duration_us"] for r in raw
               if r["started_at"].replace(tzinfo=dt.timezone.utc)
               < self.now - dt.timedelta(days=2)]
        self.store.results.roll_up(2, now=self.now)
        with self.store.engine.connect() as connection:
            rows = connection.execute(monitor_summaries.select()).mappings().all()
        self.assertEqual(sum(r["duration_sum"] for r in rows), sum(old))
        self.assertEqual(sum(r["duration_count"] for r in rows), len(old))
        self.assertEqual(min(r["duration_min"] for r in rows), min(old))
        self.assertEqual(max(r["duration_max"] for r in rows), max(old))

    def test_it_stores_no_percentile(self):
        """Not an omission. The median of twelve hourly medians is not the
        median, and an average of p95s is a p95 of nothing — a column here
        would produce a number that looks like the raw one, is not, and
        changes meaning the day the rows behind it are folded."""
        columns = {column.name for column in monitor_summaries.columns}
        for forbidden in ("median", "median_us", "p95", "p95_us",
                          "percentile"):
            with self.subTest(column=forbidden):
                self.assertNotIn(forbidden, columns)


class TheWindowItAnswersForTest(unittest.TestCase):
    """A summary is an hour, so a window that cuts one needs saying."""

    def setUp(self):
        self.store = _store()
        self.agent, _ = self.store.agents.create("a")
        self.monitor = self.store.monitors.create(
            name="m", kind="http", target="http://x/",
            agent_ids=[self.agent["id"]])
        self.now = dt.datetime.now(dt.timezone.utc).replace(
            minute=44, second=0, microsecond=0)
        self.store.results.record(self.agent["id"], [
            {"monitor_id": self.monitor["id"],
             "started_at": (self.now - dt.timedelta(minutes=m + 1)).isoformat(),
             "status": "up", "duration_us": 1000}
            for m in range(6 * 24 * 60)])

    def test_the_part_hour_at_the_far_edge_is_not_dropped(self):
        """The defect this class exists for, measured on 432,000 results
        folded at two days: asking for the last 30 days returned 43,184
        checks where the rows had said 43,200. The sixteen were a part-hour
        whose rows were inside the window and whose summary's hour started
        just outside it."""
        window = (self.now - dt.timedelta(days=5), self.now)
        self.store.results.roll_up(1, now=self.now)
        after = self.store.results.totals(self.monitor["id"], *window)

        # Exact for the window it REPORTS. Counted against the rows over
        # that same window rather than over the one asked for, because the
        # two differ by the part-hour and asserting against the narrower one
        # would be asserting the drop back.
        raw = self.store.results.totals(self.monitor["id"], *after["covers"])
        self.assertEqual(after["checks"], raw["checks"])
        self.assertGreater(after["checks"], 0)

    def test_it_neither_drops_nor_invents_the_part_hour(self):
        """Both sides are wrong and both look like a correct number. The
        summary for the hour that `start` falls inside covers minutes before
        it, so counting it whole over-reports by exactly those minutes —
        which is why `covers` reaches back to the top of that hour and the
        count is true of THAT."""
        window = (self.now - dt.timedelta(days=5), self.now)
        whole = self.store.results.totals(self.monitor["id"], *window)
        self.store.results.roll_up(1, now=self.now)
        folded = self.store.results.totals(self.monitor["id"], *window)

        minutes_before = (window[0] - folded["covers"][0]).total_seconds() / 60
        self.assertGreater(minutes_before, 0, "no part-hour in this fixture")
        self.assertEqual(folded["checks"], whole["checks"] + int(minutes_before))

    def test_it_says_the_window_it_is_exactly_true_of(self):
        """Wider than the one asked for, by up to an hour at the start —
        and named, rather than the count quietly being for a different
        window than the caller passed."""
        asked = (self.now - dt.timedelta(days=5), self.now)
        self.store.results.roll_up(1, now=self.now)
        got = self.store.results.totals(self.monitor["id"], *asked)
        covers_from, covers_to = got["covers"]
        self.assertLessEqual(covers_from, asked[0])
        self.assertGreaterEqual(covers_to, asked[1])
        self.assertEqual(covers_from.minute, 0, "not aligned to an hour")

    def test_with_nothing_folded_it_is_the_window_itself(self):
        asked = (self.now - dt.timedelta(days=5), self.now)
        got = self.store.results.totals(self.monitor["id"], *asked)
        self.assertEqual(got["covers"], asked)

    def test_it_says_where_the_percentiles_stop(self):
        """Everything before this has counts and no durations to take a
        percentile of."""
        self.store.results.roll_up(1, now=self.now)
        got = self.store.results.totals(
            self.monitor["id"], self.now - dt.timedelta(days=5), self.now)
        self.assertIsNotNone(got["oldest_row"])
        self.assertGreater(got["oldest_row"],
                           self.now - dt.timedelta(days=2))


class TheOrderOfTheTwoClocksTest(unittest.TestCase):
    """Rolling up before pruning, which is the whole of why it works."""

    def setUp(self):
        self.store = _store()
        self.agent, _ = self.store.agents.create("a")
        self.monitor = self.store.monitors.create(
            name="m", kind="http", target="http://x/",
            agent_ids=[self.agent["id"]])
        self.now = dt.datetime.now(dt.timezone.utc).replace(
            minute=30, second=0, microsecond=0)
        self.store.results.record(self.agent["id"], [
            {"monitor_id": self.monitor["id"],
             "started_at": (self.now - dt.timedelta(hours=h + 1)).isoformat(),
             "status": "up", "duration_us": 1000}
            for h in range(40 * 24)])

    def test_the_hours_between_the_two_horizons_are_folded_not_deleted(self):
        """Pruning first would throw the rows away and then summarise what
        was left, so everything between the rollup horizon and the retention
        one would be lost rather than folded — which is the outcome rolling
        up exists to avoid."""
        self.store.settings.set(ROLLUP_SETTING, 2)
        self.store.settings.set(RETENTION_SETTING, 30)
        self.store.results.prune_if_due(self.store.settings, now=self.now)

        got = self.store.results.totals(
            self.monitor["id"], self.now - dt.timedelta(days=30), self.now)
        # 30 days of hourly checks, minus nothing: the ones between day 2 and
        # day 30 are in summaries, the rest are still rows.
        self.assertGreaterEqual(got["checks"], 29 * 24)
        self.assertGreater(got["summarised"], 0)

    def test_with_the_rollup_off_it_prunes_as_it_always_did(self):
        self.store.settings.set(RETENTION_SETTING, 30)
        self.store.results.prune_if_due(self.store.settings, now=self.now)
        self.assertEqual(self.store.results.summary_count(), 0)
        self.assertGreater(self.store.results.count(), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class TheEdgesTheFirstTestsDidNotReachTest(unittest.TestCase):
    """Three mutations lived through the tests above, and each was a place
    the fixture never took the code. They are here rather than folded into
    those, because what each one needs is a DIFFERENT fixture — a horizon
    inside a day, a check with no duration, an hour folded twice — and
    bending one fixture to reach all three is how it stops reaching any."""

    def setUp(self):
        self.store = _store()
        self.agent, _ = self.store.agents.create("a")
        self.monitor = self.store.monitors.create(
            name="m", kind="http", target="http://x/",
            agent_ids=[self.agent["id"]])
        self.now = dt.datetime.now(dt.timezone.utc).replace(
            minute=30, second=0, microsecond=0)

    def record(self, results):
        self.store.results.record(self.agent["id"], [
            dict(monitor_id=self.monitor["id"], **r) for r in results])

    def test_half_a_day_means_half_a_day(self):
        """`int()` on the horizon made `roll_up(0.5)` mean `roll_up(0)` —
        off, silently, on a number somebody had deliberately typed. It
        survived every test above because each of those passes a horizon
        where rounding it down lands on the same side of the data."""
        self.record([
            {"started_at": (self.now - dt.timedelta(hours=h)).isoformat(),
             "status": "up", "duration_us": 1000}
            for h in (1, 3, 20, 30)])
        folded, _ = self.store.results.roll_up(0.5, now=self.now)
        self.assertEqual(folded, 2, "it did not fold at exactly 12 hours")
        left = self.store.results.series(
            self.monitor["id"], self.now - dt.timedelta(days=5), self.now)
        self.assertEqual(len(left), 2)

    def test_a_check_with_no_duration_is_counted_and_not_timed(self):
        """A connection refused has no response time. Counting it as one
        would divide by a bigger number than the durations it summed, and
        report a mean that is too low by exactly the failures — the
        direction that flatters."""
        old = (self.now - dt.timedelta(days=3)).replace(minute=5)
        self.record([
            {"started_at": old.isoformat(), "status": "down",
             "duration_us": None, "error": "connection refused"},
            {"started_at": old.replace(minute=6).isoformat(), "status": "up",
             "duration_us": 4000},
        ])
        self.store.results.roll_up(1, now=self.now)
        with self.store.engine.connect() as connection:
            row = connection.execute(
                monitor_summaries.select()).mappings().one()
        self.assertEqual(row["checks"], 2)
        self.assertEqual(row["duration_count"], 1, "it timed a check that "
                                                   "never reported a time")
        self.assertEqual(row["duration_sum"], 4000)
        self.assertEqual((row["duration_min"], row["duration_max"]),
                         (4000, 4000))

    def test_an_hour_folded_across_two_passes_keeps_its_smallest(self):
        """The merge path. Folding one hour in a single pass never runs it,
        so `min` turned into `max` lived — and the smallest response time of
        an hour is the one that says the check was ever fast."""
        old = (self.now - dt.timedelta(days=3)).replace(minute=0)
        self.record([{"started_at": old.replace(minute=5).isoformat(),
                      "status": "up", "duration_us": 9000}])
        self.store.results.roll_up(1, now=self.now, batch=1)

        # A second arrival into an hour already summarised, which is what a
        # late-reporting agent produces.
        self.record([{"started_at": old.replace(minute=50).isoformat(),
                      "status": "up", "duration_us": 100}])
        self.store.results.roll_up(1, now=self.now, batch=1)

        with self.store.engine.connect() as connection:
            row = connection.execute(
                monitor_summaries.select()).mappings().one()
        self.assertEqual(row["checks"], 2, "it wrote a second row for one hour")
        self.assertEqual(row["duration_min"], 100)
        self.assertEqual(row["duration_max"], 9000)
        self.assertEqual(row["duration_sum"], 9100)


class WhatTheDetailPageIsToldTest(unittest.TestCase):
    """The counts survive folding; the percentiles do not, and say so."""

    def setUp(self):
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        self.store = _store()
        self.agent, _ = self.store.agents.create("a")
        self.monitor = self.store.monitors.create(
            name="m", kind="http", target="http://x/",
            agent_ids=[self.agent["id"]])
        self.now = dt.datetime.now(dt.timezone.utc).replace(
            minute=30, second=0, microsecond=0)
        self.store.results.record(self.agent["id"], [
            {"monitor_id": self.monitor["id"],
             "started_at": (self.now - dt.timedelta(minutes=k + 1)).isoformat(),
             "status": "down" if k % 50 == 0 else "up",
             "duration_us": 1000 + k}
            for k in range(10 * 24 * 60)])
        self.source = StoreMonitorSource(self.store)

    def history(self):
        from wdash.hub import Scope
        from wdash.hub.query import TimeWindow
        # Anchored on the fixture's clock — see `TheShapeAfterFoldingTest`.
        window = TimeWindow.between(self.now - dt.timedelta(days=30), self.now)
        return self.source.history(self.monitor["id"], window,
                                   Scope.unrestricted())

    def test_with_nothing_folded_it_says_nothing(self):
        """`whole_window` is the mechanism for "the rows are not the
        window". Setting it where they ARE would put every monitor on the
        estimated path for no reason."""
        got = self.history()
        self.assertIsNone(got.whole_window)
        self.assertEqual(got.total, len(got))

    def test_the_header_still_counts_every_check(self):
        before = self.history().total
        self.store.results.roll_up(2, now=self.now)
        after = self.history()
        self.assertLess(len(after), before, "nothing was folded")
        self.assertEqual(after.total, before)
        self.assertEqual(after.whole_window["checks"], before)

    def test_the_failures_come_through_too(self):
        before = sum(1 for c in self.history() if c.status == "down")
        self.store.results.roll_up(2, now=self.now)
        self.assertEqual(self.history().whole_window["failed"], before)

    def test_it_offers_no_percentile_and_says_where_they_start(self):
        """An hourly summary cannot produce a median. Inventing one is the
        single thing this design refused to store, so the adapter passes
        None and the date the rows begin."""
        self.store.results.roll_up(2, now=self.now)
        whole = self.history().whole_window
        self.assertIsNone(whole["median_ms"])
        self.assertIsNone(whole["p95_ms"])
        self.assertFalse(whole["estimated"], "the COUNTS are exact")
        self.assertIsNotNone(whole["folded_from"])
        self.assertGreater(whole["folded_from"],
                           self.now - dt.timedelta(days=3))

    def test_the_page_turns_that_into_an_exact_availability(self):
        from wdash.api.monitor_routes import _availability
        self.store.results.roll_up(2, now=self.now)
        checks = self.history()
        summary = _availability(None, checks)
        self.assertEqual(summary["checks"], checks.whole_window["checks"])
        self.assertIsNone(summary["median_ms"])
        self.assertIsNotNone(summary["folded_from"])
        self.assertAlmostEqual(
            summary["availability"],
            round(100.0 * (summary["checks"] - summary["failed"])
                  / summary["checks"], 2))

    def test_and_says_so_on_the_page(self):
        """The sentence, rendered. A p95 of two days under a heading that
        says thirty is the kind of number somebody quotes."""
        from flask import render_template_string
        from wdash.api.monitor_routes import _availability
        from wdash.app import create_app
        from wdash.config import Config

        self.store.results.roll_up(2, now=self.now)
        summary = _availability(None, self.history())
        app = create_app(Config)
        with app.app_context():
            block = open("templates/monitor_detail.html").read()
            start = block.index("{% if summary.folded_from %}")
            end = block.index("{% endif %}", start) + len("{% endif %}")
            said = render_template_string(block[start:end], summary=summary)
        self.assertIn("counts every one of the", said)
        self.assertIn("one row per hour", said)


class TheShapeAfterFoldingTest(unittest.TestCase):
    """The sparkline over folded time, which is where this could have gone
    quietly wrong.

    Leaving summaries out of the chart was the obvious implementation and
    the wrong one: a flat gap where a month of checks used to be reads as
    "nothing ran", which is the one thing that did not happen. Every number
    this chart draws survives an hourly summary — the count and the failures
    are sums, the mean is the total over the total count, the worst is the
    largest of the largests — and it draws no percentile, which is the only
    thing a summary cannot give back.
    """

    def setUp(self):
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        self.store = _store()
        self.agent, _ = self.store.agents.create("a")
        self.monitor = self.store.monitors.create(
            name="m", kind="http", target="http://x/",
            agent_ids=[self.agent["id"]])
        self.now = dt.datetime.now(dt.timezone.utc).replace(
            minute=0, second=0, microsecond=0)
        # Ramping, which is the worst case for putting an hour in the wrong
        # bucket: with a flat response time no misplacement would show.
        # Every 97th fails, and a failure has NO duration — a connection
        # refused has no response time. Without one of those in here, the
        # total count and the timed count are the same number and a mean
        # taken over the wrong one is invisible.
        self.store.results.record(self.agent["id"], [
            {"monitor_id": self.monitor["id"],
             "started_at": (self.now - dt.timedelta(minutes=k + 1)).isoformat(),
             "status": "down" if k % 97 == 0 else "up",
             "duration_us": None if k % 97 == 0 else 1000 + k * 10}
            for k in range(10 * 24 * 60)])
        self.source = StoreMonitorSource(self.store)

    def window(self, days=7):
        """Anchored on the fixture's clock, not on the real one.

        `TimeWindow.of("7d")` ends at the real now, and the rows here end at
        `self.now` — the top of the hour this started in. The two agree when
        the test is written and drift apart as the hour turns, so rows at
        the window's edge move in and out and a folded hour lands outside a
        window its rows were inside. Both of these tests passed for an hour
        and then failed during a mutation run, which is how it was found.
        """
        from wdash.hub.query import TimeWindow
        return TimeWindow.between(self.now - dt.timedelta(days=days), self.now)

    def chart(self, points=120):
        from wdash.hub import Scope
        return self.source.series(self.monitor["id"], self.window(),
                                  Scope.unrestricted(), points=points)

    def test_no_bucket_goes_empty_where_the_rows_went(self):
        """The whole point. An empty bucket means "nothing ran then", and
        after folding that would be most of the chart."""
        before = [p.checks for p in self.chart()]
        self.store.results.roll_up(2, now=self.now)
        after = [p.checks for p in self.chart()]
        self.assertEqual(sum(1 for c in after if c == 0),
                         sum(1 for c in before if c == 0))

    def test_the_totals_on_it_are_unchanged(self):
        before = self.chart()
        self.store.results.roll_up(2, now=self.now)
        after = self.chart()
        self.assertEqual(sum(p.checks for p in before),
                         sum(p.checks for p in after))
        self.assertEqual(sum(p.down for p in before),
                         sum(p.down for p in after))

    def test_the_mean_is_over_the_checks_that_were_timed(self):
        """Not over every check. A failure with no response time still
        counts as a check, and dividing the summed duration by the number of
        CHECKS reports a mean too low by exactly the failures — the
        direction that flatters, on the number somebody watches for a
        slowdown."""
        self.store.results.roll_up(2, now=self.now)
        folded = self.store.results.summaries(
            self.monitor["id"], self.now - dt.timedelta(days=30), self.now)
        self.assertTrue([h for h in folded if h["checks"] > h["duration_count"]],
                        "no folded hour held an untimed check, so the two "
                        "divisors are the same number here")

        # One bucket, built only from folded hours, against the arithmetic
        # done by hand. Dividing by `checks` instead of `duration_count`
        # gives a different number on exactly this bucket, which is what
        # makes this an assertion rather than a restatement.
        chart = self.chart()
        width = (self.window().end - self.window().start).total_seconds() / len(chart)
        for index, point in enumerate(chart):
            start = self.window().start + dt.timedelta(seconds=index * width)
            end = start + dt.timedelta(seconds=width)
            inside = [h for h in folded
                      if start <= _aware(h["hour"]) < end]
            if not inside or point.duration_ms is None:
                continue
            if sum(h["checks"] for h in inside) == point.checks:
                counted = sum(h["duration_count"] for h in inside)
                summed = sum(h["duration_sum"] for h in inside)
                if counted == point.checks:
                    continue          # the two divisors agree here
                self.assertAlmostEqual(point.duration_ms,
                                       summed / counted / 1000.0, places=6)
                return
        self.fail("no bucket came only from folded hours with an untimed "
                  "check in it")

    def test_the_worst_it_ever_saw_survives(self):
        """`max` of the hourly maxima is the maximum. Unlike a percentile,
        this one does come back."""
        before = max(p.worst_ms for p in self.chart() if p.worst_ms)
        self.store.results.roll_up(2, now=self.now)
        after = max(p.worst_ms for p in self.chart() if p.worst_ms)
        self.assertEqual(before, after)

    def test_a_folded_hour_moves_its_bucket_mean_by_under_two_percent(self):
        """The one inexactness, bounded and measured rather than waved at.

        A bucket boundary is not on the hour, so an hour can span two and
        its checks are all attributed to the first. Measured at 1.10% on
        this fixture and this grid; the assertion leaves room for the
        fixture to change without inviting a rewrite of the rule.
        """
        before = self.chart()
        self.store.results.roll_up(2, now=self.now)
        after = self.chart()
        moved = [abs(b.duration_ms - a.duration_ms) / b.duration_ms * 100
                 for b, a in zip(before, after)
                 if b.duration_ms and a.duration_ms]
        self.assertTrue(moved, "no bucket had a mean on both sides")
        self.assertLess(max(moved), 2.0)

    def test_the_listing_draws_it_too(self):
        """`series` is the detail chart; the listing builds its sparklines
        through a different path, in one query for the page. Both had to
        learn this, and only one of them is exercised above."""
        from wdash.hub import Scope
        from wdash.hub.query import TimeWindow
        before = self.source.monitors(self.window(), Scope.unrestricted(),
                                      series=True).monitors[0]
        counted = sum(p.checks for p in before.series)
        self.store.results.roll_up(2, now=self.now)
        after = self.source.monitors(self.window(), Scope.unrestricted(),
                                     series=True).monitors[0]

        self.assertTrue(after.series, "no sparkline at all")
        # Against what it drew BEFORE, not against a floor. "More than two
        # days' worth" is true of the two days of rows that survive folding,
        # so a listing that never asked for the summaries passed it.
        self.assertEqual(sum(p.checks for p in after.series), counted)
