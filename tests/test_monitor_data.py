"""
What the monitor pages say, checked against the data they were computed from.

Every class here began as a page that rendered, looked finished and said
something false: a skipped step reported as the fastest one, a day's
availability computed from its newest 500 checks, a pager that could not
reach page 21, a chart whose clock ran backwards, an outage in one location
that no alert saw, and a broken cluster shown as a quiet one.

The Elasticsearch side runs against `HeartbeatCluster`, which evaluates the
query it is sent — the filters, the paging, the sort and the aggregations the
adapter asks for — over documents shaped like the ones the lab's Heartbeat
8.19.9 writes. A fake that hands back the same answer whatever it is asked
cannot tell a query that asks per location from one that does not.
"""

import dataclasses
import datetime as dt
import fnmatch
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.support import (  # noqa: E402
    ModelledES, _comparable, _sorted_hits, _values, es_query_matches,
    search_body,
)
from tests.test_monitors import (  # noqa: E402
    NotADict, ReplayElasticsearch, _browser_runs,
)
from wdash.hub.adapters.es_monitors import (  # noqa: E402
    ElasticsearchMonitorSource, _dig,
)
from wdash.hub.fanout import FanOutMonitorSource  # noqa: E402
from wdash.hub.models import (  # noqa: E402
    DOWN, STEP_PASSED, STEP_SKIPPED, UP, Monitor, MonitorCheck, MonitorPage,
    MonitorPoint, StepResult,
)
from wdash.hub.query import TimeWindow  # noqa: E402
from wdash.hub.scope import Scope  # noqa: E402

SCOPE = Scope.unrestricted()


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _stamp(moment):
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def heartbeat(monitor_id, when, status=UP, location="lab-frankfurt",
              duration_us=2407, error=None, schedule=15, kind="http"):
    """One `heartbeat/summary` document, in the shape the lab's Heartbeat
    8.19.9 writes it: read off `heartbeat-8.19.9` on 2026-09-11 and trimmed
    to the fields the adapter reads, plus the ones that decide whether a
    query matches (`summary.status`, `event.type`, `monitor.timespan`).

    `location=None` is a self-managed Heartbeat with no `observer` at all,
    which is what the lab wrote before the field was configured.
    """
    stamp = _stamp(when)
    source = {
        "_id": f"{monitor_id}-{location}-{when.timestamp():.3f}",
        "@timestamp": stamp,
        "monitor": {
            "id": monitor_id, "name": monitor_id, "type": kind,
            "status": status,
            "check_group": f"{monitor_id}-{location}-{when.timestamp():.3f}",
            "duration": {"us": duration_us},
            "timespan": {"gte": stamp, "lt": _stamp(
                when + dt.timedelta(seconds=schedule))},
        },
        "summary": {"status": status, "up": int(status == UP),
                    "down": int(status == DOWN), "attempt": 1,
                    "max_attempts": 1, "final_attempt": True},
        "url": {"full": f"http://synthetics-targets:8080/{monitor_id}"},
        "event": {"dataset": kind, "type": "heartbeat/summary"},
        "tags": ["lab", kind],
    }
    if location is not None:
        source["observer"] = {"geo": {"name": location}, "name": location}
    if error:
        source["error"] = {"message": error, "type": "validate"}
    return source


class HeartbeatCluster(ModelledES):
    """ModelledES, plus what the monitor adapter asks of a cluster.

    Its parent evaluates bool, term, exists and range and sorts; this adds
    what the monitor queries use and the parent does not: index PATTERNS
    (`heartbeat-*`), `from`, and the aggregations `top_hits`, `max`, `avg`,
    `percentiles`, `date_histogram` with a fixed interval and extended bounds,
    and `terms` with `missing`.

    Each part behaves the way a cluster does in the case that matters: a
    terms aggregation drops a document without the field unless `missing`
    names a bucket for it, a date histogram keys its buckets on multiples of
    the interval since the epoch, and `from` skips hits rather than being
    ignored.

    `fail`, when set, is called with each request body and may return an
    exception to raise, so one query can fail while the others answer.
    """

    INDEX = "heartbeat-8.19.9"

    def __init__(self, documents=(), fail=None):
        super().__init__({self.INDEX: ({}, [dict(d) for d in documents])})
        self.fail = fail

    def _docs(self, index):
        patterns = str(index or "").split(",")
        return [hit for name, (_, hits) in self._indices.items()
                if any(fnmatch.fnmatchcase(name, p) for p in patterns)
                for hit in hits]

    def search(self, index=None, **kwargs):
        kwargs = dict(kwargs)
        # elasticsearch-py takes `from` and renames it `from_`; its signature
        # only lists the second, so it is taken off before the check.
        start = int(kwargs.pop("from", 0) or 0)
        body = search_body(kwargs)
        self.requests.append({"index": index, "body": body, "from": start})
        if self.fail is not None:
            error = self.fail(body)
            if error is not None:
                raise error
        hits = [hit for hit in self._docs(index)
                if es_query_matches(body.get("query"), hit["_source"])]
        ordered = _sorted_hits(hits, body.get("sort"))
        response = {"took": 1, "hits": {
            "total": {"value": len(hits), "relation": "eq"},
            "hits": ordered[start:start + body.get("size", 10)]}}
        if body.get("aggs"):
            response["aggregations"] = {
                name: self._aggregate(spec, hits)
                for name, spec in body["aggs"].items()}
        return NotADict(response)

    def _aggregate(self, spec, hits):
        subs = spec.get("aggs") or {}

        def filled(bucket, members):
            for name, sub in subs.items():
                bucket[name] = self._aggregate(sub, members)
            return bucket

        def numbers(field):
            return sorted(float(v) for hit in hits
                          for v in _values(hit["_source"], field))

        if "top_hits" in spec:
            options = spec["top_hits"]
            chosen = _sorted_hits(hits, options.get("sort"))
            return {"hits": {"total": {"value": len(hits)},
                             "hits": chosen[:options.get("size", 3)]}}
        if "max" in spec:
            found = numbers(spec["max"]["field"])
            return {"value": found[-1] if found else None}
        if "avg" in spec:
            found = numbers(spec["avg"]["field"])
            return {"value": sum(found) / len(found) if found else None}
        if "percentiles" in spec:
            found = numbers(spec["percentiles"]["field"])
            out = {}
            for percent in spec["percentiles"].get("percents", (50,)):
                if not found:
                    out[str(float(percent))] = None
                    continue
                # Interpolated between the closest ranks, as a t-digest is on
                # a small sample. Not nearest-rank: a cluster's percentile is
                # an estimate, and the model must not be more exact than the
                # thing it stands in for.
                rank = (len(found) - 1) * float(percent) / 100.0
                low = int(rank)
                high = min(low + 1, len(found) - 1)
                out[str(float(percent))] = (
                    found[low] + (found[high] - found[low]) * (rank - low))
            return {"values": out}
        if "date_histogram" in spec:
            options = spec["date_histogram"]
            text = options["fixed_interval"]
            step = int(text[:-1]) * {"s": 1000, "m": 60_000}[text[-1]]
            keyed = {}
            for hit in hits:
                for value in _values(hit["_source"], options["field"]):
                    moment = int(_comparable(value) * 1000)
                    keyed.setdefault(moment // step * step, []).append(hit)
            keys = set(keyed)
            if options.get("min_doc_count", 1) == 0:
                bounds = options.get("extended_bounds") or {}
                edges = list(keys)
                for edge in (bounds.get("min"), bounds.get("max")):
                    if edge is not None:
                        edges.append(int(edge) // step * step)
                if edges:
                    keys = set(range(min(edges), max(edges) + step, step))
            buckets = []
            for key in sorted(keys):
                members = keyed.get(key, [])
                buckets.append(filled({
                    "key": key,
                    "key_as_string": _stamp(dt.datetime.fromtimestamp(
                        key / 1000, dt.timezone.utc)),
                    "doc_count": len(members)}, members))
            return {"buckets": buckets}
        if "terms" in spec:
            terms = spec["terms"]
            grouped = {}
            for hit in hits:
                found = _values(hit["_source"], terms["field"])
                if not found and "missing" in terms:
                    found = [terms["missing"]]
                for value in found:
                    grouped.setdefault(value, []).append(hit)
            ordered = sorted(grouped.items(),
                             key=lambda kv: (-len(kv[1]), str(kv[0])))
            size = terms.get("size", 10)
            return {
                "sum_other_doc_count": sum(len(m) for _, m in ordered[size:]),
                "buckets": [filled({"key": key, "doc_count": len(members)},
                                   members)
                            for key, members in ordered[:size]]}
        return super()._aggregate(spec, hits)


def _unreachable(body):
    return ConnectionError("cluster unreachable")


# ---------------------------------------------------------------------------
# A page to render them on
# ---------------------------------------------------------------------------

class _PageCase(unittest.TestCase):
    """An app whose monitor sources are whatever the test says, and a user
    with `monitors:read`. The database is a file in a temporary directory,
    never the developer's."""

    def setUp(self):
        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        self.directory = tempfile.mkdtemp(prefix="wdash-monitor-data-")
        database = os.path.join(self.directory, "page.db")

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "monitor-data"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        grant(self.app, "admin", ["system:admin", "monitors:read"],
              indices=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "u1", "username": "admin", "email": "a@b",
                "groups": [], "role": "admin",
                "permissions": ["system:admin", "monitors:read"],
                "allowed_indices": ["*"]}
            session["_user_id"] = "u1"

    def tearDown(self):
        import shutil
        self.app.store.engine.dispose()
        shutil.rmtree(self.directory, ignore_errors=True)

    def use(self, *sources):
        self.app.hub.replace_all(monitors=list(sources))

    def store_source(self):
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        return StoreMonitorSource(self.app.store)

    def text(self, url):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        return " ".join(response.get_data(as_text=True).split())

    def flashes(self):
        with self.client.session_transaction() as session:
            return list(session.get("_flashes") or [])

    def assertSays(self, page, text):
        """assertIn, without printing the whole page when it fails."""
        if text not in page:
            self.fail(f"not on the page: {text!r}")

    def assertDoesNotSay(self, page, text):
        if text in page:
            at = page.index(text)
            self.fail(f"on the page: {page[max(0, at - 80):at + 80]!r}")


# ---------------------------------------------------------------------------
# a step that never ran
# ---------------------------------------------------------------------------

class ASkippedStepHasNoDurationTest(unittest.TestCase):
    """Heartbeat writes a `step/end` for a step that never ran, and gives it a
    duration: 11 µs and 4 µs in the measured fixture, 6-7 µs on the lab
    today. Passed through, a journey that broke at sign-in reported its
    basket step at 0.0 ms — the fastest step on the page — and the trend
    beside it at -100%, the green "getting quicker" the step table was
    written to rule out."""

    def setUp(self):
        self.window = TimeWindow(start=_now() - dt.timedelta(hours=1),
                                 end=_now())
        self.source = ElasticsearchMonitorSource(
            ReplayElasticsearch(_browser_runs()))

    def _last(self, monitor_id):
        return self.source.history(monitor_id, self.window, SCOPE,
                                   limit=25)[-1]

    def test_the_measured_documents_do_give_it_a_duration(self):
        """Without this the test below would pass against a fixture whose
        skipped step had no duration, and prove nothing."""
        measured = [_dig(document, "synthetics.step.duration.us")
                    for run in _browser_runs("lab-journey-down")
                    for document in run["documents"]
                    if _dig(document, "synthetics.step.status") == "skipped"]
        self.assertTrue(measured)
        self.assertTrue(all(value for value in measured), measured)

    def test_the_adapter_reports_none(self):
        steps = self._last("lab-journey-down").steps
        self.assertEqual([s.status for s in steps],
                         ["passed", "failed", "skipped"])
        self.assertIsNone(steps[2].duration_ms)
        # And the two that ran keep what they measured.
        self.assertGreater(steps[0].duration_ms, 1)
        self.assertGreater(steps[1].duration_ms, 1000)

    def test_the_run_table_shows_no_time_for_it(self):
        from wdash.api.monitor_routes import _step
        shown = [_step(s)["duration_ms"]
                 for s in self._last("lab-journey-down").steps]
        self.assertIsNone(shown[2], "a step that never ran printed as "
                                    f"{shown[2]} ms")

    def test_a_journey_that_broke_does_not_report_its_last_step_quicker(self):
        """The reported fault, from the measured documents: four passing
        runs in the first half of the hour, four failing ones in the second.
        """
        from wdash.api.monitor_routes import _step_history
        passing = self._last("lab-journey-up")
        failing = self._last("lab-journey-down")
        start = self.window.start
        checks = ([dataclasses.replace(passing, timestamp=start
                                       + dt.timedelta(minutes=5 + i))
                   for i in range(4)]
                  + [dataclasses.replace(failing, timestamp=start
                                         + dt.timedelta(minutes=40 + i))
                     for i in range(4)])
        third = _step_history(checks, self.window)[2]
        self.assertEqual(third["skipped"], 4)
        self.assertEqual(third["runs"], 8)
        # The basket step's own time, from the runs that reached it.
        self.assertEqual(third["median_ms"],
                         round(passing.steps[2].duration_ms, 1))
        self.assertGreater(third["median_ms"], 100)
        # Nothing in the second half reached it: no trend, not -100%.
        self.assertIsNone(third["trend"])


class ASkippedStepIsLeftOutOfTheStepRowsTest(unittest.TestCase):
    """The rule in `_step_history`, held by the status and not by the
    duration happening to be missing. Another source that reports a time for
    a skipped step must not undo it."""

    def setUp(self):
        self.end = _now()
        self.window = TimeWindow.exact(self.end - dt.timedelta(hours=1),
                                       self.end)

    def _run(self, minutes_ago, third_status, third_us):
        return MonitorCheck(
            timestamp=self.end - dt.timedelta(minutes=minutes_ago),
            status=UP, duration_ms=1.0, steps=(
                StepResult(index=1, status=STEP_PASSED, duration_us=100_000),
                StepResult(index=2, status=third_status,
                           duration_us=third_us)))

    def _rows(self, checks):
        from wdash.api.monitor_routes import _step_history
        return _step_history(checks, self.window)

    def test_its_time_is_not_counted(self):
        rows = self._rows(
            [self._run(m, STEP_PASSED, 800_000) for m in (55, 50, 45)]
            + [self._run(m, STEP_SKIPPED, 11) for m in (15, 10, 5)])
        second = rows[1]
        self.assertEqual(second["skipped"], 3)
        self.assertEqual(second["median_ms"], 800.0)
        self.assertEqual(second["p95_ms"], 800.0)
        self.assertIsNone(second["trend"])
        # No mark on the sparkline for a run that never got there.
        self.assertEqual(second["spark"]["gaps"], 3)


# ---------------------------------------------------------------------------
# the header describes the window, not the newest 500
# ---------------------------------------------------------------------------

def _day_of_checks(monitor_id="m", count=1440, up_newest=500):
    """One check a minute for a day: the newest `up_newest` up at 1 ms, the
    older ones down at 30 s. True availability for the defaults is 500 of
    1,440 — 34.72% — and the slowest check took 30,000 ms."""
    now = _now()
    return [heartbeat(monitor_id, now - dt.timedelta(minutes=n, seconds=30),
                      status=UP if n < up_newest else DOWN,
                      duration_us=1000 if n < up_newest else 30_000_000,
                      error=None if n < up_newest else "timed out",
                      schedule=60)
            for n in range(count)]


class TheHeaderIsTheWholeWindowTest(_PageCase):
    """Availability, percentiles and the slowest check, over every check in
    the window.

    Elasticsearch returns at most 500 checks to a history, and the header was
    computed from those: a monitor that was down for most of the day and up
    for its last 500 minutes read 100.0% available, slowest 1.0 ms."""

    def _header(self, page):
        cards = page.split("Response time")[0]
        found = {}
        for label in ("Availability", "Median", "p95", "Slowest"):
            match = re.search(">" + label + r"</div> <div class=\"h4 mb-0 "
                                            r"mt-1\"> ([\d,.]+|<span)", cards)
            found[label] = match.group(1) if match else None
        return found

    def test_the_adapter_counts_the_whole_window(self):
        source = ElasticsearchMonitorSource(
            HeartbeatCluster(_day_of_checks()), name="lab")
        checks = source.history("m", TimeWindow.of("24h"), SCOPE)
        self.assertEqual(len(checks), 500)
        self.assertEqual(checks.total, 1440)
        whole = checks.whole_window
        self.assertEqual(whole["checks"], 1440)
        self.assertEqual(whole["failed"], 940)
        self.assertEqual(whole["worst_ms"], 30000.0)
        self.assertEqual(whole["median_ms"], 30000.0)

    def test_a_page_of_checks_does_not_ask_for_them(self):
        """Only the whole-window read carries the aggregations: a page of
        twenty-five has no use for them."""
        cluster = HeartbeatCluster(_day_of_checks())
        source = ElasticsearchMonitorSource(cluster, name="lab")
        source.history("m", TimeWindow.of("24h"), SCOPE, offset=0, limit=25)
        self.assertNotIn("aggs", cluster.requests[0]["body"])

    def test_the_page_says_what_the_whole_day_was(self):
        self.use(ElasticsearchMonitorSource(
            HeartbeatCluster(_day_of_checks()), name="lab"))
        page = self.text("/monitors/m?window=24h")
        self.assertEqual(self._header(page), {
            "Availability": "34.72", "Median": "30000.0", "p95": "30000.0",
            "Slowest": "30000.0"})
        self.assertSays(page, "1,440 check(s), <span class=\"text-danger\">"
                              "940 failed")
        # And the two estimated figures say they are estimates.
        self.assertSays(page, "estimated by the source")

    def test_the_same_through_the_fan_out(self):
        """The default deployment: Elasticsearch plus the agents' store."""
        self.use(ElasticsearchMonitorSource(
            HeartbeatCluster(_day_of_checks()), name="lab"),
            self.store_source())
        page = self.text("/monitors/m?window=24h")
        self.assertEqual(self._header(page)["Availability"], "34.72")
        self.assertEqual(self._header(page)["Slowest"], "30000.0")

    def test_a_window_that_fits_is_still_counted_run_by_run(self):
        """Under the ceiling the runs are all in hand, and nearest-rank from
        them is a real observation — no estimate, and no note."""
        self.use(ElasticsearchMonitorSource(
            HeartbeatCluster(_day_of_checks(count=40, up_newest=30)),
            name="lab"))
        page = self.text("/monitors/m?window=24h")
        self.assertEqual(self._header(page)["Availability"], "75.0")
        self.assertDoesNotSay(page, "estimated by the source")
        self.assertDoesNotSay(page.split("Response time")[0], "newest")

    def _two_places(self, documents):
        for number, document in enumerate(documents):
            place = "lab-dublin" if number % 2 else "lab-frankfurt"
            document["observer"] = {"geo": {"name": place}, "name": place}
        return documents

    def test_the_cards_below_say_which_checks_they_hold(self):
        """By location and the step rows are counted from the rows in hand,
        which are the newest 500 of the day. They say so rather than being
        read as the day."""
        self.use(ElasticsearchMonitorSource(HeartbeatCluster(
            self._two_places(_day_of_checks())), name="lab"))
        page = self.text("/monitors/m?window=24h")
        card = page.split("By location")[1].split("</table>")[0]
        self.assertSays(card, "worst first, from the newest 500 of 1,440 "
                              "checks")

    def test_and_say_nothing_when_they_hold_the_window(self):
        self.use(ElasticsearchMonitorSource(HeartbeatCluster(
            self._two_places(_day_of_checks(count=40, up_newest=30))),
            name="lab"))
        page = self.text("/monitors/m?window=24h")
        card = page.split("By location")[1].split("</table>")[0]
        self.assertDoesNotSay(card, "from the newest")

    def test_a_source_that_cannot_count_the_window_says_so(self):
        """A ceiling and no aggregate: the figures can only come from the
        rows returned, and the header says which rows those were."""
        now = _now()

        class Capped:
            name = "capped"
            capabilities = frozenset({"monitor_list", "monitor_history"})

            def supports(self, capability):
                return capability in self.capabilities

            def monitors(self, window, scope, series=False):
                return MonitorPage(monitors=[Monitor(
                    id="m", name="m", status=UP, source="capped")],
                    sources=("capped",))

            def history(self, monitor_id, window, scope, offset=0,
                        limit=None):
                # Oldest first, as every source returns them.
                rows = _Counted(MonitorCheck(
                    timestamp=now - dt.timedelta(minutes=n), status=UP,
                    duration_ms=1.0) for n in (2, 1, 0))
                rows.total = 9
                return rows

            def series(self, monitor_id, window, scope, points=120):
                return []

            def certificates(self, window, scope):
                return []

            def health(self):
                return True, "ok"

            def containers(self, scope):
                return []

        self.use(Capped())
        page = self.text("/monitors/m?window=1h")
        self.assertSays(page, "From the newest 3 of 9 checks")
        self.assertDoesNotSay(page, "estimated by the source")


class _Counted(list):
    total = 0


# ---------------------------------------------------------------------------
# one monitor, several places
# ---------------------------------------------------------------------------

class SeveralLocationsTest(unittest.TestCase):
    """The same monitor, checked from Dublin and from Frankfurt.

    The listing took each monitor's single newest check, wherever it came
    from. With Dublin down and Frankfurt up reporting in turn, the row went
    down, up, down, up — and an alert with a threshold of three saw one
    failure, then none, for ever."""

    def setUp(self):
        self.now = _now()
        self.window = TimeWindow.of("1h")

    def _page(self, documents):
        source = ElasticsearchMonitorSource(HeartbeatCluster(documents),
                                            name="lab")
        return source.monitors(self.window, SCOPE)

    def _pair(self, dublin_newer):
        """Dublin down and Frankfurt up, whichever reported last."""
        dublin, frankfurt = ((1, 2) if dublin_newer else (2, 1))
        return [
            heartbeat("api", self.now - dt.timedelta(seconds=30 * dublin),
                      status=DOWN, location="lab-dublin",
                      error="received status code 500 expecting [200]"),
            heartbeat("api", self.now - dt.timedelta(seconds=30 * frankfurt),
                      status=UP, location="lab-frankfurt"),
        ]

    def test_a_place_that_is_down_makes_the_monitor_down(self):
        for dublin_newer in (True, False):
            page = self._page(self._pair(dublin_newer))
            self.assertEqual(len(page.monitors), 1, "one row per monitor")
            monitor = page.monitors[0]
            self.assertEqual(monitor.status, DOWN,
                             f"dublin newer: {dublin_newer}")
            self.assertIn("lab-dublin", monitor.error)
            self.assertIn("received status code 500", monitor.error)
            self.assertNotIn("lab-frankfurt", monitor.error)

    def test_the_row_is_the_failing_check(self):
        """Its time and its duration, rather than the healthy place's
        beside the failing place's status."""
        documents = self._pair(dublin_newer=False)
        documents[0]["monitor"]["duration"]["us"] = 9_000_000
        monitor = self._page(documents).monitors[0]
        self.assertEqual(monitor.duration_ms, 9000.0)
        self.assertEqual(monitor.checked_at,
                         self.now.replace(microsecond=(
                             self.now.microsecond // 1000) * 1000)
                         - dt.timedelta(seconds=60))

    def test_everywhere_up_is_up_and_the_row_is_the_newest(self):
        documents = [
            heartbeat("api", self.now - dt.timedelta(seconds=90), status=UP,
                      location="lab-dublin", duration_us=5_000),
            heartbeat("api", self.now - dt.timedelta(seconds=30), status=UP,
                      location="lab-frankfurt", duration_us=7_000)]
        monitor = self._page(documents).monitors[0]
        self.assertEqual(monitor.status, UP)
        self.assertEqual(monitor.error, "")
        self.assertEqual(monitor.duration_ms, 7.0)

    def test_of_two_places_down_the_row_is_the_newer(self):
        documents = [
            heartbeat("api", self.now - dt.timedelta(seconds=90),
                      status=DOWN, location="lab-dublin", error="old"),
            heartbeat("api", self.now - dt.timedelta(seconds=30),
                      status=DOWN, location="lab-oslo", error="new"),
            heartbeat("api", self.now - dt.timedelta(seconds=10),
                      status=UP, location="lab-frankfurt")]
        monitor = self._page(documents).monitors[0]
        self.assertEqual(monitor.error, "down from lab-oslo, lab-dublin: new")

    def test_one_place_keeps_its_own_words(self):
        """A single location has nothing to be told apart from, and its
        error is Heartbeat's sentence as it was."""
        monitor = self._page([heartbeat(
            "api", self.now - dt.timedelta(seconds=30), status=DOWN,
            error="received status code 500 expecting [200]")]).monitors[0]
        self.assertEqual(monitor.error,
                         "received status code 500 expecting [200]")

    def test_a_heartbeat_that_names_no_place_is_still_listed(self):
        """A self-managed Heartbeat writes no `observer`. Grouped by a field
        it does not have, and with no bucket for "missing", its monitors would
        vanish from the list — which reads as "not configured"."""
        page = self._page([heartbeat(
            "plain", self.now - dt.timedelta(seconds=30), location=None)])
        self.assertEqual([m.id for m in page.monitors], ["plain"])

    def test_an_unnamed_place_beside_a_named_one(self):
        documents = [
            heartbeat("api", self.now - dt.timedelta(seconds=60),
                      status=DOWN, location=None, error="timed out"),
            heartbeat("api", self.now - dt.timedelta(seconds=30),
                      status=UP, location="lab-frankfurt")]
        monitor = self._page(documents).monitors[0]
        self.assertEqual(monitor.status, DOWN)
        self.assertIn("timed out", monitor.error)

    def test_the_certificate_comes_from_whoever_saw_one(self):
        """A place that could not connect saw no certificate. The row is its
        check, and the certificate the other place saw is still the
        endpoint's — dropping it would take the monitor off the TLS tab and
        resolve a certificate alert for nothing."""
        documents = self._pair(dublin_newer=True)
        documents[1]["tls"] = {"server": {"x509": {
            "not_after": _stamp(self.now + dt.timedelta(days=9)),
            "subject": {"common_name": "api.example"}}}}
        monitor = self._page(documents).monitors[0]
        self.assertEqual(monitor.status, DOWN)
        self.assertIsNotNone(monitor.certificate)
        self.assertEqual(monitor.certificate.common_name, "api.example")

    def test_an_alert_with_a_threshold_sees_every_failure(self):
        """The reported fault, end to end through the real rule evaluation:
        threshold three, the two places taking turns at being newest."""
        from wdash.alerts.evaluate import FIRING, Observation, evaluate
        rule = {"threshold": 3, "repeat_minutes": 0}
        previous, fired = {}, []
        for turn in range(4):
            monitor = self._page(self._pair(dublin_newer=turn % 2 == 0)
                                 ).monitors[0]
            observations = [Observation(monitor.id, monitor.status == DOWN,
                                        monitor.error, monitor.name)]
            for decision in evaluate(rule, previous, observations,
                                     self.now + dt.timedelta(minutes=turn)):
                previous[decision.subject] = decision.state
                if decision.notify:
                    fired.append((turn, decision.notify, decision.detail))
        self.assertEqual(previous["api"].state, FIRING)
        self.assertEqual(fired[0][0], 2, fired)
        self.assertIn("lab-dublin", fired[0][2])


class TheAlertSeesOneMonitorOnceTest(_PageCase):
    """The same missed alert, from the agents' own store.

    The store lists one row per (monitor, agent) — two places, two rows, one
    id. The alert runner keyed both on the id, so the later row's verdict
    replaced the earlier one: down from Dublin and up from Frankfurt on every
    pass counted no failures at all, and a threshold of three never fired."""

    def test_down_from_one_agent_is_down(self):
        from wdash.alerts.evaluate import FIRING, MONITOR_DOWN, evaluate
        from wdash.alerts.runner import observe

        store = self.app.store
        monitor = store.monitors.create(
            name="Checkout", kind="http", target="https://shop.example/",
            interval_seconds=60, timeout_seconds=10)
        dublin, _ = store.agents.create("dublin")
        frankfurt, _ = store.agents.create("frankfurt")
        store.monitors.update(monitor["id"],
                              agent_ids=[dublin["id"], frankfurt["id"]])
        source = self.store_source()
        rule = {"kind": MONITOR_DOWN, "threshold": 3, "repeat_minutes": 0}
        previous, now = {}, _now()
        for turn in range(3):
            moment = (now + dt.timedelta(seconds=turn)).isoformat()
            for agent, status in ((dublin, "down"), (frankfurt, "up")):
                store.results.record(agent["id"], [{
                    "monitor_id": monitor["id"], "started_at": moment,
                    "status": status, "duration_us": 1000,
                    "error": "received 500" if status == "down" else ""}])
                store.agents.seen(agent["id"])
            listed = source.monitors(TimeWindow.of("1h"), SCOPE).monitors
            self.assertEqual(sorted(m.status for m in listed), [DOWN, UP],
                             "the store should list one row per agent")
            observations = observe(rule, source, store, TimeWindow.of("1h"),
                                   now)
            self.assertEqual([(o.subject, o.bad) for o in observations],
                             [(monitor["id"], True)])
            for decision in evaluate(rule, previous, observations,
                                     now + dt.timedelta(minutes=turn)):
                previous[decision.subject] = decision.state
        self.assertEqual(previous[monitor["id"]].state, FIRING)
        self.assertEqual(previous[monitor["id"]].failures, 3)

    def test_whatever_order_the_rows_come_in(self):
        """The store and the fan-out list down rows first; the runner must
        not depend on it."""
        from wdash.alerts.evaluate import MONITOR_DOWN
        from wdash.alerts.runner import observe

        class Listed:
            def monitors(self, window, scope):
                return MonitorPage(monitors=[
                    Monitor(id="api", name="API", status=UP),
                    Monitor(id="api", name="API", status=DOWN,
                            error="received 500"),
                    Monitor(id="web", name="Web", status=UP)])

        observations = observe({"kind": MONITOR_DOWN}, Listed(), None,
                               TimeWindow.of("1h"), _now())
        self.assertEqual(sorted((o.subject, o.bad, o.detail)
                                for o in observations),
                         [("api", True, "received 500"),
                          ("web", False, "the check failed")])


# ---------------------------------------------------------------------------
# the fan-out's count and its pages
# ---------------------------------------------------------------------------

class TheFanOutKeepsTheCountTest(_PageCase):
    """The default deployment has two monitor sources — Elasticsearch and the
    agents' store — so the detail page always goes through the fan-out. It
    took the members' first 500 checks, called that the total, and the pager
    said "of 500" of a day that held 1,440 and could not reach page 21."""

    def setUp(self):
        super().setUp()
        self.documents = _day_of_checks()
        self.cluster = HeartbeatCluster(self.documents)
        self.es = ElasticsearchMonitorSource(self.cluster, name="lab")
        self.fanout = FanOutMonitorSource([self.es, self.store_source()])
        self.window = TimeWindow.of("24h")
        #: Every check's time, newest first, as the cluster holds them.
        self.newest_first = sorted(
            (d["@timestamp"] for d in self.documents), reverse=True)

    def _stamps(self, checks):
        return [_stamp(c.timestamp) for c in checks]

    def test_the_total_is_the_members_count(self):
        checks = self.fanout.history("m", self.window, SCOPE)
        self.assertEqual(checks.total, 1440)

    def test_a_page_past_the_ceiling_is_the_right_page(self):
        page = self.fanout.history("m", self.window, SCOPE, offset=975,
                                   limit=25)
        self.assertEqual(page.total, 1440)
        self.assertEqual(list(reversed(self._stamps(page))),
                         self.newest_first[975:1000])

    def test_the_first_page_is_the_newest(self):
        page = self.fanout.history("m", self.window, SCOPE, offset=0,
                                   limit=25)
        self.assertEqual(list(reversed(self._stamps(page))),
                         self.newest_first[:25])

    def test_two_places_that_both_know_it_are_merged_in_order(self):
        """Two clusters watching one endpoint: the count is both, and a page
        of the merge is the newest across both, not a page of each."""
        now = _now()
        first = [heartbeat("m", now - dt.timedelta(minutes=2 * n + 1),
                           location="lab-dublin") for n in range(30)]
        second = [heartbeat("m", now - dt.timedelta(minutes=2 * n + 2),
                            location="lab-oslo") for n in range(30)]
        fanout = FanOutMonitorSource([
            ElasticsearchMonitorSource(HeartbeatCluster(first), name="a"),
            ElasticsearchMonitorSource(HeartbeatCluster(second), name="b")])
        page = fanout.history("m", self.window, SCOPE, offset=25, limit=25)
        self.assertEqual(page.total, 60)
        merged = sorted((d["@timestamp"] for d in first + second),
                        reverse=True)
        self.assertEqual(list(reversed(self._stamps(page))), merged[25:50])

    def test_the_pager_counts_the_day(self):
        self.use(self.es, self.store_source())
        page = self.text("/monitors/m?window=24h").replace("&ndash;", "–")
        self.assertSays(page, "1–25 of 1,440 checks")
        deep = self.text("/monitors/m?window=24h&page=40").replace(
            "&ndash;", "–")
        self.assertSays(deep, "976–1000 of 1,440 checks")
        body = deep.split("Recent checks")[1].split("<tbody>")[1]
        stamps = re.findall(r'data-timestamp="([^"]+)"', body)
        self.assertEqual([_stamp(dt.datetime.fromisoformat(s)) for s in stamps],
                         self.newest_first[975:1000])


# ---------------------------------------------------------------------------
# the fan-out's chart
# ---------------------------------------------------------------------------

class TheFanOutChartKeepsItsClockTest(_PageCase):
    """Elasticsearch buckets on multiples of its interval since the epoch —
    33 of them for fifteen minutes at 30 s. The store always answers with
    exactly 120 from the window's start, even for a monitor it has never
    seen. Merged by position, the page drew 120 labels with the data in the
    first 33 and time running backwards where the two met."""

    def setUp(self):
        super().setUp()
        self.window = TimeWindow.of("15m")
        now = _now()
        documents = [heartbeat("m", now - dt.timedelta(seconds=15 * n + 5))
                     for n in range(55)]
        self.es = ElasticsearchMonitorSource(HeartbeatCluster(documents),
                                             name="lab")
        self.fanout = FanOutMonitorSource([self.es, self.store_source()])

    def test_a_member_that_knows_nothing_changes_nothing(self):
        own = self.es.series("m", self.window, SCOPE)
        merged = self.fanout.series("m", self.window, SCOPE)
        self.assertEqual([(p.timestamp, p.checks) for p in merged],
                         [(p.timestamp, p.checks) for p in own])

    def test_time_only_moves_forward(self):
        merged = self.fanout.series("m", self.window, SCOPE)
        stamps = [p.timestamp for p in merged]
        self.assertEqual(stamps, sorted(set(stamps)))

    def test_two_members_with_checks_share_one_clock(self):
        """Two sources that both measured it. Their buckets go on one grid
        across the window, by time, and no check is lost or counted twice.

        One member reported only early in the window and the other only
        late, so where each check lands can be told from the time alone."""
        now = _now()
        early = [heartbeat("m", now - dt.timedelta(seconds=630 + 15 * n),
                           location="lab-dublin") for n in range(10)]
        late = [heartbeat("m", now - dt.timedelta(seconds=10 + 15 * n),
                          location="lab-oslo") for n in range(12)]
        both = FanOutMonitorSource([
            ElasticsearchMonitorSource(HeartbeatCluster(early), name="a"),
            ElasticsearchMonitorSource(HeartbeatCluster(late), name="b")])
        merged = both.series("m", self.window, SCOPE, points=30)
        stamps = [p.timestamp for p in merged]
        self.assertEqual(len(merged), 30)
        self.assertEqual(stamps, sorted(set(stamps)))
        self.assertEqual(stamps[0], self.window.start)
        self.assertEqual(sum(p.checks for p in merged), 10 + 12)
        middle = self.window.start + (self.window.end
                                      - self.window.start) / 2
        self.assertEqual(sum(p.checks for p in merged
                             if p.timestamp < middle), 10)
        self.assertEqual(sum(p.checks for p in merged
                             if p.timestamp >= middle), 12)


# ---------------------------------------------------------------------------
# a failure is not a quiet window
# ---------------------------------------------------------------------------

def _listing_only(body):
    """The listing answers, and the history and the chart fail."""
    if "monitors" in (body.get("aggs") or {}):
        return None
    return ConnectionError("cluster unreachable")


class AFailureIsNotAQuietWindowTest(_PageCase):
    """The history and chart queries failed and returned [], and the page
    said "No check in this window." and "Not enough checks in this window to
    draw a line" — the words for a monitor that did not run."""

    def _es(self, fail):
        now = _now()
        return ElasticsearchMonitorSource(HeartbeatCluster(
            [heartbeat("api", now - dt.timedelta(seconds=30))], fail=fail),
            name="es-mon")

    def test_the_adapter_raises_rather_than_answering_empty(self):
        source = self._es(_unreachable)
        window = TimeWindow.of("1h")
        with self.assertRaises(Exception) as history:
            source.history("api", window, SCOPE)
        self.assertIn("cluster unreachable", str(history.exception))
        self.assertIn("es-mon", str(history.exception))
        with self.assertRaises(Exception) as series:
            source.series("api", window, SCOPE)
        self.assertIn("cluster unreachable", str(series.exception))

    def test_the_store_raises_too(self):
        source = self.store_source()

        def broken(*args, **kwargs):
            raise RuntimeError("database is locked")
        self.app.store.results.series = broken
        window = TimeWindow.of("1h")
        with self.assertRaises(Exception) as history:
            source.history("x", window, SCOPE)
        self.assertIn("database is locked", str(history.exception))
        with self.assertRaises(Exception):
            source.series("x", window, SCOPE)

    def test_the_fan_out_names_the_member_that_failed(self):
        now = _now()
        healthy = ElasticsearchMonitorSource(HeartbeatCluster(
            [heartbeat("api", now - dt.timedelta(seconds=30))]), name="ok")
        fanout = FanOutMonitorSource([healthy, self._es(_unreachable)])
        window = TimeWindow.of("1h")
        checks = fanout.history("api", window, SCOPE)
        self.assertEqual(len(checks), 1)
        self.assertTrue(any("es-mon" in w and "cluster unreachable" in w
                            for w in checks.warnings), checks.warnings)
        points = fanout.series("api", window, SCOPE)
        self.assertTrue(any("es-mon" in w for w in points.warnings))

    def test_a_fan_out_where_every_member_failed_raises(self):
        fanout = FanOutMonitorSource([self._es(_unreachable),
                                      self._es(_unreachable)])
        with self.assertRaises(Exception) as caught:
            fanout.history("api", TimeWindow.of("1h"), SCOPE)
        self.assertIn("cluster unreachable", str(caught.exception))
        with self.assertRaises(Exception):
            fanout.series("api", TimeWindow.of("1h"), SCOPE)

    def test_the_page_says_it_could_not_read_them(self):
        self.use(self._es(_listing_only))
        page = self.text("/monitors/api?source=es-mon&window=1h")
        self.assertDoesNotSay(page, "No check in this window")
        self.assertDoesNotSay(page, "Not enough checks in this window")
        self.assertSays(page, "The checks could not be read: es-mon: "
                              "cluster unreachable")
        self.assertSays(page, "The response times could not be read: "
                              "es-mon: cluster unreachable")
        self.assertSays(page, "checks could not be read")

    def test_the_default_deployment_says_so_too(self):
        """Elasticsearch failing, and the agents' store answering — with
        nothing, because a Heartbeat monitor is not one of its own. Nobody
        who could have answered did, which is not an empty window."""
        self.use(self._es(_listing_only), self.store_source())
        page = self.text("/monitors/api?window=1h")
        self.assertDoesNotSay(page, "No check in this window")
        self.assertDoesNotSay(page, "Not enough checks in this window")
        self.assertSays(page, "The checks could not be read: es-mon: "
                              "cluster unreachable")
        self.assertSays(page, "The response times could not be read: "
                              "es-mon: cluster unreachable")

    def test_a_member_that_failed_is_named_on_the_page(self):
        now = _now()
        healthy = ElasticsearchMonitorSource(HeartbeatCluster(
            [heartbeat("api", now - dt.timedelta(seconds=30))]), name="ok")
        self.use(healthy, self._es(_listing_only))
        page = self.text("/monitors/api?window=1h")
        top = page.split("Response time")[0]
        self.assertSays(top, "This page is incomplete")
        self.assertSays(top, "es-mon: cluster unreachable")
        # And what the healthy member said is still drawn.
        self.assertSays(page, "1 check(s)")

    def test_steps_that_could_not_be_read_are_said(self):
        """A journey's steps are a second query. When it fails the checks
        are still real, and still shown — with nothing to expand, which
        reads as a journey that had no steps unless the page says why."""
        def steps_fail(body):
            wanted = _dig(body, "query.bool.filter") or []
            if any("terms" in clause for clause in wanted):
                return ConnectionError("shard failure")
            return None
        source = ElasticsearchMonitorSource(HeartbeatCluster(
            [heartbeat("journey", _now() - dt.timedelta(seconds=30),
                       kind="browser")], fail=steps_fail), name="es-mon")
        checks = source.history("journey", TimeWindow.of("1h"), SCOPE)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks.warnings, (
            "es-mon: the steps of these runs could not be read: "
            "shard failure",))
        self.use(source)
        page = self.text("/monitors/journey?window=1h")
        self.assertSays(page.split("Response time")[0],
                        "the steps of these runs could not be read")

    def test_a_listing_that_failed_is_not_a_monitor_that_did_not_report(self):
        self.use(self._es(_unreachable))
        response = self.client.get("/monitors/api?source=es-mon&window=1h")
        self.assertEqual(response.status_code, 302)
        said = " ".join(message for _, message in self.flashes())
        self.assertNotIn("No check from", said)
        self.assertIn("cluster unreachable", said)

    def test_the_history_api_says_it_failed(self):
        self.use(self._es(_listing_only))
        response = self.client.get("/api/monitors/api/history?source=es-mon")
        self.assertEqual(response.status_code, 502)
        body = response.get_json()
        self.assertEqual(body["error_type"], "monitor_source_failed")
        self.assertIn("cluster unreachable", body["error"])


# ---------------------------------------------------------------------------
# a note is shown even when nothing failed
# ---------------------------------------------------------------------------

class ListingNotesAreShownTest(_PageCase):
    """A source that stopped at its ceiling answered, so the page is not
    partial — and the note saying it stopped was only drawn inside the
    "partial" banner. 500 monitors read as all of them."""

    class _Noted:
        name = "es-heartbeat"
        capabilities = frozenset({"monitor_list"})

        def supports(self, capability):
            return capability in self.capabilities

        def monitors(self, window, scope, series=False):
            return MonitorPage(
                monitors=[Monitor(id="a", name="a", status=UP,
                                  source="es-heartbeat")],
                sources=("es-heartbeat",),
                warnings=("es-heartbeat: showing the first 500 monitors.",))

        def certificates(self, window, scope):
            return []

        def health(self):
            return True, "ok"

        def containers(self, scope):
            return []

    def test_the_note_reaches_the_page(self):
        self.use(self._Noted())
        page = self.text("/monitors?window=1h")
        self.assertSays(page, "es-heartbeat: showing the first 500 monitors.")
        self.assertDoesNotSay(page, "This list is incomplete")

    def test_and_through_the_fan_out(self):
        self.use(self._Noted(), self.store_source())
        page = self.text("/monitors?window=1h")
        self.assertSays(page, "es-heartbeat: showing the first 500 monitors.")

    def test_the_cap_is_measured_by_the_adapter(self):
        """Which is where the note comes from: 501 monitors, one too many."""
        from wdash.hub.adapters import es_monitors
        now = _now()
        documents = [heartbeat(f"m{n}", now - dt.timedelta(seconds=30))
                     for n in range(es_monitors.MAX_MONITORS + 1)]
        page = ElasticsearchMonitorSource(
            HeartbeatCluster(documents), name="lab").monitors(
                TimeWindow.of("1h"), SCOPE)
        self.assertEqual(len(page.monitors), es_monitors.MAX_MONITORS)
        self.assertFalse(page.partial)
        self.assertTrue(any("first 500" in w for w in page.warnings))


# ---------------------------------------------------------------------------
# a source that is not there
# ---------------------------------------------------------------------------

class AnUnknownSourceIsSaidTest(_PageCase):
    """A bookmark naming a source that was renamed or removed: every monitor
    route answered 500 Internal Server Error, where the log and trace routes
    say which source is missing."""

    def setUp(self):
        super().setUp()
        self.use(ElasticsearchMonitorSource(HeartbeatCluster(
            [heartbeat("a", _now() - dt.timedelta(seconds=30))]),
            name="lab"))

    def test_the_pages_say_so_and_go_back_to_the_list(self):
        for url in ("/monitors?source=nope&window=6h",
                    "/monitors/a?source=nope&window=6h"):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 302, url)
            self.assertEqual(response.headers["Location"],
                             "/monitors?window=6h", url)
            said = [message for _, message in self.flashes()]
            self.assertIn("There is no monitor source called 'nope'.", said,
                          url)

    def test_the_api_says_so(self):
        for url in ("/api/monitors?source=nope",
                    "/api/monitors/a/history?source=nope"):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 400, url)
            self.assertEqual(response.get_json(), {
                "error": "There is no monitor source called 'nope'.",
                "error_type": "source_missing"}, url)

    def test_a_source_that_is_there_still_answers(self):
        self.assertEqual(
            self.client.get("/monitors?source=lab").status_code, 200)
        self.assertEqual(
            self.client.get("/monitors/a?source=lab").status_code, 200)
