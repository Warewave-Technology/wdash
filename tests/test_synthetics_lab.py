"""
Elastic's browser screenshots, against a cluster a real Heartbeat wrote into.

`tests/test_monitors.py` checks the assembly against a fixture. A fixture is
a copy of what was true the day it was captured, which is enough to hold the
code and not enough to notice Elastic changing the shape underneath it. This
file asks the same questions of a running lab, and it is where the shape was
measured in the first place:

  * a screenshot is not a document. One `step/screenshot_ref` per step lists
    64 tiles by content HASH, and one `screenshot/block` per distinct hash
    carries the base64 JPEG, with the hash as its `_id`;
  * the blocks are shared. 125 references pointed at 30 stored blocks, and
    the blocks behind a screenshot taken that morning had been written two
    days earlier by different runs of a DIFFERENT monitor. Whatever prunes
    the data stream therefore leaves holes in newer screenshots;
  * so nothing here can be fetched by check group, and a missing tile is a
    state the product has to be able to say out loud.

    cd lab && ./lab.sh up synthetics      # Elasticsearch, targets, Heartbeat

Give it a few minutes: the journeys run on a schedule, and an empty index is
a lab that has not got there yet rather than a broken product. Skipped when
the lab is absent, and REQUIRED when `WDASH_REQUIRE_SYNTHETICS=1` says a job
promised one — a test that exists to measure this and passes by skipping is
the fault it is looking for.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub.adapters.es_monitors import (  # noqa: E402
    ElasticsearchMonitorSource, _dig,
)
from wdash.hub.query import TimeWindow  # noqa: E402
from wdash.hub.scope import Scope  # noqa: E402

LAB_URL = os.environ.get("WDASH_LAB_URL") or "http://localhost:9200"
REQUIRED = os.environ.get("WDASH_REQUIRE_SYNTHETICS") == "1"

SCREENSHOTS = "synthetics-browser.screenshot-*"


def _client():
    try:
        from elasticsearch import Elasticsearch
        client = Elasticsearch(hosts=[LAB_URL], request_timeout=5)
        return client if client.ping() else None
    except Exception:
        return None


def _has_screenshots(client):
    """Not just "is a cluster there" — the CI cluster is, and has no
    Heartbeat writing into it.

    Bounded to the same 24 hours the tests below ask for, and that bound was
    added after a lab brought up WITHOUT the synthetics profile failed five of
    them. The index still held last week's screenshots, so this said yes; the
    tests then asked for a browser monitor that had run recently and found
    none. A gate that admits a stale lab turns "Heartbeat is not running" into
    five failures that point at the product.
    """
    try:
        found = client.search(
            index=SCREENSHOTS, size=1,
            query={"bool": {"filter": [
                {"term": {"synthetics.type": "step/screenshot_ref"}},
                {"range": {"@timestamp": {"gte": "now-24h"}}},
            ]}},
            ignore_unavailable=True, allow_no_indices=True)
        return bool(_dig(found, "hits.hits"))
    except Exception:
        return False


CLIENT = _client()
LAB = CLIENT is not None and _has_screenshots(CLIENT)

_MISSING = (f"no browser screenshot from the last 24h at {LAB_URL} — "
            f"`cd lab && ./lab.sh up synthetics` and wait for a journey to "
            f"run, or set WDASH_LAB_URL")


class TheLabIsThereWhenPromisedTest(unittest.TestCase):
    @unittest.skipUnless(REQUIRED, "only asserted where a lab is promised")
    def test_the_screenshots_are_there(self):
        self.assertIsNotNone(CLIENT, f"nothing answered at {LAB_URL}")
        self.assertTrue(LAB, "the cluster answers but has written no browser "
                             "screenshots")


@unittest.skipUnless(LAB, _MISSING)
class ElasticScreenshotShapeTest(unittest.TestCase):
    """What Heartbeat writes, asked of Heartbeat."""

    def setUp(self):
        self.client = CLIENT
        self.source = ElasticsearchMonitorSource(self.client, name="lab")
        self.scope = Scope.unrestricted()

    def _newest_ref(self):
        found = self.client.search(
            index=SCREENSHOTS, size=1, sort=[{"@timestamp": "desc"}],
            query={"term": {"synthetics.type": "step/screenshot_ref"}})
        return _dig(found, "hits.hits")[0]["_source"]

    def test_a_screenshot_is_a_reference_and_its_tiles(self):
        reference = self._newest_ref()["screenshot_ref"]
        self.assertGreater(reference["width"], 0)
        self.assertGreater(reference["height"], 0)
        blocks = reference["blocks"]
        self.assertTrue(blocks)
        for block in blocks:
            for field in ("hash", "top", "left", "width", "height"):
                self.assertIn(field, block)
        # The tiles cover the picture: every column and every row of the grid
        # appears, which is what makes "draw each at its own position" a
        # complete instruction rather than a partial one.
        area = sum(b["width"] * b["height"] for b in blocks)
        self.assertEqual(area, reference["width"] * reference["height"])

    def test_the_tiles_live_under_their_own_hash(self):
        blocks = self._newest_ref()["screenshot_ref"]["blocks"]
        hashes = sorted({b["hash"] for b in blocks})
        found = self.client.search(index=SCREENSHOTS, size=len(hashes),
                                   query={"ids": {"values": hashes}})
        hits = _dig(found, "hits.hits")
        self.assertEqual({h["_id"] for h in hits}, set(hashes),
                         "a block was not stored under its own hash")
        for hit in hits:
            self.assertTrue(_dig(hit["_source"], "synthetics.blob"))
            self.assertEqual(_dig(hit["_source"], "synthetics.blob_mime"),
                             "image/jpeg")

    def test_the_tiles_outlive_the_run_that_wrote_them(self):
        """The finding that decides the whole design. If the blocks behind a
        screenshot always belonged to its own check group, this could be one
        query filtered by group and a missing tile would be impossible."""
        reference = self._newest_ref()
        hashes = sorted({b["hash"]
                         for b in reference["screenshot_ref"]["blocks"]})
        found = self.client.search(index=SCREENSHOTS, size=len(hashes),
                                   query={"ids": {"values": hashes}})
        groups = {_dig(h["_source"], "monitor.check_group")
                  for h in _dig(found, "hits.hits")}
        self.assertNotEqual(
            groups, {_dig(reference, "monitor.check_group")},
            "every tile came from this run — either the lab has run once, or "
            "Elastic has stopped sharing blocks between runs")

    def test_a_step_of_a_real_check_assembles(self):
        """End to end through the adapter, on whatever the lab last ran."""
        window = TimeWindow.of("24h")
        page = self.source.monitors(window, self.scope)
        journeys = [m for m in page.monitors if m.type == "browser"]
        self.assertTrue(journeys, "no browser monitor in the last 24h")

        checks = self.source.history(journeys[0].id, window, self.scope,
                                     limit=5)
        steps = [s for c in checks for s in c.steps if s.screenshot_id]
        # The newest step that actually ran; a skipped one has no picture.
        self.assertTrue(steps, "no step carried a screenshot token")

        shot = self.source.step_screenshot(steps[-1].screenshot_id, self.scope)
        self.assertIsNotNone(shot, "the newest step had no screenshot")
        self.assertEqual(shot["missing"], 0)
        self.assertTrue(shot["blocks"])
        self.assertEqual(
            sum(b["width"] * b["height"] for b in shot["blocks"]),
            shot["width"] * shot["height"])
        # JPEG, from the bytes rather than from the label.
        import base64
        self.assertEqual(base64.b64decode(shot["blocks"][0]["blob"])[:3],
                         b"\xff\xd8\xff")

    def _newest_check(self, monitor_id):
        window = TimeWindow.of("24h")
        checks = [c for c in self.source.history(monitor_id, window,
                                                 self.scope, limit=5)
                  if c.steps]
        self.assertTrue(checks, f"no run of {monitor_id} carried steps")
        return checks[-1]

    def test_every_step_that_ran_has_one(self):
        """Including the step that FAILED, which is the one somebody opens."""
        check = self._newest_check("lab-journey-down")
        ran = [s for s in check.steps if s.status != "skipped"]
        self.assertTrue(ran)
        for step in ran:
            with self.subTest(step=step.index, status=step.status):
                self.assertIsNotNone(step.screenshot_id)
                self.assertIsNotNone(
                    self.source.step_screenshot(step.screenshot_id,
                                                self.scope))

    def test_a_step_that_never_ran_offers_nothing(self):
        """Measured, and it decided a line of the adapter: a skipped step
        writes a `step/end` document like any other and NO screenshot — there
        was nothing on screen, because it never ran. Handing the page a token
        for it would be a camera button that always fails.

        `lab-journey-down` signs in with the wrong password, so its third
        step is the one that never happens.
        """
        check = self._newest_check("lab-journey-down")
        skipped = [s for s in check.steps if s.status == "skipped"]
        self.assertTrue(skipped, "the failing journey reached every step, so "
                                 "this proves nothing")
        for step in skipped:
            with self.subTest(step=step.index):
                self.assertIsNone(step.screenshot_id)


@unittest.skipUnless(LAB, _MISSING)
class WhereTheAgentStoodTest(unittest.TestCase):
    """`observer.geo.name`, measured rather than remembered.

    Before the lab's Heartbeat was told where it stands, the whole `observer`
    object was ABSENT from every document it wrote — which is why an empty
    location is a state WDash carries rather than a gap it fills in. Fleet
    manages that field for you; a self-managed Heartbeat does not.
    """

    def setUp(self):
        self.source = ElasticsearchMonitorSource(CLIENT, name="lab")
        self.window = TimeWindow.of("24h")
        self.scope = Scope.unrestricted()

    def test_the_lab_stamps_its_location_on_every_document(self):
        found = CLIENT.search(index="synthetics-browser-*", size=1,
                              sort=[{"@timestamp": "desc"}],
                              query={"term": {"synthetics.type":
                                              "journey/end"}})
        source = _dig(found, "hits.hits")[0]["_source"]
        self.assertEqual(_dig(source, "observer.geo.name"), "lab-frankfurt",
                         "the lab's heartbeat.yml is meant to add this — "
                         "without it the location column cannot be measured "
                         "at all")

    def test_a_check_carries_it_through_the_adapter(self):
        page = self.source.monitors(self.window, self.scope)
        journeys = [m for m in page.monitors if m.type == "browser"]
        self.assertTrue(journeys)
        checks = self.source.history(journeys[0].id, self.window, self.scope,
                                     limit=5)
        self.assertTrue(checks)
        self.assertEqual({c.location for c in checks}, {"lab-frankfurt"})


@unittest.skipUnless(LAB, _MISSING)
class TheMonitorQueriesAgainstHeartbeatTest(unittest.TestCase):
    """The listing, the history's whole-window figures and a journey's
    steps, asked of what a real Heartbeat wrote.

    `tests/test_monitor_data.py` holds the logic against a model that
    evaluates the query. Only a cluster can refuse one — a `missing` a
    keyword field will not take, a percentile on a field that is not a
    number — and a refusal here would reach the page as a failure on every
    load.
    """

    def setUp(self):
        self.source = ElasticsearchMonitorSource(CLIENT, name="lab")
        self.window = TimeWindow.of("1h")
        self.scope = Scope.unrestricted()

    def test_the_listing_asks_each_place_and_keeps_the_answer(self):
        from wdash.hub.models import DOWN
        page = self.source.monitors(self.window, self.scope)
        self.assertFalse(page.partial, page.warnings)
        rows = {m.id: m for m in page.monitors}
        self.assertEqual(rows["lab-http-down"].status, DOWN)
        # One place in the lab, so Heartbeat's own sentence, unprefixed.
        self.assertIn("500", rows["lab-http-down"].error)
        self.assertFalse(rows["lab-http-down"].error.startswith("down from"))

    def test_the_whole_window_is_counted_by_the_cluster(self):
        """The down monitor, so the count of failures has to be every check.
        The hour fits under the ceiling, so the rows can check the count."""
        from wdash.hub.models import DOWN
        checks = self.source.history("lab-http-down", self.window, self.scope)
        self.assertTrue(checks)
        self.assertEqual(len(checks), checks.total)
        whole = checks.whole_window
        self.assertEqual(whole["checks"], checks.total)
        self.assertEqual(whole["failed"],
                         sum(1 for c in checks if c.status == DOWN))
        self.assertEqual(whole["worst_ms"],
                         max(round(c.duration_ms, 1) for c in checks))
        self.assertIsNotNone(whole["median_ms"])
        self.assertLessEqual(whole["median_ms"], whole["worst_ms"])

    def test_a_step_that_never_ran_has_no_duration(self):
        """Heartbeat writes one for it anyway — a few microseconds."""
        written = CLIENT.search(
            index="synthetics-browser-*", size=1,
            sort=[{"@timestamp": "desc"}],
            query={"bool": {"filter": [
                {"term": {"synthetics.type": "step/end"}},
                {"term": {"synthetics.step.status": "skipped"}}]}})
        hits = _dig(written, "hits.hits")
        self.assertTrue(hits, "no skipped step to measure")
        self.assertIsNotNone(_dig(hits[0]["_source"],
                                  "synthetics.step.duration.us"),
                             "Heartbeat stopped writing a duration for a "
                             "skipped step, so this proves nothing")
        checks = self.source.history("lab-journey-down", self.window,
                                     self.scope, limit=5)
        skipped = [s for c in checks for s in c.steps if s.status == "skipped"]
        self.assertTrue(skipped)
        self.assertEqual({s.duration_ms for s in skipped}, {None})


def _playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False


PLAYWRIGHT = _playwright()


@unittest.skipUnless(LAB and PLAYWRIGHT,
                     _MISSING + ", or no playwright")
class TheTilesDrawTest(unittest.TestCase):
    """The half no assertion about JSON can reach.

    The tiles are drawn onto a canvas in the browser, so "the manifest is
    correct" and "somebody can see the page the journey saw" are two claims,
    and only the second one matters. This one opens the real screen in real
    Chromium and reads the pixels back.
    """

    @classmethod
    def setUpClass(cls):
        import tempfile
        import threading

        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        database = os.path.join(tempfile.mkdtemp(), "tiles.db")
        cls.password = "tiles-preview-only"
        cls.port = 5085
        lab_url = LAB_URL

        class LabConfig(Config):
            SECRET_KEY = "tiles"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = lab_url
            MONITOR_INDEX_PATTERNS = ("heartbeat-*", "synthetics-*")
            DASHBOARD_STORAGE = "database"

        cls.app = create_app(LabConfig)
        cls.app.test_client().post("/setup", data={"username": "admin",
                                                   "password": cls.password,
                                                   "confirm": cls.password})
        grant(cls.app, "admin", ["system:admin", "monitors:read"],
              indices=["*"])
        # The local account's role, not the test principal's: this signs in
        # through the form like a person.
        cls.app.store.settings.set("rbac.user_roles", {"admin": "test-role"})
        cls.app.store.rbac.invalidate()

        threading.Thread(
            target=lambda: cls.app.run(port=cls.port, threaded=True,
                                       use_reloader=False),
            daemon=True).start()

    def test_a_step_screenshot_draws_the_page_the_journey_saw(self):
        from playwright.sync_api import sync_playwright

        with self.app.app_context():
            source = self.app.hub.monitors(self.app.hub.ALL_SOURCES)
            window = TimeWindow.of("24h")
            journeys = [m for m in source.monitors(window,
                                                   Scope.unrestricted()
                                                   ).monitors
                        if m.type == "browser"]
            self.assertTrue(journeys, "no browser monitor in the last 24h")
            # The FAILING journey on purpose: it is the one with a step that
            # never ran, so the page has to offer fewer buttons than rows.
            monitor_id = next((m.id for m in journeys
                               if m.id == "lab-journey-down"), journeys[0].id)
            newest = [c for c in source.history(monitor_id, window,
                                                Scope.unrestricted(), limit=5)
                      if c.steps][-1]
            expected_rows = len(newest.steps)
            expected_buttons = sum(1 for s in newest.steps if s.screenshot_id)

        errors = []
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_page(viewport={"width": 1400, "height": 900})
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console",
                    lambda m: errors.append(m.text) if m.type == "error"
                    else None)
            base = f"http://127.0.0.1:{self.port}"
            page.goto(f"{base}/auth/login", wait_until="networkidle")
            page.fill("input[name=username]", "admin")
            page.fill("input[name=password]", self.password)
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")
            page.goto(f"{base}/monitors/{monitor_id}?window=24h",
                      wait_until="networkidle")
            page.locator("button[data-bs-target^='#steps-']").last.click()
            newest_run = page.locator("tr[id^='steps-']").last
            self.assertEqual(newest_run.locator("tbody tr").count(),
                             expected_rows)
            shots = newest_run.locator("[data-step-screenshot]")
            self.assertEqual(shots.count(), expected_buttons,
                             "a step that never ran was offered a camera "
                             "button, which can only ever fail")
            shots.last.click()
            page.wait_for_selector("#stepShot.show")
            page.wait_for_function(
                "() => document.getElementById('stepShotStatus')"
                ".textContent.includes('tile')", timeout=20000)
            status = page.locator("#stepShotStatus").inner_text()
            # Read back from the canvas. Two questions, and the second one is
            # the reason this test exists at all:
            #
            #   how many colours are on it — a canvas cleared and never
            #   painted has exactly one;
            #   is the far corner still the colour the gaps are painted in —
            #   every tile drawn at the origin leaves the rest of the canvas
            #   holding that fill, and that version has plenty of colours in
            #   it. Not "does the corner vary": the journey site is a white
            #   page, and its bottom-right corner is legitimately one colour.
            drawn = page.evaluate("""() => {
                const canvas = document.getElementById('stepShotCanvas');
                const context = canvas.getContext('2d');
                const data = context.getImageData(
                    0, 0, canvas.width, canvas.height).data;
                const seen = new Set();
                for (let p = 0; p < data.length; p += 4) {
                    seen.add((data[p] << 16) | (data[p + 1] << 8) | data[p + 2]);
                    if (seen.size > 64) { break; }
                }
                const far = context.getImageData(canvas.width - 4,
                                                 canvas.height - 4, 1, 1).data;
                // The colour a gap is painted in, resolved the same way the
                // page resolves it.
                const probe = document.createElement('canvas')
                    .getContext('2d');
                probe.fillStyle = getComputedStyle(document.documentElement)
                    .getPropertyValue('--surface-sunken').trim();
                return {colours: seen.size,
                        corner: [far[0], far[1], far[2]],
                        fill: probe.fillStyle,
                        width: canvas.width, height: canvas.height};
            }""")
            browser.close()

        self.assertEqual(errors, [])
        self.assertIn("tile", status)
        self.assertNotIn("no longer stored", status)
        self.assertGreater(drawn["width"], 0)
        self.assertGreater(drawn["colours"], 1,
                           f"the canvas is one flat colour: {drawn}")
        fill = drawn["fill"].lstrip("#")
        as_hex = "%02x%02x%02x" % tuple(drawn["corner"])
        self.assertNotEqual(as_hex, fill.lower(),
                            "the far corner is still the colour gaps are "
                            "painted in, so the tiles did not land where the "
                            f"reference put them: {drawn}")


if __name__ == "__main__":
    unittest.main()
