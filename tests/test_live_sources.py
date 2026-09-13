"""
A source configured on the page is used by the next query.

Until this existed the configuration screen said "Restart WDash for it to be
used for queries" — the one screen whose entire job is configuring the
application, refusing to configure it. An operator adding a cluster had to
find whoever could restart the service, and in the meantime the page listed a
source that answered nothing.

The mechanism is a split rather than a rebuild, and the split is the point:

  * the source WDash registers itself — the store's own agents — cannot
    change while the process runs, so it is built once. A reload that
    replaced it would throw away a live object to arrive at exactly the same
    one.
  * sources from the CONFIGURATION PAGE are held apart and swapped as a unit.

The second half is the multi-worker problem: gunicorn runs four of these and
the administrator's form reached exactly one. So the trigger cannot be a flag
in memory — it is a stamp in the store that every worker reads, cheaply and
on a clock. Measured, on a store holding ten sources:

    read the sources, cached          0.33 us
    the stamp query, once per TTL    49    us
    a rebuild, only when it moved   627    us

And end to end, against four real gunicorn workers with one form
submission: every one of them was answering from the new source 5.1
seconds later, which is the TTL and not a coincidence.
"""

import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.hub import Hub  # noqa: E402
from wdash.store import SecretBox  # noqa: E402

PASSWORD = "a-sufficiently-long-password"


class LiveSourceTestCase(unittest.TestCase):
    """One database, and as many app objects as a test needs workers."""

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.key = SecretBox.generate_key()
        self.app = self.worker()
        self.client = self.app.test_client()
        self.secret = support.set_up(
            self.client, username="owner", password=PASSWORD)
        self.sign_in(self.client)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def worker(self):
        """Another process's app object, on the same store."""
        database, key = self.database, self.key

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "live-sources"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key
            DASHBOARD_STORAGE = "database"

        return create_app(TestConfig)

    def sign_in(self, client):
        """Through the form, both halves. Permissions are resolved from the
        store on every request, so a session written by hand is a cookie
        nothing reads."""
        support.sign_in(client, "owner", PASSWORD, self.secret, app=self.app)

    # ---------- acting through the page, not the store ----------

    def save(self, name, url="http://localhost:3100", kind="loki",
             signals=("logs",), enabled=True):
        """Create, or edit the one with this name — the form does both, and
        the id is what tells them apart."""
        data = {"name": name, "kind": kind, "url": url,
                "signals": list(signals)}
        if enabled:
            data["enabled"] = "on"
        existing = next((s for s in self.app.store.sources.all()
                         if s["name"] == name), None)
        if existing:
            data["id"] = existing["id"]
        return self.client.post("/admin/sources", data=data,
                                follow_redirects=True)

    def delete(self, name):
        row = next(s for s in self.app.store.sources.all()
                   if s["name"] == name)
        return self.client.post(f"/admin/sources/{row['id']}/delete",
                                follow_redirects=True)

    @staticmethod
    def names(app, signal="log"):
        with app.app_context():
            return [source.name
                    for source in getattr(app.hub, f"{signal}_sources")]

    @staticmethod
    def age(app):
        """Five seconds on, for the worker that did not make the edit."""
        app.hub._checked_at = 0.0


class ASavedSourceIsUsedTest(LiveSourceTestCase):
    def test_the_next_query_reaches_it(self):
        self.assertEqual(self.names(self.app), [])
        self.save("loki-one")
        self.assertEqual(self.names(self.app), ["loki-one"])

    def test_it_can_be_asked_for_by_name(self):
        """Registered and unreachable is worse than absent: the page says it
        is there."""
        self.save("loki-one")
        with self.app.app_context():
            self.assertEqual(self.app.hub.logs("loki-one").name, "loki-one")

    def test_deleting_one_takes_it_away(self):
        self.save("loki-one")
        self.save("loki-two", url="http://localhost:3101")
        self.delete("loki-one")
        self.assertEqual(self.names(self.app), ["loki-two"])

    def test_disabling_one_takes_it_away_too(self):
        """The switch is not decoration. Only enabled rows are built, and a
        source turned off has to stop answering without being deleted."""
        self.save("loki-one")
        self.save("loki-one", enabled=False)
        self.assertEqual(self.names(self.app), [])

    def test_editing_where_it_points_moves_the_queries(self):
        self.save("loki-one", url="http://localhost:3100")
        self.save("loki-one", url="http://localhost:3199")
        with self.app.app_context():
            self.assertIn("3199", self.app.hub.logs("loki-one")._url)

    def test_the_page_no_longer_asks_for_a_restart(self):
        page = self.save("loki-one").get_data(as_text=True)
        self.assertIn("in use now", page)
        self.assertNotIn("Restart WDash", page)

    def test_the_screen_stops_promising_one_either(self):
        page = self.client.get("/admin/config").get_data(as_text=True)
        self.assertIn("as soon as it is saved", page)
        self.assertNotIn("read at startup", page)


class EveryWorkerCatchesUpTest(LiveSourceTestCase):
    """The half that a flag in memory cannot do.

    Gunicorn runs four of these. The administrator's form reached one.
    """

    def test_a_worker_that_started_later_has_it(self):
        self.save("loki-one")
        self.assertEqual(self.names(self.worker()), ["loki-one"])

    def test_one_that_was_already_running_catches_up(self):
        other = self.worker()
        self.assertEqual(self.names(other), [])
        self.save("loki-one")
        self.age(other)
        self.assertEqual(self.names(other), ["loki-one"])

    def test_it_notices_a_deletion_that_moves_no_timestamp(self):
        """Why the stamp counts as well as looking at the newest change.

        Delete the OLDER of two sources and `max(updated_at)` is exactly
        where it was — the newest row did not move. Only the count says
        anything happened, and without it this worker goes on querying a
        source the administrator removed.
        """
        self.save("loki-old")
        self.save("loki-new", url="http://localhost:3101")
        other = self.worker()
        # By name, the repository's own order. It was creation order while
        # the first registered source was the one an unnamed query read;
        # nothing answers by position now, so the order only says how a
        # picker lists them.
        self.assertEqual(self.names(other), ["loki-new", "loki-old"])

        newest = max(s["updated_at"] for s in self.app.store.sources.all())
        self.delete("loki-old")
        self.assertEqual(
            max(s["updated_at"] for s in self.app.store.sources.all()),
            newest, "this test deleted the wrong one")

        self.age(other)
        self.assertEqual(self.names(other), ["loki-new"])

    def test_and_notices_a_deletion(self):
        self.save("loki-one")
        other = self.worker()
        self.assertEqual(self.names(other), ["loki-one"])
        self.delete("loki-one")
        self.age(other)
        self.assertEqual(self.names(other), [])

    def test_it_does_not_ask_the_store_on_every_read(self):
        """The check is on a clock. Without one this is a query per search,
        paid by every worker for a picture that almost never changes."""
        other = self.worker()
        asked = []
        real = other.store.sources.stamp
        other.store.sources.stamp = lambda: (asked.append(1), real())[1]
        with other.app_context():
            for _ in range(50):
                other.hub.log_sources
        self.assertEqual(len(asked), 0, "the TTL was not honoured")
        self.age(other)
        with other.app_context():
            for _ in range(50):
                other.hub.log_sources
        self.assertEqual(len(asked), 1, f"asked {len(asked)} times")

    def test_an_unchanged_store_does_not_rebuild(self):
        """Identity, not equality. Rebuilding on every check would mean a new
        client and a new connection pool every few seconds, for sources
        nobody edited."""
        self.save("loki-one")
        other = self.worker()
        with other.app_context():
            before = other.hub.logs("loki-one")
        self.age(other)
        with other.app_context():
            self.assertIs(other.hub.logs("loki-one"), before)


class TheBaseSourceIsLeftAloneTest(LiveSourceTestCase):
    """The reason this is a split and not a rebuild."""

    def test_the_agents_source_survives_a_reload(self):
        """It reads the metadata store this process already holds, so there
        is nothing a configuration edit could change about it — and it is the
        source every check WDash runs itself comes from."""
        with self.app.app_context():
            before = self.app.hub.monitors("wdash-agents")
        self.save("es-two", url="http://localhost:9201", kind="elasticsearch",
                  signals=("monitors",))
        with self.app.app_context():
            self.assertIs(self.app.hub.monitors("wdash-agents"), before)
            self.assertIn("es-two", [s.name
                                     for s in self.app.hub.monitor_sources])


class ABrokenStoreKeepsTheLastGoodPictureTest(LiveSourceTestCase):
    """Serving what was configured beats serving nothing.

    The role resolver already works this way, and for the same reason: a
    transient database error is not a reason to take every source away.
    """

    def test_a_failing_rebuild_leaves_the_sources_running(self):
        self.save("loki-one")
        with self.app.app_context():
            before = self.app.hub.logs("loki-one")
            self.app.hub._build = lambda: (_ for _ in ()).throw(
                RuntimeError("the store is down"))
            self.app.hub.reload()
            self.assertIs(self.app.hub.logs("loki-one"), before)

    def test_a_failing_stamp_does_not_take_them_away_either(self):
        self.save("loki-one")
        self.app.hub._stamp_of = lambda: (_ for _ in ()).throw(
            RuntimeError("the store is down"))
        self.age(self.app)
        self.assertEqual(self.names(self.app), ["loki-one"])


class SwappingIsAtomicTest(unittest.TestCase):
    """A reader gets the old set or the new one, never half of each.

    Mutating the registry in place would let a search that is choosing which
    sources to fan out over see a moment with some of them missing — a result
    that is quietly short, which is the failure mode this whole layer exists
    to avoid.
    """

    class Fake:
        capabilities = ()

        def __init__(self, name):
            self.name = name

        def health(self):
            return True, "ok"

    def _hub(self, current):
        hub = Hub()
        hub.reload_with(build=lambda: dict(current), stamp=lambda: 1)
        return hub

    def test_the_picture_a_reader_holds_is_never_edited_underneath_it(self):
        """The guarantee, stated without a race.

        `_registry` takes the lock only long enough to grab a reference, and
        merges outside it. That is only safe while the thing it grabbed is
        never written to again — so a reload must leave a NEW dictionary and
        leave the old one exactly as it was.
        """
        current = {"logs": [self.Fake(f"s{n}") for n in range(4)]}
        hub = self._hub(current)
        held = hub._configured["logs"]
        snapshot = dict(held)

        current["logs"] = [self.Fake("only")]
        hub.reload()

        self.assertIsNot(hub._configured["logs"], held,
                         "the registry was mutated rather than swapped")
        self.assertEqual(held, snapshot,
                         "a reader's picture changed under it")
        self.assertEqual(list(hub._configured["logs"]), ["only"])

    def test_no_reader_ever_counts_a_half_finished_swap(self):
        """The same thing again, under threads.

        Asserted as "never anything but 1 or 400" rather than "saw both": how
        often the reader runs during either phase is the scheduler's business,
        and a test that demands it observe both sides fails on a quiet
        machine for no reason.
        """
        wide = [self.Fake(f"s{n}") for n in range(400)]
        narrow = [self.Fake("only")]
        current = {"logs": wide}
        hub = self._hub(current)

        seen, stop = [], threading.Event()

        def read():
            while not stop.is_set():
                seen.append(len(hub.log_sources))

        reader = threading.Thread(target=read)
        reader.start()
        try:
            for turn in range(400):
                current["logs"] = narrow if turn % 2 else wide
                hub.reload()
        finally:
            stop.set()
            reader.join()

        self.assertTrue(seen, "the reader never ran")
        self.assertLessEqual(set(seen), {1, 400},
                             f"a partial swap was visible: "
                             f"{sorted(set(seen) - {1, 400})}")


if __name__ == "__main__":
    unittest.main()


class TheAlertProcessCatchesUpTooTest(LiveSourceTestCase):
    """`python -m wdash.alerts` builds an app, takes its hub, and loops.

    It is the process most exposed to this: it is started once and left
    running for weeks, so before the hub could refresh itself, a monitor
    source added on the configuration page was invisible to every rule until
    somebody remembered to restart the evaluator as well. Nothing said so —
    the rules ran, found nothing, and reported nothing.
    """

    def test_a_runner_started_first_sees_a_source_added_later(self):
        from wdash.alerts.runner import AlertRunner

        evaluator = self.worker()
        runner = AlertRunner(evaluator.store, evaluator.hub)
        self.assertEqual([s.name for s in runner._hub.monitor_sources],
                         ["wdash-agents"])

        self.save("es-monitors", url="http://localhost:9200",
                  kind="elasticsearch", signals=("monitors",))
        self.age(evaluator)

        # The same runner object, holding the same hub it was given.
        self.assertIn("es-monitors",
                      [s.name for s in runner._hub.monitor_sources])
