"""
The guard the lab-backed tests stand on.

Three modules measure WDash against real servers, and each one asks about a
window. They used to guard on whether the backend answered a ping. On
2026-09-20 the lab was up, healthy, holding 151,500 log documents and seven
days old; every window in those tests is twenty-four hours. Fourteen tests
failed on an untouched tree and what they said was that the adapters
returned nothing.

`tests/lab.py` asks the question those tests actually depend on — does this
backend hold anything in the window — of the backend itself, over its own
API, never through the adapter under test. That last part is the whole
point: an adapter that returns nothing while the backend holds records is
the failure those tests exist to catch, and it must not be able to hide
behind the sentence that means "go and seed the lab".

This file checks the guard, because a guard that always says yes is worse
than none: every test behind it would go on passing while measuring
nothing. It also holds `WDASH_REQUIRE_LAB=1` to its promise.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests import lab  # noqa: E402

#: Nothing listens here. Used rather than a fake, so what is measured is the
#: helper's own behaviour when a connection is refused.
CLOSED = "http://127.0.0.1:1"

LIVE = {kind: lab.volume(kind) for kind in lab.BACKENDS}
ANY_LIVE = [kind for kind, held in LIVE.items() if held is not None]


class WhatItAnswersWhenNothingIsThereTest(unittest.TestCase):
    """The three answers have to stay apart: unreachable, empty, and held."""

    def test_an_unreachable_backend_is_not_an_empty_one(self):
        """None, not 0. Telling somebody to seed a Loki that is not running
        wastes their afternoon, and `why_not` says which it is."""
        with mock.patch.object(lab, "LOKI", CLOSED), \
                mock.patch.dict(lab.BACKENDS, {"loki": (CLOSED, "loki")}):
            self.assertIsNone(lab.volume("loki"))
            reason = lab.why_not("loki")
        self.assertIn("not running", reason)
        self.assertIn("./lab.sh up loki", reason)
        self.assertNotIn("seed", reason)

    def test_an_empty_backend_is_named_with_the_command_that_fills_it(self):
        with mock.patch.object(lab, "volume", return_value=0):
            reason = lab.why_not("tempo")
        self.assertIn("nothing in the last 24 hours", reason)
        self.assertIn("./lab.sh seed tempo", reason)

    def test_every_backend_that_is_short_is_named_once(self):
        with mock.patch.object(lab, "volume", return_value=0):
            reason = lab.why_not("es-logs", "es-traces", "loki")
        self.assertIn("es-logs", reason)
        self.assertIn("loki", reason)
        # Both Elasticsearch signals come from one seeder, and a command
        # that says `elasticsearch elasticsearch` reads as a bug.
        self.assertEqual(reason.count("elasticsearch"), 1, reason)

    def test_ready_is_the_same_answer_in_two_pieces(self):
        with mock.patch.object(lab, "volume", return_value=0):
            ok, reason = lab.ready("loki")
        self.assertFalse(ok)
        self.assertTrue(reason)

        with mock.patch.object(lab, "volume", return_value=7):
            ok, reason = lab.ready("loki")
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_a_backend_nobody_defined_is_a_mistake_rather_than_a_skip(self):
        """A typo in a guard would otherwise switch its tests off silently."""
        with self.assertRaises(ValueError):
            lab.volume("quickwit")


@unittest.skipUnless(ANY_LIVE, "no lab backend is running")
class WhatItAnswersAgainstTheRunningLabTest(unittest.TestCase):
    """Asked of whatever is actually up. Nothing here needs data: these are
    about the shape of the answer, not its size."""

    def test_the_window_is_honoured(self):
        """The one property that makes this a guard about data rather than
        about ports. A count that ignored the window would report the lab's
        whole history and call a week-old lab ready — which is the fault
        this file exists for, wearing the guard's own clothes.

        Strictly less, not "no more than": every one of these backends can
        be asked over all of time, and such an answer passes a `<=` while
        being exactly the wrong number.
        """
        asked = 0
        for kind in ANY_LIVE:
            day = lab.volume(kind, hours=24)
            if day is None or day < 10:
                continue  # nothing here to tell two windows apart with
            asked += 1
            with self.subTest(backend=kind):
                second = lab.volume(kind, hours=1 / 3600)
                self.assertIsNotNone(second)
                self.assertLess(
                    second, day,
                    f"{kind} answers one second and twenty-four hours with "
                    f"the same number, so it is not reading the window")
        if not asked:
            self.skipTest("no backend holds enough to tell two windows apart")

    def test_a_query_that_fails_is_not_an_empty_backend(self):
        """The half the port probe cannot see. A backend that accepts the
        connection and then refuses the query — a 500, a body that is not
        what it should be, a timeout — has not said it is empty, and
        reporting it as empty would send somebody to seed a server that is
        busy failing."""
        with mock.patch.object(lab.requests, "get",
                               side_effect=RuntimeError("boom")), \
                mock.patch.object(lab.requests, "post",
                                  side_effect=RuntimeError("boom")), \
                mock.patch.object(lab, "reachable", return_value=True):
            for kind in lab.BACKENDS:
                with self.subTest(backend=kind):
                    self.assertIsNone(lab.volume(kind))

    def test_what_is_held_is_a_number(self):
        for kind in ANY_LIVE:
            with self.subTest(backend=kind):
                self.assertIsInstance(LIVE[kind], int)
                self.assertGreaterEqual(LIVE[kind], 0)


class ThePromisedLabIsSeededTest(unittest.TestCase):
    """A job that promised a lab must not keep the promise by skipping.

    Every guard in the three lab-backed modules is a skip when the lab is
    short. That is right on a laptop and wrong in CI, where the whole reason
    the job exists is to measure against real servers — so under
    WDASH_REQUIRE_LAB=1 the same shortfall is a failure, once, here, with
    the command in it.
    """

    def setUp(self):
        # Asked here rather than in a decorator, which is evaluated at
        # import and cannot then be driven by the test below that proves
        # this class fails rather than skips.
        if not lab.REQUIRED:
            self.skipTest("only where a job promised a lab: "
                          "WDASH_REQUIRE_LAB names the backends")

    def test_a_promised_name_is_a_backend_that_exists(self):
        """A typo in a workflow otherwise promises nothing, silently, on the
        one variable whose whole job is to stop a promise being kept by
        skipping. Carried to here rather than raised at import: this module
        is imported by most of the suite."""
        self.assertEqual(sorted(lab.PROMISED_BUT_UNKNOWN), [],
                         f"WDASH_REQUIRE_LAB names something that is not a "
                         f"lab backend; the backends are "
                         f"{sorted(lab.BACKENDS)}")

    def test_every_promised_backend_is_up_and_holds_something(self):
        """The promise, asked of exactly what was promised.

        It used to ask about whatever happened to be RUNNING, which is a
        different claim and a weaker one: a job that started an
        Elasticsearch and promised the world passed this as long as the
        Elasticsearch was seeded. Now a job names its backends and this
        holds it to those, so a promised backend that never came up is a
        failure here rather than nine errors in three other modules.
        """
        self.assertTrue(lab.PROMISED, "the promise names no backend")
        reason = lab.why_not(*sorted(lab.PROMISED), hours=24)
        self.assertIsNone(reason, reason)


class TheModulesThatStandOnItTest(unittest.TestCase):
    """The claim the whole change makes, asked of the modules making it.

    A guard is only worth what the tests behind it do when it says no, and
    the state that matters — a lab that is up and holds nothing in the
    window — is not the state this run is in. So one module is run against
    exactly that, in a process of its own, with the backend counts forced to
    zero.
    """

    #: Every module whose guard comes from `tests/lab.py`, and how many of
    #: its tests that guard covers.
    #:
    #: The number is the point. Without it, a module whose guard went back
    #: to a port probe still reports "something was skipped" — its other
    #: guard — while the tests behind the broken one run against whatever
    #: the lab happens to hold. What that number means is "tests that ask a
    #: backend a question"; a new one changes it, and changing it here is
    #: how somebody says they know.
    STANDING = {"tests.test_dashboard_tables": 3,
                "tests.test_group_by_fields_lab": 11,
                "tests.test_dashboard_number_and_alerts": 2}

    def against_an_empty_lab(self, *names):
        """Those modules, in a process of their own, with every backend UP
        and answering zero. Not in this one: their guards are module-level,
        so importing them here would fix the answer for the rest of the run.

        Both halves are patched, and the missing half is what took the first
        CI run red. `_count` alone only reaches the empty branch on a
        machine where the lab is actually running: `volume` asks `reachable`
        first and returns None — "not running" — before `_count` is ever
        called. On this developer's machine the lab is always up, so the
        simulation matched its name; on a runner with nothing listening it
        produced the OTHER state, and the assertion below about `./lab.sh
        seed` met a sentence about `./lab.sh up`. The state that is not
        simulated here is the one `WhatItAnswersWhenNothingIsThereTest`
        above covers, against a closed port.
        """
        import subprocess
        code = (
            "import sys, unittest; sys.path.insert(0, '.');"
            "from unittest import mock; from tests import lab;"
            "mock.patch.object(lab, 'reachable', return_value=True).start();"
            "p = mock.patch.object(lab, '_count', return_value=0); p.start();"
            f"s = unittest.TestLoader().loadTestsFromNames({list(names)!r});"
            "r = unittest.TextTestRunner(verbosity=0, "
            "stream=open('/dev/null', 'w')).run(s);"
            "print(len(r.failures), len(r.errors), len(r.skipped), "
            "r.skipped[0][1].replace(chr(10), ' ') if r.skipped else '')")
        # Without the promise, whatever this run was started with. The
        # question here is what those modules do on a LAPTOP whose lab is
        # empty — they skip — and under an inherited WDASH_REQUIRE_LAB the
        # same shortfall is a failure by design, which is the other half of
        # the guard and `ThePromisedLabIsSeededTest`'s subject, not this
        # one's. Inherited, it turned this into a failure inside the very
        # job that promises a lab.
        environment = dict(os.environ)
        environment.pop("WDASH_REQUIRE_LAB", None)
        done = subprocess.run([sys.executable, "-c", code], text=True,
                              capture_output=True, env=environment,
                              cwd=os.path.join(os.path.dirname(__file__), ".."),
                              timeout=600)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        failures, errors, skipped, reason = done.stdout.strip().split(" ", 3)
        return int(failures), int(errors), int(skipped), reason

    def test_an_empty_lab_is_a_skip_with_the_command_in_it(self):
        """Measured before this guard existed, on a lab seven days old:
        fourteen failures across these three, all of them saying the
        adapters answered nothing.

        Every module, not a sample. A guard is per-module and the one that
        was left behind is the one nobody would look at again.
        """
        for name, guarded in self.STANDING.items():
            with self.subTest(module=name):
                failures, errors, skipped, reason = self.against_an_empty_lab(name)
                self.assertEqual((failures, errors), (0, 0),
                                 f"{name} still reads an empty lab as a "
                                 f"broken adapter")
                self.assertEqual(skipped, guarded,
                                 f"{name} guards {skipped} of its tests on "
                                 f"the lab holding data, and this file "
                                 f"expects {guarded}")
                self.assertIn("./lab.sh seed", reason)

    def test_a_lab_with_data_in_it_is_not_skipped_away(self):
        """The other direction, and what keeps this a guard rather than a
        switch. A guard that always says no would pass every test above —
        and would quietly delete three modules' worth of measurement.

        Compared rather than counted: a module may have a skip of its own
        for a reason that has nothing to do with the lab, and pinning an
        exact number here would make adding one somebody else's failure.
        """
        if not ANY_LIVE:
            self.skipTest("no lab backend is running")
        name = "tests.test_group_by_fields_lab"
        empty_skips = self.STANDING[name]
        live = unittest.TextTestRunner(
            verbosity=0, stream=open(os.devnull, "w")).run(
                unittest.TestLoader().loadTestsFromName(name))
        self.assertLess(len(live.skipped), empty_skips,
                        "the lab holds data and the guard skipped anyway")
        self.assertEqual(len(live.failures), 0, live.failures)


class ThePromiseIsKeptLoudlyTest(unittest.TestCase):
    """That the class above FAILS rather than skips.

    It is the one test here whose whole value is in which way it goes when
    things are wrong, and every other check in this file is a skip when the
    lab is short — so without this, switching the promise off would look
    exactly like a laptop with no lab on it.
    """

    def run_promise(self, promised, held):
        suite = unittest.TestLoader().loadTestsFromTestCase(
            ThePromisedLabIsSeededTest)
        with mock.patch.object(lab, "PROMISED", frozenset(promised)), \
                mock.patch.object(lab, "REQUIRED", bool(promised)), \
                mock.patch.object(lab, "volume",
                                  side_effect=lambda kind, hours=24: held):
            return unittest.TextTestRunner(
                verbosity=0, stream=open(os.devnull, "w")).run(suite)

    def test_a_promised_lab_that_is_empty_fails(self):
        result = self.run_promise(promised=["loki"], held=0)
        self.assertEqual(len(result.failures), 1, "it skipped, or it passed")
        self.assertIn("./lab.sh seed", result.failures[0][1])

    def test_a_promised_lab_that_is_seeded_passes(self):
        result = self.run_promise(promised=["loki"], held=7)
        self.assertEqual((len(result.failures), len(result.errors)), (0, 0))

    def test_a_backend_nobody_promised_is_not_held_to_the_promise(self):
        """The fault the first CI run found, from the other side. The
        live-schema job starts an Elasticsearch; under the old flag it
        promised every backend, and a Loki that was never going to be there
        failed it. Promising `loki` and nothing else must say nothing about
        the Elasticsearch, and vice versa."""
        held = {"loki": 7}
        suite = unittest.TestLoader().loadTestsFromTestCase(
            ThePromisedLabIsSeededTest)
        with mock.patch.object(lab, "PROMISED", frozenset({"loki"})), \
                mock.patch.object(lab, "REQUIRED", True), \
                mock.patch.object(
                    lab, "volume",
                    side_effect=lambda kind, hours=24: held.get(kind)):
            result = unittest.TextTestRunner(
                verbosity=0, stream=open(os.devnull, "w")).run(suite)
        self.assertEqual((len(result.failures), len(result.errors)), (0, 0),
                         result.failures + result.errors)

    def test_the_promise_is_read_from_the_environment(self):
        """How a job makes it. Read at import, so this reloads rather than
        trusting the constant."""
        import importlib
        for value, expected in (("1", frozenset(lab.BACKENDS)),
                                ("all", frozenset(lab.BACKENDS)),
                                ("es-logs,es-traces",
                                 frozenset({"es-logs", "es-traces"})),
                                ("loki", frozenset({"loki"})),
                                ("0", frozenset()),
                                ("", frozenset())):
            with self.subTest(value=value), \
                    mock.patch.dict(os.environ,
                                    {"WDASH_REQUIRE_LAB": value}):
                reloaded = importlib.reload(lab)
                self.assertEqual(reloaded.PROMISED, expected)
                self.assertEqual(reloaded.REQUIRED, bool(expected))
        importlib.reload(lab)

    def test_a_name_that_is_not_a_backend_is_carried_not_swallowed(self):
        """It has to reach a test. Dropped quietly, a workflow that means
        `es-logs` and says `es_logs` promises nothing and reports
        success."""
        import importlib
        with mock.patch.dict(os.environ,
                             {"WDASH_REQUIRE_LAB": "es_logs,loki"}):
            reloaded = importlib.reload(lab)
            self.assertEqual(reloaded.PROMISED, frozenset({"loki"}))
            self.assertEqual(reloaded.PROMISED_BUT_UNKNOWN,
                             frozenset({"es_logs"}))
            self.assertTrue(reloaded.REQUIRED)
        importlib.reload(lab)

    def test_without_the_promise_it_is_a_skip(self):
        """On a laptop with no lab, this file says nothing.

        Every test in that class, counted against how many it has rather
        than against a number written here: pinning one would make adding a
        check to it somebody else's failure.
        """
        result = self.run_promise(promised=[], held=0)
        self.assertEqual(len(result.skipped), result.testsRun)
        self.assertEqual((len(result.failures), len(result.errors)), (0, 0))


if __name__ == "__main__":
    unittest.main()
