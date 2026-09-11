"""
`python -m tests.run`, the suite on every core, and the decisions it makes.

What it gets wrong, it gets wrong quietly: a class it does not recognise is
a class it never runs, and a green line that ran fewer tests than there are
reads exactly like one that ran them all. So what it splits, how it reads a
module, and what it does when a split loses tests are pinned here.
"""

import os
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import run  # noqa: E402

MODULE = textwrap.dedent("""
    import unittest

    class BaseTestCase(unittest.TestCase):
        def helper(self):
            pass

    class FirstTest(BaseTestCase):
        def test_one(self):
            pass
        def test_two(self):
            pass

    class ReusedTest(FirstTest):
        pass

    class _FakePage:
        def test_like_but_not_a_test(self):
            pass

    def test_module_level():
        pass
""")


class ReadingAModuleTest(unittest.TestCase):
    def test_classes_with_tests_and_classes_that_inherit_them(self):
        found = run.classes_in(MODULE)
        self.assertEqual(found["FirstTest"], ["test_one", "test_two"])
        self.assertIsNone(found["ReusedTest"], "an inherited class is split by class, never by test")
        self.assertNotIn("BaseTestCase", found)

    def test_a_helper_with_a_test_like_method_is_still_found(self):
        """Found, so run: a unittest run of a class that is not a TestCase
        fails loudly, where one never run would pass in silence."""
        self.assertIn("_FakePage", run.classes_in(MODULE))

    def test_every_real_module_can_be_read(self):
        for module in run.modules():
            with self.subTest(module=module):
                run.classes(module)


class SplittingTest(unittest.TestCase):
    def setUp(self):
        self.original = run.classes
        run.classes = lambda module: run.classes_in(MODULE)

    def tearDown(self):
        run.classes = self.original

    def test_a_quick_module_is_run_whole(self):
        self.assertEqual(run.units("m", {"m": 3}, target=10), ["m"])

    def test_a_slow_module_is_run_a_class_at_a_time(self):
        self.assertEqual(run.units("m", {"m": 30}, target=10),
                         ["m.FirstTest", "m.ReusedTest", "m._FakePage"])

    def test_a_class_is_split_only_on_its_own_measured_time(self):
        """Every class of a slow module was split into its tests on the
        module's time, and a run of 269 processes spent what it saved
        starting them."""
        units = run.units("m", {"m": 30, "m.FirstTest": 12}, target=10)
        self.assertIn("m.FirstTest.test_one", units)
        self.assertIn("m.ReusedTest", units)
        self.assertEqual(run.units("m", {"m": 30}, target=10)[0], "m.FirstTest")

    def test_an_inheriting_class_is_never_split_into_tests(self):
        units = run.units("m", {"m": 30, "m.ReusedTest": 50}, target=10)
        self.assertIn("m.ReusedTest", units)
        self.assertNotIn("m.ReusedTest.test_one", units)


class ReadingAnOutcomeTest(unittest.TestCase):
    def test_a_unit_that_fails_says_so(self):
        outcome = run.run_one("test_run.ReadingAModuleTest")
        self.assertEqual(outcome["code"], 0)
        self.assertGreater(outcome["ran"], 0)

    def test_the_counts_are_read_from_the_verdict(self):
        verdict = run._VERDICT.findall("Ran 5 tests in 0.1s\n\nFAILED (failures=1, skipped=2)\n")
        self.assertEqual(verdict, [("FAILED", "failures=1, skipped=2")])


class LostTestsTest(unittest.TestCase):
    """A split module has to run as many tests as it did whole."""

    def test_a_split_that_ran_fewer_fails_the_run(self):
        import contextlib
        import io
        import json
        import tempfile
        timings = os.path.join(tempfile.mkdtemp(), "timings.json")
        with open(timings, "w") as handle:
            json.dump({"m": 30, "counts": {"m": 10}}, handle)
        saved = (run.TIMINGS, run.modules, run.units, run.run_one)
        run.TIMINGS = timings
        run.modules = lambda wanted=(): ["m"]
        run.units = lambda module, timings, target: ["m.A", "m.B"]
        run.run_one = lambda unit: {"unit": unit, "module": "m", "code": 0,
                                    "ran": 4, "counts": {}, "seconds": 1.0,
                                    "output": ""}
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                code = run.main(["-j", "2"])
        finally:
            run.TIMINGS, run.modules, run.units, run.run_one = saved
        self.assertEqual(code, 1)
        self.assertIn("SPLIT LOST TESTS: m ran 8 of 10", out.getvalue())


class TheSuiteStaysQuickTest(unittest.TestCase):
    def test_a_test_server_stops_when_it_is_told_to(self):
        import time
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from tests.support import serve_in_background
        server = serve_in_background(HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler))
        time.sleep(0.05)
        started = time.monotonic()
        server.shutdown()
        server.server_close()
        self.assertLess(time.monotonic() - started, 0.2)

    def test_a_test_server_is_started_to_stop_at_once(self):
        """`serve_forever` looks for a request to stop every half second by
        default, and `shutdown()` waits for it to look: a server started per
        test cost every test half a second, forty-five of a two-and-a-half
        minute suite. tests/support.py starts them to stop at once."""
        here = os.path.dirname(__file__)
        offenders = []
        for name in sorted(os.listdir(here)):
            # support.py is where it is done right; this file names it.
            if not name.endswith(".py") or name in ("support.py", "test_run.py"):
                continue
            with open(os.path.join(here, name)) as handle:
                for number, line in enumerate(handle, start=1):
                    code = line.split("#")[0]
                    if "serve_forever" in code and "poll_interval" not in code:
                        offenders.append(f"{name}:{number}")
        self.assertEqual(offenders, [], "use tests.support.serve_in_background")


if __name__ == "__main__":
    unittest.main()
