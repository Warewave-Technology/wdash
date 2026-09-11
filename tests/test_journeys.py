"""
Browser journeys: the step language, and running one.

Split deliberately. Most of what can go wrong is decidable without a browser —
which step is blamed, what is skipped, what a sentence says — and those tests
run in milliseconds against a fake page. Three things are NOT decidable that
way, and they are the ones that bite:

  * Playwright's own error text. It carries the arguments of the call, and for
    a sign-in journey one of those arguments is the password. A fake page
    raises whatever the test told it to, which proves nothing about redaction.
  * The screenshot. A fake returns whatever bytes the test chose; only a real
    browser proves the capture works and that the result is a JPEG somebody
    can open.
  * That a click which navigates is waited for. Every timing in the product
    depends on it.

So those run against real Chromium, against a real HTTP server with a real
login form.
"""

import base64
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.agent.browser import _clean, run_journey
from wdash.hub.models import (
    JourneyRun, STEP_FAILED, STEP_PASSED, STEP_SKIPPED, StepResult,
)
from wdash.journeys import (
    MAX_STEPS, StepError, describe, parse, resolve, secret_names,
)

PASSWORD = "correct-horse-battery-staple"


# ---------------------------------------------------------------------------
# The language
# ---------------------------------------------------------------------------

class StepLanguageTest(unittest.TestCase):
    def test_a_journey_has_to_open_a_page_first(self):
        """Without this the first step runs against `about:blank` and the
        failure is "element not found" — which sends somebody to check their
        selector when the journey never opened a page."""
        with self.assertRaises(StepError) as caught:
            parse([{"kind": "click", "selector": "#go"}])
        self.assertIn("start by going to a URL", str(caught.exception))

    def test_a_journey_has_to_assert_something(self):
        """A sequence of clicks passes as long as the browser did not crash.
        That is a check reporting success for a site serving an error page,
        which is worse than no check at all."""
        with self.assertRaises(StepError) as caught:
            parse([{"kind": "goto", "value": "https://x.example"},
                   {"kind": "click", "selector": "#go"}])
        self.assertIn("at least one expectation", str(caught.exception))

    def test_a_journey_cannot_open_a_local_file(self):
        """`file:///etc/passwd` in a browser on the probe, rendered, and
        screenshotted back into the database.

        Written with the rest of the journey VALID. The first version was a
        single `goto`, which also breaks the "needs an expectation" rule — so
        it passed with the scheme guard deleted and proved nothing.
        """
        with self.assertRaises(StepError) as caught:
            parse([{"kind": "goto", "value": "file:///etc/passwd"},
                   {"kind": "expect_text", "value": "root"}])
        self.assertIn("http://", str(caught.exception))

    def test_it_refuses_a_verb_it_does_not_have(self):
        with self.assertRaises(StepError) as caught:
            parse([{"kind": "goto", "value": "https://x.example"},
                   {"kind": "eval", "value": "fetch('/admin/delete')"}])
        self.assertIn("not something a journey can do", str(caught.exception))

    def test_it_names_the_step_that_is_wrong(self):
        """"needs an element to act on" without a number means reading the
        whole list to find which one."""
        with self.assertRaises(StepError) as caught:
            parse([{"kind": "goto", "value": "https://x.example"},
                   {"kind": "expect_text", "value": "hello"},
                   {"kind": "click"}])
        self.assertIn("Step 3", str(caught.exception))

    def test_it_has_a_ceiling(self):
        steps = [{"kind": "goto", "value": "https://x.example"}]
        steps += [{"kind": "expect_text", "value": "x"}] * MAX_STEPS
        with self.assertRaises(StepError):
            parse(steps)

    def test_a_step_that_takes_no_element_may_not_have_one(self):
        """A selector on `expect_url` is a selector that silently does
        nothing, and somebody wrote it believing it narrowed the check."""
        with self.assertRaises(StepError):
            parse([{"kind": "goto", "value": "https://x.example"},
                   {"kind": "expect_url", "selector": "#main", "value": "/x"}])

    def test_secrets_are_found_in_order(self):
        steps = parse([{"kind": "goto", "value": "https://x.example"},
                       {"kind": "fill", "selector": "#u",
                        "value": "{{ secret.username }}"},
                       {"kind": "fill", "selector": "#p",
                        "value": "{{ secret.password }}"},
                       {"kind": "expect_url", "value": "/home"}])
        self.assertEqual(secret_names(steps), ["username", "password"])

    def test_a_missing_secret_is_named(self):
        """Otherwise the placeholder is typed into the password box verbatim,
        the site says "wrong password", and somebody goes to check the
        account."""
        step = parse([{"kind": "goto", "value": "https://x.example"},
                      {"kind": "fill", "selector": "#p",
                       "value": "{{ secret.pw }}"},
                      {"kind": "expect_url", "value": "/home"}])[1]
        with self.assertRaises(StepError) as caught:
            resolve(step, {})
        self.assertIn("'pw'", str(caught.exception))

    def test_a_description_never_holds_a_secret(self):
        """It cannot: it renders the placeholder, not the resolution."""
        step = parse([{"kind": "goto", "value": "https://x.example"},
                      {"kind": "fill", "selector": "#p",
                       "value": "{{ secret.pw }}"},
                      {"kind": "expect_url", "value": "/home"}])[1]
        self.assertNotIn(PASSWORD, describe(step))
        self.assertIn("{{ secret.pw }}", describe(step))


# ---------------------------------------------------------------------------
# Which step gets blamed
# ---------------------------------------------------------------------------

class _FakePage:
    """A page that fails where the test says and records what it was asked."""

    def __init__(self, fail_at=None, error=None, url="https://x.example/"):
        self.fail_at = fail_at
        self.error = error or RuntimeError("boom")
        self.url = url
        self.calls = []
        self.screenshots = 0

    def _step(self, name, *args):
        self.calls.append((name, args))
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            raise self.error

    def goto(self, url, **kw):
        self._step("goto", url)
        return None

    def click(self, selector, **kw):
        self._step("click", selector)

    def fill(self, selector, value, **kw):
        self._step("fill", selector, value)

    def inner_text(self, selector):
        self._step("inner_text", selector)
        return "hello"

    def wait_for_timeout(self, ms):
        pass

    def screenshot(self, **kw):
        self.screenshots += 1
        return b"\xff\xd8\xff" + b"jpeg-bytes"


class _Launcher:
    def __init__(self, page):
        self.page = page

    def __call__(self):
        return self

    def __enter__(self):
        return self.page

    def __exit__(self, *exc):
        return False


def _journey(steps, fail_at=None, error=None, secrets=None, timeout=30):
    page = _FakePage(fail_at=fail_at, error=error)
    result = run_journey({"id": "m1", "timeout_seconds": timeout,
                          "steps": steps},
                         secrets=secrets, launcher=_Launcher(page))
    return result, page


SIGN_IN = [{"kind": "goto", "value": "https://x.example/login"},
           {"kind": "fill", "selector": "#email", "value": "ops@x.example"},
           {"kind": "fill", "selector": "#password",
            "value": "{{ secret.password }}"},
           {"kind": "click", "selector": "button[type=submit]"},
           {"kind": "expect_text", "value": "hello"}]


class StepBlameTest(unittest.TestCase):
    def test_a_passing_journey_times_every_step(self):
        """The per-step durations ARE the feature. A journey reporting one
        number cannot answer which part got slower."""
        result, _ = _journey(SIGN_IN, secrets={"password": PASSWORD})
        self.assertEqual(result["status"], "up")
        self.assertEqual([s["status"] for s in result["steps"]],
                         [STEP_PASSED] * 5)
        for step in result["steps"]:
            self.assertIsNotNone(step["duration_us"])

    def test_the_steps_after_a_failure_are_skipped_not_failed(self):
        """Step 5 could not find the basket because step 4's sign-in failed.
        Reporting both as failures sends somebody to look in two places."""
        result, _ = _journey(SIGN_IN, fail_at=4,
                             secrets={"password": PASSWORD})
        self.assertEqual([s["status"] for s in result["steps"]],
                         [STEP_PASSED, STEP_PASSED, STEP_PASSED,
                          STEP_FAILED, STEP_SKIPPED])

    def test_nothing_runs_after_the_failure(self):
        """Not just reported as skipped — actually not run. A journey that
        keeps clicking after a failed sign-in is a journey clicking around a
        login page."""
        _, page = _journey(SIGN_IN, fail_at=4, secrets={"password": PASSWORD})
        self.assertEqual(len(page.calls), 4)

    def test_the_failure_names_the_step_and_what_it_was(self):
        result, _ = _journey(SIGN_IN, fail_at=4,
                             secrets={"password": PASSWORD})
        self.assertIn("step 4", result["error"])
        self.assertIn("button[type=submit]", result["error"])

    def test_a_skipped_step_has_no_duration(self):
        """Zero would draw as an instant step on a chart of the journey."""
        result, _ = _journey(SIGN_IN, fail_at=4,
                             secrets={"password": PASSWORD})
        self.assertIsNone(result["steps"][4]["duration_us"])

    def test_a_failure_is_photographed(self):
        result, page = _journey(SIGN_IN, fail_at=4,
                                secrets={"password": PASSWORD})
        self.assertEqual(page.screenshots, 1)
        self.assertIn("screenshot", result)

    def test_a_pass_is_not_photographed(self):
        """A picture a minute of a page that is fine, kept for a week."""
        result, page = _journey(SIGN_IN, secrets={"password": PASSWORD})
        self.assertEqual(page.screenshots, 0)
        self.assertNotIn("screenshot", result)

    def test_an_agent_without_a_browser_says_so(self):
        """Not "step 1 failed", which sends somebody to check a website that
        is fine."""
        def missing():
            raise ImportError("No module named 'playwright'")
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "steps": SIGN_IN}, launcher=missing)
        self.assertEqual(result["status"], "down")
        self.assertIn("no browser", result["error"])
        self.assertEqual([s["status"] for s in result["steps"]],
                         [STEP_SKIPPED] * 5)

    def test_a_browser_that_will_not_start_is_named_as_such(self):
        def broken():
            raise OSError("Failed to launch: /dev/shm too small")
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "steps": SIGN_IN}, launcher=broken)
        self.assertIn("browser could not start", result["error"])

    def test_steps_that_no_longer_parse_report_why(self):
        """A journey stored by an older version. The alternative is one that
        silently never runs and shows as unknown for ever."""
        result, _ = _journey([{"kind": "goto", "value": "https://x.example"}])
        self.assertEqual(result["status"], "down")
        self.assertIn("cannot run", result["error"])

    def test_a_journey_is_never_raised_out_of(self):
        """Same contract as run_check: a journey that could not run is a
        journey that failed, and that IS the measurement."""
        def exploding():
            raise KeyboardInterrupt  # noqa: not caught by `except Exception`
        with self.assertRaises(KeyboardInterrupt):
            run_journey({"id": "m1", "steps": SIGN_IN}, launcher=exploding)
        # Everything short of that is a result.
        for error in (ValueError("x"), OSError("y"), RuntimeError("z")):
            result = run_journey(
                {"id": "m1", "steps": SIGN_IN},
                launcher=lambda e=error: (_ for _ in ()).throw(e))
            self.assertEqual(result["status"], "down")


class RedactionTest(unittest.TestCase):
    """A password must not reach a result row, a history page or an alert."""

    def test_a_secret_in_an_error_is_replaced(self):
        self.assertEqual(_clean(RuntimeError(f"typing {PASSWORD} failed"),
                                [PASSWORD]),
                         "typing *** failed")

    def test_a_secret_inside_a_url_is_replaced(self):
        """A journey can carry a token in a query string, and a failed `goto`
        puts the whole address in the message."""
        cleaned = _clean(
            RuntimeError(f"net::ERR_FAILED at https://x/?token={PASSWORD}"),
            [PASSWORD])
        self.assertNotIn(PASSWORD, cleaned)

    def test_a_timeout_says_what_did_not_happen(self):
        """"Timeout 10000ms exceeded" says nothing about what was waited for,
        and what did not happen differs by step."""
        self.assertEqual(_clean(RuntimeError("Timeout 10000ms exceeded."),
                                [], "goto"),
                         "the page did not load in time")
        self.assertEqual(_clean(RuntimeError("Timeout 10000ms exceeded."),
                                [], "click"),
                         "it was not there in time")

    def test_a_long_error_is_trimmed(self):
        self.assertLessEqual(len(_clean(RuntimeError("x" * 5000), [])), 1000)

    def test_the_result_of_a_failed_sign_in_holds_no_password(self):
        """The whole result, serialised — the shape that goes to the server."""
        result, _ = _journey(
            SIGN_IN, fail_at=4,
            error=RuntimeError(f'fill("#password", "{PASSWORD}") failed'),
            secrets={"password": PASSWORD})
        self.assertNotIn(PASSWORD, json.dumps(result))


class JourneyModelTest(unittest.TestCase):
    def test_it_names_the_step_that_failed(self):
        run = JourneyRun("m1", steps=(
            StepResult(1, "goto", "Go to /login", STEP_PASSED, 900),
            StepResult(2, "click", "Click #go", STEP_FAILED, 40, "not there"),
            StepResult(3, "expect_text", 'Expect text "hi"', STEP_SKIPPED)))
        self.assertEqual(run.failed_step.index, 2)

    def test_completed_counts_what_ran(self):
        run = JourneyRun("m1", steps=(
            StepResult(1, "goto", "", STEP_PASSED, 900),
            StepResult(2, "click", "", STEP_FAILED, 40),
            StepResult(3, "expect_text", "", STEP_SKIPPED)))
        self.assertEqual(run.completed, 2)


# ---------------------------------------------------------------------------
# A real browser, against a real login form
# ---------------------------------------------------------------------------

LOGIN_PAGE = """<html><body><h1>Shop</h1>
<form method=post action=/login>
<input id=email name=email><input id=password name=password type=password>
<button type=submit>Sign in</button></form>%s</body></html>"""

DASHBOARD = """<html><body><h1>Dashboard</h1>
<button class=basket onclick="document.getElementById('b').innerText=
'1 item in your basket'">Add to basket</button><div id=b></div></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/dashboard"):
            return self._send(DASHBOARD)
        if self.path.startswith("/slow"):
            time.sleep(30)          # longer than any budget in these tests
            return self._send("<html><body>eventually</body></html>")
        if self.path.startswith("/late"):
            # Fills itself in after a moment, like most pages.
            return self._send(
                "<html><body><div id=t>Loading</div><script>"
                "setTimeout(function(){document.getElementById('t')"
                ".innerText='Your order is ready'}, 700)</script>"
                "</body></html>")
        if self.path.startswith("/broken"):
            return self._send("<html><body>Something went wrong</body></html>",
                              code=500)
        self._send(LOGIN_PAGE % "")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())
        if form.get("password", [""])[0] == PASSWORD:
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            return self.end_headers()
        self._send(LOGIN_PAGE % "<p class=error>Wrong password</p>")

    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def _chromium_available():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            p.chromium.launch().close()
        return True
    except Exception:
        return False


HAVE_BROWSER = _chromium_available()


@unittest.skipUnless(HAVE_BROWSER,
                     "no Chromium — run `playwright install chromium`")
class RealBrowserTest(unittest.TestCase):
    """The three things a fake page cannot prove.

    Threading, not a fixture process: a single-threaded test server blocks on
    the browser's keep-alive connection, and the first version of this measured
    a 27ms click as 5090ms. Every per-step duration in the product would have
    been read against that.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _steps(self):
        return [{"kind": "goto", "value": self.base + "/"},
                {"kind": "fill", "selector": "#email",
                 "value": "ops@x.example"},
                {"kind": "fill", "selector": "#password",
                 "value": "{{ secret.password }}"},
                {"kind": "click", "selector": "button[type=submit]"},
                {"kind": "expect_url", "value": "/dashboard"},
                {"kind": "click", "selector": ".basket"},
                {"kind": "expect_text", "value": "1 item in your basket"}]

    def _run(self, password, steps=None, timeout=60):
        return run_journey({"id": "m1", "timeout_seconds": timeout,
                            "steps": steps or self._steps()},
                           secrets={"password": password})

    def test_a_real_sign_in_passes(self):
        result = self._run(PASSWORD)
        self.assertEqual(result["status"], "up", result["error"])
        self.assertEqual([s["status"] for s in result["steps"]],
                         [STEP_PASSED] * 7)

    def test_a_click_that_navigates_is_waited_for(self):
        """Step 5 checks the address. If the click returned before the
        redirect had happened it would read /login, and every journey with a
        sign-in in it would fail."""
        result = self._run(PASSWORD)
        self.assertEqual(result["steps"][4]["status"], STEP_PASSED)

    def test_a_real_failure_names_the_step_and_the_addresses(self):
        result = self._run("wrong-password")
        self.assertEqual(result["status"], "down")
        self.assertEqual(result["steps"][4]["status"], STEP_FAILED)
        self.assertIn("/dashboard", result["error"])

    def test_playwrights_own_error_text_is_redacted(self):
        """The reason this class exists. Playwright's messages carry the
        arguments of the call, and one of those is the password."""
        steps = [{"kind": "goto", "value": self.base + "/"},
                 {"kind": "fill", "selector": "#nonexistent",
                  "value": "{{ secret.password }}"},
                 {"kind": "expect_text", "value": "Shop"}]
        result = self._run(PASSWORD, steps=steps, timeout=8)
        self.assertEqual(result["status"], "down")
        self.assertNotIn(PASSWORD, json.dumps(result))

    def test_a_secret_in_a_url_survives_a_real_navigation_failure(self):
        steps = [{"kind": "goto",
                  "value": "http://127.0.0.1:9/?token={{ secret.password }}"},
                 {"kind": "expect_text", "value": "anything"}]
        result = self._run(PASSWORD, steps=steps, timeout=8)
        self.assertNotIn(PASSWORD, json.dumps(result))

    def test_the_screenshot_is_a_jpeg_somebody_can_open(self):
        result = self._run("wrong-password")
        image = base64.b64decode(result["screenshot"]["base64"])
        # JPEG magic. A file the browser wrote and a viewer will accept.
        self.assertEqual(image[:3], b"\xff\xd8\xff")
        self.assertGreater(len(image), 1000)
        self.assertEqual(result["screenshot"]["content_type"], "image/jpeg")

    def test_expect_text_fails_when_the_text_is_not_there(self):
        """The assertion has to be able to FAIL. Without this, deleting the
        check entirely leaves every test green — every other journey here
        expects text that is present."""
        steps = [{"kind": "goto", "value": self.base + "/"},
                 {"kind": "expect_text", "value": "Order confirmed"}]
        result = run_journey({"id": "m1", "timeout_seconds": 5,
                              "steps": steps}, secrets={})
        self.assertEqual(result["status"], "down")
        self.assertIn("does not contain", result["error"])
        self.assertIn("Order confirmed", result["error"])

    def test_a_journey_stops_at_its_own_timeout(self):
        """The monitor's timeout bounds the WHOLE journey, and each step is
        capped by what is left of it. Without that a seven-step journey with a
        ten-second step timeout can run for seventy seconds while its monitor
        says sixty — and the agent starts the next run on top of it."""
        steps = [{"kind": "goto", "value": self.base + "/slow"},
                 {"kind": "expect_text", "value": "eventually"}]
        clock = time.monotonic()
        result = run_journey({"id": "m1", "timeout_seconds": 3,
                              "steps": steps}, secrets={})
        elapsed = time.monotonic() - clock
        self.assertEqual(result["status"], "down")
        # Comfortably under the step's own 10s default, which is what it would
        # have waited if the remaining budget were not applied.
        self.assertLess(elapsed, 8, f"took {elapsed:.1f}s")
        self.assertLess(result["duration_us"], 8_000_000)

    def test_it_waits_for_text_that_arrives_after_the_page(self):
        """Most pages fill themselves in after load. An assertion taken the
        instant the step begins fails on every one of them, and the journey
        blames the site."""
        steps = [{"kind": "goto", "value": self.base + "/late"},
                 {"kind": "expect_text", "value": "Your order is ready"}]
        result = run_journey({"id": "m1", "timeout_seconds": 10,
                              "steps": steps}, secrets={})
        self.assertEqual(result["status"], "up", result["error"])
        # And it did wait — a step that returned immediately would not have.
        self.assertGreater(result["steps"][1]["duration_us"], 300_000)

    def test_a_page_that_errors_fails_at_the_step_that_opened_it(self):
        """A journey whose first page 500s should say so, not spend the rest
        of its steps failing to find selectors on an error page."""
        steps = [{"kind": "goto", "value": self.base + "/broken"},
                 {"kind": "click", "selector": ".basket"},
                 {"kind": "expect_text", "value": "1 item in your basket"}]
        result = run_journey({"id": "m1", "timeout_seconds": 10,
                              "steps": steps}, secrets={})
        self.assertEqual(result["status"], "down")
        self.assertIn("answered 500", result["error"])
        self.assertEqual(result["steps"][0]["status"], STEP_FAILED)
        self.assertEqual([s["status"] for s in result["steps"][1:]],
                         [STEP_SKIPPED, STEP_SKIPPED])

    def test_expect_no_text_catches_the_error_banner(self):
        """A journey can reach the right page and still have failed."""
        steps = [{"kind": "goto", "value": self.base + "/"},
                 {"kind": "fill", "selector": "#password", "value": "nope"},
                 {"kind": "click", "selector": "button[type=submit]"},
                 {"kind": "expect_no_text", "value": "Wrong password"}]
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "steps": steps}, secrets={})
        self.assertEqual(result["status"], "down")
        self.assertIn("and should not", result["error"])


class BrowserSuiteIsNotSilentlySkippedTest(unittest.TestCase):
    """A skipped suite reads as a passing one.

    Playwright installed without its browsers is the normal broken state — the
    pip package is 3MB, the browser is 150MB and a separate command. In that
    state every test above disappears and the run still says OK.
    """

    def test_playwright_installed_means_chromium_installed(self):
        try:
            import playwright  # noqa: F401
        except ImportError:
            self.skipTest("playwright is not installed at all")
        self.assertTrue(
            HAVE_BROWSER,
            "playwright is installed but Chromium is not, so every browser "
            "test skipped. Run `playwright install chromium`.")


# ---------------------------------------------------------------------------
# Defining one, and reading the result
# ---------------------------------------------------------------------------

class JourneyPageTest(unittest.TestCase):
    """Creating a journey from the configuration page and reading its run."""

    STEPS = [{"kind": "goto", "value": "https://shop.example/login"},
             {"kind": "fill", "selector": "#email",
              "value": "ops@shop.example"},
             {"kind": "fill", "selector": "#password",
              "value": "{{ secret.password }}"},
             {"kind": "click", "selector": "button[type=submit]"},
             {"kind": "expect_url", "value": "/dashboard"}]

    def setUp(self):
        import tempfile
        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "journeys"
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
                "id": "u1", "username": "admin", "email": "a@b", "groups": [],
                "role": "admin",
                "permissions": ["system:admin", "monitors:read"],
                "allowed_indices": ["*"]}
            session["_user_id"] = "u1"

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _save(self, steps=None, **extra):
        data = {"name": "Sign in", "kind": "browser",
                "steps": json.dumps(self.STEPS if steps is None else steps),
                "interval_seconds": "300", "timeout_seconds": "60",
                "journey_secret_password": "hunter2"}
        data.update(extra)
        return self.client.post("/admin/monitors", data=data,
                                follow_redirects=True)

    def _journey(self):
        return self.app.store.monitors.all()[0]

    # ---------- defining ----------

    def test_the_address_comes_from_the_first_step(self):
        """Not asked for twice. A form with a URL box and a `goto` step has
        two answers to one question, and they drift the first time somebody
        edits one of them."""
        self._save()
        self.assertEqual(self._journey()["target"],
                         "https://shop.example/login")

    def test_the_secret_is_stored_and_never_shown_again(self):
        self._save()
        journey = self._journey()
        self.assertTrue(journey["has_credentials"])
        self.assertEqual(journey["secret_names"], ["password"])
        self.assertNotIn("hunter2", json.dumps(journey, default=str))
        page = self.client.get("/admin/config").get_data(as_text=True)
        self.assertNotIn("hunter2", page)

    def test_the_step_that_uses_the_secret_still_shows_the_placeholder(self):
        """`{{ secret.password }}` is not a password, and blanking it would
        make the step unreadable."""
        self._save()
        values = [s.get("value") for s in self._journey()["steps"]]
        self.assertIn("{{ secret.password }}", values)

    def test_a_journey_with_no_steps_is_refused(self):
        response = self._save(steps=[])
        self.assertIn("at least one step", response.get_data(as_text=True))
        self.assertEqual(self.app.store.monitors.all(), [])

    def test_a_secret_with_no_box_filled_in_is_refused(self):
        """Otherwise the journey saves, runs, and fails on a sign-in that was
        never given a password."""
        response = self._save(journey_secret_password="")
        self.assertIn("no such secret", response.get_data(as_text=True))

    def test_editing_without_retyping_keeps_the_password(self):
        """The same contract the source form uses. An empty box that wipes the
        stored credential means every edit of the interval breaks the login."""
        self._save()
        journey = self._journey()
        self.client.post("/admin/monitors",
                         data={"id": journey["id"], "name": "Sign in",
                               "kind": "browser",
                               "steps": json.dumps(self.STEPS),
                               "interval_seconds": "600",
                               "timeout_seconds": "60",
                               "journey_secret_password": ""},
                         follow_redirects=True)
        self.assertEqual(
            self.app.store.monitors.credentials(journey["id"]),
            {"password": "hunter2"})

    def test_a_secret_whose_step_was_deleted_is_dropped(self):
        """A credential kept for a step nobody uses is a credential nobody
        knows is there — it survives every audit of "what does this journey
        touch", because the steps no longer mention it."""
        self._save()
        journey = self._journey()
        without = [step for step in self.STEPS
                   if "secret" not in str(step.get("value", ""))]
        self.client.post("/admin/monitors",
                         data={"id": journey["id"], "name": "Sign in",
                               "kind": "browser",
                               "steps": json.dumps(without),
                               "interval_seconds": "300",
                               "timeout_seconds": "60"},
                         follow_redirects=True)
        self.assertEqual(
            self.app.store.monitors.credentials(journey["id"]), {})
        self.assertEqual(self._journey()["secret_names"], [])

    def test_the_editor_offers_exactly_the_verbs_the_server_validates(self):
        """A form offering a verb the validator does not have produces an
        error on save; a validator with a verb the form does not offer is a
        feature nobody can reach."""
        from wdash.journeys.steps import STEP_KINDS
        page = self.client.get("/admin/config").get_data(as_text=True)
        self.assertIn('id="stepKinds"', page)
        offered = json.loads(
            page.split('id="stepKinds">')[1].split("</script>")[0])
        self.assertEqual(set(offered), set(STEP_KINDS))

    # ---------- what the agent is given ----------

    def test_the_agent_is_given_the_steps_and_the_secrets(self):
        self._save()
        journey = self._journey()
        agent, token = self.app.store.agents.create("browser-probe")
        self.app.store.monitors.update(journey["id"],
                                       agent_ids=[agent["id"]])
        config = self.client.get(
            "/api/agent/config",
            headers={"Authorization": f"Bearer {token}"}).get_json()
        monitor = config["monitors"][0]
        self.assertEqual(len(monitor["steps"]), 5)
        self.assertEqual(monitor["secrets"], {"password": "hunter2"})

    def test_an_http_check_is_given_no_steps(self):
        """An empty steps list on every http check is an invitation to fill
        it in."""
        self.client.post("/admin/monitors",
                         data={"name": "Health", "kind": "http",
                               "target": "https://x.example/health",
                               "interval_seconds": "60",
                               "timeout_seconds": "10"},
                         follow_redirects=True)
        check = self.app.store.monitors.all()[0]
        self.assertEqual(check["steps"], [])

    # ---------- reading a run ----------

    def _report(self, failed=True, screenshot=None):
        from datetime import datetime, timezone
        self._save()
        journey = self._journey()
        agent, token = self.app.store.agents.create("browser-probe")
        self.app.store.monitors.update(journey["id"], agent_ids=[agent["id"]])
        steps = [
            {"kind": "goto", "description": "Go to https://shop.example/login",
             "status": STEP_PASSED, "duration_us": 900_000},
            {"kind": "fill", "description": "Type into #email",
             "status": STEP_PASSED, "duration_us": 120_000},
            {"kind": "fill", "description": "Type into #password",
             "status": STEP_PASSED, "duration_us": 110_000},
            {"kind": "click", "description": "Click button[type=submit]",
             "status": STEP_PASSED, "duration_us": 2_000_000},
            {"kind": "expect_url", "description": 'Expect URL "/dashboard"',
             "status": STEP_FAILED if failed else STEP_PASSED,
             "duration_us": 70_000,
             "error": "expected /dashboard, and it is /login" if failed
                      else None}]
        result = {
            "monitor_id": journey["id"],
            # NOW. A fixed timestamp falls outside the window the page asks
            # for, and the page then correctly shows nothing — which reads as
            # a broken feature and is a broken test.
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "down" if failed else "up",
            "duration_us": 3_200_000,
            "error": 'step 5 (Expect URL "/dashboard") failed' if failed
                     else "",
            "steps": steps}
        if failed:
            result["screenshot"] = screenshot or {
                "base64": base64.b64encode(
                    b"\xff\xd8\xff" + b"x" * 3000).decode()}
        self.client.post("/api/agent/results",
                         headers={"Authorization": f"Bearer {token}"},
                         json={"results": [result]})
        return journey

    def test_the_detail_page_shows_every_step(self):
        journey = self._report()
        page = self.client.get(
            f"/monitors/{journey['id']}?window=1h").get_data(as_text=True)
        self.assertEqual(page.count('class="journey-step'), 5)
        self.assertIn("Type into #password", page)

    def test_the_detail_page_marks_the_step_that_failed(self):
        journey = self._report()
        page = self.client.get(
            f"/monitors/{journey['id']}?window=1h").get_data(as_text=True)
        self.assertIn("journey-step failed", page)
        self.assertIn("expected /dashboard, and it is /login", page)

    def test_the_screenshot_is_linked_not_inlined(self):
        """Twenty-five runs on a page would be twenty-five images in the HTML,
        and nobody opens more than one."""
        journey = self._report()
        page = self.client.get(
            f"/monitors/{journey['id']}?window=1h").get_data(as_text=True)
        self.assertIn("/monitors/screenshot/", page)
        self.assertNotIn("data:image/jpeg;base64", page)

    def test_the_screenshot_is_served_as_an_image(self):
        import re
        journey = self._report()
        page = self.client.get(
            f"/monitors/{journey['id']}?window=1h").get_data(as_text=True)
        found = re.search(r"/monitors/screenshot/([0-9a-f-]{36})", page)
        self.assertIsNotNone(found)
        response = self.client.get(found.group(0))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "image/jpeg")
        self.assertEqual(response.data[:3], b"\xff\xd8\xff")

    def _screenshot_url(self, journey):
        import re
        page = self.client.get(
            f"/monitors/{journey['id']}?window=1h").get_data(as_text=True)
        found = re.search(r"/monitors/screenshot/([0-9a-f-]{36})", page)
        return found.group(0) if found else None

    def test_a_screenshot_that_is_not_an_image_is_not_kept(self):
        """The type the agent sent was stored and served back inline from
        WDash's own origin. Any agent-token holder could send `text/html`,
        and the page it made ran in the session of whoever opened it."""
        journey = self._report(screenshot={
            "base64": base64.b64encode(
                b"<html><script>alert(document.cookie)</script>").decode(),
            "content_type": "text/html"})
        self.assertIsNone(self._screenshot_url(journey))

    def test_the_type_served_is_the_bytes_not_the_senders_word(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        journey = self._report(screenshot={
            "base64": base64.b64encode(png).decode(),
            "content_type": "text/html"})
        url = self._screenshot_url(journey)
        # Stored as what it is, so nothing that reads the row later is told
        # what the sender claimed.
        stored = self.app.store.results.screenshot(url.rsplit("/", 1)[-1])
        self.assertEqual(stored["content_type"], "image/png")
        response = self.client.get(url)
        self.assertEqual(response.headers["Content-Type"], "image/png")
        self.assertIn(".png", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Content-Security-Policy"],
                         "default-src 'none'; style-src 'unsafe-inline'; sandbox")

    def test_a_row_kept_before_the_check_is_not_served(self):
        """Rows stored before the type was checked hold whatever an agent
        chose; the route looks at the bytes as well."""
        import uuid
        from datetime import datetime, timezone
        from sqlalchemy import insert
        from wdash.store.schema import journey_screenshots
        journey = self._report(failed=False)
        planted = str(uuid.uuid4())
        with self.app.store.results._engine.begin() as connection:
            connection.execute(insert(journey_screenshots).values(
                id=planted, monitor_id=journey["id"],
                captured_at=datetime.now(timezone.utc),
                content_type="text/html", bytes=40,
                image=b"<html><script>alert(1)</script></html>"))
        response = self.client.get(f"/monitors/screenshot/{planted}")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(b"<script>", response.data)

    def test_a_missing_screenshot_is_a_404_not_a_redirect(self):
        """This is an <img> target. A redirect to a page renders as a broken
        image with no explanation."""
        self._report()
        response = self.client.get(
            "/monitors/screenshot/00000000-0000-0000-0000-000000000000")
        self.assertEqual(response.status_code, 404)

    def test_a_screenshot_needs_the_monitors_permission(self):
        """A picture of a signed-in session is at least as sensitive as the
        check that produced it."""
        import re
        journey = self._report()
        page = self.client.get(
            f"/monitors/{journey['id']}?window=1h").get_data(as_text=True)
        found = re.search(r"/monitors/screenshot/([0-9a-f-]{36})", page)

        # Through the store, NOT the session. Permissions are resolved from
        # RBAC on every request; editing the session dictionary changes a copy
        # nothing reads, and the first version of this test passed against a
        # route with no permission check at all.
        from tests.support import grant
        grant(self.app, "admin", ["system:admin"], indices=["*"])
        response = self.client.get(found.group(0))
        self.assertNotEqual(response.status_code, 200,
                            "the screenshot was served without "
                            "monitors:read")

    def test_a_passing_run_has_no_screenshot(self):
        journey = self._report(failed=False)
        page = self.client.get(
            f"/monitors/{journey['id']}?window=1h").get_data(as_text=True)
        self.assertNotIn("/monitors/screenshot/", page)

    # ---------- naming the failed step ----------

    def _page(self, monitor_id):
        return self.client.get(
            f"/monitors/{monitor_id}?window=1h").get_data(as_text=True)

    def _run_row(self, page):
        """The first row of the run table — not the page.

        The header alert above it repeats the same error, and the folded steps
        below it repeat the same description, so a test scoped to the page
        passes with this row rendering nothing at all. Anchored on the card's
        own heading rather than on "the first table": the steps card sits
        above this one, and on a journey it is the first table on the page.
        """
        import html
        card = page.split("Recent checks")[1]
        return html.unescape(card.split("<tbody>")[1].split("</tr>")[0])

    def _named_step(self, page):
        """What the row says about the failed step, on its own, or None.

        Scoped this tightly on purpose. WDash's own agent writes
        `step 5 (Expect URL "/dashboard") failed` into the error, so the step
        number and the description are both in the row whether or not this
        feature exists — and a test that reads them from anywhere in the row
        is reading the fixture. Elastic's journeys say `error executing step:`
        and name nothing, which is the case that needed the row to say it.
        """
        import html
        import re
        found = re.search(r'<div class="failed-step[^"]*">(.*?)</div>',
                          page, re.S)
        return html.unescape(" ".join(found.group(1).split())) if found else None

    def test_the_row_names_the_step_that_failed(self):
        journey = self._report()
        named = self._named_step(self._page(journey["id"]))
        self.assertIsNotNone(named, "the row named no step")
        self.assertIn("step 5", named)
        self.assertIn('Expect URL "/dashboard"', named)

    def test_the_error_survives_next_to_it(self):
        """The step name says where; only the error says what. Replacing one
        with the other trades a question for a question."""
        row = self._run_row(self._page(self._report()["id"]))
        self.assertIn('step 5 (Expect URL "/dashboard") failed', row)

    def test_a_passing_run_names_no_step(self):
        page = self._page(self._report(failed=False)["id"])
        self.assertIsNone(self._named_step(page))

    def test_the_page_carries_a_row_per_step_over_the_window(self):
        """The card is per STEP over the window, above the per-RUN table.
        Both exist because they answer different questions."""
        import html
        journey = self._report()
        page = self._page(journey["id"])
        card = html.unescape(
            page.split("Steps over the last")[1].split("Recent checks")[0])
        for description in ("Go to https://shop.example/login",
                            "Type into #password", 'Expect URL "/dashboard"'):
            self.assertIn(description, card)
        self.assertIn("Share of a run", card)

    def test_a_check_with_no_steps_still_shows_its_error(self):
        """An HTTP monitor has no steps at all, and the row it has always had
        is the one being changed underneath it."""
        from datetime import datetime, timezone
        self.client.post("/admin/monitors",
                         data={"name": "Health", "kind": "http",
                               "target": "https://x.example/health",
                               "interval_seconds": "60",
                               "timeout_seconds": "10"},
                         follow_redirects=True)
        check = self.app.store.monitors.all()[0]
        agent, token = self.app.store.agents.create("http-probe")
        self.app.store.monitors.update(check["id"], agent_ids=[agent["id"]])
        self.client.post(
            "/api/agent/results",
            headers={"Authorization": f"Bearer {token}"},
            json={"results": [{
                "monitor_id": check["id"],
                "started_at": datetime.now(timezone.utc).isoformat(),
                "status": "down", "duration_us": 1_000,
                "error": "connection refused"}]})
        page = self._page(check["id"])
        self.assertIn("connection refused", self._run_row(page))
        self.assertIsNone(self._named_step(page))
        # And no steps card: an HTTP check has no steps, and a table of one
        # row called "the whole check" is a row that says nothing.
        self.assertNotIn("Steps over the last", page)


class JourneyDeletionTest(unittest.TestCase):
    """Deleting a journey has to take its screenshots with it.

    They are the only thing a monitor owns that lives in its own table, and the
    first version of `delete()` did not know about it — the pictures sat there
    until a retention sweep happened to reach them, belonging to nothing.
    Found while cleaning up a lab, which is later than a test would have.
    """

    def setUp(self):
        import tempfile
        from wdash.store import Store
        from wdash.store.secrets import SecretBox
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.store = Store.open(f"sqlite:///{self.database}",
                                secret_box=SecretBox(SecretBox.generate_key()))

    def tearDown(self):
        self.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _shots(self):
        from sqlalchemy import func, select
        from wdash.store.schema import journey_screenshots
        with self.store.engine.connect() as connection:
            return connection.execute(
                select(func.count()).select_from(journey_screenshots)).scalar()

    def _journey_with_a_failure(self, name="Sign in"):
        from datetime import datetime, timezone
        agent, _token = self.store.agents.create(name + " probe")
        journey = self.store.monitors.create(
            name=name, kind="browser", target=None, interval_seconds=300,
            timeout_seconds=60, agent_ids=[agent["id"]],
            steps=[{"kind": "goto", "value": "https://x.example/login"},
                   {"kind": "expect_url", "value": "/home"}])
        self.store.results.record(agent["id"], [{
            "monitor_id": journey["id"],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "down", "error": "step 2 failed",
            "screenshot": {"base64": base64.b64encode(
                b"\xff\xd8\xff" + b"x" * 2000).decode()}}])
        return journey

    def test_deleting_a_journey_removes_its_screenshots(self):
        journey = self._journey_with_a_failure()
        self.assertEqual(self._shots(), 1)
        self.store.monitors.delete(journey["id"])
        self.assertEqual(self._shots(), 0)

    def test_it_leaves_another_journeys_screenshots_alone(self):
        """A DELETE with the wrong WHERE would pass the test above."""
        first = self._journey_with_a_failure("First")
        self._journey_with_a_failure("Second")
        self.assertEqual(self._shots(), 2)
        self.store.monitors.delete(first["id"])
        self.assertEqual(self._shots(), 1)

    def test_the_results_go_too(self):
        journey = self._journey_with_a_failure()
        self.assertEqual(self.store.results.count(journey["id"]), 1)
        self.store.monitors.delete(journey["id"])
        self.assertEqual(self.store.results.count(journey["id"]), 0)
