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
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.agent import browser  # noqa: E402
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

    def __init__(self, fail_at=None, error=None, url="https://x.example/",
                 text="hello", field_values=()):
        self.fail_at = fail_at
        self.error = error or RuntimeError("boom")
        self.url = url
        self.text = text
        self.field_values = list(field_values)
        self.calls = []
        self.screenshots = 0
        self.masked = None

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

    def inner_text(self, selector, timeout=None):
        # With a timeout it is the photograph's look at the page, which is
        # not a step and must not count as one.
        if timeout is None:
            self._step("inner_text", selector)
        return self.text

    def wait_for_timeout(self, ms):
        pass

    def locator(self, selector):
        return _FakeLocator(self, selector)

    def screenshot(self, mask=(), **kw):
        self.screenshots += 1
        self.masked = [m.selector for m in mask]
        return b"\xff\xd8\xff" + b"jpeg-bytes"


class _FakeLocator:
    """Enough of a Playwright locator to say what would be painted over."""

    def __init__(self, page, selector):
        self.page, self.selector = page, selector

    def evaluate_all(self, script):
        return list(self.page.field_values)

    def nth(self, index):
        return _FakeLocator(self.page, f"{self.selector} >> nth={index}")


class _Launcher:
    """The browser a journey opens, and what it was asked to open it with.

    `options` is the contract change this fake exists to pin: a launcher that
    ignored them would make "expiry only" and a pinned certificate settings
    that are stored, sent to the agent, and never reach the browser.
    """

    def __init__(self, page):
        self.page = page
        self.options = None

    def __call__(self, **options):
        self.options = options
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

    def test_the_fields_a_secret_was_typed_into_are_painted_over(self):
        _, page = _journey(SIGN_IN, fail_at=4, secrets={"password": PASSWORD})
        self.assertEqual(page.masked, ["#password"])

    def test_a_field_holding_a_secret_now_is_painted_over(self):
        """A page that copies a key into a second box, or one the browser
        filled from the first: the journey never typed there."""
        page = _FakePage(fail_at=4,
                         field_values=["ops@x.example", f"Bearer {PASSWORD}", ""])
        run_journey({"id": "m1", "timeout_seconds": 30, "steps": SIGN_IN},
                    secrets={"password": PASSWORD}, launcher=_Launcher(page))
        self.assertIn(f"{browser.FIELDS} >> nth=1", page.masked)
        self.assertEqual(len(page.masked), 2, page.masked)

    def test_a_page_showing_a_secret_is_not_photographed(self):
        """In the text it could be anywhere, so nothing is painted over —
        there is no picture."""
        page = _FakePage(fail_at=4, text=f"signed in with {PASSWORD}")
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "steps": SIGN_IN},
                             secrets={"password": PASSWORD},
                             launcher=_Launcher(page))
        self.assertEqual(page.screenshots, 0)
        self.assertNotIn("screenshot", result)
        self.assertEqual(result["status"], "down")

    def test_a_short_secret_is_not_looked_for_in_the_text(self):
        """"db" is in most sentences; a journey with it would never be
        photographed. Where it was typed is still painted over."""
        page = _FakePage(fail_at=4, text="the db is down")
        run_journey({"id": "m1", "timeout_seconds": 30, "steps": SIGN_IN},
                    secrets={"password": "db"}, launcher=_Launcher(page))
        self.assertEqual(page.screenshots, 1)
        self.assertEqual(page.masked, ["#password"])

    def test_no_picture_when_what_to_cover_cannot_be_worked_out(self):
        page = _FakePage(fail_at=4)

        def broken(selector):
            raise RuntimeError("the page went away")
        page.locator = broken
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "steps": SIGN_IN},
                             secrets={"password": PASSWORD},
                             launcher=_Launcher(page))
        self.assertEqual(page.screenshots, 0)
        self.assertNotIn("screenshot", result)

    def test_a_pass_is_not_photographed(self):
        """A picture a minute of a page that is fine, kept for a week."""
        result, page = _journey(SIGN_IN, secrets={"password": PASSWORD})
        self.assertEqual(page.screenshots, 0)
        self.assertNotIn("screenshot", result)

    def test_an_agent_without_a_browser_says_so(self):
        """Not "step 1 failed", which sends somebody to check a website that
        is fine."""
        def missing(**options):
            raise ImportError("No module named 'playwright'")
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "steps": SIGN_IN}, launcher=missing)
        self.assertEqual(result["status"], "down")
        self.assertIn("no browser", result["error"])
        self.assertEqual([s["status"] for s in result["steps"]],
                         [STEP_SKIPPED] * 5)

    def test_a_browser_that_will_not_start_is_named_as_such(self):
        def broken(**options):
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
        def exploding(**options):
            raise KeyboardInterrupt  # noqa: not caught by `except Exception`
        with self.assertRaises(KeyboardInterrupt):
            run_journey({"id": "m1", "steps": SIGN_IN}, launcher=exploding)
        # Everything short of that is a result.
        for error in (ValueError("x"), OSError("y"), RuntimeError("z")):
            result = run_journey(
                {"id": "m1", "steps": SIGN_IN},
                launcher=lambda e=error, **options: (_ for _ in ()).throw(e))
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


#: A key typed into a plain text field, and a page that copies it into a
#: second box and, on request, prints it.
KEY_PAGE = """<html><body><h1>API settings</h1>
<input id=key name=key style="width:30em"
 oninput="document.getElementById('copy').value=this.value">
<input id=copy style="width:30em">
<button id=show onclick="document.getElementById('out').innerText=
document.getElementById('key').value">Show</button><div id=out></div>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/key"):
            return self._send(KEY_PAGE)
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
        from tests.support import serve_in_background
        cls.server = serve_in_background(ThreadingHTTPServer(("127.0.0.1", 0), _Handler))
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

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
        # A second, not eight: what is being checked is the message a
        # timeout produces, and it says the same whenever it comes.
        steps = [{"kind": "goto", "value": self.base + "/"},
                 {"kind": "fill", "selector": "#nonexistent",
                  "value": "{{ secret.password }}", "timeout_ms": 1000},
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

    def _key_journey(self, typed, then=()):
        """Type into the plain field, then fail: the picture is taken with
        the value still on screen."""
        steps = [{"kind": "goto", "value": self.base + "/key"},
                 {"kind": "fill", "selector": "#key", "value": typed},
                 *then,
                 {"kind": "expect_selector", "selector": "#missing",
                  "timeout_ms": 300}]
        return run_journey({"id": "m1", "timeout_seconds": 10, "steps": steps},
                           secrets={"api_key": "K3Y-AAAAAAAAAAAAAAAA",
                                    "other": "K3Y-BBBBBBBBBBBBBBBB"})

    def _picture(self, result):
        self.assertEqual(result["status"], "down")
        self.assertIn("screenshot", result, "no picture was taken")
        return base64.b64decode(result["screenshot"]["base64"])

    def test_a_key_in_a_plain_field_is_not_in_the_picture(self):
        """Two runs typing two different keys produce the same picture: the
        field and its copy are painted over. Two values that are no secret,
        typed the same way, produce different pictures, which is what makes
        the comparison able to see a key at all."""
        masked = [self._picture(self._key_journey(f"{{{{ secret.{name} }}}}"))
                  for name in ("api_key", "other")]
        self.assertEqual(masked[0], masked[1],
                         "a typed secret is visible in the screenshot")
        shown = [self._picture(self._key_journey(value))
                 for value in ("K3Y-CCCCCCCCCCCCCCCC", "K3Y-DDDDDDDDDDDDDDDD")]
        self.assertNotEqual(shown[0], shown[1],
                            "the comparison cannot see typed text")

    def test_a_page_that_prints_a_key_is_not_photographed(self):
        result = self._key_journey(
            "{{ secret.api_key }}",
            then=[{"kind": "click", "selector": "#show"}])
        self.assertEqual(result["status"], "down")
        self.assertNotIn("screenshot", result)

    def test_expect_text_fails_when_the_text_is_not_there(self):
        """The assertion has to be able to FAIL. Without this, deleting the
        check entirely leaves every test green — every other journey here
        expects text that is present."""
        steps = [{"kind": "goto", "value": self.base + "/"},
                 {"kind": "expect_text", "value": "Order confirmed",
                  "timeout_ms": 800}]
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
        result = run_journey({"id": "m1", "timeout_seconds": 2,
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

    def test_a_secret_called_headers_leaves_the_agents_configuration_alone(self):
        """Read as request secrets, a journey secret named `headers` was
        merged as a header dictionary, and /api/agent/config answered 500 to
        every agent that ran the journey — every agent, unassigned — so none
        picked up anything, their http checks included."""
        steps = [{"kind": "goto", "value": "https://shop.example/login"},
                 {"kind": "fill", "selector": "#key",
                  "value": "{{ secret.headers }}"},
                 {"kind": "expect_url", "value": "/dashboard"}]
        self._save(steps=steps, journey_secret_headers="hunter2")
        self.app.store.monitors.create("health", "http",
                                       "https://shop.example/health")
        _, token = self.app.store.agents.create("probe")
        reply = self.client.get("/api/agent/config",
                                headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(reply.status_code, 200)
        monitors = {m["name"]: m for m in reply.get_json()["monitors"]}
        self.assertEqual(sorted(monitors), ["Sign in", "health"])
        self.assertEqual(monitors["Sign in"]["request"], {})
        self.assertEqual(monitors["Sign in"]["secrets"], {"headers": "hunter2"})

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


# ---------------------------------------------------------------------------
# What a journey does about the certificate
# ---------------------------------------------------------------------------

def _private_chain(scratch):
    """A CA, a leaf it signed for 127.0.0.1, and the files a server needs."""
    import datetime as dt
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                            "Warewave Internal CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1))
          .not_valid_after(now + dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                         critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(
              ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(
              digital_signature=True, content_commitment=False,
              key_encipherment=False, data_encipherment=False,
              key_agreement=False, key_cert_sign=True, crl_sign=True,
              encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(
                NameOID.COMMON_NAME, "payments.internal")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("payments.internal"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.AuthorityKeyIdentifier
                           .from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                leaf_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))

    # And one that has already expired, signed by the same authority. A pin
    # waives EVERY certificate error for that key, expiry included — measured
    # — so this is the certificate that tells the browser and the clock
    # apart.
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(
                   NameOID.COMMON_NAME, "payments.internal")]))
               .issuer_name(ca_name).public_key(expired_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=400))
               .not_valid_after(now - dt.timedelta(days=25))
               .add_extension(x509.SubjectAlternativeName([
                   x509.DNSName("payments.internal"),
                   x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                   critical=False)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                              critical=True)
               .add_extension(x509.AuthorityKeyIdentifier
                              .from_issuer_public_key(ca_key.public_key()),
                              critical=False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                   expired_key.public_key()), critical=False)
               .sign(ca_key, hashes.SHA256()))

    def write(name, certificate, private):
        cert_path = os.path.join(scratch, f"{name}.crt")
        key_path = os.path.join(scratch, f"{name}.key")
        with open(cert_path, "wb") as handle:
            handle.write(certificate.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as handle:
            handle.write(private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        return cert_path, key_path

    cert_path, key_path = write("leaf", leaf, leaf_key)
    expired_cert_path, expired_key_path = write("expired", expired,
                                                expired_key)
    return {
        "ca_pem": ca.public_bytes(serialization.Encoding.PEM).decode(),
        "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
        "cert_path": cert_path, "key_path": key_path,
        "expired_pem": expired.public_bytes(
            serialization.Encoding.PEM).decode(),
        "expired_cert_path": expired_cert_path,
        "expired_key_path": expired_key_path,
    }


def _https_server(cert_path, key_path, body=b"<html><body>hello</body></html>"):
    import ssl
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from tests.support import serve_in_background

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return serve_in_background(server)


class JourneyTlsOptionsTest(unittest.TestCase):
    """What the journey asks its browser for.

    Read off the launcher, because that is the contract: a setting the store
    holds, the endpoint sends and the browser never receives is a setting
    stored and ignored — the shape this whole package exists to remove.
    """

    STEPS = [{"kind": "goto", "value": "https://payments.internal/login"},
             {"kind": "expect_text", "value": "hello"}]

    def _run(self, tls=None, target="https://payments.internal/login"):
        page = _FakePage()
        launcher = _Launcher(page)
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "target": target, "steps": self.STEPS,
                              "tls": tls or {}}, launcher=launcher)
        return result, launcher

    def test_a_journey_verifies_by_default(self):
        _, launcher = self._run()
        self.assertEqual(launcher.options["ignore_https_errors"], False)
        self.assertEqual(launcher.options["certificate_pins"], ())

    def test_expiry_only_waives_verification_in_the_browser(self):
        _, launcher = self._run({"mode": "expiry_only"})
        self.assertEqual(launcher.options["ignore_https_errors"], True)

    def test_a_pasted_certificate_becomes_a_pinned_key(self):
        """Not a blanket. Measured against Chromium 151: the error is ignored
        only for a chain carrying this exact public key."""
        import base64
        import hashlib

        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat,
        )
        scratch = tempfile.mkdtemp()
        try:
            chain = _private_chain(scratch)
        finally:
            import shutil
            shutil.rmtree(scratch, ignore_errors=True)
        _, launcher = self._run({"certificate": chain["leaf_pem"]})
        der = x509.load_pem_x509_certificate(
            chain["leaf_pem"].encode()).public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        expected = base64.b64encode(hashlib.sha256(der).digest()).decode()
        self.assertEqual(launcher.options["certificate_pins"], (expected,))
        self.assertEqual(launcher.options["ignore_https_errors"], False)

    def test_a_journey_reports_the_certificate_it_reached(self):
        """Otherwise "expiry only" promises a journey a clock it never
        produced: every https journey was invisible on the certificate screen
        while every http check beside it reported one."""
        scratch = tempfile.mkdtemp()
        try:
            chain = _private_chain(scratch)
            server = _https_server(chain["cert_path"], chain["key_path"])
            port = server.server_address[1]
            try:
                result, _ = self._run({"mode": "expiry_only"},
                                      target=f"https://127.0.0.1:{port}/")
            finally:
                server.shutdown()
                server.server_close()
        finally:
            import shutil
            shutil.rmtree(scratch, ignore_errors=True)
        self.assertEqual(result["tls"]["common_name"], "payments.internal")
        self.assertTrue(result["tls"]["not_after"])
        self.assertIs(result["handshake_verified"], False)

    ADDRESS = "https://svc:P4SSW0RD@payments.internal/login"

    def _goto(self, tls):
        """The URL the browser was actually asked to open."""
        page = _FakePage()
        run_journey({"id": "m1", "timeout_seconds": 30, "target": self.ADDRESS,
                     "steps": [{"kind": "goto", "value": self.ADDRESS},
                               {"kind": "expect_text", "value": "hello"}],
                     "tls": tls}, launcher=_Launcher(page))
        return page.calls[0][1][0]

    def test_a_waived_journey_does_not_type_the_password_in_its_address(self):
        """"Expiry only sends nothing" has to cover the address as well:
        measured, Chromium answers a 401 challenge with the user name and
        password from the URL it was given, over a context launched with
        ignore_https_errors=True. The store refuses to save the combination,
        so a row holding it was hand-edited or written by an older build."""
        self.assertEqual(self._goto({"mode": "expiry_only"}),
                         "https://payments.internal/login")

    def test_a_verifying_journey_keeps_what_its_address_carries(self):
        """The boundary, and it is the point of the pin: a journey that
        verified the certificate — or pinned the endpoint's own public key —
        knows what it is talking to, and may sign in."""
        self.assertEqual(self._goto({}), self.ADDRESS)

    def test_a_pin_over_an_expired_certificate_is_not_called_verified(self):
        """A pin waives EVERY certificate error for that key, expiry
        included: measured against Chromium 151, a journey pinned to a
        certificate that expired twenty-five days ago loads the page and
        comes up. Calling that handshake verified puts a verdict saying the
        certificate was good beside the expiry chip saying it was not —
        the browser and the clock disagreeing on one row. The expiry is still
        read, still shown and still alerted on; the verdict is False.
        """
        scratch = tempfile.mkdtemp()
        try:
            chain = _private_chain(scratch)
            server = _https_server(chain["expired_cert_path"],
                                   chain["expired_key_path"])
            port = server.server_address[1]
            try:
                result, _ = self._run({"certificate": chain["expired_pem"]},
                                      target=f"https://127.0.0.1:{port}/")
            finally:
                server.shutdown()
                server.server_close()
        finally:
            import shutil
            shutil.rmtree(scratch, ignore_errors=True)
        self.assertEqual(result["status"], "up", result["error"])
        self.assertIs(result["handshake_verified"], False)
        # And the clock it disagreed with is on the result, as it has to be:
        # this is the check that reports the expiry.
        self.assertTrue(result["tls"]["not_after"])

    def test_a_pin_over_a_certificate_in_date_still_counts_as_verified(self):
        """The other side of the same rule: the endpoint proved it holds the
        private key for exactly the public key this monitor names."""
        scratch = tempfile.mkdtemp()
        try:
            chain = _private_chain(scratch)
            server = _https_server(chain["cert_path"], chain["key_path"])
            port = server.server_address[1]
            try:
                result, _ = self._run({"certificate": chain["leaf_pem"]},
                                      target=f"https://127.0.0.1:{port}/")
            finally:
                server.shutdown()
                server.server_close()
        finally:
            import shutil
            shutil.rmtree(scratch, ignore_errors=True)
        self.assertIs(result["handshake_verified"], True)

    def test_an_http_journey_says_nothing_about_a_handshake(self):
        result, _ = self._run(target="http://payments.internal/login")
        self.assertIsNone(result["handshake_verified"])
        self.assertIsNone(result["tls"])

    def test_a_refused_certificate_names_what_to_paste(self):
        """Chromium's own words are ERR_CERT_AUTHORITY_INVALID, which says
        nothing about where the answer lives."""
        page = _FakePage(fail_at=1,
                         error=RuntimeError("net::ERR_CERT_AUTHORITY_INVALID "
                                            "at https://payments.internal/"))
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "target": "https://payments.internal/login",
                              "steps": self.STEPS, "tls": {}},
                             launcher=_Launcher(page))
        self.assertEqual(result["status"], "down")
        self.assertIn("Paste the certificate this endpoint presents",
                      result["error"])
        self.assertIs(result["handshake_verified"], False)

    def test_a_journey_that_already_pins_is_told_the_key_is_wrong(self):
        scratch = tempfile.mkdtemp()
        try:
            chain = _private_chain(scratch)
        finally:
            import shutil
            shutil.rmtree(scratch, ignore_errors=True)
        page = _FakePage(fail_at=1,
                         error=RuntimeError("net::ERR_CERT_AUTHORITY_INVALID"))
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "target": "https://payments.internal/login",
                              "steps": self.STEPS,
                              "tls": {"certificate": chain["ca_pem"]}},
                             launcher=_Launcher(page))
        self.assertIn("endpoint's own public key", result["error"])

    def test_an_ordinary_failure_is_not_dressed_up_as_a_certificate(self):
        page = _FakePage(fail_at=1, error=RuntimeError("boom"))
        result = run_journey({"id": "m1", "timeout_seconds": 30,
                              "target": "https://payments.internal/login",
                              "steps": self.STEPS, "tls": {}},
                             launcher=_Launcher(page))
        self.assertNotIn("Paste the certificate", result["error"])
        self.assertIs(result["handshake_verified"], True)


@unittest.skipUnless(HAVE_BROWSER,
                     "no Chromium — run `playwright install chromium`")
class PinnedCertificateTest(unittest.TestCase):
    """The measurement the journey half of this package rests on.

    A journey that signs in cannot exist without a stored secret, so if the
    only answer for a private certificate were "do not verify", every
    internal sign-in journey would have no configuration at all. The pin is
    the answer, and it is worth a real browser: `--ignore-certificate-errors-
    spki-list` is a Chromium flag whose behaviour no fake can assert.
    """

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.mkdtemp()
        cls.chain = _private_chain(cls.scratch)
        cls.server = _https_server(cls.chain["cert_path"],
                                   cls.chain["key_path"])
        cls.url = f"https://127.0.0.1:{cls.server.server_address[1]}/"
        cls.expired_server = _https_server(cls.chain["expired_cert_path"],
                                           cls.chain["expired_key_path"])
        cls.expired_url = (f"https://127.0.0.1:"
                           f"{cls.expired_server.server_address[1]}/")

    @classmethod
    def tearDownClass(cls):
        import shutil
        for server in (cls.server, cls.expired_server):
            server.shutdown()
            server.server_close()
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def _journey(self, tls, url=None):
        url = url or self.url
        return run_journey({"id": "m1", "timeout_seconds": 45,
                            "target": url, "tls": tls,
                            "steps": [{"kind": "goto", "value": url},
                                      {"kind": "expect_text",
                                       "value": "hello"}]})

    def test_a_private_certificate_is_refused_by_default(self):
        result = self._journey({})
        self.assertEqual(result["status"], "down")
        self.assertIn("ERR_CERT", result["error"])

    def test_the_endpoint_s_own_certificate_pinned_makes_it_pass(self):
        result = self._journey({"certificate": self.chain["leaf_pem"]})
        self.assertEqual(result["status"], "up", result["error"])
        self.assertIs(result["handshake_verified"], True)

    def test_the_authority_that_signed_it_does_not(self):
        """Measured, and the reason the form says to paste the endpoint's
        own: Chromium matches the public key it is shown, not the authority
        behind it. A CA pasted here would be stored and ignored, which is
        exactly the shape this package removes — so it is a failure with a
        sentence, not a silent pass."""
        result = self._journey({"certificate": self.chain["ca_pem"]})
        self.assertEqual(result["status"], "down")
        self.assertIn("endpoint's own public key", result["error"])

    def test_expiry_only_gets_through_without_a_certificate(self):
        result = self._journey({"mode": "expiry_only"})
        self.assertEqual(result["status"], "up", result["error"])
        self.assertIs(result["handshake_verified"], False)

    def test_the_pin_gets_an_expired_certificate_through_and_says_so(self):
        """The measurement behind the verdict rule: Chromium's waiver for a
        pinned key covers ERR_CERT_DATE_INVALID too, so the page loads over a
        certificate that expired twenty-five days ago. The journey is up —
        the site really did answer — and the handshake is NOT called
        verified, because the clock says otherwise and one row must not carry
        both claims."""
        result = self._journey({"certificate": self.chain["expired_pem"]},
                               url=self.expired_url)
        self.assertEqual(result["status"], "up", result["error"])
        self.assertIs(result["handshake_verified"], False)
        self.assertTrue(result["tls"]["not_after"])
