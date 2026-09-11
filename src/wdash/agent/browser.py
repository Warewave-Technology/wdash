"""
Running a journey in a real browser.

The only module in the project that imports Playwright, and it imports it
inside the function. An agent built on the plain image has no browser, and
that has to produce "this probe cannot run journeys" rather than an ImportError
at start-up that takes the http checks down with it.

Two rules shape everything here.

**Every step is timed on its own.** A journey that reports one number is a
journey that cannot answer the only interesting question — which part got
slower. The per-step durations ARE the feature.

**The first failure stops the run.** Steps after it are `skipped`, not
`failed`: step 4 could not find the basket button because step 3's sign-in
failed, and reporting five failures for one cause sends somebody looking in
four wrong places.
"""

import logging
import time

from ..hub.models import STEP_FAILED, STEP_PASSED, STEP_SKIPPED
from ..journeys import SECRET_PATTERN, StepError, describe, parse, resolve

logger = logging.getLogger(__name__)

#: Longest a whole journey may take, whatever its steps ask for. The monitor's
#: own timeout is used when it is lower.
MAX_TOTAL_SECONDS = 600

#: Viewport. A fixed size rather than the default, because a responsive site
#: shows a different navigation at 800px and a journey that clicks a menu item
#: should not depend on what the agent's default happened to be.
VIEWPORT = {"width": 1366, "height": 768}

#: Screenshot quality. Sixty is legible for reading an error banner off a page
#: and roughly a tenth of the bytes of a PNG.
SCREENSHOT_QUALITY = 60

#: How long to spend trying to photograph a failure.
#:
#: This is not a detail. Playwright's default is thirty seconds, and a
#: screenshot of a page that is STILL LOADING waits for it — which is exactly
#: the state a journey is in when it just timed out. Measured: a `goto` that
#: correctly gave up after 3s was followed by a screenshot that blocked for 27
#: more and then failed anyway. The monitor's timeout is supposed to bound the
#: whole run, only two journeys may run at once, and the evidence was holding
#: both slots for half a minute after the measurement was over.
#:
#: Two seconds. A picture is worth having and not worth waiting for.
SCREENSHOT_TIMEOUT_MS = 2_000

#: Shortest secret looked for in what a page shows. Anything shorter matches
#: ordinary text; such a secret is still covered where the journey typed it.
MIN_SECRET_SEEN = 4

#: The fields a page could be holding a secret in.
FIELDS = "input, textarea"


def run_journey(monitor, secrets=None, launcher=None, now=None):
    """Run one journey and return a result dictionary.

    Same contract as `run_check`: it returns a result rather than raising. A
    journey that could not start is a journey that failed — that IS the
    measurement.
    """
    from datetime import datetime, timezone
    started = now or datetime.now(timezone.utc)
    clock = time.monotonic()

    try:
        steps = parse(monitor.get("steps"))
    except StepError as exc:
        # Stored steps that no longer parse. Reported as a failure with the
        # reason, because the alternative is a journey that silently never
        # runs and a page that shows it as unknown for ever.
        return _result(monitor, started, "down",
                       f"this journey cannot run: {exc}", 0, [])

    plan = [{"index": i, "kind": s.kind, "description": describe(s),
             "status": STEP_SKIPPED, "duration_us": None, "error": None}
            for i, s in enumerate(steps, start=1)]

    hidden = [str(v) for v in (secrets or {}).values() if v]
    budget = min(int(monitor.get("timeout_seconds") or 60), MAX_TOTAL_SECONDS)

    try:
        browser = launcher or _chromium
        with browser() as page:
            failure, shot = _walk(page, steps, plan, secrets, hidden, budget,
                                  clock)
    except ImportError:
        return _result(monitor, started, "down",
                       "this agent has no browser — a journey needs an agent "
                       "built on the browser image", 0, plan)
    except Exception as exc:
        # The browser itself would not start: no sandbox, no /dev/shm, a
        # missing shared library. Named as such, because "step 1 failed" would
        # send somebody to look at a website that is fine.
        return _result(monitor, started, "down",
                       f"the browser could not start: {_clean(exc, hidden)}",
                       _since(clock), plan)

    return _result(monitor, started, "down" if failure else "up", failure or "",
                   _since(clock), plan, screenshot=shot)


class _chromium:
    """Playwright, opened and closed. Separate so tests can pass their own."""

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(
            args=["--disable-dev-shm-usage"])
        self._context = self._browser.new_context(
            viewport=VIEWPORT,
            # A journey signs in. Carrying a profile between runs would mean
            # the second run never exercises the login, and the check quietly
            # stops testing the thing it was written for.
            ignore_https_errors=False)
        return self._context.new_page()

    def __exit__(self, *exc):
        for closing in (self._context, self._browser):
            try:
                closing.close()
            except Exception:
                pass
        try:
            self._playwright.stop()
        except Exception:
            # A browser that will not close is a leaked process, and saying so
            # is the only way anybody finds out before the probe runs out of
            # memory.
            logger.warning("the browser did not shut down cleanly")
        return False


def _walk(page, steps, plan, secrets, hidden, budget, clock):
    """Run the steps in order. Returns (failure message, screenshot or None)."""
    for step, row in zip(steps, plan):
        left = budget - (time.monotonic() - clock)
        if left <= 0:
            row["status"] = STEP_FAILED
            row["error"] = "the journey ran out of time before this step"
            return (f"step {row['index']} ({row['description']}): the journey "
                    f"ran out of time"), _capture(page, steps, hidden)

        timeout = min(step.timeout, int(left * 1000))
        step_clock = time.monotonic()
        try:
            _do(page, step, secrets, timeout)
        except Exception as exc:
            row["status"] = STEP_FAILED
            row["duration_us"] = _since(step_clock)
            row["error"] = _clean(exc, hidden, step.kind)
            return (f"step {row['index']} ({row['description']}): "
                    f"{row['error']}"), _capture(page, steps, hidden)
        row["status"] = STEP_PASSED
        row["duration_us"] = _since(step_clock)
    return None, None


def _do(page, step, secrets, timeout):
    """One step. Raises with a sentence somebody can act on."""
    kind = step.kind
    value = resolve(step, secrets)

    if kind == "goto":
        response = page.goto(value, timeout=timeout, wait_until="load")
        # A journey whose first page 500s should not spend the rest of its
        # steps failing to find selectors on an error page.
        if response is not None and response.status >= 400:
            raise _Failed(f"the page answered {response.status}")
        return

    if kind == "click":
        return page.click(step.selector, timeout=timeout)
    if kind == "fill":
        return page.fill(step.selector, value, timeout=timeout)
    if kind == "select":
        return page.select_option(step.selector, value, timeout=timeout)
    if kind == "press":
        return page.press(step.selector, value, timeout=timeout)
    if kind == "wait_for":
        return page.wait_for_selector(step.selector, timeout=timeout)

    if kind == "expect_selector":
        if page.query_selector(step.selector) is None:
            page.wait_for_selector(step.selector, timeout=timeout)
        return

    if kind == "expect_text":
        if not _has_text(page, value, timeout):
            raise _Failed(f'the page does not contain "{value}"')
        return

    if kind == "expect_no_text":
        # No waiting: this asserts about NOW. Waiting for text to be absent
        # would pass the instant before an error banner renders, which is the
        # one moment the assertion is wrong.
        if value in _text(page):
            raise _Failed(f'the page contains "{value}", and should not')
        return

    if kind == "expect_url":
        current = page.url
        if value not in current:
            raise _Failed(f"expected the address to contain {value}, "
                          f"and it is {current}")
        return

    raise _Failed(f"'{kind}' is not something a journey can do")


class _Failed(Exception):
    """A step that ran and did not get the answer it wanted.

    Distinct from a Playwright error only in the message: this one is already
    a sentence, so `_clean` leaves it alone.
    """


def _has_text(page, needle, timeout):
    """Is the text on the page, within the step's patience?

    Polled rather than a single look: a page that fills itself in after load
    would fail an assertion taken the instant the step began, and that is most
    pages.
    """
    deadline = time.monotonic() + (timeout / 1000.0)
    while True:
        if needle in _text(page):
            return True
        if time.monotonic() >= deadline:
            return False
        page.wait_for_timeout(100)


def _text(page):
    try:
        return page.inner_text("body")
    except Exception:
        # A page with no body yet — mid-navigation, or a download. Not an
        # error of its own; the assertion simply has not found its text.
        return ""


def _capture(page, steps=(), hidden=()):
    """A picture of the failure, if one can still be taken — with nothing in
    it a journey secret was typed into.

    Password boxes draw dots, but a secret goes wherever a journey types it:
    an API key, an account number or a user name in a plain text field was
    photographed as typed and served to anybody who may read monitors, while
    the secret itself is sealed and admin-only. So every field the journey
    typed a secret into is painted over, and so is any field holding one now.
    A page that shows one as text — "signed in with key …" — gets no picture
    at all: a secret in the text could be anywhere on it.

    Best effort by design: the browser may have crashed, which is exactly when
    a screenshot is impossible and least worth failing the result over. And
    when what to cover cannot be worked out, there is no picture: a
    photograph is worth having and not worth leaking.
    """
    looked = [h for h in hidden if len(h) >= MIN_SECRET_SEEN]
    try:
        import base64
        if looked:
            shown = page.inner_text("body", timeout=SCREENSHOT_TIMEOUT_MS)
            if any(secret in shown for secret in looked):
                logger.info("no screenshot: a journey secret is on the page")
                return None
        raw = page.screenshot(type="jpeg", quality=SCREENSHOT_QUALITY,
                              full_page=False,
                              timeout=SCREENSHOT_TIMEOUT_MS,
                              # A page mid-animation is one more thing the
                              # capture would wait for.
                              animations="disabled",
                              mask=_masks(page, steps, looked))
    except Exception as exc:
        logger.debug(f"no screenshot: {exc}")
        return None
    return {"base64": base64.b64encode(raw).decode("ascii"),
            "content_type": "image/jpeg"}


def _masks(page, steps, looked):
    """The fields to paint over.

    Values are read out and compared here, not searched for in the page: a
    secret handed to the page's JavaScript is a secret handed to the page,
    and one used on another site in the same journey was never its to see.
    """
    typed = sorted({step.selector for step in steps if step.selector
                    and SECRET_PATTERN.search(step.value or "")})
    masks = [page.locator(selector) for selector in typed]
    if looked:
        fields = page.locator(FIELDS)
        values = fields.evaluate_all("all => all.map(f => String(f.value || ''))")
        masks += [fields.nth(index) for index, value in enumerate(values)
                  if any(secret in value for secret in looked)]
    return masks


def _clean(exception, hidden, kind=""):
    """A readable reason, with no credential in it.

    Playwright's messages carry the whole call — including the text of a
    `fill`, which for a sign-in journey is the password. Redacted before it
    reaches a result row, a history page and an alert body.
    """
    if isinstance(exception, (_Failed, StepError)):
        text = str(exception)
    else:
        text = str(exception).strip().split("\n")[0]
        # "Timeout 10000ms exceeded." on its own says nothing about what was
        # being waited for. The step's description already names the target,
        # so this only has to say what did not happen — and what did not
        # happen differs: a page did not load, an element did not appear.
        if "Timeout" in text and "exceeded" in text:
            text = ("the page did not load in time" if kind == "goto"
                    else "it was not there in time")
    for secret in hidden:
        if secret:
            text = text.replace(secret, "***")
    return text[:1000]


def _since(clock):
    return int((time.monotonic() - clock) * 1_000_000)


def _result(monitor, started, status, error, duration_us, steps,
            screenshot=None):
    out = {
        "monitor_id": monitor["id"],
        "started_at": started.isoformat(),
        "status": status,
        "duration_us": duration_us,
        "error": error or "",
        "steps": steps,
    }
    if screenshot:
        out["screenshot"] = screenshot
    return out
