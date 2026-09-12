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

#: How long to spend reading the certificate the journey's endpoint presents.
#: A journey's own budget is minutes; a certificate read that took minutes
#: would hold a browser slot open for a fact that is worth having and not
#: worth waiting for.
CERTIFICATE_TIMEOUT = 5

#: The two TLS decisions a monitor can carry. Same words as the http check,
#: and an unfamiliar one means the same thing there: verify.
VERIFY, EXPIRY_ONLY = "verify", "expiry_only"

#: What Chromium calls a certificate it would not accept.
_REFUSED = ("err_cert", "err_ssl", "ssl_error", "err_bad_ssl")


def _mode(tls):
    mode = ((tls or {}).get("mode") or VERIFY)
    return mode if mode in (VERIFY, EXPIRY_ONLY) else VERIFY


def _pins(pem):
    """The public keys Chromium will accept despite a certificate error.

    One per certificate in the pasted PEM, as base64 of the SHA-256 of its
    SubjectPublicKeyInfo — the form
    `--ignore-certificate-errors-spki-list` takes. Every certificate in the
    paste is pinned rather than a chosen one: which of them the endpoint
    actually presents is not something a form can know, and a pin for a key
    nothing presents simply never matches.

    Measured (Chromium 151, a leaf signed by a private CA, served at
    127.0.0.1): the leaf's key -> HTTP 200; the CA's key -> still
    ERR_CERT_AUTHORITY_INVALID; another host's leaf -> ERR_CERT_AUTHORITY_
    INVALID; the right key against a different endpoint -> refused. The
    waiver it grants for that key is total, expiry included, which is why the
    certificate is still read and still reaches the expiry alert.
    """
    if not pem:
        return ()
    import base64
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    try:
        found = x509.load_pem_x509_certificates(pem.encode())
    except Exception as exc:
        # Refused at the form, so reaching this means a hand-written row.
        # Said rather than crashed: a journey that cannot pin still runs, and
        # fails with the browser's own certificate error.
        logger.error(f"the certificate this journey was told to trust could "
                     f"not be read ({type(exc).__name__}); it was not pinned")
        return ()
    out = []
    for certificate in found:
        der = certificate.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        out.append(base64.b64encode(hashlib.sha256(der).digest()).decode())
    return tuple(out)


def _certificate_of(monitor):
    """The certificate this journey's endpoint presents, or None.

    Read here at all because otherwise "expiry only" would promise a journey
    a clock it never produced: a journey stored no TLS blob, so every https
    journey was invisible on the certificate screen while every http check
    beside it reported one. The same verification-free read the http path
    uses — what is on the wire, including the expired and the self-signed,
    which are the ones worth reporting.
    """
    from .checks import _certificate
    return _certificate(monitor.get("target") or "", CERTIFICATE_TIMEOUT)


def _refused_certificate(message):
    text = str(message or "").lower()
    return any(marker in text for marker in _REFUSED)


def _expired(certificate):
    """Whether the certificate that was read has already expired.

    Read from the timestamp rather than a rounded day count, the same rule
    the page applies: a certificate that expired an hour ago rounds to zero
    days, and zero days is "expires today".
    """
    from datetime import datetime, timezone
    moment = (certificate or {}).get("not_after")
    if not moment:
        return False
    try:
        when = datetime.fromisoformat(str(moment))
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when < datetime.now(timezone.utc)


def _verdict(monitor, tls, failure, certificate=None):
    """Whether this journey's navigation completed a verified handshake.

    None for a journey that makes no handshake, False for the waiver and for
    a certificate the browser refused, True otherwise — including a pinned
    one, where the endpoint proved it holds the private key for exactly the
    public key this monitor names.

    With ONE exception, and it is the reason the certificate is passed in:
    `--ignore-certificate-errors-spki-list` waives every certificate error
    for that key, expiry included. Measured against Chromium 151 and the
    lab's :18444, a journey pinned to a certificate that expired on
    2026-08-18 loaded the page and reported `up`. Calling that handshake
    verified would have the browser and the clock disagreeing on one row —
    the expiry chip beside a verdict that says the certificate was good — so
    a pinned run over an expired certificate says False. The expiry itself is
    still read, still shown and still alerted on.
    """
    if not str(monitor.get("target") or "").lower().startswith("https://"):
        return None
    if _mode(tls) == EXPIRY_ONLY or _refused_certificate(failure):
        return False
    if (tls or {}).get("certificate") and _expired(certificate):
        return False
    return True


def _tls_advice(failure, tls):
    """The failure, plus the sentence that names the setting answering it.

    Appended only to a certificate refusal, and never advising anybody to
    turn verification off to hide an expiry — a browser that refuses an
    expired certificate says ERR_CERT_DATE_INVALID, and the sentence for that
    one names the pin, which does not pretend the expiry away: the expiry is
    still read, still shown and still alerted on.
    """
    if not _refused_certificate(failure):
        return failure
    if (tls or {}).get("certificate"):
        return (f"{failure} — the certificate this journey trusts is not the "
                f"one this endpoint presented: a browser matches the "
                f"endpoint's own public key, not the authority that signed "
                f"it.")
    return (f"{failure} — this journey's browser trusts what the image it "
            f"runs in trusts. Paste the certificate this endpoint presents "
            f"and the browser will accept that key and no other, or set the "
            f"check to expiry only.")


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

    tls = monitor.get("tls") or {}
    waive = _mode(tls) == EXPIRY_ONLY
    pins = _pins(tls.get("certificate"))

    try:
        browser = launcher or _chromium
        with browser(ignore_https_errors=waive, certificate_pins=pins) as page:
            failure, shot = _walk(page, steps, plan, secrets, hidden, budget,
                                  clock, waive)
    except ImportError:
        # Reached by a Playwright that is on the path and will not import — a
        # half-installed one, a missing shared object. An agent that has no
        # Playwright at all never gets here: the runner asks before it starts
        # the check and reports nothing, so the journey reads `unknown` rather
        # than this agent's limitation dressed up as a broken site.
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

    # Read before the verdict is decided rather than beside it: a pinned run
    # is only as verified as the clock says, and the clock is in here.
    certificate = _certificate_of(monitor)
    return _result(monitor, started, "down" if failure else "up",
                   _tls_advice(failure or "", tls), _since(clock), plan,
                   screenshot=shot, tls=certificate,
                   handshake_verified=_verdict(monitor, tls, failure,
                                               certificate))


class _chromium:
    """Playwright, opened and closed. Separate so tests can pass their own."""

    def __init__(self, ignore_https_errors=False, certificate_pins=()):
        # Set before anything can fail, so that closing down knows what got
        # as far as existing.
        self._playwright = self._browser = self._context = None
        self._ignore = bool(ignore_https_errors)
        self._pins = tuple(certificate_pins or ())

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        args = ["--disable-dev-shm-usage"]
        if self._pins:
            # A pin, not a blanket. Measured against Chromium 151: a
            # certificate error is ignored only for a chain carrying one of
            # these public keys — the leaf's own key works, the key of the CA
            # that signed it does NOT (still ERR_CERT_AUTHORITY_INVALID), a
            # pin for another host's certificate is refused, and the same pin
            # against a different endpoint is refused. So this is the
            # journey's answer to a private certificate, and a journey behind
            # one may keep its credentials: the endpoint proved it holds the
            # private key for exactly the public key the monitor names.
            args.append("--ignore-certificate-errors-spki-list="
                        + ",".join(self._pins))
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(args=args)
            self._context = self._browser.new_context(
                viewport=VIEWPORT,
                # A journey signs in. Carrying a profile between runs would
                # mean the second run never exercises the login, and the check
                # quietly stops testing the thing it was written for.
                #
                # True only where the monitor says "expiry only" — a blanket
                # waiver, unlike the pin above, which is why the store refuses
                # to let such a journey hold a secret.
                ignore_https_errors=self._ignore)
            return self._context.new_page()
        except BaseException:
            # Python does not call `__exit__` when `__enter__` raises, and
            # `start()` has already spawned the node driver as a child
            # process. So a Chromium that would not launch — no sandbox, no
            # shared library, a full disk — leaked one driver per attempt,
            # every interval, for the life of the agent; and the next attempt
            # on the same pool thread then failed with "Sync API inside the
            # asyncio loop", because the leaked driver poisons that thread.
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *exc):
        for closing in (self._context, self._browser):
            if closing is None:
                continue
            try:
                closing.close()
            except Exception:
                pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                # A browser that will not close is a leaked process, and
                # saying so is the only way anybody finds out before the probe
                # runs out of memory.
                logger.warning("the browser did not shut down cleanly")
        self._playwright = self._browser = self._context = None
        return False


def _walk(page, steps, plan, secrets, hidden, budget, clock, waive=False):
    """Run the steps in order. Returns (failure message, screenshot or None).

    `waive` is the monitor's "expiry only", carried this far for one reason:
    a journey that does not verify sends nothing, and an address written
    `https://svc:P4SS@host/login` is a credential no secret box knows about.
    """
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
            _do(page, step, secrets, timeout, waive)
        except Exception as exc:
            row["status"] = STEP_FAILED
            row["duration_us"] = _since(step_clock)
            row["error"] = _clean(exc, hidden, step.kind)
            return (f"step {row['index']} ({row['description']}): "
                    f"{row['error']}"), _capture(page, steps, hidden)
        row["status"] = STEP_PASSED
        row["duration_us"] = _since(step_clock)
    return None, None


def _do(page, step, secrets, timeout, waive=False):
    """One step. Raises with a sentence somebody can act on."""
    kind = step.kind
    value = resolve(step, secrets)

    if kind == "goto":
        if waive:
            from .checks import _without_userinfo
            # Measured: Chromium answers a 401 challenge with the user name
            # and password from the address it was given, so a journey that
            # does not verify the certificate typed a credential into
            # whatever answered. The store refuses to save one; a row from an
            # older build or a hand-edited one stops here.
            value = _without_userinfo(value)
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
            screenshot=None, tls=None, handshake_verified=None):
    out = {
        "monitor_id": monitor["id"],
        "started_at": started.isoformat(),
        "status": status,
        "duration_us": duration_us,
        "error": error or "",
        "steps": steps,
        # Same two fields an http check reports, so a journey is a row on the
        # certificate screen like any other check rather than a blank.
        "tls": tls,
        "handshake_verified": handshake_verified,
    }
    if screenshot:
        out["screenshot"] = screenshot
    return out
