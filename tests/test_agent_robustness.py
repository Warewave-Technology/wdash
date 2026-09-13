"""
What the agent does when the thing that is wrong is the agent.

Every case here was measured before it was fixed, and every one of them ends
the same way: the probe stops saying anything true about the targets, and
nothing on the page says the probe is the reason.

  * a plain-image agent reported a browser journey DOWN every interval,
    because a journey nobody assigned goes to every agent — a working
    checkout, called broken by the one probe that never looked at it
  * a Chromium that would not launch leaked one Playwright driver per
    attempt, for the life of the agent
  * an http check with `timeout_seconds=1` ran for 20s against a server that
    trickled five bytes at a time, because `requests` bounds the wait for the
    next byte and nothing bounded the whole read
  * a 200 that was a sign-in page rather than JSON ended the process on the
    first poll, after dropping one spooled batch
  * one check that took 5s held the loop — and the flush IS the heartbeat, so
    the agent went `unknown` on the server and took its monitors with it
  * one malformed result from a non-conforming agent aborted the whole batch
    and left the good results' screenshots behind, every retry, for ever
"""

import importlib.machinery
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import select  # noqa: E402

from wdash.agent import checks, runner  # noqa: E402
from wdash.agent.browser import run_journey  # noqa: E402
from wdash.agent.checks import run_check  # noqa: E402
from wdash.agent.runner import Agent  # noqa: E402
from wdash.agent.spool import Spool  # noqa: E402
from wdash.hub.models import UNKNOWN  # noqa: E402
from wdash.hub.query import TimeWindow  # noqa: E402
from wdash.hub.scope import Scope  # noqa: E402
from wdash.store import Store  # noqa: E402
from wdash.store.schema import journey_screenshots, monitor_results  # noqa: E402

#: A real one-pixel PNG, so that a stored screenshot is a stored image.
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000b49444154789c6360000200000500017a5eab3f0000"
    "000049454e44ae426082")

STEPS = [{"kind": "goto", "value": "https://shop.example/"},
         {"kind": "expect_text", "value": "Welcome"}]

_ABSENT = object()


def _now():
    return datetime.now(timezone.utc)


def _spool():
    return os.path.join(tempfile.mkdtemp(), "spool.jsonl")


class _Swapped:
    """Put a value on an object for the block, and put the old one back."""

    def __init__(self, target, name, value):
        self.target, self.name, self.value = target, name, value

    def __enter__(self):
        self.previous = getattr(self.target, self.name)
        setattr(self.target, self.name, self.value)
        return self.value

    def __exit__(self, *exc):
        setattr(self.target, self.name, self.previous)
        return False


class _Modules:
    """Own `playwright` in `sys.modules` for the block, and hand it back."""

    NAMES = ("playwright", "playwright.sync_api")

    def _take(self):
        self.saved = {n: sys.modules.get(n, _ABSENT) for n in self.NAMES}

    def __exit__(self, *exc):
        for name, module in self.saved.items():
            if module is _ABSENT:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
        return False


class _NoPlaywright(_Modules):
    """The plain agent image: `playwright` cannot be imported.

    Blocked in `sys.modules` rather than by patching a flag of our own,
    because that is exactly what `import` and `importlib.util.find_spec` see
    on an image built without it.
    """

    def __enter__(self):
        self._take()
        for name in self.NAMES:
            sys.modules[name] = None
        return self


def _fake_playwright(fail_at=None):
    """A `playwright.sync_api` that fails where asked, and says what closed."""
    closed = []

    class Page:
        url = "https://shop.example/"

        def goto(self, url, **kwargs):
            return None

        def inner_text(self, selector, **kwargs):
            return "Welcome"

    class Context:
        def new_page(self):
            if fail_at == "new_page":
                raise RuntimeError("the page could not be opened")
            return Page()

        def close(self):
            closed.append("context")

    class Browser:
        def new_context(self, **kwargs):
            if fail_at == "new_context":
                raise RuntimeError("the context could not be opened")
            return Context()

        def close(self):
            closed.append("browser")

    class Chromium:
        def launch(self, **kwargs):
            if fail_at == "launch":
                raise RuntimeError("Failed to launch: /dev/shm is too small")
            return Browser()

    class Driver:
        chromium = Chromium()

        def stop(self):
            closed.append("driver")

    module = types.ModuleType("playwright.sync_api")
    module.sync_playwright = lambda: types.SimpleNamespace(start=Driver)
    return module, closed


class _Playwright(_Modules):
    """An agent image that HAS a browser, and a stand-in for the browser."""

    def __init__(self, fail_at=None):
        self.module, self.closed = _fake_playwright(fail_at)

    def __enter__(self):
        self._take()
        parent = types.ModuleType("playwright")
        # A spec, because that is what `find_spec` answers with and what the
        # runner asks for before it starts a journey at all.
        parent.__spec__ = importlib.machinery.ModuleSpec("playwright", None)
        parent.sync_api = self.module
        sys.modules["playwright"] = parent
        sys.modules["playwright.sync_api"] = self.module
        return self


# ---------------------------------------------------------------------------
# A journey on an agent that has no browser
# ---------------------------------------------------------------------------

class _Recorder:
    """Stands in for `run_check` and says what it was asked to run."""

    def __init__(self):
        self.ran = []

    def __call__(self, monitor, session=None):
        self.ran.append(monitor["id"])
        return {"monitor_id": monitor["id"], "status": "up",
                "started_at": _now().isoformat()}


class AJourneyOnAnAgentWithNoBrowserTest(unittest.TestCase):
    """"Nobody looked" is not "it is broken".

    A journey left unassigned runs on EVERY agent, and the plain image is the
    documented default. Reporting `down` from a probe that has no browser is
    the probe's limitation dressed up as a fact about the site — and in a
    plain-only fleet a `monitor_down` rule pages for it every interval.
    """

    MONITORS = [{"id": "journey", "name": "Checkout", "kind": "browser",
                 "interval_seconds": 60, "timeout_seconds": 30,
                 "steps": STEPS},
                {"id": "api", "name": "API", "kind": "http",
                 "target": "https://shop.example/health",
                 "interval_seconds": 60, "timeout_seconds": 5}]

    def _agent(self):
        agent = Agent("http://wdash", "t", spool_path=_spool())
        agent._apply({m["id"]: m for m in self.MONITORS})
        self.addCleanup(agent.close)
        return agent

    def test_nothing_is_reported_for_it(self):
        recorder = _Recorder()
        agent = self._agent()
        with _NoPlaywright(), _Swapped(runner, "run_check", recorder):
            started = agent.run_due(force=True, wait=True)

        self.assertEqual(recorder.ran, ["api"],
                         "an agent with no browser ran the journey")
        self.assertEqual([r["monitor_id"] for r in agent.spool.take(10)],
                         ["api"],
                         "the agent reported a journey it never ran")
        self.assertEqual(started, 2, "the http check did not run either")

    def test_the_agent_says_so_once_rather_than_every_interval(self):
        """A sentence a minute for the life of the pod is a sentence nobody
        reads; one that never appears is a journey nobody can explain."""
        agent = self._agent()
        with _NoPlaywright(), _Swapped(runner, "run_check", _Recorder()):
            with self.assertLogs("wdash.agent.runner", "WARNING") as logged:
                for _ in range(3):
                    agent.run_due(force=True, wait=True)
        said = [line for line in logged.output if "browser image" in line]
        self.assertEqual(len(said), 1, logged.output)
        self.assertIn("Checkout", said[0])

    def test_an_agent_with_a_browser_still_runs_it(self):
        recorder = _Recorder()
        agent = self._agent()
        with _Playwright(), _Swapped(runner, "run_check", recorder):
            agent.run_due(force=True, wait=True)
        self.assertEqual(sorted(recorder.ran), ["api", "journey"])


class TheJourneyReadsAsUnknownTest(unittest.TestCase):
    """The same thing from the other end: the real endpoints, the real store,
    and the row a person sees."""

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "agent-robustness"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        _, self.token = self.app.store.agents.create("plain-probe")
        self.app.store.monitors.create(
            name="Checkout journey", kind="browser", target="",
            interval_seconds=60, timeout_seconds=30, steps=STEPS)

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _through_the_client(self):
        """A session that speaks to the real routes through the test client."""
        client, token = self.client, self.token

        class Answer:
            def __init__(self, reply):
                self.status_code = reply.status_code
                self._reply = reply

            def json(self):
                return self._reply.get_json()

        class Session:
            headers = {}

            @staticmethod
            def _headers():
                return {"Authorization": f"Bearer {token}",
                        "X-Agent-Version": "test"}

            def get(self, url, timeout=None, verify=None):
                return Answer(client.get(url.replace("http://wdash", ""),
                                         headers=self._headers()))

            def post(self, url, timeout=None, verify=None, json=None):
                return Answer(client.post(url.replace("http://wdash", ""),
                                          headers=self._headers(), json=json))

        return Session()

    def test_it_is_unknown_and_pages_nobody(self):
        from wdash.alerts.runner import observe
        from wdash.hub.adapters.store_monitors import StoreMonitorSource

        agent = Agent("http://wdash", self.token, spool_path=_spool(),
                      session=self._through_the_client())
        self.addCleanup(agent.close)
        with _NoPlaywright():
            self.assertTrue(agent.fetch_config())
            self.assertEqual([m["kind"] for m in agent._monitors.values()],
                             ["browser"],
                             "the journey never reached the agent")
            agent.run_due(force=True, wait=True)
            agent.flush()

        self.assertEqual(self.app.store.results.count(), 0,
                         "the agent reported a journey it never ran")
        source = StoreMonitorSource(self.app.store)
        rows = source.monitors(TimeWindow.of("1h"),
                               Scope(containers=("*",))).monitors
        self.assertEqual([(r.name, r.status) for r in rows],
                         [("Checkout journey", UNKNOWN)])
        self.assertIn("no agent has reported", rows[0].error)

        rule = {"id": "r1", "name": "down", "kind": "monitor_down",
                "selector": {}}
        seen = observe(rule, source, self.app.store, TimeWindow.of("1h"),
                       _now())
        self.assertEqual([o.subject for o in seen.observations if o.bad], [],
                         "a working checkout paged somebody")
        # The listing is complete: nothing failed, the journey is simply
        # unknown. A rule that sees an INCOMPLETE listing holds its state
        # instead, which would hide this if it were wrong.
        self.assertTrue(seen.complete, seen.warnings)


# ---------------------------------------------------------------------------
# A browser that will not start
# ---------------------------------------------------------------------------

class ABrowserThatWillNotStartTest(unittest.TestCase):
    """Python does not call `__exit__` when `__enter__` raises.

    So every handle the failed start-up had already opened stayed open. With
    a real Playwright and `PLAYWRIGHT_BROWSERS_PATH` pointed at an empty
    directory, the node driver children counted after each attempt and a
    garbage collection went ['16132'] -> ['16132','16134'] ->
    ['16132','16134','16136']; and the second attempt on one thread failed
    with "Sync API inside the asyncio loop", because the leaked driver
    poisons the thread the next check runs on.
    """

    MONITOR = {"id": "m1", "timeout_seconds": 30, "steps": STEPS}

    def test_the_driver_is_stopped_when_the_launch_fails(self):
        with _Playwright("launch") as playwright:
            result = run_journey(self.MONITOR)
        self.assertEqual(result["status"], "down")
        self.assertIn("browser could not start", result["error"])
        self.assertEqual(playwright.closed, ["driver"],
                         "the Playwright driver was left running")

    def test_the_browser_is_closed_when_the_context_fails(self):
        with _Playwright("new_context") as playwright:
            result = run_journey(self.MONITOR)
        self.assertIn("browser could not start", result["error"])
        self.assertEqual(playwright.closed, ["browser", "driver"])

    def test_the_context_is_closed_when_the_page_fails(self):
        with _Playwright("new_page") as playwright:
            result = run_journey(self.MONITOR)
        self.assertIn("browser could not start", result["error"])
        self.assertEqual(playwright.closed, ["context", "browser", "driver"])

    def test_a_run_that_works_still_closes_everything(self):
        with _Playwright() as playwright:
            result = run_journey(self.MONITOR)
        self.assertEqual(result["status"], "up", result["error"])
        self.assertEqual(playwright.closed, ["context", "browser", "driver"])


# ---------------------------------------------------------------------------
# A response that never finishes
# ---------------------------------------------------------------------------

class _Trickle(BaseHTTPRequestHandler):
    """Five bytes every 50ms, for ten seconds — each inside any per-read
    timeout, and never an end."""

    protocol_version = "HTTP/1.1"
    stop = threading.Event()

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/quick":
            body = b"hello there"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        end = time.monotonic() + 10
        try:
            while time.monotonic() < end and not self.stop.is_set():
                self.wfile.write(b"5\r\nhello\r\n")
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(b"0\r\n\r\n")
        except Exception:
            pass


class AResponseThatNeverFinishesTest(unittest.TestCase):
    """`requests`' timeout bounds the wait for the NEXT byte, not the read.

    Measured before the fix against a server sending five bytes every 0.2s,
    with `timeout_seconds=1`: still running at 6.0s, finished at 20.2s when
    the server gave up, `status=up`, `duration_ms=20150`, no error. A server
    that never stopped would never have returned — and the agent's round, its
    flush and its heartbeat waited behind it.
    """

    class _Server(ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            # The client hanging up in the middle of the body is the whole
            # point of this server; it is not an error to report.
            pass

    @classmethod
    def setUpClass(cls):
        from tests.support import serve_in_background
        _Trickle.stop = threading.Event()
        cls.server = serve_in_background(cls._Server(("127.0.0.1", 0),
                                                     _Trickle))
        cls.address = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        _Trickle.stop.set()
        cls.server.shutdown()
        cls.server.server_close()

    def _check(self, path="/", patience=8, **monitor):
        """Run a check on a thread, so a check that never ends fails the test
        rather than hanging the suite."""
        options = {"id": "m", "kind": "http", "target": self.address + path,
                   "timeout_seconds": 1}
        options.update(monitor)
        box = {}
        clock = time.monotonic()
        thread = threading.Thread(
            target=lambda: box.setdefault("result", run_check(options)),
            daemon=True)
        thread.start()
        thread.join(patience)
        self.assertFalse(thread.is_alive(),
                         f"the check was still running after {patience}s")
        return box["result"], time.monotonic() - clock

    def test_a_trickling_body_ends_at_the_timeout(self):
        result, took = self._check()
        self.assertEqual(result["status"], "down")
        self.assertEqual(result["error"],
                         "the response did not finish within 1s")
        self.assertEqual(result["http_status"], 200)
        self.assertLess(took, 5, "it ran well past the monitor's timeout")

    def test_a_body_assertion_does_not_wait_for_ever_either(self):
        result, took = self._check(assertions={"body_contains": "NEVER"})
        self.assertEqual(result["status"], "down")
        self.assertEqual(result["error"],
                         "the response did not finish within 1s")
        self.assertLess(took, 5)

    def test_a_response_that_finishes_is_still_up(self):
        """The deadline has to bound the trickle without failing the ordinary
        answer, which is the whole difficulty."""
        result, _ = self._check(path="/quick")
        self.assertEqual(result["status"], "up", result["error"])
        self.assertEqual(result["error"], "")

    def test_a_body_assertion_still_reads_the_body(self):
        result, _ = self._check(path="/quick",
                                assertions={"body_contains": "hello"})
        self.assertEqual(result["status"], "up", result["error"])

    def test_an_overrun_still_says_which_certificate(self):
        """The overrun path returned without `tls`, and `_to_monitor` takes
        the certificate from the LATEST result — so an https monitor that
        overran lost its certificate from the page for as long as it kept
        overrunning. The rule the same function states forty lines above is
        that a monitor which goes down and cannot say which certificate has
        told you nothing."""
        certificate = {"common_name": "shop.example", "issuer": "Lab CA"}
        with _Swapped(checks, "_certificate",
                      lambda url, timeout: dict(certificate)):
            result, _ = self._check()
        self.assertEqual(result["status"], "down")
        self.assertEqual(result.get("tls"), certificate,
                         "the TLS column empties while the target overruns")


# ---------------------------------------------------------------------------
# An answer that is not JSON
# ---------------------------------------------------------------------------

class _SignInPage:
    """What an authenticating proxy answers: 200, and HTML."""

    status_code = 200

    @staticmethod
    def json():
        raise ValueError("Expecting value: line 1 column 1 (char 0)")


class _JsonList:
    """A proxy that answers JSON, and not an object."""

    status_code = 200

    @staticmethod
    def json():
        return []


class _ProxySession:
    def __init__(self, answer=_SignInPage):
        self.answer = answer
        self.gets = 0
        self.posts = 0

    def get(self, url, **kwargs):
        self.gets += 1
        return self.answer()

    def post(self, url, json=None, **kwargs):
        self.posts += 1
        return self.answer()


class AnAnswerThatIsNotJsonTest(unittest.TestCase):
    """A 200 is not proof that WDash answered it.

    An authenticating proxy redirects /api/agent/* to its own sign-in page,
    `requests` follows the redirect, and the agent reads a 200 of HTML.
    Measured before the fix: `fetch_config` raised JSONDecodeError, `flush`
    raised it too — after dropping the batch, so 3 pending results became 0 —
    and `run_forever` ended 0.0s after it started.
    """

    def _agent(self, session):
        agent = Agent("http://wdash", "t", spool_path=_spool(),
                      session=session)
        self.addCleanup(agent.close)
        return agent

    def _results(self, count=3):
        return [{"monitor_id": f"m{n}", "status": "down",
                 "started_at": _now().isoformat()} for n in range(count)]

    def test_the_configuration_request_survives_it(self):
        for answer in (_SignInPage, _JsonList):
            with self.subTest(answer=answer.__name__):
                agent = self._agent(_ProxySession(answer))
                with self.assertLogs("wdash.agent.runner", "WARNING"):
                    self.assertFalse(agent.fetch_config())

    def test_the_batch_stays_spooled(self):
        """It is not an acceptance. Dropping it lost the results of the
        outage the agent was there to measure."""
        for answer in (_SignInPage, _JsonList):
            with self.subTest(answer=answer.__name__):
                agent = self._agent(_ProxySession(answer))
                agent.spool.add(self._results())
                with self.assertLogs("wdash.agent.runner", "WARNING"):
                    self.assertEqual(agent.flush(), 0)
                self.assertEqual(agent.spool.pending(), 3)

    def test_the_agent_carries_on(self):
        session = _ProxySession()
        agent = self._agent(session)
        agent.spool.add(self._results())
        raised = {}

        def go():
            try:
                agent.run_forever()
            except BaseException as exc:
                raised["it"] = exc

        with _Swapped(runner, "FLUSH_INTERVAL", 0):
            thread = threading.Thread(target=go, daemon=True)
            thread.start()
            deadline = time.monotonic() + 10
            while session.posts < 2 and time.monotonic() < deadline:
                time.sleep(0.05)
            agent.stop()
            thread.join(10)

        self.assertNotIn("it", raised,
                         f"the agent process ended: {raised.get('it')!r}")
        self.assertFalse(thread.is_alive())
        self.assertGreaterEqual(session.posts, 2,
                                "the agent stopped trying after one answer")
        self.assertEqual(agent.spool.pending(), 3, "the results were lost")


class _UnusableConfigSession:
    """Answers JSON, and answers it with a monitor that has no id.

    A proxy that rewrites bodies, a half-written answer, a server a version
    ahead: `_apply` raises KeyError on it, and nothing between that and the
    process exit used to catch anything. The version moves every time, so the
    agent really does try to adopt it on every poll.
    """

    class _Answer:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload

        def json(self):
            return self._payload

    def __init__(self):
        self.gets = 0
        self.posts = 0

    def get(self, url, **kwargs):
        self.gets += 1
        return self._Answer({"version": f"v{self.gets}",
                             "monitors": [{"name": "a monitor with no id"}]})

    def post(self, url, json=None, **kwargs):
        self.posts += 1
        return self._Answer({"accepted": len(json["results"])})


class AnAnswerTheAgentCannotUseTest(unittest.TestCase):
    """One bad answer is a lost round, not a lost agent.

    `__main__` calls `run_forever` with no try of its own, so anything that
    escaped the loop ended the process. In Kubernetes the pod restarts, the
    emptyDir spool survives, and it crash-loops on the same answer — while
    every monitor it runs goes `unknown`.
    """

    def _run_briefly(self, agent, session, wanted):
        raised = {}

        def go():
            try:
                agent.run_forever()
            except BaseException as exc:
                raised["it"] = exc

        with _Swapped(runner, "CONFIG_INTERVAL", 0), \
                _Swapped(runner, "FLUSH_INTERVAL", 0):
            thread = threading.Thread(target=go, daemon=True)
            thread.start()
            deadline = time.monotonic() + 10
            while not wanted(session) and time.monotonic() < deadline:
                time.sleep(0.05)
            agent.stop()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        return raised

    def test_the_agent_keeps_checking_and_reporting(self):
        session = _UnusableConfigSession()
        agent = Agent("http://wdash", "t", spool_path=_spool(),
                      session=session)
        self.addCleanup(agent.close)
        agent.spool.add([{"monitor_id": "m1", "status": "up",
                          "started_at": _now().isoformat()}])
        raised = self._run_briefly(
            agent, session, lambda s: s.gets >= 2 and s.posts >= 1)

        self.assertNotIn("it", raised,
                         f"the agent process ended: {raised.get('it')!r}")
        self.assertGreaterEqual(session.gets, 2,
                                "the agent stopped asking for configuration")
        self.assertGreaterEqual(session.posts, 1,
                                "the agent stopped reporting what it had")
        self.assertEqual(agent.spool.pending(), 0,
                         "the results it already had never went")


# ---------------------------------------------------------------------------
# One slow check
# ---------------------------------------------------------------------------

class _ConfigSession:
    """Answers the two endpoints and counts the deliveries."""

    class _Answer:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload

        def json(self):
            return self._payload

    def __init__(self, monitors):
        self.monitors = monitors
        self.posts = 0

    def get(self, url, **kwargs):
        return self._Answer({"version": "v1", "monitors": self.monitors})

    def post(self, url, json=None, **kwargs):
        self.posts += 1
        return self._Answer({"accepted": len(json["results"])})


class OneSlowCheckTest(unittest.TestCase):
    """The round used to end together.

    `run_due` waited for its pool and `run_forever` waited for `run_due`, so
    the configuration poll, the flush and the stop check all queued behind the
    slowest check in the round. Measured with a 5s check beside a 1s one:
    `fast ran at: [0.0, 6.0, 11.5]`, `flushes (heartbeats) at: [11.0, 16.5]`,
    and `stop()` at 12.5s was obeyed at 16.5s. The flush is what writes
    `last_seen_at`, and an agent five minutes quiet puts every monitor it runs
    into `unknown`.
    """

    MONITORS = [{"id": "fast", "name": "fast", "kind": "http",
                 "interval_seconds": 1},
                {"id": "slow", "name": "slow", "kind": "http",
                 "interval_seconds": 1}]

    def test_it_does_not_hold_up_the_others(self):
        release = threading.Event()
        started = []

        def check(monitor, session=None):
            started.append(monitor["id"])
            if monitor["id"] == "slow":
                release.wait(20)
            return {"monitor_id": monitor["id"], "status": "up",
                    "started_at": _now().isoformat()}

        session = _ConfigSession(self.MONITORS)
        agent = Agent("http://wdash", "t", spool_path=_spool(),
                      session=session)
        thread = threading.Thread(target=agent.run_forever, daemon=True)
        try:
            with _Swapped(runner, "run_check", check), \
                    _Swapped(runner, "FLUSH_INTERVAL", 0):
                thread.start()
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and not (
                        started.count("fast") >= 3 and session.posts >= 2):
                    time.sleep(0.05)

                self.assertGreaterEqual(
                    started.count("fast"), 3,
                    f"the fast check ran {started.count('fast')} time(s) "
                    f"while one slow check was in flight")
                self.assertGreaterEqual(
                    session.posts, 2,
                    "the agent did not report — and the report is the "
                    "heartbeat — while one slow check was in flight")
                self.assertEqual(
                    started.count("slow"), 1,
                    "the slow check was started again before it had "
                    "finished its last turn")
        finally:
            release.set()
            agent.stop()
            thread.join(15)
        self.assertFalse(thread.is_alive(), "stop() waited for the round")

    def test_once_still_waits_for_every_check(self):
        """`--once` has to report what it ran, so it is the one caller that
        waits for the round."""
        def check(monitor, session=None):
            time.sleep(0.2)
            return {"monitor_id": monitor["id"], "status": "up",
                    "started_at": _now().isoformat()}

        agent = Agent("http://wdash", "t", spool_path=_spool())
        self.addCleanup(agent.close)
        agent._apply({m["id"]: m for m in self.MONITORS})
        with _Swapped(runner, "run_check", check):
            ran = agent.run_due(force=True, wait=True)
        self.assertEqual(ran, 2)
        self.assertEqual(agent.spool.pending(), 2,
                         "--once would flush before its checks had answered")


# ---------------------------------------------------------------------------
# A result the store cannot read
# ---------------------------------------------------------------------------

class AResultTheStoreCannotReadTest(unittest.TestCase):
    """Only a non-conforming agent sends these — a modified one, or somebody
    holding a stolen token — and it must cost that result and nothing else.

    Measured before the fix with [good+png, good+png, bad]: a bad
    `started_at` raised ValueError, a dictionary `error` raised KeyError on
    the slice, a list `monitor_id` TypeError, a result that was not a
    dictionary AttributeError. Each attempt stored 0 results and 2 more
    screenshots — (0,2), (0,4) ... (0,16) — because the images were kept
    before the rows were built, and the agent retried the batch for ever.
    """

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.store = Store.open(f"sqlite:///{self.database}")
        self.agent, _ = self.store.agents.create("probe")
        self.monitor = self.store.monitors.create(
            name="API", kind="http", target="https://shop.example/health",
            interval_seconds=60, timeout_seconds=5)

    def tearDown(self):
        self.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _good(self, screenshot=True, **extra):
        import base64
        out = {"monitor_id": self.monitor["id"], "status": "down",
               "started_at": _now().isoformat(), "duration_us": 1200,
               "error": "it answered 500"}
        if screenshot:
            out["screenshot"] = {
                "base64": base64.b64encode(PNG).decode("ascii"),
                "content_type": "image/png"}
        out.update(extra)
        return out

    #: Results nothing can be made of. Each one raised out of `record` and
    #: took the whole batch with it.
    def _unreadable(self):
        return {
            "a started_at that is not a time":
                self._good(started_at="soon"),
            "a monitor_id that is a list":
                self._good(monitor_id=[self.monitor["id"]]),
            "a result that is not a dictionary": "down",
            "a result that is a number": 7,
        }

    def _results(self):
        with self.store.engine.connect() as connection:
            return connection.execute(
                select(monitor_results).order_by(
                    monitor_results.c.id)).mappings().all()

    def _screenshots(self):
        with self.store.engine.connect() as connection:
            return connection.execute(
                select(journey_screenshots)).mappings().all()

    def test_one_unreadable_result_costs_only_itself(self):
        for label, bad in self._unreadable().items():
            with self.subTest(bad=label):
                before = self.store.results.count()
                with self.assertLogs("wdash.store.monitoring", "WARNING"):
                    stored = self.store.results.record(
                        self.agent["id"], [self._good(), self._good(), bad])
                self.assertEqual(stored, 2, "the batch was refused whole")
                self.assertEqual(self.store.results.count(), before + 2)

    def test_no_screenshot_is_left_without_its_result(self):
        for label, bad in self._unreadable().items():
            with self.subTest(bad=label):
                with self.assertLogs("wdash.store.monitoring", "WARNING"):
                    self.store.results.record(
                        self.agent["id"], [self._good(), self._good(), bad])
        kept = {row["id"] for row in self._screenshots()}
        referenced = {row["screenshot_id"] for row in self._results()
                      if row["screenshot_id"]}
        self.assertTrue(kept, "no screenshot was stored at all")
        self.assertEqual(kept - referenced, set(),
                         "images were kept for results that never arrived")

    def test_a_field_that_cannot_be_read_costs_the_field(self):
        """The measurement is the status and the time it was taken. Losing
        the whole result over an http status nobody can read would throw away
        the part somebody needs."""
        stored = self.store.results.record(self.agent["id"], [self._good(
            screenshot=False, error={"why": "no"}, http_status={"code": 500},
            duration_us="ages")])
        self.assertEqual(stored, 1)
        row = self._results()[0]
        self.assertEqual(row["status"], "down")
        self.assertIsNone(row["http_status"])
        self.assertIsNone(row["duration_us"])
        self.assertIn("why", row["error"])

    def test_a_good_batch_is_untouched(self):
        stored = self.store.results.record(
            self.agent["id"], [self._good(), self._good()])
        self.assertEqual(stored, 2)
        rows = self._results()
        self.assertEqual([r["status"] for r in rows], ["down", "down"])
        self.assertEqual(rows[0]["error"], "it answered 500")
        self.assertEqual(rows[0]["duration_us"], 1200)
        self.assertEqual(len(self._screenshots()), 2)

    def test_a_number_too_big_for_its_column_costs_the_field(self):
        """`10**30` is legal JSON and the right TYPE, so the type check passed
        it and the INSERT raised — OverflowError on SQLite, DataError on
        Postgres, neither of them in the guard and neither raised while the
        row was being built. Measured through the real endpoint: HTTP 500,
        `results=0 screenshots=3`, then 6, 9, 12, 15 over five retries."""
        for label, bad in {
                "a duration of 10**30": {"duration_us": 10 ** 30},
                "a duration of -10**30": {"duration_us": -10 ** 30},
                "an http status of 10**30": {"http_status": 10 ** 30},
                "an http status nobody can answer with": {"http_status": 9999},
                "a duration that is an infinity": {"duration_us":
                                                   float("inf")}}.items():
            with self.subTest(bad=label):
                before = self.store.results.count()
                with self.assertLogs("wdash.store.monitoring", "WARNING"):
                    stored = self.store.results.record(
                        self.agent["id"],
                        [self._good(), self._good(), self._good(**bad)])
                self.assertEqual(stored, 3, "the batch was refused whole")
                self.assertEqual(self.store.results.count(), before + 3)
                row = self._results()[-1]
                for field in bad:
                    self.assertIsNone(row[field],
                                      f"{field} reached the column")

        kept = {row["id"] for row in self._screenshots()}
        referenced = {row["screenshot_id"] for row in self._results()
                      if row["screenshot_id"]}
        self.assertEqual(kept - referenced, set(),
                         "images were kept for results that never arrived")

    def test_a_field_that_cannot_be_read_is_said_so(self):
        """Every other discard in `record` logs — an unreadable result, a
        monitor this agent does not run, an oversized certificate. A duration
        that arrived as "ages" reached the page as an empty cell with nothing
        anywhere saying why."""
        with self.assertLogs("wdash.store.monitoring", "WARNING") as log:
            self.store.results.record(self.agent["id"], [self._good(
                screenshot=False, duration_us="ages")])
        said = "\n".join(log.output)
        self.assertIn("duration_us", said)
        self.assertIn(self.monitor["id"], said)

    def test_no_screenshot_is_stored_when_the_rows_cannot_be(self):
        """The other half of the same defect: the images went in FIRST, on a
        savepoint that does not roll back with the block it is in. Measured
        on SQLite — the store the default installation runs — a row written
        inside `connection.begin_nested()` survived the rollback of the
        enclosing `engine.begin()`, so every retry of a batch that could not
        store left another copy of its pictures behind.
        """
        from wdash.store import monitoring

        real = monitoring.insert

        def refusing(table, *args, **kwargs):
            if table is monitor_results:
                raise RuntimeError("the results could not be stored")
            return real(table, *args, **kwargs)

        with _Swapped(monitoring, "insert", refusing):
            with self.assertRaises(RuntimeError):
                self.store.results.record(self.agent["id"],
                                          [self._good(), self._good()])

        self.assertEqual(self.store.results.count(), 0)
        self.assertEqual([dict(r) for r in self._screenshots()], [],
                         "images outlived the transaction their rows never "
                         "reached")

    def test_a_certificate_is_kept_and_a_preposterous_one_is_not(self):
        """`_steps_of` trims the steps; nothing trimmed the certificate, and a
        5,000,000-byte `tls` value was stored whole — its JSON read back at
        5,000,012 bytes."""
        certificate = {"common_name": "shop.example", "issuer": "Lab CA",
                       "key_algorithm": "RSA", "key_size": 2048}
        self.store.results.record(self.agent["id"], [
            self._good(screenshot=False, tls=certificate)])
        self.assertEqual(self._results()[0]["tls"], certificate)

        with self.assertLogs("wdash.store.monitoring", "WARNING"):
            self.store.results.record(self.agent["id"], [
                self._good(screenshot=False,
                           tls={"common_name": "x" * 5_000_000})])
        kept = self._results()[1]["tls"]
        self.assertIsNone(kept, f"{len(json.dumps(kept or {}))} bytes stored")


# ---------------------------------------------------------------------------
# A redirect chain, and a body that arrives late
# ---------------------------------------------------------------------------

class _Slow(BaseHTTPRequestHandler):
    """Slow hops, and one answer that completes just past the deadline.

    `/hop/N` waits HOP seconds and then redirects to `/hop/N-1`; `/hop/0`
    answers. `/late` sends its headers after 0.8s and its four bytes 0.5s
    after that — inside any per-read timeout, and over a 1s budget for the
    check as a whole. `/toslow` is one quick hop to an answer that takes
    three seconds, and `/tail` sends its whole body early and the end of the
    stream late.
    """

    protocol_version = "HTTP/1.1"
    HOP = 0.3

    def log_message(self, *args):
        pass

    def _answer(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/hop/"):
            time.sleep(self.HOP)
            left = int(self.path.rsplit("/", 1)[1])
            if left:
                self.send_response(302)
                self.send_header("Location", f"/hop/{left - 1}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._answer(b"arrived")
            return
        if self.path == "/late":
            time.sleep(0.8)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "4")
            self.end_headers()
            time.sleep(0.5)
            self.wfile.write(b"done")
            return
        if self.path == "/toslow":
            time.sleep(self.HOP)
            self.send_response(302)
            self.send_header("Location", "/slow")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/slow":
            time.sleep(3)
            self._answer(b"eventually")
            return
        if self.path == "/tail":
            # The body arrives early and the END of the stream arrives late:
            # the read loop never has to cut anything off, and the exchange
            # is still over its budget.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            time.sleep(0.5)
            self.wfile.write(b"4\r\ndone\r\n")
            self.wfile.flush()
            time.sleep(0.8)
            self.wfile.write(b"0\r\n\r\n")
            return
        self._answer(b"arrived")


class _SlowServerTest(unittest.TestCase):
    """One server for both, started once."""

    class _Server(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address):
            pass

    @classmethod
    def setUpClass(cls):
        from tests.support import serve_in_background
        cls.server = serve_in_background(cls._Server(("127.0.0.1", 0), _Slow))
        cls.address = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _check(self, path, patience=8, **monitor):
        options = {"id": "m", "kind": "http", "target": self.address + path,
                   "timeout_seconds": 1}
        options.update(monitor)
        box = {}
        clock = time.monotonic()
        thread = threading.Thread(
            target=lambda: box.setdefault("result", run_check(options)),
            daemon=True)
        thread.start()
        thread.join(patience)
        self.assertFalse(thread.is_alive(),
                         f"the check was still running after {patience}s")
        return box["result"], time.monotonic() - clock


class ARedirectChainTest(_SlowServerTest):
    """The timeout was a deadline for the body and a per-hop figure for
    everything before it.

    `_get_following` handed every hop the whole `timeout_seconds`, so a check
    could spend (MAX_REDIRECTS + 1) x timeout before the body read even
    started — and a target that writes its own Location headers chooses that
    multiplier itself. Measured at the base commit against ten redirects of
    0.8s each with `timeout_seconds=1`: the check returned after 8.9s.
    """

    def test_a_chain_of_redirects_ends_at_the_timeout(self):
        result, took = self._check("/hop/10")
        self.assertEqual(result["status"], "down", result["error"])
        self.assertLess(took, 2.0,
                        f"ten hops of {_Slow.HOP}s ran {took:.1f}s against a "
                        f"1s timeout")
        self.assertRegex(result["error"], "within 1s|timed out")

    def test_a_spent_budget_stops_the_chain_asking(self):
        """The deciding condition on its own, without the timing: a chain
        with nothing left of its budget must not make another request."""
        import requests
        with requests.Session() as client:
            with self.assertRaises(checks._Overran):
                checks._get_following(client, self.address + "/hop/3", {},
                                      None, None, time.monotonic() - 1)

    def test_one_hop_cannot_spend_more_than_is_left(self):
        """The budget has to reach the hop itself, not only the loop around
        it: one redirect to an answer that takes three seconds used to be
        three seconds of a one-second check."""
        result, took = self._check("/toslow")
        self.assertEqual(result["status"], "down", result["error"])
        self.assertLess(took, 2.0,
                        f"one hop to a 3s answer took {took:.1f}s against a "
                        f"1s timeout")

    def test_a_redirect_is_still_followed(self):
        """The hop budget must not stop a monitor following the one hop
        nearly every site makes."""
        result, _ = self._check("/hop/1", timeout_seconds=5,
                                assertions={"body_contains": "arrived"})
        self.assertEqual(result["status"], "up", result["error"])


class ABodyThatArrivesLateTest(_SlowServerTest):
    """"The response did not finish within 1s" about a response that
    finished.

    The deadline is checked after a chunk is read, so an answer whose last
    chunk landed past it was reported as unfinished when it was merely late.
    Measured at the base commit: a complete 200 whose four-byte body was fully
    read came back as `down`, "the response did not finish within 1s".
    """

    def test_a_late_answer_is_said_to_be_late_rather_than_unfinished(self):
        result, took = self._check("/late")
        self.assertEqual(result["status"], "down", "over its budget is down")
        self.assertRegex(result["error"],
                         r"^the response took \d+ ms, over the 1s timeout$")
        self.assertEqual(result["http_status"], 200)
        self.assertLess(took, 4)

    def test_a_body_that_ended_by_itself_can_still_be_late(self):
        """The read loop never had to cut this one off — the body was all
        there early and the end of the stream came late — so the deadline
        has to be asked about after the loop as well as inside it."""
        result, took = self._check("/tail")
        self.assertEqual(result["status"], "down", "over its budget is down")
        self.assertRegex(result["error"],
                         r"^the response took \d+ ms, over the 1s timeout$")
        self.assertLess(took, 3)

    def test_an_answer_inside_the_budget_is_still_up(self):
        result, _ = self._check("/hop/0", timeout_seconds=5)
        self.assertEqual(result["status"], "up", result["error"])
        self.assertEqual(result["error"], "")


# ---------------------------------------------------------------------------
# A check that lands while a delivery is in flight
# ---------------------------------------------------------------------------

class _SlowDelivery:
    """A server that takes half a second to accept a batch."""

    class _Answer:
        def __init__(self, count):
            self.status_code = 200
            self._count = count

        def json(self):
            return {"accepted": self._count}

    def __init__(self):
        self.delivered = []

    def post(self, url, json=None, **kwargs):
        self.delivered.extend(r["monitor_id"] for r in json["results"])
        time.sleep(0.5)
        return self._Answer(len(json["results"]))

    def get(self, url, **kwargs):
        raise AssertionError("this test does not poll for configuration")


class ASpoolThatMovesDuringADeliveryTest(unittest.TestCase):
    """`drop` counted from the front, and the front moves.

    A check now spools on its own thread (that is what stopped one slow
    monitor holding the heartbeat), so an append can land while the POST is in
    flight — and an append that overflows the spool trims the OLDEST. The
    `drop(len(batch))` that followed then ate that many from the NEW front:
    results that had never been sent, while the log said it was dropping the
    oldest. In production this needs a full spool, which is recovery from
    exactly the long outage the spool exists for.

    Measured before the fix with a spool of 20 at its limit, a POST that took
    0.5s and five results added 0.2s in: `NEVER sent and no longer spooled:
    [new0, new1, new2, new3, new4]`.
    """

    def test_a_result_added_during_a_delivery_is_not_dropped_unsent(self):
        path = _spool()
        agent = Agent("http://wdash", "t", spool_path=path,
                      session=_SlowDelivery())
        agent.spool = Spool(path, limit=20)
        agent.spool.add([{"monitor_id": f"old{n}", "status": "up"}
                         for n in range(20)])

        accepted = []
        sender = threading.Thread(
            target=lambda: accepted.append(agent.flush()), daemon=True)
        sender.start()
        time.sleep(0.2)
        with self.assertLogs("wdash.agent.spool", "WARNING"):
            agent.spool.add([{"monitor_id": f"new{n}", "status": "up"}
                             for n in range(5)])
        sender.join(10)
        self.assertFalse(sender.is_alive(), "the delivery never returned")

        delivered = set(agent._session.delivered)
        left = [r["monitor_id"] for r in agent.spool.take(100)]
        self.assertEqual(accepted, [20])
        self.assertEqual(
            [m for m in left if m in delivered], [],
            "a result the server took is still spooled and will be sent twice")
        self.assertEqual(
            left, [f"new{n}" for n in range(5)],
            "results measured during the delivery were dropped without ever "
            "being sent")


# ---------------------------------------------------------------------------
# Stopping while a check is still running
# ---------------------------------------------------------------------------

class AStopWithACheckInFlightTest(unittest.TestCase):
    """`close()` said the running checks were "abandoned, not waited for".

    They are not: a pool's worker threads are not daemons and the interpreter
    joins them on the way out, so `shutdown(wait=False)` returns at once and
    the process then blocks until the slowest check in flight finishes — up
    to MAX_JOURNEY_TIMEOUT for a journey, well past a container's grace
    period. Measured with one 5s check in flight: `close()` returned in 0.00s,
    the interpreter exited 4.8s later. That is the comment an operator reads
    while looking at a pod that will not stop.
    """

    def test_the_checks_that_hold_the_process_are_named(self):
        release = threading.Event()
        self.addCleanup(release.set)
        running = threading.Event()

        def check(monitor, session=None):
            running.set()
            release.wait(20)
            return {"monitor_id": monitor["id"], "status": "up",
                    "started_at": _now().isoformat()}

        agent = Agent("http://wdash", "t", spool_path=_spool())
        agent._apply({"j": {"id": "j", "name": "Checkout journey",
                            "kind": "http", "interval_seconds": 1}})
        with _Swapped(runner, "run_check", check):
            agent.run_due(force=True)
            self.assertTrue(running.wait(5), "the check never started")
            clock = time.monotonic()
            with self.assertLogs("wdash.agent.runner", "WARNING") as log:
                agent.close()
            took = time.monotonic() - clock

        self.assertLess(took, 1.0, "close() waited for the check")
        self.assertIn("Checkout journey", "\n".join(log.output),
                      "nothing said what the process is waiting for")


# ---------------------------------------------------------------------------
# A check that hangs
# ---------------------------------------------------------------------------

class ACheckThatStoppedComingBackTest(unittest.TestCase):
    """The agent's heartbeat says the AGENT is alive, not that a check ran.

    Checks now run on threads of their own, which is what keeps one slow
    monitor from holding the heartbeat — and it means a check that hangs
    leaves the rest of the agent reporting normally. `agent['stale']` was the
    only freshness signal in the row, so the monitors page went on showing the
    last result as the CURRENT status for as long as the check hung.

    Measured at the implementer's commit with real endpoints and a check that
    answered once and then hung: `check started 2 time(s); the 2nd one is
    still hanging / agent last_seen_at: 23:43:14 stale=False / page row: API
    status=up checked_at=23:43:13 error=''`. The only notice was one line in
    the agent's own log.
    """

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.store = Store.open(f"sqlite:///{self.database}")
        self.agent, _ = self.store.agents.create("probe")
        self.monitor = self.store.monitors.create(
            name="API", kind="http", target="https://shop.example/health",
            interval_seconds=60, timeout_seconds=5)

    def tearDown(self):
        self.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _row(self, ago_seconds, window=None):
        """The page row for a monitor whose only result is that old, from an
        agent that is heartbeating normally."""
        from datetime import timedelta

        from wdash.hub.adapters.store_monitors import StoreMonitorSource

        started = _now() - timedelta(seconds=ago_seconds)
        self.store.results.record(self.agent["id"], [
            {"monitor_id": self.monitor["id"], "status": "up",
             "started_at": started.isoformat(), "duration_us": 1200}])
        self.store.agents.seen(self.agent["id"])
        rows = StoreMonitorSource(self.store).monitors(
            window or TimeWindow.of("24h"),
            Scope(containers=("*",))).monitors
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_a_check_that_has_not_come_back_is_not_the_current_status(self):
        row = self._row(ago_seconds=20 * 60)
        self.assertEqual(row.status, UNKNOWN,
                         "a check that hung an agent still calls alive was "
                         "shown as the current status")
        self.assertIn("not the current one", row.error)
        self.assertIn("no result since", row.error)

    def test_a_check_that_answered_on_time_is_untouched(self):
        """The whole difficulty: this must not turn an ordinary monitor
        `unknown` between two turns of its own schedule."""
        row = self._row(ago_seconds=30)
        self.assertNotEqual(row.status, UNKNOWN, row.error)
        self.assertEqual(row.error, "")

    def test_one_slow_turn_is_not_called_a_hang(self):
        """Three intervals, and never sooner than five minutes: a monitor on
        a fifteen-second schedule must not go `unknown` over one slow
        minute."""
        self.store.monitors.update(self.monitor["id"], interval_seconds=15)
        row = self._row(ago_seconds=90)
        self.assertNotEqual(row.status, UNKNOWN, row.error)

    def test_a_window_that_ends_in_the_future_does_not_age_a_check(self):
        """A window's end is aligned FORWARD to a bucket boundary, so it sits
        in the future for most of every bucket. Measured on a 24-hour window:
        it ended at 00:10 while the clock said 00:06 — which would have put
        every monitor on a short schedule into `unknown` four minutes out of
        every five."""
        from datetime import timedelta

        now = _now()
        row = self._row(ago_seconds=30,
                        window=TimeWindow.exact(now - timedelta(hours=1),
                                                now + timedelta(hours=1)))
        self.assertNotEqual(row.status, UNKNOWN, row.error)

    def test_the_agent_being_quiet_is_still_said_of_the_agent(self):
        """Two different facts, and the agent's name is the more useful one
        when it applies."""
        from datetime import timedelta

        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        from wdash.store.schema import agents as agents_table
        from sqlalchemy import update

        started = _now() - timedelta(seconds=20 * 60)
        self.store.results.record(self.agent["id"], [
            {"monitor_id": self.monitor["id"], "status": "up",
             "started_at": started.isoformat(), "duration_us": 1200}])
        with self.store.engine.begin() as connection:
            connection.execute(update(agents_table).values(
                last_seen_at=_now() - timedelta(hours=1)))
        rows = StoreMonitorSource(self.store).monitors(
            TimeWindow.of("24h"), Scope(containers=("*",))).monitors
        self.assertEqual(rows[0].status, UNKNOWN)
        self.assertIn("agent 'probe' has not reported", rows[0].error)


if __name__ == "__main__":
    unittest.main()
