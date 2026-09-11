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

from wdash.agent import runner  # noqa: E402
from wdash.agent.browser import run_journey  # noqa: E402
from wdash.agent.checks import run_check  # noqa: E402
from wdash.agent.runner import Agent  # noqa: E402
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
            ELASTICSEARCH_URL = ""
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
        self.assertEqual([o.subject for o in seen if o.bad], [],
                         "a working checkout paged somebody")


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


if __name__ == "__main__":
    unittest.main()
