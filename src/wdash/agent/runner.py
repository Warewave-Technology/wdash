"""
The agent loop: fetch configuration, run checks on time, ship results.

Everything here is about keeping three failures apart, because conflating any
two of them produces a monitoring system that lies:

  * the TARGET is down       -> a result, status down, with a reason
  * WDASH is unreachable     -> results spool; nothing is reported as down
  * this AGENT is dead       -> WDash sees no heartbeat and says `unknown`

The third is the one that cannot be handled here, by definition. It is handled
by `last_seen_at` on the server: an agent that has gone quiet puts its monitors
into `unknown` rather than `down`, because "nobody looked" is not "it is
broken".
"""

import importlib.util
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .checks import run_check
from .spool import Spool

logger = logging.getLogger(__name__)

#: How often to ask for configuration. Cheap — the server answers with a
#: content hash and the agent reschedules only when it changes.
CONFIG_INTERVAL = 60

#: How often to try to ship what is spooled.
FLUSH_INTERVAL = 10

#: Results per request. Matches the server's limit; a bigger batch would be
#: refused whole after the agent had already built it.
BATCH = 500

#: Bytes one delivery may carry. A journey's failure screenshot rides along
#: with its result, and a batch counted in results alone was refused whole:
#: the proxy in front of the server took 1m, a handful of failed journeys
#: passed it, and the 413 was taken as "the server will never want these" —
#: the down results were dropped, the monitor stayed green, and nothing on
#: the server said so. Well under the 16m the server and its proxy accept.
MAX_BATCH_BYTES = 4 * 1024 * 1024

#: Answers that mean "not now", like a 5xx: the results are kept.
RETRY_LATER = (408, 429)

#: Checks running at once. A monitor that hangs for its whole timeout must not
#: hold up the others, and an agent with two hundred monitors should not open
#: two hundred sockets at the same instant.
MAX_CONCURRENCY = 16

#: Browsers running at once. Not sixteen: a Chromium is a few hundred
#: megabytes of resident memory, and sixteen of them is five gigabytes on a
#: probe sized for a Python process. Two is enough to keep journeys from
#: queueing behind each other and small enough to run beside the http checks
#: on the same host.
#:
#: A separate limit rather than a lower MAX_CONCURRENCY, because the two are
#: bounded by different things — sockets for one, memory for the other — and
#: dropping the shared limit to two would make an agent with two hundred http
#: monitors take a hundred times as long to get round them.
BROWSER_CONCURRENCY = 2

#: Backoff when the server cannot be reached, in seconds. Ends at a minute:
#: long enough not to hammer a server that is down, short enough that recovery
#: is noticed quickly.
BACKOFF = (1, 2, 5, 10, 30, 60)


def _answer(response, what):
    """The JSON object in an answer, or None when there is not one.

    A 200 is not proof that WDash answered it. An SSO or authenticating proxy
    in front of the server redirects `/api/agent/*` to its own sign-in page,
    `requests` follows the redirect, and the agent reads a 200 of HTML. That
    used to raise out of `fetch_config` on the first poll and out of `flush`
    AFTER the batch had been dropped: the container crash-looped, its monitors
    went unknown, and one spooled batch was gone.
    """
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        logger.warning(f"{what} was answered with something that is not a "
                       f"JSON object — is a proxy or a sign-in page "
                       f"intercepting /api/agent?")
        return None
    return payload


def _has_browser():
    """Whether this image can run a journey at all.

    The browser is a separate image — 1.77GB against 260MB — and the plain one
    has no Playwright. Asked before the check rather than discovered inside
    it, because the answer decides whether to report AT ALL rather than what
    to report: see `_run_one`.
    """
    try:
        return importlib.util.find_spec("playwright") is not None
    except (ImportError, ValueError):
        # A `playwright` that is on the path and broken, or blocked in
        # `sys.modules`. Either way this agent cannot run a journey.
        return False


def _within(results, limit):
    """The oldest results whose JSON fits in `limit` bytes, and at least one."""
    import json
    batch, size = [], 0
    for result in results:
        size += len(json.dumps(result)) + 2
        if batch and size > limit:
            break
        batch.append(result)
    return batch


class Agent:
    def __init__(self, server, token, spool_path="agent-spool.jsonl",
                 version="0.1.0", verify=True, session=None):
        self.server = server.rstrip("/")
        self.token = token
        self.version = version
        self.verify = verify
        self.spool = Spool(spool_path)
        self._session = session
        self._stop = threading.Event()

        #: monitor id -> when it should next run, on the monotonic clock.
        self._due = {}
        self._monitors = {}
        self._browsers = threading.Semaphore(BROWSER_CONCURRENCY)
        self._config_version = None

        #: One pool for the life of the agent, and the ids running in it. A
        #: pool per round meant the round ended together — see `run_due`.
        self._pool = None
        self._running = set()
        self._overrunning = set()
        self._lock = threading.Lock()
        #: Monitors this agent has already said it cannot run, so that saying
        #: so does not become a line a minute for ever.
        self._unrunnable = set()

    # ---------- HTTP to WDash ----------

    def _client(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self.token}",
                "X-Agent-Version": self.version,
            })
        return self._session

    def fetch_config(self):
        """Ask what to check. Returns True when the configuration changed."""
        try:
            response = self._client().get(
                f"{self.server}/api/agent/config", timeout=30,
                verify=self.verify)
        except Exception as exc:
            logger.warning(f"could not reach {self.server}: {exc}")
            return False

        if response.status_code == 401:
            # Not retried into a backoff loop: a rejected token is not going
            # to start working, and an agent quietly retrying for ever is one
            # nobody notices is disconnected.
            logger.error("this agent's token was refused; check it is enabled")
            return False
        if response.status_code != 200:
            logger.warning(f"configuration request answered "
                           f"{response.status_code}")
            return False

        payload = _answer(response, "the configuration request")
        if payload is None:
            return False
        if payload.get("version") == self._config_version:
            return False

        self._config_version = payload.get("version")
        monitors = {m["id"]: m for m in payload.get("monitors", [])}
        self._apply(monitors)
        return True

    def _apply(self, monitors):
        """Adopt a new configuration without disturbing what has not changed.

        A monitor whose definition is untouched keeps its place in the
        schedule. Rescheduling everything on every poll would make every check
        fire at the same instant after each poll — a thundering herd the agent
        creates itself, and one that puts a spike into the very timings it is
        measuring.
        """
        now = time.monotonic()
        for monitor_id, monitor in monitors.items():
            existing = self._monitors.get(monitor_id)
            if existing != monitor:
                # New or changed: run it soon, but stagger so a fresh agent
                # with fifty monitors does not open fifty connections at once.
                self._due[monitor_id] = now + (len(self._due) % 10) * 0.5
            self._monitors[monitor_id] = monitor

        for gone in set(self._monitors) - set(monitors):
            self._monitors.pop(gone, None)
            self._due.pop(gone, None)
        logger.info(f"configuration: {len(self._monitors)} monitor(s)")

    def flush(self):
        """Ship what is spooled. Returns how many were accepted.

        The oldest results first, as many as fit in MAX_BATCH_BYTES. A batch
        the server calls too large (413) is halved and offered again until it
        fits; only a single result too large to be taken at all is given up
        on, and it alone.
        """
        pending = self.spool.take(BATCH)
        if not pending:
            return 0
        batch = _within(pending, MAX_BATCH_BYTES)
        while True:
            try:
                response = self._client().post(
                    f"{self.server}/api/agent/results", timeout=30,
                    verify=self.verify, json={"results": batch})
            except Exception as exc:
                logger.warning(f"could not ship {len(batch)} result(s): {exc}")
                return 0
            if response.status_code == 413 and len(batch) > 1:
                batch = batch[:len(batch) // 2]
                continue
            break

        if response.status_code >= 500 or response.status_code in RETRY_LATER:
            # Kept: the server said it failed, or not now — not that it did
            # not want them.
            logger.warning(f"server answered {response.status_code}; "
                           f"{len(batch)} result(s) stay spooled")
            return 0
        if response.status_code == 401:
            logger.error("this agent's token was refused; results stay spooled")
            return 0
        if response.status_code >= 400:
            # 4xx that is not auth means the server will never take these.
            # Keeping them would block every later result behind a batch that
            # can never be delivered. A 413 reaches here for one result only.
            logger.error(f"server rejected {len(batch)} result(s) with "
                         f"{response.status_code}; dropping them"
                         + (f" (monitor {batch[0].get('monitor_id')})"
                            if len(batch) == 1 else ""))
            self.spool.drop(len(batch))
            return 0

        # Read BEFORE the spool is dropped. A 200 whose body is not JSON is
        # not an acceptance — it is the sign-in page a proxy answered with —
        # and dropping first meant the batch was gone before anybody found
        # out.
        payload = _answer(response, f"a delivery of {len(batch)} result(s)")
        if payload is None:
            return 0

        self.spool.drop(len(batch))
        accepted = payload.get("accepted", len(batch))
        if not isinstance(accepted, int):
            accepted = len(batch)
        if accepted < len(batch):
            logger.warning(f"{len(batch) - accepted} result(s) were not "
                           f"stored — is this agent still assigned them?")
        return accepted

    # ---------- the loop ----------

    def due_now(self, now=None):
        """Monitors whose turn it is."""
        now = time.monotonic() if now is None else now
        return [self._monitors[i] for i, when in sorted(self._due.items(),
                                                        key=lambda kv: kv[1])
                if when <= now and i in self._monitors]

    def run_due(self, force=False, wait=False):
        """Start whatever is due, spooling each result as it lands. Returns
        how many checks were started.

        STARTED, not finished. A round that waited for its slowest check held
        the loop behind it — the configuration poll, the flush, and the flush
        IS the heartbeat, so an agent with one slow monitor went `unknown` on
        the server and took every monitor it ran with it. Measured before
        this, with one check that took 5s and a second on a 1s interval: the
        fast one ran at 0.0s, 6.0s and 11.5s, and the first heartbeat was held
        until 11.0s. A check still running from its last turn is skipped
        rather than started again, so a target slower than its own interval
        cannot fill the pool with copies of itself.

        `force` runs everything regardless of the schedule, and `wait` waits
        for it. That is what `--once` needs: a fresh agent staggers its
        monitors over the next few seconds so fifty of them do not open fifty
        connections at the same instant, which is right for a daemon and
        useless for "let me test this configuration" — it would run one check
        and exit.
        """
        due = list(self._monitors.values()) if force else self.due_now()
        if not due:
            return 0

        now = time.monotonic()
        started = []
        for monitor in due:
            # Rescheduled BEFORE running, from the time it was due rather than
            # from now. Otherwise every check's duration is added to its own
            # interval and a slow monitor drifts later all day.
            interval = monitor.get("interval_seconds") or 60
            previous = self._due.get(monitor["id"], now)
            self._due[monitor["id"]] = max(now, previous + interval)
            if not self._claim(monitor):
                continue
            started.append(self._pool_for().submit(self._run_and_spool,
                                                   monitor))

        for future in (started if wait else ()):
            future.result()
        return len(started)

    def _pool_for(self):
        """The checking pool, made on first use and kept."""
        if self._pool is None:
            self._pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENCY,
                                            thread_name_prefix="wdash-check")
        return self._pool

    def _claim(self, monitor):
        """Take this monitor's turn, unless its last one is still running.

        Said once per overrun rather than once per round: a journey with ten
        minutes of patience and a one-minute interval would otherwise write
        nine identical lines before it finished.
        """
        with self._lock:
            if monitor["id"] in self._running:
                if monitor["id"] not in self._overrunning:
                    self._overrunning.add(monitor["id"])
                    logger.warning(f"check '{monitor.get('name')}' has not "
                                   f"finished its last turn; skipping it "
                                   f"until it does")
                return False
            self._running.add(monitor["id"])
            return True

    def _run_and_spool(self, monitor):
        """One check, on a pool thread, spooled the moment it is done.

        One at a time rather than a round at a time, because the round no
        longer ends together — and a result held in memory until its
        neighbours finish is a result an agent crash loses.
        """
        try:
            result = self._run_one(monitor)
            if result:
                self.spool.add([result])
        except Exception:
            logger.exception(f"check '{monitor.get('name')}' could not be "
                             f"spooled")
        finally:
            with self._lock:
                self._running.discard(monitor["id"])
                self._overrunning.discard(monitor["id"])

    def _run_one(self, monitor):
        try:
            if (monitor.get("kind") or "").lower() == "browser":
                if not _has_browser():
                    # Nothing is reported, and that is the point: this agent
                    # did not look. Reporting `down` would be this agent's
                    # limitation dressed up as a fact about the site — and a
                    # journey left unassigned goes to EVERY agent, so one
                    # plain probe was enough to call a working checkout down
                    # every interval and page whoever holds a monitor_down
                    # rule. Unrun, the journey reads `unknown` with "no agent
                    # has reported a result for this check", which is what the
                    # README and the manifest promise.
                    self._cannot_run(monitor)
                    return None
                # Queued behind the browser limit rather than the pool's. A
                # journey waiting here still holds a pool worker, which is
                # right: the alternative is running it late and reporting a
                # duration that includes the wait.
                with self._browsers:
                    return run_check(monitor)
            return run_check(monitor)
        except Exception as exc:
            # A check must never take the loop down. This is a bug in the
            # agent rather than a fact about the target, so it is logged as
            # one — but it is still recorded, because a monitor that silently
            # stops reporting looks like a monitor nobody configured.
            logger.exception(f"check '{monitor.get('name')}' raised")
            from .checks import _now, _result
            return _result(monitor, _now(), "down",
                           f"the agent could not run this check: {exc}")

    def _cannot_run(self, monitor):
        """Say once, per monitor, that this agent is the wrong image for it.

        Once rather than every interval: a sentence a minute for the life of
        the pod is a sentence nobody reads.
        """
        if monitor["id"] in self._unrunnable:
            return
        self._unrunnable.add(monitor["id"])
        logger.warning(
            f"journey '{monitor.get('name')}' needs an agent built on the "
            f"browser image; this one has no browser, so it is reporting "
            f"nothing for it and the journey will read as unknown until a "
            f"browser agent runs it")

    def _guarded(self, work, what):
        """Run one part of the round. A failure costs that part and no more.

        Nothing between here and the process exit used to catch anything —
        `__main__` calls `run_forever` and that is all — so one unreadable
        answer ended the agent. In Kubernetes the pod restarts, the spool
        survives on its emptyDir, and it meets the same answer again: a
        crash loop, and every monitor it ran reading `unknown`.

        One guard per part rather than one around the round, because a
        configuration that cannot be read must not stop the results that have
        already been measured from being delivered.
        """
        try:
            return work()
        except Exception:
            logger.exception(what)
            return None

    def run_forever(self):
        logger.info(f"agent starting against {self.server}")
        self._guarded(self.fetch_config, "the first configuration request "
                                         "failed")

        last_config = last_flush = time.monotonic()
        failures = 0
        while not self._stop.is_set():
            now = time.monotonic()
            # Each clock is moved BEFORE the work it schedules, so that
            # something which keeps failing is retried on its own interval
            # rather than on every turn of the loop.
            if now - last_config >= CONFIG_INTERVAL:
                last_config = now
                self._guarded(self.fetch_config,
                              "the configuration could not be read; the agent "
                              "keeps the one it has")

            self._guarded(self.run_due, "a round of checks could not start")

            if now - last_flush >= FLUSH_INTERVAL:
                last_flush = now
                shipped = self._guarded(self.flush, "a delivery failed") or 0
                pending = self._guarded(self.spool.pending,
                                        "the spool could not be read") or 0
                if pending and not shipped:
                    failures += 1
                    wait = BACKOFF[min(failures, len(BACKOFF) - 1)]
                    logger.info(f"{pending} result(s) waiting; "
                                f"next attempt in {wait}s")
                    last_flush = now + wait - FLUSH_INTERVAL
                else:
                    failures = 0

            # A short sleep rather than sleeping until the next due time: the
            # configuration can change under us, and a long sleep would keep
            # running the old schedule until it woke.
            self._stop.wait(0.5)
        self.close()
        logger.info("agent stopping")

    def stop(self):
        self._stop.set()

    def close(self):
        """Let the checking threads go. Whatever is still running is
        abandoned, not waited for: a stop signal has a deadline, and a journey
        may have ten minutes left on its own."""
        pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
