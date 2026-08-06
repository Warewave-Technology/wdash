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

#: Checks running at once. A monitor that hangs for its whole timeout must not
#: hold up the others, and an agent with two hundred monitors should not open
#: two hundred sockets at the same instant.
MAX_CONCURRENCY = 16

#: Backoff when the server cannot be reached, in seconds. Ends at a minute:
#: long enough not to hammer a server that is down, short enough that recovery
#: is noticed quickly.
BACKOFF = (1, 2, 5, 10, 30, 60)


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
        self._config_version = None

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

        payload = response.json()
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
        """Ship what is spooled. Returns how many were accepted."""
        pending = self.spool.take(BATCH)
        if not pending:
            return 0
        try:
            response = self._client().post(
                f"{self.server}/api/agent/results", timeout=30,
                verify=self.verify, json={"results": pending})
        except Exception as exc:
            logger.warning(f"could not ship {len(pending)} result(s): {exc}")
            return 0

        if response.status_code >= 500:
            # Kept: the server said it failed, not that it did not want them.
            logger.warning(f"server answered {response.status_code}; "
                           f"{len(pending)} result(s) stay spooled")
            return 0
        if response.status_code == 401:
            logger.error("this agent's token was refused; results stay spooled")
            return 0
        if response.status_code >= 400:
            # 4xx that is not auth means the server will never take these.
            # Keeping them would block every later result behind a batch that
            # can never be delivered.
            logger.error(f"server rejected {len(pending)} result(s) with "
                         f"{response.status_code}; dropping them")
            self.spool.drop(len(pending))
            return 0

        self.spool.drop(len(pending))
        accepted = (response.json() or {}).get("accepted", len(pending))
        if accepted < len(pending):
            logger.warning(f"{len(pending) - accepted} result(s) were not "
                           f"stored — is this agent still assigned them?")
        return accepted

    # ---------- the loop ----------

    def due_now(self, now=None):
        """Monitors whose turn it is."""
        now = time.monotonic() if now is None else now
        return [self._monitors[i] for i, when in sorted(self._due.items(),
                                                        key=lambda kv: kv[1])
                if when <= now and i in self._monitors]

    def run_due(self, force=False):
        """Run whatever is due, spool the results. Returns how many ran.

        `force` runs everything regardless of the schedule. That is what
        `--once` needs: a fresh agent staggers its monitors over the next few
        seconds so fifty of them do not open fifty connections at the same
        instant, which is right for a daemon and useless for "let me test this
        configuration" — it would run one check and exit.
        """
        due = list(self._monitors.values()) if force else self.due_now()
        if not due:
            return 0

        now = time.monotonic()
        for monitor in due:
            # Rescheduled BEFORE running, from the time it was due rather than
            # from now. Otherwise every check's duration is added to its own
            # interval and a slow monitor drifts later all day.
            interval = monitor.get("interval_seconds") or 60
            previous = self._due.get(monitor["id"], now)
            self._due[monitor["id"]] = max(now, previous + interval)

        workers = min(MAX_CONCURRENCY, len(due))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(self._run_one, due))
        self.spool.add([r for r in results if r])
        return len(results)

    def _run_one(self, monitor):
        try:
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

    def run_forever(self):
        logger.info(f"agent starting against {self.server}")
        self.fetch_config()

        last_config = last_flush = time.monotonic()
        failures = 0
        while not self._stop.is_set():
            now = time.monotonic()
            if now - last_config >= CONFIG_INTERVAL:
                self.fetch_config()
                last_config = now

            self.run_due()

            if now - last_flush >= FLUSH_INTERVAL:
                shipped = self.flush()
                pending = self.spool.pending()
                if pending and not shipped:
                    failures += 1
                    wait = BACKOFF[min(failures, len(BACKOFF) - 1)]
                    logger.info(f"{pending} result(s) waiting; "
                                f"next attempt in {wait}s")
                    last_flush = now + wait - FLUSH_INTERVAL
                else:
                    failures = 0
                    last_flush = now

            # A short sleep rather than sleeping until the next due time: the
            # configuration can change under us, and a long sleep would keep
            # running the old schedule until it woke.
            self._stop.wait(0.5)
        logger.info("agent stopping")

    def stop(self):
        self._stop.set()
