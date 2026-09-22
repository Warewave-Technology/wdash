"""
The checks WDash runs itself, as a neutral monitor source.

Phase one read what Heartbeat wrote. This reads what our own agents write, and
the point of the neutral model is that nothing downstream can tell the
difference: the same page, the same fan-out, the same sparklines and the same
detail page serve both, and a deployment running Heartbeat and our agent side
by side sees one list.

Two things here are not translation, they are judgement:

**A monitor with no results is UNKNOWN, not missing.** A check that is
configured and has never reported is the most important row on the page — it
means the agent is not running it — and leaving it out makes a broken
assignment look like a tidy configuration.

**A monitor whose agent has gone quiet is UNKNOWN, not what it last said.**
Showing the last known status would report a target as `up` for as long as
nobody was watching. "The agent stopped" and "the target is fine" are
different facts, and the second one is the one nobody should be told without
evidence.

**A monitor that is OVERDUE is UNKNOWN too, even from a healthy agent.** The
agent's heartbeat says the agent is alive; it says nothing about this check.
An agent runs its checks on threads of its own, so one check that hangs — a
journey with ten minutes of patience, a target that keeps a connection open —
leaves the rest of the agent reporting normally while that one monitor's last
result sits on the page as the CURRENT status. Measured: a check that answered
once and then hung was still shown as `up` twenty-six seconds later, with a
fresh `last_seen_at` and nothing anywhere saying the check had not come back.
"""

import logging
from datetime import datetime, timedelta, timezone

from ..models import DOWN, STEP_SKIPPED, UNKNOWN, UP, Certificate, Monitor, \
    MonitorCheck, MonitorPage, MonitorPoint, SourceRef, StepResult
from ..source import Capability, MonitorSource, MonitorSourceError

logger = logging.getLogger(__name__)

#: Where SQLite stops being the right store for this table. MEASURED on this
#: schema, thirty days of history, a 24-hour page:
#:
#:     10 monitors @ 60s     432,000 rows    228 MB      99 ms
#:     50 monitors @ 60s   2,160,000 rows    1.2 GB     508 ms
#:     50 monitors @ 15s   8,640,000 rows    4.8 GB   2,274 ms
#:
#: Two million is where the page stops feeling instant and eight is where it
#: stops being usable. The number is here rather than in a document because a
#: threshold nobody can find is a threshold nobody applies — and because the
#: honest answer at that scale is Postgres, not another index.
SQLITE_COMFORTABLE_ROWS = 2_000_000

#: Buckets in the sparkline. Matches the Elasticsearch adapter, so the two
#: kinds of source draw the same width of history in a row.
SPARKLINE_POINTS = 24

#: How many of a monitor's own intervals may pass before its last result stops
#: being called the current one. Three, like the agent's own staleness rule:
#: one missed turn is a slow check, three is a check that is not coming back.
OVERDUE_INTERVALS = 3

#: And never sooner than this, whatever the interval. A monitor on a
#: fifteen-second schedule would otherwise go `unknown` for a forty-five
#: second hiccup, which is a way to teach people to ignore the word. Matches
#: `AGENT_STALE_AFTER`, so a check is never called overdue before the agent
#: running it would be called silent.
OVERDUE_FLOOR = timedelta(minutes=5)


def _aware(value):
    """SQLite hands back naive datetimes; Postgres hands back aware ones.

    Comparing the two raises, and these comparisons decide which bucket a
    result lands in — so a dialect difference would move points around on the
    chart rather than fail loudly.
    """
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _mode(definition):
    """A check's stored TLS decision, in the neutral model's words.

    Read through the store's own rule so "no setting", "verify" and a value
    this version does not recognise are one answer rather than three.
    """
    from ...store.monitoring import tls_mode
    return tls_mode(definition.get("tls"))


def _certificate(payload, verified=None):
    """The stored TLS blob as a neutral Certificate.

    The agent already writes this shape, so there is nothing to map — which
    is deliberate: a translation here would be a second place for the field
    names to drift.

    `verified` comes from the result's own column rather than from inside
    this blob: the blob is NULL exactly when no certificate could be read,
    and the verdict has to survive that.
    """
    if not payload:
        return None
    from datetime import datetime

    def moment(value):
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None

    return Certificate(
        common_name=payload.get("common_name", ""),
        issuer=payload.get("issuer", ""),
        not_before=moment(payload.get("not_before")),
        not_after=moment(payload.get("not_after")),
        fingerprint=payload.get("fingerprint", ""),
        key_algorithm=payload.get("key_algorithm", ""),
        key_size=int(payload.get("key_size") or 0),
        key_curve=payload.get("key_curve", ""),
        signature_algorithm=payload.get("signature_algorithm", ""),
        # Only a real boolean. Every result written before the column existed
        # reads None — "this run does not say" — which must render as
        # nothing, not as a finding.
        verified=verified if isinstance(verified, bool) else None,
    )


class StoreMonitorSource(MonitorSource):
    """Reads the results WDash's own agents reported."""

    backend = "wdash"

    def __init__(self, store, name="wdash-agents"):
        self._store = store
        self.name = name

    @property
    def capabilities(self):
        return frozenset({Capability.MONITOR_LIST, Capability.MONITOR_HISTORY,
                          Capability.TLS_CERTIFICATES})

    def health(self):
        """The metadata store, and whether anything is reporting into it.

        An agentless installation is healthy: WDash works perfectly well
        reading Heartbeat and never running a check of its own. What would not
        be healthy is agents that exist and have all gone quiet, so that is
        what the detail says.
        """
        try:
            agents = self._store.agents.all()
        except Exception as exc:
            return False, str(exc)
        if not agents:
            return True, "no agents registered"
        alive = [a for a in agents if a["enabled"] and not a["stale"]]
        if not alive:
            return False, (f"none of the {len(agents)} registered agent(s) "
                           f"have reported recently")

        detail = f"{len(alive)} of {len(agents)} agent(s) reporting"
        # Said rather than merely suffered. Past the measured threshold the
        # page gets slow, and a page that is slow without saying why sends
        # somebody to look at the network.
        warning = self.storage_warning()
        if warning:
            detail = f"{detail}; {warning}"
        return True, detail

    def storage_warning(self):
        """A sentence when the results table has outgrown SQLite, else "".

        Only for SQLite: Postgres is what the answer is at this scale, so
        warning about it there would be advice to do what has already been
        done.
        """
        try:
            from ...store.database import is_sqlite
            if not is_sqlite(self._store.engine):
                return ""
            rows = self._store.results.count()
        except Exception:
            return ""
        if rows <= SQLITE_COMFORTABLE_ROWS:
            return ""
        return (f"{rows:,} stored results — past about "
                f"{SQLITE_COMFORTABLE_ROWS:,} this page slows down on SQLite. "
                f"Shorten the retention period or move DATABASE_URL to "
                f"Postgres.")

    def containers(self, scope):
        """Nothing to enumerate: a monitor is not stored in a container."""
        return []

    # ---------- listing ----------

    def monitors(self, window, scope, series=False):
        try:
            definitions = self._store.monitors.all(enabled_only=True)
            agents = {a["id"]: a for a in self._store.agents.all()}
            latest = self._store.results.latest(window_start=window.start)
        except Exception as exc:
            return MonitorPage(partial=True, sources=(self.name,),
                               warnings=(f"{self.name}: {exc}",))

        by_id = {d["id"]: d for d in definitions}
        rows = []
        reported = set()

        for result in latest:
            definition = by_id.get(result["monitor_id"])
            if definition is None:
                # A result for a monitor that has since been deleted. Not
                # shown: the row would name something nobody can open.
                continue
            reported.add(result["monitor_id"])
            rows.append(self._to_monitor(definition, result,
                                         agents.get(result["agent_id"]),
                                         window.end))

        # Configured but silent. This is the row that matters most and the one
        # a "list what reported" query would leave out.
        for definition in definitions:
            if definition["id"] not in reported:
                rows.append(self._to_monitor(definition, None, None,
                                             window.end))

        if series:
            self._attach_series(rows, window)

        rows.sort(key=lambda m: (m.status != DOWN, m.name.lower(), m.source))
        return MonitorPage(monitors=rows, sources=(self.name,))

    def _to_monitor(self, definition, result, agent, asked_at=None):
        """One row. `result` is None when nothing has been reported."""
        if result is None:
            status, checked_at, duration, error, certificate, ref = (
                UNKNOWN, None, None, "", None, None)
            detail = "no agent has reported a result for this check"
        elif agent is not None and agent["stale"]:
            # The last result is real, and stale. Reporting it as the current
            # status would say a target is up for as long as nobody is
            # watching — which is exactly backwards.
            status = UNKNOWN
            checked_at = _aware(result["started_at"])
            duration = (result["duration_us"] or 0) / 1000.0
            certificate = _certificate(result["tls"],
                                       result.get("handshake_verified"))
            ref = None
            # `last_seen_at` is None for an agent that has never checked in —
            # which is reachable the moment somebody registers one and it
            # never starts. Formatting it directly crashed the whole listing,
            # so one unregistered agent took away every other monitor's row.
            since = _aware(agent["last_seen_at"])
            when = f"since {since:%H:%M}" if since else "at all"
            detail = (f"agent '{agent['name']}' has not reported {when} — "
                      f"this is its last known result, not the current one")
            error = detail
        elif self._overdue(definition, result, asked_at):
            # The agent is reporting; THIS CHECK is not. The agent runs its
            # checks on threads of its own, so one that hangs stops answering
            # while its neighbours and the heartbeat carry on — and the row
            # went on showing the last answer as the current one. Unknown for
            # the same reason a silent agent is: nobody looked.
            status = UNKNOWN
            checked_at = _aware(result["started_at"])
            duration = (result["duration_us"] or 0) / 1000.0
            certificate = _certificate(result["tls"],
                                       result.get("handshake_verified"))
            ref = None
            detail = (f"no result since {checked_at:%H:%M} — this check runs "
                      f"every {definition.get('interval_seconds') or 60}s, so "
                      f"this is its last known result, not the current one")
            error = detail
        else:
            status = DOWN if result["status"] == DOWN else UP
            checked_at = _aware(result["started_at"])
            duration = (result["duration_us"] or 0) / 1000.0
            error = result["error"] or ""
            certificate = _certificate(result["tls"],
                                       result.get("handshake_verified"))
            ref = SourceRef(backend=self.backend, container="wdash_monitor_results",
                            id=str(result["id"]))
            detail = ""

        if result is None:
            error = detail

        labels = definition.get("labels") or {}
        tags = tuple(f"{k}={v}" for k, v in sorted(labels.items()))
        if agent is not None:
            tags += (f"agent={agent['name']}",)

        return Monitor(
            id=definition["id"], name=definition["name"],
            type=definition["kind"], url=definition["target"],
            status=status, checked_at=checked_at, duration_ms=duration,
            error=error, tags=tags, certificate=certificate,
            # From the DEFINITION, which is here whether or not a result is:
            # a check that has never run, whose agent has gone quiet or whose
            # certificate could not be read still has a TLS decision, and
            # that decision is what the page says out loud.
            tls_mode=_mode(definition),
            source=self.name, ref=ref)

    @staticmethod
    def _overdue(definition, result, asked_at=None):
        """Whether the last result is too old to be called the current one.

        Against the monitor's OWN interval, because that is the only thing
        that says how often an answer is expected, and against a floor, so a
        fifteen-second schedule does not go `unknown` over one slow minute.
        `asked_at` is the end of the window being drawn rather than the clock,
        so a page about last Tuesday is not told that every check on it is
        late — but never later than the clock, because a window's end is
        aligned FORWARD to a bucket boundary and sits in the future for most
        of every bucket. Measured without that: a 24-hour window ended at
        00:10 while it was 00:06, and every monitor on a fifteen-second
        schedule read `unknown` four minutes out of every five.
        """
        started = _aware(result["started_at"])
        if started is None:
            return False
        now = datetime.now(timezone.utc)
        asked_at = min(_aware(asked_at) or now, now)
        interval = definition.get("interval_seconds") or 60
        allowed = max(timedelta(seconds=interval * OVERDUE_INTERVALS),
                      OVERDUE_FLOOR)
        return (asked_at - started) > allowed

    # ---------- history ----------

    def _results(self, monitor_id, window):
        """Raises rather than answering []: the page draws "no check in this
        window" from an empty history, and a store that could not be read
        has not said that."""
        try:
            return self._store.results.series(
                monitor_id, window.start, window.end)
        except Exception as exc:
            logger.warning(f"{self.name}: could not read history: {exc}")
            raise MonitorSourceError(
                f"{self.name}: could not read the results: {exc}") from exc

    def _agent_names(self):
        """Agent id -> the name somebody typed when they registered it.

        Never raises: a history that renders without saying where each check
        ran is worse than one that says it, and far better than none.
        """
        try:
            return {a["id"]: a["name"] for a in self._store.agents.all()}
        except Exception as exc:
            logger.warning(f"{self.name}: could not read agents: {exc}")
            return {}

    def history(self, monitor_id, window, scope, offset=0, limit=None):
        rows = self._results(monitor_id, window)
        # One lookup for the page rather than one per row, and by NAME: an
        # agent id is a uuid, and a page that prints uuids where it means
        # "Dublin" has not answered the question.
        names = self._agent_names()
        checks = [MonitorCheck(
            timestamp=_aware(r["started_at"]),
            status=DOWN if r["status"] == DOWN else UP,
            duration_ms=(r["duration_us"] or 0) / 1000.0,
            error=r["error"] or "",
            steps=_steps(r.get("steps")),
            location=names.get(r.get("agent_id"), ""),
            screenshot_id=r.get("screenshot_id")) for r in rows]

        # Paged here rather than in SQL. The metadata store holds one
        # deployment's own checks, not a cluster's worth of logs, and the
        # window has already bounded it — a LIMIT/OFFSET per dialect would be
        # more code than the rows it saves reading.
        total = len(checks)
        if limit is not None:
            newest_first = list(reversed(checks))
            page = newest_first[int(offset):int(offset) + int(limit)]
            checks = list(reversed(page))

        result = _CountedChecks(checks)
        result.total = total

        # Where the hours behind the rows have been folded, the rows are no
        # longer the window. `totals` counts both halves — exactly, which is
        # what the summary is for — so the header can say 30 days while the
        # rows in hand are two.
        #
        # No median and no p95 here, and not an omission: an hourly summary
        # cannot produce either, so the page shows them from the rows it has
        # and says from when. A number invented for the folded part would be
        # the one thing this whole design refused to store.
        try:
            counted = self._store.results.totals(
                monitor_id, window.start, window.end)
        except Exception as exc:
            logger.warning(f"{self.name}: could not count the window: {exc}")
            return result

        if counted["summarised"]:
            result.total = counted["checks"]
            result.whole_window = {
                "checks": counted["checks"], "failed": counted["down"],
                "median_ms": None, "p95_ms": None, "worst_ms": None,
                # The COUNTS are exact. `estimated` is about the percentiles,
                # and there are none to estimate.
                "estimated": False,
                "folded_from": counted["oldest_row"],
                "covers": counted["covers"],
            }
        return result

    def series(self, monitor_id, window, scope, points=120):
        return self._bucket(self._results(monitor_id, window), window, points,
                            with_worst=True)

    def _attach_series(self, rows, window):
        """Every sparkline from ONE query.

        Asking per monitor was fifty queries to draw fifty shapes — the same
        N+1 the Elasticsearch adapter avoids with a sub-aggregation. Measured
        on 8.6 million rows it cost 1.1 seconds of the 3.1 the listing took.
        """
        try:
            grouped = self._store.results.latest_series(
                window.start, window.end)
        except Exception as exc:
            logger.warning(f"{self.name}: could not read series: {exc}")
            return
        for monitor in rows:
            monitor.series = tuple(self._bucket(
                grouped.get(monitor.id, []), window, SPARKLINE_POINTS))

    @staticmethod
    def _bucket(rows, window, points, with_worst=False):
        """Fixed-width buckets across the WHOLE window.

        Across the window rather than across the results, so a monitor added
        an hour ago produces the same number of buckets as its neighbours.
        Drawn to the same width, differing bucket counts put different moments
        above each other and give every row its own x-axis.
        """
        points = max(1, int(points))
        span = (window.end - window.start).total_seconds()
        if span <= 0:
            return []
        width = span / points

        buckets = [[] for _ in range(points)]
        for row in rows:
            started = _aware(row["started_at"])
            offset = (started - window.start).total_seconds()
            index = int(offset // width)
            if 0 <= index < points:
                buckets[index].append(row)

        from datetime import timedelta
        out = []
        for index, contents in enumerate(buckets):
            moment = window.start + timedelta(seconds=index * width)
            durations = [r["duration_us"] for r in contents
                         if r["duration_us"] is not None]
            point = MonitorPoint(
                timestamp=moment,
                duration_ms=(sum(durations) / len(durations) / 1000.0
                             if durations else None),
                down=sum(1 for r in contents if r["status"] == DOWN),
                checks=len(contents))
            if with_worst:
                point.worst_ms = (max(durations) / 1000.0
                                  if durations else None)
            out.append(point)
        return out

    # ---------- certificates ----------

    def certificates(self, window, scope):
        page = self.monitors(window, scope)
        with_certificates = [m for m in page.monitors if m.certificate]
        with_certificates.sort(
            key=lambda m: (m.certificate.days_remaining is None,
                           m.certificate.days_remaining or 0))
        return with_certificates


def _steps(raw):
    """Stored step results as StepResult. Never raises.

    A journey whose steps came back malformed is still a check with a status
    and a duration, and losing the whole row over the decoration would turn a
    rendering problem into a gap in the history.
    """
    if not raw:
        return ()
    if isinstance(raw, str):
        import json
        try:
            raw = json.loads(raw)
        except ValueError:
            return ()
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(StepResult(
        index=s.get("index") or i,
        kind=s.get("kind") or "",
        description=s.get("description") or "",
        status=s.get("status") or STEP_SKIPPED,
        duration_us=s.get("duration_us"),
        error=s.get("error") or "")
        for i, s in enumerate(raw, start=1) if isinstance(s, dict))


class _CountedChecks(list):
    """A list that also knows the total, matching the Elasticsearch source."""
    total = 0
    #: The header figures over the WHOLE window, when the rows are no longer
    #: it — set where older hours have been folded into summaries. Declared
    #: here and not only assigned, so the attribute exists on every one of
    #: these: `monitor_routes` reaches for it with `getattr`, which would
    #: have read "no folding" and "this object predates folding" as the same
    #: thing for ever.
    whole_window = None
