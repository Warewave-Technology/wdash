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
"""

import logging
from datetime import timezone

from ..models import DOWN, STEP_SKIPPED, UNKNOWN, UP, Certificate, Monitor, \
    MonitorCheck, MonitorPage, MonitorPoint, SourceRef, StepResult
from ..source import Capability, MonitorSource

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


def _aware(value):
    """SQLite hands back naive datetimes; Postgres hands back aware ones.

    Comparing the two raises, and these comparisons decide which bucket a
    result lands in — so a dialect difference would move points around on the
    chart rather than fail loudly.
    """
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _certificate(payload):
    """The stored TLS blob as a neutral Certificate.

    The agent already writes this shape, so there is nothing to map — which
    is deliberate: a translation here would be a second place for the field
    names to drift.
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
                                         agents.get(result["agent_id"])))

        # Configured but silent. This is the row that matters most and the one
        # a "list what reported" query would leave out.
        for definition in definitions:
            if definition["id"] not in reported:
                rows.append(self._to_monitor(definition, None, None))

        if series:
            self._attach_series(rows, window)

        rows.sort(key=lambda m: (m.status != DOWN, m.name.lower(), m.source))
        return MonitorPage(monitors=rows, sources=(self.name,))

    def _to_monitor(self, definition, result, agent):
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
            certificate = _certificate(result["tls"])
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
        else:
            status = DOWN if result["status"] == DOWN else UP
            checked_at = _aware(result["started_at"])
            duration = (result["duration_us"] or 0) / 1000.0
            error = result["error"] or ""
            certificate = _certificate(result["tls"])
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
            source=self.name, ref=ref)

    # ---------- history ----------

    def _results(self, monitor_id, window):
        try:
            return self._store.results.series(
                monitor_id, window.start, window.end)
        except Exception as exc:
            logger.warning(f"{self.name}: could not read history: {exc}")
            return []

    def history(self, monitor_id, window, scope, offset=0, limit=None):
        rows = self._results(monitor_id, window)
        checks = [MonitorCheck(
            timestamp=_aware(r["started_at"]),
            status=DOWN if r["status"] == DOWN else UP,
            duration_ms=(r["duration_us"] or 0) / 1000.0,
            error=r["error"] or "",
            steps=_steps(r.get("steps")),
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
