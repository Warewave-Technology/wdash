"""
Agents, the monitors they run, and what they found.

WDash still does not probe anything. An agent pulls its configuration from
here, runs the checks on its own schedule, and pushes results back — so the
network path, the retries and the timing belong to the agent, and restarting
WDash misses no check.

Two things in here are load-bearing and easy to get wrong:

**Tokens are not password hashes.** Argon2 exists to make a low-entropy secret
expensive to guess. An agent token is 256 bits of machine-generated
randomness; there is no dictionary to attack, and running Argon2 on every
result batch would burn CPU for no security while giving anybody who can reach
the ingest endpoint a way to exhaust the server. A SHA-256 lookup is the right
tool, and the difference is written down because "why is this not Argon2 like
everything else" is the obvious question.

**A silent agent is not a failing target.** If an agent stops reporting, its
monitors go `unknown`. Reporting them as `down` turns a dead agent into a
false outage, and a false outage is how a monitoring system trains people to
ignore it.
"""

import hashlib
import json
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, insert, select, update

from .schema import agents, monitor_agents, monitor_results, monitors

logger = logging.getLogger(__name__)

#: How long after its last word an agent is treated as gone. Three intervals
#: of the slowest sensible schedule: long enough that one missed beat is not an
#: alarm, short enough that a dead agent is noticed within minutes.
AGENT_STALE_AFTER = timedelta(minutes=5)

#: What a check can be. Short on purpose — ICMP needs a raw socket and so a
#: privileged container, and a browser check needs a browser. Both are real,
#: and both are a decision rather than a type that quietly appears in a list.
MONITOR_KINDS = ("http", "tcp")

#: Bounds on a schedule. Below the floor an agent is a load generator; above
#: the ceiling the monitor is a daily report and the window selector on the
#: page cannot reach it.
MIN_INTERVAL = 10
MAX_INTERVAL = 3600
MAX_TIMEOUT = 120


class MonitoringError(ValueError):
    """A definition the store will not accept."""


def _now():
    return datetime.now(timezone.utc)


def hash_token(token):
    """Hex SHA-256. See the module docstring for why this is not Argon2."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token():
    """A token with no structure worth guessing at."""
    return secrets.token_urlsafe(32)


def _aware(value):
    """Timestamps come back naive from SQLite and aware from Postgres.

    Comparing the two raises, and the comparison here decides whether an agent
    is considered alive — so a dialect difference would make agents look dead
    on one database and fine on the other.
    """
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


class AgentRepository:
    def __init__(self, engine):
        self._engine = engine

    # ---------- writing ----------

    def create(self, name, labels=None):
        """Register an agent. Returns (row, token).

        The token is returned ONCE and never stored — only its hash is. An
        operator who loses it rotates rather than recovers, which is the only
        honest thing a store that cannot read its own secrets can offer.
        """
        name = (name or "").strip()
        if not name:
            raise MonitoringError("An agent needs a name.")

        token = new_token()
        row = {
            "id": str(uuid.uuid4()),
            "name": name,
            "token_hash": hash_token(token),
            "labels": labels or {},
            "last_seen_at": None,
            "version": None,
            "enabled": True,
            "created_at": _now(),
        }
        with self._engine.begin() as connection:
            try:
                connection.execute(insert(agents).values(**row))
            except Exception as exc:
                raise MonitoringError(
                    f"An agent called '{name}' already exists.") from exc
        return self._public(row), token

    def rotate_token(self, agent_id):
        """A new token, and the old one stops working immediately.

        No grace period: an overlap window is exactly what somebody rotating a
        leaked token does not want.
        """
        token = new_token()
        with self._engine.begin() as connection:
            result = connection.execute(
                update(agents).where(agents.c.id == agent_id)
                .values(token_hash=hash_token(token)))
        return token if result.rowcount else None

    def seen(self, agent_id, version=None):
        """Record that an agent is alive. Called on every exchange."""
        values = {"last_seen_at": _now()}
        if version:
            values["version"] = version
        with self._engine.begin() as connection:
            connection.execute(
                update(agents).where(agents.c.id == agent_id).values(**values))

    def set_enabled(self, agent_id, enabled):
        with self._engine.begin() as connection:
            connection.execute(
                update(agents).where(agents.c.id == agent_id)
                .values(enabled=bool(enabled)))

    def delete(self, agent_id):
        with self._engine.begin() as connection:
            connection.execute(
                delete(monitor_agents).where(
                    monitor_agents.c.agent_id == agent_id))
            connection.execute(delete(agents).where(agents.c.id == agent_id))

    # ---------- reading ----------

    def by_token(self, token):
        """The agent this token belongs to, or None.

        Looked up by hash rather than compared one by one, so the cost does
        not grow with the number of agents — and so there is no loop whose
        duration leaks how far down the list a token was found.
        """
        if not token:
            return None
        with self._engine.connect() as connection:
            row = connection.execute(
                select(agents).where(
                    agents.c.token_hash == hash_token(token))).mappings().first()
        if row is None or not row["enabled"]:
            return None
        return self._public(row)

    def all(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(agents).order_by(agents.c.name)).mappings().all()
        return [self._public(r) for r in rows]

    def get(self, agent_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(agents).where(agents.c.id == agent_id)).mappings().first()
        return self._public(row) if row else None

    @staticmethod
    def _public(row):
        """Never the token hash. It leaves this class in no direction."""
        last_seen = _aware(row["last_seen_at"])
        return {
            "id": row["id"],
            "name": row["name"],
            "labels": row["labels"] or {},
            "last_seen_at": last_seen,
            "version": row["version"],
            "enabled": bool(row["enabled"]),
            "created_at": _aware(row["created_at"]),
            "stale": (last_seen is None
                      or (_now() - last_seen) > AGENT_STALE_AFTER),
        }


class MonitorRepository:
    def __init__(self, engine):
        self._engine = engine

    # ---------- validation ----------

    @staticmethod
    def validate(kind, target, interval, timeout):
        kind = (kind or "").strip().lower()
        if kind not in MONITOR_KINDS:
            raise MonitoringError(
                f"'{kind}' is not a check type. Available: "
                f"{', '.join(MONITOR_KINDS)}.")

        target = (target or "").strip()
        if not target:
            raise MonitoringError("A monitor needs something to check.")
        if kind == "http" and not target.startswith(("http://", "https://")):
            raise MonitoringError(
                "An http check needs a URL beginning http:// or https://.")
        if kind == "tcp":
            host, _, port = target.rpartition(":")
            if not host or not port.isdigit() or not 0 < int(port) < 65536:
                raise MonitoringError(
                    "A tcp check needs host:port, for example db.internal:5432.")

        interval = int(interval or 60)
        if not MIN_INTERVAL <= interval <= MAX_INTERVAL:
            raise MonitoringError(
                f"The interval has to be between {MIN_INTERVAL} and "
                f"{MAX_INTERVAL} seconds.")

        timeout = int(timeout or 10)
        if not 1 <= timeout <= MAX_TIMEOUT:
            raise MonitoringError(
                f"The timeout has to be between 1 and {MAX_TIMEOUT} seconds.")
        if timeout >= interval:
            # Otherwise a slow check is still running when the next one is due,
            # and the agent either overlaps them or silently skips.
            raise MonitoringError(
                "The timeout has to be shorter than the interval, or a slow "
                "check is still running when the next one is due.")
        return kind, target, interval, timeout

    # ---------- writing ----------

    def create(self, name, kind, target, interval_seconds=60,
               timeout_seconds=10, assertions=None, labels=None,
               agent_ids=(), created_by=None):
        kind, target, interval, timeout = self.validate(
            kind, target, interval_seconds, timeout_seconds)
        name = (name or "").strip()
        if not name:
            raise MonitoringError("A monitor needs a name.")

        now = _now()
        row = {
            "id": str(uuid.uuid4()),
            "name": name, "kind": kind, "target": target,
            "interval_seconds": interval, "timeout_seconds": timeout,
            "assertions": assertions or {},
            "labels": labels or {},
            "enabled": True,
            "created_by": created_by,
            "created_at": now, "updated_at": now,
        }
        with self._engine.begin() as connection:
            connection.execute(insert(monitors).values(**row))
            self._assign(connection, row["id"], agent_ids)
        return self.get(row["id"])

    def update(self, monitor_id, agent_ids=None, **changes):
        allowed = {"name", "kind", "target", "interval_seconds",
                   "timeout_seconds", "assertions", "labels", "enabled"}
        values = {k: v for k, v in changes.items() if k in allowed}
        if {"kind", "target", "interval_seconds", "timeout_seconds"} & set(values):
            current = self.get(monitor_id)
            if current is None:
                return None
            kind, target, interval, timeout = self.validate(
                values.get("kind", current["kind"]),
                values.get("target", current["target"]),
                values.get("interval_seconds", current["interval_seconds"]),
                values.get("timeout_seconds", current["timeout_seconds"]))
            values.update(kind=kind, target=target,
                          interval_seconds=interval, timeout_seconds=timeout)
        values["updated_at"] = _now()

        with self._engine.begin() as connection:
            result = connection.execute(
                update(monitors).where(monitors.c.id == monitor_id)
                .values(**values))
            if not result.rowcount:
                return None
            if agent_ids is not None:
                connection.execute(delete(monitor_agents).where(
                    monitor_agents.c.monitor_id == monitor_id))
                self._assign(connection, monitor_id, agent_ids)
        return self.get(monitor_id)

    def delete(self, monitor_id):
        with self._engine.begin() as connection:
            connection.execute(delete(monitor_agents).where(
                monitor_agents.c.monitor_id == monitor_id))
            connection.execute(delete(monitor_results).where(
                monitor_results.c.monitor_id == monitor_id))
            result = connection.execute(
                delete(monitors).where(monitors.c.id == monitor_id))
        return bool(result.rowcount)

    @staticmethod
    def _assign(connection, monitor_id, agent_ids):
        rows = [{"monitor_id": monitor_id, "agent_id": a}
                for a in dict.fromkeys(agent_ids or ())]
        if rows:
            connection.execute(insert(monitor_agents).values(rows))

    # ---------- reading ----------

    def all(self, enabled_only=False):
        query = select(monitors).order_by(monitors.c.name)
        if enabled_only:
            query = query.where(monitors.c.enabled.is_(True))
        with self._engine.connect() as connection:
            rows = connection.execute(query).mappings().all()
            assignments = self._assignments(connection)
        return [self._public(r, assignments.get(r["id"], [])) for r in rows]

    def get(self, monitor_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(monitors).where(
                    monitors.c.id == monitor_id)).mappings().first()
            if row is None:
                return None
            assignments = self._assignments(connection, monitor_id)
        return self._public(row, assignments.get(monitor_id, []))

    def for_agent(self, agent_id):
        """What this agent should be checking.

        A monitor with NO assignment is run by every agent. That is the useful
        default — one agent, everything on it — without making the common case
        require bookkeeping. Explicitly assigning it to nobody would mean a
        monitor that exists and is never checked, which looks like a broken
        agent.
        """
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(monitors).where(monitors.c.enabled.is_(True))
                .order_by(monitors.c.name)).mappings().all()
            assignments = self._assignments(connection)
        out = []
        for row in rows:
            assigned = assignments.get(row["id"], [])
            if not assigned or agent_id in assigned:
                out.append(self._public(row, assigned))
        return out

    @staticmethod
    def _assignments(connection, monitor_id=None):
        query = select(monitor_agents)
        if monitor_id:
            query = query.where(monitor_agents.c.monitor_id == monitor_id)
        out = {}
        for row in connection.execute(query).mappings():
            out.setdefault(row["monitor_id"], []).append(row["agent_id"])
        return out

    @staticmethod
    def _public(row, agent_ids):
        return {
            "id": row["id"], "name": row["name"], "kind": row["kind"],
            "target": row["target"],
            "interval_seconds": row["interval_seconds"],
            "timeout_seconds": row["timeout_seconds"],
            "assertions": row["assertions"] or {},
            "labels": row["labels"] or {},
            "enabled": bool(row["enabled"]),
            "created_by": row["created_by"],
            "agent_ids": list(agent_ids),
        }


class ResultRepository:
    def __init__(self, engine):
        self._engine = engine

    def record(self, agent_id, results):
        """Store a batch. Returns how many were kept.

        Results for monitors this agent is not assigned are DROPPED rather
        than stored: an ingest endpoint that accepts anything is a way to
        paint the whole board green, and a compromised agent should be able to
        lie about its own checks and nothing else.
        """
        if not results:
            return 0

        allowed = {m["id"] for m in MonitorRepository(self._engine)
                   .for_agent(agent_id)}
        received = _now()
        rows = []
        for result in results:
            monitor_id = result.get("monitor_id")
            if monitor_id not in allowed:
                logger.warning(
                    f"agent {agent_id} reported for monitor {monitor_id}, "
                    f"which it does not run")
                continue
            started = result.get("started_at")
            if isinstance(started, str):
                started = datetime.fromisoformat(started.replace("Z", "+00:00"))
            rows.append({
                "monitor_id": monitor_id,
                "agent_id": agent_id,
                "started_at": started or received,
                "received_at": received,
                "status": "down" if result.get("status") == "down" else "up",
                "duration_us": result.get("duration_us"),
                "error": (result.get("error") or "")[:2000] or None,
                "http_status": result.get("http_status"),
                "tls": result.get("tls"),
            })
        if not rows:
            return 0
        with self._engine.begin() as connection:
            connection.execute(insert(monitor_results).values(rows))
        return len(rows)

    def prune(self, older_than_days):
        """Delete results past the retention period. Returns how many went.

        Retention exists from the first version rather than being added later,
        because a table that grows without bound is noticed when it is already
        too large to clean up cheaply. Thirty days by default: a monitoring
        page is used to answer "when did this start", and a week cannot answer
        it for anything that started a fortnight ago.
        """
        if not older_than_days:
            return 0
        cutoff = _now() - timedelta(days=int(older_than_days))
        with self._engine.begin() as connection:
            result = connection.execute(
                delete(monitor_results).where(
                    monitor_results.c.started_at < cutoff))
        return result.rowcount or 0

    def latest(self, window_start=None):
        """The most recent result per (monitor, agent).

        Per PAIR, not per monitor: one check running from two places is two
        answers, and collapsing them throws away the only thing the second
        agent was installed to say.
        """
        query = select(
            monitor_results.c.monitor_id, monitor_results.c.agent_id,
            func.max(monitor_results.c.started_at).label("started_at"),
        ).group_by(monitor_results.c.monitor_id, monitor_results.c.agent_id)
        if window_start:
            query = query.where(monitor_results.c.started_at >= window_start)

        with self._engine.connect() as connection:
            pairs = connection.execute(query).mappings().all()
            if not pairs:
                return []
            # One row each, fetched by exact timestamp. A correlated subquery
            # per pair would be one query per monitor.
            rows = connection.execute(
                select(monitor_results).where(
                    monitor_results.c.started_at >= min(
                        _aware(p["started_at"]) for p in pairs))
            ).mappings().all()

        wanted = {(p["monitor_id"], p["agent_id"]): _aware(p["started_at"])
                  for p in pairs}
        out = {}
        for row in rows:
            key = (row["monitor_id"], row["agent_id"])
            if key in wanted and _aware(row["started_at"]) == wanted[key]:
                out[key] = dict(row)
        return list(out.values())

    def series(self, monitor_id, start, end, agent_id=None):
        """Every result for one monitor in a window, oldest first."""
        query = select(monitor_results).where(
            monitor_results.c.monitor_id == monitor_id,
            monitor_results.c.started_at >= start,
            monitor_results.c.started_at <= end,
        ).order_by(monitor_results.c.started_at)
        if agent_id:
            query = query.where(monitor_results.c.agent_id == agent_id)
        with self._engine.connect() as connection:
            return [dict(r) for r in
                    connection.execute(query).mappings().all()]

    def count(self, monitor_id=None):
        query = select(func.count()).select_from(monitor_results)
        if monitor_id:
            query = query.where(monitor_results.c.monitor_id == monitor_id)
        with self._engine.connect() as connection:
            return connection.execute(query).scalar() or 0
