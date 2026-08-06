"""
Who changed what, in the authorization configuration.

Logging already said that a change happened. It could not answer "what could
this role see last Tuesday" — the question that comes up exactly once, after
something has gone wrong, by which time the log has rotated and the current
state is the only state anybody can see.

Append-only, and not deletable from the UI. An audit trail an administrator can
edit is not an audit trail.

Recording failures matters as much as recording successes: a refused attempt to
grant somebody administration is the more interesting row.
"""

import datetime as dt
import logging
from datetime import datetime, timezone

from sqlalchemy import desc, select

from .schema import audit

logger = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, engine):
        self._engine = engine

    @staticmethod
    def _serialisable(value):
        """Make a stored object safe for a JSON column.

        Role and settings dictionaries carry `updated_at` as a datetime, which
        no JSON encoder will take. Swallowing that failure meant successful
        changes silently produced no audit row while refused ones did — an
        audit trail that records only what did not happen.
        """
        if isinstance(value, dict):
            return {key: AuditLog._serialisable(item)
                    for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [AuditLog._serialisable(item) for item in value]
        if isinstance(value, (dt.datetime, dt.date)):
            return value.isoformat()
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        return str(value)

    def record(self, actor, action, subject=None, state=None, address=None):
        """Write one entry. Never raises.

        A failure to record must not take down the change itself — losing an
        audit row is bad, refusing an administrator's repair because the audit
        table is unhappy is worse.
        """
        state = self._serialisable(state)
        try:
            with self._engine.begin() as connection:
                connection.execute(audit.insert().values(
                    at=datetime.now(timezone.utc),
                    actor=actor or "unknown",
                    action=action,
                    subject=subject,
                    address=address,
                    state=state))
        except Exception as exc:
            logger.error(f"Could not write audit entry '{action}': {exc}")

    def recent(self, limit=100, subject=None, actor=None, action=None,
               since=None, until=None, offset=0):
        """A page of the trail, newest first.

        Filters are ANDed and all optional. `offset` pages rather than
        streaming everything: an audit trail is append-only and grows forever,
        so "show me the last hundred" has to be the default rather than a
        thing the caller remembers to ask for.
        """
        try:
            query = select(audit).order_by(desc(audit.c.at))
            if subject:
                query = query.where(audit.c.subject == subject)
            if actor:
                query = query.where(audit.c.actor == actor)
            if action:
                query = query.where(audit.c.action == action)
            if since is not None:
                query = query.where(audit.c.at >= since)
            if until is not None:
                query = query.where(audit.c.at <= until)
            query = query.limit(limit).offset(offset)
            with self._engine.connect() as connection:
                rows = connection.execute(query).mappings().all()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.error(f"Could not read the audit trail: {exc}")
            return []

    def count(self, subject=None, actor=None, action=None,
              since=None, until=None):
        """How many rows match, so the page can say what it is a page OF."""
        from sqlalchemy import func
        try:
            query = select(func.count()).select_from(audit)
            if subject:
                query = query.where(audit.c.subject == subject)
            if actor:
                query = query.where(audit.c.actor == actor)
            if action:
                query = query.where(audit.c.action == action)
            if since is not None:
                query = query.where(audit.c.at >= since)
            if until is not None:
                query = query.where(audit.c.at <= until)
            with self._engine.connect() as connection:
                return connection.execute(query).scalar() or 0
        except Exception as exc:
            logger.error(f"Could not count the audit trail: {exc}")
            return 0

    def actions(self):
        """Distinct action names, for a filter that offers what exists.

        A free-text box here would be the same mistake the permission
        catalogue exists to prevent: a typo that returns nothing looks
        identical to a period when nothing happened.
        """
        try:
            with self._engine.connect() as connection:
                rows = connection.execute(
                    select(audit.c.action).distinct()
                    .order_by(audit.c.action)).scalars().all()
            return list(rows)
        except Exception as exc:
            logger.error(f"Could not list audit actions: {exc}")
            return []

    def state_at(self, subject, moment):
        """What `subject` looked like at `moment`, or None.

        The whole point of storing the resulting state rather than a diff: one
        row answers the question without replaying anything.
        """
        try:
            with self._engine.connect() as connection:
                row = connection.execute(
                    select(audit)
                    .where(audit.c.subject == subject)
                    .where(audit.c.at <= moment)
                    .order_by(desc(audit.c.at)).limit(1)).mappings().first()
            return dict(row) if row else None
        except Exception as exc:
            logger.error(f"Could not read the audit trail: {exc}")
            return None
