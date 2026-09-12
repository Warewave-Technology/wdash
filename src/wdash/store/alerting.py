"""
Alert rules, channels, state, silences and history.

The interesting one is `state`. Everything else is configuration; that table
is the memory that makes "failing for the third time running", "it has
recovered" and "do not say this again for ten minutes" possible at all.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, insert, select, update

from .schema import (
    alert_channels, alert_history, alert_rules, alert_silences, alert_state,
)

logger = logging.getLogger(__name__)


class AlertingError(ValueError):
    """A definition the store will not accept."""


def _now():
    return datetime.now(timezone.utc)


def _aware(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


class ChannelRepository:
    def __init__(self, engine, secret_box=None):
        self._engine = engine
        self._secrets = secret_box

    def create(self, name, kind="webhook", url=None, headers=None,
               secret_headers=None):
        from ..alerts.channels import CHANNEL_KINDS

        name = (name or "").strip()
        if not name:
            raise AlertingError("A channel needs a name.")
        if kind not in CHANNEL_KINDS:
            raise AlertingError(
                f"'{kind}' is not a channel type. Available: "
                f"{', '.join(CHANNEL_KINDS)}.")
        url = (url or "").strip()
        if not url.startswith(("http://", "https://")):
            raise AlertingError(
                "A webhook needs a URL beginning http:// or https://.")

        # The URL is a secret for Slack and Teams — the path IS the
        # credential — so it is sealed rather than stored beside the name. The
        # host is kept in the clear so a screen can say where alerts go
        # without being able to send one.
        from urllib.parse import urlparse
        parsed = urlparse(url)
        row = {
            "id": str(uuid.uuid4()),
            "name": name, "kind": kind,
            "config": {"host": parsed.netloc, "headers": headers or {}},
            "secrets": self._seal({"url": url,
                                   "headers": secret_headers or {}}),
            "enabled": True,
            "created_at": _now(),
        }
        with self._engine.begin() as connection:
            try:
                connection.execute(insert(alert_channels).values(**row))
            except Exception as exc:
                raise AlertingError(
                    f"A channel called '{name}' already exists.") from exc
        return self._public(row)

    def delete(self, channel_id):
        with self._engine.begin() as connection:
            connection.execute(
                delete(alert_channels).where(alert_channels.c.id == channel_id))

    def all(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(alert_channels).order_by(
                    alert_channels.c.name)).mappings().all()
        return [self._public(r) for r in rows]

    def get(self, channel_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(alert_channels).where(
                    alert_channels.c.id == channel_id)).mappings().first()
        return self._public(row) if row else None

    def credentials(self, channel_id):
        """The sealed half. For the alert runner, and nowhere else.

        Raises `DeliveryError` when the box will not open. It used to log a
        line with no reason and return {}, and `send` then refused for the
        only thing it could see — "This channel has no URL." — so every alert
        during a key rotation went into the history blaming a URL that was
        fine, and sent whoever read it to check the wrong thing.
        """
        from ..alerts.channels import DeliveryError
        from .secrets import SecretsCorrupt, SecretsUnavailable

        with self._engine.connect() as connection:
            row = connection.execute(
                select(alert_channels.c.secrets).where(
                    alert_channels.c.id == channel_id)).first()
        if not row or not row[0]:
            return {}
        try:
            # No `self._secrets is None` guard: the Store always hands one in
            # (`secret_box or SecretBox.from_environment()`, and
            # `from_environment` returns a box whether or not the variable is
            # set), so the branch could not fire — and `SecretBox.open`
            # raises the better sentence for a keyless box anyway.
            return json.loads(self._secrets.open(row[0]) or "{}")
        except (SecretsCorrupt, SecretsUnavailable) as exc:
            logger.error(f"could not read the credentials for channel "
                         f"{channel_id}: {exc}")
            raise DeliveryError(str(exc)) from exc
        except Exception as exc:
            logger.error(f"could not read the credentials for channel "
                         f"{channel_id}: {exc}")
            raise DeliveryError(
                f"this channel's stored credentials could not be read "
                f"({type(exc).__name__})") from exc

    def _seal(self, secret):
        if not secret:
            return None
        from .secrets import SecretsUnavailable
        if self._secrets is None:
            raise AlertingError(
                "WDASH_ENCRYPTION_KEY is not set, so a webhook URL cannot be "
                "stored — it is a credential.")
        try:
            return self._secrets.seal(json.dumps(secret))
        except SecretsUnavailable as exc:
            raise AlertingError(str(exc)) from exc

    @staticmethod
    def _public(row):
        return {
            "id": row["id"], "name": row["name"], "kind": row["kind"],
            # The host, not the URL. Enough for a screen to say where alerts
            # go; not enough for a reader to send one.
            "host": (row["config"] or {}).get("host", ""),
            "headers": (row["config"] or {}).get("headers", {}),
            "enabled": bool(row["enabled"]),
        }


class RuleRepository:
    def __init__(self, engine):
        self._engine = engine

    def create(self, name, kind, channel_id, threshold=3, repeat_minutes=0,
               days_before=None, selector=None, created_by=None):
        from ..alerts.evaluate import CERTIFICATE_EXPIRING, RULE_KINDS

        name = (name or "").strip()
        if not name:
            raise AlertingError("A rule needs a name.")
        if kind not in RULE_KINDS:
            raise AlertingError(
                f"'{kind}' is not a rule type. Available: "
                f"{', '.join(RULE_KINDS)}.")
        if not channel_id:
            raise AlertingError("A rule needs somewhere to send.")

        threshold = int(threshold or 1)
        if not 1 <= threshold <= 100:
            raise AlertingError("The threshold has to be between 1 and 100.")
        if kind == CERTIFICATE_EXPIRING:
            days_before = int(days_before or 30)
            if not 1 <= days_before <= 365:
                raise AlertingError(
                    "Warn between 1 and 365 days before expiry.")
            # A certificate does not flap. Requiring three consecutive
            # evaluations before saying so delays the warning by three
            # evaluation intervals for no benefit.
            threshold = 1

        now = _now()
        row = {
            "id": str(uuid.uuid4()), "name": name, "kind": kind,
            "selector": selector or {}, "threshold": threshold,
            "days_before": days_before,
            "repeat_minutes": max(0, int(repeat_minutes or 0)),
            "channel_id": channel_id, "enabled": True,
            "created_by": created_by, "created_at": now, "updated_at": now,
        }
        with self._engine.begin() as connection:
            connection.execute(insert(alert_rules).values(**row))
        return self.get(row["id"])

    def update(self, rule_id, **changes):
        allowed = {"name", "threshold", "repeat_minutes", "days_before",
                   "selector", "channel_id", "enabled"}
        values = {k: v for k, v in changes.items() if k in allowed}
        if not values:
            return self.get(rule_id)
        values["updated_at"] = _now()
        with self._engine.begin() as connection:
            result = connection.execute(
                update(alert_rules).where(alert_rules.c.id == rule_id)
                .values(**values))
        return self.get(rule_id) if result.rowcount else None

    def delete(self, rule_id):
        with self._engine.begin() as connection:
            connection.execute(
                delete(alert_state).where(alert_state.c.rule_id == rule_id))
            connection.execute(
                delete(alert_rules).where(alert_rules.c.id == rule_id))

    def all(self, enabled_only=False):
        query = select(alert_rules).order_by(alert_rules.c.name)
        if enabled_only:
            query = query.where(alert_rules.c.enabled.is_(True))
        with self._engine.connect() as connection:
            return [dict(r) for r in
                    connection.execute(query).mappings().all()]

    def get(self, rule_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(alert_rules).where(
                    alert_rules.c.id == rule_id)).mappings().first()
        return dict(row) if row else None


class AlertStateRepository:
    """The memory the state machine runs on."""

    def __init__(self, engine):
        self._engine = engine

    def load(self, rule_id):
        """subject -> State, for one rule."""
        from ..alerts.evaluate import State
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(alert_state).where(
                    alert_state.c.rule_id == rule_id)).mappings().all()
        return {r["subject"]: State(
            state=r["state"], failures=r["failures"],
            since=_aware(r["since"]),
            last_notified_at=_aware(r["last_notified_at"]),
            detail=r["detail"] or "") for r in rows}

    def save(self, rule_id, subject, state):
        values = {
            "state": state.state, "failures": state.failures,
            "since": state.since, "last_notified_at": state.last_notified_at,
            "detail": (state.detail or "")[:2000],
        }
        with self._engine.begin() as connection:
            changed = connection.execute(
                update(alert_state)
                .where(alert_state.c.rule_id == rule_id,
                       alert_state.c.subject == subject)
                .values(**values)).rowcount
            if not changed:
                connection.execute(insert(alert_state).values(
                    rule_id=rule_id, subject=subject, **values))

    def forget(self, rule_id, subject):
        with self._engine.begin() as connection:
            connection.execute(
                delete(alert_state).where(
                    alert_state.c.rule_id == rule_id,
                    alert_state.c.subject == subject))


class SilenceRepository:
    def __init__(self, engine):
        self._engine = engine

    def create(self, subject, until, reason=None, created_by=None):
        subject = (subject or "").strip()
        if not subject:
            raise AlertingError("A silence needs something to silence.")
        if until is None or _aware(until) <= _now():
            # A silence that has already expired is a control that did
            # nothing, and somebody walks away believing they set one.
            raise AlertingError("A silence has to end in the future.")
        row = {"id": str(uuid.uuid4()), "subject": subject, "until": until,
               "reason": reason, "created_by": created_by,
               "created_at": _now()}
        with self._engine.begin() as connection:
            connection.execute(insert(alert_silences).values(**row))
        return row

    def active(self, now=None):
        """The set of currently silenced subjects."""
        now = now or _now()
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(alert_silences.c.subject).where(
                    alert_silences.c.until > now)).all()
        return {r[0] for r in rows}

    def all(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(alert_silences).order_by(
                    alert_silences.c.until.desc())).mappings().all()
        return [dict(r, until=_aware(r["until"]),
                     created_at=_aware(r["created_at"])) for r in rows]

    def delete(self, silence_id):
        with self._engine.begin() as connection:
            connection.execute(
                delete(alert_silences).where(
                    alert_silences.c.id == silence_id))

    def prune(self, now=None):
        """Drop silences that ended. Keeps the list readable."""
        with self._engine.begin() as connection:
            return connection.execute(
                delete(alert_silences).where(
                    alert_silences.c.until < (now or _now()))).rowcount or 0


class AlertHistoryRepository:
    def __init__(self, engine):
        self._engine = engine

    def record(self, rule_id, subject, transition, detail="",
               delivered=False, error=None, label=None):
        """Every transition, delivered or not.

        A delivery that failed and was never written down is an alert nobody
        received and nobody knows was missed — the worst of both.
        """
        with self._engine.begin() as connection:
            connection.execute(insert(alert_history).values(
                at=_now(), rule_id=rule_id, subject=subject,
                subject_label=(label or subject)[:255],
                transition=transition, detail=(detail or "")[:2000],
                delivered=bool(delivered),
                delivery_error=(error or None)))

    @classmethod
    def _outstanding(cls, since=None, until=None):
        """Rows that are the LAST word on their (rule, subject).

        "Never delivered" has to be a thing that can drain. Counting every
        failed row ever written is one row per evaluation while a channel is
        broken — about 2,880 a day per subject at a thirty-second interval —
        and no later success ever took one away, so the badge on /alerts only
        ever went up while promising it drains by itself.

        By the primary key rather than `at`: several rows for one subject can
        share a timestamp to the millisecond, and then max(at) picks whichever
        the dialect happens to return.

        The last word IN THE WINDOW when there is one. Taking it over all
        time and filtering that row afterwards answered a question about now
        under a chart about then: an alert that reached nobody inside the
        window stopped counting the moment the same rule and subject spoke
        again AFTER the window — even when the later row failed too and
        nothing had been fixed. Measured through the board on an absolute
        past range: the alerts table drew ('checkout', delivered=no, "webhook
        refused: 500") while the number beside it read 0 under "of the 1
        alert in this window reached nobody". Only the END of a window can be
        in the past (`TimeWindow.between` rounds it up), so this is exactly
        the case `until` was added for.

        The drain is unchanged, because the window bounds the candidates as
        well as the answer: a failure retried successfully inside the window
        is still the last word there and still counts 0. What no longer
        happens is a window being called quiet because of something outside
        it.
        """
        from sqlalchemy import func
        newest = (select(func.max(alert_history.c.id))
                  .where(*cls._within(since, until))
                  .group_by(alert_history.c.rule_id, alert_history.c.subject))
        return (alert_history.c.delivered.is_(False),
                alert_history.c.id.in_(newest))

    @staticmethod
    def _within(since, until):
        """The window, as where-clauses on `at`.

        Neither bound is a default. The Alerts page asks for the last N
        alerts EVER and paginates them, which is the right question for a
        page you open once you already suspect something; a dashboard set to
        "Last 1 hour" asking the same question would put last month's alerts
        under an hour's charts.

        Both bounds, not just `since`: a dashboard can be pointed at an
        absolute range that ended in the past, and a since-only filter would
        answer "last Tuesday 14:00 until now" for a board reading
        14:00-15:00. Measured on both dialects with rows five minutes to four
        hours old — 5 rows, 3 inside a one-hour window, 1 inside an absolute
        60-100 minutes-ago window, SQLite and Postgres agreeing exactly.

        `at` is stored as `DateTime(timezone=True)`: a timestamptz on
        Postgres, and a naive UTC string on SQLite, where an aware UTC bind
        compares correctly because `record` writes UTC too.
        """
        clauses = []
        if since is not None:
            clauses.append(alert_history.c.at >= since)
        if until is not None:
            clauses.append(alert_history.c.at <= until)
        return clauses

    def recent(self, limit=100, offset=0, undelivered_only=False,
               since=None, until=None):
        query = select(alert_history).order_by(alert_history.c.at.desc())
        if undelivered_only:
            query = query.where(*self._outstanding(since, until))
        query = query.where(*self._within(since, until))
        query = query.limit(int(limit)).offset(int(offset))
        with self._engine.connect() as connection:
            return [dict(r, at=_aware(r["at"])) for r in
                    connection.execute(query).mappings().all()]

    def count(self, undelivered_only=False, since=None, until=None):
        from sqlalchemy import func
        query = select(func.count()).select_from(alert_history)
        if undelivered_only:
            # The window narrows WHICH rows are counted and which rows get to
            # be the last word, which are the same narrowing: a failure
            # retried successfully inside the window is drained by the
            # success, and one that was still failing when the window closed
            # counts, whatever happened afterwards. `_outstanding` is the
            # Alerts page's own definition — the last word on each rule and
            # subject — and the page asks it unbounded, which is unchanged.
            query = query.where(*self._outstanding(since, until))
        query = query.where(*self._within(since, until))
        with self._engine.connect() as connection:
            return connection.execute(query).scalar() or 0
