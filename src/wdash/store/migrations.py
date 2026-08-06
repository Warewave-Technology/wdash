"""
Schema migrations.

A numbered list rather than Alembic. The schema is small, WDash owns every
table, and an autogenerating migration tool would add a directory of generated
files and an env.py to a project whose whole appeal is that it is easy to read.
Each step is a plain function; the applied version is a row, so it travels with
the data rather than with the checkout.

Migrations run at startup under a lock, because several gunicorn workers start
at once and must not race to create the same tables. There are two locks, one
per dialect, and neither is optional — see `_serialise`. The SQLite one was
missing for a while, which is why it is written down.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select, text

from .schema import metadata, schema_version

logger = logging.getLogger(__name__)


def _create_everything(connection):
    """Version 1: every table as defined in schema.py."""
    metadata.create_all(connection, checkfirst=True)


def _add_audit(connection):
    """Version 2: the authorization audit trail."""
    from .schema import audit
    audit.create(connection, checkfirst=True)


#: (version, description, function). Append only — never edit a released step,
#: because a deployment that already ran it will not run it again.
def _add_dashboard_visibility(connection):
    """Version 3: who may see that a dashboard exists.

    Existing rows default to 'shared', so nothing disappears on upgrade. The
    boundary rule still applies to them, which is the change.
    """
    from sqlalchemy import inspect, text
    columns = {column["name"] for column
               in inspect(connection).get_columns("wdash_dashboards")}
    if "visibility" not in columns:
        connection.execute(text(
            "ALTER TABLE wdash_dashboards ADD COLUMN visibility "
            "VARCHAR(16) NOT NULL DEFAULT 'shared'"))


def _add_signin_attempts(connection):
    """Sign-in history, for rate limiting and for the audit screen.

    Created on its own rather than through `create_all`, so an existing
    installation gets exactly this table and nothing else is touched.
    """
    from .schema import signin_attempts
    signin_attempts.create(connection, checkfirst=True)


def _add_audit_address(connection):
    """Where the actor was, on every audit row."""
    from sqlalchemy import inspect, text
    columns = {column["name"] for column
               in inspect(connection).get_columns("wdash_audit")}
    if "address" not in columns:
        connection.execute(text(
            "ALTER TABLE wdash_audit ADD COLUMN address VARCHAR(64)"))


def _add_audit_forwarding(connection):
    """The queue marker. Existing rows are unforwarded, which is correct —
    turning forwarding on should ship the history, not just what comes next."""
    from sqlalchemy import inspect, text
    columns = {column["name"] for column
               in inspect(connection).get_columns("wdash_audit")}
    if "forwarded_at" not in columns:
        connection.execute(text(
            "ALTER TABLE wdash_audit ADD COLUMN forwarded_at TIMESTAMP"))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_wdash_audit_forwarded_at "
            "ON wdash_audit (forwarded_at)"))


def _add_source_signals(connection):
    """One source, several signals.

    Backfilled from the old single-signal column so nothing changes for an
    existing row. Two rows pointing at one cluster are LEFT as two: merging
    them would have to choose which name survives and which credential wins,
    and guessing that on somebody's behalf is worse than leaving a tidy-up
    they can do themselves.
    """
    import json

    from sqlalchemy import inspect, text
    columns = {column["name"] for column
               in inspect(connection).get_columns("wdash_sources")}
    if "signals" not in columns:
        connection.execute(text(
            "ALTER TABLE wdash_sources ADD COLUMN signals TEXT"))

    for row in connection.execute(text(
            "SELECT id, signal FROM wdash_sources "
            "WHERE signals IS NULL")).mappings().all():
        connection.execute(
            text("UPDATE wdash_sources SET signals = :signals WHERE id = :id"),
            {"signals": json.dumps([row["signal"]]), "id": row["id"]})


def _grant_monitors_to_admins(connection):
    """Version 8: `monitors:read` for roles that already administer.

    DEFAULT_ROLES only applies to a database being seeded. An existing
    installation upgrading to a version with a Monitors screen would find
    nobody able to open it — including the administrator — and a permission
    nobody holds looks exactly like a broken page.

    Only roles that already hold `system:admin` are touched. That is the
    narrowest defensible rule: `system:admin` already means "everything", so
    this grants nothing that was not already implied. Editors and viewers are
    left alone, because giving somebody sight of every monitored endpoint is
    a decision, not a migration.
    """
    import json

    from sqlalchemy import text

    # `name` is the primary key here; there is no `id` column.
    rows = connection.execute(text(
        "SELECT name, permissions FROM wdash_roles")).mappings().all()
    for row in rows:
        try:
            permissions = json.loads(row["permissions"] or "[]")
        except (TypeError, ValueError):
            continue
        if not isinstance(permissions, list):
            continue
        if "system:admin" not in permissions or "monitors:read" in permissions:
            continue
        permissions.append("monitors:read")
        connection.execute(
            text("UPDATE wdash_roles SET permissions = :permissions "
                 "WHERE name = :name"),
            {"permissions": json.dumps(permissions), "name": row["name"]})


MIGRATIONS = [
    (1, "initial schema", _create_everything),
    (2, "authorization audit trail", _add_audit),
    (3, "dashboard visibility", _add_dashboard_visibility),
    (4, "sign-in attempt history", _add_signin_attempts),
    (5, "actor address on audit rows", _add_audit_address),
    (6, "audit forwarding queue marker", _add_audit_forwarding),
    (7, "one source, several signals", _add_source_signals),
    (8, "monitors:read for existing administrators", _grant_monitors_to_admins),
]


def current_version(connection):
    try:
        result = connection.execute(
            select(schema_version.c.version)
            .order_by(schema_version.c.version.desc()).limit(1)).scalar()
        return result or 0
    except Exception:
        # The version table itself does not exist yet.
        return 0


#: Written to only so that writing to it takes SQLite's write lock. It holds
#: one row and nobody reads it.
_LOCK_TABLE = "wdash_migration_lock"


def _serialise(connection, dialect):
    """Make every other worker wait until this one has finished.

    Postgres has advisory locks. SQLite does not, and it had NOTHING here —
    the module said migrations ran under a lock, and for the shipped image,
    which is SQLite with `--workers 4`, that was not true. Two workers both
    read version 0, both ran `CREATE TABLE`, and the loser died with

        sqlite3.OperationalError: table wdash_schema_version already exists
        [1] [ERROR] Reason: Worker failed to boot.

    taking the whole container with it.

    `engine.begin()` opens a DEFERRED transaction, so a SQLite write lock is
    not taken until the first write — by which time both workers have already
    read the version and decided what to do. Writing something first is what
    moves the lock ahead of that decision. Any write would do; a table nobody
    reads makes it obvious that the write is the point.

    Latecomers wait rather than fail: `busy_timeout` comes from the engine's
    `connect_args={"timeout": 15}`, and it IS honoured for ordinary
    statements — unlike `PRAGMA journal_mode`, which is its own story in
    database.py.
    """
    if dialect == "postgresql":
        # The number is arbitrary but must stay constant; it identifies this
        # lock. Released when the transaction ends, however it ends.
        connection.execute(text("SELECT pg_advisory_xact_lock(724301)"))
        return

    if dialect == "sqlite":
        connection.execute(text(
            f"CREATE TABLE IF NOT EXISTS {_LOCK_TABLE} (id INTEGER PRIMARY KEY)"))
        connection.execute(text(
            f"INSERT OR REPLACE INTO {_LOCK_TABLE} (id) VALUES (1)"))


def migrate(engine):
    """Bring the database up to the latest version. Safe to call concurrently."""
    with engine.begin() as connection:
        _serialise(connection, engine.dialect.name)

        version = current_version(connection)
        target = max(step[0] for step in MIGRATIONS)
        if version >= target:
            return version

        for number, description, step in MIGRATIONS:
            if number <= version:
                continue
            logger.info(f"Applying migration {number}: {description}")
            step(connection)
            connection.execute(schema_version.insert().values(
                version=number, applied_at=datetime.now(timezone.utc)))

        return target
