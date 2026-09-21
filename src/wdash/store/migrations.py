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

from sqlalchemy import inspect, select, text

from .schema import metadata, schema_version
from .sources import without_password

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
        # Text on SQLite, already a list on Postgres, where psycopg reads a
        # JSON column for itself. Only the text was expected: json.loads on
        # a list raised TypeError, which was caught as "not a list of
        # permissions" — so on Postgres every administrator was skipped, and
        # the Monitors screen opened for nobody.
        value = row["permissions"]
        try:
            permissions = value if isinstance(value, list) else json.loads(value or "[]")
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


def _add_own_monitoring(connection):
    """Version 9: agents, monitors, their assignment, and results.

    Created here rather than by widening `_create_everything`, because that
    step already ran on every existing installation and will never run again.
    A table added to it is a table nobody upgrading ever gets.
    """
    from .schema import agents, monitor_agents, monitor_results, monitors
    for table in (agents, monitors, monitor_agents, monitor_results):
        table.create(connection, checkfirst=True)


def _index_monitor_results(connection):
    """Version 10: the two indexes the listing needs.

    Version 9 shipped one index, on (monitor_id, started_at) — right for the
    detail page, which asks about one monitor, and useless for the listing,
    which filters on time across all of them. Measured on 8.6 million rows the
    listing took 1.7 seconds and the sparklines 3.1, both on a full table
    scan.

    Added as a migration rather than by editing version 9: that step already
    ran everywhere and will never run again.
    """
    from sqlalchemy import text
    for name, columns in (
            ("ix_wdash_monitor_results_time", "started_at"),
            ("ix_wdash_monitor_results_latest",
             "monitor_id, agent_id, started_at"),
    ):
        connection.execute(text(
            f"CREATE INDEX IF NOT EXISTS {name} "
            f"ON wdash_monitor_results ({columns})"))


def _add_monitor_request(connection):
    """Version 11: request configuration and its secrets.

    Two columns rather than widening `assertions`, because they answer
    different questions: assertions are about the RESPONSE and are safe to
    show anywhere, while the request carries credentials that must never be
    read back to a screen.
    """
    from sqlalchemy import inspect, text
    columns = {column["name"] for column
               in inspect(connection).get_columns("wdash_monitors")}
    if "request" not in columns:
        connection.execute(text(
            "ALTER TABLE wdash_monitors ADD COLUMN request TEXT"))
    if "secrets" not in columns:
        connection.execute(text(
            "ALTER TABLE wdash_monitors ADD COLUMN secrets TEXT"))


def _add_alerting(connection):
    """Version 12: rules, channels, state, silences and history."""
    from .schema import (
        alert_channels, alert_history, alert_rules, alert_silences, alert_state,
    )
    for table in (alert_channels, alert_rules, alert_state, alert_silences,
                  alert_history):
        table.create(connection, checkfirst=True)


def _add_alert_label(connection):
    """Version 13: the name a history row is about.

    Version 12 stored the subject id alone, so the history screen showed a
    uuid. Looking the name up at render time does not work either: history is
    most often read about a monitor that has since been deleted.
    """
    from sqlalchemy import inspect, text
    columns = {column["name"] for column
               in inspect(connection).get_columns("wdash_alert_history")}
    if "subject_label" not in columns:
        connection.execute(text(
            "ALTER TABLE wdash_alert_history ADD COLUMN subject_label VARCHAR(255)"))


def _add_browser_journeys(connection):
    """Version 14: browser journeys and the evidence from a failed one.

    Three additions, none of which touch an existing row: a step list on the
    monitor, the per-step results on each run, and the screenshots in their
    own table so retention can drop pictures long before it drops history.
    """
    from sqlalchemy import inspect, text
    from .schema import journey_screenshots

    inspector = inspect(connection)
    json_type = "JSONB" if connection.dialect.name == "postgresql" else "TEXT"

    for table, column, kind in (
            ("wdash_monitors", "steps", json_type),
            ("wdash_monitor_results", "steps", json_type),
            ("wdash_monitor_results", "screenshot_id", "VARCHAR(64)")):
        existing = {c["name"] for c in inspector.get_columns(table)}
        if column not in existing:
            connection.execute(
                text(f"ALTER TABLE {table} ADD COLUMN {column} {kind}"))

    journey_screenshots.create(connection, checkfirst=True)


def _index_alert_history_latest(connection):
    """Version 15: the index the "never delivered" badge needs.

    That badge now asks for the LAST row per (rule, subject) rather than
    every failed row ever written, which is what let it drain — and which
    turned it into a `max(id) GROUP BY rule_id, subject` over the one table
    that grows a row per evaluation while a channel is broken, roughly 2,880
    a day per subject. It is read on every render of /alerts (twice when the
    undelivered filter is on) and once on the configuration page.

    Measured on SQLite, 200,000 rows over five subjects: 96 ms to 12 ms, the
    plan going from SCAN + USE TEMP B-TREE FOR GROUP BY to a covering index
    scan.

    Added as a migration as well as to the table, so an existing database
    gets it — version 12 created this table and will never run again.
    """
    from sqlalchemy import text
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_wdash_alert_history_latest "
        "ON wdash_alert_history (rule_id, subject, id)"))

def _report_source_name_collisions(connection):
    """Version 16: name the sources that have been shadowing each other.

    Until now two rows could share a name as long as their legacy `signal`
    columns differed, so an Elasticsearch source called `prod` serving logs
    and traces sat beside a Jaeger `prod` serving traces. Both were stored,
    both were built, and the hub keeps one registry per signal keyed by name
    — so one of them answered every trace query, the `*` fan-out included,
    and the other was never asked. The configuration page showed two healthy
    sources. `SourceRepository` refuses this now, which does nothing for a
    store that already has it.

    The rows are left exactly as they are. Merging them would have to choose
    which name survives and which credential wins, and renaming one silently
    would break every role rule that names it (`prod:app-*` is a rule for a
    source called prod and a pattern for everybody else). What this step does
    is make the collision visible: a log line for whoever is watching the
    upgrade, and an audit row, which is the copy still there next week — and
    the audit screen is where an administrator looks when a source they
    configured is returning nothing.
    """
    from .schema import audit, sources

    rows = connection.execute(select(
        sources.c.id, sources.c.name, sources.c.kind,
        sources.c.signal, sources.c.signals)).mappings().all()

    by_name = {}
    for row in rows:
        by_name.setdefault(row["name"], []).append(row)

    for name, group in sorted(by_name.items()):
        if len(group) < 2:
            continue
        for index, row in enumerate(group):
            mine = _signals_of(row)
            for other in group[index + 1:]:
                shared = sorted(mine & _signals_of(other))
                if not shared:
                    continue
                logger.warning(
                    "Two sources are called %r and both serve %s: %s (%s) "
                    "and %s (%s). Only one of them is ever asked. Rename one "
                    "on the configuration page.",
                    name, " and ".join(shared), row["id"], row["kind"],
                    other["id"], other["kind"])
                connection.execute(audit.insert().values(
                    at=datetime.now(timezone.utc),
                    actor="migration",
                    action="source name collision",
                    subject=f"source:{name}",
                    state={
                        "name": name, "signals": shared,
                        "sources": [{"id": row["id"], "kind": row["kind"]},
                                    {"id": other["id"],
                                     "kind": other["kind"]}],
                        "consequence": "Only one of these answers a query "
                                       "for this signal; the other is never "
                                       "asked.",
                    }))


def _add_monitor_tls(connection):
    """Version 17: a check's own TLS decision, and what its handshake did.

    Two columns, added NULL, on the guarded ALTER shape migration 14 uses.
    NULL on `wdash_monitors.tls` reads as "verify against the public roots",
    which is what every existing check already does, so no check changes its
    behaviour, its result or its alerts on upgrade. NULL on
    `wdash_monitor_results.handshake_verified` reads as "this run does not
    say", which is true of every result written before this change — it must
    not read as "verified", and it must not read as a finding either.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(connection)
    json_type = "JSONB" if connection.dialect.name == "postgresql" else "TEXT"

    for table, column, kind in (
            ("wdash_monitors", "tls", json_type),
            ("wdash_monitor_results", "handshake_verified", "BOOLEAN")):
        existing = {c["name"] for c in inspector.get_columns(table)}
        if column not in existing:
            connection.execute(
                text(f"ALTER TABLE {table} ADD COLUMN {column} {kind}"))


def _add_local_totp(connection):
    """Version 18: a local account's second factor.

    Three columns, added NULL, on the guarded ALTER shape migrations 14 and
    17 use. NULL on all three reads as "this account has not enrolled", which
    is true of every account that exists at the moment of the upgrade — and
    what it means is that its next sign-in enrols. It must not read as
    "enrolled, with no secret": that is an account which can never produce a
    code that matches, and the way out of it is the recovery tool.

    Nothing is backfilled and nobody is locked out by the upgrade itself. The
    accounts that existed keep their passwords, keep their roles, and are
    asked to enrol the next time they sign in.
    """
    from sqlalchemy import inspect, text

    existing = {column["name"] for column
                in inspect(connection).get_columns("wdash_users")}
    for column, kind in (("totp_secret", "TEXT"),
                         ("totp_confirmed_at", "TIMESTAMP"),
                         ("totp_last_step", "BIGINT")):
        if column not in existing:
            connection.execute(text(
                f"ALTER TABLE wdash_users ADD COLUMN {column} {kind}"))


def _give_an_installation_with_no_roles_the_built_in_ones(connection):
    """Version 19: the built-in roles, the default role and the claim
    mappings — for an installation that has no roles, and for no other.

    They were written by `RoleRepository.seed`, on every start that found the
    roles table empty: after the migration and outside its lock, so the
    workers booting one new installation raced each other to it, and each
    write needed an upsert to survive the worker beside it. Here they are
    written once, in the transaction that creates the tables, under the lock
    every worker takes, and committed with the version row that says so.

    An installation that has any role is left exactly as it is. Somebody's
    edited `admin` is not reset by an upgrade, and an installation that
    imported `auditor` and `ops` from an rbac.yaml at an earlier version is
    not given an `admin` beside them — which would map `wdash-admins` onto
    `system:admin` in an organisation that never granted it to anybody.

    Each setting is written only where none is stored. On a new installation
    none can be. Where the roles table was emptied by hand, the one that
    matters is the claim mapping, whose loss is silent: `memberOf` replaced
    by `groups` resolves no group mapping for anybody, and everybody lands
    on the default role.

    `DEFAULT_ROLES` is read when this runs, which for a new installation is
    the version being installed. Changing it later changes what a new
    installation gets and does nothing for one that exists — that takes a
    migration of its own, as `monitors:read` did at version 8.
    """
    from .roles import DEFAULT_CLAIM_MAPPINGS, DEFAULT_ROLES
    from .schema import roles, settings

    if connection.execute(select(roles.c.name).limit(1)).first() is not None:
        return

    now = datetime.now(timezone.utc)
    for name, definition in DEFAULT_ROLES.items():
        services = definition["services"]
        connection.execute(roles.insert().values(
            name=name,
            description=definition["description"],
            permissions=list(definition["permissions"]),
            containers=list(definition["containers"]),
            trace_containers=list(definition["trace_containers"]),
            services=list(services) if services is not None else None,
            groups=list(definition["groups"]),
            updated_at=now))

    stored = set(connection.execute(select(settings.c.key)).scalars())
    for key, value in (("rbac.default_role", "viewer"),
                       ("rbac.user_roles", {}),
                       ("rbac.claim_mappings", dict(DEFAULT_CLAIM_MAPPINGS))):
        if key not in stored:
            connection.execute(settings.insert().values(
                key=key, value=value, updated_at=now))


def _signals_of(row):
    """What a source row serves, as a set.

    Read through the typed column rather than through raw SQL, so SQLAlchemy
    decodes the JSON on both dialects and this does not have to know which
    one it is on. Migration 8 read a JSON column through `text()`, got a
    string on SQLite and a list on Postgres, and quietly skipped every row on
    one of them.

    A row still carrying NULL — written before migration 7 and never
    backfilled — falls back to the legacy single-signal column, which is the
    same rule `SourceRepository._public` reads by.
    """
    value = row["signals"]
    if not isinstance(value, list):
        value = [row["signal"]]
    return set(value)


def _report_source_urls_holding_a_password(connection):
    """Version 20: name the sources whose address carries a credential.

    `validate_url` refuses `https://reader:secret@es:9200` now. A row saved
    before it did still holds that password in clear text in the `config`
    column, where the `secrets` column beside it is the one that is sealed —
    so a dump or a replica of this database carries a working credential, and
    the configuration page used to print it.

    The rows are left exactly as they are, for a reason that is not the one
    migration 16 had. It is not that rewriting them is ambiguous: it is that
    sealing needs the encryption key, and migrations deliberately run without
    one. `Store.open` migrates BEFORE it builds a `SecretBox`, because an
    installation with no key must still be able to start and be given one,
    and a step that needed the key would take that away. So this cannot move
    the credential; only the operator can, and the save that used to accept
    it now refuses it until they do.

    What is left is to make sure nobody has to discover this by reading the
    database: a log line for whoever is watching the upgrade, and an audit
    row, which is the copy still there next week. Both masked — the point is
    that this value has travelled far enough already.
    """
    from urllib.parse import urlsplit

    from .schema import audit, sources

    rows = connection.execute(select(
        sources.c.id, sources.c.name, sources.c.config)).mappings().all()

    for row in rows:
        url = (row["config"] or {}).get("url") or ""
        # `urlsplit` on something that is not a URL at all returns a part-less
        # result rather than raising, which is the answer we want: a row whose
        # config was hand-written is not a finding.
        try:
            password = urlsplit(url).password
        except ValueError:
            continue
        if password is None:
            continue

        masked = without_password(url)
        logger.warning(
            "Source %r (%s) has a password written into its address: %s. It "
            "is stored in clear text, unlike the password box beside it. "
            "Open the source on the configuration page, take the credential "
            "out of the address and type it into the username and password "
            "boxes — saving it in the address is refused from this version "
            "on.", row["name"], row["id"], masked)
        connection.execute(audit.insert().values(
            at=datetime.now(timezone.utc),
            actor="migration",
            action="source password in the address",
            subject=f"source:{row['id']}",
            state={
                "name": row["name"], "url": masked,
                "consequence": "The password is in the config column in "
                               "clear text, not in the sealed secrets "
                               "column, so a dump or a replica of this "
                               "database carries a working credential.",
                "remedy": "Re-save the source with the credential in the "
                          "username and password boxes.",
            }))


def _take_the_credential_out_of_the_channel_host(connection):
    """Version 21: drop `user:password@` from every stored channel host.

    `ChannelRepository.create` used to store `urlparse(url).netloc` verbatim
    in the clear `config` column, and a netloc carries the userinfo. So a
    webhook saved as `https://alerts:s3cr3t@hooks.example.com/...` had that
    password on disk unencrypted, on the configuration page under the words
    "the full URL is encrypted and not shown", in its `channel added` audit
    row and in the application log.

    Unlike the source URLs migration 20 can only report, these rows CAN be
    repaired here, and for a reason worth saying out loud: nothing is lost.
    The whole URL, credential and all, is already in the sealed `secrets`
    column — `config.host` was only ever a duplicate for the screen to read,
    and `send()` uses the sealed copy. So this needs no encryption key,
    which migrations do not have, and no channel changes where it delivers.

    The audit rows and log lines already written are not rewritten. An
    append-only trail is the point of one, and a migration that edited it to
    hide a disclosure would be a worse thing than the disclosure.
    """
    from .alerting import where_it_goes
    from .schema import alert_channels

    rows = connection.execute(select(
        alert_channels.c.id, alert_channels.c.name,
        alert_channels.c.config)).mappings().all()

    for row in rows:
        config = dict(row["config"] or {})
        host = config.get("host") or ""
        if "@" not in host:
            continue
        config["host"] = where_it_goes(f"https://{host}")
        connection.execute(alert_channels.update().where(
            alert_channels.c.id == row["id"]).values(config=config))
        logger.warning(
            "Channel %r had a credential in its stored host; it has been "
            "reduced to %r. The credential is still in the sealed column, "
            "so the channel delivers exactly as before — but it was on the "
            "configuration page and in the audit trail, so rotate it.",
            row["name"], config["host"])


MIGRATIONS = [
    (1, "initial schema", _create_everything),
    (2, "authorization audit trail", _add_audit),
    (3, "dashboard visibility", _add_dashboard_visibility),
    (4, "sign-in attempt history", _add_signin_attempts),
    (5, "actor address on audit rows", _add_audit_address),
    (6, "audit forwarding queue marker", _add_audit_forwarding),
    (7, "one source, several signals", _add_source_signals),
    (8, "monitors:read for existing administrators", _grant_monitors_to_admins),
    (9, "agents, monitors and their results", _add_own_monitoring),
    (10, "index monitor results for the listing", _index_monitor_results),
    (11, "monitor request configuration and its secrets", _add_monitor_request),
    (12, "alert rules, channels, state and history", _add_alerting),
    (13, "the name an alert was about", _add_alert_label),
    (14, "browser journeys, their steps and their screenshots",
     _add_browser_journeys),
    (15, "index alert history for the undelivered badge",
     _index_alert_history_latest),
    (16, "report sources that shadow each other by name",
     _report_source_name_collisions),
    (17, "a check's own TLS decision, and whether its handshake was verified",
     _add_monitor_tls),
    (18, "a local account's second factor, sealed at rest", _add_local_totp),
    (19, "the built-in roles, default role and claim mappings, for an "
         "installation with no roles",
     _give_an_installation_with_no_roles_the_built_in_ones),
    (20, "report the sources whose address carries a password",
     _report_source_urls_holding_a_password),
    (21, "take the credential out of every stored alert channel host",
     _take_the_credential_out_of_the_channel_host),
]


def current_version(connection):
    """The newest migration applied, 0 on a database that has none.

    Asked whether the version table exists, not told by an error. It used
    to query the table and read a failure as "version 0" — which on SQLite
    is true and on Postgres is fatal: a failed statement aborts the whole
    transaction, and this runs inside the one every migration then needs.
    Measured against an empty Postgres 16: every start ended in "current
    transaction is aborted, commands ignored until end of transaction
    block", so no Postgres installation could get past its first start.
    """
    if not inspect(connection).has_table(schema_version.name):
        return 0
    result = connection.execute(
        select(schema_version.c.version)
        .order_by(schema_version.c.version.desc()).limit(1)).scalar()
    return result or 0


#: Written to only so that writing to it takes SQLite's write lock. It holds
#: one row and nobody reads it.
_LOCK_TABLE = "wdash_migration_lock"


def serialise_writes(connection, dialect, postgres_key):
    """Take the lock that makes a read-then-write atomic for other workers.

    Public, and shared with `audit.record_state`: the two have the same
    problem exactly — decide from a read, then write — and solving it twice
    means solving it differently the second time. `postgres_key` names the
    lock so that two callers doing different work do not wait for each
    other; SQLite has one writer for the whole database, so the table below
    serves everybody.
    """
    if dialect == "postgresql":
        # Released when the transaction ends, however it ends.
        connection.execute(text("SELECT pg_advisory_xact_lock(:key)"),
                           {"key": postgres_key})
        return

    if dialect == "sqlite":
        connection.execute(text(
            f"CREATE TABLE IF NOT EXISTS {_LOCK_TABLE} (id INTEGER PRIMARY KEY)"))
        connection.execute(text(
            f"INSERT OR REPLACE INTO {_LOCK_TABLE} (id) VALUES (1)"))


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
    # The number is arbitrary but must stay constant; it identifies this
    # lock.
    serialise_writes(connection, dialect, 724301)


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
