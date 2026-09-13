"""
Moving a metadata store from one database to another.

The documented way to more than one replica is Postgres, and the second step
of it read "migrate what is on the volume": accounts, roles, sources and their
sealed credentials, dashboards, the audit trail, agents, monitors and their
history, alerting. Nothing did it. `migrate_cli` moves dashboards and saved
searches, `recover` resets a password, and a generic copy tool knows neither
that JSON is text on SQLite and JSON on Postgres, nor that the schema carries
its own version, nor that a copied row keeps its id while a Postgres sequence
starts again at one.

    python -m wdash.store.copy --from sqlite:////data/wdash.db \\
        --to postgresql+psycopg://user:pass@host/wdash

The source is only read, and has to be at the version this WDash writes —
start this version against it once, which migrates it. The target is
migrated here and has to hold nothing but what migrating it wrote: since
migration 19 that is an empty installation's built-in roles and three
settings, which the source's replace. Every table is copied in the order its
keys need, through the schema, so a JSON value arrives as JSON and a time as
a time. Sealed columns are copied as they are: the target needs the same
WDASH_ENCRYPTION_KEY, and this needs none. Both databases are then counted,
table by table, and a difference is an error.
"""

import argparse
import logging
import sys
from datetime import timezone

from sqlalchemy import DateTime, func, select, text

from .database import build_engine, describe
from .migrations import MIGRATIONS, current_version, migrate
from .schema import metadata, schema_version

logger = logging.getLogger(__name__)

#: Rows written per statement.
CHUNK = 500


class CopyRefused(RuntimeError):
    """The copy would not be a faithful one, so it was not started."""


def _tables():
    return [t for t in metadata.sorted_tables if t is not schema_version]


def _counts(engine):
    with engine.connect() as connection:
        return {t.name: connection.execute(select(func.count()).select_from(t)).scalar()
                for t in _tables()}


def _aware(table):
    """The columns of `table` that hold a moment."""
    return [c.name for c in table.columns
            if isinstance(c.type, DateTime) and c.type.timezone]


def _contents(engine, names):
    """The rows of the named tables as the schema reads them, moments aside,
    in primary-key order — comparable across dialects and across days."""
    found = {}
    with engine.connect() as connection:
        for table in _tables():
            if table.name not in names:
                continue
            moments = {c.name for c in table.columns
                       if isinstance(c.type, DateTime)}
            keys = [c.name for c in table.primary_key.columns]
            rows = [{k: v for k, v in row.items() if k not in moments}
                    for row in connection.execute(select(table)).mappings()]
            found[table.name] = sorted(
                rows, key=lambda row: tuple(str(row[k]) for k in keys))
    return found


def _left_by_migrating():
    """What migrating an empty database leaves in it, table by table.

    Since migration 19 that is not nothing, and a target is not "occupied"
    for holding it: an installation with no roles is given the built-in ones.
    Measured rather than listed — a database of its own, migrated and read —
    so a later migration that writes a row is accounted for here without
    anybody remembering that this exists.
    """
    engine = build_engine("sqlite:///:memory:")
    try:
        migrate(engine)
        written = {name for name, rows in _counts(engine).items() if rows}
        return _contents(engine, written)
    finally:
        engine.dispose()


def copy_store(source, target, log=logger.info):
    """Copy every row from engine `source` to engine `target`.

    Returns {table: rows}. Raises CopyRefused before writing anything when
    the copy could not be faithful.
    """
    latest = max(step[0] for step in MIGRATIONS)
    with source.connect() as connection:
        version = current_version(connection)
    if version != latest:
        raise CopyRefused(
            f"the source is at schema version {version} and this WDash writes "
            f"{latest}. Start this version of WDash against it once — it "
            f"migrates on start — and copy after that.")

    migrate(target)
    held = {name: rows for name, rows in _counts(target).items() if rows}
    left = _left_by_migrating()
    # A table holding exactly what migrating wrote is replaced by the
    # source's rows. Anything else — one more row, one edited field, a table
    # migrating does not write to at all — is somebody's, and refused.
    migrated = _contents(target, set(held) & set(left))
    replaced = sorted(name for name in migrated if migrated[name] == left[name])
    occupied = {name: rows for name, rows in held.items()
                if name not in replaced}
    if occupied:
        raise CopyRefused(
            "the target is not empty: " + ", ".join(
                f"{rows} in {name}" for name, rows in sorted(occupied.items()))
            + ". Nothing was copied.")

    copied = {}
    with source.connect() as reading, target.begin() as writing:
        for table in reversed(_tables()):
            if table.name in replaced:
                writing.execute(table.delete())
                log(f"{table.name}: {held[table.name]} written by migrating "
                    f"the target, replaced")
        for table in _tables():
            moments = _aware(table)
            rows, total = [], 0
            for row in reading.execute(select(table)).mappings():
                row = dict(row)
                # SQLite hands back a naive time for a column declared with a
                # zone; WDash only ever wrote UTC into it.
                for name in moments:
                    if row.get(name) is not None and row[name].tzinfo is None:
                        row[name] = row[name].replace(tzinfo=timezone.utc)
                rows.append(row)
                if len(rows) >= CHUNK:
                    writing.execute(table.insert(), rows)
                    total += len(rows)
                    rows = []
            if rows:
                writing.execute(table.insert(), rows)
                total += len(rows)
            copied[table.name] = total
            log(f"{table.name}: {total}")
        if target.dialect.name == "postgresql":
            # The ids came with the rows; the sequences behind them did not.
            # Left at one, the next audit row or monitor result would collide
            # with a copied one.
            for table in _tables():
                for column in table.primary_key.columns:
                    if column.autoincrement is True:
                        writing.execute(text(
                            f"SELECT setval(pg_get_serial_sequence('{table.name}', "
                            f"'{column.name}'), COALESCE(MAX({column.name}), 1), "
                            f"MAX({column.name}) IS NOT NULL) FROM {table.name}"))

    arrived = _counts(target)
    different = {name: (rows, arrived.get(name)) for name, rows in copied.items()
                 if arrived.get(name) != rows}
    if different:
        raise RuntimeError(f"the target does not hold what was copied: {different}")
    return copied


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m wdash.store.copy",
        description="Copy a WDash metadata store into an empty database.")
    parser.add_argument("--from", dest="source", required=True,
                        help="the store to copy, e.g. sqlite:////data/wdash.db")
    parser.add_argument("--to", dest="target", required=True,
                        help="an empty database, e.g. postgresql+psycopg://…")
    arguments = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    source, target = build_engine(arguments.source), build_engine(arguments.target)
    print(f"copying {describe(source)} into {describe(target)}")
    try:
        copied = copy_store(source, target, log=print)
    except CopyRefused as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2
    print(f"done: {sum(copied.values())} rows in {len(copied)} tables. "
          f"Start WDash against the target with the same WDASH_ENCRYPTION_KEY.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
