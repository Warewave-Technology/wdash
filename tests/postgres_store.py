"""
The suite, on Postgres.

Every test opens its store through `build_engine`, almost always on SQLite:
a temporary file, or `:memory:`. With WDASH_TEST_POSTGRES set to a Postgres
URL whose user may create schemas, each of those is swapped for a schema of
its own in one database made for the run, and the run drops it at the end.
The same tests, on the other dialect — which nothing had ever run: the first
migration aborted its own transaction on an empty Postgres, so no
installation could get past its first start, and no test could have seen it.

A schema rather than a database per store: a database is a copy of a
template, seven megabytes and a tenth of a second each, and the suite opens
stores by the thousand. A schema is a name; `search_path` puts each engine in
its own.

Tests that are about SQLite itself — its journal mode, its file on disk —
are skipped on Postgres with `sqlite_only`, which says so.
"""

import atexit
import os
import unittest
import uuid
import weakref

URL = os.environ.get("WDASH_TEST_POSTGRES")

#: One schema per SQLite file, so a test reopening its file finds its data.
_schemas = {}
_database = None
#: Every engine opened on the run's database, closed before it is dropped —
#: a dropped database with connections still in a pool is a traceback at exit.
_engines = weakref.WeakSet()


def active():
    return bool(URL)


def sqlite_only(reason):
    """Skip a test that is about SQLite when the suite runs on Postgres."""
    return unittest.skipIf(active(), f"about SQLite: {reason}")


def _admin():
    import psycopg
    from sqlalchemy.engine import make_url
    parsed = make_url(URL).set(drivername="postgresql")
    return psycopg.connect(parsed.render_as_string(hide_password=False),
                           autocommit=True)


def _run_database():
    """The database this run's schemas live in: made by the first process
    that needs one, and named in the environment for the processes it
    starts, so four workers opening one file open one schema."""
    global _database
    if _database is None:
        from sqlalchemy.engine import make_url
        name = os.environ.get("WDASH_TEST_POSTGRES_DATABASE")
        if not name:
            name = f"wdash_suite_{uuid.uuid4().hex[:12]}"
            with _admin() as connection:
                connection.execute(f"CREATE DATABASE {name}")
            os.environ["WDASH_TEST_POSTGRES_DATABASE"] = name
            atexit.register(_drop, name)
        _database = make_url(URL).set(drivername="postgresql+psycopg", database=name)
    return _database


def _drop(name):
    for engine in list(_engines):
        try:
            engine.dispose()
        except Exception:
            pass
    try:
        with _admin() as connection:
            connection.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
    except Exception:
        pass


def _schema_for(sqlite_url):
    import psycopg
    database = _run_database()
    import hashlib
    path = sqlite_url.split("///", 1)[-1] if "///" in sqlite_url else ""
    key = None if path in ("", ":memory:") else os.path.abspath(path)
    if key is not None and key in _schemas:
        return database, _schemas[key]
    # Named by the file, so another process opening the same file finds the
    # same schema; a fresh one for every in-memory database.
    schema = "s_" + (hashlib.sha1(key.encode()).hexdigest()[:16] if key
                     else uuid.uuid4().hex[:16])
    with psycopg.connect(database.set(drivername="postgresql")
                         .render_as_string(hide_password=False),
                         autocommit=True) as connection:
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
        except psycopg.errors.UniqueViolation:
            # IF NOT EXISTS is not atomic in Postgres: two processes creating
            # the same schema at once, one of them is told it already exists
            # the hard way. It does, which is all that was wanted.
            pass
    if key is not None:
        _schemas[key] = schema
    return database, schema


def install():
    """Route every SQLite store the suite opens to a Postgres schema."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from wdash import store
    from wdash.store import database

    original = database.build_engine

    def build_engine(url=None, echo=False):
        text = str(url or "")
        if text.startswith("sqlite"):
            target, schema = _schema_for(text)
            url = target.update_query_dict({"options": f"-csearch_path={schema}"})
            engine = original(url, echo=echo)
            _engines.add(engine)
            return engine
        return original(url, echo=echo)

    database.build_engine = build_engine
    store.build_engine = build_engine
