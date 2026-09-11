"""
Several processes starting against one SQLite database at the same time.

The shipped image runs `gunicorn --workers 4`, so four processes call
`create_app` within milliseconds of each other. On a fresh database that used
to end like this:

    File "/app/src/wdash/store/database.py", line 63, in _configure_sqlite
        cursor.execute("PRAGMA journal_mode=WAL")
    sqlite3.OperationalError: database is locked
    [1] [ERROR] Worker failed to boot.
    [1] [ERROR] Shutting down: Master

Exit code 3, and the whole container with it — so a first deployment could
not start. `connect_args={"timeout": 15}` did not help: changing journal mode
needs exclusive access and is the one statement SQLite refuses immediately
instead of waiting out `busy_timeout`.

Nothing about it was intermittent in a way that helps, either. It depends on
which worker wins, so it starts perhaps one time in three — the shape of bug
that gets closed as "could not reproduce".
"""

import multiprocessing
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.postgres_store import sqlite_only  # noqa: E402
from wdash.store.database import build_engine  # noqa: E402

WORKERS = 4


def _open_and_count(url, barrier=None, results=None):
    """What a worker does on boot: connect, then read something.

    Top level and argument-driven because `spawn` re-imports this module in
    every child — a closure would not survive the trip.
    """
    from sqlalchemy import text
    try:
        engine = build_engine(url)
        if barrier is not None:
            barrier.wait(timeout=20)      # start together, not in turn
        with engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar()
        engine.dispose()
        outcome = "ok"
    except Exception as exc:
        outcome = f"{type(exc).__name__}: {exc}"
    if results is not None:
        results.put(outcome)
    return outcome


@sqlite_only("its journal mode and its lock")
class ConcurrentStartTest(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.path)          # a FRESH database: the failing case
        self.url = f"sqlite:///{self.path}"

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.path + suffix):
                os.unlink(self.path + suffix)

    def test_four_workers_can_start_together_on_a_fresh_database(self):
        """`--workers 4` in the Dockerfile is not a hypothetical number.

        Processes rather than a Pool: `Pool` pickles its arguments with a
        pickler that refuses synchronisation primitives, and without the
        barrier the workers start in turn — which is the case that always
        passed.
        """
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(WORKERS)
        results = context.Queue()
        workers = [context.Process(target=_open_and_count,
                                   args=(self.url, barrier, results))
                   for _ in range(WORKERS)]
        for worker in workers:
            worker.start()
        outcomes = [results.get(timeout=30) for _ in workers]
        for worker in workers:
            worker.join(timeout=30)

        self.assertEqual(sorted(outcomes), ["ok"] * WORKERS)
        # Gunicorn shuts the master down when a worker fails to boot, so a
        # non-zero exit here is the whole container going away.
        self.assertEqual([w.exitcode for w in workers], [0] * WORKERS)

    def test_the_database_still_ends_up_in_wal(self):
        """Catching the race must not mean quietly giving up on WAL — without
        it a reader blocks every writer, which is the reason it is set."""
        _open_and_count(self.url)
        with sqlite3.connect(self.path) as connection:
            mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

    def test_connecting_while_another_connection_holds_the_file(self):
        """The race, made deterministic.

        A second connection is open and the file is NOT yet in WAL, which is
        exactly the state a losing worker finds. Setting journal_mode here
        raises; surviving it is the fix.
        """
        # Create the file in the default (rollback) journal mode.
        with sqlite3.connect(self.path) as setup:
            setup.execute("PRAGMA journal_mode=DELETE")
            setup.execute("CREATE TABLE t (x INTEGER)")

        holder = sqlite3.connect(self.path)
        holder.execute("BEGIN")
        holder.execute("INSERT INTO t VALUES (1)")   # holds the write lock
        try:
            self.assertEqual(_open_and_count(self.url), "ok")
        finally:
            holder.rollback()
            holder.close()

    def test_a_second_start_on_a_wal_database_writes_no_pragma(self):
        """Once set, the mode is read and left alone. Re-issuing it on every
        connect is what put the statement in the path of the race.

        Observed with SQLite's own trace callback, installed by a `connect`
        listener registered with `insert=True` so it runs BEFORE the one that
        issues the pragmas. `sqlite3.Cursor.execute` cannot be patched — it is
        an immutable type.
        """
        from sqlalchemy import event, text

        _open_and_count(self.url)             # first start: sets WAL

        statements = []
        engine = build_engine(self.url)

        @event.listens_for(engine, "connect", insert=True)
        def _trace(connection, _record):
            connection.set_trace_callback(statements.append)

        with engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar()
        engine.dispose()

        self.assertIn("PRAGMA journal_mode", statements)
        self.assertNotIn("PRAGMA journal_mode=WAL", statements)


if __name__ == "__main__":
    unittest.main()


def _migrate_once(url, barrier=None, results=None):
    """A whole worker boot: build the engine, migrate, read the version."""
    try:
        from wdash.store.migrations import current_version, migrate
        engine = build_engine(url)
        if barrier is not None:
            barrier.wait(timeout=20)
        migrate(engine)
        with engine.connect() as connection:
            version = current_version(connection)
        engine.dispose()
        outcome = f"ok:{version}"
    except Exception as exc:
        outcome = f"{type(exc).__name__}: {exc}"
    if results is not None:
        results.put(outcome)
    return outcome


class ConcurrentMigrationTest(unittest.TestCase):
    """Four workers migrating one fresh database at the same time.

    The module said migrations ran under a lock. They did — on Postgres. The
    shipped image is SQLite with `--workers 4`, and there the second worker
    died with

        sqlite3.OperationalError: table wdash_schema_version already exists

    which gunicorn turns into "Worker failed to boot" and a container that
    exits. A comment describing a guarantee the code does not give is worse
    than no comment: it is where you stop looking.
    """

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.path)
        self.url = f"sqlite:///{self.path}"

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.path + suffix):
                os.unlink(self.path + suffix)

    def _run(self, workers=WORKERS):
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(workers)
        results = context.Queue()
        processes = [context.Process(target=_migrate_once,
                                     args=(self.url, barrier, results))
                     for _ in range(workers)]
        for process in processes:
            process.start()
        outcomes = [results.get(timeout=60) for _ in processes]
        for process in processes:
            process.join(timeout=60)
        return outcomes, [p.exitcode for p in processes]

    def test_they_all_survive(self):
        outcomes, exits = self._run()
        failed = [o for o in outcomes if not o.startswith("ok:")]
        self.assertEqual(failed, [], f"workers died: {failed}")
        self.assertEqual(exits, [0] * WORKERS)

    def test_they_all_agree_on_the_version(self):
        """A worker that skipped a step because another was mid-migration
        would serve requests against a schema it thinks is newer than it is."""
        outcomes, _ = self._run()
        self.assertEqual(len(set(outcomes)), 1, outcomes)

    def test_the_schema_is_actually_complete_afterwards(self):
        """Serialising must not mean one worker quietly doing nothing."""
        self._run()
        from sqlalchemy import inspect
        from wdash.store.database import build_engine
        from wdash.store.schema import metadata
        engine = build_engine(self.url)
        present = set(inspect(engine).get_table_names())
        engine.dispose()
        missing = sorted(set(metadata.tables) - present)
        self.assertEqual(missing, [], f"tables never created: {missing}")

    def test_migrating_an_existing_database_again_changes_nothing(self):
        """The ordinary case — a restart — must not pay for the lock with a
        rewrite."""
        first = _migrate_once(self.url)
        second = _migrate_once(self.url)
        self.assertEqual(first, second)


def _open_store(url, barrier=None, results=None):
    """What a worker does on boot after migrating: open the store, which
    seeds a fresh one. Top level, for `spawn`."""
    from wdash.store import Store
    try:
        if barrier is not None:
            barrier.wait(timeout=20)
        store = Store.open(url, rbac_file="config/rbac.yaml")
        store.engine.dispose()
        outcome = "ok"
    except Exception as exc:
        outcome = f"{type(exc).__name__}: {exc}"
    if results is not None:
        results.put(outcome)
    return outcome


class ConcurrentSeedTest(unittest.TestCase):
    """Four workers opening one fresh store at the same time — the whole of
    it, seeding included, which the migration tests above stop short of.

    The migration ran under a lock; the seed after it did not. It read the
    roles table, found it empty, and wrote each role with a select and then
    an insert, and so did the worker beside it. Measured on SQLite: 17 of
    100 starts ended in "UNIQUE constraint failed: wdash_roles.name", and
    gunicorn stopped the whole server over the one worker that failed to
    boot. On Postgres the same, on wdash_settings.
    """

    ROUNDS = 6

    def _round(self):
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(path)
        url = f"sqlite:///{path}"
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(WORKERS)
        results = context.Queue()
        processes = [context.Process(target=_open_store, args=(url, barrier, results))
                     for _ in range(WORKERS)]
        for process in processes:
            process.start()
        outcomes = [results.get(timeout=90) for _ in processes]
        for process in processes:
            process.join(timeout=60)
        from wdash.store import Store
        store = Store.open(url, rbac_file="config/rbac.yaml")
        roles = sorted(role["name"] for role in store.roles.all())
        mapped = store.settings.get("rbac.default_role")
        store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.unlink(path + suffix)
        return outcomes, roles, mapped

    def test_every_worker_starts_and_the_seed_is_whole(self):
        from wdash.store.roles import _read_rbac_file
        expected = sorted(_read_rbac_file("config/rbac.yaml")["roles"])
        for _ in range(self.ROUNDS):
            outcomes, roles, default = self._round()
            failed = [o for o in outcomes if o != "ok"]
            self.assertEqual(failed, [], f"workers died: {failed}")
            self.assertEqual(roles, expected)
            self.assertIsNotNone(default)
