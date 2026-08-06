"""
Where WDash's own state lives.

Two dialects from one codebase: PostgreSQL for anything running more than one
process, SQLite for a single node and for the lab. SQLite is offered because
"docker compose up" should not require a database server to try the thing; it
is NOT offered for multi-replica, because a database on a shared filesystem is
a well-known way to corrupt data quietly.

The engine is built once per process. SQLAlchemy Core rather than the ORM: the
schema is small, the queries are plain, and an ORM here would add a mapping
layer over tables that are already the shape we want.
"""

import logging

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url

logger = logging.getLogger(__name__)

#: Guessed when nothing is configured: a file beside the other local state.
DEFAULT_URL = "sqlite:///data/wdash.db"


class DatabaseError(RuntimeError):
    """The metadata store is unreachable or misconfigured."""


def build_engine(url=None, echo=False):
    """Create the engine for `url`, applying the settings each dialect needs."""
    url = url or DEFAULT_URL
    try:
        parsed = make_url(url)
    except Exception as exc:
        raise DatabaseError(f"DATABASE_URL is not a valid URL: {exc}") from exc

    if parsed.drivername.startswith("sqlite"):
        in_memory = parsed.database in (None, "", ":memory:")
        if in_memory:
            # An in-memory database lives inside its connection, so the default
            # pool hands every caller a different, empty one. StaticPool keeps
            # a single connection, and therefore a single database — which is
            # what anybody asking for :memory: actually meant.
            from sqlalchemy.pool import StaticPool
            engine = create_engine(url, echo=echo, poolclass=StaticPool,
                                   connect_args={"check_same_thread": False})
        else:
            # SQLite serialises writers and defaults to a five-second lock
            # timeout. Fine for one process, and not a substitute for a real
            # server — which is exactly what the documentation says.
            engine = create_engine(url, echo=echo,
                                   connect_args={"timeout": 15})

        @event.listens_for(engine, "connect")
        def _configure_sqlite(connection, _record):
            cursor = connection.cursor()
            # Write-ahead logging so a reader is not blocked by a writer, and
            # foreign keys on because SQLite ignores them by default — a
            # silent difference from Postgres is exactly what you do not want
            # from a second dialect.
            if not in_memory:
                # Read before writing. `journal_mode` is a property of the
                # FILE and survives every connection, so this has to happen
                # once in the database's life rather than once per connect.
                #
                # It matters because changing journal mode needs exclusive
                # access, and — alone among statements — SQLite does NOT wait
                # for `busy_timeout` before refusing. `connect_args` above is
                # ignored for exactly this one pragma. Four gunicorn workers
                # starting together therefore raced on a fresh database, and
                # the loser died with "database is locked" before serving a
                # request; gunicorn then shut the master down with "Worker
                # failed to boot". A first deployment could not start at all.
                mode = cursor.execute("PRAGMA journal_mode").fetchone()
                if (mode[0] if mode else "").lower() != "wal":
                    try:
                        cursor.execute("PRAGMA journal_mode=WAL")
                    except Exception:
                        # Another process is setting it at this instant. The
                        # mode it lands on is the one this connection gets,
                        # which is the mode that was wanted — so this is a
                        # race that has already been won, not a failure.
                        pass
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

        return engine

    if parsed.drivername.startswith("postgresql"):
        return create_engine(
            url, echo=echo,
            # Gunicorn workers each hold a pool; keep it small and recycle so a
            # connection killed by a proxy does not surface as a random error.
            pool_size=5, max_overflow=5, pool_pre_ping=True, pool_recycle=1800,
        )

    raise DatabaseError(
        f"Unsupported database: {parsed.drivername}. "
        "WDash supports postgresql:// and sqlite://.")


def is_sqlite(engine):
    return engine.dialect.name == "sqlite"


def describe(engine):
    """A short, secret-free description for logs and the health endpoint."""
    url = engine.url
    if url.drivername.startswith("sqlite"):
        return f"sqlite:{url.database}"
    return f"{url.drivername}://{url.host}:{url.port or 5432}/{url.database}"
