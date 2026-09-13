"""
Moving a metadata store to another database: `python -m wdash.store.copy`.

The documented way to more than one replica is Postgres, and its second step
said to migrate what is on the volume, with nothing to do it. What moves has
to arrive as it was: every table, the sealed columns still opening with the
same key, the local account still signing in, and on Postgres the sequences
behind copied ids moved past them — or the next audit row collides with a
copied one.

On SQLite the copy is SQLite to SQLite. With WDASH_TEST_POSTGRES set, the
suite's stores are Postgres schemas (tests/postgres_store.py), so the same
tests copy between two of those, and `SqliteToPostgresTest` copies a real
SQLite file into one — the move a deployment actually makes.
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import postgres_store  # noqa: E402
from wdash.store import SecretBox, Store  # noqa: E402
from wdash.store.copy import CopyRefused, copy_store, main  # noqa: E402

PASSWORD = "a-sufficiently-long-password"


def populate(store):
    """A store with a row in every table that matters, and a secret in
    every place one is sealed."""
    store.users.create_first_admin("owner", PASSWORD, role="admin")
    store.sources.create("primary", "logs", "elasticsearch",
                         {"url": "http://es:9200", "username": "wdash",
                          "verify_certs": True}, secret="S3cretPW")
    store.settings.set("auth.oidc", {"client_id": "wdash", "enabled": True},
                       secret="oidc-secret")
    store.dashboards.create_dashboard("Checkout", "", "service:checkout",
                                      "owner", ["app-*"])
    store.saved_searches.create("errors", "level:error", "1h", "owner")
    for n in range(3):
        store.audit.record("owner", f"change {n}", subject="role:x", state={"n": n})
        store.signin.record("owner", "10.0.0.1", "failure")
    agent, _ = store.agents.create("probe")
    monitor = store.monitors.create(
        "billing", "http", "https://billing.internal/health",
        agent_ids=[agent["id"]],
        request={"secret_headers": {"X-Api-Key": "SEALED-KEY"}})
    store.results.record(agent["id"], [{
        "monitor_id": monitor["id"], "status": "down",
        "started_at": (datetime.now(timezone.utc) - timedelta(minutes=n)).isoformat(),
        "error": "boom"} for n in range(4)])
    channel = store.channels.create("hook", url="https://hooks.example/T/B/SECRETTOKEN")
    rule = store.rules.create("billing down", "monitor_down", channel["id"])
    store.alert_history.record(rule["id"], monitor["id"], "firing", detail="down")
    return {"monitor": monitor["id"], "channel": channel["id"], "rule": rule["id"]}


class CopyTest(unittest.TestCase):
    def setUp(self):
        self.key = SecretBox.generate_key()
        self.folder = tempfile.mkdtemp()

    def store(self, name):
        return Store.open(f"sqlite:///{self.folder}/{name}.db",
                          secret_box=SecretBox(self.key))

    def test_everything_arrives_and_still_opens(self):
        source = self.store("source")
        ids = populate(source)
        target_url = f"sqlite:///{self.folder}/target.db"
        from wdash.store.database import build_engine
        copied = copy_store(source.engine, build_engine(target_url), log=lambda *_: None)
        self.assertGreater(sum(copied.values()), 20)

        target = self.store("target")
        self.assertIsNotNone(target.users.verify("owner", PASSWORD),
                             "the local account does not sign in on the copy")
        primary = target.sources.all()[0]
        self.assertEqual(target.sources.credential(primary["id"]), "S3cretPW")
        self.assertEqual(target.settings.secret("auth.oidc"), "oidc-secret")
        self.assertEqual(target.monitors.credentials(ids["monitor"])["headers"],
                         {"X-Api-Key": "SEALED-KEY"})
        self.assertIn("SECRETTOKEN", target.channels.credentials(ids["channel"])["url"])
        self.assertEqual(target.results.count(), 4)
        self.assertEqual([r["name"] for r in target.roles.all()],
                         [r["name"] for r in source.roles.all()])
        self.assertEqual(target.audit.recent()[0]["state"], {"n": 2})

    def test_what_is_written_next_does_not_collide_with_what_was_copied(self):
        """The ids came with the rows. On Postgres the sequences behind them
        did not, and the next audit row would have been id 1 again."""
        source = self.store("source")
        populate(source)
        from wdash.store.database import build_engine
        copy_store(source.engine, build_engine(f"sqlite:///{self.folder}/target.db"),
                   log=lambda *_: None)
        target = self.store("target")
        target.audit.record("owner", "after the move")
        target.signin.record("owner", "10.0.0.2", "success")
        self.assertEqual(len(target.audit.recent()), 4)

    def test_a_target_that_holds_anything_is_refused(self):
        source = self.store("source")
        populate(source)
        target = self.store("target")          # seeded roles are something
        from wdash.store.database import build_engine
        with self.assertRaises(CopyRefused) as refused:
            copy_store(source.engine, build_engine(f"sqlite:///{self.folder}/target.db"),
                       log=lambda *_: None)
        self.assertIn("wdash_roles", str(refused.exception))
        self.assertEqual(target.users.count(), 0, "something was copied anyway")

    def test_a_source_behind_this_version_is_refused(self):
        """Read-only means not migrating it here: start WDash on it first."""
        from sqlalchemy import text
        source = self.store("source")
        with source.engine.begin() as connection:
            connection.execute(text("DELETE FROM wdash_schema_version WHERE version > 10"))
        from wdash.store.database import build_engine
        with self.assertRaises(CopyRefused) as refused:
            copy_store(source.engine, build_engine(f"sqlite:///{self.folder}/target.db"),
                       log=lambda *_: None)
        self.assertIn("version 10", str(refused.exception))

    def test_a_target_that_does_not_hold_what_was_sent_is_an_error(self):
        """Counted on both sides afterwards: something writing to the target
        during the copy is not a faithful copy, and says so."""
        from wdash.store import copy as copying
        from wdash.store.database import build_engine
        source = self.store("source")
        populate(source)
        counted = copying._counts
        calls = []

        def counts(engine):
            calls.append(engine)
            found = counted(engine)
            if len(calls) > 1:
                found["wdash_audit"] += 1
            return found
        copying._counts = counts
        try:
            with self.assertRaises(RuntimeError) as caught:
                copy_store(source.engine,
                           build_engine(f"sqlite:///{self.folder}/target.db"),
                           log=lambda *_: None)
        finally:
            copying._counts = counted
        self.assertIn("wdash_audit", str(caught.exception))

    def test_the_command_says_what_it_did_and_refuses_out_loud(self):
        source = self.store("source")
        populate(source)
        import contextlib
        import io
        source_url = f"sqlite:///{self.folder}/source.db"
        target_url = f"sqlite:///{self.folder}/target.db"
        for expected, said in ((0, "done:"), (2, "refused: the target is not empty")):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["--from", source_url, "--to", target_url])
            self.assertEqual(code, expected)
            self.assertIn(said, out.getvalue() + err.getvalue())


@unittest.skipUnless(postgres_store.active(), "needs WDASH_TEST_POSTGRES")
class SqliteToPostgresTest(unittest.TestCase):
    """The move a deployment makes: a real SQLite file, into Postgres, and
    WDash started on the result."""

    def test_the_sqlite_file_moves_to_postgres_and_the_application_opens_it(self):
        from sqlalchemy import create_engine
        from wdash.store import migrate
        from wdash.store.database import build_engine

        key = SecretBox.generate_key()
        folder = tempfile.mkdtemp()
        # Built past the suite's routing: this one really is a SQLite file.
        source_engine = create_engine(f"sqlite:///{folder}/volume.db")
        migrate(source_engine)
        source = Store(source_engine, SecretBox(key))
        source.roles.seed(source.settings)
        populate(source)

        target_url = f"sqlite:///{folder}/postgres.db"   # routed to Postgres
        routed = build_engine(target_url)
        self.assertEqual(routed.dialect.name, "postgresql")
        # A session in another zone. SQLite hands back a naive time for a
        # column declared with one, and Postgres reads a naive time in the
        # session's zone: copied as it came, noon UTC arrived as noon Tokyo.
        from sqlalchemy import create_engine as raw
        options = routed.url.query["options"]
        target_engine = raw(routed.url.update_query_dict(
            {"options": f"{options} -ctimezone=Asia/Tokyo"}))
        copy_store(source_engine, target_engine, log=lambda *_: None)
        from sqlalchemy import select
        from wdash.store.schema import audit
        with source_engine.connect() as a, target_engine.connect() as b:
            before = [r.replace(tzinfo=timezone.utc) for r in
                      a.execute(select(audit.c.at).order_by(audit.c.id)).scalars()]
            after = list(b.execute(select(audit.c.at).order_by(audit.c.id)).scalars())
        self.assertEqual(after, before, "a copied time moved")

        from wdash.app import create_app
        from wdash.config import Config

        class OnPostgres(Config):
            TESTING = True
            SECRET_KEY = "copy"
            DATABASE_URL = target_url
            ENCRYPTION_KEY = key

        app = create_app(OnPostgres)
        self.assertEqual(app.store.engine.dialect.name, "postgresql")
        response = app.test_client().post("/auth/login", data={
            "username": "owner", "password": PASSWORD})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(app.store.sources.credential(app.store.sources.all()[0]["id"]),
                         "S3cretPW")


if __name__ == "__main__":
    unittest.main()
