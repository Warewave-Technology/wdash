"""
The metadata store.

WDash's own state, deliberately not in Elasticsearch. Dashboards were briefly
stored there, which was correct while Elasticsearch was the only backend and
wrong the moment it became one source among several — a Loki-only deployment
would have nowhere to put them, and a search index is a poor home for a
password hash or an OIDC client secret.

The properties worth locking down:

  * first-run setup happens exactly once, even under a race
  * a failed decryption is reported, and a missing key NEVER means plaintext
  * two people editing different objects never conflict; two editing the same
    one are told, rather than one of them silently losing their work
  * an existing rbac.yaml is imported once and then left alone
"""

import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.store import (  # noqa: E402
    DatabaseError, ObjectConflict, SecretBox, SecretsCorrupt,
    SecretsUnavailable, SetupClosed, Store, WeakPassword, build_engine,
)

PASSWORD = "a-sufficiently-long-password"


def fresh_store(**kwargs):
    return Store.open("sqlite:///:memory:", **kwargs)


class EngineTest(unittest.TestCase):
    def test_an_unsupported_dialect_is_refused_clearly(self):
        with self.assertRaises(DatabaseError) as caught:
            build_engine("mysql://localhost/wdash")
        self.assertIn("postgresql", str(caught.exception))

    def test_nonsense_is_refused_rather_than_crashing_later(self):
        with self.assertRaises(DatabaseError):
            build_engine("this is not a url")

    def test_migrating_twice_is_a_no_op(self):
        from wdash.store import migrate
        engine = build_engine("sqlite:///:memory:")
        self.assertEqual(migrate(engine), migrate(engine))


class SetupTest(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()

    def test_a_new_installation_needs_setup(self):
        self.assertTrue(self.store.needs_setup)

    def test_setup_closes_once_an_account_exists(self):
        self.store.users.create_first_admin("admin", PASSWORD)
        self.assertFalse(self.store.needs_setup)

    def test_setup_cannot_be_run_twice(self):
        self.store.users.create_first_admin("admin", PASSWORD)
        with self.assertRaises(SetupClosed):
            self.store.users.create_first_admin("intruder", PASSWORD)

    def test_concurrent_setup_produces_exactly_one_account(self):
        """Two workers processing two submissions of the setup form.

        Uses a file rather than :memory: on purpose — SQLAlchemy gives each
        thread its own in-memory database, so the threads would not even see
        each other and the test would pass without testing anything.

        Distinct usernames on purpose too: the username constraint must not be
        what saves us, or the guard would only work when two people happened to
        pick the same name.
        """
        path = tempfile.mktemp(suffix=".db")
        store = Store.open(f"sqlite:///{path}")
        try:
            errors, barrier = [], threading.Barrier(8)

            def attempt(index):
                barrier.wait()
                try:
                    store.users.create_first_admin(f"admin{index}", PASSWORD)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=attempt, args=(i,))
                       for i in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(store.users.count(), 1,
                             f"{store.users.count()} accounts created, expected 1")
            self.assertEqual(len(errors), 7)
            self.assertTrue(all(isinstance(e, SetupClosed) for e in errors),
                            f"unexpected failures: {[type(e).__name__ for e in errors]}")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_the_setup_guard_does_not_use_an_aggregate_lock(self):
        """PostgreSQL rejects FOR UPDATE beside an aggregate.

        An earlier version guarded the race with
        `SELECT count(*) ... FOR UPDATE`, which would not have serialised
        anything — it would have made first-run setup fail outright on the one
        dialect that needs the guard most.
        """
        import inspect

        from wdash.store import users as users_module
        source = inspect.getsource(users_module.UserRepository.create_first_admin)
        self.assertNotIn("with_for_update", source)

    def test_a_short_password_is_refused(self):
        with self.assertRaises(WeakPassword):
            self.store.users.create_first_admin("admin", "short")

    def test_usernames_are_case_folded(self):
        self.store.users.create_first_admin("Admin", PASSWORD)
        self.assertIsNotNone(self.store.users.by_username("ADMIN"))
        self.assertIsNotNone(self.store.users.verify("aDmIn", PASSWORD))


class AuthenticationTest(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        self.store.users.create_first_admin("admin", PASSWORD)

    def test_the_right_password_authenticates(self):
        self.assertIsNotNone(self.store.users.verify("admin", PASSWORD))

    def test_the_wrong_password_does_not(self):
        self.assertIsNone(self.store.users.verify("admin", "wrong-but-long-enough"))

    def test_an_unknown_user_does_not(self):
        self.assertIsNone(self.store.users.verify("nobody", PASSWORD))

    def test_a_disabled_account_cannot_sign_in(self):
        self.store.users.set_disabled("admin", True)
        self.assertIsNone(self.store.users.verify("admin", PASSWORD))

    def test_the_password_is_never_stored_recoverably(self):
        account = self.store.users.by_username("admin")
        self.assertNotIn(PASSWORD, account["password_hash"])
        self.assertTrue(account["password_hash"].startswith("$argon2"))

    def test_the_last_local_account_cannot_be_removed(self):
        """Otherwise a broken identity provider locks everyone out."""
        with self.assertRaises(ValueError):
            self.store.users.delete("admin")

    def test_an_account_can_be_removed_once_another_exists(self):
        self.store.users.create("second", PASSWORD, "admin")
        self.assertTrue(self.store.users.delete("admin"))


class SecretsTest(unittest.TestCase):
    def test_a_secret_round_trips(self):
        box = SecretBox(SecretBox.generate_key())
        self.assertEqual(box.open(box.seal("client-secret")), "client-secret")

    def test_a_missing_key_refuses_rather_than_storing_plaintext(self):
        """The failure everyone believes cannot happen to them."""
        box = SecretBox(key=None)
        self.assertFalse(box.available)
        with self.assertRaises(SecretsUnavailable):
            box.seal("client-secret")

    def test_no_key_means_no_key_even_with_one_in_the_environment(self):
        """`SecretBox(None)` used to fall back to the environment.

        Two consequences, and the second is the bad one. A deployment that
        configured no key got one anyway if the variable happened to be
        exported — and the "secrets cannot be stored" path became untestable on
        any machine that had one, which is how four tests covering exactly that
        path came to fail as if they were flaky.
        """
        import os
        from unittest import mock
        from wdash.store.secrets import KEY_VARIABLE
        with mock.patch.dict(os.environ,
                             {KEY_VARIABLE: SecretBox.generate_key()}):
            self.assertFalse(SecretBox(None).available)
            # The one caller with no configuration to read still gets it.
            self.assertTrue(SecretBox.from_environment().available)

    def test_the_stored_form_does_not_contain_the_value(self):
        box = SecretBox(SecretBox.generate_key())
        self.assertNotIn("client-secret", box.seal("client-secret"))

    def test_a_changed_key_is_reported_not_silently_empty(self):
        sealed = SecretBox(SecretBox.generate_key()).seal("client-secret")
        with self.assertRaises(SecretsCorrupt):
            SecretBox(SecretBox.generate_key()).open(sealed)

    def test_a_passphrase_is_stretched_rather_than_rejected(self):
        """Rejecting one reliably produces a deployment with no key at all."""
        box = SecretBox("a memorable passphrase")
        self.assertEqual(box.open(box.seal("value")), "value")

    def test_empty_values_are_not_encrypted(self):
        box = SecretBox(SecretBox.generate_key())
        self.assertIsNone(box.seal(""))
        self.assertIsNone(box.open(None))


class RoleTest(unittest.TestCase):
    def test_defaults_are_seeded_when_no_file_exists(self):
        store = fresh_store(rbac_file="does/not/exist.yaml")
        self.assertIn("admin", [r["name"] for r in store.roles.all()])

    def test_an_existing_rbac_file_is_imported(self):
        """An upgrade must not silently discard the roles somebody wrote."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("roles:\n  auditor:\n    permissions: [logs:read]\n"
                         "    indices: ['audit-*']\n    groups: [auditors]\n")
            path = handle.name
        try:
            store = fresh_store(rbac_file=path)
            names = [r["name"] for r in store.roles.all()]
            self.assertEqual(names, ["auditor"])
        finally:
            os.unlink(path)

    def test_the_file_is_imported_once_and_then_ignored(self):
        """Otherwise a restart quietly reverts every edit made in the UI."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("roles:\n  auditor:\n    permissions: [logs:read]\n"
                         "    indices: ['audit-*']\n")
            path = handle.name
        try:
            store = fresh_store(rbac_file=path)
            store.roles.upsert("auditor", ["logs:read", "traces:read"],
                               ["audit-*"], ["*"])
            self.assertFalse(store.roles.seed(path), "seeding ran a second time")
            self.assertIn("traces:read", store.roles.get("auditor")["permissions"])
        finally:
            os.unlink(path)

    def test_the_config_shape_matches_what_rbac_consumers_expect(self):
        config = fresh_store().roles.as_config()
        self.assertIn("roles", config)
        for role in config["roles"].values():
            for key in ("permissions", "indices", "trace_indices", "groups"):
                self.assertIn(key, role, key)

    def test_a_broken_file_falls_back_rather_than_failing_to_start(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("roles: [this is not a mapping\n")
            path = handle.name
        try:
            store = fresh_store(rbac_file=path)
            self.assertTrue(store.roles.all(), "left with no roles at all")
        finally:
            os.unlink(path)


class ObjectTest(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        self.dashboards = self.store.dashboards

    def test_a_dashboard_round_trips_with_panels_and_thresholds(self):
        created = self.dashboards.create_dashboard(
            "D", "", "level:ERROR", "u", ["app-*"],
            panels=[{"id": "p", "type": "terms", "title": "Hosts",
                     "field": "host", "size": 3, "width": 6}],
            thresholds={"error_rate": {"warning": 0.05}})

        loaded = self.dashboards.get_dashboard(created.id)
        self.assertEqual(loaded.get_panels()[0]["field"], "host")
        self.assertEqual(loaded.thresholds["error_rate"]["warning"], 0.05)
        self.assertEqual(loaded.index_patterns, ["app-*"])

    def test_concurrent_edits_to_different_dashboards_both_survive(self):
        """The lost update the JSON file had, gone by construction."""
        first = self.dashboards.create_dashboard("First", "", "*", "u")
        second = self.dashboards.create_dashboard("Second", "", "*", "u")

        # Both read before either writes.
        first_revision = self.dashboards.get_dashboard(first.id).revision
        second_revision = self.dashboards.get_dashboard(second.id).revision

        self.dashboards.update_dashboard(first.id, name="First edited",
                                         revision=first_revision)
        self.dashboards.update_dashboard(second.id, name="Second edited",
                                         revision=second_revision)

        self.assertEqual(sorted(d.name for d in self.dashboards.get_all_dashboards()),
                         ["First edited", "Second edited"])

    def test_a_stale_revision_is_refused(self):
        created = self.dashboards.create_dashboard("D", "", "*", "u")
        stale = self.dashboards.get_dashboard(created.id).revision

        self.dashboards.update_dashboard(created.id, name="Winner", revision=stale)
        with self.assertRaises(ObjectConflict):
            self.dashboards.update_dashboard(created.id, name="Loser", revision=stale)

        self.assertEqual(self.dashboards.get_dashboard(created.id).name, "Winner")

    def test_an_update_without_a_revision_still_works(self):
        """A script does not track revisions and should not have to."""
        created = self.dashboards.create_dashboard("D", "", "*", "u")
        self.assertIsNotNone(
            self.dashboards.update_dashboard(created.id, name="Renamed"))

    def test_updating_something_gone_returns_none(self):
        self.assertIsNone(self.dashboards.update_dashboard("missing", name="x"))

    def test_a_saved_search_belongs_to_its_author(self):
        search = self.store.saved_searches.create("Mine", "level:ERROR", "24h", "me")
        self.assertEqual([s.name for s in self.store.saved_searches.all_for("me")],
                         ["Mine"])
        self.assertEqual(self.store.saved_searches.all_for("someone-else"), [])
        self.assertFalse(self.store.saved_searches.delete(search.id, "someone-else"))
        self.assertTrue(self.store.saved_searches.delete(search.id, "me"))


class MigrationCliTest(unittest.TestCase):
    """Moving the JSON files into the database."""

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.dashboards = os.path.join(self.directory, "dashboards.json")
        self.searches = os.path.join(self.directory, "saved_searches.json")
        self.database = os.path.join(self.directory, "wdash.db")

        import json
        with open(self.dashboards, "w") as handle:
            json.dump([{"id": "keep-this-id", "name": "Existing",
                        "description": "", "query": "level:ERROR",
                        "created_by": "someone",
                        "created_at": "2026-01-15T10:00:00+00:00",
                        "index_patterns": ["app-*"]},
                       {"id": "private-one", "name": "Private",
                        "description": "", "query": "*",
                        "created_by": "someone",
                        "created_at": "2026-01-15T10:00:00+00:00",
                        "index_patterns": ["app-*"],
                        "visibility": "private"}], handle)
        with open(self.searches, "w") as handle:
            json.dump([{"id": "search-1", "name": "Mine", "query": "*",
                        "time_range": "24h", "created_by": "someone",
                        "created_at": "2026-01-15T10:00:00+00:00"}], handle)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def run_migration(self, dry_run=False):
        from wdash.store.migrate_cli import main
        arguments = ["--database-url", f"sqlite:///{self.database}",
                     "--dashboards", self.dashboards,
                     "--saved-searches", self.searches]
        if dry_run:
            arguments.append("--dry-run")
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            main(arguments)

    def store(self):
        return Store.open(f"sqlite:///{self.database}")

    def test_a_private_dashboard_stays_private(self):
        """Visibility was not carried, so it normalised to the default —
        `shared` — and every private dashboard came out of the migration
        visible to everybody. A silent access widening, at the one moment
        somebody is trusting this to move their data faithfully.
        """
        self.run_migration()
        moved = {d.name: d for d in self.store().dashboards.get_all_dashboards()}
        self.assertEqual(moved["Private"].visibility, "private")

    def test_a_shared_dashboard_stays_shared(self):
        """The other direction, so the fix cannot be "make everything private"
        — which would hide dashboards people rely on and read as data loss."""
        self.run_migration()
        moved = {d.name: d for d in self.store().dashboards.get_all_dashboards()}
        self.assertEqual(moved["Existing"].visibility, "shared")

    def test_a_dry_run_writes_nothing(self):
        self.run_migration(dry_run=True)
        self.assertEqual(self.store().dashboards.get_all_dashboards(), [])

    def test_identity_is_preserved(self):
        """A dashboard that changes id breaks every link somebody pasted."""
        self.run_migration()
        dashboard = self.store().dashboards.get_dashboard("keep-this-id")
        self.assertIsNotNone(dashboard)
        self.assertEqual(dashboard.name, "Existing")
        self.assertEqual(dashboard.index_patterns, ["app-*"])

    def test_creation_time_is_preserved(self):
        """A bulk import must not restamp everything as created today."""
        self.run_migration()
        dashboard = self.store().dashboards.get_dashboard("keep-this-id")
        self.assertEqual(dashboard.created_at.year, 2026)
        self.assertEqual(dashboard.created_at.month, 1)

    def test_running_twice_does_not_duplicate(self):
        """An interrupted run must be safe to repeat.

        Compared against the first run rather than against a fixed number, so
        adding a row to the fixture cannot make this fail for a reason that
        has nothing to do with duplication.
        """
        self.run_migration()
        store = self.store()
        after_one = (len(store.dashboards.get_all_dashboards()),
                     len(store.saved_searches.all_for("someone")))
        self.run_migration()
        store = self.store()
        self.assertEqual((len(store.dashboards.get_all_dashboards()),
                          len(store.saved_searches.all_for("someone"))),
                         after_one)

    def test_the_source_files_are_left_alone(self):
        """The migration has to be reversible while people are trying it."""
        self.run_migration()
        self.assertTrue(os.path.exists(self.dashboards))


if __name__ == "__main__":
    unittest.main(verbosity=2)
