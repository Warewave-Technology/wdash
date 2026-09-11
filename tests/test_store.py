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


class TheTwoSetsOfDefaultsAgreeTest(unittest.TestCase):
    """There are two answers to "what roles does a fresh install have".

    `DEFAULT_ROLES` in `store/roles.py`, and `config/rbac.yaml`, which ships
    with the repository and is imported when it is there. Seeding runs ONCE,
    on an empty table, so whichever of the two a deployment landed on is the
    one it keeps — and they had drifted apart:

        roles.py     admin / editor    / viewer   groups wdash-*
        rbac.yaml    admin / developer / viewer   groups admins, developers,
                                                         viewers

    So a directory group named `wdash-admins` granted nothing on an install
    that had the file, and `admins` granted nothing on one that did not.
    Neither failed; both signed people in and gave them the default role.
    """

    def setUp(self):
        import yaml
        from wdash.store.roles import DEFAULT_ROLES
        self.code = DEFAULT_ROLES
        with open(os.path.join(os.path.dirname(__file__), "..",
                               "config", "rbac.yaml")) as handle:
            self.file = yaml.safe_load(handle)

    def test_the_role_names_match(self):
        self.assertEqual(sorted(self.code), sorted(self.file["roles"]))

    def test_the_group_names_match(self):
        """The file maps group -> role; the code stores groups per role, so
        one of them is inverted before they can be compared at all."""
        from_file = {}
        for group, role in self.file["group_roles"].items():
            from_file.setdefault(role, []).append(group)
        from_code = {name: list(definition["groups"])
                     for name, definition in self.code.items()
                     if definition.get("groups")}
        self.assertEqual({k: sorted(v) for k, v in from_code.items()},
                         {k: sorted(v) for k, v in from_file.items()})

    def test_the_groups_are_namespaced(self):
        """A directory almost certainly has a group called `admins` already,
        it usually means domain administrators, and a default that maps it to
        `system:admin` hands WDash's highest privilege to everyone in it."""
        for group in self.file["group_roles"]:
            self.assertTrue(group.startswith("wdash-"),
                            f"{group!r} is a name somebody else's directory "
                            f"probably already uses")

    def test_the_permissions_match(self):
        """Names and groups agreeing is not enough, and the gap was measured
        rather than imagined: the file predated `monitors:read` and granted it
        to nobody, so a fresh installation that had it — which is every clone
        of this repository — had no Monitors screen for anyone at all,
        including the administrator. No error; the nav item simply was not
        there."""
        from_code = {name: sorted(definition["permissions"])
                     for name, definition in self.code.items()}
        from_file = {name: sorted(definition["permissions"])
                     for name, definition in self.file["roles"].items()}
        self.assertEqual(from_code, from_file)

    def test_every_permission_is_granted_by_some_default_role(self):
        """A permission no shipped role holds is a screen a fresh install
        cannot open, and the only symptom is a missing menu item. Both sets
        are checked: a deployment lands on one of them, not on the union."""
        from wdash.permissions import PERMISSIONS
        for label, roles in (("roles.py", self.code),
                             ("rbac.yaml", self.file["roles"])):
            granted = {permission for definition in roles.values()
                       for permission in definition["permissions"]}
            for permission in PERMISSIONS:
                with self.subTest(source=label, permission=permission):
                    self.assertIn(permission, granted,
                                  f"{label} grants {permission} to no role, "
                                  f"so nothing it gates can be reached")

    def test_the_shipped_file_maps_no_named_person(self):
        """It is imported into every fresh installation, so anything here is
        a mapping a stranger inherits. It used to carry a maintainer's own
        username, which granted admin to anyone signing in with that name."""
        self.assertEqual(self.file.get("user_roles") or {}, {})


class DatabaseAddressTest(unittest.TestCase):
    """`postgresql://` names no driver, and SQLAlchemy then reaches for
    psycopg2, which is not installed — psycopg 3 is. It was the form the
    README, .env.example and the store's own error message gave. Measured
    against the lab's Postgres: "No module named 'psycopg2'"."""

    def test_an_address_that_names_no_driver_gets_the_one_installed(self):
        from wdash.store.database import build_engine
        for written in ("postgresql://u:p@db.invalid/wdash",
                        "postgres://u:p@db.invalid/wdash"):
            with self.subTest(written=written):
                engine = build_engine(written)
                self.assertEqual(engine.url.drivername, "postgresql+psycopg")
                self.assertEqual(engine.url.database, "wdash")
                engine.dispose()

    def test_one_that_names_it_is_left_alone(self):
        from wdash.store.database import build_engine
        engine = build_engine("postgresql+psycopg://u:p@db.invalid/wdash")
        self.assertEqual(engine.url.drivername, "postgresql+psycopg")
        engine.dispose()


class SimultaneousWriteTest(unittest.TestCase):
    """Two writers of the same new key, with the second deciding while the
    first has written and not yet committed.

    A select and then an insert decided before writing: the second writer
    saw no row, inserted, and died on the key when the first committed.
    That is what four workers seeding one new installation did, one start in
    six. A single statement has no decision to get wrong. Deterministic
    rather than a race: the first write is held open while the second runs.
    """

    def setUp(self):
        folder = tempfile.mkdtemp()
        self.store = Store.open(f"sqlite:///{folder}/w.db")

    def _while_another_holds(self, insert, write):
        from datetime import datetime, timezone
        failures = []
        holder = self.store.engine.connect()
        transaction = holder.begin()
        holder.execute(insert)

        def second():
            try:
                write()
            except Exception as exc:
                failures.append(exc)
        thread = threading.Thread(target=second)
        thread.start()
        thread.join(0.5)                 # it has decided, and is waiting
        transaction.commit()
        holder.close()
        thread.join(20)
        return failures

    def test_a_role_written_twice_at_once(self):
        from datetime import datetime, timezone
        from wdash.store.schema import roles
        failures = self._while_another_holds(
            roles.insert().values(name="ops", permissions=[], containers=[],
                                  trace_containers=[], groups=[],
                                  updated_at=datetime.now(timezone.utc)),
            lambda: self.store.roles.upsert("ops", permissions=["logs:read"],
                                            containers=["app-*"], trace_containers=[]))
        self.assertEqual(failures, [])
        self.assertEqual(self.store.roles.get("ops")["permissions"], ["logs:read"])

    def test_two_saves_of_one_dashboard_at_the_same_revision(self):
        """The lost update the revision column exists to stop.

        It was checked in Python and then written `WHERE id = :id`, so the
        check and the write were two statements with the whole race window
        between them. Measured on a file SQLite store before the fix: 20
        trials of 4 barrier-aligned saves at revision 1, 57 of 80 calls
        reported success and 18 of 20 trials had more than one winner. On
        Postgres the second UPDATE waits for the row lock and then re-checks
        a WHERE clause that names only the id, so it applies too.

        Deterministic rather than a race: the first save is held open,
        uncommitted, while the second reads the revision it is about to
        invalidate.
        """
        board = self.store.dashboards.create_dashboard("D", "", "*", "u")
        stale = board.revision

        from datetime import datetime, timezone
        from wdash.store.schema import dashboards
        failures, wrote = [], []

        def second():
            try:
                wrote.append(self.store.dashboards.update_dashboard(
                    board.id, name="second", revision=stale))
            except Exception as exc:
                failures.append(exc)

        holder = self.store.engine.connect()
        transaction = holder.begin()
        holder.execute(dashboards.update()
                       .where(dashboards.c.id == board.id)
                       .values(name="first", revision=stale + 1,
                               updated_at=datetime.now(timezone.utc)))
        thread = threading.Thread(target=second)
        thread.start()
        thread.join(0.5)             # it has read the revision, and is waiting
        transaction.commit()
        holder.close()
        thread.join(20)

        self.assertEqual([type(f).__name__ for f in failures], ["ObjectConflict"],
                         f"the second save was not refused: wrote={wrote}")
        self.assertEqual(self.store.dashboards.get_dashboard(board.id).name,
                         "first", "the first writer's edit was overwritten")

    def test_a_revisionless_save_still_wins_after_losing_the_race(self):
        """Last-write-wins was documented for callers that track nothing, and
        a revision predicate must not turn that into a refusal."""
        board = self.store.dashboards.create_dashboard("D", "", "*", "u")

        from datetime import datetime, timezone
        from wdash.store.schema import dashboards
        failures, wrote = [], []

        def second():
            try:
                wrote.append(self.store.dashboards.update_dashboard(
                    board.id, name="script").name)
            except Exception as exc:
                failures.append(exc)

        holder = self.store.engine.connect()
        transaction = holder.begin()
        holder.execute(dashboards.update()
                       .where(dashboards.c.id == board.id)
                       .values(name="person", revision=board.revision + 1,
                               updated_at=datetime.now(timezone.utc)))
        thread = threading.Thread(target=second)
        thread.start()
        thread.join(0.5)
        transaction.commit()
        holder.close()
        thread.join(20)

        self.assertEqual(failures, [])
        self.assertEqual(wrote, ["script"])
        self.assertEqual(self.store.dashboards.get_dashboard(board.id).name,
                         "script")

    def test_a_setting_written_twice_at_once(self):
        from datetime import datetime, timezone
        from wdash.store.schema import settings
        failures = self._while_another_holds(
            settings.insert().values(key="auth.ldap", value={"enabled": False},
                                     updated_at=datetime.now(timezone.utc)),
            lambda: self.store.settings.set("auth.ldap", {"enabled": True}))
        self.assertEqual(failures, [])
        self.assertEqual(self.store.settings.get("auth.ldap"), {"enabled": True})
