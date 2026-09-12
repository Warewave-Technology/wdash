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

    def run_cli(self, arguments):
        """The command as an operator runs it: exit code, stdout, stderr."""
        import contextlib
        import io

        from wdash.store.migrate_cli import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(arguments)
        return code, out.getvalue(), err.getvalue()

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

    # ---------- what it reads when nobody says ----------

    def configured_at(self, path):
        """Point the application's own setting at a file, as a deployment
        with DASHBOARD_STORAGE_FILE set does."""
        from unittest import mock

        from wdash.config import Config
        return mock.patch.object(Config, "DASHBOARD_STORAGE_FILE", path)

    def test_with_no_paths_it_reads_what_the_application_reads(self):
        """The defaults were the literals `data/dashboards.json` and
        `data/saved_searches.json`, relative to whatever directory the
        command was run from. The application reads DASHBOARD_STORAGE_FILE
        and keeps searches beside it, so any deployment that set it — the
        Kubernetes one, /data — or anybody running this from somewhere other
        than the app root got "0 moved ... Done" and, after flipping
        DASHBOARD_STORAGE to database, an empty dashboard list."""
        with self.configured_at(self.dashboards):
            code, out, _ = self.run_cli(
                ["--database-url", f"sqlite:///{self.database}"])
        self.assertEqual(code, 0)
        self.assertIn("Dashboards:     2 moved", out)
        self.assertIn("Saved searches: 1 moved", out)
        self.assertEqual(
            {d.name for d in self.store().dashboards.get_all_dashboards()},
            {"Existing", "Private"})

    def test_the_searches_file_follows_the_dashboards_file(self):
        """Two independent defaults are how a deployment that moved its data
        directory migrates its dashboards and leaves its searches behind."""
        with self.configured_at(self.dashboards):
            self.run_cli(["--database-url", f"sqlite:///{self.database}"])
        self.assertEqual(
            [s.name for s in self.store().saved_searches.all_for("someone")],
            ["Mine"])

    def test_the_paths_it_read_are_printed_in_full(self):
        """"0 moved" against a path nobody named is indistinguishable from
        "0 moved" against the right one."""
        with self.configured_at(self.dashboards):
            _, out, _ = self.run_cli(
                ["--database-url", f"sqlite:///{self.database}"])
        self.assertIn(os.path.abspath(self.dashboards), out)
        self.assertIn(os.path.abspath(self.searches), out)

    def test_a_file_that_is_not_there_stops_the_run(self):
        """It counted as none: `_load_json` answered a missing path with an
        empty list, and the run finished with "Done. Set
        DASHBOARD_STORAGE=database"."""
        missing = os.path.join(self.directory, "elsewhere", "dashboards.json")
        code, out, err = self.run_cli(
            ["--database-url", f"sqlite:///{self.database}",
             "--dashboards", missing, "--saved-searches", self.searches])
        self.assertEqual(code, 1)
        self.assertIn(f"not found: {missing}", err)
        self.assertNotIn("Done.", out)
        self.assertFalse(os.path.exists(self.database))

    def test_a_deployment_that_really_has_none_can_say_so(self):
        missing = os.path.join(self.directory, "elsewhere", "dashboards.json")
        code, out, _ = self.run_cli(
            ["--database-url", f"sqlite:///{self.database}",
             "--dashboards", missing, "--saved-searches", self.searches,
             "--allow-missing"])
        self.assertEqual(code, 0)
        self.assertIn("Done.", out)
        self.assertEqual(
            [s.name for s in self.store().saved_searches.all_for("someone")],
            ["Mine"])

    # ---------- a file the run will never open is not a requirement ----------

    def test_a_deployment_that_has_never_saved_a_search_still_migrates(self):
        """The application creates saved_searches.json on the first save, so
        its absence beside a dashboards file is the ordinary state of an
        installation whose users have not saved a search. Requiring it turned
        that into "Nothing was read and nothing was written", exit 1 — and
        the README's first command is this one."""
        os.unlink(self.searches)
        with self.configured_at(self.dashboards):
            code, out, err = self.run_cli(
                ["--database-url", f"sqlite:///{self.database}"])
        self.assertEqual(code, 0, err)
        self.assertIn("Dashboards:     2 moved", out)
        self.assertIn("Saved searches: 0 moved", out)
        self.assertEqual(
            {d.name for d in self.store().dashboards.get_all_dashboards()},
            {"Existing", "Private"})

    def test_the_absent_searches_file_is_named_as_absent_not_as_empty(self):
        """"0 moved" has to say which of the two it means, here as much as
        anywhere: a file that is not there yet, or a file that is empty."""
        os.unlink(self.searches)
        with self.configured_at(self.dashboards):
            _, out, _ = self.run_cli(
                ["--database-url", f"sqlite:///{self.database}"])
        self.assertIn(os.path.abspath(self.searches), out)
        self.assertIn("not there yet", out)

    def test_the_dry_run_the_readme_starts_with_needs_no_searches_file(self):
        os.unlink(self.searches)
        with self.configured_at(self.dashboards):
            code, out, err = self.run_cli(
                ["--database-url", f"sqlite:///{self.database}", "--dry-run"])
        self.assertEqual(code, 0, err)
        self.assertIn("Dashboards:     2 to move", out)

    def test_an_elasticsearch_run_does_not_ask_for_a_searches_file(self):
        """--from-elasticsearch reads neither JSON file — it says so itself,
        "not stored in Elasticsearch; skipped" — and it is the path the
        removal of the Elasticsearch dashboard store points operators at. It
        exited 1 over a saved_searches.json it would never have opened,
        without contacting Elasticsearch at all."""
        from unittest import mock

        os.unlink(self.searches)
        os.unlink(self.dashboards)
        record = {"id": "from-es", "name": "Out of the index",
                  "description": "", "query": "*", "created_by": "someone",
                  "created_at": "2026-01-15T10:00:00+00:00",
                  "index_patterns": ["app-*"]}
        with self.configured_at(self.dashboards), mock.patch(
                "wdash.store.migrate_cli._load_elasticsearch",
                return_value=[record]) as reader:
            code, out, err = self.run_cli(
                ["--database-url", f"sqlite:///{self.database}",
                 "--from-elasticsearch", "http://localhost:9200"])
        self.assertEqual(code, 0, err)
        self.assertEqual(reader.call_count, 1)
        self.assertNotIn("not found", err)
        self.assertIn("not stored in Elasticsearch; skipped", out)
        self.assertEqual(
            [d.name for d in self.store().dashboards.get_all_dashboards()],
            ["Out of the index"])

    def test_a_named_searches_file_that_is_not_there_still_stops_the_run(self):
        """The guard is not dropped, only narrowed to files the run reads:
        a path somebody typed is a path they expect to be read."""
        missing = os.path.join(self.directory, "elsewhere", "searches.json")
        code, out, err = self.run_cli(
            ["--database-url", f"sqlite:///{self.database}",
             "--dashboards", self.dashboards, "--saved-searches", missing])
        self.assertEqual(code, 1)
        self.assertIn(f"not found: {missing}", err)
        self.assertNotIn("Done.", out)

    def test_allowing_one_missing_file_does_not_allow_the_other(self):
        """--allow-missing was all-or-nothing, and the refusal pointed
        straight at it: switching off the check for a searches file switched
        off the check on the dashboards path too, which is the state this
        guard exists to refuse."""
        missing_searches = os.path.join(self.directory, "no", "searches.json")
        missing_dashboards = os.path.join(self.directory, "no", "dash.json")
        code, out, err = self.run_cli(
            ["--database-url", f"sqlite:///{self.database}",
             "--dashboards", missing_dashboards,
             "--saved-searches", missing_searches,
             "--allow-missing-searches"])
        self.assertEqual(code, 1)
        self.assertIn(f"not found: {missing_dashboards}", err)
        self.assertNotIn(f"not found: {missing_searches}", err)
        self.assertNotIn("Done.", out)

    def test_the_refusal_names_the_flag_for_the_file_that_is_missing(self):
        missing = os.path.join(self.directory, "elsewhere", "dashboards.json")
        _, _, err = self.run_cli(
            ["--database-url", f"sqlite:///{self.database}",
             "--dashboards", missing, "--saved-searches", self.searches])
        self.assertIn("--allow-missing-dashboards", err)


class SourcesThatShadowEachOtherAreReportedTest(unittest.TestCase):
    """A store that already has two sources sharing a name within one signal.

    `SourceRepository` refuses to make another, which does nothing for the
    ones that are already there: one of them answers every query for that
    signal and the other is never asked, while the configuration page shows
    two healthy sources. The rows are left exactly as they are — renaming one
    would break every role rule that names it — so the upgrade's job is to
    say which pair it is, in the log and in the trail that is still there
    next week.
    """

    def upgrade_from_fourteen(self, rows):
        """A store at the previous version, with these source rows in it."""
        import logging
        from datetime import datetime, timezone

        from wdash.store import migrations
        from wdash.store.schema import sources

        engine = build_engine("sqlite:///:memory:")
        every = migrations.MIGRATIONS
        migrations.MIGRATIONS = [step for step in every if step[0] <= 14]
        try:
            migrations.migrate(engine)
        finally:
            migrations.MIGRATIONS = every

        now = datetime.now(timezone.utc)
        with engine.begin() as connection:
            for row in rows:
                record = dict(row)
                # The legacy column is NOT NULL and is written by every
                # version of this application; `signals` is the one that
                # might be missing.
                if "signal" not in record:
                    record["signal"] = record["signals"][0]
                connection.execute(sources.insert().values(
                    config={}, secrets=None, enabled=True,
                    created_at=now, updated_at=now, **record))

        with self.assertLogs("wdash.store.migrations", "INFO") as caught:
            migrations.migrate(engine)
        warnings = [record.getMessage() for record in caught.records
                    if record.levelno >= logging.WARNING]
        return engine, warnings

    ELASTIC = {"id": "one", "name": "prod", "kind": "elasticsearch",
               "signals": ["logs", "traces"]}
    JAEGER = {"id": "two", "name": "prod", "kind": "jaeger",
              "signals": ["traces"]}
    #: The pair migration 7 deliberately left for somebody to merge by hand.
    LEGACY_LOGS = {"id": "three", "name": "eu", "kind": "loki",
                   "signals": ["logs"]}
    LEGACY_TRACES = {"id": "four", "name": "eu", "kind": "tempo",
                     "signals": ["traces"]}

    def test_the_pair_is_named_with_the_signal_they_share(self):
        _, warnings = self.upgrade_from_fourteen([self.ELASTIC, self.JAEGER])
        self.assertEqual(len(warnings), 1)
        self.assertIn("prod", warnings[0])
        self.assertIn("traces", warnings[0])
        self.assertIn("jaeger", warnings[0])

    def test_it_reaches_the_audit_trail(self):
        """A log line is gone by the time somebody asks why a source they
        configured returns nothing."""
        engine, _ = self.upgrade_from_fourteen([self.ELASTIC, self.JAEGER])
        from wdash.store.audit import AuditLog
        rows = [row for row in AuditLog(engine).recent()
                if row["action"] == "source name collision"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["subject"], "source:prod")
        self.assertEqual(rows[0]["state"]["signals"], ["traces"])

    def test_a_row_that_never_got_a_signals_list_is_read_by_its_column(self):
        """Migration 7 backfilled `signals` from the legacy column, but a row
        written straight into the database can still carry NULL, and it is
        shadowing whatever shares its name just the same."""
        _, warnings = self.upgrade_from_fourteen(
            [self.ELASTIC, dict(self.JAEGER, signals=None, signal="traces")])
        self.assertEqual(len(warnings), 1)
        self.assertIn("traces", warnings[0])

    def test_the_legacy_pair_is_not_reported(self):
        """One row for logs and one for traces sharing a name is the shape
        migration 7 left behind on purpose. Neither shadows the other."""
        engine, warnings = self.upgrade_from_fourteen(
            [self.LEGACY_LOGS, self.LEGACY_TRACES])
        self.assertEqual(warnings, [])
        from wdash.store.audit import AuditLog
        self.assertEqual([row for row in AuditLog(engine).recent()
                          if row["action"] == "source name collision"], [])

    def test_the_rows_are_left_exactly_as_they_are(self):
        """Renaming one silently would break every role rule naming it, and
        merging them would have to choose which credential wins."""
        engine, _ = self.upgrade_from_fourteen([self.ELASTIC, self.JAEGER])
        from sqlalchemy import select

        from wdash.store.schema import sources
        with engine.connect() as connection:
            rows = connection.execute(
                select(sources.c.id, sources.c.name)).mappings().all()
        self.assertEqual({row["id"]: row["name"] for row in rows},
                         {"one": "prod", "two": "prod"})


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

    @staticmethod
    def _boundaries(definition, containers, trace_containers):
        """The three boundaries, with the two spellings of "everything"
        written the same way. `services: None` means no service restriction
        and the file's `["*"]` is a pattern that matches every service; they
        come to the same thing, and demanding one spelling would make this a
        test about style rather than about access."""
        def unrestricted(value):
            return ["*"] if value is None else sorted(value)
        return {"containers": unrestricted(definition.get(containers)),
                "trace_containers": unrestricted(
                    definition.get(trace_containers)),
                "services": unrestricted(definition.get("services"))}

    def test_the_boundaries_match(self):
        """Names, groups and permissions agreeing is not enough: the three
        boundaries are what a role IS, and they had drifted the other way
        from the names. `developer` reached every log container and every
        service here, while the file held it to `app-*`, `service-*` and six
        application services; `viewer` reached every service here and exactly
        one in the file. An installation that found no readable file — a pip
        install outside the repository, a renamed ConfigMap key, a mount that
        was not there yet — was seeded with the WIDER set, and seeding runs
        once."""
        from_code = {name: self._boundaries(
            definition, "containers", "trace_containers")
            for name, definition in self.code.items()}
        from_file = {name: self._boundaries(
            definition, "indices", "trace_indices")
            for name, definition in self.file["roles"].items()}
        self.assertEqual(from_code, from_file)

    def test_an_installation_seeded_without_the_file_gets_them(self):
        """The comparison above is between two literals. This is what a
        deployment actually ends up holding."""
        store = Store.open("sqlite:///:memory:")
        developer = store.roles.get("developer")
        self.assertEqual(sorted(developer["containers"]),
                         ["app-*", "service-*"])
        self.assertIn("api-gateway", developer["services"])
        self.assertNotIn("postgres", developer["services"])
        self.assertEqual(store.roles.get("viewer")["services"],
                         ["api-gateway"])

    def test_the_shipped_file_maps_no_named_person(self):
        """It is imported into every fresh installation, so anything here is
        a mapping a stranger inherits. It used to carry a maintainer's own
        username, which granted admin to anyone signing in with that name."""
        self.assertEqual(self.file.get("user_roles") or {}, {})


class AnRbacFileThatCannotBeUsedSaysSoTest(unittest.TestCase):
    """Seeding runs once, so a file that is not read is not read ever.

    Three ways of losing one, all of which happen: the path is wrong (a
    renamed ConfigMap key, a mount that moved, a pip install run outside the
    repository), the `roles` block is mis-indented or misnamed — `role:` —
    or it is there and empty. Every one of them produced a running
    installation on the built-in default roles with the file's own
    group_roles, user_roles and default_role dropped, and the only line
    written was INFO "Seeded 3 roles from built-in defaults".
    """

    LOGGER = "wdash.store.roles"

    def setUp(self):
        self.directory = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def written(self, body):
        path = os.path.join(self.directory, "rbac.yaml")
        with open(path, "w") as handle:
            handle.write(body)
        return path

    def seed(self, path, level="INFO"):
        """Open a store on that file and hand back what was logged."""
        with self.assertLogs(self.LOGGER, level) as caught:
            store = Store.open("sqlite:///:memory:", rbac_file=path)
        return store, [f"{r.levelname} {r.getMessage()}" for r in caught.records]

    # ---------- the file is not read ----------

    def test_a_missing_file_is_a_warning_naming_the_path(self):
        path = os.path.join(self.directory, "not-here", "rbac.yaml")
        _, lines = self.seed(path)
        warnings = [line for line in lines if line.startswith("WARNING")]
        self.assertEqual(len(warnings), 1)
        self.assertIn(os.path.abspath(path), warnings[0])

    def test_a_roles_block_that_is_a_list_is_an_error_naming_the_path(self):
        """`roles:` written as a list, which is what a mis-indentation
        produces."""
        path = self.written("roles:\n  - admin\n  - viewer\n")
        _, lines = self.seed(path)
        errors = [line for line in lines if line.startswith("ERROR")]
        self.assertEqual(len(errors), 1)
        self.assertIn(os.path.abspath(path), errors[0])

    def test_a_misspelt_block_is_an_error_naming_the_path(self):
        path = self.written("role:\n  ops:\n    permissions: [logs:read]\n"
                            "default_role: ops\n")
        _, lines = self.seed(path)
        self.assertTrue([line for line in lines if line.startswith("ERROR")])

    def test_an_empty_roles_block_is_an_error_too(self):
        """The worst of the three: it parsed, so it counted as a file."""
        path = self.written("roles: {}\ndefault_role: ops\n")
        _, lines = self.seed(path)
        self.assertTrue([line for line in lines if line.startswith("ERROR")])

    def test_the_info_line_names_the_source_actually_used(self):
        """With `roles: {}` it named the file while seeding the built-in
        roles, which is the one combination that cannot be true."""
        path = self.written(
            "roles: {}\ndefault_role: ops\n"
            "group_roles:\n  corp-admins: admin\n")
        _, lines = self.seed(path)
        seeded = [line for line in lines if "Seeded" in line]
        self.assertEqual(len(seeded), 1)
        self.assertIn("built-in defaults", seeded[0])
        self.assertNotIn(path, seeded[0])

    def test_an_unusable_roles_block_takes_the_file_s_mappings_with_it(self):
        """Half of one file and half of another is the state nothing can
        describe: the built-in roles were seeded, and then the file's group
        mapping was applied to them, its default_role stored and its
        user_roles stored — pointing at roles from the other source."""
        path = self.written(
            "roles: {}\ndefault_role: ops\n"
            "user_roles:\n  alice@example.com: admin\n"
            "group_roles:\n  corp-admins: admin\n")
        store, _ = self.seed(path)
        self.assertEqual(store.roles.get("admin")["groups"], ["wdash-admins"])
        self.assertEqual(store.settings.get("rbac.default_role"), "viewer")
        self.assertEqual(store.settings.get("rbac.user_roles"), {})

    def test_an_unusable_roles_block_keeps_the_claim_mappings(self):
        """`claim_mappings` names the claims an identity provider sends. It
        is not a role mapping and does not depend on one, and dropping it
        with the roles block is the same loss this file is about, one step
        earlier: an installation whose provider sends `memberOf` goes back to
        reading `groups`, every group mapping resolves nothing, and everybody
        lands on the default role. Silently — import_claims is deliberately
        quiet, and the ERROR above it enumerates group_roles, user_roles and
        default_role.
        """
        path = self.written(
            "roles: {}\n"
            "claim_mappings:\n"
            "  email_claim: mail\n"
            "  username_claim: uid\n"
            "  groups_claim: memberOf\n")
        store, _ = self.seed(path)
        self.assertEqual(store.settings.get("rbac.claim_mappings"),
                         {"email_claim": "mail", "username_claim": "uid",
                          "groups_claim": "memberOf"})

    def test_a_file_that_cannot_be_parsed_at_all_keeps_nothing(self):
        """The other side of it: a document that is not a mapping of blocks
        has no claim_mappings to keep, and must not be invented."""
        path = self.written("- admin\n- viewer\n")
        store, _ = self.seed(path)
        self.assertIsNone(store.settings.get("rbac.claim_mappings"))

    # ---------- the file is read, and points at roles it has not got ----------

    def test_a_group_mapped_to_an_undefined_role_is_named(self):
        """The inversion can only attach a group to a role being seeded, so
        this one was dropped on the floor."""
        path = self.written(
            "roles:\n  ops:\n    permissions: [logs:read]\n"
            "  viewer:\n    permissions: [logs:read]\n"
            "default_role: viewer\n"
            "group_roles:\n  corp-devs: developers\n")
        store, lines = self.seed(path, level="WARNING")
        self.assertTrue(any("corp-devs" in line and "developers" in line
                            for line in lines), lines)
        self.assertEqual(store.roles.get("ops")["groups"], [])

    def test_a_person_mapped_to_an_undefined_role_is_named(self):
        """Stored as written, resolving to a role that is not there, which
        is no permissions at all."""
        path = self.written(
            "roles:\n  ops:\n    permissions: [logs:read]\n"
            "default_role: ops\n"
            "user_roles:\n  bob@example.com: developers\n")
        _, lines = self.seed(path, level="WARNING")
        self.assertTrue(any("bob@example.com" in line for line in lines), lines)

    def test_a_default_role_that_is_not_defined_is_named(self):
        path = self.written(
            "roles:\n  ops:\n    permissions: [logs:read]\n"
            "default_role: readers\n")
        _, lines = self.seed(path, level="WARNING")
        self.assertTrue(any("readers" in line for line in lines), lines)

    def test_a_default_role_the_file_names_is_quoted_as_the_file_s(self):
        """The half that was already right, held so the other half cannot be
        fixed by flattening both into one vague sentence."""
        path = self.written(
            "roles:\n  ops:\n    permissions: [logs:read]\n"
            "default_role: readers\n")
        _, lines = self.seed(path, level="WARNING")
        self.assertTrue(
            any("names 'readers' as the default role" in line
                for line in lines), lines)

    def test_a_file_with_no_default_role_is_not_blamed_for_naming_one(self):
        """`default_role` falls back to 'viewer' in the code, so a file that
        omits the key and defines no viewer was told it "names 'viewer' as
        the default role and does not define it". The alarm is right —
        everybody with no mapping gets nothing — but an operator sent to the
        file to find `default_role: viewer` does not find it.
        """
        path = self.written("roles:\n  ops:\n    permissions: [logs:read]\n")
        _, lines = self.seed(path, level="WARNING")
        warnings = [line for line in lines if line.startswith("WARNING")]
        self.assertEqual(len(warnings), 1, warnings)
        self.assertNotIn("names 'viewer' as the default role", warnings[0])
        self.assertIn("built-in default", warnings[0])
        self.assertIn("viewer", warnings[0])

    def test_the_shipped_file_produces_nothing_above_info(self):
        """The one that matters: none of this may cry wolf on a fresh clone
        of this repository."""
        rbac = os.path.join(os.path.dirname(__file__), "..", "config",
                            "rbac.yaml")
        with self.assertNoLogs(self.LOGGER, "WARNING"):
            Store.open("sqlite:///:memory:", rbac_file=rbac)


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


class MonitorTlsUpgradeTest(unittest.TestCase):
    """Version 17 on a store that already has checks and results in it.

    Two columns, both NULL, and nothing else touched. What the upgrade must
    not do is change a single existing check's behaviour: NULL on
    `wdash_monitors.tls` has to read as "verify against the public roots",
    which is what every check did before the column existed, and NULL on
    `wdash_monitor_results.handshake_verified` has to read as "this run does
    not say" — not as verified, and not as a finding.

    Runs on both dialects: with WDASH_TEST_POSTGRES set, `build_engine` puts
    this store in a Postgres schema instead, and the ALTERs are the part most
    likely to differ between the two.
    """

    def _at_sixteen(self):
        from datetime import datetime, timezone

        from sqlalchemy import text

        from wdash.store import migrations

        engine = build_engine("sqlite:///:memory:")
        every = migrations.MIGRATIONS
        migrations.MIGRATIONS = [step for step in every if step[0] <= 16]
        try:
            migrations.migrate(engine)
        finally:
            migrations.MIGRATIONS = every

        now = datetime.now(timezone.utc).isoformat()
        with engine.begin() as connection:
            # Migration 1 builds the tables from schema.py, which already
            # declares this version's columns — so a store "at 16" made by
            # running the steps has them anyway, and an upgrade test written
            # against it asserts nothing about the ALTER it is for. Dropped
            # here so this really is a store the new columns are missing
            # from, which is what an installation being upgraded actually is.
            for table, column in (("wdash_monitors", "tls"),
                                  ("wdash_monitor_results",
                                   "handshake_verified")):
                connection.execute(text(
                    f"ALTER TABLE {table} DROP COLUMN {column}"))
            connection.execute(text(
                "INSERT INTO wdash_monitors (id, name, kind, target, "
                "interval_seconds, timeout_seconds, enabled, created_at, "
                "updated_at) VALUES ('m1', 'API', 'http', "
                "'https://payments.internal/health', 60, 10, true, "
                f"'{now}', '{now}')"))
            connection.execute(text(
                "INSERT INTO wdash_monitor_results (monitor_id, agent_id, "
                "started_at, received_at, status, duration_us) VALUES "
                f"('m1', 'a1', '{now}', '{now}', 'up', 1000)"))
        return engine

    def test_the_columns_are_added_and_every_check_still_verifies(self):
        from wdash.store import migrations
        engine = self._at_sixteen()
        # The latest, rather than 17 written out: this test is about the two
        # columns below, and a number that has to be edited every time a
        # migration is added is a test that fails for the wrong reason.
        self.assertEqual(migrations.migrate(engine),
                         max(step[0] for step in migrations.MIGRATIONS))

        store = Store(engine)
        monitor = store.monitors.get("m1")
        self.assertEqual(monitor["tls"], {})
        from wdash.store.monitoring import tls_mode
        self.assertEqual(tls_mode(monitor["tls"]), "verify")
        self.assertEqual(monitor["target"], "https://payments.internal/health")

    def test_a_result_written_before_the_upgrade_reports_no_verdict(self):
        from wdash.store import migrations
        engine = self._at_sixteen()
        migrations.migrate(engine)
        rows = Store(engine).results.latest()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["handshake_verified"])

    def test_the_upgrade_is_safe_to_run_again(self):
        from wdash.store import migrations
        engine = self._at_sixteen()
        self.assertEqual(migrations.migrate(engine), migrations.migrate(engine))


class LocalTotpUpgradeTest(unittest.TestCase):
    """Version 18 on a store that already has local accounts in it.

    Three columns, all NULL, and nothing else touched. What the upgrade must
    not do is lock anybody out of an installation that was working: the
    accounts keep their passwords and their roles, and NULL on all three
    reads as "has not enrolled", which means the next sign-in enrols. It
    must not read as "enrolled, with no secret" — an account that can never
    produce a code that matches, whose only way out is the recovery tool.

    Runs on both dialects: with WDASH_TEST_POSTGRES set, `build_engine` puts
    this store in a Postgres schema instead, and the ALTERs are the part most
    likely to differ between the two.
    """

    def _at_seventeen(self):
        from datetime import datetime, timezone

        from sqlalchemy import text

        from wdash.store import migrations

        engine = build_engine("sqlite:///:memory:")
        every = migrations.MIGRATIONS
        migrations.MIGRATIONS = [step for step in every if step[0] <= 17]
        try:
            migrations.migrate(engine)
        finally:
            migrations.MIGRATIONS = every

        now = datetime.now(timezone.utc).isoformat()
        with engine.begin() as connection:
            # Migration 1 builds the tables from schema.py, which already
            # declares this version's columns, so a store "at 17" made by
            # running the steps has them anyway. Dropped here so this really
            # is a store the new columns are missing from, which is what an
            # installation being upgraded actually is.
            for column in ("totp_secret", "totp_confirmed_at",
                           "totp_last_step"):
                connection.execute(text(
                    f"ALTER TABLE wdash_users DROP COLUMN {column}"))
            connection.execute(text(
                "INSERT INTO wdash_users (id, username, email, password_hash, "
                "role, disabled, created_at) VALUES ('u1', 'owner', NULL, "
                f"'not-a-real-hash', 'admin', false, '{now}')"))
        return engine

    def test_the_columns_are_added_and_the_account_has_not_enrolled(self):
        from wdash.store import migrations
        engine = self._at_seventeen()
        self.assertEqual(migrations.migrate(engine),
                         max(step[0] for step in migrations.MIGRATIONS))

        account = Store(engine).users.by_username("owner")
        self.assertFalse(account["totp_enrolled"])
        self.assertIsNone(account["totp_confirmed_at"])
        self.assertIsNone(account["totp_last_step"])
        self.assertEqual(account["role"], "admin")
        self.assertFalse(account["disabled"])

    def test_the_sealed_secret_never_travels_with_the_account(self):
        """It is a credential. Everything but the sign-in path reads these
        rows to put them on a page, in an audit row or through an invariant,
        and a secret that travels with them is one waiting to be rendered."""
        from wdash.store import migrations
        engine = self._at_seventeen()
        migrations.migrate(engine)
        store = Store(engine, SecretBox(SecretBox.generate_key()))
        store.users.confirm_totp("owner", "GEZDGNBVGY3TQOJQ", 1)

        self.assertNotIn("totp_secret", store.users.by_username("owner"))
        self.assertNotIn("totp_secret", store.users.all()[0])
        self.assertTrue(store.users.by_username("owner")["totp_enrolled"])
        self.assertEqual(store.users.totp_secret("owner"), "GEZDGNBVGY3TQOJQ")

    def test_a_secret_cannot_be_stored_with_no_key(self):
        """Rule one of store/secrets.py, on the newest thing it seals."""
        from wdash.store import migrations
        engine = self._at_seventeen()
        migrations.migrate(engine)
        store = Store(engine, SecretBox(None))
        with self.assertRaises(SecretsUnavailable):
            store.users.confirm_totp("owner", "GEZDGNBVGY3TQOJQ", 1)

    def test_the_upgrade_is_safe_to_run_again(self):
        from wdash.store import migrations
        engine = self._at_seventeen()
        self.assertEqual(migrations.migrate(engine), migrations.migrate(engine))
