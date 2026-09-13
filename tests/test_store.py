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
  * an installation with no roles is given the built-in ones, and one that
    has roles is never given anything
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
    def reopened(self, change):
        """Open a store on a file, change it, and open it again — a restart."""
        url = f"sqlite:///{tempfile.mkdtemp()}/restart.db"
        store = Store.open(url)
        change(store)
        store.engine.dispose()
        return Store.open(url)

    def test_a_new_installation_has_the_default_roles(self):
        from wdash.store.roles import DEFAULT_ROLES
        self.assertEqual([r["name"] for r in fresh_store().roles.all()],
                         sorted(DEFAULT_ROLES))

    def test_an_edit_survives_the_next_start(self):
        """Otherwise a restart quietly reverts every edit made in the UI."""
        def edit(store):
            store.roles.upsert("admin", ["logs:read", "system:admin"],
                               ["prod-*"], ["*"], groups=["corp-sre"])
        admin = self.reopened(edit).roles.get("admin")
        self.assertEqual(admin["permissions"], ["logs:read", "system:admin"])
        self.assertEqual(admin["containers"], ["prod-*"])
        self.assertEqual(admin["groups"], ["corp-sre"])

    def test_an_installation_with_roles_of_its_own_is_given_none_of_these(self):
        """What an installation that imported `auditor` from an rbac.yaml at
        an earlier version looks like. Adding the built-in roles beside it
        would map `wdash-admins` onto `system:admin` in an organisation that
        never granted that to anybody."""
        def replace(store):
            for role in store.roles.all():
                store.roles.delete(role["name"])
            store.roles.upsert("auditor", ["logs:read"], ["audit-*"], [],
                               groups=["corp-audit"])
        store = self.reopened(replace)
        self.assertEqual([r["name"] for r in store.roles.all()], ["auditor"])


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


class TheDefaultRolesTest(unittest.TestCase):
    """What migrating an empty database gives it, held to the one definition.

    There were three answers to "what roles does a fresh install have":
    `DEFAULT_ROLES`, `config/rbac.yaml`, and the copy of that file in the
    Kubernetes ConfigMap. They are written once, so whichever an installation
    landed on was the one it kept — and they had drifted apart in names,
    groups, permissions and boundaries. A test compared the first two; the
    third was compared with nothing, and gave `developer` every service.

    One definition is left, so there is nothing to compare it with. What is
    left to hold is that the migration writes it, every field of it, and
    that what it says is still worth getting. Migrated here and opened with
    no `Store.open`, so it is the migration being held and not whatever else
    a start might do.
    """

    FIELDS = ("description", "permissions", "containers", "trace_containers",
              "services", "groups")

    def setUp(self):
        from wdash.store import migrate
        from wdash.store.roles import DEFAULT_ROLES
        self.defaults = DEFAULT_ROLES
        engine = build_engine("sqlite:///:memory:")
        migrate(engine)
        self.store = Store(engine)

    def test_the_migration_writes_exactly_the_default_roles(self):
        stored = {role["name"]: {field: role[field] for field in self.FIELDS}
                  for role in self.store.roles.all()}
        self.assertEqual(stored, self.defaults)

    def test_it_maps_no_named_person_and_defaults_to_viewer(self):
        """A mapping here is one every new installation inherits from
        somebody else. The shipped file once carried a maintainer's own
        username, which granted admin to anyone signing in with that name."""
        self.assertEqual(self.store.settings.get("rbac.user_roles"), {})
        self.assertEqual(self.store.settings.get("rbac.default_role"), "viewer")

    def test_it_stores_the_claims_the_shipped_file_named(self):
        """`config/rbac.yaml` carried `claim_mappings`, and every installation
        made from this repository stored them. Written out rather than read
        from `DEFAULT_CLAIM_MAPPINGS`: with the file gone this is the record
        of what they were, and changing one changes which claim a new
        installation reads a person's groups from."""
        self.assertEqual(self.store.settings.get("rbac.claim_mappings"),
                         {"email_claim": "email",
                          "username_claim": "preferred_username",
                          "groups_claim": "groups"})

    def test_the_groups_are_namespaced(self):
        """A directory almost certainly has a group called `admins` already,
        it usually means domain administrators, and a default that maps it to
        `system:admin` hands WDash's highest privilege to everyone in it."""
        for name, definition in self.defaults.items():
            for group in definition["groups"]:
                self.assertTrue(group.startswith("wdash-"),
                                f"{name} maps {group!r}, a name somebody "
                                f"else's directory probably already uses")

    def test_every_permission_is_granted_by_some_default_role(self):
        """A permission no shipped role holds is a screen a new installation
        cannot open, and the only symptom is a missing menu item. Measured
        once already: the file predated `monitors:read` and granted it to
        nobody, so every clone of this repository had no Monitors screen for
        anyone, the administrator included."""
        from wdash.permissions import PERMISSIONS
        granted = {permission for definition in self.defaults.values()
                   for permission in definition["permissions"]}
        for permission in PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertIn(permission, granted)

    def test_no_default_role_asks_for_a_permission_that_is_not_one(self):
        """`logs:search` folded into `logs:read` and `user:manage` into
        `system:admin`. The ConfigMap's copy of the roles once shipped both. A
        retired name is translated on the way out, so it is not an error — it
        is a definition of a version of this application that no longer
        exists."""
        from wdash.permissions import RETIRED, known
        for name, definition in self.defaults.items():
            for permission in definition["permissions"]:
                with self.subTest(role=name, permission=permission):
                    self.assertNotIn(permission, RETIRED)
                    self.assertTrue(known(permission))

    def test_the_middle_roles_do_not_reach_infrastructure(self):
        """The boundaries are what a role IS. `developer` once reached every
        log container and every service from here, and `viewer` every
        service, while the file held them to applications — so an
        installation that found no file was seeded with the wider set."""
        developer = self.store.roles.get("developer")
        self.assertEqual(sorted(developer["containers"]), ["app-*", "service-*"])
        self.assertIn("api-gateway", developer["services"])
        self.assertNotIn("postgres", developer["services"])
        self.assertEqual(self.store.roles.get("viewer")["services"],
                         ["api-gateway"])


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


class BuiltInRolesUpgradeTest(unittest.TestCase):
    """Version 19 on the stores an upgrade actually meets.

    Before it, the built-in roles were written at start-up by
    `RoleRepository.seed`, so every store at version 18 that anybody runs
    already has roles: the built-in ones, edited or not, or its own from an
    rbac.yaml. The migration has to leave every one of them exactly as it
    was — every column of every row, times included — and give the built-in
    roles only to a store that has none.

    Runs on both dialects: with WDASH_TEST_POSTGRES set, `build_engine` puts
    this store in a Postgres schema instead.
    """

    MEMBEROF = {"email_claim": "mail", "username_claim": "uid",
                "groups_claim": "memberOf"}

    def at_eighteen(self):
        from wdash.store import migrations

        engine = build_engine("sqlite:///:memory:")
        every = migrations.MIGRATIONS
        migrations.MIGRATIONS = [step for step in every if step[0] <= 18]
        try:
            migrations.migrate(engine)
        finally:
            migrations.MIGRATIONS = every
        return engine, Store(engine)

    @staticmethod
    def everything(engine):
        """Every column of every role and every setting."""
        from sqlalchemy import select

        from wdash.store.schema import roles, settings
        with engine.connect() as connection:
            return {
                "roles": {row["name"]: dict(row) for row in
                          connection.execute(select(roles)).mappings()},
                "settings": {row["key"]: dict(row) for row in
                             connection.execute(select(settings)).mappings()},
            }

    def upgraded(self, engine):
        """(before, after) migrating to the latest version."""
        from wdash.store import migrations
        before = self.everything(engine)
        self.assertEqual(migrations.migrate(engine),
                         max(step[0] for step in migrations.MIGRATIONS))
        return before, self.everything(engine)

    def test_an_installation_whose_roles_were_edited_is_left_as_it_was(self):
        from wdash.store.roles import DEFAULT_CLAIM_MAPPINGS, DEFAULT_ROLES
        engine, store = self.at_eighteen()
        # What its first start gave it...
        for name, definition in DEFAULT_ROLES.items():
            store.roles.upsert(
                name, definition["permissions"], definition["containers"],
                definition["trace_containers"], services=definition["services"],
                groups=definition["groups"],
                description=definition["description"])
        store.settings.set("rbac.default_role", "viewer")
        store.settings.set("rbac.user_roles", {})
        store.settings.set("rbac.claim_mappings", dict(DEFAULT_CLAIM_MAPPINGS))
        # ...and then the page.
        store.roles.upsert("admin", ["logs:read", "system:admin"],
                           ["prod-*", "-prod-secrets"], ["tempo:*"],
                           services=["checkout"],
                           groups=["corp-sre", "wdash-admins"],
                           description="edited on the page")
        store.roles.delete("developer")
        store.roles.upsert("auditor", ["logs:read"], ["audit-*"], [],
                           services=[], groups=["corp-audit"])
        store.settings.set("rbac.default_role", "auditor", updated_by="alice")
        store.settings.set("rbac.user_roles", {"bob@example.com": "admin"},
                           updated_by="alice")
        store.settings.set("rbac.claim_mappings", self.MEMBEROF,
                           updated_by="alice")

        before, after = self.upgraded(engine)
        self.assertEqual(after, before)
        self.assertEqual(sorted(after["roles"]), ["admin", "auditor", "viewer"])

    def test_an_installation_with_only_roles_of_its_own_is_given_nothing(self):
        """What importing an rbac.yaml of `auditor` and `ops` left, at a
        version before claim mappings were read. The built-in roles beside
        them would map `wdash-admins` onto `system:admin` in an organisation
        that never granted it; a claim mapping would be a write into an
        installation that has roles, which this migration never makes."""
        engine, store = self.at_eighteen()
        store.roles.upsert("auditor", ["logs:read"], ["audit-*"], [],
                           services=[], groups=["corp-audit"],
                           description="Reads the audit indices")
        store.roles.upsert("ops", ["logs:read", "traces:read", "system:admin"],
                           ["*", "-secrets-*"], ["tempo:*"],
                           services=["*", "-vault"],
                           groups=["corp-sre", "corp-oncall"])
        store.settings.set("rbac.default_role", "auditor")
        store.settings.set("rbac.user_roles", {"carol@example.com": "ops"})

        before, after = self.upgraded(engine)
        self.assertEqual(after, before)
        self.assertNotIn("rbac.claim_mappings", after["settings"])

    def test_a_claim_mapping_already_stored_is_never_replaced(self):
        """Roles emptied by hand leave their settings behind. The roles are
        written again; a stored setting is not — `memberOf` replaced by
        `groups` resolves no group mapping for anybody, and says nothing."""
        from wdash.store.roles import DEFAULT_ROLES
        engine, store = self.at_eighteen()
        store.settings.set("rbac.claim_mappings", self.MEMBEROF,
                           updated_by="alice")
        store.settings.set("rbac.default_role", "ops", updated_by="alice")

        before, after = self.upgraded(engine)
        self.assertEqual(sorted(after["roles"]), sorted(DEFAULT_ROLES))
        for key in ("rbac.claim_mappings", "rbac.default_role"):
            self.assertEqual(after["settings"][key], before["settings"][key])
        self.assertEqual(after["settings"]["rbac.user_roles"]["value"], {})

    def test_running_it_again_changes_nothing(self):
        """The version row keeps `migrate` from running it twice. This is
        the step itself, over its own work: it must neither fail on a key it
        wrote nor rewrite a row."""
        from wdash.store import migrations
        engine, _ = self.at_eighteen()
        migrations.migrate(engine)
        once = self.everything(engine)
        with engine.begin() as connection:
            migrations._give_an_installation_with_no_roles_the_built_in_ones(
                connection)
        self.assertEqual(self.everything(engine), once)
        self.assertEqual(migrations.migrate(engine), migrations.migrate(engine))
        self.assertEqual(self.everything(engine), once)
