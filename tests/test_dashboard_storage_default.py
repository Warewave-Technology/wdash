"""
Dashboards and saved searches live in the metadata database by default.

The setting moved; the JSON file store did not go anywhere. Three things have
to hold at once, and this module is arranged around them:

  * an installation that says nothing gets the database, for dashboards AND
    for saved searches — one setting decides both, which is the half of the
    flip that is easy to miss. The saved searches are not on the dashboards
    page, so nobody goes looking for them until the shift when the query they
    always run has gone;
  * an installation that says `DASHBOARD_STORAGE=file` gets exactly what it
    got before, files and all;
  * an installation that has JSON files and never said anything is TOLD, at
    start-up, by name, with the command — instead of being shown an empty
    list that says "Create your first". The warning has to be silent for a
    deployment with no file, an empty file, or one whose records are already
    in the database, or it is a line people learn to scroll past.
"""

import contextlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, SRC)

from tests import support  # noqa: E402

import wdash.app as app_module  # noqa: E402
from wdash.app import create_app, files_left_behind  # noqa: E402
from wdash.config import Config, DEFAULT_DASHBOARD_FILE  # noqa: E402
from wdash.store import SecretBox, Store  # noqa: E402

PASSWORD = "a-sufficiently-long-password"


#: "the class decides", as distinct from "say nothing".
KEEP = object()


class _Installation(unittest.TestCase):
    """One data directory, one metadata database, nothing else set."""

    STORAGE = None                      # None: say nothing, take the default

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="wdash-a2-")
        self.dashboards = os.path.join(self.directory, "dashboards.json")
        self.searches = os.path.join(self.directory, "saved_searches.json")
        self.database = os.path.join(self.directory, "wdash.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def config(self, storage=KEEP, **extra):
        """A config class. `storage=None` leaves DASHBOARD_STORAGE unsaid,
        which is the case the whole module is about."""
        values = {
            "TESTING": True,
            "SECRET_KEY": "storage-default",
            "DATABASE_URL": f"sqlite:///{self.database}",
            "ENCRYPTION_KEY": SecretBox.generate_key(),
            "OIDC_CLIENT_ID": None,
            "ELASTICSEARCH_URL": "",
            "DASHBOARD_STORAGE_FILE": self.dashboards,
        }
        chosen = self.STORAGE if storage is KEEP else storage
        if chosen is not None:
            values["DASHBOARD_STORAGE"] = chosen
        values.update(extra)
        return type("TestConfig", (Config,), values)

    def warnings_at_start_up(self, config):
        """Every WARNING create_app logs, as text.

        A fresh installation logs two of its own — no local account yet, and
        no encryption key — so "did it warn?" has to be asked of the message,
        not of the level.
        """
        with self.assertLogs("wdash.app", "WARNING") as caught:
            create_app(config)
        return [record.getMessage() for record in caught.records]

    def build(self, **extra):
        app = create_app(self.config(**extra))
        client = app.test_client()
        support.set_up(client, username="owner", password=PASSWORD)
        return app, client

    def write_dashboards(self, records):
        with open(self.dashboards, "w") as handle:
            json.dump(records, handle)

    def write_searches(self, records):
        with open(self.searches, "w") as handle:
            json.dump(records, handle)

    def a_dashboard(self, identifier="left-1", name="Left behind"):
        return {"id": identifier, "name": name, "description": "",
                "query": "level:ERROR", "created_by": "owner",
                "created_at": "2026-01-15T10:00:00+00:00",
                "index_patterns": ["app-*"]}

    def a_search(self, identifier="search-1", name="Mine"):
        return {"id": identifier, "name": name, "query": "level:ERROR",
                "time_range": "24h", "created_by": "owner",
                "created_at": "2026-01-15T10:00:00+00:00"}


class TheDefaultIsTheDatabaseTest(_Installation):
    """What an installation that sets nothing at all gets."""

    def test_a_dashboard_saved_by_somebody_who_set_nothing_is_in_the_database(self):
        """The owner's ask. Before this the same install wrote a second store
        beside the metadata database that was opened either way."""
        app, client = self.build()
        app.dashboard_manager.create_dashboard(
            "Board", "", "*", "owner", ["app-*"])

        store = Store.open(f"sqlite:///{self.database}")
        self.assertEqual([d.name for d in store.dashboards.get_all_dashboards()],
                         ["Board"])
        self.assertFalse(os.path.exists(self.dashboards),
                         "a JSON dashboard file was written anyway")

    def test_a_saved_search_goes_with_them(self):
        """The half D1 did not mention: one setting decides both, so the
        default flip moves saved searches as well. If this ever lands in the
        file while dashboards land in the database, the migration is a
        half-truth again."""
        app, client = self.build()
        response = client.post("/api/saved-searches",
                               json={"name": "Mine", "query": "level:ERROR",
                                     "time_range": "24h"})
        self.assertEqual(response.status_code, 201)

        store = Store.open(f"sqlite:///{self.database}")
        self.assertEqual([s.name for s in store.saved_searches.all_for("owner")],
                         ["Mine"])
        self.assertFalse(os.path.exists(self.searches),
                         "a JSON saved-searches file was written anyway")

    def test_the_two_stores_cannot_be_split_by_a_config_that_omits_the_key(self):
        """`app.config.get('DASHBOARD_STORAGE', ...)` was read twice with a
        default of its own each time. A config object that simply has no such
        key — which is every config not built from `Config` — then read its
        dashboards from one store and its searches from the other."""
        from wdash.config import Config as _Config

        class Bare:
            pass

        for name in dir(_Config):
            if name.isupper() and name != "DASHBOARD_STORAGE":
                setattr(Bare, name, getattr(_Config, name))
        Bare.TESTING = True
        Bare.SECRET_KEY = "no-storage-key"
        Bare.DATABASE_URL = f"sqlite:///{self.database}"
        Bare.ENCRYPTION_KEY = SecretBox.generate_key()
        Bare.OIDC_CLIENT_ID = None
        Bare.ELASTICSEARCH_URL = ""
        Bare.DASHBOARD_STORAGE_FILE = self.dashboards

        app = create_app(Bare)
        client = app.test_client()
        support.set_up(client, username="owner", password=PASSWORD)
        app.dashboard_manager.create_dashboard("Board", "", "*", "owner", ["*"])
        client.post("/api/saved-searches",
                    json={"name": "Mine", "query": "*", "time_range": "1h"})

        store = Store.open(f"sqlite:///{self.database}")
        self.assertEqual([d.name for d in store.dashboards.get_all_dashboards()],
                         ["Board"])
        self.assertEqual([s.name for s in store.saved_searches.all_for("owner")],
                         ["Mine"],
                         "the search went to the file while dashboards "
                         "went to the database")


class AFileInstallationIsUnchangedTest(_Installation):
    """`DASHBOARD_STORAGE=file` must behave exactly as it did before."""

    STORAGE = "file"

    def test_the_dashboard_is_written_to_the_json_file(self):
        app, client = self.build()
        app.dashboard_manager.create_dashboard(
            "Board", "", "*", "owner", ["app-*"])

        with open(self.dashboards) as handle:
            stored = json.load(handle)
        self.assertEqual([row["name"] for row in stored], ["Board"])

        store = Store.open(f"sqlite:///{self.database}")
        self.assertEqual(store.dashboards.get_all_dashboards(), [],
                         "the database was written to as well")

    def test_the_saved_search_is_written_beside_it(self):
        app, client = self.build()
        response = client.post("/api/saved-searches",
                               json={"name": "Mine", "query": "level:ERROR",
                                     "time_range": "24h"})
        self.assertEqual(response.status_code, 201)

        with open(self.searches) as handle:
            stored = json.load(handle)
        self.assertEqual([row["name"] for row in stored], ["Mine"])

        store = Store.open(f"sqlite:///{self.database}")
        self.assertEqual(store.saved_searches.all_for("owner"), [],
                         "the database was written to as well")

    def test_what_is_already_in_the_files_is_still_listed(self):
        """The upgrade path for somebody who does not want to move."""
        self.write_dashboards([self.a_dashboard(name="Existing")])
        self.write_searches([self.a_search(name="Saved")])
        app, client = self.build()

        self.assertEqual(
            [d.name for d in app.dashboard_manager.get_all_dashboards()],
            ["Existing"])
        self.assertEqual([row["name"] for row in
                          client.get("/api/saved-searches").get_json()],
                         ["Saved"])

    def test_nothing_is_said_about_files_that_are_being_read(self):
        """The warning is about a store nobody reads. Here they are read."""
        self.write_dashboards([self.a_dashboard()])
        self.write_searches([self.a_search()])
        said = self.warnings_at_start_up(self.config(SECRET_KEY="file-quiet"))
        self.assertEqual(
            [line for line in said if "migrate_cli" in line], [],
            "a file installation was told to migrate the files it reads")


class TheStartUpWarningTest(_Installation):
    """What an upgrading installation is told, and when it is told nothing."""

    def warning(self, **extra):
        """The start-up warning this configuration produces, or None."""
        app = create_app(self.config(**extra))
        return files_left_behind(app.store, self.dashboards)

    def test_the_dashboards_file_is_named_with_a_count(self):
        self.write_dashboards([self.a_dashboard("a"), self.a_dashboard("b")])
        said = self.warning()
        self.assertIn(os.path.abspath(self.dashboards), said)
        self.assertIn("2 dashboards", said)

    def test_the_saved_searches_file_is_named_too(self):
        """The failure the critique found: an operator sees the warning about
        dashboards.json, migrates dashboards only, and their saved searches
        are gone from the Logs page with nothing naming the file that still
        holds them."""
        self.write_dashboards([self.a_dashboard()])
        self.write_searches([self.a_search()])
        said = self.warning()
        self.assertIn(os.path.abspath(self.searches), said)
        self.assertIn("1 saved search", said)

    def test_searches_alone_are_enough_to_warn(self):
        """An installation whose users saved searches but never made a
        dashboard has no dashboards.json at all."""
        self.write_searches([self.a_search()])
        said = self.warning()
        self.assertIsNotNone(said, "a saved-searches file left behind said "
                                   "nothing at all")
        self.assertIn(os.path.abspath(self.searches), said)

    def test_it_says_what_to_run(self):
        self.write_dashboards([self.a_dashboard()])
        self.write_searches([self.a_search()])
        said = self.warning()
        self.assertIn("wdash.store.migrate_cli", said)
        self.assertIn(f"--dashboards {self.dashboards}", said)
        self.assertIn(f"--saved-searches {self.searches}", said)

    def test_it_says_nothing_was_deleted(self):
        """The first thought on seeing an empty dashboard list is that
        somebody deleted them."""
        self.write_dashboards([self.a_dashboard()])
        self.assertIn("Nothing has been deleted", self.warning())

    def test_it_reaches_the_log_at_start_up(self):
        """Not just a function that could be called."""
        self.write_dashboards([self.a_dashboard()])
        said = self.warnings_at_start_up(self.config(SECRET_KEY="warned"))
        self.assertTrue(
            any(os.path.abspath(self.dashboards) in line for line in said),
            said)

    # ---------- and when it must stay quiet ----------

    def test_no_file_at_all_says_nothing(self):
        """A new installation. Warning it about a file it never had is how a
        warning becomes noise."""
        self.assertIsNone(self.warning())

    def test_an_empty_file_says_nothing(self):
        self.write_dashboards([])
        self.write_searches([])
        self.assertIsNone(self.warning())

    def test_a_file_whose_records_are_already_in_the_database_says_nothing(self):
        """The migration leaves the JSON files where they are, deliberately,
        so the move is reversible. A warning that can only be silenced by
        deleting the data would teach people to ignore it."""
        self.write_dashboards([self.a_dashboard()])
        self.write_searches([self.a_search()])
        self.migrate()
        self.assertIsNone(self.warning())

    def test_a_file_holding_one_record_that_moved_and_one_that_did_not(self):
        """Counted per record, not per file: an interrupted migration leaves
        exactly this."""
        self.write_dashboards([self.a_dashboard("a"), self.a_dashboard("b")])
        self.migrate()
        self.write_dashboards([self.a_dashboard("a"), self.a_dashboard("b"),
                               self.a_dashboard("c")])
        self.assertIn("1 dashboard that", self.warning())

    def test_a_file_that_cannot_be_read_is_named_as_unreadable(self):
        """Not counted as zero. A failure that looks like emptiness is the
        one thing this whole check exists to prevent."""
        with open(self.dashboards, "w") as handle:
            handle.write("{not json at all")
        said = self.warning()
        self.assertIn(os.path.abspath(self.dashboards), said)
        self.assertIn("cannot be read", said)

    def test_a_test_run_is_not_warned_about_the_repository_s_own_files(self):
        """`data/dashboards.json` belongs to the checkout, not to a TESTING
        app that named no path — the file store has been redirected away from
        it for as long as the isolation has existed, and reading it to warn
        about it puts the test run back on the developer's own data.

        Proved by moving what "the packaged default" is, since the real one
        must not be written to from a test.
        """
        from unittest import mock

        packaged = os.path.join(self.directory, "packaged.json")
        with open(packaged, "w") as handle:
            json.dump([self.a_dashboard()], handle)

        with mock.patch("wdash.app.DEFAULT_DASHBOARD_FILE", packaged):
            said = self.warnings_at_start_up(
                self.config(SECRET_KEY="packaged",
                            DASHBOARD_STORAGE_FILE=packaged))
        self.assertEqual([line for line in said if packaged in line], [],
                         "a test run was told to migrate the repository's "
                         "own dashboards file")

    def test_a_test_run_does_not_write_its_saved_searches_into_the_checkout(self):
        """The searches file is derived from the dashboards file, and the
        derivation used the raw setting while the dashboards file used the
        isolated one — so a TESTING app on the file store kept its
        dashboards in a temporary directory and its saved searches in
        `data/saved_searches.json`, in the repository."""
        from unittest import mock

        packaged = os.path.join(self.directory, "packaged.json")
        beside = os.path.join(self.directory, "saved_searches.json")

        with mock.patch("wdash.app.DEFAULT_DASHBOARD_FILE", packaged):
            app = create_app(self.config(storage="file",
                                         SECRET_KEY="packaged-searches",
                                         DASHBOARD_STORAGE_FILE=packaged))
            client = app.test_client()
            support.set_up(client, username="owner", password=PASSWORD)
            reply = client.post("/api/saved-searches",
                                json={"name": "Mine", "query": "*",
                                      "time_range": "1h"})
        self.assertEqual(reply.status_code, 201)
        self.assertFalse(os.path.exists(beside),
                         "a test run wrote a saved search beside the "
                         "packaged dashboards file")

    def test_a_start_up_check_that_throws_does_not_stop_the_application(self):
        """Somebody's dashboards being unreachable is bad; their WDash not
        starting is worse."""
        from unittest import mock

        self.write_dashboards([self.a_dashboard()])
        with mock.patch("wdash.app._stored_ids",
                        side_effect=RuntimeError("no database")):
            app = create_app(self.config(SECRET_KEY="still-starts"))
        self.assertIsNotNone(app)

    # ---------- the command it prints is one that runs ----------

    def migrate(self, extra=()):
        from wdash.store.migrate_cli import main

        arguments = ["--database-url", f"sqlite:///{self.database}",
                     "--dashboards", self.dashboards]
        if os.path.exists(self.searches):
            arguments += ["--saved-searches", self.searches]
        arguments += list(extra)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = main(arguments)
        return code, out.getvalue()

    def printed_command(self, said):
        """The arguments the warning tells somebody to run."""
        return said.split("migrate_cli", 1)[1].splitlines()[0].split()

    def run_printed(self, said):
        from wdash.store.migrate_cli import main

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = main(["--database-url", f"sqlite:///{self.database}"]
                        + self.printed_command(said))
        return code, out.getvalue()

    def test_the_command_it_prints_is_one_that_runs(self):
        """A printed command that exits 1 is worse than no command: the
        migration refuses a path it was told to read and cannot find, so
        naming a file that is not there stops the run before it reads
        anything. Here there are searches and no dashboards file at all,
        which is an installation whose users saved searches and never made a
        dashboard."""
        self.write_searches([self.a_search()])          # no dashboards file
        said = self.warning()
        code, out = self.run_printed(said)
        self.assertEqual(code, 0, out)
        self.assertIn("Saved searches: 1 moved", out)

    def test_it_does_not_name_a_searches_file_that_is_not_there(self):
        """Named, the migration requires it and exits 1. Unnamed, it derives
        the same path from the dashboards file and treats absence as the
        ordinary "nobody has saved one"."""
        self.write_dashboards([self.a_dashboard()])
        said = self.warning()
        self.assertNotIn("--saved-searches", said)
        code, out = self.run_printed(said)
        self.assertEqual(code, 0, out)
        self.assertIn("Dashboards:     1 moved", out)

    def test_running_it_silences_the_warning(self):
        """The whole loop: told, ran what it said, told nothing more."""
        self.write_dashboards([self.a_dashboard()])
        self.write_searches([self.a_search()])
        code, out = self.run_printed(self.warning())
        self.assertEqual(code, 0, out)
        self.assertIsNone(self.warning())


class TheMigrationCarriesEverythingTest(_Installation):
    """A file installation of my own making, moved, field by field.

    Written through the application rather than by hand, so what is migrated
    is what WDash actually stores — a fixture written to match the importer
    proves only that the fixture matches the importer.
    """

    STORAGE = "file"

    def test_every_field_arrives_and_the_pages_show_them(self):
        app, client = self.build()
        manager = app.dashboard_manager
        first = manager.create_dashboard(
            "Errors by service", "the one on the wall", "level:ERROR",
            "owner", ["app-*", "api-*"],
            panels=[{"id": "p1", "type": "terms", "title": "Hosts",
                     "field": "host", "size": 3, "width": 6}],
            thresholds={"error_rate": {"warning": 1.0, "critical": 5.0}},
            visibility="private")
        second = manager.create_dashboard(
            "Everything", "", "*", "colleague", ["*"], source="secondary")
        manager.create_dashboard("Third", "", "*", "owner", ["*"])
        client.post("/api/saved-searches",
                    json={"name": "Yesterday's errors",
                          "query": "level:ERROR AND service:\"api\"",
                          "time_range": "24h"})

        with open(self.dashboards) as handle:
            self.assertEqual(len(json.load(handle)), 3)

        code, out = self.migrate()
        self.assertEqual(code, 0, out)
        self.assertIn("Dashboards:     3 moved", out)
        self.assertIn("Saved searches: 1 moved", out)

        store = Store.open(f"sqlite:///{self.database}")
        moved = {d.name: d for d in store.dashboards.get_all_dashboards()}
        self.assertEqual(sorted(moved), ["Errors by service", "Everything",
                                         "Third"])

        arrived = moved["Errors by service"]
        self.assertEqual(arrived.id, first.id)
        self.assertEqual(arrived.description, "the one on the wall")
        self.assertEqual(arrived.query, "level:ERROR")
        self.assertEqual(arrived.created_by, "owner")
        self.assertEqual(sorted(arrived.index_patterns), ["api-*", "app-*"])
        self.assertEqual(arrived.get_panels()[0]["field"], "host")
        self.assertEqual(arrived.thresholds,
                         {"error_rate": {"warning": 1.0, "critical": 5.0}})
        self.assertEqual(arrived.visibility, "private")
        self.assertEqual(
            arrived.created_at.replace(tzinfo=None).isoformat(timespec="seconds"),
            first.created_at.replace(tzinfo=None).isoformat(timespec="seconds"),
            "a bulk import must not restamp history")

        self.assertEqual(moved["Everything"].source, "secondary")
        self.assertEqual(moved["Everything"].created_by, "colleague")

        search = store.saved_searches.all_for("owner")[0]
        self.assertEqual(search.name, "Yesterday's errors")
        self.assertEqual(search.query, 'level:ERROR AND service:"api"')
        self.assertEqual(search.time_range, "24h")

    def test_the_same_installation_started_on_the_default_shows_them_all(self):
        """End to end: the files, the migration, and then the pages of an
        installation that now sets nothing."""
        app, client = self.build()
        for name in ("One", "Two"):
            app.dashboard_manager.create_dashboard(name, "", "*", "owner", ["*"])
        client.post("/api/saved-searches",
                    json={"name": "Mine", "query": "*", "time_range": "24h"})
        code, out = self.migrate()
        self.assertEqual(code, 0, out)

        upgraded = create_app(self.config(storage=None,
                                          SECRET_KEY="upgraded"))
        self.assertEqual(
            sorted(d.name for d in upgraded.dashboard_manager.get_all_dashboards()),
            ["One", "Two"])

        after = upgraded.test_client()
        with after.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": None,
                                    "username": "owner", "groups": []}
            session["_user_id"] = self.owner_id(upgraded)
        self.assertEqual([row["name"] for row in
                          after.get("/api/saved-searches").get_json()],
                         ["Mine"])

    def test_nothing_more_is_said_about_the_files_afterwards(self):
        app, client = self.build()
        app.dashboard_manager.create_dashboard("One", "", "*", "owner", ["*"])
        client.post("/api/saved-searches",
                    json={"name": "Mine", "query": "*", "time_range": "24h"})
        self.migrate()

        upgraded = create_app(self.config(storage=None,
                                          SECRET_KEY="quiet-after"))
        self.assertIsNone(files_left_behind(upgraded.store, self.dashboards))

    def migrate(self):
        from wdash.store.migrate_cli import main

        out = io.StringIO()
        arguments = ["--database-url", f"sqlite:///{self.database}",
                     "--dashboards", self.dashboards]
        if os.path.exists(self.searches):
            arguments += ["--saved-searches", self.searches]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = main(arguments)
        return code, out.getvalue()

    def owner_id(self, app):
        return app.store.users.by_username("owner")["id"]


class ThePrintedCommandFindsTheConfiguredDatabaseTest(_Installation):
    """The command the warning prints, run the way an operator runs it.

    The warning does not print --database-url on purpose: that address
    carries a password on Postgres and this line goes into a log. So the
    command has to find the metadata database by itself, the same way the
    application does — and `--database-url` defaulted from `os.environ` at
    the moment argparse built the flag, before anything had imported
    `wdash.config` and therefore before `load_dotenv()` had run.

    A deployment that keeps DATABASE_URL in `.env` — `cp .env.example .env`
    is the README's own quick start — ran exactly what it was told to run,
    was shown "Dashboards: 1 moved" and "Done", and its configured store was
    never opened. The records landed in a brand-new `data/wdash.db` beside
    the working directory, so the next start printed the same warning again:
    a loop with a success message in it, on the one path this package
    advertises.
    """

    def setUp(self):
        super().setUp()
        # A deployment directory of its own, with the package reachable
        # underneath it — `load_dotenv()` walks up from wdash/config.py, so
        # this is what makes the .env found here THIS deployment's and not
        # some other checkout's.
        self.deployment = tempfile.mkdtemp(prefix="wdash-a2-deployment-")
        os.symlink(SRC, os.path.join(self.deployment, "src"))
        self.configured = os.path.join(self.deployment, "metadata", "wdash.db")
        os.makedirs(os.path.dirname(self.configured))
        with open(os.path.join(self.deployment, ".env"), "w") as handle:
            handle.write(f"DATABASE_URL=sqlite:///{self.configured}\n")
        # Laid out the way a deployment is: the JSON files under data/, which
        # is also where `sqlite:///data/wdash.db` lands when nothing resolves
        # the configured address.
        self.data = os.path.join(self.deployment, "data")
        os.makedirs(self.data)
        self.dashboards = os.path.join(self.data, "dashboards.json")
        self.searches = os.path.join(self.data, "saved_searches.json")
        self.stray = os.path.join(self.data, "wdash.db")

    def tearDown(self):
        shutil.rmtree(self.deployment, ignore_errors=True)
        super().tearDown()

    def printed_command(self, said):
        return said.split("migrate_cli", 1)[1].splitlines()[0].split()

    def test_it_runs_against_the_database_the_dot_env_names(self):
        self.write_dashboards([self.a_dashboard(name="On the wall")])
        app = create_app(self.config())
        said = files_left_behind(app.store, self.dashboards)
        arguments = self.printed_command(said)

        environment = dict(os.environ)
        for key in ("DATABASE_URL", "DASHBOARD_STORAGE",
                    "DASHBOARD_STORAGE_FILE", "WDASH_NO_DOTENV"):
            environment.pop(key, None)
        environment["PYTHONPATH"] = os.path.join(self.deployment, "src")
        done = subprocess.run(
            [sys.executable, "-m", "wdash.store.migrate_cli"] + arguments,
            cwd=self.deployment, env=environment, capture_output=True,
            text=True)
        told = done.stdout + done.stderr

        self.assertEqual(done.returncode, 0, told)
        self.assertIn("1 moved", told)
        self.assertFalse(
            os.path.exists(self.stray),
            "the migration made itself a database beside the working "
            f"directory instead of opening the configured one:\n{told}")
        self.assertTrue(
            os.path.exists(self.configured),
            f"it reported a successful move and never opened the database "
            f"this deployment configured:\n{told}")
        # Read as a file, not through `Store`: this asserts WHICH database
        # the separate process wrote to, and on a Postgres run the suite
        # swaps every SQLite address in THIS process for a schema of its own.
        with contextlib.closing(sqlite3.connect(self.configured)) as opened:
            self.assertEqual(
                [row[0] for row in
                 opened.execute("select name from wdash_dashboards")],
                ["On the wall"])

    def test_the_printed_command_still_carries_no_database_address(self):
        """The other way to make the command work is to print the address
        into the warning, and the warning goes to the log. Base commit
        0b10034 is about exactly that."""
        self.write_dashboards([self.a_dashboard()])
        app = create_app(self.config())
        said = files_left_behind(app.store, self.dashboards)
        self.assertNotIn("--database-url", said)

    def test_the_flag_defaults_to_the_configuration_not_to_the_environment(self):
        """The fault without the subprocess: what the default is READ from.
        `os.environ` at the moment argparse builds the flag is not the
        configuration this deployment runs on."""
        from wdash.store import migrate_cli

        self.write_dashboards([self.a_dashboard()])
        wanted = f"sqlite:///{os.path.join(self.directory, 'elsewhere.db')}"
        opened = []
        real = migrate_cli.Store

        class Spy:
            @staticmethod
            def open(url=None, **keywords):
                opened.append(url)
                return real.open(f"sqlite:///{self.database}", **keywords)

        with mock.patch.object(migrate_cli, "Store", Spy), \
                mock.patch.object(Config, "DATABASE_URL", wanted):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(out):
                code = migrate_cli.main(["--dashboards", self.dashboards])
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(opened, [wanted])

    def test_an_address_on_the_command_line_still_wins(self):
        """The flag is the override, not the other way round."""
        from wdash.store import migrate_cli

        self.write_dashboards([self.a_dashboard()])
        opened = []
        real = migrate_cli.Store

        class Spy:
            @staticmethod
            def open(url=None, **keywords):
                opened.append(url)
                return real.open(f"sqlite:///{self.database}", **keywords)

        with mock.patch.object(migrate_cli, "Store", Spy), \
                mock.patch.object(Config, "DATABASE_URL", "sqlite:///ignored"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(out):
                migrate_cli.main(["--database-url", "sqlite:///said-so",
                                  "--dashboards", self.dashboards])
        self.assertEqual(opened, ["sqlite:///said-so"])


class AnUnrecognisedSettingIsRefusedTest(_Installation):
    """A value that is neither 'database' nor 'file'.

    It used to reach the JSON file store without a word. Harmless while
    'file' was the default and held the data; now the data is in the
    database, so one transposed letter showed an empty dashboard list and an
    empty saved-search list with nothing logged — "there is nothing" and "we
    looked somewhere else" made indistinguishable, which is the defect this
    whole package exists to remove.
    """

    def a_dashboard_in_the_database(self):
        store = Store.open(f"sqlite:///{self.database}")
        store.dashboards.create_dashboard(
            name="On the wall", description="", query="*",
            created_by="owner", index_patterns=["*"])

    def test_a_transposed_letter_is_refused_rather_than_shown_as_empty(self):
        self.a_dashboard_in_the_database()
        with self.assertRaises(RuntimeError) as refused:
            create_app(self.config(storage="databse"))
        said = str(refused.exception)
        self.assertIn("databse", said, "the refusal does not name the value")
        self.assertIn("'database'", said)
        self.assertIn("'file'", said)

    def test_an_abbreviation_is_refused_too(self):
        self.a_dashboard_in_the_database()
        with self.assertRaises(RuntimeError):
            create_app(self.config(storage="db"))

    def test_a_trailing_space_still_names_the_database(self):
        """Only the environment path stripped, so 'database ' off a config
        object was a different store from 'database'."""
        app = create_app(self.config(storage="database "))
        self.assertIs(app.dashboard_manager, app.store.dashboards)

    def test_a_key_carrying_nothing_means_the_default(self):
        """An empty value is what Config makes of an empty environment
        variable, and it means "not set" there. Refusing it would turn an
        unset variable in a Kubernetes ConfigMap into a start-up failure."""
        for nothing in ("", None):
            with self.subTest(value=nothing):
                app = create_app(self.config(DASHBOARD_STORAGE=nothing,
                                             SECRET_KEY=f"empty-{nothing}"))
                self.assertIs(app.dashboard_manager, app.store.dashboards)

    def test_the_two_values_that_are_known_still_work(self):
        """A refusal that refuses everything is not an improvement."""
        from wdash.dashboard import DashboardManager

        on_database = create_app(self.config(storage="database"))
        self.assertIs(on_database.dashboard_manager,
                      on_database.store.dashboards)
        self.assertIsInstance(
            create_app(self.config(storage="file",
                                   SECRET_KEY="still-file")).dashboard_manager,
            DashboardManager)


class ATestAppLeavesNoDirectoryBehindTest(_Installation):
    """The TESTING redirect away from the packaged data/ directory.

    It has to happen before the storage branch — both halves need the path,
    the file store to write to it and the start-up check to read it — but
    only the half that WRITES needs a directory to be there. Making one per
    test app left 1,225 of them behind per suite run against the 26 apps
    that use the file store, on a machine already holding a quarter of a
    million.
    """

    def under_its_own_temporary_directory(self, root, **extra):
        """create_app with tempfile pointed somewhere this test owns, and
        the packaged dashboards path, which is what triggers the redirect."""
        previous = tempfile.tempdir
        tempfile.tempdir = root
        try:
            app = create_app(self.config(
                DASHBOARD_STORAGE_FILE=DEFAULT_DASHBOARD_FILE, **extra))
        finally:
            tempfile.tempdir = previous
        return app, sorted(name for name in os.listdir(root)
                           if name.startswith("wdash-test-"))

    def test_a_database_app_makes_no_directory_it_will_never_open(self):
        root = os.path.join(self.directory, "tmp")
        os.makedirs(root)
        app, made = self.under_its_own_temporary_directory(root)
        self.assertIs(app.dashboard_manager, app.store.dashboards)
        self.assertEqual(made, [], "a test app that runs entirely on the "
                                   "database made a directory nothing opens")

    def test_the_check_is_handed_a_path_under_a_directory_that_is_not_there(self):
        """The redirect did not go; only the directory did. What the check
        reads still has to be somewhere other than the repository's data/,
        and it has to read as "no file" — which a path whose directory does
        not exist does."""
        root = os.path.join(self.directory, "tmp")
        os.makedirs(root)
        seen = []
        real = app_module.left_behind_report

        def watched(store, dashboards_file):
            seen.append(dashboards_file)
            return real(store, dashboards_file)

        previous = tempfile.tempdir
        tempfile.tempdir = root
        try:
            with mock.patch.object(app_module, "left_behind_report", watched):
                create_app(self.config(
                    DASHBOARD_STORAGE_FILE=DEFAULT_DASHBOARD_FILE))
        finally:
            tempfile.tempdir = previous

        self.assertEqual(len(seen), 1, seen)
        self.assertTrue(seen[0].startswith(root),
                        f"the check was pointed at {seen[0]}, not at a path "
                        f"of this test run's own")
        self.assertFalse(os.path.exists(os.path.dirname(seen[0])),
                         "a directory was made for a path only ever read")

    def test_a_file_app_still_gets_a_directory_of_its_own_and_can_write(self):
        """The isolation is the point of the redirect and must not go with
        the litter: `save_dashboards` treats a missing directory as the
        failure it is, so the half that writes makes one."""
        root = os.path.join(self.directory, "tmp")
        os.makedirs(root)
        first, _ = self.under_its_own_temporary_directory(
            root, storage="file", SECRET_KEY="one")
        second, made = self.under_its_own_temporary_directory(
            root, storage="file", SECRET_KEY="two")

        self.assertEqual(len(made), 2, made)
        self.assertNotEqual(first.dashboard_manager.storage_path,
                            second.dashboard_manager.storage_path)
        first.dashboard_manager.create_dashboard(
            "One", "", "*", "owner", ["*"])
        self.assertTrue(os.path.exists(first.dashboard_manager.storage_path))
        self.assertEqual(
            [d.name for d in second.dashboard_manager.get_all_dashboards()],
            [], "one test app could see another's dashboards")


class TheCheckReadsTheFilesBeforeTheDatabaseTest(_Installation):
    """Every worker runs the start-up check at every start.

    The ordinary answer — a database installation with no JSON files at all
    — used to cost two full id columns off a store that may hold thousands
    of rows, read before anything looked at whether there was a file to
    compare them against.
    """

    def test_no_files_means_the_id_columns_are_never_scanned(self):
        app = create_app(self.config())
        calls = []
        real = app_module._stored_ids

        def counted(store):
            calls.append(store)
            return real(store)

        with mock.patch.object(app_module, "_stored_ids", counted):
            self.assertIsNone(files_left_behind(app.store, self.dashboards))
            self.assertEqual(calls, [], "the database was read to answer a "
                                        "question about files that are not "
                                        "there")

            self.write_dashboards([self.a_dashboard()])
            self.assertIsNotNone(files_left_behind(app.store, self.dashboards))
            self.assertEqual(len(calls), 1, "and it still reads them when "
                                            "there is something to compare")

    def test_an_empty_file_is_still_nothing_to_compare(self):
        self.write_dashboards([])
        self.write_searches([])
        app = create_app(self.config())
        calls = []
        real = app_module._stored_ids

        def counted(store):
            calls.append(store)
            return real(store)

        with mock.patch.object(app_module, "_stored_ids", counted):
            self.assertIsNone(files_left_behind(app.store, self.dashboards))
        self.assertEqual(calls, [])

    def test_a_file_that_cannot_be_read_is_not_mistaken_for_no_file(self):
        """`[]` and only `[]` is "nothing here". None is a file nobody could
        read, and short-circuiting on falsiness would make it silent — the
        failure looking like emptiness again, one layer down."""
        with open(self.dashboards, "w") as handle:
            handle.write("{not json")
        app = create_app(self.config())
        self.assertIn("cannot be read",
                      files_left_behind(app.store, self.dashboards))


class TheOrderOfTheDashboardsPageTest(_Installation):
    """What an installation sees the moment after it migrates.

    The file store returned insertion order; the database returns newest
    first, so a board that moves in sees its list invert once. That is the
    order this store has always had and it is the wanted one. What was not
    wanted is what a bulk migration does to it: `created_at` is preserved to
    the second, so whole runs of dashboards arrive sharing one timestamp and
    `created_at DESC` alone left their order to the database — the page
    reshuffling between loads for no reason anybody can see.
    """

    def test_records_of_the_same_age_come_back_in_one_fixed_order(self):
        store = Store.open(f"sqlite:///{self.database}")
        moment = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        for identifier in ("c-third", "a-first", "b-second"):
            store.dashboards.create_dashboard(
                name=identifier, description="", query="*",
                created_by="owner", index_patterns=["*"],
                dashboard_id=identifier, created_at=moment)

        self.assertEqual(
            [d.id for d in store.dashboards.get_all_dashboards()],
            ["a-first", "b-second", "c-third"])
        self.assertEqual(
            [d.id for d in store.dashboards.get_user_dashboards("owner")],
            ["a-first", "b-second", "c-third"])

    def test_a_newer_dashboard_is_still_first(self):
        """The tie-break is a tie-break, not the order."""
        store = Store.open(f"sqlite:///{self.database}")
        store.dashboards.create_dashboard(
            name="older", description="", query="*", created_by="owner",
            index_patterns=["*"], dashboard_id="a-older",
            created_at=datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc))
        store.dashboards.create_dashboard(
            name="newer", description="", query="*", created_by="owner",
            index_patterns=["*"], dashboard_id="z-newer",
            created_at=datetime(2026, 2, 15, 10, 0, tzinfo=timezone.utc))
        self.assertEqual(
            [d.id for d in store.dashboards.get_all_dashboards()],
            ["z-newer", "a-older"])


class RunShellScriptTest(unittest.TestCase):
    """`run.sh` made an empty `data/dashboards.json` on every start.

    Harmless while the file store was the default and that file was the
    store. Now it is a decoy: it says `[]` beside a database holding the
    dashboards, and it is the first thing whoever goes looking next finds.

    Nothing under tests/ read this script at all, so the guard that stopped
    it went in unpinned. The block is lifted out and run on its own rather
    than asserted about as text — the whole script installs dependencies and
    starts the application, and a test that only greps cannot tell a guard
    from a comment.
    """

    def setUp(self):
        self.path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "run.sh"))
        with open(self.path) as handle:
            self.script = handle.read()

    def guard(self):
        """The `if` block that creates the file, lifted out of the script."""
        lines = self.script.splitlines()
        opens = [index for index, line in enumerate(lines)
                 if line.startswith("if ") and "dashboards.json" in line]
        self.assertEqual(len(opens), 1,
                         f"{self.path} no longer has exactly one block "
                         f"creating dashboards.json")
        start = opens[0]
        end = next(index for index in range(start, len(lines))
                   if lines[index].strip() == "fi")
        return "\n".join(lines[start:end + 1])

    def after_the_guard(self, **environment):
        """Where data/dashboards.json would be, having run the block."""
        scratch = tempfile.mkdtemp(prefix="wdash-a2-run-sh-")
        self.addCleanup(shutil.rmtree, scratch, True)
        chosen = dict(os.environ)
        chosen.pop("DASHBOARD_STORAGE", None)
        chosen.update(environment)
        done = subprocess.run(["bash", "-c", self.guard()], cwd=scratch,
                              env=chosen, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return os.path.join(scratch, "data", "dashboards.json")

    def test_a_deployment_that_says_nothing_gets_no_empty_dashboards_file(self):
        self.assertFalse(
            os.path.exists(self.after_the_guard()),
            "an empty JSON file was left beside the store that holds the "
            "dashboards")

    def test_a_file_deployment_still_gets_its_empty_dashboards_file(self):
        """DASHBOARD_STORAGE=file behaves exactly as it did, start-up script
        included."""
        made = self.after_the_guard(DASHBOARD_STORAGE="file")
        self.assertTrue(os.path.exists(made))
        with open(made) as handle:
            self.assertEqual(json.load(handle), [])

    def test_a_database_deployment_said_out_loud_gets_none_either(self):
        self.assertFalse(
            os.path.exists(self.after_the_guard(DASHBOARD_STORAGE="database")))

    def test_the_script_reads_dot_env_before_it_decides(self):
        """The setting usually lives in `.env`, not in the shell that runs
        this. Read afterwards it would be unset here whatever the deployment
        configured, and a file deployment would lose its file."""
        self.assertLess(self.script.index("source .env"),
                        self.script.index("DASHBOARD_STORAGE"),
                        "run.sh decides before it has read .env")


class ThePageSaysWhatTheLogSaysTest(_Installation):
    """The half of D1 the start-up warning does not reach.

    D1's stated outcome was that an installation with a dashboards.json
    beside a database store is TOLD "instead of showing an empty list that
    says Create your first". Only the log half was built. Measured on a
    non-migrated installation: the start-up line named both files, and
    /dashboards rendered "Create your first dashboard to get started" with no
    mention of dashboards.json anywhere in the response, while
    /api/saved-searches answered a bare [] — indistinguishable from "you have
    never saved one", which is the project's own "a failure must never look
    like emptiness" applied to the screen rather than to the log.

    Four gunicorn workers each logging a line once, hours before anybody
    looked, is not a substitute for the one place the question gets asked.
    """

    def signed_in(self, app, permissions=("dashboard:view",)):
        from tests.support import grant

        grant(app, "u", permissions=list(permissions))
        client = app.test_client()
        with client.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": "u@x",
                                    "username": "u", "groups": []}
            session["_user_id"] = "1"
        return client

    def page(self, app=None, **extra):
        app = app or create_app(self.config(**extra))
        return self.signed_in(app).get("/dashboards").get_data(as_text=True)

    def test_the_page_names_what_is_in_the_file_rather_than_saying_create_your_first(self):
        self.write_dashboards([self.a_dashboard(), self.a_dashboard("l2", "B")])
        shown = self.page()
        self.assertIn("2 dashboards are in a JSON file that nothing is "
                      "reading", shown)
        self.assertIn("Nothing has been deleted", shown)
        self.assertNotIn("Create your first", shown,
                         "the list is empty, but somebody did create these")

    def test_one_dashboard_is_not_told_about_in_the_plural(self):
        self.write_dashboards([self.a_dashboard()])
        self.assertIn("1 dashboard is in a JSON file that nothing is reading",
                      self.page())

    def test_an_administrator_is_given_the_file_and_the_command(self):
        """The count is for everybody who can see the page; the path and the
        command are for somebody who can act on them."""
        self.write_dashboards([self.a_dashboard()])
        app = create_app(self.config(SECRET_KEY="admin-sees"))
        admin = self.signed_in(app, ("dashboard:view", "system:admin"))
        seen = admin.get("/dashboards").get_data(as_text=True)
        self.assertIn(os.path.abspath(self.dashboards), seen)
        self.assertIn("wdash.store.migrate_cli", seen)

    def test_somebody_who_cannot_run_it_is_not_shown_a_command(self):
        self.write_dashboards([self.a_dashboard()])
        shown = self.page()
        self.assertIn("1 dashboard is in a JSON file", shown)
        self.assertNotIn("wdash.store.migrate_cli", shown)
        self.assertNotIn(os.path.abspath(self.dashboards), shown)

    def test_a_file_that_cannot_be_read_is_not_shown_as_nothing(self):
        with open(self.dashboards, "w") as handle:
            handle.write("{not json")
        self.assertIn("cannot be read", self.page())

    def test_an_installation_with_no_file_is_told_nothing(self):
        shown = self.page()
        self.assertNotIn("nothing is reading", shown)
        self.assertIn("Create your first", shown)

    def test_a_file_installation_is_told_nothing_because_it_is_reading_them(self):
        """DASHBOARD_STORAGE=file behaves exactly as it does today."""
        self.write_dashboards([self.a_dashboard()])
        shown = self.page(storage="file")
        self.assertNotIn("nothing is reading", shown)

    def test_the_page_goes_quiet_the_moment_the_migration_runs(self):
        """Without a restart: the question is asked when the page is
        rendered, and the migration leaves the JSON files where they are."""
        from tests.support import StubLogSource
        from wdash.hub import Hub

        record = self.a_dashboard(name="On the wall")
        record["index_patterns"] = ["*"]
        self.write_dashboards([record])
        app = create_app(self.config())
        hub = Hub()
        hub.add_logs(StubLogSource())
        app.hub = hub
        client = self.signed_in(app)
        self.assertIn("nothing is reading",
                      client.get("/dashboards").get_data(as_text=True))

        from wdash.store.migrate_cli import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = main(["--database-url", f"sqlite:///{self.database}",
                         "--dashboards", self.dashboards])
        self.assertEqual(code, 0, out.getvalue())

        after = client.get("/dashboards").get_data(as_text=True)
        self.assertNotIn("nothing is reading", after)
        self.assertIn("On the wall", after)
        self.assertTrue(os.path.exists(self.dashboards),
                        "the migration is reversible; the file stays")

    def test_a_check_that_throws_costs_the_block_and_not_the_page(self):
        self.write_dashboards([self.a_dashboard()])
        app = create_app(self.config())
        client = self.signed_in(app)
        with mock.patch("wdash.app._stored_ids",
                        side_effect=RuntimeError("no database")):
            answered = client.get("/dashboards")
        self.assertEqual(answered.status_code, 200)
        self.assertNotIn("nothing is reading", answered.get_data(as_text=True))

    def test_the_saved_search_list_is_handed_what_the_api_cannot_say(self):
        """/api/saved-searches answers `[]` for "you have none" and for "they
        are in a file nothing is reading", and the dropdown printed "No saved
        searches yet" over both. The server hands the list its empty state so
        the API's shape does not have to change."""
        from tests.support import StubLogSource
        from wdash.hub import Hub

        self.write_searches([self.a_search(), self.a_search("s2", "Other")])
        app = create_app(self.config())
        hub = Hub()
        hub.add_logs(StubLogSource())
        app.hub = hub
        client = self.signed_in(app, ("logs:read",))

        shown = client.get("/logs").get_data(as_text=True)
        self.assertIn('data-left-behind="2 saved searches are in a JSON file '
                      'that nothing is reading"', shown)
        self.assertEqual(client.get("/api/saved-searches").get_json(), [],
                         "the API's shape is unchanged")
        self.assertNotIn("0 dashboards", shown)

    def test_a_logs_page_with_nothing_left_behind_carries_no_attribute(self):
        self.assertNotIn("data-left-behind", self.logs_page())

    def test_one_file_left_behind_does_not_make_the_other_page_lie(self):
        """The report exists as soon as EITHER file has something in it, and
        each page asks it about its own half. A dashboards file nobody
        migrated must not put "0 saved searches are in a JSON file" on the
        log page, and a searches file must not put a block on the dashboards
        page."""
        self.write_dashboards([self.a_dashboard()])
        self.assertNotIn("data-left-behind", self.logs_page(),
                         "the saved-search list was told about dashboards")

        self.tearDown()
        self.setUp()
        self.write_searches([self.a_search()])
        shown = self.page()
        self.assertNotIn("nothing is reading", shown,
                         "the dashboards page was told about saved searches")
        self.assertIn("Create your first", shown)

    def logs_page(self, **extra):
        from tests.support import StubLogSource
        from wdash.hub import Hub

        app = create_app(self.config(**extra))
        hub = Hub()
        hub.add_logs(StubLogSource())
        app.hub = hub
        client = self.signed_in(app, ("logs:read",))
        return client.get("/logs").get_data(as_text=True)


class OneMessageNamesOnePathTest(_Installation):
    """The sentence and the command named different files.

    The sentence used `os.path.abspath`; the command handed back the raw
    DASHBOARD_STORAGE_FILE, which is `data/dashboards.json` in the packaged
    default. So the message told the operator about /srv/wdash/data/…  and
    then gave them a command that resolves to that file only if they happen
    to run it from the application's working directory. It failed safe when
    they did not — the migration refuses a path it cannot find — but a
    message that names one file should name it once.
    """

    def relative(self):
        """The warning, asked about a relative path from inside the data
        directory, which is the packaged shape."""
        app = create_app(self.config())
        here = os.getcwd()
        os.chdir(self.directory)
        try:
            return files_left_behind(app.store, "dashboards.json")
        finally:
            os.chdir(here)

    def test_the_command_names_the_same_file_the_sentence_does(self):
        self.write_dashboards([self.a_dashboard()])
        said = self.relative()
        command = said.split("migrate_cli", 1)[1].splitlines()[0].split()
        named = command[command.index("--dashboards") + 1]
        self.assertTrue(os.path.isabs(named), said)
        self.assertIn(named, said.split("holds")[0],
                      "the sentence and the command name different files")

    def test_the_searches_file_is_absolute_too(self):
        self.write_dashboards([self.a_dashboard()])
        self.write_searches([self.a_search()])
        said = self.relative()
        command = said.split("migrate_cli", 1)[1].splitlines()[0].split()
        named = command[command.index("--saved-searches") + 1]
        self.assertTrue(os.path.isabs(named), said)
        self.assertIn(named, said)

    def test_it_still_runs_from_somewhere_else_entirely(self):
        """Which is the point: the same command, run from a directory that
        has no data/ in it at all."""
        from wdash.store.migrate_cli import main

        self.write_dashboards([self.a_dashboard(name="On the wall")])
        elsewhere = tempfile.mkdtemp(prefix="wdash-a2-elsewhere-")
        self.addCleanup(shutil.rmtree, elsewhere, True)
        said = self.relative()
        arguments = said.split("migrate_cli", 1)[1].splitlines()[0].split()

        here = os.getcwd()
        os.chdir(elsewhere)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                code = main(["--database-url", f"sqlite:///{self.database}"]
                            + arguments)
        finally:
            os.chdir(here)
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("1 moved", out.getvalue())


class TheMigrationCarriesASavedSearchSourceTest(_Installation):
    """`migrate_saved_searches` dropped `source` while `migrate_dashboards`
    carried it, with the comment two functions above explaining exactly why
    it must. The column, the parameter and the reason were all there and
    nothing was passed.

    Nothing is lost today, because no writer sets a source on a saved search
    — which makes it a trap rather than a live defect, and "every field
    arrives" true only because the field is unreachable. It is in the one
    command every upgrading installation is now sent through.
    """

    def test_a_saved_search_that_names_a_source_keeps_it(self):
        from wdash.store.migrate_cli import main

        record = self.a_search()
        record["source"] = "secondary"
        self.write_searches([record, self.a_search("s2", "No source")])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = main(["--database-url", f"sqlite:///{self.database}",
                         "--dashboards", self.dashboards,
                         "--allow-missing-dashboards",
                         "--saved-searches", self.searches])
        self.assertEqual(code, 0, out.getvalue())

        store = Store.open(f"sqlite:///{self.database}")
        self.assertEqual(store.saved_searches.get("search-1").source,
                         "secondary")
        self.assertIsNone(store.saved_searches.get("s2").source,
                          "a record that named none must not invent one")


class BothStoresSayWhichOneAnsweredTest(_Installation):
    """`get_stats()` answers a different shape from each store, and both
    /api/debug endpoints hand the dict straight to `jsonify`.

    So moving the default silently took four keys off an installation that
    set nothing — storage_path, file_exists, loaded_signature,
    disk_signature, should_reload — with nothing left in the response to say
    which store had answered. The file keys cannot be invented for a database
    without lying, so the agreement is the honest intersection plus
    `backend`; the file store keeps everything it had.
    """

    AGREED = ("backend", "total_dashboards")

    def stats(self, storage):
        from tests.support import grant

        app = create_app(self.config(storage=storage,
                                     SECRET_KEY=f"stats-{storage}"))
        grant(app, "u", permissions=["system:admin"])
        client = app.test_client()
        with client.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": "u@x",
                                    "username": "u", "groups": []}
            session["_user_id"] = "1"
        return (client.get("/api/debug/dashboard-manager").get_json(),
                client.post("/api/debug/refresh-dashboards").get_json())

    def test_every_store_answers_the_agreed_keys_from_both_endpoints(self):
        from wdash.store.objects import DASHBOARD_STATS

        self.assertEqual(tuple(DASHBOARD_STATS), self.AGREED)
        for storage, expected in (("database", "database"), ("file", "file")):
            with self.subTest(storage=storage):
                debug, refreshed = self.stats(storage)
                for answer in (debug["manager_stats"], refreshed["stats"]):
                    for key in DASHBOARD_STATS:
                        self.assertIn(key, answer, f"{storage}: {key}")
                    self.assertEqual(answer["backend"], expected)
                    self.assertEqual(answer["total_dashboards"], 0)

    def test_a_file_installation_keeps_every_key_it_had(self):
        """Taking them away to make the shapes match would break the
        installations that are scripted against them."""
        debug, refreshed = self.stats("file")
        for answer in (debug["manager_stats"], refreshed["stats"]):
            for key in ("storage_path", "file_exists", "loaded_signature",
                        "disk_signature", "should_reload"):
                self.assertIn(key, answer, key)


if __name__ == "__main__":      # pragma: no cover - the suite runs this
    unittest.main()
