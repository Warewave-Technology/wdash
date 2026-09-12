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
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app, files_left_behind  # noqa: E402
from wdash.config import Config  # noqa: E402
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
        client.post("/setup", data={"username": "owner",
                                    "password": PASSWORD,
                                    "confirm": PASSWORD})
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
        client.post("/setup", data={"username": "owner", "password": PASSWORD,
                                    "confirm": PASSWORD})
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
            client.post("/setup", data={"username": "owner",
                                        "password": PASSWORD,
                                        "confirm": PASSWORD})
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


if __name__ == "__main__":      # pragma: no cover - the suite runs this
    unittest.main()
