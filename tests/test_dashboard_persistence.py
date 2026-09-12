"""
Dashboard creation, editing and storage.

The theme is the same one that runs through the hub: a failure must never be
reported as a success, and a mistake must surface where it was made.

Three faults these tests lock down, all found by exercising the forms:

  * a save that failed still flashed "created successfully", so the dashboard
    was silently gone
  * a malformed query saved cleanly and only failed later, on every view
  * a name of nothing but spaces passed the `if not name` check
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.dashboard.dashboard_manager import (  # noqa: E402
    DashboardManager, DashboardStorageError,
)


class FakeES:
    def ping(self):
        return True

    @property
    def cat(self):
        class Cat:
            def indices(self, **kw):
                return [{"index": "app-logs-000001", "creation.date": "100"}]
        return Cat()

    @property
    def indices(self):
        class Indices:
            def get_mapping(self, index=None, **kw):
                return {"app-logs-000001": {"mappings": {"properties": {
                    "level": {"type": "keyword"}}}}}
        return Indices()

    def search(self, **kw):
        return {"took": 1, "hits": {"total": {"value": 0}, "hits": []},
                "aggregations": {}}


class RouteTest(unittest.TestCase):
    #: Named rather than inherited from the default. These are the JSON
    #: file store's own tests — two of them reach for `storage_path` and
    #: break the write — and they ran on the default only because the
    #: default used to be 'file'. Said here, they go on saying what they
    #: always said: an installation that sets DASHBOARD_STORAGE=file gets
    #: exactly the behaviour it got before the default moved.
    #:
    #: `DatabaseRouteTest` below runs the same route behaviours against the
    #: store people now get without setting anything.
    STORAGE = "file"

    def setUp(self):
        handle, self.storage = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        with open(self.storage, "w") as file:
            file.write("[]")
        backend = self.STORAGE

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "dash-persistence"
            DASHBOARD_STORAGE_FILE = self.storage
            DASHBOARD_STORAGE = backend

        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource

        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(FakeES()))
        self.app.hub = hub
        self.manager = self.app.dashboard_manager
        self.client = self.app.test_client()
        self.login()

    def tearDown(self):
        if os.path.exists(self.storage):
            os.unlink(self.storage)

    def login(self, permissions=("dashboard:view", "dashboard:create",
                                 "dashboard:edit", "dashboard:delete")):
        from tests.support import grant
        grant(self.app, "u", permissions)
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": list(permissions),
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def create(self, **overrides):
        form = {"name": "Test", "query": "*", "description": "",
                "index_patterns": ["*"]}
        form.update(overrides)
        return self.client.post("/dashboard/create", data=form,
                                follow_redirects=True)

    def names(self):
        self.manager.refresh_cache()
        return [d.name for d in self.manager.get_all_dashboards()]

    # ---------- the query is checked before it is stored ----------

    def test_a_malformed_query_is_refused_at_save_time(self):
        """Otherwise the mistake surfaces on every later view, not here."""
        response = self.create(name="broken", query='level:"unterminated')
        self.assertNotIn("broken", self.names())
        self.assertIn(b"cannot be parsed", response.data)

    def test_a_valid_query_is_accepted(self):
        self.create(name="fine", query='level:ERROR AND service:"api"')
        self.assertIn("fine", self.names())

    def test_a_stored_dashboard_can_always_be_opened(self):
        """The point of validating early: no dashboard that 400s on view."""
        self.create(name="fine", query="level:ERROR")
        self.manager.refresh_cache()
        dashboard = next(d for d in self.manager.get_all_dashboards()
                         if d.name == "fine")
        response = self.client.get(f"/api/dashboard/{dashboard.id}/data")
        self.assertNotEqual(response.status_code, 400,
                            "a saved dashboard must not fail to render")

    # ---------- whitespace ----------

    def test_a_name_of_only_spaces_is_refused(self):
        response = self.create(name="   ")
        self.assertEqual(self.names(), [])
        self.assertIn(b"name is required", response.data)

    def test_a_query_of_only_spaces_is_refused(self):
        response = self.create(query="   ")
        self.assertEqual(self.names(), [])
        self.assertIn(b"query is required", response.data)

    def test_surrounding_whitespace_is_trimmed(self):
        self.create(name="  Padded  ", query="  *  ")
        self.assertIn("Padded", self.names())

    # ---------- storage failure ----------

    def test_a_failed_save_is_not_reported_as_success(self):
        """The worst failure mode on this page: told it worked, nothing saved."""
        self.manager.storage_path = "/nonexistent-directory/dashboards.json"
        try:
            response = self.create(name="lost")
        finally:
            self.manager.storage_path = self.storage

        self.assertNotIn(b"created successfully", response.data)
        self.assertIn(b"NOT been created", response.data)
        self.assertNotIn("lost", self.names())

    def test_a_failed_edit_says_the_change_was_not_applied(self):
        self.create(name="original")
        self.manager.refresh_cache()
        dashboard = next(d for d in self.manager.get_all_dashboards())

        self.manager.storage_path = "/nonexistent-directory/dashboards.json"
        try:
            response = self.client.post(
                f"/dashboard/{dashboard.id}/edit",
                data={"name": "renamed", "query": "*", "description": "",
                      "index_patterns": ["*"]}, follow_redirects=True)
        finally:
            self.manager.storage_path = self.storage

        self.assertIn(b"NOT applied", response.data)
        self.assertIn("original", self.names())

    def test_deleting_something_already_gone_is_a_404_not_a_success(self):
        response = self.client.post("/dashboard/does-not-exist/delete")
        self.assertEqual(response.status_code, 404)


class PanelFormTest(RouteTest):
    """Panels travel as JSON in one hidden field and are re-validated here."""

    def test_panels_can_be_customised_through_the_form(self):
        self.create(name="custom", panels=json.dumps([
            {"type": "terms", "title": "Hosts", "field": "host", "size": 3,
             "width": 6}]))
        self.manager.refresh_cache()
        dashboard = next(d for d in self.manager.get_all_dashboards())
        panels = dashboard.get_panels()
        self.assertEqual(len(panels), 1)
        self.assertEqual(panels[0]["field"], "host")

    def test_a_panel_naming_an_unusable_field_is_refused(self):
        response = self.create(name="bad", panels=json.dumps([
            {"type": "terms", "field": "body"}]))
        self.assertEqual(self.names(), [])
        self.assertIn(b"cannot group by", response.data)

    def test_unreadable_panel_json_is_refused(self):
        response = self.create(name="bad", panels="{not json")
        self.assertEqual(self.names(), [])
        self.assertIn(b"could not be read", response.data)

    def test_omitting_panels_leaves_the_dashboard_on_the_defaults(self):
        """Not the same as storing today's defaults, which would freeze them."""
        self.create(name="plain")
        self.manager.refresh_cache()
        dashboard = next(d for d in self.manager.get_all_dashboards())
        self.assertIsNone(dashboard.panels)
        self.assertEqual(len(dashboard.get_panels()), 3)

    def test_the_editor_page_carries_the_current_panels(self):
        self.create(name="custom", panels=json.dumps([
            {"type": "terms", "title": "Hosts", "field": "host", "width": 6}]))
        self.manager.refresh_cache()
        dashboard = next(d for d in self.manager.get_all_dashboards())

        response = self.client.get(f"/dashboard/{dashboard.id}/edit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"panelList", response.data)
        self.assertIn(b"Hosts", response.data)


class DatabaseRouteTest(RouteTest):
    """The same routes against the store an installation now gets by default.

    Everything RouteTest checks — the query validated before it is stored, a
    name of spaces refused, whitespace trimmed, panels re-validated — used to
    be checked against the JSON file only, because that was the default.
    Nothing here is new behaviour; it is the same behaviour, asked of the
    store people actually run.
    """

    STORAGE = "database"

    def _breaking_the_store(self):
        """Make the next write fail the way a database in trouble fails.

        The file store's version of this is pointing `storage_path` at a
        directory that is not there. The repository has no path to break, so
        the write itself is made to raise the error it raises — the route
        must report a save that did not happen as a save that did not
        happen, whichever store refused it.
        """
        from unittest import mock

        from wdash.dashboard.dashboard_manager import DashboardStorageError

        def refuse(*args, **kwargs):
            raise DashboardStorageError("no connection to the database")

        return mock.patch.object(self.manager, "create_dashboard", refuse), \
            mock.patch.object(self.manager, "update_dashboard", refuse)

    def test_a_failed_save_is_not_reported_as_success(self):
        create, _ = self._breaking_the_store()
        with create:
            response = self.create(name="lost")
        self.assertNotIn(b"created successfully", response.data)
        self.assertIn(b"NOT been created", response.data)
        self.assertNotIn("lost", self.names())

    def test_a_failed_edit_says_the_change_was_not_applied(self):
        self.create(name="original")
        dashboard = next(d for d in self.manager.get_all_dashboards())
        _, update = self._breaking_the_store()
        with update:
            response = self.client.post(
                f"/dashboard/{dashboard.id}/edit",
                data={"name": "renamed", "query": "*", "description": "",
                      "index_patterns": ["*"]}, follow_redirects=True)
        self.assertIn(b"NOT applied", response.data)
        self.assertIn("original", self.names())


class DatabasePanelFormTest(DatabaseRouteTest, PanelFormTest):
    """Panels through the form, into the database store.

    `DatabaseRouteTest` first, so the two storage-failure tests are the ones
    that break a database write rather than the ones that break a file path.
    """

    STORAGE = "database"


class StorageTest(unittest.TestCase):
    """The manager on its own, without Flask."""

    def setUp(self):
        # A directory of its own, not the shared system temp.
        #
        # `test_a_failed_save_leaves_no_temporary_file_behind` lists the
        # directory before and after and asserts nothing was left. Pointed at
        # /tmp that is an assertion about every other process on the machine,
        # and it failed once in a full run and passed on its own — which reads
        # as flakiness and is really a test asking the wrong question.
        self.directory = tempfile.mkdtemp(prefix="wdash-dashboards-")
        self.storage = os.path.join(self.directory, "dashboards.json")
        with open(self.storage, "w") as file:
            file.write("[]")
        self.manager = DashboardManager(self.storage)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_save_raises_rather_than_swallowing(self):
        self.manager.storage_path = "/nonexistent-directory/dashboards.json"
        with self.assertRaises(DashboardStorageError):
            self.manager.save_dashboards()

    def test_a_failed_save_leaves_no_temporary_file_behind(self):
        directory = os.path.dirname(self.storage)
        before = set(os.listdir(directory))
        self.manager.storage_path = os.path.join(directory, "sub", "dir", "x.json")
        with self.assertRaises(DashboardStorageError):
            self.manager.save_dashboards()
        self.assertEqual(set(os.listdir(directory)) - before, set())

    def test_an_external_write_is_picked_up(self):
        """Another worker's change must become visible, not be cached forever."""
        self.manager.create_dashboard("mine", "", "*", "u", ["*"])
        self.assertEqual(len(self.manager.get_all_dashboards()), 1)

        with open(self.storage) as file:
            data = json.load(file)
        data.append(dict(data[0], id="second-dashboard", name="theirs"))
        with open(self.storage, "w") as file:
            json.dump(data, file)

        names = {d.name for d in self.manager.get_all_dashboards()}
        self.assertIn("theirs", names,
                      "a change written by another process was never seen")

    def test_a_same_second_external_write_is_still_seen(self):
        """A wall-clock 'is it newer' test misses a write in the same tick.

        The signature only has to differ, so an identical timestamp with
        different content still counts as a change.
        """
        self.manager.create_dashboard("first", "", "*", "u", ["*"])
        signature = self.manager._signature()

        with open(self.storage) as file:
            data = json.load(file)
        data.append(dict(data[0], id="second-dashboard", name="second"))
        with open(self.storage, "w") as file:
            json.dump(data, file)
        # Force the timestamp back to what it was: only the size now differs.
        os.utime(self.storage, ns=(signature[0], signature[0]))

        self.assertTrue(self.manager._should_reload())
        self.assertIn("second",
                      {d.name for d in self.manager.get_all_dashboards()})

    def test_a_corrupt_file_does_not_wipe_the_loaded_dashboards(self):
        """Half-written JSON must not read as 'your dashboards are gone'."""
        self.manager.create_dashboard("keep me", "", "*", "u", ["*"])
        with open(self.storage, "w") as file:
            file.write('[{"id": "x", "name": ')      # truncated

        self.assertEqual([d.name for d in self.manager.get_all_dashboards()],
                         ["keep me"])


class FailedWriteTest(unittest.TestCase):
    """What memory holds after a save that raised.

    The routes say "has NOT been created", "your changes were NOT applied"
    and "it is still there". Every read in this worker said the opposite,
    because the mutation happened before the write and nothing put it back —
    and `_loaded_signature` still matched the untouched file, so no read ever
    reloaded. The existing tests could not see it: they all call
    `refresh_cache()` first, which reads the file the save never reached.
    """

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="wdash-failed-write-")
        self.storage = os.path.join(self.directory, "dashboards.json")
        with open(self.storage, "w") as file:
            file.write("[]")
        self.manager = DashboardManager(self.storage)
        self.manager.create_dashboard("keep", "", "*", "u", ["*"])
        self.manager.create_dashboard("to-delete", "", "*", "u", ["*"])
        self.ids = {d.name: d.id for d in self.manager.get_all_dashboards()}

    def tearDown(self):
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def unwritable(self):
        """Point the manager at a directory that does not exist.

        The file keeps its contents, which is the case that matters: the disk
        still holds the dashboards the user was told they still have.
        """
        self.manager.storage_path = os.path.join(
            self.directory, "gone", "dashboards.json")

    def names(self):
        """Without refresh_cache: what this worker serves, right now."""
        return sorted(d.name for d in self.manager.dashboards.values())

    def on_disk(self):
        with open(self.storage) as file:
            return sorted(d["name"] for d in json.load(file))

    def test_a_create_that_could_not_be_written_is_not_in_memory_either(self):
        self.unwritable()
        with self.assertRaises(DashboardStorageError):
            self.manager.create_dashboard("phantom", "", "*", "u", ["*"])
        self.assertEqual(self.names(), ["keep", "to-delete"])
        self.assertEqual(self.on_disk(), ["keep", "to-delete"])

    def test_an_edit_that_could_not_be_written_is_not_applied_in_memory(self):
        self.unwritable()
        with self.assertRaises(DashboardStorageError):
            self.manager.update_dashboard(self.ids["keep"],
                                          name="edit-not-applied")
        self.assertEqual(self.names(), ["keep", "to-delete"])
        self.assertEqual(self.on_disk(), ["keep", "to-delete"])

    def test_a_delete_that_could_not_be_written_leaves_it_there(self):
        self.unwritable()
        with self.assertRaises(DashboardStorageError):
            self.manager.delete_dashboard(self.ids["to-delete"])
        self.assertEqual(self.names(), ["keep", "to-delete"])
        self.assertEqual(self.on_disk(), ["keep", "to-delete"])

    def test_the_next_successful_save_does_not_carry_the_failures_out(self):
        """The part that reaches the disk: three refusals, then one create,
        and the file held all four."""
        self.unwritable()
        for attempt in (
                lambda: self.manager.create_dashboard("phantom", "", "*", "u", ["*"]),
                lambda: self.manager.update_dashboard(self.ids["keep"],
                                                      name="edit-not-applied"),
                lambda: self.manager.delete_dashboard(self.ids["to-delete"])):
            with self.assertRaises(DashboardStorageError):
                attempt()

        self.manager.storage_path = self.storage
        self.manager.create_dashboard("next", "", "*", "u", ["*"])
        self.assertEqual(self.on_disk(), ["keep", "next", "to-delete"])

        fresh = DashboardManager(self.storage)
        self.assertEqual(sorted(d.name for d in fresh.get_all_dashboards()),
                         ["keep", "next", "to-delete"])


class IsolationTest(unittest.TestCase):
    """A test run must not write into the repository's data directory.

    It did. `test_dashboard_visibility` never set DASHBOARD_STORAGE_FILE, so
    every run appended its fixtures to `data/dashboards.json` — 3,172
    dashboards accumulated there, and the dashboards page rendered all of them
    into a seven-megabyte response. The metadata store already had this
    protection; the file store did not.
    """

    def test_a_testing_app_does_not_use_the_packaged_dashboard_file(self):
        from wdash.config import Config, DEFAULT_DASHBOARD_FILE

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "isolation"
            DATABASE_URL = "sqlite:///:memory:"
            ELASTICSEARCH_URL = ""
            # The isolation being checked belongs to the file store, and
            # the file store is no longer what an app gets by not saying.
            DASHBOARD_STORAGE = "file"

        app = create_app(TestConfig)
        path = app.dashboard_manager.storage_path
        self.assertNotEqual(str(path), DEFAULT_DASHBOARD_FILE)
        self.assertNotIn("data/dashboards.json", str(path))

    def test_an_explicitly_configured_path_is_still_honoured(self):
        """The isolation compares against the literal default, so a test that
        deliberately points somewhere is not redirected out from under it."""
        from wdash.config import Config

        handle, chosen = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        try:
            class TestConfig(Config):
                TESTING = True
                SECRET_KEY = "isolation"
                DATABASE_URL = "sqlite:///:memory:"
                ELASTICSEARCH_URL = ""
                DASHBOARD_STORAGE = "file"
                DASHBOARD_STORAGE_FILE = chosen

            app = create_app(TestConfig)
            self.assertEqual(app.dashboard_manager.storage_path, chosen)
        finally:
            os.unlink(chosen)
