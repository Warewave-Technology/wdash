"""
Saved searches, in whichever store is configured.

They stayed on the JSON file when dashboards moved to the database, which made
the migration a half-truth: it copied searches into the database, printed
"Done", and nothing ever read them from there. The database copy was dead
weight and the file remained the real one — so a deployment that migrated,
switched over and then lost the file would have lost searches it believed were
safe.

Both stores are exercised by the same tests, because "it works on one of them"
is how the two drifted apart in the first place.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

PASSWORD = "correct-horse-battery"


class SavedSearchTestCase(unittest.TestCase):
    STORAGE = "file"

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.database = os.path.join(self.directory, "wdash.db")
        self.storage = os.path.join(self.directory, "dashboards.json")
        database, storage, backend = self.database, self.storage, self.STORAGE

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "searches"
            DATABASE_URL = f"sqlite:///{database}"
            DASHBOARD_STORAGE_FILE = storage
            DASHBOARD_STORAGE = backend
            ENCRYPTION_KEY = SecretBox.generate_key()
            OIDC_CLIENT_ID = None
            ELASTICSEARCH_URL = ""

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.client.post("/setup", data={"username": "owner",
                                         "password": PASSWORD,
                                         "confirm": PASSWORD})

    def tearDown(self):
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def create(self, name="mine", query="level:ERROR", client=None):
        return (client or self.client).post(
            "/api/saved-searches",
            json={"name": name, "query": query, "time_range": "24h"})

    def listed(self, client=None):
        return (client or self.client).get("/api/saved-searches").get_json()

    def second_user(self):
        """A signed-in client for a different account."""
        self.app.store.users.create("colleague", PASSWORD, role="admin")
        mapping = dict(self.app.store.settings.get("rbac.user_roles") or {})
        mapping["colleague"] = "admin"
        self.app.store.settings.set("rbac.user_roles", mapping)
        self.app.store.rbac.invalidate()
        client = self.app.test_client()
        client.post("/auth/login",
                    data={"username": "colleague", "password": PASSWORD})
        return client


class BehaviourTest(SavedSearchTestCase):
    def test_a_search_round_trips(self):
        self.assertEqual(self.create().status_code, 201)
        names = [entry["name"] for entry in self.listed()]
        self.assertEqual(names, ["mine"])

    def test_a_search_belongs_to_the_person_who_saved_it(self):
        """A saved search carries somebody's working query. It is not a
        broadcast."""
        self.create(name="private-to-owner")
        self.assertEqual(self.listed(self.second_user()), [])

    def test_deleting_somebody_elses_search_is_refused(self):
        search_id = self.create().get_json()["id"]
        response = self.second_user().delete(f"/api/saved-searches/{search_id}")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(len(self.listed()), 1, "it was deleted anyway")

    def test_deleting_your_own_search_works(self):
        search_id = self.create().get_json()["id"]
        self.assertEqual(
            self.client.delete(f"/api/saved-searches/{search_id}").status_code,
            200)
        self.assertEqual(self.listed(), [])

    def test_deleting_something_that_is_not_there(self):
        self.assertEqual(
            self.client.delete("/api/saved-searches/nope").status_code, 404)

    def test_a_search_needs_a_name_and_a_query(self):
        self.assertEqual(
            self.client.post("/api/saved-searches",
                             json={"name": "no query"}).status_code, 400)

    def test_reading_needs_the_log_permission(self):
        """A saved search holds a query, and everything else that touches log
        queries is gated."""
        self.app.store.roles.upsert("admin", permissions=["dashboard:view"],
                                    containers=["*"], trace_containers=["*"])
        self.app.store.rbac.invalidate()
        self.assertEqual(
            self.client.get("/api/saved-searches").status_code, 403)


class DatabaseStoreTest(BehaviourTest):
    """The same behaviour, backed by the metadata store."""

    STORAGE = "database"

    def test_searches_reach_the_database_rather_than_the_file(self):
        """The half-truth this module exists for: migrating wrote rows the
        application then ignored."""
        self.create(name="in-the-database")

        from sqlalchemy import select
        from wdash.store.schema import saved_searches
        with self.app.store.engine.connect() as connection:
            names = [row[0] for row in
                     connection.execute(select(saved_searches.c.name))]
        self.assertEqual(names, ["in-the-database"])

        path = os.path.join(self.directory, "saved_searches.json")
        self.assertFalse(os.path.exists(path),
                         "the file store was written to as well")

    def test_a_migrated_search_is_visible(self):
        """What somebody actually does: run the migration, switch over, and
        expect their searches to still be there."""
        self.app.store.saved_searches.create(
            name="migrated", query="*", time_range="1h", created_by="owner")
        self.assertIn("migrated", [entry["name"] for entry in self.listed()])


class FileStoreTest(SavedSearchTestCase):
    """The default, until a deployment has run the migration."""

    STORAGE = "file"

    def test_searches_reach_the_file(self):
        self.create(name="in-the-file")
        path = os.path.join(self.directory, "saved_searches.json")
        self.assertTrue(os.path.exists(path))
        with open(path) as handle:
            self.assertEqual([row["name"] for row in json.load(handle)],
                             ["in-the-file"])

    def test_the_database_is_left_alone(self):
        """Writing to both would make "which one is real" unanswerable."""
        self.create()
        from sqlalchemy import select
        from wdash.store.schema import saved_searches
        with self.app.store.engine.connect() as connection:
            self.assertEqual(
                connection.execute(select(saved_searches.c.name)).all(), [])


if __name__ == "__main__":
    unittest.main()
