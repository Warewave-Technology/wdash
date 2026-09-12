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
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

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
        self.secret = support.set_up(
            self.client, username="owner", password=PASSWORD)
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
        # Its first sign-in, so this enrols an authenticator on the way
        # through — which is what a local account's first sign-in does.
        support.sign_in(client, "colleague", PASSWORD)
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


class UnreadableFileTest(SavedSearchTestCase):
    """A file that cannot be read must not read as "you have none".

    Measured before the fix, on a file holding alice's, bob's and one entry
    written before `time_range` existed: GET answered 200 [], POST answered
    201, and the file then held one row — everybody else's searches were
    gone. Over a file truncated mid-JSON, the same.
    """

    STORAGE = "file"

    @property
    def path(self):
        return os.path.join(self.directory, "saved_searches.json")

    def write(self, text):
        with open(self.path, "w") as handle:
            handle.write(text)

    def rows(self):
        with open(self.path) as handle:
            return json.load(handle)

    def other_peoples(self):
        return [{"id": "a1", "name": "alice's", "query": "*",
                 "time_range": "1h", "created_by": "alice"},
                {"id": "b1", "name": "bob's", "query": "*",
                 "time_range": "1h", "created_by": "bob"}]

    def test_a_truncated_file_is_not_an_empty_list(self):
        self.write('[{"id": "a1", "name": ')
        reply = self.client.get("/api/saved-searches")
        self.assertEqual(reply.status_code, 503)
        self.assertEqual(reply.get_json()["error_type"],
                         "saved_searches_unavailable")

    def test_a_create_over_a_truncated_file_does_not_overwrite_it(self):
        self.write('[{"id": "a1", "name": ')
        reply = self.create(name="mine")
        self.assertEqual(reply.status_code, 503)
        with open(self.path) as handle:
            self.assertEqual(handle.read(), '[{"id": "a1", "name": ')

    def test_a_delete_over_a_truncated_file_does_not_overwrite_it(self):
        self.write('[{"id": "a1", "name": ')
        reply = self.client.delete("/api/saved-searches/a1")
        self.assertEqual(reply.status_code, 503)
        with open(self.path) as handle:
            self.assertEqual(handle.read(), '[{"id": "a1", "name": ')

    def test_one_entry_from_before_time_range_does_not_lose_the_rest(self):
        """The legacy row that emptied three people's lists.

        `time_range` arrived after the first saved searches were written, so
        an entry from before it has none. The parse ran over the whole file
        inside one try, so that one KeyError returned `[]` — and the next
        create wrote `[]` plus one row over everybody's.
        """
        rows = self.other_peoples()
        rows.append({"id": "c1", "name": "legacy", "query": "level:ERROR",
                     "created_by": "owner"})
        self.write(json.dumps(rows))

        self.assertEqual(self.create(name="mine").status_code, 201)
        self.assertEqual(sorted(row["name"] for row in self.rows()),
                         ["alice's", "bob's", "legacy", "mine"])
        # And its owner still sees it, with the window the search form
        # offers when nobody has chosen one.
        listed = {search["name"]: search for search in self.listed()}
        self.assertEqual(sorted(listed), ["legacy", "mine"])
        self.assertEqual(listed["legacy"]["time_range"], "1h")

    def test_a_row_that_cannot_be_read_is_skipped_not_dropped(self):
        """Skipping it keeps the list usable; leaving it in the file keeps it
        recoverable once whatever wrote it is fixed."""
        rows = self.other_peoples()
        rows.append({"nonsense": True})
        self.write(json.dumps(rows))

        self.assertEqual(self.listed(), [])          # none are the owner's
        self.assertEqual(self.create(name="mine").status_code, 201)
        self.assertIn({"nonsense": True}, self.rows())
        self.assertEqual(len(self.rows()), 4)

    def test_a_row_that_is_not_a_search_at_all_is_skipped_by_every_verb(self):
        """A row that is not even an object, which is what half a rewrite or
        a hand-edit leaves behind.

        Listing skips it and creating steps over it, because both go through
        the loader. Deleting did neither: it filtered the raw rows with
        `row.get('id')` and met a string, so DELETE was an AttributeError and
        a 500 — the one verb that could not live with a file the other two
        had been taught to read.
        """
        rows = self.other_peoples()
        rows.append("junk-row")
        rows.append({"id": "mine-1", "name": "mine", "query": "*",
                     "time_range": "1h", "created_by": "owner"})
        self.write(json.dumps(rows))

        self.assertEqual([search["name"] for search in self.listed()], ["mine"])

        missing = self.client.delete("/api/saved-searches/no-such-id")
        self.assertEqual(missing.status_code, 404, missing.get_data(as_text=True))

        reply = self.client.delete("/api/saved-searches/mine-1")
        self.assertEqual(reply.status_code, 200, reply.get_data(as_text=True))
        # Deleted, and the row nobody could read is still there to be
        # recovered rather than swept up with it.
        self.assertIn("junk-row", self.rows())
        self.assertEqual(sorted(row["name"] for row in self.rows()
                                if isinstance(row, dict)),
                         ["alice's", "bob's"])

    def signed_in(self):
        """Another client for the same account — another worker's request."""
        client = self.app.test_client()
        support.sign_in(client, "owner", PASSWORD, self.secret, app=self.app)
        return client

    def test_saves_made_at_the_same_moment_all_survive(self):
        """Read-modify-write over one file with nothing held across it: each
        worker reads the list, adds one row, and writes the whole thing back,
        so a save that lands between another's read and write is erased."""
        workers, each = 6, 8
        clients = [self.signed_in() for _ in range(workers)]
        started = threading.Barrier(workers)
        replies = []

        def save(client, index):
            started.wait()
            for step in range(each):
                replies.append(
                    self.create(name=f"w{index}-{step}", client=client).status_code)

        threads = [threading.Thread(target=save, args=(client, index))
                   for index, client in enumerate(clients)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)

        self.assertEqual(set(replies), {201})
        self.assertEqual(len(self.rows()), workers * each,
                         f"{workers * each - len(self.rows())} saved searches "
                         f"were written and then lost")

    def test_a_reader_never_sees_a_half_written_file(self):
        """'w' truncates before it writes, so a reader landing in the middle
        of a save saw an empty or partial file."""
        self.create(name="first")
        seen = []
        stop = threading.Event()

        def read():
            while not stop.is_set():
                try:
                    with open(self.path) as handle:
                        seen.append(len(json.load(handle)))
                except FileNotFoundError:
                    pass
                except ValueError:
                    seen.append("half-written")

        reader = threading.Thread(target=read)
        reader.start()
        try:
            for index in range(40):
                self.create(name=f"s{index}")
        finally:
            stop.set()
            reader.join(20)

        self.assertNotIn("half-written", seen)
        self.assertFalse([count for count in seen if count == 0],
                         "a reader saw an empty file mid-save")


if __name__ == "__main__":
    unittest.main()
