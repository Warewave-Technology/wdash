"""
The dashboard list, when there are a lot of them.

This page rendered every dashboard it could find. With three thousand of them
in the lab — leaked there by a test that wrote into the repository's data
directory — the response was seven megabytes. An append-only list of anything
grows, and "render all of it" is a way to take the process down from a URL.

Paged after the visibility filter, so the numbers describe what THIS person
can see. Pushing the filter into the store would give three backends three
expressions of one rule, which is the trap this codebase has already fallen
into once with index patterns.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

from wdash.api.dashboard_routes import DASHBOARDS_PER_PAGE  # noqa: E402
from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

PASSWORD = "correct-horse-battery"


class PagingTestCase(unittest.TestCase):
    #: Which store to exercise. Paging is the same either way; the concurrent
    #: edit tests below need the one that tracks revisions.
    STORAGE = "file"

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        handle, self.storage = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        os.unlink(self.storage)
        database, storage, backend = self.database, self.storage, self.STORAGE

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "paging"
            DATABASE_URL = f"sqlite:///{database}"
            DASHBOARD_STORAGE_FILE = storage
            DASHBOARD_STORAGE = backend
            ENCRYPTION_KEY = SecretBox.generate_key()
            OIDC_CLIENT_ID = None
            ELASTICSEARCH_URL = ""

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        support.set_up(self.client, username="owner", password=PASSWORD)
    def tearDown(self):
        for path in (self.database, self.storage):
            if os.path.exists(path):
                os.unlink(path)

    def make(self, count, created_by="owner", visibility="shared"):
        for index in range(count):
            self.app.dashboard_manager.create_dashboard(
                name=f"board-{index:04d}", description="", query="*",
                created_by=created_by, index_patterns=["*"],
                visibility=visibility)

    def cards(self, page=None):
        """Distinct dashboard names on the page.

        Counted as names, not as lines that mention one: a card carries its
        name in the title and again in the delete button's data attributes,
        so counting lines reported three times as many dashboards as the page
        actually held.
        """
        import re
        url = "/dashboards" if page is None else f"/dashboards?page={page}"
        body = self.client.get(url).get_data(as_text=True)
        return sorted(set(re.findall(r"board-\d{4}", body)))


class PageSizeTest(PagingTestCase):
    def test_a_long_list_is_bounded(self):
        self.make(DASHBOARDS_PER_PAGE * 3)
        self.assertEqual(len(self.cards()), DASHBOARDS_PER_PAGE)

    def test_the_response_stays_small(self):
        """The measure that started this: seven megabytes of one page."""
        self.make(500)
        body = self.client.get("/dashboards").get_data()
        self.assertLess(len(body), 200_000, f"{len(body):,} bytes")

    def test_a_short_list_shows_no_controls(self):
        """Pagination on a page with one dashboard is noise."""
        self.make(3)
        self.assertNotIn("pagination",
                         self.client.get("/dashboards").get_data(as_text=True))

    def test_a_long_list_shows_controls(self):
        self.make(DASHBOARDS_PER_PAGE + 1)
        self.assertIn("pagination",
                      self.client.get("/dashboards").get_data(as_text=True))


class PageContentTest(PagingTestCase):
    def setUp(self):
        super().setUp()
        self.make(DASHBOARDS_PER_PAGE * 2 + 5)

    def test_the_second_page_holds_different_dashboards(self):
        self.assertNotEqual(self.cards(0), self.cards(1))

    def test_every_dashboard_appears_on_exactly_one_page(self):
        """A list that drops one in the middle is worse than one that stops
        early, because nothing about it looks wrong."""
        seen = []
        for page in range(3):
            seen.extend(self.cards(page))
        self.assertEqual(len(seen), len(set(seen)),
                         "a dashboard appeared on two pages")
        self.assertEqual(len(seen), DASHBOARDS_PER_PAGE * 2 + 5,
                         "a dashboard fell between two pages")

    def test_the_last_page_is_not_empty(self):
        self.assertTrue(self.cards(2))

    def test_a_page_past_the_end_shows_the_last_page(self):
        """A stale link to page 9 of a two-page list must not read as "your
        dashboards are gone"."""
        self.assertTrue(self.cards(99))

    def test_a_negative_page_shows_the_first_page(self):
        """Not merely "does not error". A negative index reaches the slice as
        a negative offset and quietly returns a window counted from the END,
        so page -3 rendered real dashboards and looked like it worked.
        """
        self.assertEqual(self.client.get("/dashboards?page=-3").status_code, 200)
        self.assertEqual(self.cards(-3), self.cards(0))

    def test_a_nonsense_page_does_not_error(self):
        self.assertEqual(
            self.client.get("/dashboards?page=banana").status_code, 200)

    def test_the_count_shown_is_the_count_of_what_is_visible(self):
        body = self.client.get("/dashboards").get_data(as_text=True)
        self.assertIn(str(DASHBOARDS_PER_PAGE * 2 + 5), body)


class VisibilityTest(PagingTestCase):
    """Paging and the boundary have to agree, or one of them is a leak."""

    def test_paging_counts_only_what_this_person_may_see(self):
        self.make(5, created_by="owner", visibility="shared")
        self.make(DASHBOARDS_PER_PAGE * 2, created_by="someone-else",
                  visibility="private")

        self.app.store.roles.upsert("admin", permissions=["dashboard:view"],
                                    containers=["*"], trace_containers=["*"])
        self.app.store.rbac.invalidate()

        body = self.client.get("/dashboards").get_data(as_text=True)
        self.assertNotIn("pagination", body,
                         "somebody else's private dashboards made pages")
        self.assertEqual(len(self.cards()), 5)

    def test_hidden_dashboards_are_still_counted_out_loud(self):
        """"There are 4 more you cannot see" is what somebody needs to ask the
        right question; hiding it only makes them ask the wrong one."""
        self.make(2, created_by="owner")
        self.make(4, created_by="someone-else", visibility="private")
        self.app.store.roles.upsert("admin", permissions=["dashboard:view"],
                                    containers=["*"], trace_containers=["*"])
        self.app.store.rbac.invalidate()
        body = self.client.get("/dashboards").get_data(as_text=True)
        self.assertIn("4 dashboards", body)


if __name__ == "__main__":
    unittest.main()


class ConcurrentEditTest(PagingTestCase):
    """What the removed Elasticsearch store was the only one to protect.

    That store used `if_seq_no` and refused a write against a stale document,
    and the route caught its exception by name. The database store implements
    the same thing with a `revision` column — and nothing used it. Its own
    docstring said "the edit form passes it"; the form did not, so optimistic
    locking was implemented, tested at the repository, and never reached from
    the application. Two people editing one dashboard lost an edit silently.
    """

    STORAGE = "database"

    def setUp(self):
        super().setUp()
        self.make(1)
        self.dashboard = self.app.dashboard_manager.get_all_dashboards()[0]

    def edit(self, name, revision=None):
        form = {"name": name, "description": "", "query": "*",
                "index_patterns": "app-*", "visibility": "shared"}
        if revision is not None:
            form["revision"] = str(revision)
        return self.client.post(f"/dashboard/{self.dashboard.id}/edit",
                                data=form, follow_redirects=True)

    def current(self):
        return self.app.dashboard_manager.get_dashboard(self.dashboard.id)

    def test_the_form_carries_the_revision(self):
        """The half that was missing. Without it on the page, nothing the
        server does with revisions can ever fire."""
        body = self.client.get(
            f"/dashboard/{self.dashboard.id}/edit").get_data(as_text=True)
        self.assertIn('name="revision"', body)

    def test_an_ordinary_edit_still_works(self):
        self.edit("renamed", revision=self.current().revision)
        self.assertEqual(self.current().name, "renamed")

    def test_a_second_edit_from_a_stale_form_is_refused(self):
        """Two people with the page open. The first saves; the second's form
        still carries the revision from before."""
        stale = self.current().revision
        self.edit("first writer", revision=stale)
        self.edit("second writer", revision=stale)
        self.assertEqual(self.current().name, "first writer",
                         "the second write silently overwrote the first")

    def test_the_refusal_says_what_happened(self):
        """"Try again" is the wrong instruction: somebody else's work is at
        stake, so the answer is "look at what changed"."""
        stale = self.current().revision
        self.edit("first writer", revision=stale)
        body = self.edit("second writer", revision=stale).get_data(as_text=True)
        self.assertIn("changed by someone else", body)

    def test_the_revision_advances_on_every_write(self):
        before = self.current().revision
        self.edit("once", revision=before)
        self.assertGreater(self.current().revision, before)

    def test_a_caller_that_tracks_nothing_gets_last_write_wins(self):
        """A script has no form and no revision to send. Refusing it would
        break every non-interactive caller to protect a case it is not in."""
        self.edit("from a script")
        self.assertEqual(self.current().name, "from a script")
