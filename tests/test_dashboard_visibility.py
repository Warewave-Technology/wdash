"""
Who can see which dashboard.

`dashboard:view` used to mean "see every dashboard". Panel data was always
filtered by the viewer's own boundaries, so nothing leaked — but a dashboard's
name and query are themselves information. `payment-fraud-investigation` over
`fraud-*` tells you something whether or not you can read the index.

The rule: **you can see a dashboard if you could see its data.** It needs no
new concept and cannot drift out of step with the data boundary, because it is
the data boundary. `visibility: private` exists for the one thing the rule
cannot express — an author keeping something to themselves among colleagues who
share their access.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.dashboard.visibility import (  # noqa: E402
    DEFAULT, PRIVATE, SHARED, can_view, explain, normalise,
)
from wdash.models import Dashboard  # noqa: E402


class RuleTest(unittest.TestCase):
    """The rule on its own, without a cluster."""

    def board(self, author="alice", visibility=SHARED):
        return Dashboard("d1", "Board", "", "*", author, visibility=visibility)

    def test_you_see_a_shared_dashboard_whose_data_you_can_reach(self):
        self.assertTrue(can_view(self.board(), "bob", False, ["app-logs"]))

    def test_you_do_not_see_one_whose_data_you_cannot(self):
        """It was never usable to them; hiding it costs nothing and stops the
        list advertising what exists."""
        self.assertFalse(can_view(self.board(), "bob", False, []))

    def test_a_private_dashboard_is_hidden_even_from_people_who_share_access(self):
        self.assertFalse(
            can_view(self.board(visibility=PRIVATE), "bob", False, ["app-logs"]))

    def test_authors_always_see_their_own(self):
        """Otherwise a dashboard over an index that does not exist yet is
        invisible to the person who just wrote it, which reads as 'it did not
        save'."""
        self.assertTrue(can_view(self.board(), "alice", False, []))
        self.assertTrue(
            can_view(self.board(visibility=PRIVATE), "alice", False, []))

    def test_administrators_see_every_dashboard(self):
        """Being unable to see the thing you are allowed to delete is not a
        boundary, it is a puzzle."""
        self.assertTrue(
            can_view(self.board(visibility=PRIVATE), "bob", True, []))

    def test_the_reason_is_available_for_the_list_and_for_tests(self):
        self.assertEqual(explain(self.board(), "alice", False, []), "yours")
        self.assertIn("private", explain(self.board(visibility=PRIVATE),
                                         "bob", False, ["x"]))
        self.assertIn("within your access",
                      explain(self.board(), "bob", False, []))


class NormaliseTest(unittest.TestCase):
    def test_nonsense_falls_back_to_the_default(self):
        self.assertEqual(normalise("whatever"), DEFAULT)
        self.assertEqual(normalise(None), DEFAULT)
        self.assertEqual(normalise(""), DEFAULT)

    def test_the_default_is_shared(self):
        """A dashboard stored before this existed must not disappear on
        upgrade. The boundary rule still applies to it, which is the change."""
        self.assertEqual(DEFAULT, SHARED)
        self.assertIsNone(
            Dashboard.from_dict({"id": "1", "name": "n", "description": "",
                                 "query": "*", "created_by": "u"}).visibility
            != SHARED or None)

    def test_both_values_round_trip(self):
        for value in (SHARED, PRIVATE):
            board = Dashboard("1", "n", "", "*", "u", visibility=value)
            self.assertEqual(
                Dashboard.from_dict(board.to_dict()).visibility, value)


class ListingTest(unittest.TestCase):
    """The rule as the application applies it."""

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "visibility"
            DATABASE_URL = f"sqlite:///{database}"

        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource
        from tests.test_dashboard_contract import FakeES

        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(FakeES()))
        self.app.hub = hub
        self.app.store.users.create_first_admin("setup", "a-long-enough-pw")

        manager = self.app.dashboard_manager
        manager.create_dashboard("AppBoard", "", "*", "alice", ["app-*"])
        manager.create_dashboard("SecretBoard", "", "*", "alice", ["infra-*"],
                                 visibility=PRIVATE)
        manager.create_dashboard("InfraBoard", "", "*", "alice", ["infra-*"])
        self.ids = {d.name: d.id for d in manager.get_all_dashboards()}

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def client_for(self, username, containers, admin=False):
        client = self.app.test_client()
        permissions = ["dashboard:view"] + (["system:admin"] if admin else [])
        self.app.store.roles.upsert(
            f"role-{username}", permissions=permissions,
            containers=containers, trace_containers=[])
        mapped = dict(self.app.store.settings.get("rbac.user_roles", {}) or {})
        mapped[username] = f"role-{username}"
        self.app.store.settings.set("rbac.user_roles", mapped)
        self.app.store.rbac.invalidate()

        with client.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": f"{username}@x",
                                    "username": username, "groups": []}
            session["_user_id"] = "1"
        return client

    def names_seen(self, client):
        page = client.get("/dashboards").data
        return [name for name in ("AppBoard", "SecretBoard", "InfraBoard")
                if name.encode() in page]

    def test_recent_logs_has_the_gates_every_other_panel_has(self):
        """Measured: for alice's PRIVATE dashboard, a viewer who was not its
        author got 404 from data, log-levels, patterns and stats, and 200
        from recent-logs, with the dashboard's query run for them."""
        manager = self.app.dashboard_manager
        manager.create_dashboard("Fraud", "", 'service:"fraud"', "alice",
                                 ["app-*"], visibility=PRIVATE)
        fraud = next(d.id for d in manager.get_all_dashboards()
                     if d.name == "Fraud")
        es = self.app.hub.logs()._es
        client = self.client_for("u", ["app-*"])
        before = len(es.searches)
        for suffix in ("data", "log-levels", "recent-logs"):
            with self.subTest(suffix=suffix):
                reply = client.get(f"/api/dashboard/{fraud}/{suffix}")
                self.assertEqual(reply.status_code, 404)
        self.assertEqual(len(es.searches), before, "the private query was run")

    def test_recent_logs_says_when_there_is_no_such_dashboard(self):
        """Not an empty list: that is the answer for a dashboard with nothing
        recent in it, and the two were indistinguishable."""
        client = self.client_for("u", ["app-*"])
        for dashboard in ("does-not-exist", self.ids["SecretBoard"]):
            with self.subTest(dashboard=dashboard):
                reply = client.get(f"/api/dashboard/{dashboard}/recent-logs")
                self.assertEqual(reply.status_code, 404)

    def test_recent_logs_for_its_author_still_works(self):
        client = self.client_for("alice", ["app-*"])
        reply = client.get(f"/api/dashboard/{self.ids['AppBoard']}/recent-logs")
        self.assertEqual(reply.status_code, 200)
        self.assertIn("records", reply.get_json())

    def test_recent_logs_with_a_query_that_does_not_parse_is_a_400(self):
        manager = self.app.dashboard_manager
        manager.create_dashboard("Bad", "", "service:(", "alice", ["app-*"])
        bad = next(d.id for d in manager.get_all_dashboards() if d.name == "Bad")
        client = self.client_for("alice", ["app-*"])
        reply = client.get(f"/api/dashboard/{bad}/recent-logs")
        self.assertEqual(reply.status_code, 400)
        self.assertEqual(reply.get_json()["error_type"], "invalid_query")

    def test_recent_logs_when_the_source_cannot_answer_is_a_503(self):
        client = self.client_for("alice", ["app-*"])
        from wdash.api import dashboard_routes
        original = dashboard_routes._targets
        calls = []

        def failing(dashboard, scope):
            calls.append(dashboard.id)
            # The visibility check asks first; it treats a failure as
            # unreachable, so the endpoint's own call is the second.
            if len(calls) > 1:
                raise ConnectionError("cluster down")
            return original(dashboard, scope)
        dashboard_routes._targets = failing
        try:
            reply = client.get(
                f"/api/dashboard/{self.ids['AppBoard']}/recent-logs")
        finally:
            dashboard_routes._targets = original
        self.assertEqual(reply.status_code, 503)
        self.assertNotIn("records", reply.get_json())

    def test_a_reader_sees_only_dashboards_over_data_they_can_reach(self):
        client = self.client_for("bob", ["app-*"])
        self.assertEqual(self.names_seen(client), ["AppBoard"])

    def test_a_different_boundary_sees_a_different_set(self):
        client = self.client_for("carol", ["infra-*"])
        self.assertEqual(self.names_seen(client), ["InfraBoard"])

    def test_the_author_sees_their_own_including_the_private_one(self):
        client = self.client_for("alice", ["app-*"])
        self.assertEqual(sorted(self.names_seen(client)),
                         ["AppBoard", "InfraBoard", "SecretBoard"])

    def test_an_administrator_sees_everything(self):
        client = self.client_for("erin", ["*"], admin=True)
        self.assertEqual(sorted(self.names_seen(client)),
                         ["AppBoard", "InfraBoard", "SecretBoard"])

    def test_the_hidden_count_is_stated_rather_than_left_as_a_gap(self):
        """'There are 4 more you cannot see' is what somebody needs to ask the
        right question; hiding it only makes them ask the wrong one."""
        client = self.client_for("bob", ["app-*"])
        self.assertIn(b"not shown", client.get("/dashboards").data)

    def test_it_is_stated_even_when_nothing_is_visible(self):
        """The case where it matters most: an empty page saying 'create your
        first dashboard' while three exist is actively misleading."""
        client = self.client_for("dave", [])
        page = client.get("/dashboards").data
        self.assertEqual(self.names_seen(client), [])
        self.assertIn(b"not shown", page)

    # ---------- a source that cannot answer is not a boundary ----------

    def notices(self, client):
        """The page's own sentences, with the template's line breaks taken
        out so an assertion reads like the screen does."""
        import re
        page = client.get("/dashboards").data.decode()
        body = page.split('<h2><i class="fas fa-chart-bar"></i> Dashboards')[-1]
        body = body.split("No Dashboards Found")[0].split('<div class="row">')[0]
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()

    def unreachable_source(self):
        """Make the catalogue raise, the way Loki and VictoriaLogs do when
        their labels cannot be read."""
        source = self.app.hub.logs()
        original = source.containers

        def failing(scope, *args, **kwargs):
            raise ConnectionError("stream labels could not be read: refused")
        source.containers = failing
        self.addCleanup(setattr, source, "containers", original)

    def test_an_outage_is_not_reported_as_privacy_or_access(self):
        """Measured before: as bob, with the catalogue raising, the page said
        '3 dashboards are not shown: either private to their authors, or
        covering data outside your access' and mentioned no outage at all.
        The reader goes to an administrator for access they already have.

        The count is 2, not 3: alice's SecretBoard is PRIVATE, so bob could
        not see it whatever the source said, and counting it as "could not be
        checked" promises it might appear once the backend is back. See
        `test_a_private_dashboard_is_private_through_an_outage_too`.
        """
        self.unreachable_source()
        client = self.client_for("bob", ["app-*"])
        said = self.notices(client)

        self.assertIn("2 dashboards could not be checked", said)
        self.assertIn("elasticsearch", said)
        self.assertNotIn("3 dashboards could not be checked", said)

    def test_a_private_dashboard_is_private_through_an_outage_too(self):
        """One source failing for everything — which is what an outage
        actually looks like, as against the surgical one below.

        `_visible` put every dashboard that failed `can_view` into `unchecked`
        whenever the reach could not be read, without asking whether the
        visibility rule would have hidden it anyway. Somebody else's PRIVATE
        dashboard is hidden whatever its source says, and the page told bob
        "there is no saying what they can reach", which reads as "they may
        turn up when the backend is back". One of them never will.
        """
        self.unreachable_source()
        client = self.client_for("bob", ["app-*"])
        said = self.notices(client)

        self.assertIn("1 dashboard is not shown", said)
        self.assertIn("2 dashboards could not be checked", said)
        self.assertEqual(self.names_seen(client), [])

    def test_the_two_counts_are_kept_apart(self):
        """One private dashboard and two that could not be checked: the page
        must say one of each, not three of the wrong one."""
        source = self.app.hub.logs()
        original = source.containers
        secret = self.ids["SecretBoard"]

        def selective(scope, *args, **kwargs):
            # The private one resolves normally; the shared two cannot be
            # checked, because their reach is what an outage hides.
            if getattr(selective, "board", None) == secret:
                return original(scope, *args, **kwargs)
            raise ConnectionError("stream labels could not be read: refused")

        from wdash.api import dashboard_routes
        original_targets = dashboard_routes._targets

        def targets(dashboard, scope):
            selective.board = dashboard.id
            return original_targets(dashboard, scope)

        source.containers = selective
        dashboard_routes._targets = targets
        self.addCleanup(setattr, source, "containers", original)
        self.addCleanup(setattr, dashboard_routes, "_targets", original_targets)

        client = self.client_for("bob", ["app-*"])
        said = self.notices(client)
        self.assertIn("1 dashboard is not shown", said)
        self.assertIn("2 dashboards could not be checked", said)

    def test_an_outage_does_not_open_what_the_reach_was_holding_shut(self):
        """The list page knows three answers now; the endpoints know two, and
        UNCHECKED has to land on the closed side of that line.

        AppBoard is alice's, shared, and bob sees it only because its data is
        within his reach. With the catalogue down nobody can say that it is,
        so the endpoints answer exactly as they do for a dashboard whose data
        is outside his access. `test_an_unreachable_source_hides_rather_than
        _reveals` says this for the listing; these are the doors the listing
        is not.

        Whether "not found" is the right WORD for it is a separate question —
        /api/search?dashboard=<id> says 503 and names the source — but it
        must not be "here you are".
        """
        self.unreachable_source()
        board = self.ids["AppBoard"]
        client = self.client_for("bob", ["app-*"])

        for suffix in ("data", "stats", "recent-logs", "patterns", "timeline"):
            with self.subTest(endpoint=suffix):
                reply = client.get(f"/api/dashboard/{board}/{suffix}")
                self.assertEqual(reply.status_code, 404)
        self.assertEqual(client.get(f"/dashboard/{board}").status_code, 302)

    def test_the_author_still_sees_their_own_through_an_outage(self):
        """An outage hides what a dashboard reaches; it does not hide a
        dashboard from the person who wrote it."""
        self.unreachable_source()
        client = self.client_for("alice", ["app-*"])
        said = self.notices(client)
        self.assertEqual(sorted(self.names_seen(client)),
                         ["AppBoard", "InfraBoard", "SecretBoard"])
        self.assertNotIn("could not be checked", said)


class ColonNameTest(unittest.TestCase):
    """A dashboard over `unknown_service:*` is visible to a role granted
    `unknown_service:*`: no source has that name, so the colon is part of
    it — and the dashboards' routes have to know the configured names to
    read it that way."""

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "visibility"
            DATABASE_URL = f"sqlite:///{database}"

        from tests.support import StubLogSource
        from wdash.hub import Hub
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(StubLogSource(containers=("unknown_service:java",
                                               "logs-app")))
        self.app.hub = hub
        self.app.store.users.create_first_admin("setup", "a-long-enough-pw")
        self.app.dashboard_manager.create_dashboard(
            "UnnamedBoard", "", "*", "alice", ["unknown_service:*"])

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def test_it_is_listed_for_a_role_granted_those_names(self):
        client = ListingTest.client_for(self, "bob", ["unknown_service:*"])
        self.assertIn(b"UnnamedBoard", client.get("/dashboards").data)


class ApiIsNotTheWayAroundTest(ListingTest):
    """A rule applied only to the list is not a boundary, it is a speed bump."""

    def test_the_page_of_an_invisible_dashboard_is_not_reachable(self):
        client = self.client_for("bob", ["app-*"])
        response = client.get(f"/dashboard/{self.ids['SecretBoard']}")
        self.assertEqual(response.status_code, 302)

    def test_its_data_endpoint_answers_not_found_rather_than_denied(self):
        """A distinct 'you may not see this' turns the URL into a way to find
        out which dashboards exist."""
        client = self.client_for("bob", ["app-*"])
        response = client.get(f"/api/dashboard/{self.ids['SecretBoard']}/data")
        self.assertEqual(response.status_code, 404)

    def test_the_per_panel_endpoints_are_covered_too(self):
        client = self.client_for("bob", ["app-*"])
        for suffix in ("stats", "timeline", "services", "heatmap", "patterns"):
            response = client.get(
                f"/api/dashboard/{self.ids['SecretBoard']}/{suffix}")
            self.assertEqual(response.status_code, 404, suffix)

    def test_a_visible_dashboard_still_works(self):
        client = self.client_for("bob", ["app-*"])
        self.assertEqual(
            client.get(f"/api/dashboard/{self.ids['AppBoard']}/data").status_code,
            200)

    def test_a_source_qualified_grant_sees_its_dashboards(self):
        """The targets were computed by a pattern check that never said which
        source it was about, so a role granted `elasticsearch:app-*` saw no
        shared dashboard at all, and got 404 from the ones it could read."""
        client = self.client_for("carol", ["elasticsearch:app-*"])
        self.assertEqual(self.names_seen(client), ["AppBoard"])
        self.assertEqual(
            client.get(f"/api/dashboard/{self.ids['AppBoard']}/data").status_code,
            200)

    def test_a_source_qualified_exclusion_hides_what_it_excludes(self):
        client = self.client_for("dave", ["*", "-elasticsearch:infra-*"])
        self.assertEqual(self.names_seen(client), ["AppBoard"])

    def test_containers_you_cannot_read_are_counted_not_named(self):
        """A dashboard over `*` resolves to indices a viewer may not read, and
        naming them is what the visibility rule holds back — `fraud-*` says
        something whether or not you can open it. An administrator sees them
        all."""
        manager = self.app.dashboard_manager
        manager.create_dashboard("Everything", "", "*", "alice", ["*"])
        board = next(d.id for d in manager.get_all_dashboards()
                     if d.name == "Everything")

        reader = self.client_for("bob", ["app-*"])
        for suffix in ("patterns", "data"):
            payload = reader.get(f"/api/dashboard/{board}/{suffix}").get_json()
            with self.subTest(endpoint=suffix):
                self.assertEqual(payload["resolved_containers"],
                                 ["app-logs-000001"])
                self.assertEqual(payload["total_resolved"], 2)

        admin = self.client_for("root", ["app-*"], admin=True)
        payload = admin.get(f"/api/dashboard/{board}/patterns").get_json()
        self.assertEqual(sorted(payload["resolved_containers"]),
                         ["app-logs-000001", "infra-logs-000001"])

    def test_an_unreachable_source_hides_rather_than_reveals(self):
        """A backend being down must not open the list up."""
        broken = self.app.hub.logs()
        original = broken.containers
        broken.containers = lambda scope: (_ for _ in ()).throw(
            RuntimeError("cluster unreachable"))
        try:
            client = self.client_for("bob", ["app-*"])
            self.assertEqual(self.names_seen(client), [])
        finally:
            broken.containers = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
