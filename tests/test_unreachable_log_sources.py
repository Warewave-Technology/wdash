"""
A log source that cannot be reached is not an empty one.

The Loki and VictoriaLogs adapters answered a catalogue they could not read
with an empty list and a line in the log. Every screen then said what an
empty list means, to an administrator whose backend was down:

    /logs                    "No Access to Log Indices" and "No log indices
                             found in Elasticsearch"
    /api/search              404 no_indices
    /api/indices             200, zero containers
    the role editor          "matches nothing on this installation" and
                             "This role would reach no data at all" — an
                             invitation to "fix" a correct pattern into `*`
    the target picker        the source, with "nothing here"

The routes had the right answer written the whole time, in `except` branches
that could not fire. These tests point real adapters at an address nothing
listens on, so the transport fails the way it does in production.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.hub.adapters.loki import LokiLogSource  # noqa: E402
from wdash.hub.adapters.victorialogs import VictoriaLogsSource  # noqa: E402
from wdash.store import SecretBox  # noqa: E402

PASSWORD = "a-sufficiently-long-password"
#: Refused at once: nothing listens on port 1.
NOWHERE = "http://127.0.0.1:1"
WINDOW = "start_time=2026-08-04T09:00:00Z&end_time=2026-08-04T10:00:00Z"


class _Installation(unittest.TestCase):
    """A claimed installation whose only log source is `build()`."""

    NAME = "loki-down"

    def build(self):
        return LokiLogSource(NOWHERE, name=self.NAME, timeout=5)

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "unreachable"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key

        self.app = create_app(TestConfig)
        self.app.hub.replace_all(logs=[self.build()])
        self.client = self.app.test_client()
        support.set_up(self.client, username="owner", password=PASSWORD)
    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)


class UnreachableLokiTest(_Installation):
    def test_the_logs_page_says_it_could_not_connect_and_to_what(self):
        body = self.client.get("/logs").get_data(as_text=True)
        # Both: the message at the top and the box the page draws.
        self.assertIn(f"Unable to connect to {self.NAME}. Please check", body)
        self.assertIn(f"Unable to connect to {self.NAME} to retrieve log data",
                      body)
        self.assertNotIn("Elasticsearch", body.split("Log Viewer", 1)[1])
        self.assertNotIn("No Access to Log Indices", body)
        self.assertNotIn("No log indices found", body)

    def test_a_search_is_a_connection_error_and_not_no_indices(self):
        response = self.client.get(f"/api/search?q=*&{WINDOW}")
        self.assertEqual(response.status_code, 503)
        payload = response.get_json()
        self.assertEqual(payload["error_type"], "elasticsearch_connection")
        self.assertIn(self.NAME, payload["error"])
        self.assertNotIn("Elasticsearch", payload["error"])
        # The client draws the suggestions beside this message, and it used
        # to advise checking Elasticsearch whatever the backend was. The name
        # is in the payload rather than only inside the sentence.
        self.assertEqual(payload["source"], self.NAME)

    def test_the_container_listing_is_a_connection_error_too(self):
        response = self.client.get("/api/indices")
        self.assertEqual(response.status_code, 503)
        self.assertIn(self.NAME, response.get_json()["error"])
        self.assertEqual(response.get_json()["source"], self.NAME)

    def test_the_role_preview_says_it_could_not_check(self):
        """A correct pattern was reported as matching nothing, which is what a
        typo looks like — and the obvious "fix" for a typo is a wider
        pattern."""
        result = self.client.post("/admin/api/roles/preview", json={
            "permissions": ["logs:read"], "containers": ["app-*"],
            "trace_containers": [], "services": []}).get_json()
        said = " ".join(result["warnings"])
        self.assertIn(f"{self.NAME} could not be listed", said)
        entry = next(entry for entry in result["logs"]
                     if entry["source"] == self.NAME)
        self.assertTrue(entry.get("error"), entry)
        self.assertFalse(result["reaches_nothing"],
                         "a source nobody could list was reported as "
                         "reaching nothing")
        self.assertFalse(result["reaches_everything"]["logs"])

    def test_the_picker_says_the_source_did_not_answer(self):
        listing = self.client.get("/admin/api/available").get_json()["logs"]
        entry = next(entry for entry in listing if entry["source"] == self.NAME)
        self.assertEqual(entry["containers"], [])
        self.assertTrue(entry.get("error"), entry)

    def board(self):
        """A dashboard owned by the signed-in account, over this source."""
        manager = self.app.dashboard_manager
        manager.create_dashboard("Board", "", "*", "owner", ["*"])
        return next(d.id for d in manager.get_all_dashboards()
                    if d.name == "Board")

    def test_a_dashboard_names_the_source_that_did_not_answer(self):
        """It said "Unable to connect to Elasticsearch" whichever backend was
        down, so a Loki outage sent whoever was looking to a cluster this
        deployment does not even have."""
        board = self.board()
        # `recent-logs` was the third of these until the E1 package removed
        # it: nothing called it, and the records panel on /data answers the
        # question it was written for.
        for endpoint in ("data", "stats"):
            with self.subTest(endpoint=endpoint):
                reply = self.client.get(f"/api/dashboard/{board}/{endpoint}")
                self.assertEqual(reply.status_code, 503)
                payload = reply.get_json()
                self.assertIn(self.NAME, payload["error"])
                self.assertNotIn("Elasticsearch", payload["error"])
                # A field of its own as well: the client draws its own
                # suggestions beside the message.
                self.assertEqual(payload["source"], self.NAME)

    def test_every_source_down_behind_all_sources_is_an_error_too(self):
        """The fan-out took a member's failure as an empty list as well, so
        `All sources` over two dead backends answered "no indices"."""
        self.app.hub.replace_all(logs=[
            self.build(),
            VictoriaLogsSource(NOWHERE, name="other-down", timeout=5)])
        response = self.client.get(f"/api/search?q=*&source=*&{WINDOW}")
        self.assertEqual(response.status_code, 503)
        self.assertIn(self.NAME, response.get_json()["details"])
        self.assertIn("other-down", response.get_json()["details"])


class UnreachableVictoriaLogsTest(UnreachableLokiTest):
    NAME = "victorialogs-down"

    def build(self):
        return VictoriaLogsSource(NOWHERE, name=self.NAME, timeout=5)


class OneMemberDownTest(_Installation):
    """The other half: one backend down must not take the others with it,
    nor hide what the others say."""

    def test_the_members_that_answered_are_still_listed(self):
        from tests.test_fanout import StubSource
        from wdash.hub import Scope
        from wdash.hub.fanout import FanOutLogSource

        fanout = FanOutLogSource([
            self.build(), StubSource("up", "elasticsearch", ["app-logs"], [])])
        self.assertEqual(fanout.containers(Scope.unrestricted()), ["app-logs"])

    def test_a_pattern_that_grants_everything_on_the_rest_is_still_called_out(self):
        """`*` where `app-*` was meant is the dangerous direction, and a
        source that is down elsewhere must not hide it."""
        from tests.test_fanout import StubSource
        self.app.hub.replace_all(logs=[
            self.build(), StubSource("up", "elasticsearch", ["app-logs"], [])])
        result = self.client.post("/admin/api/roles/preview", json={
            "permissions": ["logs:read"], "containers": ["*"],
            "trace_containers": [], "services": []}).get_json()
        self.assertTrue(result["reaches_everything"]["logs"], result)
        answered = next(entry for entry in result["logs"]
                        if entry["source"] == "up")
        self.assertNotIn("error", answered)
        self.assertEqual(answered["count"], 1)

    def test_a_trace_store_that_cannot_be_listed_is_marked_the_same_way(self):
        from tests.test_trace_fanout import StubTraceSource

        class Down(StubTraceSource):
            def containers(self, scope):
                raise RuntimeError("tempo is unreachable")

        self.app.hub.replace_all(logs=[], traces=[Down("tempo-down")])
        result = self.client.post("/admin/api/roles/preview", json={
            "permissions": ["traces:read"], "containers": [],
            "trace_containers": ["*"], "services": []}).get_json()
        entry = next(entry for entry in result["traces"]
                     if entry["source"] == "tempo-down")
        self.assertIn("unreachable", entry["error"])
        self.assertFalse(result["reaches_nothing"])

    def test_a_listing_that_fails_the_second_time_is_still_a_503(self):
        """The search lists twice — everything, then what the role reaches —
        and only the first was inside the handler. A backend that went away
        between the two answered with Flask's HTML 500."""
        from tests.support import StubLogSource
        from wdash.hub import Scope

        class Flaky(StubLogSource):
            def containers(self, scope):
                if scope != Scope.unrestricted():
                    raise RuntimeError("gone between two calls")
                return super().containers(scope)

        self.app.hub.replace_all(logs=[Flaky(name="flaky")])
        response = self.client.get(f"/api/search?q=*&{WINDOW}")
        self.assertEqual(response.status_code, 503)
        self.assertIn("flaky", response.get_json()["error"])


class VictoriaLogsDashboardTest(unittest.TestCase):
    """A dashboard over VictoriaLogs whose query holds a clause LogsQL cannot
    express. The aggregation raised, so the whole data endpoint answered
    Flask's HTML 500, and the page could only say it failed to parse it."""

    STORAGE = "database"

    def setUp(self):
        from tests.support import change_dashboard, grant, install_dashboard
        from tests.test_conformance_victorialogs import FakeVictoriaLogs
        from wdash.hub import Hub
        from wdash.models import Dashboard

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "vl-dashboard"
            DASHBOARD_STORAGE = self.STORAGE

        self.harness = FakeVictoriaLogs()
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(VictoriaLogsSource("http://vl:9428", name="victorialogs",
                                        session=self.harness))
        self.app.hub = hub
        self.dashboard = install_dashboard(self.app, Dashboard(
            dashboard_id="d1", name="VL", description="", query="*",
            created_by="u", index_patterns=["*"]))
        self.client = self.app.test_client()
        grant(self.app, "u", ["dashboard:view"], ("*",))
        with self.client.session_transaction() as session:
            session["user_data"] = {"id": "1", "email": "u@x", "username": "u",
                                    "groups": []}
            session["_user_id"] = "1"

    def test_a_filter_it_cannot_express_is_an_error_the_page_can_show(self):
        response = self.client.get(
            "/api/dashboard/d1/data?q=status:%5B500%20TO%20599%5D")
        self.assertEqual(response.content_type, "application/json")
        self.assertGreaterEqual(response.status_code, 400,
                                "zeros for a query that did not run read as "
                                "a quiet hour")
        payload = response.get_json()
        self.assertIn("VictoriaLogs cannot express", payload["error"])
        # The page prints these under the message. Without them the reader
        # gets a reason for the first refusal only.
        self.assertIn("VictoriaLogs cannot express", " ".join(payload["warnings"]))

    def test_so_is_a_stored_query_it_cannot_express(self):
        from tests.support import change_dashboard

        change_dashboard(self.app, self.dashboard, query="host:w?b")
        for endpoint in ("data", "stats"):
            with self.subTest(endpoint=endpoint):
                response = self.client.get(f"/api/dashboard/d1/{endpoint}")
                self.assertEqual(response.content_type, "application/json")
                self.assertGreaterEqual(response.status_code, 400)
                self.assertIn("VictoriaLogs cannot express",
                              response.get_json()["error"])

    def test_a_query_it_can_express_still_draws(self):
        response = self.client.get("/api/dashboard/d1/data")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.get_json()["total_hits"], 0)

    def test_a_result_that_is_partly_there_is_still_drawn(self):
        """Only an answer with nothing in it is refused. One panel failing
        beside others that answered is a partial dashboard, with the reason
        in its warnings."""
        from wdash.hub.aggregation import AggregationResult, Bucket

        source = self.app.hub.logs()
        partial = AggregationResult(
            total=5, buckets={"_levels": [Bucket(key="ERROR", count=5)]},
            warnings=("p1 failed: backend timed out",), failed=True)
        source.multi_aggregate = lambda requests, scope: [partial] * len(requests)
        response = self.client.get("/api/dashboard/d1/data")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["error_count"], 5)
        self.assertEqual(payload["warnings"], ["p1 failed: backend timed out"])


class VictoriaLogsDashboardOnTheFileStoreTest(VictoriaLogsDashboardTest):
    """The same, on the JSON store, which is still supported.

    Pinned there when the default moved, because its fixture replaced the
    stored query in place — a write only on the manager that hands out the
    object it stores. A source that cannot express a stored query is a
    failure that must not look like a quiet hour on either store.
    """

    STORAGE = "file"
