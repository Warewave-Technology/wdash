"""
Advisor HTTP layer tests.

No Elasticsearch required: analyze() is swapped for one returning a saved
fixture, so these tests measure the routes, authorization and caching rather
than the cluster.
"""

import os
import sys
import unittest

from tests.support import grant

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.advisor import ClusterSnapshot, run_rules  # noqa: E402
from wdash.api import advisor_routes  # noqa: E402
from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "lab-cluster.json")

ADMIN_SESSION = {
    "id": "u1", "email": "admin@example.com", "username": "admin", "groups": [],
    "role": "admin",
    "permissions": ["logs:read", "dashboard:view", "system:admin"],
    "allowed_indices": ["*"],
}

VIEWER_SESSION = {
    "id": "u2", "email": "viewer@example.com", "username": "viewer", "groups": [],
    "role": "viewer",
    "permissions": ["logs:read", "dashboard:view"],
    "allowed_indices": ["app-*"],
}


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret-key"
    WTF_CSRF_ENABLED = False


class AdvisorRouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_report = run_rules(ClusterSnapshot.load(FIXTURE))

    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

        # Return the fixture report instead of calling analyze()
        self._original_analyze = advisor_routes.analyze
        self.call_count = 0

        def fake_analyze(es, timeout=30):
            self.call_count += 1
            return self.fixture_report

        advisor_routes.analyze = fake_analyze
        # One entry per source now: two sources of the same kind are two
        # deployments, and serving one's report for the other would be worse
        # than no cache.
        advisor_routes._cache.clear()

    def tearDown(self):
        advisor_routes.analyze = self._original_analyze
        # One entry per source now: two sources of the same kind are two
        # deployments, and serving one's report for the other would be worse
        # than no cache.
        advisor_routes._cache.clear()

    def login(self, user_data):
        grant(self.app, user_data["username"], user_data["permissions"],
              indices=user_data.get("allowed_indices", ["*"]))
        with self.client.session_transaction() as session:
            session["user_data"] = user_data
            session["_user_id"] = user_data["id"]

    # --- authorization ---

    def test_page_requires_authentication(self):
        response = self.client.get("/advisor")
        self.assertEqual(response.status_code, 302)

    def test_json_requires_authentication(self):
        response = self.client.get("/api/advisor/report")
        self.assertEqual(response.status_code, 302)

    def test_non_admin_gets_403_on_json(self):
        self.login(VIEWER_SESSION)
        response = self.client.get("/api/advisor/report")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error_type"], "permission_denied")

    def test_non_admin_redirected_from_page(self):
        self.login(VIEWER_SESSION)
        response = self.client.get("/advisor")
        self.assertEqual(response.status_code, 302)

    def test_non_admin_cannot_list_rules(self):
        self.login(VIEWER_SESSION)
        self.assertEqual(self.client.get("/api/advisor/rules").status_code, 403)

    # --- behaviour ---

    def test_admin_gets_report_page(self):
        self.login(ADMIN_SESSION)
        response = self.client.get("/advisor")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Cluster Advisor", response.data)
        # The critical finding from the fixture must appear on the page
        self.assertIn(b"MAP001", response.data)

    def test_admin_gets_json_report(self):
        self.login(ADMIN_SESSION)
        response = self.client.get("/api/advisor/report")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("findings", payload)
        self.assertIn("score", payload)
        self.assertTrue(any(f["rule_id"] == "MAP001" for f in payload["findings"]))

    def test_rules_catalogue(self):
        self.login(ADMIN_SESSION)
        payload = self.client.get("/api/advisor/rules").get_json()
        self.assertGreater(payload["total"], 10)
        self.assertTrue(all("id" in r and "title" in r for r in payload["rules"]))

    # --- caching ---

    def test_report_is_cached_between_requests(self):
        self.login(ADMIN_SESSION)
        self.client.get("/api/advisor/report")
        self.client.get("/api/advisor/report")
        self.assertEqual(self.call_count, 1, "the second request should have been served from cache")

    def test_refresh_bypasses_cache(self):
        self.login(ADMIN_SESSION)
        self.client.get("/api/advisor/report")
        response = self.client.get("/api/advisor/report?refresh=1")
        self.assertEqual(self.call_count, 2)
        self.assertTrue(response.get_json()["cache"]["fresh"])

    # --- error path ---

    def test_analysis_failure_returns_503(self):
        def exploding_analyze(es, timeout=30):
            raise ConnectionError("cluster unreachable")

        advisor_routes.analyze = exploding_analyze
        self.login(ADMIN_SESSION)
        response = self.client.get("/api/advisor/report")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error_type"], "advisor_error")

    def test_page_survives_analysis_failure(self):
        def exploding_analyze(es, timeout=30):
            raise ConnectionError("cluster unreachable")

        advisor_routes.analyze = exploding_analyze
        self.login(ADMIN_SESSION)
        response = self.client.get("/advisor")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analysis unavailable", response.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class DefaultSourceTest(unittest.TestCase):
    """What a bare `/advisor` — the link in the menu — analyses.

    It used to mean the environment cluster unconditionally, from when that
    was the only cluster there could be. Unset ELASTICSEARCH_URL and manage
    every source on the configuration page, and the first thing an admin sees
    is "no Elasticsearch is configured" on a screen that is simultaneously
    offering five sources it can analyse. Picking any of them fixes it, so the
    fault reads as intermittent rather than as a wrong default.
    """

    # Not a subclass of AdvisorRouteTest: inheriting the harness would also
    # inherit its tests, and rerunning them against a deliberately broken
    # setUp reports failures that say nothing about either.
    setUpClass = AdvisorRouteTest.__dict__["setUpClass"]
    login = AdvisorRouteTest.login
    tearDown = AdvisorRouteTest.tearDown

    def setUp(self):
        AdvisorRouteTest.setUp(self)
        # The state this class is about: no environment cluster.
        self.app.es_client = None
        self.login(ADMIN_SESSION)

    def _add(self, name, kind="loki", url="http://loki:3100"):
        return self.app.store.sources.create(
            name=name, signal=["logs"], kind=kind,
            config={"url": url, "verify_certs": False})

    def test_a_bare_request_falls_back_to_a_configured_source(self):
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        with self.app.test_request_context("/advisor"):
            self.assertEqual(advisor_routes._default_source(), "lab-elastic")

    def test_the_environment_cluster_still_wins_when_it_exists(self):
        """Not a behaviour change for anyone configured the old way."""
        self.app.es_client = object()
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        with self.app.test_request_context("/advisor"):
            self.assertEqual(advisor_routes._default_source(),
                             advisor_routes.ENVIRONMENT_SOURCE)

    def test_nothing_at_all_resolves_to_nothing(self):
        with self.app.test_request_context("/advisor"):
            self.assertIsNone(advisor_routes._default_source())

    def test_the_bare_page_analyses_that_source(self):
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        body = self.client.get("/advisor").get_data(as_text=True)
        self.assertNotIn("no Elasticsearch is configured", body)
        self.assertEqual(self.call_count, 1)

    def _selected_option(self, body):
        """Which option carries `selected`. The attribute is on its own line
        in the template, so a substring match on `value="x" selected` tests
        the indentation rather than the behaviour."""
        import re
        for match in re.finditer(r'<option value="([^"]+)"([^>]*)>', body):
            if "selected" in match.group(2):
                return match.group(1)
        return None

    def test_the_picker_shows_what_the_page_is_reporting_on(self):
        """A picker disagreeing with the page is worse than no picker: the
        first thing somebody does with it is switch to the source already on
        screen, and nothing appears to happen.

        `aaa-loki` sorts first, so a picker that just highlights the head of
        the list gets this wrong — which is what the template did before the
        selection was resolved on the server.
        """
        self._add("aaa-loki")
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        body = self.client.get("/advisor?source=lab-elastic").get_data(as_text=True)
        self.assertEqual(self._selected_option(body), "lab-elastic")

    def test_the_bare_picker_shows_the_source_that_was_analysed(self):
        # Two, because the picker is hidden when there is only one thing to
        # pick — and a hidden picker cannot disagree with anything.
        self._add("aaa-loki")
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        body = self.client.get("/advisor").get_data(as_text=True)
        self.assertEqual(self._selected_option(body), "aaa-loki")

    def test_an_elasticsearch_report_knows_which_source_it_is_about(self):
        """`analyze()` inspects a client it was handed and never learns what
        the configuration page calls it. An anonymous report is unreadable as
        soon as there are two."""
        self._add("aaa-loki")
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        with self.app.test_request_context("/advisor?source=lab-elastic"):
            report = advisor_routes._build_report("lab-elastic")
        self.assertEqual(report.source, "lab-elastic")

    def test_the_bare_page_and_the_named_one_share_one_cache_entry(self):
        """They are the same report. Keying the bare request separately would
        analyse the cluster twice and let the two copies drift apart."""
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        self.client.get("/advisor")
        self.client.get("/advisor?source=lab-elastic")
        self.assertEqual(self.call_count, 1)
        self.assertEqual(list(advisor_routes._cache), ["lab-elastic"])

    def test_an_unanalysable_source_keeps_the_picker(self):
        """One unreachable backend must not take away the control you would
        use to pick a reachable one."""
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        self._add("lab-loki")

        def explode(es, timeout=30):
            raise RuntimeError("connection refused")

        advisor_routes.analyze = explode
        body = self.client.get("/advisor").get_data(as_text=True)
        self.assertIn("lab-loki", body)

    def test_the_json_endpoint_uses_the_same_default(self):
        self._add("lab-elastic", kind="elasticsearch",
                  url="http://cluster:9200")
        payload = self.client.get("/api/advisor/report").get_json()
        self.assertNotIn("error_type", payload)

    def test_with_no_sources_the_message_does_not_blame_elasticsearch(self):
        """"No Elasticsearch is configured" sends somebody to set a variable
        that is no longer how sources are added."""
        payload = self.client.get("/api/advisor/report").get_json()
        self.assertEqual(payload["error_type"], "no_cluster")
        self.assertIn("configuration page", payload["error"])
