"""
Running with no Elasticsearch at all.

WDash was built in front of Elasticsearch, and the client was constructed
unconditionally in the app factory. A deployment reading logs from Loki or
VictoriaLogs still had to run a cluster it never queried — and could not say
so: `ELASTICSEARCH_URL=""` fell straight back to the local default, because
the config read it with `or` rather than a default. "No cluster here" was
literally unsayable.

What these hold is that it starts, that it signs people in, and that every
screen needing a cluster says which thing is missing instead of failing in a
way that reads as an outage.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

PASSWORD = "correct-horse-battery"


class NoElasticsearchTestCase(unittest.TestCase):
    STORAGE = "database"

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database, storage = self.database, self.STORAGE

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "no-elastic"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            OIDC_CLIENT_ID = None
            #: The point of the whole module.
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = storage

        self.config = TestConfig
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.client.post("/setup", data={"username": "owner",
                                         "password": PASSWORD,
                                         "confirm": PASSWORD})

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)


class StartupTest(NoElasticsearchTestCase):
    def test_the_application_starts(self):
        self.assertIsNone(self.app.es_client)

    def test_no_elasticsearch_sources_are_registered(self):
        """A source pointing at a cluster that is not there would fail every
        search and report it as an outage."""
        self.assertEqual(self.app.hub.log_sources, [])
        self.assertEqual(self.app.hub.trace_sources, [])

    def test_an_unset_url_still_gets_the_local_default(self):
        """Set-and-empty means none; unset means the default it always was."""
        self.assertEqual(self._reread({}), "http://localhost:9200")

    def test_an_explicitly_empty_url_stays_empty(self):
        """Read through the environment, because that is where the bug was.

        `os.environ.get('ELASTICSEARCH_URL') or default` turns an explicitly
        empty value straight back into the local URL, so switching
        Elasticsearch off was unsayable. Asserting on the class attribute
        alone does not exercise that line at all.
        """
        self.assertEqual(self._reread({"ELASTICSEARCH_URL": ""}), "")

    @staticmethod
    def _reread(environment):
        """Re-import the config module under a given environment."""
        import importlib
        from unittest import mock
        import wdash.config
        with mock.patch.dict(os.environ, environment, clear=False):
            if "ELASTICSEARCH_URL" not in environment:
                os.environ.pop("ELASTICSEARCH_URL", None)
            reloaded = importlib.reload(wdash.config)
            value = reloaded.Config.ELASTICSEARCH_URL
        importlib.reload(wdash.config)
        return value

    def test_signing_in_works(self):
        self.client.get("/auth/logout")
        response = self.client.post(
            "/auth/login", data={"username": "owner", "password": PASSWORD})
        self.assertEqual(response.status_code, 302)

    def test_health_does_not_mention_a_cluster_that_is_not_there(self):
        payload = self.client.get("/health").get_json()
        self.assertNotIn("elasticsearch", payload)
        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["store"], "connected")


class ScreenTest(NoElasticsearchTestCase):
    def test_the_logs_page_names_the_missing_thing(self):
        """Not "unable to connect": there is nothing to connect to, and the
        answer is on the configuration page rather than in an outage."""
        body = self.client.get("/logs").get_data(as_text=True)
        self.assertIn("No log source is configured", body)
        self.assertNotIn("Unable to connect", body)

    def test_searching_says_no_source_rather_than_no_results(self):
        payload = self.client.get(
            "/api/search?q=*&size=5").get_json()
        self.assertEqual(payload["error_type"], "no_source")

    def test_the_dashboards_page_still_renders(self):
        """Dashboards live in the metadata store; listing them needs nothing
        from a log backend."""
        self.assertEqual(self.client.get("/dashboards").status_code, 200)

    def test_the_configuration_page_still_works(self):
        """The one screen that must work, because it is where the source gets
        added."""
        self.assertEqual(self.client.get("/admin/config").status_code, 200)

    def test_the_audit_trail_still_works(self):
        self.assertEqual(self.client.get("/admin/audit").status_code, 200)

    def test_the_advisor_says_what_it_needs(self):
        payload = self.client.get("/api/advisor/report").get_json()
        self.assertEqual(payload["error_type"], "no_cluster")

    def test_an_empty_advisor_report_is_never_shown_as_a_clean_bill(self):
        """A report with no findings reads as "your cluster is perfect".

        The wording is not the point — that there is a reason on the screen
        instead of an empty report is. So this asserts the shape: the page
        says the analysis did not happen, and says nothing that could be read
        as a pass.
        """
        body = self.client.get("/advisor").get_data(as_text=True)
        self.assertIn("Analysis unavailable", body)
        self.assertIn("no source to analyse", body)
        self.assertNotIn("No issues found", body)

    def test_traces_say_there_is_no_trace_source(self):
        payload = self.client.get("/api/traces/services").get_json()
        self.assertEqual(payload["error_type"], "no_trace_source")

    def test_field_statistics_do_not_crash(self):
        self.assertEqual(self.client.get("/api/field-stats").status_code, 503)


class DashboardStorageTest(NoElasticsearchTestCase):
    STORAGE = "elasticsearch"

    def setUp(self):
        # Deliberately not calling super(): this configuration must not start.
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)

    def test_a_removed_store_is_refused_loudly(self):
        """`DASHBOARD_STORAGE=elasticsearch` was removed.

        Falling through to the file store would present an empty list as
        though every dashboard had been deleted, and somebody would go looking
        for a deletion that never happened.
        """
        message = self._refusal()
        self.assertIn("removed", message.lower())

    def test_the_refusal_says_how_to_get_the_data_out(self):
        """A removal that leaves data unreachable is a deletion with extra
        steps. The way out has to be in the message somebody actually sees."""
        message = self._refusal()
        self.assertIn("migrate_cli", message)
        self.assertIn("--from-elasticsearch", message)

    def _refusal(self):
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "no-elastic"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            OIDC_CLIENT_ID = None
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "elasticsearch"

        with self.assertRaises(RuntimeError) as caught:
            create_app(TestConfig)
        return str(caught.exception)


class WithASourceTest(NoElasticsearchTestCase):
    """A configured non-Elasticsearch source is all it takes to be useful."""

    def setUp(self):
        super().setUp()
        from tests.test_fanout import StubSource
        self.app.hub.replace_all(logs=[StubSource(
            "victoria", "victorialogs", ["app-logs", "infra-logs"], [])])

    def test_the_logs_page_works_with_no_cluster_at_all(self):
        body = self.client.get("/logs").get_data(as_text=True)
        self.assertNotIn("No log source is configured", body)
        # The template prints the count, not the names.
        self.assertIn("Available: 2 indices", body)

    def test_health_reports_that_source_and_no_cluster(self):
        payload = self.client.get("/health").get_json()
        self.assertIn("victoria", payload)
        self.assertNotIn("elasticsearch", payload)


if __name__ == "__main__":
    unittest.main()


class EnvironmentIsolationTest(unittest.TestCase):
    """The suite must mean the same thing on every machine.

    A developer with a deployment's variables in their shell ran a different
    suite from CI, and it failed in a way that reads as flakiness rather than
    as configuration. Twice: `WDASH_ENCRYPTION_KEY` took out four tests,
    `TRACE_INDEX_PATTERNS` set empty took out 127.

    Checked as a test rather than left to the import: a name added to `Config`
    that flips behaviour needs adding here too, and nothing else would say so.
    """

    def test_the_variables_that_flip_behaviour_are_neutralised(self):
        from tests import NEUTRALISED
        for name in NEUTRALISED:
            self.assertNotIn(name, os.environ,
                             f"{name} survived into the test process")

    def test_every_config_value_that_means_off_when_empty_is_listed(self):
        """The two that read with a default rather than `or` are exactly the
        two where empty means "off" — so those are the dangerous ones."""
        import inspect

        from wdash import config as config_module
        source = inspect.getsource(config_module)
        from tests import NEUTRALISED

        missing = []
        for line in source.splitlines():
            if "os.environ.get(" not in line or "," not in line:
                continue
            # `os.environ.get('X', default)` — a default rather than `or`,
            # which is the shape that lets an empty value through.
            for name in ("ELASTICSEARCH_URL", "TRACE_INDEX_PATTERNS"):
                if f"'{name}'" in line and name not in NEUTRALISED:
                    missing.append(name)
        self.assertEqual(missing, [])


class HealthProbeTest(NoElasticsearchTestCase):
    """What `/health` says, and what Kubernetes does about it.

    Both probes in kubernetes/wdash-deployment.yaml point here, which makes
    this endpoint's status code a control signal rather than a report:

      * readiness failing removes the pod from the Service, so the
        configuration page — the one screen that could fix an unreachable
        source — becomes unreachable too;
      * liveness failing RESTARTS the container, so a thirty-second Loki
        outage becomes a restart loop.

    Neither is a sane response to a data source being down. The metadata
    store is different: accounts and roles live there, so without it the
    instance really cannot serve anybody.
    """

    def _payload(self):
        response = self.client.get("/health")
        return response.status_code, response.get_json()

    def _break_source(self, name="loki"):
        class Broken:
            def __init__(self, name): self.name = name
            def health(self): return False, "connection refused"
        self.app.hub.replace_all(logs=[Broken(name)])

    def test_an_unreachable_source_does_not_take_the_instance_out_of_service(self):
        self._break_source()
        status, payload = self._payload()
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "degraded")

    def test_the_unreachable_source_is_named(self):
        """So an alert can say which backend is down without diffing two
        payloads."""
        self._break_source("lab-loki")
        _, payload = self._payload()
        self.assertEqual(payload["degraded"], ["lab-loki"])
        self.assertEqual(payload["lab-loki"], "unreachable")

    def test_a_source_that_raises_is_treated_the_same(self):
        class Exploding:
            name = "boom"
            def health(self): raise RuntimeError("no route to host")
        self.app.hub.replace_all(logs=[Exploding()])
        status, payload = self._payload()
        self.assertEqual(status, 200)
        self.assertEqual(payload["boom"], "unreachable")

    def test_an_unreachable_metadata_store_does_take_it_out_of_service(self):
        """The one hard dependency. Without it there is nobody to sign in as,
        so serving traffic would only produce errors."""
        class Broken:
            def count(self): raise RuntimeError("database is gone")
        self.app.store.users = Broken()
        status, payload = self._payload()
        self.assertEqual(status, 503)
        self.assertEqual(payload["status"], "unhealthy")

    def test_everything_working_is_still_plain_healthy(self):
        """`degraded` must not appear when nothing is."""
        self.app.hub.replace_all(logs=[])
        status, payload = self._payload()
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "healthy")
        self.assertNotIn("degraded", payload)

    def test_a_fresh_deployment_with_nothing_configured_is_reachable(self):
        """The deadlock this fixes: the default ELASTICSEARCH_URL points at a
        localhost that is not there, so on a first deployment the pod never
        became ready — and the configuration page was the thing behind the
        readiness gate."""
        self.app.hub.replace_all(logs=[], traces=[])
        status, _ = self._payload()
        self.assertEqual(status, 200)
        self.assertEqual(self.client.get("/admin/config").status_code, 200)
