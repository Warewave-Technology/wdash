"""
Basic tests for WDash application
"""

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from wdash.app import create_app
from wdash.config import Config


class TestConfig(Config):
    """Test configuration"""
    TESTING = True
    ELASTICSEARCH_URL = 'http://localhost:9200'
    SECRET_KEY = 'test-secret-key'
    RBAC_CONFIG_FILE = 'config/rbac.yaml'


class WDashTestCase(unittest.TestCase):
    """Base test case for WDash"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
    
    def tearDown(self):
        """Clean up after tests"""
        self.app_context.pop()
    
    def test_app_creation(self):
        """Test that app can be created"""
        self.assertIsNotNone(self.app)
        self.assertTrue(self.app.testing)
    
    def test_health_endpoint(self):
        """The probe answers at all, in one shape or the other."""
        response = self.client.get('/health')
        self.assertIn(response.status_code, [200, 503])
        self.assertIn('status', response.get_json())
    
    def test_index_page_sends_an_unclaimed_installation_to_setup(self):
        """Nobody owns this installation yet, so nothing else is useful."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/setup'))

    def test_index_page_loads_once_the_installation_is_claimed(self):
        from tests.support import claim
        claim(self.app)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'WDash', response.data)

    
    def test_logs_page_requires_auth(self):
        """Test that logs page requires authentication"""
        from tests.support import claim
        claim(self.app)
        response = self.client.get('/logs')
        self.assertEqual(response.status_code, 302)  # Redirect to login


if __name__ == '__main__':
    unittest.main()

class HealthTest(unittest.TestCase):
    """What the probe must never do is report a broken instance as healthy —
    and, just as important, what it must not call broken.

    An orchestrator keeps routing traffic to whatever answers 200, so a
    false-healthy probe is worse than no probe. Three ways it managed that:

      * `ping()` RETURNS False for an unreachable cluster rather than raising,
        and only the exception was handled
      * nothing but the environment-configured Elasticsearch was checked, so a
        dead Loki or a missing metadata store did not register
      * the failure branch handed `str(exc)` to an unauthenticated caller,
        which is where connection strings live

    The fourth was the opposite mistake. Both Kubernetes probes read this
    endpoint, so answering 503 for an unreachable data source removed the pod
    from the Service — hiding the configuration page that could have fixed it
    — and had the kubelet restart the container. Only the metadata store
    decides the status code now; everything else is reported and named.
    """

    class _Source:
        capabilities = frozenset()

        def __init__(self, name, healthy=True, detail="down at 10.0.0.5:3100"):
            self.name = name
            self._healthy = healthy
            self._detail = detail

        def health(self):
            return self._healthy, self._detail

        def containers(self, scope):
            return []

    def _app(self, ping=True, sources=()):
        app = create_app(TestConfig)
        app.es_client.es.ping = lambda: ping
        app.hub._logs = {source.name: source for source in sources}
        app.hub._traces = {}
        return app

    def test_a_cluster_that_answers_false_is_not_connected(self):
        """`ping()` does not raise; it returns False."""
        response = self._app(ping=False).test_client().get('/health')
        self.assertEqual(response.get_json()['elasticsearch'], 'unreachable')
        self.assertEqual(response.get_json()['status'], 'degraded')

    def test_a_configured_source_being_down_is_degraded_not_out_of_service(self):
        """It used to answer 503, and both Kubernetes probes read this
        endpoint — so an unreachable Loki pulled the pod out of the Service
        AND had the kubelet restart the container. WDash still serves sign-in,
        dashboards, the configuration page and every other source; reporting
        that as dead cost more than the outage did.
        """
        app = self._app(sources=[self._Source('lab-loki', healthy=False)])
        response = app.test_client().get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['lab-loki'], 'unreachable')
        self.assertEqual(response.get_json()['status'], 'degraded')
        self.assertEqual(response.get_json()['degraded'], ['lab-loki'])

    def test_a_healthy_source_does_not_drag_the_instance_down(self):
        app = self._app(sources=[self._Source('lab-loki', healthy=True)])
        response = app.test_client().get('/health')
        self.assertEqual(response.get_json()['lab-loki'], 'connected')
        self.assertEqual(response.get_json()['status'], 'healthy')

    def test_a_source_that_raises_is_unreachable_rather_than_fatal(self):
        """One broken adapter must not take the probe itself down."""
        class Exploding(self._Source):
            def health(self):
                raise RuntimeError("boom")

        app = self._app(sources=[Exploding('angry')])
        response = app.test_client().get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['angry'], 'unreachable')

    def test_a_broken_metadata_store_does_take_it_out_of_service(self):
        """The one hard dependency. Accounts and roles live there, so serving
        traffic without it produces nothing but errors — and this is what the
        503 is now reserved for."""
        app = self._app()
        class Broken:
            def count(self): raise RuntimeError("database is gone")
        app.store.users = Broken()
        response = app.test_client().get('/health')
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()['status'], 'unhealthy')

    def test_the_body_carries_no_detail_for_an_anonymous_caller(self):
        """/health needs no sign-in, so its body is public."""
        secret = "http://elastic:hunter2@internal-cluster.example:9200"
        app = self._app(ping=False,
                        sources=[self._Source('lab-loki', healthy=False,
                                              detail=secret)])
        body = app.test_client().get('/health').get_data(as_text=True)
        self.assertNotIn("hunter2", body)
        self.assertNotIn("internal-cluster", body)


class ElasticsearchClientTest(unittest.TestCase):
    """Certificate verification was wired off in code, not configured off.

    Sources added through the config page have carried a `verify_certs` switch
    since they existed. The environment-configured cluster — the one every
    deployment talks to — could not verify anything, and the code said so in a
    TODO rather than in the settings table.
    """

    def _built(self, **overrides):
        from unittest import mock
        from wdash.logs.elasticsearch_client import ElasticsearchClient
        config = {"ELASTICSEARCH_URL": "https://cluster:9200",
                  "ELASTICSEARCH_USERNAME": None, "ELASTICSEARCH_PASSWORD": None}
        config.update(overrides)
        with mock.patch("wdash.logs.elasticsearch_client.Elasticsearch") as built:
            ElasticsearchClient(config)
        return built.call_args.kwargs

    def test_verification_is_off_by_default(self):
        """Stated, so that turning it on is a decision somebody can make.

        The default stays off because flipping it would take the cluster away
        from every deployment using a self-signed certificate, on upgrade,
        with no warning.
        """
        self.assertFalse(self._built()["verify_certs"])

    def test_verification_can_be_turned_on(self):
        self.assertTrue(
            self._built(ELASTICSEARCH_VERIFY_CERTS=True)["verify_certs"])

    def test_a_private_authority_can_be_trusted(self):
        """Verification without a bundle trusts the system store only, which
        is exactly the case an internal cluster is not in."""
        built = self._built(ELASTICSEARCH_VERIFY_CERTS=True,
                            ELASTICSEARCH_CA_CERTS="/etc/ssl/internal.pem")
        self.assertEqual(built["ca_certs"], "/etc/ssl/internal.pem")

    def test_certificate_warnings_are_only_silenced_when_asked_for(self):
        """Silencing them while verifying hides the problem being verified."""
        self.assertTrue(
            self._built(ELASTICSEARCH_VERIFY_CERTS=True)["ssl_show_warn"])
        self.assertFalse(self._built()["ssl_show_warn"])
