"""
Basic tests for WDash application
"""

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from wdash import __version__
from wdash.app import create_app
from wdash.config import Config


class TestConfig(Config):
    """Test configuration"""
    TESTING = True
    SECRET_KEY = 'test-secret-key'


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
            #: How many times /health probed it. One adapter over one client
            #: registered for three signals must be asked once.
            self.asked = 0

        def health(self):
            self.asked += 1
            return self._healthy, self._detail

        def containers(self, scope):
            return []

    class _Cluster:
        """Enough of an `elasticsearch.Elasticsearch` for the adapters'
        `health()`: a `ping()` that answers what it is told and counts."""

        def __init__(self, answers=True):
            self.answers, self.pings = answers, 0

        def ping(self):
            self.pings += 1
            return self.answers

    def _app(self, sources=(), monitors=()):
        app = create_app(TestConfig)
        app.hub._logs = {source.name: source for source in sources}
        app.hub._traces = {}
        app.hub._monitors = {source.name: source for source in monitors}
        return app

    def test_a_monitors_only_backend_is_asked_too(self):
        """It was not. The endpoint built its own list out of the log and
        trace registries, so a Heartbeat cluster — a whole screen and every
        monitor_down alert — could be down while this said healthy, with
        nothing named. Measured: the source's own `health()` answered
        `(False, ...)` and /health answered 200 `{"status": "healthy"}`."""
        app = self._app(monitors=[self._Source('uptime-es', healthy=False)])
        body = app.test_client().get('/health').get_json()
        self.assertEqual(body['uptime-es'], 'unreachable')
        self.assertEqual(body['status'], 'degraded')
        self.assertEqual(body['degraded'], ['uptime-es'])

    def test_a_monitor_adapter_on_the_same_client_costs_no_extra_ping(self):
        """Adding the monitor registry must not turn one stored
        Elasticsearch into three round trips. The report has one slot per
        name, so one probe per name is what fills it."""
        source = self._Source('lab-es', healthy=True)
        app = self._app(sources=[source], monitors=[source])
        app.hub._traces = {'lab-es': source}
        self.assertEqual(
            app.test_client().get('/health').get_json()['lab-es'], 'connected')
        self.assertEqual(source.asked, 1)

    def test_a_source_called_store_does_not_answer_for_the_store(self):
        """One flat report and a name an administrator typed. Measured both
        ways round: a dead metadata store with a healthy source called
        `store` answered 200 `healthy`, and a healthy store with that source
        down answered 503."""
        app = self._app(sources=[self._Source('store', healthy=True)])

        class Broken:
            def count(self): raise RuntimeError("database is gone")
        app.store.users = Broken()

        response = app.test_client().get('/health')
        body = response.get_json()
        self.assertEqual(body['store'], 'unreachable')
        self.assertEqual(body['source:store'], 'connected')
        self.assertEqual(response.status_code, 503)

    def test_a_source_called_store_being_down_does_not_take_it_out(self):
        """The other way: the store is the only hard dependency, and a
        source is not it whatever it is called."""
        app = self._app(sources=[self._Source('store', healthy=False)])
        response = app.test_client().get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['store'], 'connected')
        self.assertEqual(response.get_json()['source:store'], 'unreachable')

    def test_a_source_named_after_a_field_of_the_report_is_not_dropped(self):
        """`status` and `version` were overwritten by the payload itself, so
        such a source vanished from the report without a word."""
        app = self._app(sources=[self._Source('version', healthy=False),
                                 self._Source('status', healthy=False)])
        body = app.test_client().get('/health').get_json()
        self.assertEqual(body['version'], __version__)
        self.assertEqual(body['status'], 'degraded')
        self.assertEqual(body['source:version'], 'unreachable')
        self.assertEqual(body['source:status'], 'unreachable')

    def test_a_cluster_that_answers_false_is_not_connected(self):
        """`ping()` does not raise; it returns False. Through the real
        adapter, as a stored source is built, so the branch that turns a
        False into "unreachable" is the one measured."""
        from wdash.hub.adapters import ElasticsearchLogSource
        app = self._app(sources=[ElasticsearchLogSource(
            self._Cluster(answers=False), name='lab-es')])
        response = app.test_client().get('/health')
        self.assertEqual(response.get_json()['lab-es'], 'unreachable')
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
        app = self._app(sources=[self._Source('lab-loki', healthy=False,
                                              detail=secret)])
        body = app.test_client().get('/health').get_data(as_text=True)
        self.assertNotIn("hunter2", body)
        self.assertNotIn("internal-cluster", body)


class ProbeTest(unittest.TestCase):
    """What each Kubernetes probe reads, and how long it takes to answer.

    /health asked every backend in turn, inside the request: the environment
    cluster twice with a ten-second timeout, then five seconds per Loki,
    Tempo and VictoriaLogs. Measured: one Loki waiting out its timeout made
    it answer in 5.0s, past both probe timeouts; a cluster that accepted and
    never replied made it 20.0s. The kubelet read a slow answer as a dead
    one and restarted a container that was fine.
    """

    class _Slow(HealthTest._Source):
        def __init__(self, name, seconds, healthy=True):
            super().__init__(name, healthy=healthy)
            self.seconds, self.asked = seconds, 0

        def health(self):
            import time
            self.asked += 1
            time.sleep(self.seconds)
            return self._healthy, self._detail

    def _app(self, sources=(), **config):
        app = HealthTest._app(self, sources=sources)
        app.config.update(config)
        return app

    def _timed(self, app, path):
        import time
        started = time.monotonic()
        response = app.test_client().get(path)
        return response, time.monotonic() - started

    def test_liveness_asks_nothing_outside_the_process(self):
        """A restart fixes only the process. Nothing else may decide it."""
        hanging = self._Slow('lab-loki', 5)
        app = self._app(sources=[hanging])

        class Broken:
            def count(self): raise RuntimeError("database is gone")
        app.store.users = Broken()
        response, took = self._timed(app, '/livez')
        self.assertEqual(response.status_code, 200)
        self.assertLess(took, 0.5)
        self.assertEqual(hanging.asked, 0)

    def test_readiness_is_the_store_and_only_the_store(self):
        hanging = self._Slow('lab-loki', 5)
        app = self._app(sources=[hanging])
        response, took = self._timed(app, '/readyz')
        self.assertEqual(response.status_code, 200)
        self.assertLess(took, 0.5)
        self.assertEqual(hanging.asked, 0)

        class Broken:
            def count(self): raise RuntimeError("database is gone")
        app.store.users = Broken()
        self.assertEqual(app.test_client().get('/readyz').status_code, 503)

    def test_a_backend_that_hangs_costs_the_report_its_budget_not_its_timeout(self):
        app = self._app(sources=[self._Slow('lab-loki', 5)],
                        HEALTH_BUDGET_SECONDS=0.5)
        response, took = self._timed(app, '/health')
        self.assertLess(took, 1.5, f"took {took:.1f}s")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['lab-loki'], 'unreachable')
        self.assertEqual(response.get_json()['degraded'], ['lab-loki'])

    def test_the_backends_are_asked_at_once(self):
        """Three that take 0.4s each answer in about 0.4s, not 1.2s."""
        sources = [self._Slow(f'loki-{n}', 0.4) for n in range(3)]
        app = self._app(sources=sources, HEALTH_BUDGET_SECONDS=2)
        response, took = self._timed(app, '/health')
        self.assertLess(took, 1.0, f"took {took:.1f}s")
        self.assertEqual(response.get_json()['status'], 'healthy')

    def test_the_report_is_reused_for_a_while(self):
        """A poller must not hold a worker per poll on a backend that hangs."""
        source = self._Slow('lab-loki', 0)
        app = self._app(sources=[source], HEALTH_CACHE_SECONDS=60)
        for _ in range(3):
            app.test_client().get('/health')
        self.assertEqual(source.asked, 1)
        app.config['HEALTH_CACHE_SECONDS'] = 0
        app.test_client().get('/health')
        self.assertEqual(source.asked, 2)

    def test_one_source_serving_logs_and_traces_is_asked_once(self):
        """One stored Elasticsearch serving both signals is two adapters over
        one client, under one name. It used to be pinged as both — once as
        the log source and once as the trace source."""
        from wdash.hub.adapters import (ElasticsearchLogSource,
                                        ElasticsearchTraceSource)
        cluster = HealthTest._Cluster()
        app = HealthTest._app(self, sources=[
            ElasticsearchLogSource(cluster, name='lab-es')])
        app.hub._traces = {'lab-es': ElasticsearchTraceSource(
            cluster, name='lab-es')}
        payload = app.test_client().get('/health').get_json()
        self.assertEqual(cluster.pings, 1)
        self.assertEqual(payload['lab-es'], 'connected')

    def test_the_probes_answer_before_setup(self):
        """An unclaimed installation sends everything to /setup, and a probe
        that got a redirect would never pass."""
        app = self._app()
        for path in ('/livez', '/readyz', '/health'):
            with self.subTest(path=path):
                self.assertEqual(app.test_client().get(path).status_code, 200)
