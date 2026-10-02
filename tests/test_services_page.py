"""
The service table, and the backends that cannot fill one.

Measured before any of it was written, against the lab's three trace
backends, because the answer decided the shape:

  * Elasticsearch answers all five columns in ONE request, both in the APM
    shape and the collector's.
  * Jaeger's metrics endpoints answer 501 — "metrics querying is currently
    disabled" — without a separate Prometheus behind them, and `/api/traces`
    caps at 200 traces server-side: asked for 1500, returned 200.
  * Tempo 2.6.1's TraceQL metrics answer 500 — "empty ring" — without its
    metrics-generator, and its search caps at 200 the same way.

So a throughput counted from Jaeger or Tempo would be a floor printed as a
number. The table is an Elasticsearch feature, the capability says so, and
the page names the sources it is NOT made of rather than quietly leaving
their services out.
"""

import datetime as dt
import os
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub.models import ServiceMetrics, ServicePoint  # noqa: E402
from wdash.hub.source import Capability  # noqa: E402

NOW = dt.datetime(2026, 10, 2, 2, 0, tzinfo=dt.timezone.utc)


class WhatARowSaysTest(unittest.TestCase):
    """The two numbers the model derives, and the one it refuses to."""

    def test_throughput_is_per_minute_of_the_window_asked_for(self):
        row = ServiceMetrics(name="api", calls=1200, window_seconds=3600)
        self.assertAlmostEqual(row.per_minute, 20.0)

    def test_a_window_of_nothing_is_not_divided_by(self):
        self.assertEqual(ServiceMetrics(name="api", calls=5).per_minute, 0.0)

    def test_the_failure_rate_of_no_calls_is_not_zero(self):
        """Zero per cent of nothing is a claim. The page draws an empty cell
        for None and a number for 0.0, and those are different readings."""
        self.assertIsNone(ServiceMetrics(name="api").failed_ratio)
        self.assertEqual(
            ServiceMetrics(name="api", calls=10).failed_ratio, 0.0)


class TheSparklineTest(unittest.TestCase):
    """Drawn server-side, and nothing rather than a misleading line."""

    def _spark(self, values):
        from wdash.api.trace_routes import _spark
        return _spark(values)

    def test_one_reading_draws_nothing(self):
        """A polyline needs two points, and a single mark with no line is a
        dot somebody reads as a trend."""
        self.assertIsNone(self._spark([5.0]))

    def test_all_zeroes_draw_nothing(self):
        """A line along the bottom reads as a measurement of zero. Nothing
        happened is not the same reading as everything took no time."""
        self.assertIsNone(self._spark([0, 0, 0, 0]))

    def test_a_gap_breaks_the_line_rather_than_joining_across_it(self):
        shape = self._spark([1.0, 2.0, None, 4.0, 5.0])
        self.assertEqual(len(shape["runs"]), 2)

    def test_the_throughput_sparkline_is_a_rate_not_a_count(self):
        """The number beside it is per minute. A sparkline on a different
        unit than its number is two readings of one thing, and only one of
        them is labelled."""
        from wdash.api.trace_routes import _service_row
        # FIVE slices of a ten-minute window: two minutes each, so a slice
        # holding 20 calls is 10 a minute. One slice per minute would make
        # the count and the rate the same number, and the check blind.
        row = ServiceMetrics(name="api", calls=60, window_seconds=600)
        row.series = tuple(
            ServicePoint(timestamp=NOW + dt.timedelta(minutes=2 * i),
                         latency_ms=5.0, calls=(i + 1) * 4)
            for i in range(5))
        drawn = _service_row(row)
        self.assertAlmostEqual(drawn["throughput_spark"]["peak"], 10.0,
                               places=1)

    def test_the_peak_is_carried_for_the_label(self):
        """The shape has no axis, so the only way to read a magnitude off it
        is the title — which is why it is on every one."""
        self.assertEqual(self._spark([1.0, 9.0, 3.0])["peak"], 9.0)


class WhatABackendCanMeasureTest(unittest.TestCase):
    """The capability, and the refusal behind it."""

    def test_only_elasticsearch_declares_it(self):
        from wdash.hub.adapters import (ElasticsearchTraceSource,
                                        JaegerTraceSource, TempoTraceSource)
        es = ElasticsearchTraceSource(client=object())
        self.assertIn(Capability.SERVICE_METRICS, es.capabilities)
        for cls in (JaegerTraceSource, TempoTraceSource):
            with self.subTest(backend=cls.__name__):
                source = cls("http://localhost:1")
                self.assertIn(Capability.SERVICE_LIST, source.capabilities)
                self.assertNotIn(Capability.SERVICE_METRICS,
                                 source.capabilities)

    def test_a_backend_that_cannot_refuses_with_a_reason(self):
        """Not an empty list. An empty table is indistinguishable from a
        window with no traffic in it, and only one of those is true."""
        from wdash.hub.adapters import JaegerTraceSource
        source = JaegerTraceSource("http://localhost:1")
        with self.assertRaises(NotImplementedError) as refused:
            source.service_metrics(None, None)
        said = str(refused.exception)
        self.assertIn("cannot measure services", said)
        self.assertIn("jaeger", said.lower())


class TheTableOnThePageTest(unittest.TestCase):
    """Rendered, with a source that can measure and one that cannot."""

    def setUp(self):
        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "services"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        grant(self.app, "u", ["traces:read"], indices=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": ["traces:read"],
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": []}
            session["_user_id"] = "1"

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _hub(self, *sources):
        from wdash.hub import Hub
        hub = Hub()
        for source in sources:
            hub.add_traces(source)
        self.app.hub = hub
        return hub

    def _measuring(self, rows, name="es"):
        from wdash.hub.models import PartialList
        from wdash.hub.source import TraceSource

        class Measuring(TraceSource):
            backend = "elasticsearch"

            def __init__(self):
                self.name = name

            @property
            def capabilities(self):
                return frozenset({Capability.TRACE_SEARCH,
                                  Capability.SERVICE_LIST,
                                  Capability.SERVICE_METRICS})

            def health(self):
                return True, "ok"

            def trace(self, trace_id, window, scope):
                return None

            def services(self, window, scope):
                return PartialList([])

            def containers(self, scope):
                return []

            def service_metrics(self, window, scope):
                return PartialList(list(rows))

        return Measuring()

    def _blind(self, name="jaeger"):
        from wdash.hub.models import PartialList
        from wdash.hub.source import TraceSource

        class Blind(TraceSource):
            backend = "jaeger"

            def __init__(self):
                self.name = name

            @property
            def capabilities(self):
                return frozenset({Capability.TRACE_SEARCH,
                                  Capability.SERVICE_LIST})

            def health(self):
                return True, "ok"

            def trace(self, trace_id, window, scope):
                return None

            def services(self, window, scope):
                return PartialList([])

            def containers(self, scope):
                return []

        return Blind()

    @staticmethod
    def _row(name, **extra):
        """A row whose SERIES agrees with its totals — a fixture where a
        service with no calls still has a sparkline would be testing a page
        against data the adapter cannot produce."""
        row = ServiceMetrics(name=name, window_seconds=3600, **extra)
        if row.calls:
            row.series = tuple(
                ServicePoint(timestamp=NOW + dt.timedelta(minutes=i),
                             latency_ms=10.0 + i, calls=5, failed=i % 2)
                for i in range(6))
        else:
            row.series = tuple(
                ServicePoint(timestamp=NOW + dt.timedelta(minutes=i))
                for i in range(6))
        return row

    def page(self):
        return self.client.get("/services").get_data(as_text=True)

    def test_a_service_is_a_row(self):
        self._hub(self._measuring([
            self._row("api-gateway", environment="production",
                      latency_ms=54.0, calls=1200, failed=0)]))
        page = self.page()
        self.assertIn("api-gateway", page)
        self.assertIn("production", page)
        self.assertIn("54 ms", page)

    def test_the_throughput_is_the_rate_not_the_count(self):
        """1,200 entry spans over an hour is 20 a minute, and the count is
        in the title where somebody can check the rate against it."""
        self._hub(self._measuring([self._row("api", calls=1200)]))
        page = self.page()
        self.assertIn("20.0 tpm", page)
        self.assertIn("1,200 entry span(s)", page)

    def test_a_service_nothing_called_shows_no_failure_rate(self):
        """Checked by the thing the percentage branch renders and the empty
        one does not — its title. Asserting the string "0.0%" is absent
        matches "peak 20.0%" in a sparkline's own label, which is a test
        passing for the wrong reason or failing for one."""
        self._hub(self._measuring([self._row("quiet", calls=0)]))
        page = self.page()
        self.assertNotIn('title="0 of 0"', page)
        self.assertIn('<span class="text-muted">&mdash;</span>', page)

    def test_a_source_that_cannot_measure_is_named_rather_than_dropped(self):
        """The failure this page would otherwise introduce: a table silently
        missing a backend's services, which reads as that backend having
        none."""
        self._hub(self._measuring([self._row("api")]), self._blind())
        page = self.page()
        self.assertIn("jaeger", page)
        self.assertIn("200 traces", page,
                      "the page does not say WHY that backend is left out")

    def test_a_source_that_can_measure_is_not_complained_about(self):
        self._hub(self._measuring([self._row("api")]))
        self.assertNotIn("Not from", self.page())

    def test_with_no_measuring_source_the_page_says_what_to_add(self):
        """Never "no services": that is a statement about the traffic, and
        this is a statement about the backend."""
        self._hub(self._blind())
        page = self.page()
        self.assertIn("No source here can measure services", page)
        self.assertIn("Elasticsearch", page)

    def test_an_empty_window_says_so_as_a_window(self):
        self._hub(self._measuring([]))
        self.assertIn("No service answered a request", self.page())

    def test_a_source_that_failed_says_so_rather_than_drawing_nothing(self):
        from wdash.hub.source import TraceSource

        class Broken(self._measuring([]).__class__):
            def service_metrics(self, window, scope):
                raise RuntimeError("the cluster refused the aggregation")

        self._hub(Broken())
        self.assertIn("the cluster refused", self.page())

    def test_a_row_links_to_that_service_s_traces_in_the_same_window(self):
        """The next question anybody asks of a row. The link carries BOTH
        the service and the window, because a table read over six hours
        opening a trace list over twenty-four is two screens disagreeing
        about what somebody is looking at."""
        self._hub(self._measuring([self._row("api-gateway", calls=10)]))
        page = self.client.get("/services?window=6h").get_data(as_text=True)
        self.assertIn("/traces?service=api-gateway&amp;window=6h", page)

    def test_every_window_this_page_offers_can_be_handed_over(self):
        """The two pickers are separate ladders, and a window the other page
        does not offer is dropped on arrival — leaving somebody who clicked
        from fifteen minutes looking at twenty-four, labelled correctly and
        still not what they were reading."""
        from wdash.api.trace_routes import SERVICE_RANGES
        traces = pathlib.Path(
            os.path.join(os.path.dirname(__file__), "..",
                         "templates", "traces.html")).read_text()
        picker = traces.split('id="timeRange"')[1].split("</select>")[0]
        offered = set(re.findall(r'<option value="([0-9a-z]+)"', picker))
        missing = sorted({value for value, _ in SERVICE_RANGES} - offered)
        self.assertEqual(missing, [],
                         "the Services table offers windows the Traces page "
                         "cannot open on")

    def test_exactly_one_navigation_item_is_the_current_page(self):
        """Two items of one blueprint both lit up when this page was added:
        the strip marks by blueprint so that `/traces/<id>` is still Traces.
        Two current pages at once is the navbar saying something that cannot
        be true."""
        self._hub(self._measuring([self._row("api")]))
        for path, expected in (("/services", "Services"), ("/traces", "Traces")):
            with self.subTest(path=path):
                html = self.client.get(path).get_data(as_text=True)
                active = [name.strip() for name in re.findall(
                    r'nav-link active[^>]*>\s*<i[^>]*></i>\s*([A-Za-z ]+)', html)]
                self.assertEqual(active, [expected])


class WhatTheRequestAsksForTest(unittest.TestCase):
    """The shape of the aggregation, where a cluster cannot show it.

    `_grouped` and `_search_groups` are replaced so the request can be read
    before it is sent. Measuring this against the lab would only prove what
    the lab's mappings happen to have.
    """

    def _asked(self, schema):
        from wdash.hub.adapters import ElasticsearchTraceSource
        from wdash.hub.query import TimeWindow
        from wdash.hub.scope import Scope

        source = ElasticsearchTraceSource(client=object())
        source._grouped = lambda scope: ({schema: ["i"]}, [])
        captured = []

        def _search_groups(groups, requests, failures):
            captured.extend(body for _, body in requests)
            return [None for _ in groups]

        source._search_groups = _search_groups
        source.service_metrics(TimeWindow.of("1h"),
                               Scope(principal="x", containers=("*",),
                                     trace_containers=("*",), services=None))
        return captured[0]

    def test_a_shape_with_an_environment_is_asked_for_one(self):
        from wdash.hub.adapters.es_trace_schema import ApmSpanSchema
        aggs = self._asked(ApmSpanSchema())["aggs"]["services"]["aggs"]
        self.assertEqual(aggs["environment"]["terms"]["field"],
                         "service.environment")

    def test_a_shape_with_none_is_not(self):
        """A terms aggregation on a field name of "" is a clause asking
        nothing, and the column it fills would be an empty one presented as
        the environment."""
        from wdash.hub.adapters.es_trace_schema import ApmSpanSchema

        class NoEnvironment(ApmSpanSchema):
            environment_field = ""

        aggs = self._asked(NoEnvironment())["aggs"]["services"]["aggs"]
        self.assertNotIn("environment", aggs)

    def test_only_entry_spans_are_asked_about(self):
        from wdash.hub.adapters.es_trace_schema import ApmSpanSchema
        schema = ApmSpanSchema()
        clauses = self._asked(schema)["query"]["bool"]["filter"]
        self.assertIn(schema.entry_filter(), clauses)


class TwoShapesOneServiceTest(unittest.TestCase):
    """A cluster migrating from the APM agents to the collector holds the
    same service name in both shapes, and the table is one row."""

    def _merged(self, apm_calls, apm_ms, otel_calls, otel_ms):
        from wdash.hub.adapters import ElasticsearchTraceSource
        from wdash.hub.adapters.es_trace_schema import (ApmSpanSchema,
                                                        OtelSpanSchema)
        from wdash.hub.query import TimeWindow
        from wdash.hub.scope import Scope

        def answer(calls, average, failed=0):
            return {"aggregations": {"services": {"buckets": [{
                "key": "api-gateway", "doc_count": calls,
                "latency": {"value": average},
                "failed": {"doc_count": failed},
                "environment": {"buckets": [{"key": "production"}]},
                "over_time": {"buckets": []}}]}}}

        source = ElasticsearchTraceSource(client=object())
        apm, otel = ApmSpanSchema(), OtelSpanSchema()
        source._grouped = lambda scope: ({apm: ["a"], otel: ["o"]}, [])
        # Microseconds for APM, nanoseconds for the collector.
        source._search_groups = lambda groups, requests, failures: [
            answer(apm_calls, apm_ms * 1000.0),
            answer(otel_calls, otel_ms * 1e6)]
        rows = list(source.service_metrics(
            TimeWindow.of("1h"),
            Scope(principal="x", containers=("*",), trace_containers=("*",),
                  services=None)))
        return rows[0]

    def test_the_two_are_one_row(self):
        row = self._merged(100, 10.0, 100, 10.0)
        self.assertEqual(row.calls, 200)

    def test_each_shape_is_read_in_its_own_unit(self):
        """Microseconds on the APM side, nanoseconds on the collector's. Read
        in the wrong one a service answering in 10ms reads as 10,000."""
        row = self._merged(100, 10.0, 100, 10.0)
        self.assertAlmostEqual(row.latency_ms, 10.0, places=1)

    def test_the_merged_latency_is_weighted_by_the_calls(self):
        """A mean of means weights a service's quiet half as heavily as its
        busy one: 900 calls at 10ms beside 100 at 110ms is 20ms, not 60."""
        row = self._merged(900, 10.0, 100, 110.0)
        self.assertAlmostEqual(row.latency_ms, 20.0, places=1)


def _lab_elasticsearch():
    from tests import lab
    if lab.volume("es-logs") is None:
        return None
    from elasticsearch import Elasticsearch
    return Elasticsearch(hosts=[lab.ES], request_timeout=25)


class AgainstTheLabTest(unittest.TestCase):
    """The aggregation, against a real cluster holding both trace shapes."""

    @classmethod
    def setUpClass(cls):
        client = _lab_elasticsearch()
        if client is None:
            raise unittest.SkipTest("es-logs is not running")
        from wdash.hub.adapters import ElasticsearchTraceSource
        cls.source = ElasticsearchTraceSource(client)

    def rows(self, window="24h"):
        from wdash.hub.query import TimeWindow
        from wdash.hub.scope import Scope
        return list(self.source.service_metrics(
            TimeWindow.of(window),
            Scope(principal="x", containers=("*",), trace_containers=("*",),
                  services=None)))

    def test_a_real_cluster_fills_every_column(self):
        rows = self.rows()
        if not rows:
            self.skipTest("no trace spans in the last 24 hours — "
                          "cd lab && ./lab.sh seed elasticsearch")
        row = rows[0]
        self.assertTrue(row.name)
        self.assertTrue(row.environment, "the environment column is empty")
        self.assertIsNotNone(row.latency_ms)
        self.assertGreater(row.calls, 0)
        self.assertIsNotNone(row.failed_ratio)
        self.assertTrue(row.series, "no sparkline to draw")

    def test_the_latency_is_in_milliseconds_rather_than_the_backend_unit(self):
        """The APM shape stores microseconds and the collector's stores
        nanoseconds. Read in either, a service answering in a fifth of a
        second reads as 200,000 or 200,000,000 — a number the column's own
        "ms" would then be lying about."""
        rows = self.rows()
        if not rows:
            self.skipTest("no trace spans in the last 24 hours")
        for row in rows:
            with self.subTest(service=row.name):
                self.assertLess(row.latency_ms, 60_000,
                                f"{row.name} answers in {row.latency_ms} ms, "
                                f"which is a minute — the unit is wrong")

    def test_a_service_with_failures_has_a_rate_above_zero(self):
        """The lab seeds failures. A filter counting nothing would leave
        every rate at 0.0, which is a number the page draws confidently."""
        rows = self.rows()
        if not rows:
            self.skipTest("no trace spans in the last 24 hours")
        self.assertTrue(
            any((row.failed_ratio or 0) > 0 for row in rows),
            "no service failed anything, so a filter counting nothing would "
            "read exactly like this answer")

    def test_only_entry_spans_are_counted(self):
        """A service's latency is the time it took to ANSWER. Counting the
        spans inside somebody else's request makes a service look slower the
        more it delegates, and puts a database on the table as though it
        served requests of its own."""
        rows = self.rows()
        if not rows:
            self.skipTest("no trace spans in the last 24 hours")
        names = {row.name for row in rows}
        for leaf in ("postgres", "redis", "elasticsearch"):
            self.assertNotIn(leaf, names,
                             f"{leaf} is on the table, so inner spans are "
                             f"being counted as traffic")

    def test_the_sparkline_covers_the_window_rather_than_the_data(self):
        """Extended bounds, so a service that stopped halfway shows a line
        that stops halfway rather than one stretched over the window."""
        rows = self.rows()
        if not rows:
            self.skipTest("no trace spans in the last 24 hours")
        self.assertGreaterEqual(len(rows[0].series), 20)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
