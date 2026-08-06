"""
Synthetic monitors and TLS certificates.

A third signal. Logs say what happened inside the system, traces say how a
request moved through it, and neither can tell you the system stopped
answering: an application that is unreachable writes no logs and emits no
spans, which looks exactly like a quiet night.

Everything asserted here about the Heartbeat document shape was read off
documents a real Heartbeat 8.19 wrote into a real cluster — see
`lab/synthetics/`. The fixtures below are trimmed copies of those, not
inventions.
"""

import datetime as dt
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub.adapters.es_monitors import (  # noqa: E402
    DEFAULT_PATTERNS, ElasticsearchMonitorSource, _certificate, _dig, _status,
)
from wdash.hub.fanout import FanOutMonitorSource  # noqa: E402
from wdash.hub.models import DOWN, UNKNOWN, UP, Certificate, Monitor, MonitorPage  # noqa: E402
from wdash.hub.query import TimeWindow  # noqa: E402
from wdash.hub.scope import Scope  # noqa: E402


def _now():
    return dt.datetime.now(dt.timezone.utc)


class NotADict:
    """What elasticsearch-py hands back.

    `ObjectApiResponse` subscripts and `.get`s like a dictionary and is
    neither a `dict` nor a `Mapping`. Every fake in this file wraps its
    top-level response in this, because a fake returning a plain dict cannot
    reproduce the bug that shipped: `_dig` checked `isinstance(x, dict)`, took
    the default for every path starting at the response, and the monitor
    listing came back empty against a cluster with six monitors in it.
    """

    def __init__(self, payload):
        self._payload = payload

    def __getitem__(self, key):
        return self._payload[key]

    def get(self, key, default=None):
        return self._payload.get(key, default)


#: A real Heartbeat document, trimmed. Two things here are the whole reason
#: the adapter is not a one-liner: `summary.status` sits beside
#: `monitor.status` and means something different, and the certificate is
#: under `tls.server.x509` rather than the flat `tls.certificate_*` fields.
def _document(monitor_id="lab-http-up", name="Lab endpoint", status=UP,
              summary_status=None, tls_days=None, error=None, kind="http"):
    source = {
        "@timestamp": _now().isoformat().replace("+00:00", "Z"),
        "monitor": {"id": monitor_id, "name": name, "type": kind,
                    "status": status, "duration": {"us": 5974}},
        "url": {"full": f"https://{monitor_id}.example:8443/"},
        "summary": {"status": summary_status or status, "up": 1, "down": 0},
        "tags": ["lab"],
    }
    if error:
        source["error"] = {"message": error, "type": "validate"}
    if tls_days is not None:
        expiry = _now() + dt.timedelta(days=tls_days)
        source["tls"] = {
            "server": {
                "x509": {
                    "subject": {"common_name": f"{monitor_id}.example"},
                    "issuer": {"common_name": "Warewave Lab"},
                    "not_before": (_now() - dt.timedelta(days=1)).isoformat(),
                    "not_after": expiry.isoformat().replace("+00:00", "Z"),
                    "public_key_algorithm": "RSA",
                    "public_key_size": 2048,
                    "signature_algorithm": "SHA256-RSA",
                    "serial_number": "42",
                },
                "hash": {"sha256": "abc123"},
            },
        }
    return {"_index": ".ds-heartbeat-000001", "_id": monitor_id + "-1",
            "_source": source}


class FakeElasticsearch:
    """Answers the aggregation the adapter actually issues."""

    def __init__(self, documents=(), fail=False):
        self.documents = list(documents)
        self.fail = fail
        self.requests = []

    def ping(self):
        return True

    def search(self, index=None, **kwargs):
        self.requests.append({"index": index, **kwargs})
        if self.fail:
            raise RuntimeError("cluster unreachable")
        if kwargs.get("size", 0) > 0:          # a history query
            return NotADict({"hits": {"hits": self.documents}})
        wants_series = "series" in json.dumps(kwargs.get("aggs") or {})
        buckets = []
        for document in self.documents:
            bucket = {"key": document["_source"]["monitor"]["id"],
                      "latest": {"hits": {"hits": [document]}}}
            if wants_series:
                # Shaped like the real response: three buckets, the middle one
                # empty. A fake that answers the listing but not the histogram
                # lets the wiring between them be deleted with the tests still
                # green — which is exactly what happened.
                bucket["series"] = {"buckets": [
                    {"key_as_string": "2026-08-06T10:00:00.000Z",
                     "doc_count": 3, "duration": {"value": 5000.0},
                     "down": {"doc_count": 0}},
                    {"key_as_string": "2026-08-06T10:05:00.000Z",
                     "doc_count": 0, "duration": {"value": None},
                     "down": {"doc_count": 0}},
                    {"key_as_string": "2026-08-06T10:10:00.000Z",
                     "doc_count": 3, "duration": {"value": 9000.0},
                     "down": {"doc_count": 1}},
                ]}
            buckets.append(bucket)
        return NotADict({"hits": {"total": {"value": len(self.documents)}},
                         "aggregations": {"monitors": {"buckets": buckets}}})


class ResponseTraversalTest(unittest.TestCase):
    """The bug that a dict-shaped fake cannot find."""

    def test_it_reads_through_the_client_s_response_object(self):
        response = NotADict({"aggregations": {"monitors": {"buckets": [1, 2]}}})
        self.assertEqual(_dig(response, "aggregations.monitors.buckets"), [1, 2])

    def test_a_missing_branch_is_the_default_not_an_error(self):
        self.assertIsNone(_dig(NotADict({"a": {}}), "a.b.c"))

    def test_a_stored_none_is_not_a_missing_key(self):
        """`{"error": None}` means "no error", and a sentinel is what tells
        that apart from the key being absent."""
        self.assertIsNone(_dig({"error": None}, "error", default="absent"))

    def test_it_stops_at_a_leaf_rather_than_raising(self):
        self.assertEqual(_dig({"a": "leaf"}, "a.b", default="x"), "x")


class StatusTest(unittest.TestCase):
    """`summary.status` and `monitor.status` are different questions."""

    def test_the_summary_wins_over_the_attempt(self):
        """A check configured to retry that failed once and then succeeded
        writes `monitor.status: down` and `summary.status: up`. Reporting the
        attempt is reporting flapping the operator configured away."""
        self.assertEqual(
            _status({"monitor": {"status": DOWN}, "summary": {"status": UP}}), UP)

    def test_without_a_summary_the_attempt_is_all_there_is(self):
        self.assertEqual(_status({"monitor": {"status": DOWN}}), DOWN)

    def test_anything_unrecognised_is_unknown_not_up(self):
        """"No answer" is not "yes"."""
        self.assertEqual(_status({"monitor": {"status": "weird"}}), UNKNOWN)
        self.assertEqual(_status({}), UNKNOWN)


class CertificateTest(unittest.TestCase):
    def test_days_are_rounded_not_truncated(self):
        """`timedelta.days` throws the remainder away, so a certificate with
        eleven days left — which is really ten days and twenty-three hours —
        would read as ten. Every number on the page would be one low, in the
        direction that makes expiry look further off than it is."""
        certificate = Certificate(not_after=_now() + dt.timedelta(days=11))
        self.assertEqual(certificate.days_remaining, 11)

    def test_an_hour_past_expiry_is_expired_and_zero_days(self):
        """Zero days is "expires today". Only the sign of the interval can
        say it has already gone."""
        certificate = Certificate(not_after=_now() - dt.timedelta(hours=1))
        self.assertEqual(certificate.days_remaining, 0)
        self.assertTrue(certificate.expired)

    def test_no_expiry_is_none_rather_than_zero(self):
        """Zero would sort to the top and read as the most urgent row on the
        page."""
        self.assertIsNone(Certificate().days_remaining)
        self.assertFalse(Certificate().expired)

    def test_it_is_read_from_the_ecs_fields(self):
        certificate = _certificate(_document(tls_days=30)["_source"])
        self.assertEqual(certificate.issuer, "Warewave Lab")
        self.assertEqual(certificate.key_size, 2048)
        self.assertEqual(certificate.fingerprint, "abc123")

    def test_a_check_that_saw_no_certificate_has_none(self):
        """Not an empty Certificate: an empty one would appear in the TLS tab
        as a row with no expiry, which reads as a certificate nobody can
        read rather than a check that never used TLS."""
        self.assertIsNone(_certificate(_document()["_source"]))

    def test_an_ecdsa_key_is_described_by_its_curve(self):
        """Found by pointing a monitor at a real endpoint. Google's
        certificate is ECDSA, and ECDSA certificates carry
        `public_key_curve: P-256` and NO `public_key_size` — so the page said
        `ECDSA-0`, which is not a key. The lab's own certificates are all RSA
        and never showed it."""
        source = dict(_document(tls_days=60)["_source"])
        source["tls"]["server"]["x509"] = {
            "not_after": (_now() + dt.timedelta(days=60)).isoformat(),
            "public_key_algorithm": "ECDSA",
            "public_key_curve": "P-256",
            "subject": {"common_name": "www.example.com"},
            "issuer": {"common_name": "Example CA"},
        }
        certificate = _certificate(source)
        self.assertEqual(certificate.key_curve, "P-256")
        self.assertEqual(certificate.key_description, "ECDSA P-256")

    def test_an_rsa_key_is_described_by_its_size(self):
        self.assertEqual(
            _certificate(_document(tls_days=30)["_source"]).key_description,
            "RSA-2048")

    def test_a_key_with_neither_is_not_given_a_fabricated_number(self):
        self.assertEqual(Certificate(key_algorithm="Ed25519").key_description,
                         "Ed25519")
        self.assertEqual(Certificate().key_description, "")

    def test_the_flat_field_is_still_read_for_older_agents(self):
        source = {"tls": {"certificate_not_valid_after":
                          (_now() + dt.timedelta(days=5)).isoformat()}}
        self.assertEqual(_certificate(source).days_remaining, 5)


class MonitorListingTest(unittest.TestCase):
    def setUp(self):
        self.window = TimeWindow.of("1h")
        self.scope = Scope(containers=("*",))

    def _source(self, documents, **kwargs):
        return ElasticsearchMonitorSource(
            FakeElasticsearch(documents, **kwargs), name="lab")

    def test_one_row_per_monitor(self):
        source = self._source([_document("a"), _document("b")])
        self.assertEqual(len(source.monitors(self.window, self.scope).monitors), 2)

    def test_only_summary_documents_are_counted(self):
        """A retry group writes one document per attempt and a summary only on
        the last. Without the filter, one check is counted several times."""
        source = self._source([_document()])
        source.monitors(self.window, self.scope)
        query = json.dumps(source._es.requests[0]["query"])
        self.assertIn("summary.status", query)
        self.assertIn("exists", query)

    def test_down_monitors_sort_first(self):
        """A list ordered by id puts the one thing needing attention wherever
        the alphabet happens to place it.

        The down monitor is deliberately named LAST alphabetically. Named
        first, this test passes against a plain sort by id — which is the
        behaviour it exists to reject.
        """
        source = self._source([_document("aa-up", name="Aardvark"),
                               _document("zz-down", name="Zebra",
                                         status=DOWN, summary_status=DOWN)])
        monitors = source.monitors(self.window, self.scope).monitors
        self.assertEqual([m.id for m in monitors], ["zz-down", "aa-up"])

    def test_monitors_of_the_same_status_are_sorted_by_name(self):
        """Otherwise the list reorders itself between refreshes as the
        aggregation returns buckets in whatever order it likes."""
        source = self._source([_document("m2", name="Zebra"),
                               _document("m1", name="Aardvark")])
        monitors = source.monitors(self.window, self.scope).monitors
        self.assertEqual([m.name for m in monitors], ["Aardvark", "Zebra"])

    def test_the_error_message_is_carried(self):
        source = self._source([_document(status=DOWN, summary_status=DOWN,
                                         error="received status code 500")])
        monitor = source.monitors(self.window, self.scope).monitors[0]
        self.assertIn("500", monitor.error)

    def test_duration_is_milliseconds_not_microseconds(self):
        source = self._source([_document()])
        monitor = source.monitors(self.window, self.scope).monitors[0]
        self.assertAlmostEqual(monitor.duration_ms, 5.974, places=3)

    def test_a_failing_cluster_is_partial_rather_than_empty(self):
        """Empty is what "no monitors configured" looks like."""
        page = self._source([], fail=True).monitors(self.window, self.scope)
        self.assertTrue(page.partial)
        self.assertEqual(page.monitors, [])
        self.assertTrue(page.warnings)

    def test_certificates_come_from_the_same_listing(self):
        """Built from the monitor list rather than a second query, so the two
        tabs cannot disagree about what is on the wire."""
        source = self._source([_document("plain"),
                               _document("secure", tls_days=9)])
        certificates = source.certificates(self.window, self.scope)
        self.assertEqual([m.id for m in certificates], ["secure"])

    def test_certificates_are_sorted_by_what_expires_first(self):
        source = self._source([_document("late", tls_days=200),
                               _document("soon", tls_days=3)])
        certificates = source.certificates(self.window, self.scope)
        self.assertEqual([m.id for m in certificates], ["soon", "late"])

    def test_it_reads_heartbeat_indices_by_default(self):
        """`*` would make every listing scan the whole cluster and find
        nothing — slowly, and looking like "no monitors configured"."""
        self.assertEqual(self._source([])._patterns, DEFAULT_PATTERNS)


class FanOutTest(unittest.TestCase):
    """Two agents watching one endpoint is the point, not a duplicate."""

    class _Source:
        capabilities = frozenset({"monitor_list"})

        def __init__(self, name, monitors, fail=False):
            self.name = name
            self._monitors = monitors
            self._fail = fail

        def monitors(self, window, scope):
            if self._fail:
                raise RuntimeError("unreachable")
            return MonitorPage(monitors=self._monitors, sources=(self.name,))

        def certificates(self, window, scope):
            return []

        def history(self, monitor_id, window, scope):
            return []

        def health(self):
            return True, "ok"

        def containers(self, scope):
            return []

    def test_the_same_monitor_from_two_places_stays_two_rows(self):
        """"Up from Frankfurt, down from Singapore" IS the answer. Collapsing
        it throws away the only thing the second agent was installed to say,
        and which one survives depends on dictionary order."""
        fanout = FanOutMonitorSource([
            self._Source("frankfurt", [Monitor(id="api", name="API",
                                               status=UP, source="frankfurt")]),
            self._Source("singapore", [Monitor(id="api", name="API",
                                               status=DOWN, source="singapore")]),
        ])
        page = fanout.monitors(None, None)
        self.assertEqual(len(page.monitors), 2)
        self.assertEqual(page.counts, {UP: 1, DOWN: 1, UNKNOWN: 0})

    def test_a_failed_source_makes_the_page_partial_and_names_itself(self):
        fanout = FanOutMonitorSource([
            self._Source("ok", [Monitor(id="a", status=UP, source="ok")]),
            self._Source("broken", [], fail=True),
        ])
        page = fanout.monitors(None, None)
        self.assertTrue(page.partial)
        self.assertEqual(page.missing_sources, ("broken",))
        # And the monitors that DID answer are still shown.
        self.assertEqual(len(page.monitors), 1)


class RoleUpgradeTest(unittest.TestCase):
    """`monitors:read` for installations that already exist.

    Changing DEFAULT_ROLES only affects a database being seeded. Without the
    migration, everybody upgrading — including the administrator — would find
    a screen nobody can open, which looks exactly like a broken page.
    """

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.path)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.path + suffix):
                os.unlink(self.path + suffix)

    def _database_at_version_seven(self, roles):
        from datetime import datetime, timezone

        from sqlalchemy import text

        from wdash.store.database import build_engine
        from wdash.store.schema import metadata
        engine = build_engine(f"sqlite:///{self.path}")
        with engine.begin() as connection:
            metadata.create_all(connection)
            for name, permissions in roles.items():
                connection.execute(text(
                    "INSERT INTO wdash_roles (name, permissions, containers,"
                    " trace_containers, services, groups, updated_at)"
                    " VALUES (:n, :p, '[]', '[]', '[]', '[]', :t)"),
                    {"n": name, "p": json.dumps(permissions),
                     "t": datetime.now(timezone.utc)})
            for version in range(1, 8):
                connection.execute(text(
                    "INSERT INTO wdash_schema_version (version, applied_at)"
                    " VALUES (:v, :t)"),
                    {"v": version, "t": datetime.now(timezone.utc)})
        return engine

    def _permissions(self, engine):
        from sqlalchemy import text
        with engine.connect() as connection:
            return {row["name"]: json.loads(row["permissions"])
                    for row in connection.execute(text(
                        "SELECT name, permissions FROM wdash_roles")).mappings()}

    def test_an_existing_administrator_can_open_the_screen(self):
        from wdash.store.migrations import migrate
        engine = self._database_at_version_seven({
            "admin": ["logs:read", "system:admin"],
            "editor": ["logs:read", "dashboard:edit"],
        })
        migrate(engine)
        permissions = self._permissions(engine)
        engine.dispose()
        self.assertIn("monitors:read", permissions["admin"])

    def test_nobody_else_is_granted_anything(self):
        """`system:admin` already means everything, so this grants nothing
        that was not implied. Giving an editor sight of every monitored
        endpoint is a decision, not a migration."""
        from wdash.store.migrations import migrate
        engine = self._database_at_version_seven({
            "admin": ["logs:read", "system:admin"],
            "editor": ["logs:read", "dashboard:edit"],
        })
        migrate(engine)
        permissions = self._permissions(engine)
        engine.dispose()
        self.assertNotIn("monitors:read", permissions["editor"])

    def test_running_it_twice_does_not_duplicate_the_permission(self):
        from wdash.store.migrations import _grant_monitors_to_admins, migrate
        engine = self._database_at_version_seven(
            {"admin": ["logs:read", "system:admin"]})
        migrate(engine)
        with engine.begin() as connection:
            _grant_monitors_to_admins(connection)
        permissions = self._permissions(engine)
        engine.dispose()
        self.assertEqual(permissions["admin"].count("monitors:read"), 1)


if __name__ == "__main__":
    unittest.main()


class SparklineTest(unittest.TestCase):
    """The shape drawn beside each monitor.

    Server-rendered SVG rather than a charting library: fifty rows would be
    fifty chart instances, each holding a canvas and a redraw loop, to draw
    fifty shapes that never change.
    """

    @staticmethod
    def _points(values, downs=()):
        from wdash.hub.models import MonitorPoint
        return [MonitorPoint(timestamp=None, duration_ms=value,
                             down=(1 if index in downs else 0),
                             checks=(0 if value is None else 3))
                for index, value in enumerate(values)]

    def _spark(self, values, downs=()):
        from wdash.api.monitor_routes import sparkline
        return sparkline(self._points(values, downs))

    def test_a_gap_breaks_the_line(self):
        """Joining across a gap draws a monitor that was not reporting as one
        that was reporting steadily — the outage becomes a straight line."""
        spark = self._spark([10, 20, None, None, 30, 25])
        self.assertEqual(len(spark["runs"]), 2)
        self.assertEqual(spark["gaps"], 2)

    def test_one_point_draws_nothing(self):
        """A dot rendered as a chart reads as a trend."""
        self.assertIsNone(self._spark([10]))

    def test_no_data_at_all_draws_nothing(self):
        """So the template can say "not enough data" instead of showing an
        empty box, which reads as a flat line at zero."""
        self.assertIsNone(self._spark([None, None, None]))

    def test_failures_are_marked_where_they_happened(self):
        spark = self._spark([10, 20, 15], downs={1})
        self.assertEqual(len(spark["failures"]), 1)
        # Second of three points, so halfway across.
        self.assertAlmostEqual(spark["failures"][0][0], spark["width"] / 2,
                               delta=1)

    def test_the_peak_sits_at_the_top(self):
        """Scaled to its own maximum: a monitor answering in 3 ms and one
        answering in 3 s both need to show their shape."""
        spark = self._spark([10, 40, 20])
        heights = [float(pair.split(",")[1])
                   for pair in spark["runs"][0].split()]
        self.assertEqual(min(heights), 2.0)      # the padding, i.e. the top

    def test_a_flat_line_is_still_drawn(self):
        """Every value equal is a real answer — a monitor that is reliably
        fast — not a reason to render nothing."""
        spark = self._spark([10, 10, 10])
        self.assertEqual(len(spark["runs"]), 1)


class SeriesTest(MonitorListingTest):
    """The aggregation behind the sparkline."""

    def test_the_listing_can_carry_a_series(self):
        source = self._source([_document("a")])
        page = source.monitors(self.window, self.scope, series=True)
        request = source._es.requests[0]
        self.assertIn("series", json.dumps(request["aggs"]))

    def test_it_is_one_query_not_one_per_monitor(self):
        """A page issuing fifty requests to draw fifty sparklines stops
        working at a hundred monitors."""
        source = self._source([_document("a"), _document("b"), _document("c")])
        source.monitors(self.window, self.scope, series=True)
        self.assertEqual(len(source._es.requests), 1)

    def test_it_is_not_asked_for_unless_wanted(self):
        """The certificate screen has no use for it and should not pay for
        the aggregation."""
        source = self._source([_document("a")])
        source.monitors(self.window, self.scope)
        self.assertNotIn("series", json.dumps(source._es.requests[0]["aggs"]))

    def test_every_series_spans_the_whole_window(self):
        """Without extended_bounds a monitor added an hour ago produces fewer
        buckets than its neighbours, and drawn to the same width the two
        sparklines put different moments above each other."""
        source = self._source([_document("a")])
        source.monitors(self.window, self.scope, series=True)
        histogram = source._es.requests[0]["aggs"]["monitors"]["aggs"]["series"]
        self.assertIn("extended_bounds", histogram["date_histogram"])

    def test_empty_buckets_are_kept(self):
        """A gap means the agent stopped. Dropping the bucket would join the
        line across it."""
        source = self._source([_document("a")])
        source.monitors(self.window, self.scope, series=True)
        histogram = source._es.requests[0]["aggs"]["monitors"]["aggs"]["series"]
        self.assertEqual(histogram["date_histogram"]["min_doc_count"], 0)

    def test_the_series_reaches_the_monitor(self):
        """The query can be perfect and the result never attached. Asserting
        on the request shape alone leaves that wiring untested — and it was."""
        source = self._source([_document("a")])
        monitor = source.monitors(self.window, self.scope,
                                  series=True).monitors[0]
        self.assertEqual(len(monitor.series), 3)
        self.assertAlmostEqual(monitor.series[0].duration_ms, 5.0)

    def test_the_empty_bucket_survives_as_a_gap(self):
        source = self._source([_document("a")])
        monitor = source.monitors(self.window, self.scope,
                                  series=True).monitors[0]
        self.assertFalse(monitor.series[1].has_data)
        self.assertIsNone(monitor.series[1].duration_ms)

    def test_a_failing_bucket_is_marked(self):
        source = self._source([_document("a")])
        monitor = source.monitors(self.window, self.scope,
                                  series=True).monitors[0]
        self.assertTrue(monitor.series[2].is_down)

    def test_without_the_flag_the_monitor_carries_no_series(self):
        source = self._source([_document("a")])
        monitor = source.monitors(self.window, self.scope).monitors[0]
        self.assertEqual(monitor.series, ())

    def test_a_bucket_with_one_failure_in_six_is_down(self):
        """Averaging the status away is how a five-minute outage disappears
        from a day-long chart."""
        from wdash.hub.models import MonitorPoint
        point = MonitorPoint(timestamp=None, duration_ms=10, down=1, checks=6)
        self.assertTrue(point.is_down)


class AvailabilityTest(unittest.TestCase):
    """The numbers in the detail header."""

    @staticmethod
    def _checks(pairs):
        from wdash.hub.models import MonitorCheck
        return [MonitorCheck(timestamp=None, status=status, duration_ms=ms)
                for status, ms in pairs]

    def _summary(self, pairs):
        from wdash.api.monitor_routes import _availability
        return _availability([], self._checks(pairs))

    def test_availability_counts_runs_not_buckets(self):
        """A bucket holding six runs of which one failed is one failure in
        six. Counting buckets would call it one in one."""
        summary = self._summary([(UP, 10)] * 9 + [(DOWN, 5)])
        self.assertEqual(summary["availability"], 90.0)
        self.assertEqual(summary["checks"], 10)
        self.assertEqual(summary["failed"], 1)

    def test_p95_is_a_real_observation(self):
        """Nearest-rank, so the number shown is one that actually happened
        rather than an interpolation between two that did."""
        summary = self._summary([(UP, float(n)) for n in range(1, 101)])
        self.assertIn(summary["p95_ms"], (95.0, 96.0))

    def test_nothing_measured_is_none_rather_than_zero(self):
        """Zero milliseconds is the fastest possible answer, not the absence
        of one."""
        summary = self._summary([])
        self.assertIsNone(summary["availability"])
        self.assertIsNone(summary["median_ms"])

    def test_a_check_with_no_duration_does_not_count_as_zero(self):
        summary = self._summary([(UP, 10), (UP, None), (UP, 20)])
        self.assertEqual(summary["worst_ms"], 20)
        self.assertGreater(summary["median_ms"], 0)


class HistoryPagingTest(MonitorListingTest):
    """Paged in Elasticsearch, not in Python.

    A monitor on a fifteen-second schedule writes 5,760 checks a day.
    Fetching all of them to show twenty-five works in a lab and falls over on
    the first real deployment.
    """

    def _source_with(self, count):
        documents = [_document(f"c{n}") for n in range(count)]
        return ElasticsearchMonitorSource(
            FakeElasticsearch(documents), name="lab")

    def test_the_offset_and_size_reach_the_query(self):
        source = self._source_with(3)
        source.history("m", self.window, self.scope, offset=50, limit=25)
        request = source._es.requests[0]
        self.assertEqual(request["from"], 50)
        self.assertEqual(request["size"], 25)

    def test_the_total_is_counted_exactly(self):
        """This number is shown as "of N". Elasticsearch stops counting at
        10,000 by default, and "of 10,000" on 12,000 checks is simply wrong."""
        source = self._source_with(3)
        source.history("m", self.window, self.scope)
        self.assertTrue(source._es.requests[0]["track_total_hits"])

    def test_a_negative_offset_becomes_zero(self):
        source = self._source_with(3)
        source.history("m", self.window, self.scope, offset=-10, limit=5)
        self.assertEqual(source._es.requests[0]["from"], 0)

    def test_the_page_size_is_capped(self):
        """`?limit=100000` must not become a request for a hundred thousand
        documents."""
        source = self._source_with(3)
        source.history("m", self.window, self.scope, limit=999999)
        self.assertLessEqual(source._es.requests[0]["size"], 500)

    def test_the_result_still_looks_like_a_list(self):
        """Callers that predate paging — the fan-out, the chart — index and
        iterate it. A tuple return would have been a signature change for
        every implementation of MonitorSource."""
        source = self._source_with(2)
        checks = source.history("m", self.window, self.scope)
        self.assertIsInstance(checks, list)
        self.assertEqual(len(checks), 2)


class PagerTest(unittest.TestCase):
    def _pager(self, page, total):
        from wdash.api.monitor_routes import _pager
        return _pager(page, total)

    def test_one_page_gets_no_pager(self):
        """A control that cannot do anything is one somebody clicks before
        believing it."""
        self.assertIsNone(self._pager(1, 20))

    def test_the_range_shown_matches_the_page(self):
        pager = self._pager(3, 242)
        self.assertEqual((pager["first"], pager["last"]), (51, 75))

    def test_the_last_page_stops_at_the_total(self):
        """Not 250. A range that runs past the end says rows exist that do
        not."""
        pager = self._pager(10, 242)
        self.assertEqual(pager["last"], 242)

    def test_a_page_past_the_end_lands_on_the_last_one(self):
        pager = self._pager(99, 242)
        self.assertEqual(pager["page"], 10)
        self.assertFalse(pager["has_next"])

    def test_the_number_list_is_a_window(self):
        """231 pages of check history would otherwise be a pager wider than
        the table."""
        pager = self._pager(50, 10000)
        self.assertLessEqual(len(pager["numbers"]), 5)
        self.assertIn(50, pager["numbers"])

    def test_the_window_does_not_run_off_either_end(self):
        for page, total in ((1, 10000), (400, 10000)):
            pager = self._pager(page, total)
            self.assertTrue(all(1 <= n <= pager["pages"]
                                for n in pager["numbers"]))


class ChartDataTest(unittest.TestCase):
    """What the detail chart is handed.

    Chart.js rather than server-rendered SVG here, and the reason is measured
    rather than assumed: base.html loads the library on every page already, so
    one chart costs no download, and hovering to read an exact time and value
    is most of why the page gets opened. The sparklines stay SVG because a
    hundred rows would be a hundred canvases drawing shapes that never change.
    """

    @staticmethod
    def _points(rows):
        from wdash.hub.models import MonitorPoint
        out = []
        for average, worst, down in rows:
            point = MonitorPoint(timestamp=dt.datetime(2026, 8, 6, 10, 0,
                                                       tzinfo=dt.timezone.utc),
                                 duration_ms=average, down=down,
                                 checks=0 if average is None else 3)
            point.worst_ms = worst
            out.append(point)
        return out

    def _chart(self, rows):
        from wdash.api.monitor_routes import response_chart
        return response_chart(self._points(rows))

    def test_a_gap_is_null_not_zero(self):
        """Chart.js breaks a line at a null and draws straight through a
        zero. Zero milliseconds would be the fastest reading on the chart at
        the moment the agent stopped reporting."""
        chart = self._chart([(10, 20, 0), (None, None, 0), (12, 22, 0)])
        self.assertIsNone(chart["average"][1])
        self.assertIsNone(chart["worst"][1])

    def test_the_arrays_line_up_with_the_labels(self):
        """The failure marks are drawn by index, so a shorter array would put
        them under the wrong time."""
        chart = self._chart([(10, 20, 0), (None, None, 0), (12, 22, 1)])
        self.assertEqual(len(chart["labels"]), 3)
        self.assertEqual(len(chart["average"]), 3)
        self.assertEqual(len(chart["failures"]), 3)

    def test_failures_are_counted_not_flagged(self):
        """Three failures in a bucket and one are different facts, and the
        tooltip says which."""
        chart = self._chart([(10, 20, 0), (12, 22, 3)])
        self.assertEqual(chart["failures"][1], 3)
        self.assertEqual(chart["failure_count"], 3)

    def test_too_little_data_draws_nothing(self):
        """One point is a dot, and a dot drawn as a chart reads as a trend."""
        self.assertIsNone(self._chart([(10, 20, 0)]))

    def test_the_peak_covers_both_series(self):
        """A y-axis scaled to the average alone clips the slowest line off the
        top of the chart."""
        chart = self._chart([(10, 100, 0), (10, 10, 0)])
        self.assertEqual(chart["peak_ms"], 100)


class FanOutCompletenessTest(unittest.TestCase):
    """The fan-out has to offer everything the routes ask a source for.

    Twice now a method was added to the sources and not to the fan-out, and
    both times the symptom appeared only once a SECOND source was configured
    — because with one source `hub.monitors(ALL)` returns the source itself
    and the fan-out is never built. The sparklines went empty the first time;
    the detail chart went to "not enough checks to draw a line" the second,
    while the list beside it was full.

    So this checks the class rather than the instance.
    """

    #: What the monitor routes call on whatever `hub.monitors()` returns.
    USED_BY_ROUTES = ("monitors", "history", "certificates", "series",
                      "health", "containers", "supports", "capabilities")

    def test_the_fanout_offers_everything_a_source_does(self):
        from wdash.hub.adapters.es_monitors import ElasticsearchMonitorSource
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        from wdash.hub.fanout import FanOutMonitorSource

        for source in (ElasticsearchMonitorSource, StoreMonitorSource):
            missing = [name for name in self.USED_BY_ROUTES
                       if hasattr(source, name)
                       and not hasattr(FanOutMonitorSource, name)]
            self.assertEqual(
                missing, [],
                f"the fan-out cannot serve {missing} that "
                f"{source.__name__} provides")

    def test_the_optional_arguments_are_accepted_too(self):
        """Present is not enough. `monitors(series=True)` and
        `history(offset=, limit=)` are how the page asks for a sparkline and a
        page of checks, and a fan-out that takes neither silently drops both.
        """
        import inspect

        from wdash.hub.fanout import FanOutMonitorSource
        signatures = {
            "monitors": ("series",),
            "history": ("offset", "limit"),
            "series": ("points",),
        }
        for name, expected in signatures.items():
            parameters = inspect.signature(
                getattr(FanOutMonitorSource, name)).parameters
            for argument in expected:
                self.assertIn(argument, parameters,
                              f"FanOutMonitorSource.{name} does not take "
                              f"{argument}")

    def test_a_two_source_hub_still_draws_a_chart(self):
        """The reported fault, end to end: with one source the page worked and
        with two it said there was not enough data."""
        from wdash.hub import Hub
        from wdash.hub.models import UP, Monitor, MonitorPage, MonitorPoint
        from wdash.hub.query import TimeWindow

        class Source:
            capabilities = frozenset({"monitor_list", "monitor_history"})

            def __init__(self, name, knows):
                self.name = name
                self._knows = knows

            def monitors(self, window, scope, series=False):
                return MonitorPage(
                    monitors=[Monitor(id=self._knows, name=self._knows,
                                      status=UP, source=self.name)],
                    sources=(self.name,))

            def series(self, monitor_id, window, scope, points=120):
                if monitor_id != self._knows:
                    return []
                return [MonitorPoint(timestamp=None, duration_ms=10 + n,
                                     down=0, checks=3) for n in range(points)]

            def history(self, monitor_id, window, scope):
                return []

            def certificates(self, window, scope):
                return []

            def health(self):
                return True, "ok"

            def containers(self, scope):
                return []

        hub = Hub()
        hub.add_monitors(Source("first", "a"))
        hub.add_monitors(Source("second", "b"))
        merged = hub.monitors(hub.ALL_SOURCES)

        from wdash.api.monitor_routes import response_chart
        points = merged.series("a", TimeWindow.of("1h"), None, points=12)
        self.assertTrue(points, "the fan-out returned no series")
        self.assertIsNotNone(response_chart(points),
                             "a full series still produced no chart")

    def test_merging_two_series_weights_by_check_count(self):
        """A plain mean of means lets a source with one check outweigh one
        with fifty."""
        from wdash.hub.fanout import FanOutMonitorSource
        from wdash.hub.models import MonitorPoint

        class Source:
            capabilities = frozenset()

            def __init__(self, name, duration, checks):
                self.name = name
                self._duration = duration
                self._checks = checks

            def series(self, monitor_id, window, scope, points=120):
                return [MonitorPoint(timestamp=None,
                                     duration_ms=self._duration,
                                     down=0, checks=self._checks)]

            def health(self):
                return True, "ok"

            def containers(self, scope):
                return []

            def monitors(self, window, scope, series=False):
                return None

        fanout = FanOutMonitorSource([Source("busy", 10.0, 50),
                                      Source("quiet", 1000.0, 1)])
        point = fanout.series("m", None, None, points=1)[0]
        # 50 checks at 10 ms and one at 1000: the weighted mean is ~29 ms,
        # the mean of means would be 505.
        self.assertLess(point.duration_ms, 100)
        self.assertEqual(point.checks, 51)
