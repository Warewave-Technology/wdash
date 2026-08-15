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
        # `check_group` is on EVERY check, not only a browser one — measured
        # on the lab's HTTP monitors. Which is the reason the step lookup has
        # to decide on `monitor.type`: a group id being present says nothing
        # about there being steps to fetch.
        "monitor": {"id": monitor_id, "name": name, "type": kind,
                    "check_group": f"{monitor_id}-group-1",
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


# ---------------------------------------------------------------------------
# Elastic's own browser journeys
# ---------------------------------------------------------------------------

#: TWO complete runs of each of the lab's two browser journeys, captured from
#: `synthetics-browser-*` after a real Heartbeat 8.19.9 ran them against the
#: lab's sign-in page. One journey passes; one fails at its second step
#: because the password is wrong, which is the only way to measure what a
#: failure looks like.
#:
#: Two runs each rather than one, because with one run per monitor a join on
#: `monitor.id` and a join on `monitor.check_group` return exactly the same
#: documents — so the fixture could not tell the correct join from a wrong
#: one, and a mutation showed it did not.
BROWSER_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                               "elastic-browser-journey.json")


def _browser_runs(monitor=None):
    with open(BROWSER_FIXTURE) as handle:
        runs = json.load(handle)["runs"]
    return [r for r in runs if monitor is None or r["monitor"] == monitor]


def _many_runs(monitor, count, steps_per_run=None):
    """One measured run, repeated with fresh identities and timestamps.

    The SHAPE stays measured — these are the documents Heartbeat wrote — and
    only the volume is made up, which is the part a lab of two journeys
    cannot supply. Anything asserted on the CONTENTS of a run belongs in a
    test that uses the fixture directly.

    `steps_per_run` lengthens the journey by repeating its measured steps.
    The document cap is 10,000 and history stops at 500 checks, so a
    three-step journey cannot reach it however long it runs: without a long
    journey, a test of the cap passes without the cap ever being applied.
    """
    template = _browser_runs(monitor)[0]["documents"]
    measured_steps = [d for d in template
                      if _dig(d, "synthetics.type") == "step/end"]
    other = [d for d in template
             if _dig(d, "synthetics.type") != "step/end"]

    runs = []
    for number in range(count):
        moment = _now() - dt.timedelta(minutes=count - number)
        group = f"{monitor}-{number}"
        steps = []
        wanted = steps_per_run or len(measured_steps)
        for index in range(wanted):
            copy = json.loads(json.dumps(measured_steps[
                index % len(measured_steps)]))
            copy["synthetics"]["step"]["index"] = index + 1
            copy["synthetics"]["index"] = index + 1
            steps.append(copy)

        documents = []
        for offset, document in enumerate(other + steps):
            copy = document if document in steps \
                else json.loads(json.dumps(document))
            copy["monitor"]["check_group"] = group
            copy["@timestamp"] = (moment + dt.timedelta(seconds=offset)) \
                .isoformat().replace("+00:00", "Z")
            documents.append(copy)
        runs.append({"monitor": monitor, "check_group": group,
                     "documents": documents})
    return runs


class ReplayElasticsearch:
    """Answers the two queries a browser history issues, from real documents.

    It routes on what the query ASKS for rather than on call order, so an
    adapter that stops filtering by `synthetics.type` or by check group gets
    the wrong documents back instead of the right ones by luck.

    Order is not preserved. Elasticsearch returns hits in an unspecified order
    without a `sort`, and the adapter depends on step order being right — so a
    fake that hands back fixture order would hold that dependency up whether
    or not the adapter ever asked for it.
    """

    def __init__(self, runs):
        self.documents = [document for run in runs
                          for document in run["documents"]]
        self.requests = []

    def ping(self):
        return True

    def search(self, index=None, **kwargs):
        self.requests.append(kwargs)
        filters = _dig(kwargs, "query.bool.filter") or []
        wanted_types = set()
        groups = None
        monitors = set()
        for clause in filters:
            for field, value in (clause.get("term") or {}).items():
                if field == "synthetics.type":
                    wanted_types.add(value)
                if field == "monitor.id":
                    monitors.add(value)
            for field, values in (clause.get("terms") or {}).items():
                if field == "monitor.check_group":
                    groups = set(values)
            if "exists" in clause:
                wanted_types.add("heartbeat/summary")

        hits = []
        for document in self.documents:
            kind = _dig(document, "synthetics.type")
            if wanted_types and kind not in wanted_types:
                continue
            if groups is not None \
                    and _dig(document, "monitor.check_group") not in groups:
                continue
            if monitors and _dig(document, "monitor.id") not in monitors:
                continue
            hits.append({"_index": ".ds-synthetics-browser-default-000001",
                         "_id": f"{kind}-{len(hits)}", "_source": document})

        # Fixture order destroyed first, then the requested sort applied, then
        # `size` honoured — which is what a cluster does, and what makes both
        # the ordering and the cap something a test can hold.
        hits.reverse()
        total = len(hits)
        for sort in reversed(kwargs.get("sort") or ()):
            field, options = next(iter(sort.items()))
            descending = (options or {}).get("order") == "desc"
            hits.sort(key=lambda hit: _dig(hit["_source"], field) or 0,
                      reverse=descending)
        size = kwargs.get("size")
        if size is not None:
            hits = hits[:size]
        return NotADict({"hits": {"total": {"value": total}, "hits": hits}})


class ElasticBrowserJourneyTest(unittest.TestCase):
    """Per-step detail from Elastic's browser monitors.

    Held back through two phases because the document shape had never been
    measured and a guessed one produces a page that looks complete and is
    wrong. It has now been measured, and the shape was not what reading a
    summary document would suggest: a browser check is six documents in a
    different data stream, tied together by `monitor.check_group`.
    """

    def setUp(self):
        self.runs = _browser_runs()
        self.client = ReplayElasticsearch(self.runs)
        self.source = ElasticsearchMonitorSource(self.client)
        self.window = TimeWindow(start=_now() - dt.timedelta(hours=1),
                                 end=_now())

    def _history(self, monitor_id, limit=25):
        return self.source.history(monitor_id, self.window,
                                   Scope.unrestricted(), limit=limit)

    def test_a_passing_journey_reports_every_step(self):
        check = self._history("lab-journey-up")[-1]
        self.assertEqual([s.description for s in check.steps],
                         ["open the sign-in page", "sign in", "add to basket"])
        self.assertEqual({s.status for s in check.steps}, {"passed"})

    def test_the_steps_are_in_the_order_they_ran(self):
        """By `synthetics.step.index`, not by timestamp: two steps finishing
        inside the same millisecond agree on the second and not the first."""
        check = self._history("lab-journey-up")[-1]
        self.assertEqual([s.index for s in check.steps], [1, 2, 3])

    def test_a_failure_names_the_step_that_broke(self):
        """The whole point of a per-step view. "The journey failed" is a fact
        nobody can act on; "sign in failed" is one somebody can."""
        check = self._history("lab-journey-down")[-1]
        self.assertEqual(check.failed_step.description, "sign in")
        self.assertEqual(check.failed_step.index, 2)

    def test_the_step_after_a_failure_is_skipped_not_failed(self):
        """It never ran. Reporting it as failed says the basket is broken when
        what is broken is the sign-in in front of it — and that is where
        somebody would go looking."""
        check = self._history("lab-journey-down")[-1]
        third = check.steps[2]
        self.assertEqual(third.status, "skipped")
        self.assertEqual(third.description, "add to basket")

    def test_the_error_is_the_browsers_own_words(self):
        """ECS `error.message` prefixes it with "error executing step: ",
        which is scaffolding rather than information."""
        check = self._history("lab-journey-down")[-1]
        self.assertEqual(check.failed_step.error,
                         "page.waitForSelector: Timeout 5000ms exceeded.")

    def test_each_step_carries_its_own_duration(self):
        check = self._history("lab-journey-up")[-1]
        durations = [s.duration_ms for s in check.steps]
        self.assertTrue(all(d is not None for d in durations))
        # The lab's basket button waits 400ms on purpose, so the last step is
        # the slow one — the shape a per-step view exists to show.
        self.assertEqual(max(durations), durations[-1])

    def test_the_script_source_never_reaches_the_page(self):
        """`synthetics.payload.source` is the step's CODE.

        The lab's failing journey has a literal password in it, which is
        exactly what a real one would have. WDash redacts secrets out of its
        own journeys; carrying Elastic's script bodies onto the same page
        would hand back the thing redaction exists to prevent.
        """
        stored = json.dumps(_browser_runs("lab-journey-down"))
        self.assertIn("wrong-password", stored,
                      "the fixture no longer contains the thing being kept "
                      "off the page, so this test proves nothing")

        rendered = json.dumps([
            {"description": s.description, "status": s.status,
             "error": s.error, "kind": s.kind}
            for check in self._history("lab-journey-down")
            for s in check.steps])
        self.assertNotIn("wrong-password", rendered)
        self.assertNotIn("page.fill", rendered)

    def test_one_runs_steps_do_not_land_on_another(self):
        """Two journeys ran in the same minute. Joined on anything looser than
        `monitor.check_group` — the monitor id, the timestamp — the failing
        one's steps would appear under the passing one."""
        passing = self._history("lab-journey-up")[-1]
        self.assertEqual([s.status for s in passing.steps],
                         ["passed", "passed", "passed"])
        failing = self._history("lab-journey-down")[-1]
        self.assertEqual([s.status for s in failing.steps],
                         ["passed", "failed", "skipped"])

    def test_two_runs_of_one_journey_keep_their_own_steps(self):
        """The join has to be `monitor.check_group` and nothing looser.

        On `monitor.id` — which is the obvious wrong answer, since that is
        what the history query already filters by — every run of a monitor
        collects every step the monitor ever ran. A three-step journey with
        two runs in the window then shows six steps per run, numbered
        1,1,2,2,3,3, and the whole point of the view is gone.
        """
        checks = self._history("lab-journey-down")
        self.assertEqual(len(checks), 2, "the fixture needs two runs here")
        for check in checks:
            self.assertEqual([s.index for s in check.steps], [1, 2, 3])

    def test_a_journey_end_document_is_not_read_as_a_step(self):
        """`journey/end` also carries `payload.status`. Counted as a step it
        adds a fourth row to a three-step journey, with no name."""
        check = self._history("lab-journey-up")[-1]
        self.assertEqual(len(check.steps), 3)
        self.assertTrue(all(s.description for s in check.steps))

    def test_an_http_monitor_costs_no_extra_query(self):
        """Steps are a browser thing. Asking for them on every history would
        double the requests behind the busiest page in the product.

        With a real HTTP check in it, rather than an empty client: an empty
        one returns no hits, so there is nothing to ask a second question
        about and the test passes whatever the adapter does. It did — a
        mutation that deleted the browser condition entirely survived this
        test in that form.
        """
        client = FakeElasticsearch([_document(kind="http")])
        source = ElasticsearchMonitorSource(client)
        source.history("lab-http-up", self.window, Scope.unrestricted(),
                       limit=25)
        self.assertEqual(len(client.requests), 1)

    def test_the_step_query_asks_only_for_the_runs_on_this_page(self):
        """Scoped to the check groups just read, and nothing wider.

        `monitor.id` is the obvious wrong answer — the history query filters
        by it already — and it is wrong in a way no fixture shows: on a
        cluster it matches every run the monitor has ever recorded, so the
        size cap truncates and some rows on the page silently lose their
        steps. What reaches the cluster is the behaviour here.
        """
        self._history("lab-journey-down")
        asked = _dig(self.client.requests[-1], "query.bool.filter") or []
        terms = [clause["terms"] for clause in asked if "terms" in clause]
        self.assertEqual(len(terms), 1)
        self.assertIn("monitor.check_group", terms[0])
        self.assertEqual(
            sorted(terms[0]["monitor.check_group"]),
            sorted(run["check_group"]
                   for run in _browser_runs("lab-journey-down")))

    def test_steps_arrive_when_nobody_asked_for_a_page(self):
        """The bug that made the whole feature invisible on a real screen.

        The first version fetched steps only when the caller passed a bounded
        `limit`, on the reasoning that the availability figures read the whole
        window and never look at a step. But the fan-out pages in Python —
        deliberately, because a page of a merge is not the merge of two pages
        — so it asks every source for the WHOLE window. Every journey came
        back with no steps on any deployment with more than one monitor
        source, which is the ordinary case, and the page showed a browser
        monitor with nothing to expand.

        It passed every test above, because they all called the adapter
        directly.
        """
        checks = self.source.history("lab-journey-up", self.window,
                                     Scope.unrestricted())
        self.assertTrue(all(check.steps for check in checks))

    def test_the_lookup_never_asks_for_more_than_a_search_can_return(self):
        """`index.max_result_window` is 10,000, and a plain search asking for
        more is refused. The refusal arrives as an exception, which this
        adapter turns into "no steps" — so the cliff would show up as a
        browser monitor with nothing to expand, on exactly the deployments
        with enough history to want it."""
        runs = _many_runs("lab-journey-up", 400)
        source = ElasticsearchMonitorSource(ReplayElasticsearch(runs))
        client = source._es
        source.history("lab-journey-up", self.window, Scope.unrestricted())
        self.assertLessEqual(client.requests[-1]["size"], 10_000)

    def test_when_the_cap_bites_it_is_the_oldest_runs_that_lose_their_steps(self):
        """A cap has to fall somewhere. Falling on the newest runs would take
        the steps off the rows on the first page — the ones somebody opened
        the monitor to look at.

        Thirty steps a run, because three cannot reach the cap: history stops
        at 500 checks and 500 × 3 is well under 10,000, so the same test on a
        short journey passes with the cap never applied — which is how the
        first version of it passed while the order was wrong.
        """
        runs = _many_runs("lab-journey-up", 400, steps_per_run=30)
        source = ElasticsearchMonitorSource(ReplayElasticsearch(runs))
        checks = source.history("lab-journey-up", self.window,
                                Scope.unrestricted())
        with_steps = [bool(check.steps) for check in checks]
        self.assertIn(False, with_steps, "the cap did not bite, so this "
                                         "proves nothing about where it falls")
        # `history` returns oldest first, so the newest are at the end.
        self.assertTrue(all(with_steps[-100:]))
        self.assertFalse(with_steps[0])

    def test_a_status_nobody_has_measured_is_shown_rather_than_translated(self):
        """Three values have been seen. A fourth from some later agent should
        appear as what it said — mapping it onto one of ours would be a
        guess presented as a reading."""
        run = _browser_runs("lab-journey-up")[-1]
        for document in run["documents"]:
            if _dig(document, "synthetics.step.index") == 2:
                document["synthetics"]["step"]["status"] = "flaky"
        source = ElasticsearchMonitorSource(ReplayElasticsearch([run]))
        check = source.history("lab-journey-up", self.window,
                               Scope.unrestricted(), limit=25)[-1]
        self.assertEqual(check.steps[1].status, "flaky")


class TheDetailPageAsksForWhatItDrawsTest(unittest.TestCase):
    """What one load of the detail page costs the source.

    Measured rather than reasoned about, against the store adapter with 20
    monitors and a day of minute-by-minute checks — 28,800 rows:

        monitors(series=True)   93 ms
        series                   5 ms
        history(limit, offset)   4 ms
        history                  5 ms
        ------------------------------
        116 ms, of which 93 built a sparkline for every monitor on a page
        that shows one and draws its own chart from `series`.

    Two calls went. `monitors` is asked without series, and the page of checks
    is sliced out of the history the availability figures had already read.
    The same page is now 52 ms and three calls. Both are asserted here because
    both are invisible from the screen: nothing renders differently, so the
    only thing that can notice a regression is a test that counts.
    """

    def setUp(self):
        from datetime import datetime, timedelta, timezone

        import sqlalchemy

        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.schema import monitor_results
        from wdash.store.secrets import SecretBox

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "detail-page"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        grant(self.app, "admin", ["system:admin", "monitors:read"],
              indices=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "u1", "username": "admin", "email": "a@b", "groups": [],
                "role": "admin",
                "permissions": ["system:admin", "monitors:read"],
                "allowed_indices": ["*"]}
            session["_user_id"] = "u1"

        # More than one monitor, or the wasted work has nothing to be wasted
        # on: `series=True` costs whatever the OTHER monitors cost.
        now = datetime.now(timezone.utc)
        self.ids = []
        for n in range(4):
            monitor = self.app.store.monitors.create(
                name=f"check-{n}", kind="http",
                target=f"https://x{n}.example/health",
                interval_seconds=60, timeout_seconds=10)
            self.ids.append(monitor["id"])
        rows = [{"monitor_id": monitor_id, "agent_id": "a1",
                 "started_at": now - timedelta(seconds=60 * i),
                 "received_at": now - timedelta(seconds=60 * i),
                 "status": "down" if i % 10 == 0 else "up",
                 "duration_us": 100_000 + i, "error": "", "steps": None,
                 "screenshot_id": None}
                for monitor_id in self.ids for i in range(30)]
        with self.app.store.engine.begin() as connection:
            connection.execute(sqlalchemy.insert(monitor_results), rows)

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _calls(self, url):
        """Every source call one request makes, as (method, kwargs)."""
        calls = []

        def wrap(source, name):
            original = getattr(source, name)

            def counted(*args, **kwargs):
                calls.append((name, dict(kwargs)))
                return original(*args, **kwargs)
            setattr(source, name, counted)

        with self.app.app_context():
            sources = list(self.app.hub.monitor_sources)
        for source in sources:
            for name in ("monitors", "history", "series"):
                wrap(source, name)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.status_code)
        for source in sources:
            for name in ("monitors", "history", "series"):
                # Instance attributes only; the class methods are untouched.
                delattr(source, name)
        return calls, response.get_data(as_text=True)

    def test_no_sparkline_is_built_for_a_page_that_shows_one_monitor(self):
        calls, _ = self._calls(f"/monitors/{self.ids[0]}?window=1h")
        for name, kwargs in calls:
            if name == "monitors":
                self.assertNotIn("series", kwargs,
                                 "the detail page asked for a sparkline per "
                                 "monitor and renders none of them")

    def test_the_history_is_read_once(self):
        calls, _ = self._calls(f"/monitors/{self.ids[0]}?window=1h")
        history = [kwargs for name, kwargs in calls if name == "history"]
        self.assertEqual(len(history), 1, history)

    def test_the_listing_still_gets_its_sparklines(self):
        """The saving is specific to the detail page. The listing draws one
        shape per row and must go on asking for them."""
        calls, _ = self._calls("/monitors?window=1h")
        asked = [kwargs for name, kwargs in calls if name == "monitors"]
        self.assertTrue(any(kwargs.get("series") for kwargs in asked), asked)

    def test_the_rows_are_the_newest_ones(self):
        """The page is now a slice of a list the route already held rather
        than a query written for it, and a slice taken from the wrong end
        looks like a page that renders."""
        import re
        _, page = self._calls(f"/monitors/{self.ids[0]}?window=1h")
        body = page.split("Recent checks")[1].split("<tbody>")[1]
        # 30 checks, 25 to a page: the first page is the newest 25, and the
        # oldest five are not on it.
        self.assertEqual(body.count('class="monitor-status'), 25)
        self.assertIn("1–25 of 30 checks", " ".join(page.split())
                      .replace("&ndash;", "–"))
        # Counting rows is not enough: the source returns them oldest-first
        # for the chart, so a slice taken from the wrong end is 25 rows of
        # last hour's checks under a heading that says "newest first".
        stamps = re.findall(r'data-timestamp="([^"]+)"', body)
        self.assertEqual(len(stamps), 25)
        self.assertEqual(stamps, sorted(stamps, reverse=True))
        self.newest = stamps

    def test_the_second_page_is_the_rest(self):
        import re
        _, first = self._calls(f"/monitors/{self.ids[0]}?window=1h")
        _, page = self._calls(f"/monitors/{self.ids[0]}?window=1h&page=2")
        body = page.split("Recent checks")[1].split("<tbody>")[1]
        self.assertEqual(body.count('class="monitor-status'), 5)
        stamps = re.findall(r'data-timestamp="([^"]+)"', body)
        oldest_on_page_one = re.findall(
            r'data-timestamp="([^"]+)"',
            first.split("Recent checks")[1].split("<tbody>")[1])[-1]
        self.assertTrue(all(stamp < oldest_on_page_one for stamp in stamps),
                        "page two overlaps page one")

    def test_a_window_bigger_than_the_source_can_hold_is_still_paged(self):
        """The shortcut is only valid while the whole window is in hand. A
        source with a ceiling — Elasticsearch stops at 500 — reports a total
        larger than the list it returned, and page 40 can only come from a
        query written for it."""
        from wdash.api.monitor_routes import _checks_page
        from wdash.hub.source import Capability

        class Capped:
            def __init__(self):
                self.asked = []

            def supports(self, capability):
                return capability == Capability.MONITOR_HISTORY

            def history(self, monitor_id, window, scope, offset=0, limit=None):
                self.asked.append((offset, limit))
                return []

        ceiling = _CountedList([object()] * 500)
        ceiling.total = 5000
        source = Capped()
        with self.app.test_request_context("/monitors/x"):
            _checks_page(source, "x", None, 40, ceiling)
        self.assertEqual(source.asked, [(975, 25)])


class _CountedList(list):
    """A history list that knows the window holds more than it returned."""
    total = 0


class StepHistoryTest(unittest.TestCase):
    """Which step got slower, from the history the page already read.

    A journey's run list answers "did it work". It cannot answer the question
    somebody actually has when a checkout takes nine seconds — which of the
    seven steps IS the nine seconds, and was it always. That is what these
    rows are, and every number in them is computed from `history`, so the
    feature costs no query of its own.
    """

    def setUp(self):
        from wdash.hub.models import (
            MonitorCheck, STEP_FAILED, STEP_PASSED, STEP_SKIPPED, StepResult)
        self.MonitorCheck = MonitorCheck
        self.StepResult = StepResult
        self.PASSED, self.FAILED, self.SKIPPED = (
            STEP_PASSED, STEP_FAILED, STEP_SKIPPED)
        self.end = _now()
        self.start = self.end - dt.timedelta(hours=1)
        self.window = TimeWindow.exact(self.start, self.end)

    def _run(self, minutes_ago, durations, statuses=None, names=None):
        """One journey run, oldest-first order being the caller's business."""
        statuses = statuses or [self.PASSED] * len(durations)
        names = names or [f"step {i + 1}" for i in range(len(durations))]
        steps = tuple(
            self.StepResult(index=i + 1, kind="browser", description=names[i],
                            status=statuses[i],
                            duration_us=(None if durations[i] is None
                                         else int(durations[i] * 1000)))
            for i in range(len(durations)))
        return self.MonitorCheck(
            timestamp=self.end - dt.timedelta(minutes=minutes_ago),
            status=UP, duration_ms=sum(d for d in durations if d),
            steps=steps)

    def _rows(self, checks):
        from wdash.api.monitor_routes import _step_history
        return _step_history(checks, self.window)

    def test_a_monitor_with_no_steps_gets_no_rows(self):
        """Every HTTP check in the product goes through this. An empty list is
        what keeps the card off their pages."""
        plain = [self.MonitorCheck(timestamp=self.end, status=UP,
                                   duration_ms=12.0)]
        self.assertEqual(self._rows(plain), [])
        self.assertEqual(self._rows([]), [])

    def test_one_row_per_step_in_order(self):
        rows = self._rows([self._run(50, [900, 120, 2000]),
                           self._run(10, [800, 130, 2200])])
        self.assertEqual([r["index"] for r in rows], [1, 2, 3])
        self.assertEqual([r["runs"] for r in rows], [2, 2, 2])

    def test_the_median_is_per_step(self):
        rows = self._rows([self._run(50, [100, 900]),
                           self._run(30, [200, 950]),
                           self._run(10, [300, 1000])])
        self.assertEqual(rows[0]["median_ms"], 200.0)
        self.assertEqual(rows[1]["median_ms"], 950.0)

    def test_the_share_says_which_step_is_the_run(self):
        """The whole point of the column: 'the checkout takes nine seconds' is
        not actionable, 'the basket page is eight of the nine' is."""
        rows = self._rows([self._run(30, [100, 800, 100])])
        self.assertEqual([r["share"] for r in rows], [10.0, 80.0, 10.0])

    def test_a_step_that_never_ran_is_absent_not_fast(self):
        """A journey stops at its first failure. Counting the steps after it
        as zero-duration is how a broken sign-in reports the checkout getting
        quicker."""
        rows = self._rows([
            self._run(40, [100, 200, 300]),
            self._run(20, [100, 200, None],
                      statuses=[self.PASSED, self.FAILED, self.SKIPPED])])
        self.assertEqual(rows[2]["median_ms"], 300.0)
        self.assertEqual(rows[2]["skipped"], 1)
        self.assertEqual(rows[1]["failed"], 1)

    def test_the_rows_are_keyed_on_the_index_not_the_name(self):
        """Descriptions are stored per run so an old run stays readable after
        the journey is edited. Grouping on them would split one step into two
        rows the day somebody fixed a typo — and the newer name is the one to
        show."""
        rows = self._rows([self._run(40, [100], names=["Clcik submit"]),
                           self._run(10, [120], names=["Click submit"])])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["runs"], 2)
        self.assertEqual(rows[0]["description"], "Click submit")

    # ---------- the trend ----------

    def test_a_step_that_got_slower_says_so(self):
        early = [self._run(minutes, [100, 1000]) for minutes in (55, 50, 45)]
        late = [self._run(minutes, [100, 2000]) for minutes in (15, 10, 5)]
        rows = self._rows(early + late)
        self.assertEqual(rows[1]["trend"]["percent"], 100.0)
        self.assertEqual(rows[1]["trend"]["was_ms"], 1000.0)
        self.assertEqual(rows[1]["trend"]["now_ms"], 2000.0)
        self.assertEqual(rows[0]["trend"]["percent"], 0.0)

    def test_a_step_that_got_faster_says_so(self):
        rows = self._rows([self._run(m, [200]) for m in (55, 50, 45)]
                          + [self._run(m, [100]) for m in (15, 10, 5)])
        self.assertEqual(rows[0]["trend"]["percent"], -50.0)

    def test_too_few_runs_on_either_side_is_no_trend(self):
        """Two against two is not a trend, it is two numbers — and a
        percentage printed from them is a coin toss with a decimal point."""
        rows = self._rows([self._run(m, [100]) for m in (55, 50)]
                          + [self._run(m, [400]) for m in (10, 5)])
        self.assertIsNone(rows[0]["trend"])

    def test_a_window_with_nothing_in_its_first_half_has_no_trend(self):
        """The common case for a monitor added this morning: everything is in
        the second half, and 'stable' would be a claim about a period with no
        data in it."""
        rows = self._rows([self._run(m, [100]) for m in (20, 15, 10, 5)])
        self.assertIsNone(rows[0]["trend"])

    # ---------- the sparkline ----------

    def test_the_sparkline_is_drawn_per_run(self):
        """Bucketed by time it drew NOTHING: a polyline needs two adjacent
        marks, a journey on a five-minute schedule fills one bucket in twelve,
        and every mark was an island. The column rendered blank on every row,
        which no assertion about numbers would have caught."""
        rows = self._rows([self._run(m, [100 + m]) for m in (50, 40, 30, 20)])
        self.assertIsNotNone(rows[0]["spark"])
        self.assertTrue(rows[0]["spark"]["runs"], "no polyline was drawn")
        self.assertEqual(rows[0]["drawn"], 4)

    def test_a_failed_step_is_marked_on_its_line(self):
        rows = self._rows([
            self._run(40, [100]),
            self._run(30, [100], statuses=[self.FAILED]),
            self._run(20, [100])])
        self.assertEqual(len(rows[0]["spark"]["failures"]), 1)

    def test_one_run_is_not_a_line(self):
        """A single mark drawn as a chart reads as a trend."""
        rows = self._rows([self._run(30, [100])])
        self.assertIsNone(rows[0]["spark"])

    def test_only_the_last_marks_are_drawn(self):
        """A window can hold five hundred runs; the sparkline is 110 pixels
        wide. The newest are the ones worth the pixels."""
        from wdash.api.monitor_routes import STEP_POINTS
        rows = self._rows([self._run(50 - i * 0.05, [100])
                           for i in range(STEP_POINTS + 40)])
        self.assertEqual(rows[0]["runs"], STEP_POINTS + 40)
        self.assertEqual(rows[0]["drawn"], STEP_POINTS)


SCREENSHOT_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                                  "elastic-step-screenshot.json")


def _screenshot_fixture():
    with open(SCREENSHOT_FIXTURE) as handle:
        return json.load(handle)


class ReplayScreenshotElasticsearch:
    """Answers the two queries a step screenshot issues, from real documents.

    Routes on what is asked for, not on call order: an adapter that stopped
    filtering by step index would get every step's reference back and pass a
    test that a call-order fake would wave through.
    """

    def __init__(self, fixture, drop=()):
        self.ref = fixture["ref"]
        self.blocks = {b["_id"]: b for b in fixture["blocks"]
                       if b["_id"] not in drop}
        self.requests = []

    def ping(self):
        return True

    def search(self, index=None, **kwargs):
        self.requests.append(kwargs)
        ids = _dig(kwargs, "query.ids.values")
        if ids is not None:
            return NotADict({"hits": {"hits": [
                self.blocks[i] for i in ids if i in self.blocks]}})

        wanted = {}
        for clause in (_dig(kwargs, "query.bool.filter") or []):
            wanted.update(clause.get("term") or {})
        source = self.ref["_source"]
        if wanted.get("synthetics.type") != "step/screenshot_ref":
            return NotADict({"hits": {"hits": []}})
        if wanted.get("monitor.check_group") != _dig(source,
                                                     "monitor.check_group"):
            return NotADict({"hits": {"hits": []}})
        if wanted.get("synthetics.step.index") != _dig(
                source, "synthetics.step.index"):
            return NotADict({"hits": {"hits": []}})
        return NotADict({"hits": {"hits": [self.ref]}})


class ElasticStepScreenshotTest(unittest.TestCase):
    """The picture of a step, out of the pieces Elastic actually stores.

    Measured against a running Heartbeat 8.19 rather than transcribed, and the
    shape is the reason this took a lab: Elastic does not store a screenshot.
    It stores one `step/screenshot_ref` per step listing 64 tiles by content
    HASH, and one `screenshot/block` per distinct hash whose `_id` is that
    hash. In the lab, 125 references pointed at 30 stored blocks, and the
    blocks behind a screenshot taken today had been written two days earlier
    by different runs of a different monitor.

    Which is why none of this can be a `get` by check group, and why a
    missing block is a fact the screen has to be able to state.
    """

    def setUp(self):
        self.fixture = _screenshot_fixture()
        self.reference = self.fixture["ref"]["_source"]
        self.group = _dig(self.reference, "monitor.check_group")
        self.index = _dig(self.reference, "synthetics.step.index")
        self.token = f"{self.group}:{self.index}"

    def _source(self, drop=()):
        return ElasticsearchMonitorSource(
            ReplayScreenshotElasticsearch(self.fixture, drop=drop),
            name="lab")

    def _shot(self, drop=()):
        return self._source(drop).step_screenshot(self.token,
                                                  Scope.unrestricted())

    # ---------- what the fixture itself says ----------

    def test_the_fixture_is_the_shape_that_needed_measuring(self):
        """If this ever fails, the rest of the class is testing a fiction."""
        blocks = self.reference["screenshot_ref"]["blocks"]
        self.assertEqual(len(blocks), 64)
        self.assertEqual({(b["width"], b["height"]) for b in blocks},
                         {(160, 90)})
        self.assertLess(len({b["hash"] for b in blocks}), len(blocks),
                        "no tile repeated, so this fixture cannot show "
                        "deduplication at all")
        stored = {b["_source"]["monitor"]["check_group"]
                  for b in self.fixture["blocks"]}
        self.assertNotIn(self.group, stored,
                         "every block was written by this run, so the fixture "
                         "cannot show that blocks outlive their run")

    # ---------- assembling ----------

    def test_it_returns_the_size_and_every_tile(self):
        shot = self._shot()
        self.assertEqual(shot["width"],
                         self.reference["screenshot_ref"]["width"])
        self.assertEqual(shot["height"],
                         self.reference["screenshot_ref"]["height"])
        self.assertEqual(len(shot["blocks"]), 64)
        self.assertEqual(shot["missing"], 0)

    def test_every_tile_carries_where_it_goes(self):
        """A tile without its position is a piece of a page nobody can put
        back. `top` of zero is a real position, so the check is on presence."""
        for tile in self._shot()["blocks"]:
            for field in ("left", "top", "width", "height", "blob", "mime"):
                self.assertIn(field, tile)
            self.assertTrue(tile["blob"])
            self.assertEqual(tile["mime"], "image/jpeg")

    def test_a_repeated_tile_is_fetched_once_and_drawn_many_times(self):
        """64 tiles, 14 of them distinct. Fetching per tile would be four and
        a half times the bytes for the same picture."""
        source = self._source()
        source.step_screenshot(self.token, Scope.unrestricted())
        asked = [r for r in source._es.requests if _dig(r, "query.ids.values")]
        self.assertEqual(len(asked), 1)
        requested = asked[0]["query"]["ids"]["values"]
        self.assertEqual(len(requested), len(set(requested)))
        self.assertLess(len(requested), 64)

    def test_a_block_that_is_gone_is_counted_not_invented(self):
        """Blocks are content-addressed and outlive the run that wrote them,
        so whatever prunes the data stream punches holes in NEWER
        screenshots. A hole reported as a tile would read as a blank region
        of the page under test."""
        gone = self.fixture["blocks"][0]["_id"]
        repeats = sum(1 for b in self.reference["screenshot_ref"]["blocks"]
                      if b["hash"] == gone)
        shot = self._shot(drop=(gone,))
        self.assertEqual(shot["missing"], repeats)
        self.assertEqual(len(shot["blocks"]), 64 - repeats)

    def test_the_step_and_the_moment_travel_with_it(self):
        shot = self._shot()
        self.assertEqual(shot["step"],
                         _dig(self.reference, "synthetics.step.name"))
        self.assertEqual(shot["taken_at"], self.reference["@timestamp"])
        self.assertEqual(shot["source"], "lab")

    # ---------- refusing ----------

    def test_a_token_for_another_step_finds_nothing(self):
        source = self._source()
        self.assertIsNone(source.step_screenshot(f"{self.group}:99",
                                                 Scope.unrestricted()))

    def test_rubbish_is_refused_without_a_query(self):
        """A token arrives from a URL. Anything that is not `group:index`
        must not become a search."""
        source = self._source()
        for token in ("", None, "no-colon", "group:", "group:two",
                      "group:2:3:x"):
            with self.subTest(token=token):
                self.assertIsNone(
                    source.step_screenshot(token, Scope.unrestricted()))
        self.assertEqual(source._es.requests, [])

    def test_a_group_with_a_colon_in_it_still_works(self):
        """Split from the RIGHT. A check group is a uuid today; a source that
        one day writes `region:group` would otherwise take the region as the
        whole id and find nothing."""
        source = self._source()
        source.step_screenshot(f"eu-west:{self.group}:{self.index}",
                               Scope.unrestricted())
        asked = source._es.requests[0]
        wanted = {}
        for clause in _dig(asked, "query.bool.filter") or []:
            wanted.update(clause.get("term") or {})
        self.assertEqual(wanted["monitor.check_group"],
                         f"eu-west:{self.group}")

    def test_a_cluster_that_refuses_is_no_screenshot_not_an_error(self):
        source = ElasticsearchMonitorSource(FakeElasticsearch(fail=True),
                                            name="lab")
        self.assertIsNone(source.step_screenshot(self.token,
                                                 Scope.unrestricted()))


class SkippedStepScreenshotTest(unittest.TestCase):
    """No token for a step that never ran — measured, then held here.

    The lab found it (`tests/test_synthetics_lab.py`): a skipped step writes
    a `step/end` document like any other and no screenshot at all, because
    nothing was on screen. Guarded from the fixture too, so the rule survives
    a machine with no lab on it.
    """

    def setUp(self):
        self.window = TimeWindow.of("24h")
        self.scope = Scope.unrestricted()
        run = _browser_runs("lab-journey-down")[-1]
        source = ElasticsearchMonitorSource(ReplayElasticsearch([run]))
        self.check = source.history("lab-journey-down", self.window,
                                    self.scope, limit=5)[-1]

    def test_the_fixture_holds_a_run_that_stopped_early(self):
        self.assertIn("skipped", [s.status for s in self.check.steps])

    def test_a_step_that_ran_carries_a_token(self):
        for step in self.check.steps:
            if step.status == "skipped":
                continue
            with self.subTest(step=step.index):
                self.assertTrue(step.screenshot_id)
                self.assertTrue(step.screenshot_id.endswith(f":{step.index}"))

    def test_a_skipped_step_carries_none(self):
        for step in self.check.steps:
            if step.status != "skipped":
                continue
            with self.subTest(step=step.index):
                self.assertIsNone(step.screenshot_id)


class StepScreenshotRouteTest(unittest.TestCase):
    """The endpoint the page fetches, and what it says when there is nothing.

    Asked of every source that can answer rather than of a named one — the
    check group is a uuid, so the source that has it is the source it came
    from, and a link that carried the source name would rot the moment
    somebody renamed one.
    """

    class Answering:
        name = "answers"

        def __init__(self, shot=None):
            self.shot, self.asked = shot, []

        def step_screenshot(self, token, scope):
            self.asked.append(token)
            return self.shot

    class Exploding:
        name = "explodes"

        def step_screenshot(self, token, scope):
            raise RuntimeError("cluster unreachable")

    class Deaf:
        """A source with no screenshots at all — the store adapter's shape."""
        name = "deaf"

    SHOT = {"width": 4, "height": 2, "blocks": [], "missing": 0}

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
            SECRET_KEY = "shots"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        grant(self.app, "admin", ["system:admin", "monitors:read"],
              indices=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "u1", "username": "admin", "email": "a@b", "groups": [],
                "role": "admin",
                "permissions": ["system:admin", "monitors:read"],
                "allowed_indices": ["*"]}
            session["_user_id"] = "u1"

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _register(self, *sources):
        for source in sources:
            self.app.hub._monitors[source.name] = source

    def _get(self, token="group-1:2"):
        return self.client.get(f"/api/monitors/step-screenshot/{token}")

    def test_the_source_that_has_it_answers(self):
        answering = self.Answering(self.SHOT)
        self._register(self.Deaf(), answering)
        response = self._get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["width"], 4)
        self.assertEqual(answering.asked, ["group-1:2"])

    def test_a_source_that_cannot_answer_is_stepped_over(self):
        """A cluster being unreachable must not turn every other source's
        screenshots into an error page."""
        answering = self.Answering(self.SHOT)
        self._register(self.Exploding(), answering)
        self.assertEqual(self._get().status_code, 200)

    def test_nothing_stored_is_a_404_that_says_why(self):
        self._register(self.Answering(None))
        response = self._get()
        self.assertEqual(response.status_code, 404)
        self.assertIn("per step", response.get_json()["error"])

    def test_it_needs_the_monitors_permission(self):
        """A screenshot of a signed-in session is at least as sensitive as
        the check that produced it."""
        from tests.support import grant
        self._register(self.Answering(self.SHOT))
        grant(self.app, "admin", ["system:admin"], indices=["*"])
        response = self._get()
        self.assertEqual(response.status_code, 403)

    def test_the_answer_is_cacheable_because_the_moment_has_passed(self):
        self._register(self.Answering(self.SHOT))
        self.assertIn("immutable",
                      self._get().headers.get("Cache-Control", ""))
