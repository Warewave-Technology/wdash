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
        buckets = [{"key": d["_source"]["monitor"]["id"],
                    "latest": {"hits": {"hits": [d]}}}
                   for d in self.documents]
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
