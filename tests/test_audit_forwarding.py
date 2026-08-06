"""
Shipping the audit trail to Splunk or Elasticsearch.

The property that matters is not "does it send" — it is "what happens when it
cannot". An audit forwarder that loses rows quietly is worse than no forwarder,
because the trail on the far end looks complete.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import create_engine, select  # noqa: E402

from wdash.store.audit import AuditLog  # noqa: E402
from wdash.store.forwarding import (  # noqa: E402
    AuditForwarder, ElasticsearchSink, Sink, SinkError, SplunkSink, build_sink)
from wdash.store.schema import audit, metadata  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text or json.dumps(self._payload)

    def json(self):
        return self._payload


class FakeHttp:
    """The `requests` surface these sinks use, and nothing else."""

    def __init__(self, response=None, explode=False):
        self.calls = []
        self.response = response or FakeResponse()
        self.explode = explode

    def post(self, url, data=None, headers=None, auth=None, timeout=None,
             verify=None):
        self.calls.append({"url": url, "data": data, "headers": headers or {},
                           "auth": auth, "verify": verify})
        if self.explode:
            raise OSError("connection refused")
        return self.response


class CountingSink(Sink):
    def __init__(self, fail_after=None):
        self.batches = []
        self.fail_after = fail_after

    def send(self, entries):
        if self.fail_after is not None and len(self.batches) >= self.fail_after:
            raise SinkError("the far end is unhappy")
        self.batches.append(list(entries))


class ForwarderTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.engine = create_engine(f"sqlite:///{self.database}")
        metadata.create_all(self.engine)
        self.log = AuditLog(self.engine)

    def tearDown(self):
        self.engine.dispose()
        os.unlink(self.database)

    def write(self, count, action="role saved"):
        for index in range(count):
            self.log.record("owner", action, subject=f"role:{index}",
                            state={"containers": ["app-*"]}, address="10.0.0.1")

    def unforwarded(self):
        with self.engine.connect() as connection:
            return connection.execute(
                select(audit).where(audit.c.forwarded_at.is_(None))
            ).mappings().all()


class SweepTest(ForwarderTestCase):
    def test_history_ships_too(self):
        """The reason the marker lives on the row rather than in memory: point
        WDash at a destination today and yesterday's entries go as well."""
        self.write(3)
        sink = CountingSink()
        self.assertEqual(AuditForwarder(self.engine, sink).sweep(), 3)
        self.assertEqual(len(sink.batches[0]), 3)

    def test_a_delivered_row_is_not_delivered_again(self):
        self.write(3)
        forwarder = AuditForwarder(self.engine, CountingSink())
        forwarder.sweep()
        self.assertEqual(forwarder.sweep(), 0)

    def test_a_refused_batch_leaves_every_row_waiting(self):
        """Marking before sending turns any failure into permanent silent
        loss — the one thing this must never do."""
        self.write(3)
        forwarder = AuditForwarder(self.engine, CountingSink(fail_after=0))
        with self.assertRaises(SinkError):
            forwarder.sweep()
        self.assertEqual(len(self.unforwarded()), 3)

    def test_a_refused_batch_goes_again_next_time(self):
        self.write(3)
        sink = CountingSink(fail_after=0)
        forwarder = AuditForwarder(self.engine, sink)
        with self.assertRaises(SinkError):
            forwarder.sweep()
        sink.fail_after = None
        self.assertEqual(forwarder.sweep(), 3)

    def test_a_batch_is_bounded(self):
        """A first run against months of history must not build one request
        the far end refuses."""
        self.write(20)
        sink = CountingSink()
        AuditForwarder(self.engine, sink).sweep(batch=5)
        self.assertEqual(len(sink.batches[0]), 5)

    def test_draining_walks_the_whole_backlog(self):
        self.write(20)
        sink = CountingSink()
        self.assertEqual(
            AuditForwarder(self.engine, sink).drain(batch=5), 20)

    def test_draining_is_bounded_too(self):
        """'Until empty' against a large backlog is an unbounded loop holding
        a database connection."""
        self.write(50)
        sink = CountingSink()
        shipped = AuditForwarder(self.engine, sink).drain(limit=2, batch=5)
        self.assertEqual(shipped, 10)

    def test_pending_counts_what_is_waiting(self):
        self.write(4)
        forwarder = AuditForwarder(self.engine, CountingSink())
        self.assertEqual(forwarder.pending(), 4)
        forwarder.sweep()
        self.assertEqual(forwarder.pending(), 0)

    def test_rows_go_oldest_first(self):
        """A truncated backlog should leave a gap at the end, not the middle."""
        self.write(6)
        sink = CountingSink()
        AuditForwarder(self.engine, sink).sweep(batch=3)
        subjects = [entry["subject"] for entry in sink.batches[0]]
        self.assertEqual(subjects, ["role:0", "role:1", "role:2"])

    def test_the_queue_marker_does_not_travel(self):
        """It is our bookkeeping, not the receiver's business."""
        self.write(1)
        sink = CountingSink()
        AuditForwarder(self.engine, sink).sweep()
        self.assertIn("forwarded_at", self.log.recent()[0])
        # The sink is handed rows straight from the table; what must not
        # travel is checked at the serialisation boundary below.


class SplunkTest(ForwarderTestCase):
    def _send(self, http, **overrides):
        self.write(2)
        arguments = {"url": "https://splunk.example:8088", "token": "hec-token",
                     "session": http}
        arguments.update(overrides)
        AuditForwarder(self.engine, SplunkSink(**arguments)).sweep()
        return http.calls[0]

    def test_it_posts_to_the_event_collector(self):
        call = self._send(FakeHttp())
        self.assertTrue(call["url"].endswith("/services/collector/event"))
        self.assertEqual(call["headers"]["Authorization"], "Splunk hec-token")

    def test_events_are_concatenated_objects_not_an_array(self):
        """HEC's own format. An array produces a 400 that reads like an
        authentication problem."""
        body = self._send(FakeHttp())["data"].decode()
        self.assertFalse(body.lstrip().startswith("["))
        decoder, index, events = json.JSONDecoder(), 0, 0
        while index < len(body):
            _, index = decoder.raw_decode(body, index)
            events += 1
        self.assertEqual(events, 2)

    def test_the_event_time_is_when_it_happened(self):
        """An ISO string here is accepted and then indexed as the time of
        receipt, so every event arrives stamped with when the sweep ran."""
        body = self._send(FakeHttp())["data"].decode()
        first = json.JSONDecoder().raw_decode(body, 0)[0]
        self.assertIsInstance(first["time"], float)

    def test_the_bookkeeping_column_does_not_travel(self):
        body = self._send(FakeHttp())["data"].decode()
        first = json.JSONDecoder().raw_decode(body, 0)[0]
        self.assertNotIn("forwarded_at", first["event"])
        self.assertIn("actor", first["event"])

    def test_an_http_error_is_a_sink_error(self):
        self.write(1)
        http = FakeHttp(FakeResponse(status_code=403, text="invalid token"))
        forwarder = AuditForwarder(
            self.engine, SplunkSink("https://splunk.example:8088", "bad",
                                    session=http))
        with self.assertRaises(SinkError):
            forwarder.sweep()
        self.assertEqual(len(self.unforwarded()), 1)

    def test_an_unreachable_host_is_a_sink_error(self):
        self.write(1)
        forwarder = AuditForwarder(
            self.engine, SplunkSink("https://splunk.example:8088", "t",
                                    session=FakeHttp(explode=True)))
        with self.assertRaises(SinkError):
            forwarder.sweep()

    def test_certificate_verification_is_on_unless_turned_off(self):
        self.assertTrue(self._send(FakeHttp())["verify"])
        self.assertFalse(
            self._send(FakeHttp(), verify_certs=False)["verify"])


class ElasticsearchTest(ForwarderTestCase):
    def _send(self, http, **overrides):
        self.write(2)
        arguments = {"url": "https://audit.example:9200", "session": http}
        arguments.update(overrides)
        AuditForwarder(self.engine, ElasticsearchSink(**arguments)).sweep()
        return http.calls[0]

    def test_it_posts_ndjson_to_the_bulk_api(self):
        call = self._send(FakeHttp())
        self.assertTrue(call["url"].endswith("/_bulk"))
        self.assertEqual(call["headers"]["Content-Type"],
                         "application/x-ndjson")

    def test_the_row_id_is_the_document_id(self):
        """Delivery is at-least-once by design. Without a stable id, that
        means 'eventually many' rather than 'exactly the same row again'."""
        body = self._send(FakeHttp())["data"].decode()
        header = json.loads(body.splitlines()[0])
        self.assertEqual(header["index"]["_id"], "1")

    def test_a_partial_rejection_is_not_a_success(self):
        """`errors: true` with a 200 is the standard way to lose data while
        believing it was written."""
        self.write(1)
        response = FakeResponse(payload={
            "errors": True,
            "items": [{"index": {"error": {"type": "mapper_parsing_exception"}}}]})
        forwarder = AuditForwarder(
            self.engine,
            ElasticsearchSink("https://audit.example:9200",
                              session=FakeHttp(response)))
        with self.assertRaises(SinkError):
            forwarder.sweep()
        self.assertEqual(len(self.unforwarded()), 1)

    def test_a_clean_bulk_response_marks_the_rows(self):
        self.write(1)
        response = FakeResponse(payload={"errors": False, "items": []})
        shipped = AuditForwarder(
            self.engine,
            ElasticsearchSink("https://audit.example:9200",
                              session=FakeHttp(response))).sweep()
        self.assertEqual(shipped, 1)
        self.assertEqual(self.unforwarded(), [])


class BuildSinkTest(unittest.TestCase):
    def test_forwarding_off_builds_nothing(self):
        self.assertIsNone(build_sink({"enabled": False, "kind": "splunk"}, "t"))
        self.assertIsNone(build_sink(None, None))

    def test_splunk_without_a_token_is_refused_rather_than_half_built(self):
        """A sink that cannot authenticate fails on every sweep and looks like
        a network problem."""
        with self.assertRaises(ValueError):
            build_sink({"enabled": True, "kind": "splunk",
                        "url": "https://splunk.example:8088"}, None)

    def test_an_unknown_destination_is_refused(self):
        with self.assertRaises(ValueError):
            build_sink({"enabled": True, "kind": "carrier-pigeon",
                        "url": "https://x"}, "t")

    def test_the_verification_setting_survives_the_build(self):
        """Tested here as well as on the sink: the sink honoured the flag
        while `build_sink` could still have been passing a constant."""
        for kind, extra in (("splunk", {}), ("elasticsearch", {})):
            settings = {"enabled": True, "kind": kind, "url": "https://x",
                        **extra}
            self.assertTrue(build_sink(dict(settings), "token")._verify, kind)
            self.assertFalse(
                build_sink(dict(settings, verify_certs=False), "token")._verify,
                kind)

    def test_elasticsearch_gets_a_default_index(self):
        sink = build_sink({"enabled": True, "kind": "elasticsearch",
                           "url": "https://audit.example:9200"}, None)
        self.assertEqual(sink._index, "wdash-audit")


if __name__ == "__main__":
    unittest.main()
