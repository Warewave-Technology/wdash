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
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import create_engine, select  # noqa: E402

from wdash.store.audit import AuditLog  # noqa: E402
from wdash.store.forwarding import (  # noqa: E402
    AuditForwarder, ElasticsearchSink, Sink, SinkError, SplunkSink, build_sink)
from wdash.store.schema import audit, metadata  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text="", headers=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text or json.dumps(self._payload)
        #: A real response has headers, and the sink reads Location off a
        #: refusal to say where it was being sent. A double without them
        #: forced a bare `except` into that path.
        self.headers = dict(headers or {})

    def json(self):
        return self._payload


def _as_the_real_thing(url, data):
    """What the destination itself answers a batch it accepted.

    A fake that answers `{}` to everything models a proxy, not a SIEM: Splunk
    replies `{"text": "Success", "code": 0}` and `_bulk` replies with one item
    per action. A sink that checks either of those would be untestable against
    a fake that does not send them.
    """
    if url.endswith("/_bulk"):
        documents = len((data or b"").decode().strip().splitlines()) // 2
        return FakeResponse(payload={
            "errors": False,
            "items": [{"index": {"status": 201, "_id": str(n)}}
                      for n in range(documents)]})
    return FakeResponse(payload={"text": "Success", "code": 0})


class FakeHttp:
    """The `requests` surface these sinks use, and nothing else."""

    def __init__(self, response=None, explode=False):
        self.calls = []
        #: None means "answer the way the destination would".
        self.response = response
        self.explode = explode

    def post(self, url, data=None, headers=None, auth=None, timeout=None,
             verify=None, allow_redirects=None):
        self.calls.append({"url": url, "data": data, "headers": headers or {},
                           "auth": auth, "verify": verify,
                           "allow_redirects": allow_redirects})
        if self.explode:
            raise OSError("connection refused")
        if self.response is not None:
            return self.response
        return _as_the_real_thing(url, data)


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

    def test_a_200_that_says_no_is_a_sink_error_too(self):
        """HEC answers `code: 0` for success and a non-zero code with a
        reason for everything else — over HTTP 200. Reading the status alone
        marks rows as delivered that the collector refused."""
        self.write(1)
        http = FakeHttp(FakeResponse(
            payload={"text": "Incorrect index", "code": 7}))
        forwarder = AuditForwarder(
            self.engine, SplunkSink("https://splunk.example:8088", "t",
                                    session=http))
        with self.assertRaises(SinkError) as caught:
            forwarder.sweep()
        self.assertIn("Incorrect index", str(caught.exception))
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
        response = FakeResponse(payload={
            "errors": False, "items": [{"index": {"status": 201}}]})
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


class ProxiedDestinationTest(ForwarderTestCase):
    """A destination behind an SSO proxy, against a real listener.

    Measured with the real `requests`: the proxy answered the POST with a 302
    to its login page, `requests` followed it as a GET, the login page's 200
    was read as acceptance, and three rows were marked as sent to a SIEM that
    never received them. This is the whole reason the sweep marks rows.
    """

    def setUp(self):
        super().setUp()
        self.seen = []
        self.mode = "redirect"
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(
                    int(self.headers.get("Content-Length", 0)))
                outer.seen.append(("POST", self.path))
                if outer.mode == "redirect":
                    self.send_response(302)
                    self.send_header(
                        "Location", f"http://127.0.0.1:{outer.port}/login")
                    self.end_headers()
                elif outer.mode == "html":
                    self._write(200, b"<html>Sign in</html>", "text/html")
                else:
                    self._write(200, outer.accepted(self.path, body),
                                "application/json")

            def do_GET(self):
                outer.seen.append(("GET", self.path))
                self._write(200, b"<html>Sign in</html>", "text/html")

            def _write(self, status, body, kind):
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *arguments):
                pass

        from tests.support import serve_in_background
        self.server = serve_in_background(
            HTTPServer(("127.0.0.1", 0), Handler))
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        super().tearDown()

    @staticmethod
    def accepted(path, body):
        """What the destination itself answers a batch it took."""
        if path.endswith("/_bulk"):
            documents = len(body.decode().strip().splitlines()) // 2
            return json.dumps({"errors": False,
                               "items": [{"index": {"status": 201}}
                                         for _ in range(documents)]}).encode()
        return b'{"text": "Success", "code": 0}'

    def _sinks(self):
        url = f"http://127.0.0.1:{self.port}"
        return (("splunk", SplunkSink(url, "hec-token")),
                ("elasticsearch", ElasticsearchSink(url)))

    def _refused(self, mode):
        """Both sinks against the proxy. name -> (reason, what it received).

        The same three rows for both, because nothing may be marked: a sink
        that marked them would leave the second with nothing to send.
        """
        self.mode = mode
        self.write(3)
        out = {}
        for name, sink in self._sinks():
            self.seen.clear()
            with self.assertRaises(SinkError) as caught:
                AuditForwarder(self.engine, sink).sweep()
            self.assertEqual(len(self.unforwarded()), 3,
                             f"{name}: rows were marked as sent")
            out[name] = (str(caught.exception), list(self.seen))
        return out

    def test_a_redirect_to_a_login_page_is_not_a_delivery(self):
        for name, (message, seen) in self._refused("redirect").items():
            self.assertIn("302", message, name)
            # Where it was being sent is the whole diagnosis: the URL is
            # right and something in front of it wants a sign-in.
            self.assertIn("/login", message,
                          f"{name}: the reason does not say where it went")
            self.assertEqual([kind for kind, _ in seen], ["POST"],
                             f"{name}: the redirect was followed")

    def test_an_html_page_answered_with_200_is_not_a_delivery_either(self):
        """The same proxy, serving the login form to the POST directly."""
        for name, (message, _) in self._refused("html").items():
            self.assertTrue(message, name)

    def test_the_destinations_own_answer_still_ships(self):
        """The refusals above are worth nothing if nothing gets through."""
        self.mode = "accept"
        for name, sink in self._sinks():
            self.write(3, action=f"{name} row")
            self.assertEqual(AuditForwarder(self.engine, sink).sweep(), 3,
                             name)
            self.assertEqual(self.unforwarded(), [], name)


class PartialBulkTest(ForwarderTestCase):
    """One row Elasticsearch will never index must not hold up the rest.

    `state` is a free-shaped object; an audit row whose state carries per-user
    keys ('john', 'john.doe') is refused by dynamic mapping for ever. The
    whole batch failed, the sweep always re-selects the oldest rows by id, and
    the queue stopped moving at 1,202 rows.
    """

    def _answer(self, *statuses):
        return FakeResponse(payload={
            "errors": any(status >= 300 for status in statuses),
            "items": [
                {"index": ({"status": status} if status < 300 else
                           {"status": status,
                            "error": {"type": "mapper_parsing_exception",
                                      "reason": "object mapping for [state."
                                                "user_roles.john] tried to "
                                                "parse field as object"}})}
                for status in statuses]})

    def _sweep(self, response):
        forwarder = AuditForwarder(
            self.engine,
            ElasticsearchSink("https://audit.example:9200",
                              session=FakeHttp(response)))
        with self.assertRaises(SinkError) as caught:
            forwarder.sweep()
        return str(caught.exception)

    def test_the_documents_it_took_are_not_sent_again(self):
        self.write(3)
        self._sweep(self._answer(201, 400, 201))
        self.assertEqual([row["subject"] for row in self.unforwarded()],
                         ["role:1"])

    def test_the_rejection_says_how_many_and_why(self):
        self.write(3)
        message = self._sweep(self._answer(201, 400, 201))
        self.assertIn("1 of 3", message)
        self.assertIn("mapper_parsing_exception", message)

    def test_the_error_carries_how_many_rows_it_did_mark(self):
        """The count is the caller's only way to know: the return value never
        arrives. Without it the configuration page said "nothing was marked
        as sent" over the top of rows that had been."""
        self.write(3)
        forwarder = AuditForwarder(
            self.engine,
            ElasticsearchSink("https://audit.example:9200",
                              session=FakeHttp(self._answer(201, 400, 201))))
        with self.assertRaises(SinkError) as caught:
            forwarder.sweep()
        self.assertEqual(caught.exception.marked, 2)

    def test_a_drain_counts_the_batches_that_went_whole_as_well(self):
        """`drain` walks several batches. The ones that went before the
        refusal are marked too, and were being thrown away with the count."""
        self.write(3)
        forwarder = AuditForwarder(self.engine, CountingSink(fail_after=2))
        with self.assertRaises(SinkError) as caught:
            forwarder.drain(batch=1)
        self.assertEqual(caught.exception.marked, 2)
        self.assertEqual([row["subject"] for row in self.unforwarded()],
                         ["role:2"])

    def test_an_answer_that_skips_documents_is_not_a_success(self):
        """Fewer items than actions means the far end is not the far end —
        an aggregating proxy, or a truncated body. Marking the rows on that
        is loss that looks like delivery."""
        self.write(3)
        message = self._sweep(
            FakeResponse(payload={"errors": False,
                                  "items": [{"index": {"status": 201}}]}))
        self.assertIn("3", message)
        self.assertEqual(len(self.unforwarded()), 3)

    def test_a_body_that_is_not_json_is_not_a_success(self):
        self.write(1)
        message = self._sweep(FakeResponse(text="<html>Sign in</html>"))
        self.assertTrue(message)
        self.assertEqual(len(self.unforwarded()), 1)


class FreeShapedStateTest(ForwarderTestCase):
    """The audited state is somebody else's shape, and it is not a mapping.

    'mappings updated' stores `user_roles` keyed by user identifiers — emails,
    names with dots. Under dynamic mapping 'john' is a string field and
    'john.doe' wants 'john' to be an object, which is a permanent rejection.
    """

    def _mappings_row(self):
        self.log.record("owner", "mappings updated", subject="roles",
                        state={"default_role": "viewer",
                               "user_roles": {"john": "admin",
                                              "john.doe": "viewer"}})

    def test_elasticsearch_gets_the_state_as_text(self):
        self._mappings_row()
        http = FakeHttp()
        AuditForwarder(
            self.engine,
            ElasticsearchSink("https://audit.example:9200",
                              session=http)).sweep()
        document = json.loads(http.calls[0]["data"].decode().splitlines()[1])
        self.assertIsInstance(document["state"], str,
                              "a free-shaped object under dynamic mapping")
        self.assertEqual(json.loads(document["state"])["user_roles"],
                         {"john": "admin", "john.doe": "viewer"},
                         "the state must still be there in full")

    def test_a_row_with_no_state_does_not_become_the_word_null(self):
        self.log.record("owner", "signed in", subject="owner")
        http = FakeHttp()
        AuditForwarder(
            self.engine,
            ElasticsearchSink("https://audit.example:9200",
                              session=http)).sweep()
        document = json.loads(http.calls[0]["data"].decode().splitlines()[1])
        self.assertIsNone(document["state"])

    def test_splunk_still_gets_the_object(self):
        """HEC indexes arbitrary JSON without a mapping. Flattening it there
        would cost the structure for nothing."""
        self._mappings_row()
        http = FakeHttp()
        AuditForwarder(
            self.engine,
            SplunkSink("https://splunk.example:8088", "t",
                       session=http)).sweep()
        event = json.JSONDecoder().raw_decode(
            http.calls[0]["data"].decode(), 0)[0]["event"]
        self.assertEqual(event["state"]["user_roles"]["john.doe"], "viewer")


if __name__ == "__main__":
    unittest.main()
