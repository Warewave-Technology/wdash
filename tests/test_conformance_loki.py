"""
The Loki adapter against the shared conformance suite.

Written against the suite rather than audited after the fact — which is the
whole reason the suite exists. Every property it checks was learned the hard
way in Elasticsearch, and Loki has the same traps in a different dialect: an
empty stream selector is a syntax error rather than a wildcard, but "the scope
permits nothing" still has to mean "issue no query".

The fake speaks Loki's HTTP API, so the adapter is exercised through the same
path it uses against a real server: URL, parameters, JSON shape.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conformance import Harness, LogSourceConformance  # noqa: E402
from wdash.hub.adapters.loki import LokiLogSource, _escape  # noqa: E402

SERVICES = ["api-gateway", "payment-service"]


class FakeResponse:
    def __init__(self, payload, status_code=200, text=""):
        self._payload = payload
        self.status_code = status_code
        self.text = text or json.dumps(payload)

    def json(self):
        return self._payload


class FakeLoki(Harness):
    """Loki's HTTP API, enough of it."""

    def __init__(self):
        self._requests = []
        self._fail_next = False
        #: Windows Loki has data for. None means "every window".
        self._labels_present = None

    # --- harness contract ---

    def requests(self):
        # Label lookups are how the adapter learns what exists; they are not
        # data queries, and counting them would make "issued no query"
        # impossible to state.
        return [request for request in self._requests
                if "/label/" not in request["path"]]

    def reset(self):
        self._requests = []

    def containers(self):
        return SERVICES

    def fail_next(self):
        self._fail_next = True

    def no_labels(self):
        """Loki reporting an empty label list, as it does for a quiet window."""
        self._labels_present = []

    def mentions(self, request, text):
        return text in json.dumps(request, default=str)

    def carries_window(self, request, window):
        """Loki takes nanoseconds since the epoch, not an ISO date."""
        params = request.get("params") or {}
        start = params.get("start") or params.get("time")
        if not start:
            return False
        return abs(int(start) / 1_000_000_000 - window.start.timestamp()) < 2

    # --- the requests session the adapter holds ---

    def get(self, url, params=None, headers=None, auth=None, timeout=None,
            verify=None):
        path = url.split("://", 1)[-1].split("/", 1)[-1]
        self._requests.append({"path": "/" + path, "params": dict(params or {})})

        if self._fail_next:
            self._fail_next = False
            return FakeResponse({}, status_code=503, text="unavailable")

        if "/label/" in path:
            data = SERVICES if self._labels_present is None else self._labels_present
            return FakeResponse({"status": "success", "data": data})
        if path.endswith("ready"):
            return FakeResponse({}, text="ready")
        if "query_range" in path:
            return FakeResponse(self._range(params or {}))
        return FakeResponse(self._instant())

    def _range(self, params):
        if "count_over_time" in (params.get("query") or ""):
            return {"status": "success", "data": {"resultType": "matrix",
                                                  "result": [{
                "metric": {}, "values": [[1754305800, "7"], [1754305860, "3"]]}]}}
        return {"status": "success", "data": {"resultType": "streams", "result": [{
            "stream": {"service_name": "api-gateway", "level": "info",
                       "namespace": "prod"},
            "values": [["1754305800000000000",
                        '{"msg":"hello","trace_id":"abc","level":"info"}'],
                       ["1754305801000000000", "plain text line"]],
        }]}}

    def _instant(self):
        return {"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": {"level": "info"}, "value": [1754305800, "12"]},
            {"metric": {"level": "error"}, "value": [1754305800, "3"]},
        ]}}


class LokiConformanceTest(LogSourceConformance, unittest.TestCase):
    def build(self):
        harness = FakeLoki()
        source = LokiLogSource("http://loki:3100", name="loki-lab",
                               session=harness)
        return source, harness


class LokiSpecificTest(unittest.TestCase):
    """The parts that are Loki's own problem rather than the hub's."""

    def setUp(self):
        self.harness = FakeLoki()
        self.source = LokiLogSource("http://loki:3100", name="loki",
                                    session=self.harness)

    def _search(self, scope=None, **overrides):
        import datetime as dt

        from wdash.hub import LogQuery, Scope, TimeWindow
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        arguments = {"window": TimeWindow.exact(now - dt.timedelta(hours=1), now),
                     "text": "*", "limit": 10}
        arguments.update(overrides)
        return self.source.search(LogQuery(**arguments),
                                  scope or Scope.unrestricted())

    # --- the two empties ---

    def test_labels_are_read_over_the_window_being_searched(self):
        """A label value only exists for a time range.

        Asked without one, Loki answers for its own default — the last six
        hours. So a search over the last seven days found no streams and
        reported it as an authorization boundary, on an installation whose
        data was simply older than six hours.
        """
        import datetime as dt

        from wdash.hub import LogQuery, Scope, TimeWindow
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        window = TimeWindow.exact(now - dt.timedelta(days=7), now)
        self.source.search(LogQuery(window=window, text="*", limit=10),
                           Scope.unrestricted())

        label_calls = [request for request in self.harness._requests
                       if "/label/" in request["path"]]
        self.assertTrue(label_calls, "no label lookup was made at all")
        params = label_calls[0]["params"]
        self.assertIn("start", params, "the label lookup carried no window")
        self.assertAlmostEqual(
            int(params["start"]) / 1_000_000_000, window.start.timestamp(),
            delta=2, msg="the label lookup used a window of its own")

    def test_a_quiet_window_is_a_note_and_not_a_refusal(self):
        """'You may not see this' and 'nothing was logged then' are different.

        They used to be one message. One of them is somebody's fault and the
        other is a time picker, and the first sends people to their
        administrator.
        """
        self.harness.no_labels()
        page = self._search()
        self.assertTrue(page.informational)
        self.assertFalse(page.records)
        joined = " ".join(page.warnings).lower()
        self.assertIn("time range", joined)
        self.assertNotIn("scope", joined)

    def test_a_scope_that_permits_nothing_is_still_a_refusal(self):
        """The other half: this one must NOT soften into a note."""
        from wdash.hub import Scope
        page = self._search(scope=Scope(principal="narrow",
                                        containers=("nothing-matches-*",)))
        self.assertFalse(page.informational)
        self.assertIn("scope", " ".join(page.warnings).lower())

    def test_label_lookups_are_cached_per_window(self):
        """One cache slot served whatever the first caller asked for.

        A one-hour search could then answer from a seven-day catalogue, or the
        catalogue could answer from a one-hour search — either way the list is
        for a window nobody asked about.
        """
        import datetime as dt

        from wdash.hub import LogQuery, Scope, TimeWindow
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        for hours in (1, 1, 24):
            self.source.search(
                LogQuery(window=TimeWindow.exact(now - dt.timedelta(hours=hours), now),
                         text="*", limit=10), Scope.unrestricted())

        windows = {request["params"].get("start")
                   for request in self.harness._requests
                   if "/label/" in request["path"]}
        self.assertEqual(len(windows), 2,
                         "one window was reused for another, or nothing cached")

    def test_the_catalogue_looks_further_back_than_lokis_default(self):
        """`containers()` has no window: it answers "what could be granted".

        Loki's own default is six hours, short enough that a quiet morning
        reads as an empty installation on the role editor's picker.
        """
        from wdash.hub import Scope
        self.source.containers(Scope.unrestricted())
        label_calls = [request for request in self.harness._requests
                       if "/label/" in request["path"]]
        span_ns = (int(label_calls[0]["params"]["end"])
                   - int(label_calls[0]["params"]["start"]))
        self.assertGreater(span_ns / 1_000_000_000, 6 * 3600,
                           "the catalogue inherited Loki's six-hour default")

    def test_the_selector_is_never_empty(self):
        """`{}` is a LogQL syntax error, not a wildcard."""
        from wdash.hub.adapters.loki import LokiError
        with self.assertRaises(LokiError):
            self.source._selector([])

    def test_one_stream_uses_equality_and_several_use_a_regex(self):
        self.assertEqual(self.source._selector(["api-gateway"]),
                         '{service_name="api-gateway"}')
        self.assertIn("=~", self.source._selector(SERVICES))

    def test_label_values_are_escaped(self):
        """A quote would end the string early and change which streams match."""
        self.assertNotIn('"', _escape('bad"value')[1:-1].replace('\\"', ""))
        selector = self.source._selector(['a"b'])
        self.assertIn('\\"', selector)

    def test_the_scope_reaches_the_selector(self):
        from wdash.hub import Scope
        self.harness.reset()
        self._search(scope=Scope(containers=("api-gateway",),
                                 permissions=frozenset({"logs:read"})))
        query = self.harness.requests()[0]["params"]["query"]
        self.assertIn("api-gateway", query)
        self.assertNotIn("payment-service", query)

    def test_a_text_search_becomes_a_line_filter(self):
        self.harness.reset()
        self._search(text="timeout")
        self.assertIn('|= "timeout"',
                      self.harness.requests()[0]["params"]["query"])

    def test_an_inexpressible_query_is_refused_not_dropped(self):
        """Silently dropping a clause returns MORE than was asked for, which is
        the one direction an access-controlled system must never round in."""
        page = self._search(text="service:a OR service:b")
        self.assertTrue(page.warnings)
        self.assertTrue(page.partial)

    def test_labels_become_the_resource(self):
        record = self._search().records[0]
        self.assertEqual(record.service, "api-gateway")
        self.assertEqual(record.resource.get("namespace"), "prod")

    def test_a_structured_line_yields_attributes_and_a_trace_id(self):
        record = self._search().records[0]
        self.assertEqual(record.trace_id, "abc")
        self.assertEqual(record.attributes.get("msg"), "hello")

    def test_a_plain_line_is_kept_as_the_body_without_invented_structure(self):
        record = self._search().records[1]
        self.assertEqual(record.body, "plain text line")
        self.assertEqual(record.attributes, {})

    def test_the_severity_label_is_used_when_present(self):
        self.assertEqual(self._search().records[0].severity, "INFO")

    def test_the_total_is_not_invented(self):
        """Loki reports no match count for a range query. Reporting the number
        returned is honest; a made-up total is a number people reason about."""
        page = self._search(limit=2)
        self.assertEqual(page.total, len(page.records))
        self.assertTrue(page.warnings, "a capped result said nothing about it")
        self.assertFalse(page.counted, "a floor was reported as a match count")

    def test_a_result_under_the_limit_is_a_real_count(self):
        """Loki did return everything there was, so the total is exact.

        Marking every Loki page uncertain would make the flag useless — the
        one it appears on is the one where it means something.
        """
        page = self._search(limit=1000)
        self.assertTrue(page.counted)
        self.assertFalse(page.warnings)

    def test_fetch_returns_none_rather_than_a_guess(self):
        """A stream plus a nanosecond is not a durable handle, and returning
        the wrong line is worse than returning none."""
        from wdash.hub.models import SourceRef
        from wdash.hub import Scope
        self.assertIsNone(
            self.source.fetch(SourceRef("loki", "api-gateway", "1"),
                              Scope.unrestricted()))

    def test_severity_buckets_are_normalised(self):
        """Loki labels are lower case; the neutral model promises otherwise.

        Two sources answering one panel with "ERROR" and "error" draw two bars
        for one thing, and colour only one of them red.
        """
        from wdash.hub.aggregation import Terms
        import datetime as dt
        from wdash.hub import LogQuery, Scope, TimeWindow

        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        result = self.source.aggregate(
            LogQuery(window=TimeWindow.exact(now - dt.timedelta(hours=1), now),
                     text="*"),
            [Terms(name="levels", field="severity")], Scope.unrestricted())

        keys = [bucket.key for bucket in result.get("levels")]
        self.assertIn("INFO", keys)
        self.assertIn("ERROR", keys)
        self.assertNotIn("info", keys)

    def test_unsupported_capabilities_are_not_declared(self):
        """Loki has no field mappings and no document ids; claiming otherwise
        would offer features that return something thinner than the name."""
        from wdash.hub import Capability
        for absent in (Capability.FIELD_STATS, Capability.CONTEXT,
                       Capability.RAW_DOCUMENT):
            self.assertNotIn(absent, self.source.capabilities)


if __name__ == "__main__":
    unittest.main(verbosity=2)
