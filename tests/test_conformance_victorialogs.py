"""
VictoriaLogs against the adapter contract, plus what is its own problem.

The shared suite holds the boundary rules every source obeys. What is here is
the part LogsQL gets to be different about — and the two places where being
closer to Elasticsearch than Loki is changes the answer: it can count, and it
can list field values.
"""

import datetime as dt
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conformance import Harness, LogSourceConformance  # noqa: E402

from wdash.hub.adapters.victorialogs import VictoriaLogsSource  # noqa: E402
from wdash.hub.source import Capability  # noqa: E402

SERVICES = ["api-gateway", "auth-service", "checkout-api", "payment-service"]

#: The shape VictoriaLogs actually returns, taken from a running instance
#: rather than from what an adapter would find convenient.
ROWS = [
    {"_time": "2026-08-04T11:59:00.000000Z",
     "_stream_id": "0000000000000000d749dff69bface69",
     "_stream": '{level="info",service="api-gateway"}',
     "_msg": "GET /orders 200 in 12ms", "host": "api-gateway-1",
     "level": "info", "service": "api-gateway", "trace_id": "abc123"},
    {"_time": "2026-08-04T11:58:00.000000Z",
     "_stream_id": "0000000000000000b315f26be47bbf28",
     "_stream": '{level="error",service="api-gateway"}',
     "_msg": "upstream timeout", "host": "api-gateway-2",
     "level": "error", "service": "api-gateway"},
]


def _selects(selector, field, values):
    """Which of `values` a LogsQL container filter would select.

    Enough of LogsQL's documented semantics to judge the scope filter this
    adapter renders, and no more: `field:"phrase"` is a phrase filter, which
    matches the phrase anywhere in the value on word boundaries;
    `field:in("a", ...)` is the multi-exact filter, which matches whole
    values; `OR` between them. Anything else is a test failure, not a guess.
    """
    import re

    string = r'"((?:[^"\\]|\\.)*)"'
    unquote = lambda text: re.sub(r"\\(.)", r"\1", text)  # noqa: E731
    inner = selector[1:-1] if selector.startswith("(") else selector
    chosen = set()
    for clause in inner.split(" OR "):
        exact = re.fullmatch(rf"{re.escape(field)}:in\((.*)\)", clause)
        phrase = re.fullmatch(rf"{re.escape(field)}:{string}", clause)
        if exact:
            wanted = {unquote(v) for v in re.findall(string, exact.group(1))}
            chosen |= {value for value in values if value in wanted}
        elif phrase:
            words = re.compile(rf"(?<!\w){re.escape(unquote(phrase.group(1)))}"
                               rf"(?!\w)")
            chosen |= {value for value in values if words.search(value)}
        else:
            raise AssertionError(f"not a container filter: {clause!r}")
    return chosen


class FakeResponse:
    def __init__(self, text="", status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else json.dumps(payload or {})

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeVictoriaLogs(Harness):
    """VictoriaLogs' HTTP API, enough of it."""

    def __init__(self):
        self._requests = []
        self._fail_next = False
        self._values_present = None

    # --- harness contract ---

    def requests(self):
        # Field-value lookups are how the adapter learns what exists; they are
        # not data queries, and counting them would make "issued no query"
        # impossible to state.
        return [request for request in self._requests
                if "field_values" not in request["path"]
                and "field_names" not in request["path"]]

    def reset(self):
        self._requests = []

    def containers(self):
        return SERVICES

    def fail_next(self):
        self._fail_next = True

    def no_values(self):
        self._values_present = []

    def mentions(self, request, text):
        return text in json.dumps(request, default=str)

    def carries_window(self, request, window):
        params = request.get("params") or {}
        start = params.get("start")
        if not start:
            return False
        parsed = dt.datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        return abs((parsed - window.start).total_seconds()) < 2

    # --- the requests session the adapter holds ---

    def post(self, url, data=None, headers=None, auth=None, timeout=None,
             verify=None):
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1]
        self._requests.append({"path": path, "params": dict(data or {})})

        if self._fail_next:
            self._fail_next = False
            return FakeResponse(text="too many requests", status_code=429)

        if "field_values" in path:
            field = (data or {}).get("field")
            if self._values_present == []:
                return FakeResponse(payload={"values": []})
            if field == "service":
                return FakeResponse(payload={"values": [
                    {"value": name, "hits": 3} for name in SERVICES]})
            return FakeResponse(payload={"values": [
                {"value": "info", "hits": 7}, {"value": "error", "hits": 2}]})

        if "field_names" in path:
            return FakeResponse(payload={"values": [
                {"value": "_msg", "hits": 9}, {"value": "level", "hits": 9},
                {"value": "service", "hits": 9}]})

        if "stats_query" in path:
            return FakeResponse(payload={"status": "success", "data": {
                "resultType": "vector",
                "result": [{"metric": {"__name__": "hits"},
                            "value": [1785944978.5, "42"]}]}})

        if "hits" in path:
            return FakeResponse(payload={"hits": [
                {"fields": {"level": "info"},
                 "timestamps": ["2026-08-04T11:58:00Z", "2026-08-04T11:59:00Z"],
                 "values": [4, 3], "total": 7},
                {"fields": {"level": "error"},
                 "timestamps": ["2026-08-04T11:59:00Z"],
                 "values": [2], "total": 2}]})

        return FakeResponse(text="\n".join(json.dumps(row) for row in ROWS))

    def get(self, url, auth=None, timeout=None, verify=None):
        return FakeResponse(text="OK")


class VictoriaLogsConformanceTest(LogSourceConformance, unittest.TestCase):
    def build(self):
        harness = FakeVictoriaLogs()
        return VictoriaLogsSource("http://vl:9428", name="victorialogs",
                                  stream_field="service",
                                  session=harness), harness


class VictoriaLogsSpecificTest(unittest.TestCase):
    """The parts that are LogsQL's own problem rather than the hub's."""

    def setUp(self):
        self.harness = FakeVictoriaLogs()
        self.source = VictoriaLogsSource(
            "http://vl:9428", name="victorialogs", stream_field="service",
            session=self.harness)

    def _query(self, **overrides):
        from wdash.hub import LogQuery, TimeWindow
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        arguments = {"window": TimeWindow.exact(now - dt.timedelta(hours=1), now),
                     "text": "*", "limit": 10}
        arguments.update(overrides)
        return LogQuery(**arguments)

    def _search(self, scope=None, **overrides):
        from wdash.hub import Scope
        return self.source.search(self._query(**overrides),
                                  scope or Scope.unrestricted())

    def _sent(self, marker="logsql/query"):
        return next(request for request in reversed(self.harness._requests)
                    if marker in request["path"])

    # --- capabilities ---

    def test_it_declares_the_two_capabilities_loki_lacks(self):
        """Not a detail: the sidebar and the record count are both built from
        declared capability, so understating them removes working features."""
        self.assertIn(Capability.FIELD_STATS, self.source.capabilities)
        self.assertIn(Capability.AGGREGATION, self.source.capabilities)

    def test_it_declares_no_capability_it_cannot_serve(self):
        """`_stream_id` names a stream, not a line."""
        self.assertNotIn(Capability.RAW_DOCUMENT, self.source.capabilities)
        self.assertNotIn(Capability.CONTEXT, self.source.capabilities)

    def test_fetch_returns_none_rather_than_a_guess(self):
        from wdash.hub import Scope
        from wdash.hub.models import SourceRef
        self.assertIsNone(self.source.fetch(
            SourceRef("victorialogs", "api-gateway", "1"), Scope.unrestricted()))

    # --- the selector ---

    def test_the_container_filter_is_never_empty(self):
        """An empty LogsQL filter means `*` — every stream, which is the exact
        opposite of "the scope permits nothing"."""
        from wdash.hub.adapters.victorialogs import VictoriaLogsError
        with self.assertRaises(VictoriaLogsError):
            self.source._selector([])

    def test_one_container_and_several_use_the_same_exact_filter(self):
        self.assertEqual(self.source._selector(["api-gateway"]),
                         'service:in("api-gateway")')
        self.assertEqual(self.source._selector(["a", "b"]),
                         'service:in("a", "b")')

    def test_values_are_always_quoted(self):
        """An unquoted value ends at the first space and the rest becomes a
        separate filter, which silently widens the query."""
        rendered = self.source._selector(["payment service"])
        self.assertEqual(rendered, 'service:in("payment service")')

    def test_an_allowed_name_selects_only_itself(self):
        """The scope decides which values may be read, and the filter has to
        select exactly those.

        It rendered `service:"app-billing"`, which LogsQL reads as a PHRASE
        filter: the words `app billing` anywhere in the value, on word
        boundaries. So a role holding `app-*` and `-*-pii-*` was correctly
        refused `app-billing-pii-eu` by the scope, and read it anyway through
        the `app-billing` it was allowed. The same shape widened every exact
        grant (`pay` read `pay-api`) and every suffix pattern.

        Judged with LogsQL's documented semantics, modelled in `_selects`:
        a phrase filter matches on word boundaries, `in(...)` matches whole
        values.
        """
        from wdash.hub import Scope

        available = ["app-billing", "app-billing-pii-eu", "app-web",
                     "api-gateway", "api-gateway-internal", "pay", "pay-api"]
        scope = Scope(principal="p",
                      containers=("app-*", "-*-pii-*", "api-gateway", "pay"))
        allowed = scope.resolve(available, source=self.source.name)
        self.assertEqual(sorted(allowed),
                         ["api-gateway", "app-billing", "app-web", "pay"])

        rendered = self.source._selector(allowed)
        self.assertEqual(sorted(_selects(rendered, "service", available)),
                         sorted(allowed),
                         f"{rendered} selects values the scope refused")

    def test_a_quote_in_a_value_cannot_end_the_string(self):
        rendered = self.source._selector(['evil" OR service:*'])
        self.assertNotIn('" OR service:*"', rendered.replace('\\"', ""))
        self.assertIn('\\"', rendered)

    # --- counting ---

    def test_the_total_is_a_real_count(self):
        """The reason this adapter is not shaped like Loki's. The number on
        screen is the number of matches, which is what people assume."""
        page = self._search()
        self.assertEqual(page.total, 42)
        self.assertTrue(page.counted)
        self.assertGreater(page.total, len(page.records))

    def test_a_failed_count_is_admitted_rather_than_guessed(self):
        """Falling back to len(records) silently turns a page into a total."""
        original = self.source._count
        self.source._count = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("stats unavailable"))
        try:
            page = self._search()
        finally:
            self.source._count = original
        self.assertFalse(page.counted)
        self.assertEqual(page.total, len(page.records))
        self.assertTrue(page.warnings)

    # --- the two empties ---

    def test_a_quiet_window_is_a_note_and_not_a_refusal(self):
        self.harness.no_values()
        page = self._search()
        self.assertTrue(page.informational)
        joined = " ".join(page.warnings).lower()
        self.assertIn("time range", joined)
        self.assertNotIn("scope", joined)

    def test_a_scope_that_permits_nothing_is_still_a_refusal(self):
        from wdash.hub import Scope
        page = self._search(scope=Scope(principal="narrow",
                                        containers=("nothing-matches-*",)))
        self.assertFalse(page.informational)
        self.assertIn("scope", " ".join(page.warnings).lower())

    # --- field statistics ---

    def test_field_statistics_come_from_the_backend(self):
        """Approximating from a page of results describes the page, not the
        data — which is why this is a capability rather than a helper."""
        from wdash.hub import Scope
        stats = self.source.field_stats(self._query(), Scope.unrestricted(),
                                        fields=["level"])
        self.assertEqual(stats[0].field, "level")
        self.assertEqual(stats[0].values[0].count, 7)

    def test_field_statistics_are_the_hub_types_not_dictionaries(self):
        """The first version returned dictionaries, which type-checked nowhere
        and failed at the one call site the moment a real request arrived."""
        from wdash.hub import Scope
        from wdash.hub.models import FieldStat, FieldValue
        stats = self.source.field_stats(self._query(), Scope.unrestricted(),
                                        fields=["level"])
        self.assertIsInstance(stats[0], FieldStat)
        self.assertIsInstance(stats[0].values[0], FieldValue)

    def test_two_spellings_of_one_level_become_one_row(self):
        """VictoriaLogs stores what was written: `warn` and `warning` come
        back as separate rows, and both are WARN. Unmerged they put the same
        label on the sidebar twice with the counts split between them.
        """
        # `post`, not `get`: every VictoriaLogs endpoint is a POST, and
        # overriding the wrong one leaves the default fixture in place — a
        # test that exercises nothing and passes.
        def values(url, data=None, **kwargs):
            if "field_values" in url:
                return FakeResponse(payload={"values": [
                    {"value": "warn", "hits": 948},
                    {"value": "warning", "hits": 1},
                    {"value": "info", "hits": 4602}]})
            return FakeResponse(payload={"values": []})

        self.harness.post = values
        from wdash.hub import Scope
        stats = self.source.field_stats(self._query(), Scope.unrestricted(),
                                        fields=["severity"])
        counts = {value.value: value.count for value in stats[0].values}
        self.assertEqual(counts["WARN"], 949)
        self.assertEqual(len([v for v in stats[0].values if v.value == "WARN"]),
                         1)

    def test_a_field_the_backend_cannot_count_is_left_out(self):
        """High-cardinality fields answer with every value at zero hits. A
        list of values with no numbers beside them is not a statistic, and
        showing it invites somebody to read the zeros as real."""
        def uncountable(url, data=None, **kwargs):
            if "field_values" in url:
                return FakeResponse(payload={"values": [
                    {"value": "abc", "hits": 0}, {"value": "def", "hits": 0}]})
            return FakeResponse(payload={"values": []})

        self.harness.post = uncountable
        from wdash.hub import Scope
        self.assertEqual(
            self.source.field_stats(self._query(), Scope.unrestricted(),
                                    fields=["trace_id"]),
            [])

    def test_the_value_list_is_bounded(self):
        """`top` is what keeps a field with a thousand values from becoming a
        thousand rows in a sidebar."""
        def many(url, data=None, **kwargs):
            if "field_values" in url:
                return FakeResponse(payload={"values": [
                    {"value": f"v{i}", "hits": 100 - i} for i in range(40)]})
            return FakeResponse(payload={"values": []})

        self.harness.post = many
        from wdash.hub import Scope
        stats = self.source.field_stats(self._query(), Scope.unrestricted(),
                                        fields=["host"], top=5)
        self.assertEqual(len(stats[0].values), 5)
        self.assertEqual(stats[0].values[0].value, "v0")

    def test_field_statistic_keys_are_normalised(self):
        from wdash.hub import Scope
        stats = self.source.field_stats(self._query(), Scope.unrestricted(),
                                        fields=["severity"])
        self.assertEqual({value.value for value in stats[0].values},
                         {"INFO", "ERROR"})

    def test_field_statistics_respect_the_scope(self):
        from wdash.hub import Scope
        stats = self.source.field_stats(
            self._query(), Scope(principal="narrow", containers=("nothing-*",)),
            fields=["level"])
        self.assertEqual(stats, [])

    def test_the_short_histogram_form_works_too(self):
        """Declared HISTOGRAM without defining the method; every caller went
        through `aggregate`, so nothing failed until something used it."""
        from wdash.hub import Scope
        buckets = self.source.histogram(self._query(), Scope.unrestricted())
        self.assertTrue(buckets)

    # --- severity ---

    def test_severity_is_normalised_on_records(self):
        page = self._search()
        self.assertEqual({record.severity for record in page.records},
                         {"INFO", "ERROR"})

    def test_severity_buckets_are_normalised(self):
        """VictoriaLogs stores what was written, which is usually lower case.
        Two sources answering one panel with "ERROR" and "error" draw two
        bars for the same thing."""
        from wdash.hub import Scope
        from wdash.hub.aggregation import Terms
        result = self.source.aggregate(
            self._query(), [Terms(name="levels", field="severity")],
            Scope.unrestricted())
        self.assertEqual({bucket.key for bucket in result.buckets["levels"]},
                         {"INFO", "ERROR"})

    def test_two_spellings_of_one_level_merge_rather_than_double(self):
        """Normalising can map two keys onto one; two buckets with the same
        key render as two bars each showing half the number."""
        from wdash.hub.adapters.victorialogs import _merge_buckets
        merged = _merge_buckets([("WARN", 3), ("WARN", 2), ("INFO", 1)])
        self.assertEqual([(bucket.key, bucket.count) for bucket in merged],
                         [("WARN", 5), ("INFO", 1)])

    # --- histogram ---

    def test_the_histogram_is_transposed_into_neutral_buckets(self):
        """VictoriaLogs answers with one series per group and parallel arrays;
        the neutral model wants one bucket per instant."""
        from wdash.hub import Scope
        from wdash.hub.aggregation import DateHistogram, Terms
        result = self.source.aggregate(
            self._query(),
            [DateHistogram(name="timeline", interval="1m",
                           sub=(Terms(name="levels", field="severity"),))],
            Scope.unrestricted())
        buckets = result.buckets["timeline"]
        self.assertEqual(len(buckets), 2)
        totals = {bucket.key_text: bucket.count for bucket in buckets}
        # 11:59 carries 3 info and 2 error in the fixture.
        self.assertEqual(totals["2026-08-04T11:59:00Z"], 5)
        self.assertEqual(totals["2026-08-04T11:58:00Z"], 4)

    def test_an_unknown_interval_does_not_produce_a_broken_query(self):
        """Calendar intervals arrive here from the dashboard; LogsQL takes
        durations only."""
        from wdash.hub.adapters.victorialogs import _step
        self.assertEqual(_step("1w"), "1w")
        self.assertEqual(_step("month"), "1m")
        self.assertEqual(_step(None), "1m")

    # --- query rendering ---

    def test_a_field_query_reaches_the_backend_as_a_field_filter(self):
        self._search(text="level:error")
        self.assertIn('level:"error"', self._sent()["params"]["query"])

    def test_a_bare_word_searches_the_message(self):
        self._search(text="timeout")
        query = self._sent()["params"]["query"]
        self.assertIn('"timeout"', query)

    def test_a_query_logsql_cannot_express_is_refused_rather_than_dropped(self):
        """Dropping a clause returns MORE than was asked for — the one
        direction an access-controlled system must never round in."""
        from wdash.hub import query_language as ql
        from wdash.hub.adapters.victorialogs import VictoriaLogsError

        class Impossible:
            pass

        with self.assertRaises(VictoriaLogsError):
            self.source._filter(Impossible())

    def test_the_scope_is_pushed_into_the_query(self):
        """Filtering afterwards leaves a restricted role with an empty page:
        the backend has already chosen its rows before any post-filter runs."""
        from wdash.hub import Scope
        self._search(scope=Scope(principal="p", containers=("api-*",)))
        query = self._sent()["params"]["query"]
        self.assertIn('service:in("api-gateway")', query)
        self.assertNotIn("payment-service", query)

    # --- transport ---

    def test_requests_go_by_post(self):
        """A LogsQL query with several filters outgrows what proxies carry in
        a URL, and the failure is a 414 that reads like an outage."""
        self._search()
        self.assertTrue(self.harness._requests)

    def test_a_malformed_line_does_not_lose_the_page(self):
        source = self.source
        original = self.harness.post

        def broken(url, data=None, **kwargs):
            if "logsql/query" in url and "stats" not in url:
                return FakeResponse(
                    text=json.dumps(ROWS[0]) + "\n{not json\n"
                         + json.dumps(ROWS[1]))
            return original(url, data=data, **kwargs)

        self.harness.post = broken
        page = source.search(self._query(), __import__(
            "wdash.hub", fromlist=["Scope"]).Scope.unrestricted())
        self.assertEqual(len(page.records), 2)

    def test_an_error_response_is_reported_not_swallowed(self):
        self.harness.fail_next()
        page = self._search()
        self.assertTrue(page.warnings)


if __name__ == "__main__":
    unittest.main()
