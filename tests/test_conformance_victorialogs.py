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
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conformance import Harness, LogSourceConformance  # noqa: E402

from wdash.hub.adapters.victorialogs import VictoriaLogsSource  # noqa: E402
from wdash.hub.source import Capability  # noqa: E402

SERVICES = ["api-gateway", "auth-service", "checkout-api", "payment-service"]

#: What the fake holds, as RECORDS rather than as a canned answer per
#: endpoint. `field_values` and `stats by` are two views of one table, and a
#: fake that answers them from two hardcoded lists cannot tell an adapter
#: that reads the right one from an adapter that reads the wrong one — which
#: is how ten services all counting zero passed the suite. Nine records:
#: level info 7 / error 2, service api-gateway 4 / auth-service 3 /
#: checkout-api 1 / payment-service 1.
RECORDS = (
    [{"service": "api-gateway", "level": "info"}] * 4
    + [{"service": "auth-service", "level": "info"}] * 3
    + [{"service": "checkout-api", "level": "error"}] * 1
    + [{"service": "payment-service", "level": "error"}] * 1
)

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


def _filter_keeps(expression, rows):
    """Which of `rows` a LogsQL filter keeps.

    `rows` is {name: {field: value}}, so a filter can be judged against the
    RECORDS VictoriaLogs holds rather than against one field's values — which
    is the whole question for severity, where a level may be written as
    `level`, `severity`, `log.level` or `severity_text` and the record reads
    whichever comes first.

    LogsQL's semantics, measured on the lab's VictoriaLogs v1.9.1 over this
    area's own wdash-b-rev-* rows:

      * `field:""` matches a row whose field is missing or empty — it kept
        the 24 lines of the four shapes without a `level`;
      * `field:~"re"` is the regexp filter, which LogsQL does NOT anchor
        (`level:~"(?i)rr"` kept all 13 `error` and `ERR` lines), and
        `field:"phrase"` matches the words anywhere in the value;
      * `AND`, `OR`, `NOT` and parentheses group as written, and a `NOT`
        over a parenthesised group inverts it.

    Anything else is a test failure, not a guess.
    """
    import re

    string = r'"((?:[^"\\]|\\.)*)"'
    unquote = lambda text: re.sub(r"\\(.)", r"\1", text)  # noqa: E731
    name = r'(?:"[\w.]+"|[\w.]+)'

    def split(text, token):
        """Top-level occurrences of ` <token> ` only, parentheses respected."""
        parts, depth, start = [], 0, 0
        index = 0
        while index < len(text):
            character = text[index]
            if character == '"':
                index = re.compile(string).match(text, index).end()
                continue
            depth += (character == "(") - (character == ")")
            if depth == 0 and text.startswith(f" {token} ", index):
                parts.append(text[start:index])
                index += len(token) + 2
                start = index
                continue
            index += 1
        parts.append(text[start:])
        return parts

    def holds(text, row):
        text = text.strip()
        # One pair of parentheses around the whole thing: a top-level split
        # finds nothing outside them, so they can come off.
        if (text.startswith("(") and text.endswith(")")
                and len(split(text, "OR")) == 1
                and len(split(text, "AND")) == 1):
            return holds(text[1:-1], row)
        clauses = split(text, "OR")
        if len(clauses) > 1:
            return any(holds(clause, row) for clause in clauses)
        terms = split(text, "AND")
        if len(terms) > 1:
            return all(holds(term, row) for term in terms)
        if text.startswith("NOT "):
            return not holds(text[4:], row)
        match = re.fullmatch(rf"({name}):(~?){string}", text)
        if not match:
            raise AssertionError(f"not a LogsQL filter: {text!r}")
        field = match.group(1).strip('"')
        body, value = unquote(match.group(3)), row.get(field, "")
        if match.group(2) == "~":
            return re.search(body, value) is not None
        if body == "":
            return value == ""
        return re.search(rf"(?<!\w){re.escape(body)}(?!\w)", value) is not None

    return {key for key, row in rows.items() if holds(expression, row)}


def _by_level(expression, values):
    """`_filter_keeps` over rows whose only field is `level`.

    The severity checks below were written against one field's values, and
    they still say what they said: `""` is a row carrying no `level` at all,
    which is what VictoriaLogs reports for a missing field.
    """
    rows = {value: ({"level": value} if value else {}) for value in values}
    return _filter_keeps(expression, rows)


def _stats_by(fields, limit=None):
    """`| stats by (...) count() as hits` over RECORDS.

    One row per combination of values the records actually hold; a field a
    record does not carry is absent from its row, which is what VictoriaLogs
    returns and what the adapter has to read a missing value out of.

    `limit` is `| sort by (hits desc) | limit N` applied by the BACKEND, as
    the lab's VictoriaLogs applies it: to the rows, before the adapter sees
    them. It has to be modelled here rather than assumed harmless, because
    the rows and the buckets are the same thing only for a field whose keys
    are not rewritten — and where they are, cutting the rows reports a wrong
    number rather than a short list.
    """
    counts = {}
    for record in RECORDS:
        key = tuple(record.get(field) for field in fields)
        counts[key] = counts.get(key, 0) + 1
    rows = []
    for key, count in counts.items():
        row = {field: value for field, value in zip(fields, key)
               if value is not None}
        row["hits"] = str(count)
        rows.append(row)
    if limit is None:
        return rows
    rows.sort(key=lambda row: -int(row["hits"]))
    return rows[:limit]


def _field_values(field, limit):
    """`/select/logsql/field_values`, including the part that made D5.

    Measured on the lab's VictoriaLogs v1.9.1 over 2026-09-01..09-13, where
    `service` holds 22 values: `limit=50` answered with every value and its
    real hits, biggest first; `limit=10` answered with ten values in byte
    order and **hits 0 for every one of them**. The limit is applied before
    the counting, so asking for the top ten of a field with more than ten
    values is asking for a list of names with no numbers.
    """
    counts = {}
    for record in RECORDS:
        value = record.get(field)
        if value:
            counts[value] = counts.get(value, 0) + 1
    if len(counts) > limit:
        return [{"value": value, "hits": 0}
                for value in sorted(counts)[:limit]]
    return [{"value": value, "hits": count} for value, count in
            sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


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
        #: What `/select/logsql/field_names` answers. Replaceable, because the
        #: editor's group-by offer is read from it and a deployment's field
        #: names are the whole variable.
        self.field_names = None

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
            return FakeResponse(payload={"values": _field_values(
                field, int((data or {}).get("limit") or 10))})

        if "field_names" in path:
            names = (["_msg", "level", "service"] if self.field_names is None
                     else self.field_names)
            return FakeResponse(payload={
                "values": [{"value": name, "hits": 9} for name in names]})

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

        grouped = re.search(r"\| stats by \(([^)]*)\)",
                            (data or {}).get("query") or "")
        if grouped:
            # `stats by` returns one row per combination of the grouped
            # fields, with the fields a row does not carry simply absent —
            # grouped by the fields it was ASKED for. It used to answer with
            # levels whatever the query said, so an adapter grouping by
            # `service` got level rows back and a panel could be wrong in
            # either direction without the fake noticing.
            fields = [name.strip().strip('"')
                      for name in grouped.group(1).split(",")]
            # And the ranking clause, if the adapter asked VictoriaLogs to
            # cut the rows rather than carrying all of them home. A fake that
            # ignored it would answer a bounded request with every row, so an
            # adapter that dropped the clause would look identical to one
            # that kept it.
            cut = re.search(r"\| sort by \(hits desc\) \| limit (\d+)",
                            (data or {}).get("query") or "")
            return FakeResponse(text="\n".join(
                json.dumps(row) for row in
                _stats_by(fields, int(cut.group(1)) if cut else None)))

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
        #
        # Rows, not `field_values`: the sidebar is counted with `stats by`
        # now, for the reason the panel beside it is. The two spellings are
        # the lab's own — this is the same answer in the endpoint that can
        # count it.
        original = self.harness.post

        def rows(url, data=None, **kwargs):
            if "| stats by (" not in ((data or {}).get("query") or ""):
                return original(url, data=data, **kwargs)
            return FakeResponse(text="\n".join(json.dumps(row) for row in [
                {"level": "warn", "hits": "948"},
                {"level": "warning", "hits": "1"},
                {"level": "info", "hits": "4602"}]))

        self.harness.post = rows
        from wdash.hub import Scope
        stats = self.source.field_stats(self._query(), Scope.unrestricted(),
                                        fields=["severity"])
        counts = {value.value: value.count for value in stats[0].values}
        self.assertEqual(counts["WARN"], 949)
        self.assertEqual(len([v for v in stats[0].values if v.value == "WARN"]),
                         1)

    def test_a_field_with_more_values_than_the_limit_is_still_counted(self):
        """This test used to assert the defect, so it is the defect's shape.

        It was `test_a_field_the_backend_cannot_count_is_left_out`, and its
        premise — "high-cardinality fields answer with every value at zero
        hits" — described `field_values`, not the backend. The field can be
        counted; the endpoint the sidebar asked could not count it, because
        its `limit` is applied to the values BEFORE they are counted. The
        guard then dropped every such field without a word.

        Measured on the lab over 2026-09-01..09-13, `top=10`: the sidebar
        listed level, env, log.level, severity and severity_text and left out
        `service` (22 distinct values over 2,103 records) and `host` (16) —
        the two fields a field list exists for. Counted with `stats by` the
        same call answers service auth-service 440, checkout-api 409,
        payment-service 400 and host auth-service-3 170, payment-service-3
        144.

        `service` here holds four values and `top` is two, which is the shape
        that answered in zeroes.
        """
        from wdash.hub import Scope
        stats = self.source.field_stats(self._query(), Scope.unrestricted(),
                                        fields=["service"], top=2)
        self.assertEqual(
            [(value.value, value.count) for value in stats[0].values],
            [("api-gateway", 4), ("auth-service", 3)],
            "the field the sidebar exists for, with the counts the records "
            "hold rather than a list of names all reading zero")

    def test_a_field_that_really_cannot_be_counted_says_so(self):
        """`count()` never answers zero, so an all-zero answer is malformed
        now rather than ordinary — and a field vanishing from the sidebar
        with nothing on screen and nothing in the log is the project's
        forbidden failure at sidebar scale."""
        original = self.harness.post

        def uncountable(url, data=None, **kwargs):
            if "| stats by (" not in ((data or {}).get("query") or ""):
                return original(url, data=data, **kwargs)
            return FakeResponse(text=json.dumps({"trace_id": "abc",
                                                 "hits": "0"}))

        self.harness.post = uncountable
        from wdash.hub import Scope
        with self.assertLogs("wdash.hub.adapters.victorialogs",
                             level="WARNING") as logged:
            stats = self.source.field_stats(self._query(),
                                            Scope.unrestricted(),
                                            fields=["trace_id"])
        self.assertEqual(stats, [])
        self.assertTrue(any("trace_id" in line for line in logged.output),
                        logged.output)

    def test_the_value_list_is_bounded(self):
        """`top` is what keeps a field with a thousand values from becoming a
        thousand rows in a sidebar.

        Bounded in the REQUEST as well as in the answer: `stats by` returns
        one row per distinct value, so a sidebar asking about `host` used to
        parse every host in the window to keep ten. The rows below are more
        than `top` because a backend that ignored the clause would still have
        to be cut here.
        """
        original = self.harness.post

        def many(url, data=None, **kwargs):
            if "| stats by (" not in ((data or {}).get("query") or ""):
                return original(url, data=data, **kwargs)
            return FakeResponse(text="\n".join(
                json.dumps({"host": f"v{i}", "hits": str(100 - i)})
                for i in range(40)))

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

    # --- top values ---

    def test_top_values_are_counted_over_records_not_listed_from_a_field(self):
        """`field_values` applies its limit BEFORE it counts.

        Measured on the lab's VictoriaLogs v1.9.1 over 2026-09-01..09-13,
        where `service` holds 22 values: at the panel's default size of 10
        the endpoint answered with ten values in byte order and hits 0 for
        every one — so the Top Services panel every new dashboard is born
        with summed to zero and the client drew "No data in this window",
        beside a volume panel counting 2,103 of the same records in the same
        request. Asked for 50 the same endpoint answered auth-service 440,
        checkout-api 409, payment-service 400. `stats by` counts first, so
        the size is applied to a ranking instead of to a value list.
        """
        from wdash.hub import Scope
        from wdash.hub.aggregation import Terms

        result = self.source.aggregate(
            self._query(), [Terms(name="t", field="service", size=2)],
            Scope.unrestricted())

        self.assertEqual(
            [(bucket.key, bucket.count) for bucket in result.get("t")],
            [("api-gateway", 4), ("auth-service", 3)],
            "the top two of four services, with the counts the records hold")
        self.assertEqual(
            self._sent()["params"]["query"],
            'service:in("api-gateway", "auth-service", "checkout-api", '
            '"payment-service") | stats by (service) count() as hits '
            '| sort by (hits desc) | limit 2')

    def test_the_backend_cuts_the_ranking_for_a_field_it_can_cut(self):
        """`stats by` answers with ONE ROW PER DISTINCT VALUE.

        Where `field_values` sent `limit=size`, this sends none, so the
        answer's size became the field's cardinality — the panel needs ten
        rows and parses every one on every dashboard load, and the field list
        asks about `trace_id`, which is one row per trace. Measured on the
        lab over 2026-09-01..09-13: `stats by (trace_id)` answers 535 rows in
        22,978 bytes and the same query cut to 10 in 403 bytes; `_msg` 1,873
        rows in 95,207 bytes against 610. `host` is 16 rows on the lab and
        unbounded in a real deployment, and `_terms` accepts any field.
        """
        from wdash.hub import Scope
        from wdash.hub.aggregation import Terms

        self.source.aggregate(self._query(),
                              [Terms(name="t", field="service", size=3)],
                              Scope.unrestricted())
        self.assertIn("| sort by (hits desc) | limit 3",
                      self._sent()["params"]["query"],
                      "every distinct value came home to keep three")

    def test_the_backend_does_not_cut_a_ranking_whose_keys_are_rewritten(self):
        """Where the rows are not the buckets, cutting them is a wrong number.

        A level is normalised before it is merged — `warn` and `warning` are
        one WARN — so the top `size` ROWS are not the top `size` LEVELS. This
        is the arm that has to stay uncut, and the fake applies the clause
        the way the lab does so that adding it here is visible as a count
        that is too small rather than as a list that is too short.
        """
        from wdash.hub import Scope
        from wdash.hub.aggregation import Terms

        original = self.harness.post

        def spellings(url, data=None, **kwargs):
            response = original(url, data=data, **kwargs)
            if "| stats by (" not in ((data or {}).get("query") or ""):
                return response
            rows = [{"level": "warn", "hits": "948"},
                    {"level": "warning", "hits": "1"},
                    {"level": "info", "hits": "4602"}]
            cut = re.search(r"\| limit (\d+)", (data or {}).get("query") or "")
            if cut:
                rows.sort(key=lambda row: -int(row["hits"]))
                rows = rows[:int(cut.group(1))]
            return FakeResponse(text="\n".join(json.dumps(r) for r in rows))

        self.harness.post = spellings
        result = self.source.aggregate(
            self._query(), [Terms(name="t", field="level", size=2)],
            Scope.unrestricted())

        self.assertNotIn("| limit", self._sent()["params"]["query"],
                         "a level ranking cut by rows loses a spelling")
        self.assertEqual(
            [(bucket.key, bucket.count) for bucket in result.get("t")],
            [("INFO", 4602), ("WARN", 949)],
            "WARN is 948 + 1, which the top two ROWS would have reported as "
            "948 with the second spelling never arriving")

    def test_a_value_that_arrives_after_a_bigger_one_is_still_ranked(self):
        """Truncation happens after the sort, not as the rows arrive.

        `stats by` returns its groups in no particular order, so cutting the
        list at `size` where it is read would answer with whichever two
        VictoriaLogs happened to send first.
        """
        from wdash.hub import Scope
        from wdash.hub.aggregation import Terms

        original = self.harness.post

        def reversed_rows(url, data=None, **kwargs):
            response = original(url, data=data, **kwargs)
            if "| stats by (" in ((data or {}).get("query") or ""):
                rows = [json.loads(line) for line in response.text.splitlines()]
                return FakeResponse(text="\n".join(
                    json.dumps(row) for row in reversed(rows)))
            return response

        self.harness.post = reversed_rows
        result = self.source.aggregate(
            self._query(), [Terms(name="t", field="service", size=2)],
            Scope.unrestricted())
        self.assertEqual(
            [(bucket.key, bucket.count) for bucket in result.get("t")],
            [("api-gateway", 4), ("auth-service", 3)])

    def test_records_carrying_no_value_are_labelled_when_the_panel_asks(self):
        """`missing` is part of the neutral model and this dropped it.

        Elasticsearch puts records without the field into a bucket named by
        `missing`; `field_values` never mentions them, so the same panel over
        the same records disagreed by however many rows never carried the
        field. `stats by` returns them as a row with the field absent.
        """
        from wdash.hub import Scope
        from wdash.hub.aggregation import Terms

        original = self.harness.post

        def with_a_nameless_row(url, data=None, **kwargs):
            response = original(url, data=data, **kwargs)
            if "| stats by (" in ((data or {}).get("query") or ""):
                return FakeResponse(text=response.text + "\n"
                                    + json.dumps({"hits": "5"}))
            return response

        self.harness.post = with_a_nameless_row
        labelled = self.source.aggregate(
            self._query(),
            [Terms(name="t", field="service", size=10, missing="unknown")],
            Scope.unrestricted())
        self.assertIn(("unknown", 5),
                      [(b.key, b.count) for b in labelled.get("t")])

        plain = self.source.aggregate(
            self._query(), [Terms(name="t", field="service", size=10)],
            Scope.unrestricted())
        self.assertNotIn("", [bucket.key for bucket in plain.get("t")],
                         "a row with no value became a bucket with no name")

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

    def test_a_level_panel_counts_what_the_page_calls_that_level(self):
        """The panel asked `field_values` for `level` alone, while a record's
        level is read from the first of four fields it carries. Measured on
        the lab over one row shape per field: a panel over the 24 rows the
        page draws as ERROR reported ERROR 6 and drew the other 18 as
        UNSPECIFIED — a level nobody wrote.

        The rows below are the lab's own answer to `| stats by (level,
        severity, "log.level", severity_text) count()`.
        """
        from wdash.hub import Scope
        from wdash.hub.aggregation import Terms

        original = self.harness.post

        def stats(url, data=None, **kwargs):
            if "| stats by (" in ((data or {}).get("query") or ""):
                return FakeResponse(text="\n".join(json.dumps(row) for row in [
                    {"level": "error", "hits": "6"},
                    {"hits": "6"},
                    {"level": "info", "severity": "error", "hits": "6"},
                    {"severity": "error", "hits": "6"},
                    {"log.level": "error", "hits": "6"},
                    {"severity_text": "error", "hits": "6"}]))
            return original(url, data=data, **kwargs)

        self.harness.post = stats
        try:
            result = self.source.aggregate(
                self._query(), [Terms(name="levels", field="severity")],
                Scope.unrestricted())
        finally:
            self.harness.post = original

        self.assertEqual(
            sorted((bucket.key, bucket.count) for bucket in result.get("levels")),
            [("ERROR", 24), ("INFO", 6), ("UNSPECIFIED", 6)])

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
        # It pinned `level:"error"` — the case-sensitive phrase filter that
        # found none of the ERR or ERROR lines. What has to reach the backend
        # is a filter on `level` that keeps the errors and nothing else.
        self._search(text="level:error")
        clause = self._sent()["params"]["query"].split(" AND ", 1)[1]
        self.assertEqual(_by_level(clause, ["error", "ERR", "warn", "info"]),
                         {"error", "ERR"})
        self._search(text="host:api-gateway-1")
        self.assertIn('host:"api-gateway-1"', self._sent()["params"]["query"])

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

    # --- severity is matched the way it is normalised ---

    SPELLINGS = ["error", "ERROR", "err", "Err", "warn", "WARN", "warning",
                 "Warning", "info", "INFO", "notice", "terror", "errors",
                 "an error", "warn2", "custom", "CUSTOM", ""]

    def _level_filter(self, text):
        from wdash.hub import query_language as ql
        return self.source._filter(ql.parse(text))

    def test_the_documented_upper_case_level_matches_lower_case_values(self):
        """`level:ERROR` is the example on the logs page, and the data says
        `error`. LogsQL phrase filters match case, so on the lab's
        VictoriaLogs, over 40 lines of which 13 are `error` or `ERR`, it
        found none, with no warning."""
        for typed in ("level:ERROR", "level:error", "level:Err",
                      'level:"ERROR"', "severity:error"):
            with self.subTest(typed=typed):
                self.assertEqual(
                    _by_level(self._level_filter(typed), self.SPELLINGS),
                    {"error", "ERROR", "err", "Err"})

    def test_a_level_filter_matches_whole_values_only(self):
        """The regexp filter is not anchored in LogsQL. `level:~"err"` would
        keep `terror`, `errors` and `an error` too."""
        kept = _by_level(self._level_filter("level:WARN"), self.SPELLINGS)
        self.assertEqual(kept, {"warn", "WARN", "warning", "Warning"})

    def test_a_level_that_is_no_severity_still_ignores_case_and_nothing_else(self):
        self.assertEqual(
            _by_level(self._level_filter("level:Custom"), self.SPELLINGS),
            {"custom", "CUSTOM"})

    def test_unspecified_is_every_level_no_severity_is_spelled_as(self):
        self.assertEqual(
            _by_level(self._level_filter("level:UNSPECIFIED"), self.SPELLINGS),
            {"terror", "errors", "an error", "warn2", "custom", "CUSTOM", ""})

    def test_negating_a_level_keeps_everything_else(self):
        """`-level:ERROR` kept all 40 lab lines, `error` ones included."""
        self.assertEqual(
            _by_level(self._level_filter("-level:ERROR"), self.SPELLINGS),
            set(self.SPELLINGS) - {"error", "ERROR", "err", "Err"})

    def test_a_sidebar_row_filters_to_the_rows_it_counted(self):
        """The sidebar merges `warn` and `warning` into one WARN row, which
        is right, and clicking it asked for `level:"WARN"`, which matched
        neither: on the lab every sidebar row — WARN 14, INFO 13, ERROR 13 —
        led to 0 results."""
        from wdash.hub import Scope

        original = self.harness.post

        def values(url, data=None, **kwargs):
            if "| stats by (" not in ((data or {}).get("query") or ""):
                return original(url, data=data, **kwargs)
            return FakeResponse(text="\n".join(json.dumps(row) for row in [
                {"level": "warn", "hits": "948"},
                {"level": "warning", "hits": "1"},
                {"level": "info", "hits": "4602"}]))

        self.harness.post = values
        stats = self.source.field_stats(self._query(), Scope.unrestricted(),
                                        fields=["level"])
        self.harness.post = original
        row = next(value for value in stats[0].values if value.count == 949)

        self._search(text=f'{stats[0].field}:"{row.value}"')
        query = self._sent()["params"]["query"]
        clause = query.split(" AND ", 1)[1]
        self.assertEqual(_by_level(clause, ["warn", "warning", "info"]),
                         {"warn", "warning"})

    def test_a_regex_character_in_a_level_is_a_character(self):
        self.assertEqual(
            _by_level(self._level_filter('level:"a.b"'), ["a.b", "A.B", "aXb"]),
            {"a.b", "A.B"})

    #: One row per shape of severity field. `_to_record` reads a record's
    #: severity from the FIRST of level, severity, log.level, severity_text
    #: the row carries — so these are ERROR four times, then INFO and
    #: UNSPECIFIED.
    SHAPES = {
        "level": {"level": "error"},
        "severity": {"severity": "error"},
        "dotted": {"log.level": "error"},
        "text": {"severity_text": "error"},
        "both": {"level": "info", "severity": "error"},
        # An empty field is not a field the row carries: the record reader
        # skips it, and both backends match it with `field:""`. So this row
        # is ERROR, decided by `severity`.
        "empty": {"level": "", "severity": "error"},
        "none": {},
    }

    def _severity_of(self, fields):
        """What the page calls a row carrying these fields."""
        row = {"_time": "2026-08-04T11:59:00.000000Z", "_msg": "x",
               "service": "api-gateway", **fields}
        return self.source._to_record(row).severity

    def test_a_level_filter_finds_the_rows_the_page_calls_that_level(self):
        """The filter read `level` and nothing else, while the record reads
        `level`, `severity`, `log.level` or `severity_text`, whichever the row
        has. An OTel pipeline writes `severity`, so every row the page showed
        as ERROR was invisible to `level:ERROR`, with no warning.
        """
        for level in ("ERROR", "INFO", "UNSPECIFIED"):
            with self.subTest(level=level):
                self.assertEqual(
                    _filter_keeps(self._level_filter(f"level:{level}"),
                                  self.SHAPES),
                    {name for name, fields in self.SHAPES.items()
                     if self._severity_of(fields) == level})

    def test_unspecified_does_not_sweep_up_a_row_with_no_level_field(self):
        """`NOT (level:~"...")` keeps every row without a `level` field, so
        `level:UNSPECIFIED` answered with rows the page draws as ERROR."""
        kept = _filter_keeps(self._level_filter("level:UNSPECIFIED"),
                             self.SHAPES)
        self.assertEqual(kept, {"none"})

    def test_the_field_that_decides_is_the_one_the_record_read(self):
        """A row carrying both is INFO, because `level` comes first."""
        self.assertEqual(self._severity_of(self.SHAPES["both"]), "INFO")
        self.assertNotIn("both", _filter_keeps(self._level_filter("level:ERROR"),
                                               self.SHAPES))
        self.assertIn("both", _filter_keeps(self._level_filter("level:INFO"),
                                            self.SHAPES))

    def test_negating_a_level_keeps_every_row_that_is_not_it(self):
        """`-level:ERROR` over the shapes: everything the page does not draw
        as ERROR, which includes the rows with no level at all."""
        self.assertEqual(
            _filter_keeps(self._level_filter("-level:ERROR"), self.SHAPES),
            {"both", "none"})

    def test_an_empty_field_is_not_a_field_the_row_carries(self):
        """`absent` and `empty` are one state — Loki drops an empty label at
        ingestion and LogsQL matches both with `field:""` — so the reader has
        to skip an empty one and let the next field decide, exactly as the
        rendered filter does."""
        self.assertEqual(self._severity_of(self.SHAPES["empty"]), "ERROR")
        self.assertIn("empty", _filter_keeps(self._level_filter("level:ERROR"),
                                             self.SHAPES))

    # --- aggregations LogsQL cannot express ---

    def test_an_aggregation_logsql_cannot_express_fails_rather_than_raises(self):
        """search turned these into a warning; aggregate let the exception
        out, and every dashboard over VictoriaLogs whose query or filter held
        a range, an inner wildcard or NOT * answered with Flask's HTML 500."""
        from wdash.hub import Scope
        from wdash.hub.aggregation import Terms

        for text in ("status:[500 TO 599]", "host:w?b", "NOT *"):
            with self.subTest(text=text):
                self.harness.reset()
                aggregations = [Terms(name="t", field="severity")]
                result = self.source.aggregate(self._query(text=text),
                                               aggregations, Scope.unrestricted())
                self.assertTrue(result.failed)
                self.assertIn("VictoriaLogs cannot express", " ".join(result.warnings))
                # Only the catalogue lookup (`*`) may have gone out: anything
                # else is a query sent without the clause it could not render.
                self.assertEqual(
                    [request["path"] for request in self.harness._requests
                     if request["params"].get("query") != "*"], [])
                batched = self.source.multi_aggregate(
                    [(self._query(text=text), aggregations),
                     (self._query(), aggregations)], Scope.unrestricted())
                self.assertTrue(batched[0].failed)
                self.assertFalse(batched[1].failed,
                                 "one query it cannot express failed the batch")

    # --- the catalogue ---

    def test_a_catalogue_that_cannot_be_read_is_an_error_and_not_an_empty_list(self):
        from wdash.hub import Scope
        from wdash.hub.adapters.victorialogs import VictoriaLogsError
        self.harness.fail_next()
        with self.assertRaises(VictoriaLogsError) as caught:
            self.source.containers(Scope.unrestricted())
        self.assertIn("429", str(caught.exception))

    def test_the_catalogue_is_one_lookup_however_often_a_request_asks(self):
        from wdash.hub import Scope
        self.harness.reset()
        self.source.containers(Scope.unrestricted())
        self.source.containers(Scope(principal="p", containers=("api-*",)))
        lookups = [request for request in self.harness._requests
                   if "field_values" in request["path"]]
        self.assertEqual(len(lookups), 1)


if __name__ == "__main__":
    unittest.main()
