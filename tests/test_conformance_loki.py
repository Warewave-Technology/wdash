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


def _selects(selector, values):
    """Which of `values` a LogQL stream selector would select.

    `{l="v"}` is equality. `{l=~"re"}` is a regular expression that Loki,
    like Prometheus, anchors at both ends, so it is judged with fullmatch.
    The selector's own string layer is undone first, the way Loki's parser
    does, and what is left is handed to Python's `re`, which agrees with
    RE2 on everything an escaped literal and `|` can express.
    """
    import re

    match = re.fullmatch(r'\{(\w+)(=~|=)"((?:[^"\\]|\\.)*)"\}', selector)
    if not match:
        raise AssertionError(f"not a single-label selector: {selector!r}")
    operator, body = match.group(2), re.sub(r"\\(.)", r"\1", match.group(3))
    if operator == "=":
        return {value for value in values if value == body}
    pattern = re.compile(body)
    return {value for value in values if pattern.fullmatch(value)}


def _label_stage_keeps(stage, streams):
    """Which of `streams` a LogQL label filter stage keeps.

    `streams` is {name: {label: value}}, so a stage can be judged against the
    LABEL SETS Loki holds rather than against one label's values — which is
    the whole question for severity, where a level may be written as `level`,
    `severity` or `detected_level` and the record reads whichever comes first.

    LogQL's label filter semantics, every one of them measured on the lab's
    Loki 3.1.1 over this area's own wdash-b-rev-* streams:

      * a label the stream does not carry reads as the empty string, so
        `level=""` kept the 18 lines of the three streams without one;
      * `and` binds tighter than `or` — `level=~"(?i)(error|err)" or
        level="" and severity=~"(?i)(error|err)"` kept 12 (the `level` and
        the `severity` stream), not the 6 the other grouping gives;
      * `=~` and `!~` are anchored at both ends: `level=~"(?i)rr"` kept none
        of the `error` lines and `level=~"(?i)err"` kept only `ERR`.

    Anything else in the stage is a test failure, not a guess.
    """
    import re

    predicate = re.compile(r'(\w+)(=~|!~|!=|=)"((?:[^"\\]|\\.)*)"')

    def holds(text, labels):
        text = text.strip()
        match = predicate.fullmatch(text)
        if not match:
            raise AssertionError(f"not a label predicate: {text!r}")
        label, operator, body = match.group(1), match.group(2), match.group(3)
        body = re.sub(r"\\(.)", r"\1", body)
        value = labels.get(label, "")
        if operator in ("=", "!="):
            kept = value == body
        else:
            kept = re.fullmatch(body, value) is not None
        return kept if operator in ("=", "=~") else not kept

    if not stage.startswith(" | "):
        raise AssertionError(f"not a label filter stage: {stage!r}")
    body = stage[3:]
    return {name for name, labels in streams.items()
            # `and` first, then `or`: the grouping Loki was measured to use.
            if any(all(holds(term, labels) for term in clause.split(" and "))
                   for clause in body.split(" or "))}


def _by_level(stage, values):
    """`_label_stage_keeps` over streams whose only label is `level`.

    The severity checks below were written against one label's values, and
    they still say what they said: `""` is a stream carrying no `level` at
    all, which is how Loki reports a missing label.
    """
    streams = {value: ({"level": value} if value else {}) for value in values}
    return _label_stage_keeps(stage, streams)


def _line_filters_keep(pipeline, lines):
    """Which of `lines` a chain of ` |= "x"` / ` != "x"` stages keeps.

    Anything else in the chain is a test failure, not a guess.
    """
    import re

    stages = re.findall(r' (\|=|!=) "((?:[^"\\]|\\.)*)"', pipeline)
    if "".join(f' {op} "{text}"' for op, text in stages) != pipeline:
        raise AssertionError(f"not a chain of line filters: {pipeline!r}")
    kept = []
    for line in lines:
        if all((re.sub(r"\\(.)", r"\1", text) in line) == (op == "|=")
               for op, text in stages):
            kept.append(line)
    return kept


class FakeResponse:
    def __init__(self, payload, status_code=200, text=""):
        self._payload = payload
        self.status_code = status_code
        self.text = text or json.dumps(payload)

    def json(self):
        return self._payload


#: A `count_over_time` sample instant INSIDE the window these tests use
#: (2026-08-04 11:00 -> 12:00), and the one a minute after it. The fixture
#: answered with instants from 2025 — a year outside the range it was asked
#: for, which the real Loki never does. It did not matter while the adapter
#: passed every instant through untouched; it does now that the adapter reads
#: the window to drop the one sample that counts only the past.
SAMPLE_AT = 1785843000            # 2026-08-04 11:30:00Z
NEXT_SAMPLE_AT = SAMPLE_AT + 60   # 11:31:00Z

#: What those samples become. Loki's sample at t is the count for the step
#: ENDING at t, so the bucket is keyed one step earlier; the step for a
#: one-hour window is a minute.
SAMPLE_KEY = (SAMPLE_AT - 60) * 1000
NEXT_SAMPLE_KEY = (NEXT_SAMPLE_AT - 60) * 1000

#: Streams a RANGE metric query counts over: a label set, and lines per
#: second. Modelled rather than canned, because the fixture that ignores what
#: it is asked is exactly how a missing `by` clause passes for a present one:
#: this file's old matrix answered every `count_over_time` with one unlabelled
#: series, so a split the adapter never built and a split it built correctly
#: were the same green test.
#:
#: The totals are what the canned answer was — 7 at the first sample and 3 at
#: the next — so nothing that counted the whole had to change.
METRIC_STREAMS = (
    ({"service_name": "api-gateway", "level": "info"},
     {SAMPLE_AT: 5, NEXT_SAMPLE_AT: 3}),
    ({"service_name": "api-gateway", "level": "error"},
     {SAMPLE_AT: 2}),
)

#: The label names Loki holds, which is a short list and not the fields a
#: record carries: `/loki/api/v1/labels` is what the editor's group-by select
#: is filled from.
LABEL_NAMES = ("detected_level", "level", "service_name")


class FakeLoki(Harness):
    """Loki's HTTP API, enough of it."""

    def __init__(self):
        self._requests = []
        self._fail_next = False
        #: Windows Loki has data for. None means "every window".
        self._labels_present = None
        #: What a log query answers with, stream by stream, in Loki's own
        #: shape. None means the default single stream.
        self.streams = None
        #: What an instant metric query answers with. None means the default
        #: per-level vector.
        self.vector = None
        #: What a range metric query counts over. Replaceable, so a test can
        #: put a stream with no `level` label in front of the adapter.
        self.metric_streams = METRIC_STREAMS
        #: The label NAMES. None means the default list.
        self.label_names = None

    # --- harness contract ---

    def requests(self):
        # Label lookups are how the adapter learns what exists; they are not
        # data queries, and counting them would make "issued no query"
        # impossible to state. `/labels` is the same kind of lookup one level
        # up — the label NAMES, which is what the editor's group-by list is.
        return [request for request in self._requests
                if "/label/" not in request["path"]
                and not request["path"].endswith("/labels")]

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
        if path.endswith("/labels"):
            names = (LABEL_NAMES if self.label_names is None
                     else self.label_names)
            return FakeResponse({"status": "success", "data": list(names)})
        if path.endswith("ready"):
            return FakeResponse({}, text="ready")
        if "query_range" in path:
            return FakeResponse(self._range(params or {}))
        return FakeResponse(self._instant())

    def _range(self, params):
        if "count_over_time" in (params.get("query") or ""):
            return {"status": "success",
                    "data": {"resultType": "matrix",
                             "result": self._matrix(params["query"])}}
        if self.streams is not None:
            return {"status": "success", "data": {"resultType": "streams",
                                                  "result": self.streams}}
        return {"status": "success", "data": {"resultType": "streams", "result": [{
            "stream": {"service_name": "api-gateway", "level": "info",
                       "namespace": "prod"},
            "values": [["1754305800000000000",
                        '{"msg":"hello","trace_id":"abc","level":"info"}'],
                       ["1754305801000000000", "plain text line"]],
        }]}}

    def _matrix(self, query):
        """`sum [by (...)] (count_over_time(...))` over `metric_streams`.

        The `by` clause is READ, so a query with none answers with one
        unlabelled series and a query naming a label nothing carries answers
        the same way — which is what the lab's Loki does, measured: `sum by
        (host)` over streams with no `host` label returns ONE series, no
        labels, carrying every line.
        """
        import re

        match = re.search(r"sum(?:\s+by\s+\(([^)]*)\))?\s*\(count_over_time",
                          query)
        if not match:
            raise AssertionError(f"not a count_over_time query: {query!r}")
        names = [name.strip()
                 for name in (match.group(1) or "").split(",") if name.strip()]

        grouped = {}
        for labels, points in self.metric_streams:
            key = tuple(sorted((name, labels[name]) for name in names
                               if labels.get(name)))
            counted = grouped.setdefault(key, {})
            for at, count in points.items():
                counted[at] = counted.get(at, 0) + count
        return [{"metric": dict(key),
                 "values": [[at, str(count)] for at, count in sorted(counted.items())]}
                for key, counted in grouped.items()]

    def _instant(self):
        if self.vector is not None:
            return {"status": "success", "data": {"resultType": "vector",
                                                  "result": self.vector}}
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

    def test_an_allowed_name_selects_only_itself(self):
        """Several streams are selected by one regular expression, and the
        names in it are the values the scope allowed: data, not syntax.

        They were joined with `|` and nothing else, so `pay.svc` also
        selected `payXsvc`, and a service somebody named `team-a-x|.+` (a
        name anyone who can set OTEL_SERVICE_NAME inside an allowed prefix
        can choose) turned a grant of `team-a-*` into every stream in Loki,
        `billing-pii` included.
        """
        from wdash.hub import Scope

        # The quote is there for the ORDER of the two escapes: regex first,
        # string second. The other way round, the regex escape doubles the
        # string escape's backslash and the quote closes the string.
        available = ["team-a-api", "team-a-x|.+", "billing-pii", "payXsvc",
                     "pay.svc", "(a)", "back\\slash", 'q"uote']
        scope = Scope(principal="p", containers=(
            "team-a-*", "pay.svc", "(a)", "back\\slash", 'q"uote'))
        allowed = scope.resolve(available, source=self.source.name)
        self.assertEqual(sorted(allowed), sorted(
            ["team-a-api", "team-a-x|.+", "pay.svc", "(a)", "back\\slash",
             'q"uote']))

        selector = self.source._selector(allowed)
        self.assertEqual(sorted(_selects(selector, available)),
                         sorted(allowed),
                         f"{selector} selects streams the scope refused")

    def test_every_character_re2_reads_as_syntax_is_escaped(self):
        """Every one of them, not the handful the case above happens to use.

        Dropping `[`, `^`, `*` or `?` from the escape passed every other test
        here, and each still widens a grant: with `team-a-*` and `-*-pii*`,
        an allowed name `team-a-[^q]*` selected the `team-a-billing-pii` the
        scope had refused.
        """
        from wdash.hub import Scope
        from wdash.hub.adapters.loki import _literal

        for character in "\\.+*?()|[]{}^$":
            with self.subTest(character=character):
                self.assertEqual(_literal(character), "\\" + character)

        available = ["team-a-[^q]*", "team-a-x?", "team-a-y{0}",
                     "team-a-$^", "team-a-billing-pii"]
        scope = Scope(principal="p", containers=("team-a-*", "-*-pii*"))
        allowed = scope.resolve(available, source=self.source.name)
        self.assertNotIn("team-a-billing-pii", allowed)
        selector = self.source._selector(allowed)
        self.assertEqual(sorted(_selects(selector, available)),
                         sorted(allowed),
                         f"{selector} selects streams the scope refused")

    def test_one_allowed_name_selects_only_itself_too(self):
        """The single-stream form is equality, which has no syntax to leak
        through; asserted so that it stays that way."""
        selector = self.source._selector(["pay.svc"])
        self.assertEqual(_selects(selector, ["pay.svc", "payXsvc"]),
                         {"pay.svc"})

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

    # Picked by content, not by position: these took records[0] and [1] in
    # the order the fake's one stream listed them, which was the unsorted
    # stream order the page used to show.

    def test_a_structured_line_yields_attributes_and_a_trace_id(self):
        record = next(record for record in self._search().records
                      if record.body.startswith("{"))
        self.assertEqual(record.trace_id, "abc")
        self.assertEqual(record.attributes.get("msg"), "hello")

    def test_a_plain_line_is_kept_as_the_body_without_invented_structure(self):
        record = next(record for record in self._search().records
                      if not record.body.startswith("{"))
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

    # --- severity is matched the way it is normalised ---

    def _severity_stage(self, text):
        from wdash.hub import query_language as ql
        return self.source._pipeline(ql.parse(text))

    SPELLINGS = ["error", "ERROR", "err", "Err", "warn", "WARN", "warning",
                 "Warning", "info", "INFO", "notice", "fatal", "crit",
                 "terror", "errors", "warn2", "custom", "CUSTOM", ""]

    def test_the_documented_upper_case_level_matches_lower_case_labels(self):
        """`level:ERROR` is the example on the logs page, and Loki pipelines
        write `error`. The filter compared the two exactly: on the lab's Loki,
        over 40 lines of which 13 are `error` or `ERR`, it found none — with
        no warning, which reads as a quiet day.

        Every spelling that normalises to ERROR is an ERROR: the records say
        so and the level panel counts them so. A filter that matches fewer
        of them than the panel counted is a panel nobody can drill into.
        """
        for typed in ("level:ERROR", "level:error", "level:Err",
                      'level:"ERROR"', "severity:error"):
            with self.subTest(typed=typed):
                self.assertEqual(
                    _by_level(self._severity_stage(typed), self.SPELLINGS),
                    {"error", "ERROR", "err", "Err"})

    def test_warn_matches_every_spelling_it_was_counted_from(self):
        self.assertEqual(
            _by_level(self._severity_stage("level:WARN"), self.SPELLINGS),
            {"warn", "WARN", "warning", "Warning"})
        self.assertEqual(
            _by_level(self._severity_stage("level:INFO"), self.SPELLINGS),
            {"info", "INFO", "notice"})

    def test_a_level_that_is_no_severity_still_ignores_case_and_nothing_else(self):
        self.assertEqual(
            _by_level(self._severity_stage("level:Custom"), self.SPELLINGS),
            {"custom", "CUSTOM"})

    def test_unspecified_is_every_level_no_severity_is_spelled_as(self):
        """UNSPECIFIED is what normalisation calls a missing or unknown level,
        so as a filter it is "none of the known spellings", not a word."""
        self.assertEqual(
            _by_level(self._severity_stage("level:UNSPECIFIED"), self.SPELLINGS),
            {"terror", "errors", "warn2", "custom", "CUSTOM", ""})

    def test_a_severity_filter_reaches_loki_as_the_same_stage(self):
        self.harness.reset()
        self._search(text="level:ERROR")
        query = self.harness.requests()[0]["params"]["query"]
        stage = query[query.index("}") + 1:]
        self.assertEqual(_by_level(stage, self.SPELLINGS),
                         {"error", "ERROR", "err", "Err"})

    def test_a_regex_character_in_a_level_is_a_character(self):
        """The typed value ends up inside a regular expression."""
        self.assertEqual(
            _by_level(self._severity_stage('level:"a.b"'), ["a.b", "A.B", "aXb"]),
            {"a.b", "A.B"})

    #: One stream per shape of severity label. `_to_records` reads a record's
    #: severity from the FIRST of level, severity, detected_level the stream
    #: carries — so these are ERROR, ERROR, ERROR, INFO and UNSPECIFIED.
    SHAPES = {
        "level": {"level": "error"},
        "severity": {"severity": "error"},
        "detected": {"detected_level": "error"},
        "both": {"level": "info", "severity": "error"},
        "none": {},
    }

    def _severity_of(self, labels):
        """What the page calls a line from a stream with these labels."""
        body = {"data": {"result": [{"stream": dict(labels),
                                     "values": [["1754309400000000000", "x"]]}]}}
        return self.source._to_records(body)[0].severity

    def test_a_level_filter_finds_the_lines_the_page_calls_that_level(self):
        """The filter read `level` and nothing else, while the record reads
        `level`, `severity` or `detected_level`, whichever the stream has.

        On an OTel pipeline — which writes `severity`, and is the shape this
        whole finding is about — every line the page showed as ERROR was
        invisible to `level:ERROR`, with no warning. Measured on the lab's
        Loki 3.1.1 over this area's own streams: `| level=~"(?i)(error|err)"`
        kept 6 of the 18 ERROR lines, `| severity=~"(?i)(error|err)"` 0 of
        them, because an absent label matches nothing under `=~`.

        The filter and the record reader have to agree line for line, or the
        level panel is one nobody can drill into.
        """
        for level in ("ERROR", "INFO", "UNSPECIFIED"):
            with self.subTest(level=level):
                self.assertEqual(
                    _label_stage_keeps(self._severity_stage(f"level:{level}"),
                                       self.SHAPES),
                    {name for name, labels in self.SHAPES.items()
                     if self._severity_of(labels) == level})

    def test_unspecified_does_not_sweep_up_a_stream_with_no_level_label(self):
        """The negation is the direction that quietly returns MORE.

        `| level!~"(?i)(...)"` keeps every line of a stream that has no
        `level` at all — an absent label matches nothing under `=~` and
        EVERYTHING under `!~`, measured on the lab: `severity!~"(?i)(error)"`
        kept all 40 lines of streams carrying no `severity`. So
        `level:UNSPECIFIED` answered with lines the page draws as ERROR.
        """
        kept = _label_stage_keeps(self._severity_stage("level:UNSPECIFIED"),
                                  self.SHAPES)
        self.assertEqual(kept, {"none"})
        for name in ("severity", "detected"):
            self.assertNotIn(name, kept,
                             f"{name} is an ERROR stream on the page")

    def test_the_label_that_decides_is_the_one_the_record_read(self):
        """A stream carrying both is INFO, because `level` comes first — so
        an or-chain over the three labels would have answered `level:ERROR`
        with a line the page draws as INFO."""
        self.assertEqual(self._severity_of(self.SHAPES["both"]), "INFO")
        self.assertNotIn(
            "both", _label_stage_keeps(self._severity_stage("level:ERROR"),
                                       self.SHAPES))
        self.assertIn(
            "both", _label_stage_keeps(self._severity_stage("level:INFO"),
                                       self.SHAPES))

    # --- negation ---

    LINES = ["GET session", "GET other", "POST session", "POST other"]

    def test_a_negated_group_is_refused_rather_than_half_negated(self):
        """NOT (a b) is NOT a OR NOT b. It was rendered as `!= "a" |= "b"`,
        which is NOT a AND b: on the lab's Loki, NOT (GET session) over 40
        lines kept 10 where 30 match, and said nothing.

        A chain of line filters cannot say OR, so the only honest answer is
        a refusal the page can show.
        """
        from wdash.hub import query_language as ql
        from wdash.hub.adapters.loki import LokiError

        for text in ("NOT (GET session)", "-(GET AND session)",
                     "NOT (GET -session)", "NOT (GET level:error)",
                     "NOT (level:error GET)", "NOT NOT GET",
                     "NOT level:error", "-host:web"):
            with self.subTest(text=text):
                with self.assertRaises(LokiError):
                    self.source._pipeline(ql.parse(text))
                self.harness.reset()
                page = self._search(text=text)
                self.assertTrue(page.partial)
                self.assertIn("negation", " ".join(page.warnings))
                self.assertEqual(self.harness.requests(), [],
                                 "a query went out for a negation Loki "
                                 "cannot express")

    def test_one_negated_word_or_phrase_is_still_a_line_filter(self):
        from wdash.hub import query_language as ql

        for text, kept in (("NOT GET", ["POST session", "POST other"]),
                           ("-session", ["GET other", "POST other"]),
                           ('NOT "GET session"',
                            ["GET other", "POST session", "POST other"]),
                           ('-message:"POST other"',
                            ["GET session", "GET other", "POST session"]),
                           ("GET -session", ["GET other"])):
            with self.subTest(text=text):
                self.assertEqual(
                    _line_filters_keep(self.source._pipeline(ql.parse(text)),
                                       self.LINES), kept)

    # --- one timeline from several streams ---

    @staticmethod
    def _stream(service, level, *entries):
        return {"stream": {"service_name": service, "level": level},
                "values": [[f"17543058{second:02d}000000000", body]
                           for second, body in entries]}

    def test_several_streams_come_back_as_one_timeline_newest_first(self):
        """Loki answers stream by stream, each in the direction asked for,
        and the page drew them in that order: on the lab's Loki, 40 lines
        written round-robin into six streams came back as six runs, one
        stream after another, with nothing sorting them on the way to the
        screen.
        """
        self.harness.streams = [
            self._stream("api-gateway", "info", (3, "a3"), (1, "a1")),
            self._stream("payment-service", "error", (4, "b4"), (2, "b2"))]
        page = self._search()
        self.assertEqual([record.body for record in page.records],
                         ["b4", "a3", "b2", "a1"])

    def test_ascending_is_oldest_first_across_streams_too(self):
        self.harness.streams = [
            self._stream("api-gateway", "info", (1, "a1"), (3, "a3")),
            self._stream("payment-service", "error", (2, "b2"), (4, "b4"))]
        page = self._search(ascending=True)
        self.assertEqual([record.body for record in page.records],
                         ["a1", "b2", "a3", "b4"])

    # --- terms over labels ---

    def _terms(self, field, source=None):
        import datetime as dt

        from wdash.hub import LogQuery, Scope, TimeWindow
        from wdash.hub.aggregation import Terms
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        self.harness.reset()
        return (source or self.source).aggregate(
            LogQuery(window=TimeWindow.exact(now - dt.timedelta(hours=1), now),
                     text="*"),
            [Terms(name="t", field=field)], Scope.unrestricted())

    def _sent_instant(self):
        return [request["params"]["query"] for request in self.harness.requests()
                if request["path"].endswith("/query")]

    def test_the_service_panel_groups_by_the_label_this_source_was_given(self):
        """`stream_label` is configurable, and `service` was mapped to
        `service_name` whatever it said. A source configured with `app` was
        asked `sum by (service_name)`, which Loki answers with one series and
        no label: the services panel came back empty, with no warning."""
        source = LokiLogSource("http://loki:3100", name="loki",
                               stream_label="app", session=self.harness)
        self.harness.vector = [{"metric": {"app": "api"}, "value": [0, "7"]},
                               {"metric": {"app": "web"}, "value": [0, "5"]}]
        result = self._terms("service", source)
        self.assertIn("sum by (app)", self._sent_instant()[0])
        self.assertEqual([(bucket.key, bucket.count) for bucket in result.get("t")],
                         [("api", 7), ("web", 5)])
        self.assertEqual(result.warnings, ())

    def test_a_level_panel_counts_what_the_page_calls_that_level(self):
        """The panel grouped by `level` alone while a record's level is read
        from the first of three labels it carries, so the panel and the
        search answered different questions about the same lines. Measured on
        the lab over one stream per shape: a search for level:ERROR returned
        18 records and the panel beside it reported ERROR 6.

        The series below are the lab's own answer to
        `sum by (level, severity, detected_level) (count_over_time(...))`.
        """
        from wdash.hub.aggregation import Terms
        self.harness.vector = [
            {"metric": {}, "value": [0, "6"]},
            {"metric": {"detected_level": "error"}, "value": [0, "6"]},
            {"metric": {"level": "error", "detected_level": "error"},
             "value": [0, "6"]},
            {"metric": {"severity": "error", "detected_level": "error"},
             "value": [0, "6"]},
            {"metric": {"level": "info", "severity": "error",
                        "detected_level": "info"}, "value": [0, "6"]},
        ]
        result = self._aggregate("*", Terms(name="levels", field="severity"))
        self.assertEqual(
            sorted((bucket.key, bucket.count)
                   for bucket in result.get("levels")),
            [("ERROR", 18), ("INFO", 6), ("UNSPECIFIED", 6)])
        self.assertIn("sum by (level, severity, detected_level)",
                      self._sent_instant()[0])
        # A stream carrying none of the three has no level, which is an
        # answer — not a field Loki cannot count.
        self.assertEqual(result.warnings, ())

    def test_a_field_that_is_not_a_label_says_so_rather_than_drawing_nothing(self):
        """Loki answers `sum by (host)` over streams with no `host` label with
        one series whose labels are empty. That was skipped, and the panel
        was an empty chart that reads as "no hosts logged anything" — the
        very thing the docstring said it avoided."""
        self.harness.vector = [{"metric": {}, "value": [0, "12"]}]
        result = self._terms("host")
        self.assertEqual(result.get("t"), [])
        said = " ".join(result.warnings)
        self.assertIn("host", said)
        self.assertIn("not a Loki label", said)

    def test_a_label_only_some_streams_carry_is_counted_where_it_is(self):
        """Streams without the label come back as one unlabelled series.
        That is not "not a label" — the rest carry it — and the buckets are
        the answer."""
        self.harness.vector = [{"metric": {"host": "web-1"}, "value": [0, "3"]},
                               {"metric": {}, "value": [0, "9"]}]
        result = self._terms("host")
        self.assertEqual([(bucket.key, bucket.count) for bucket in result.get("t")],
                         [("web-1", 3)])
        self.assertEqual(result.warnings, ())

    def test_a_label_with_nothing_in_the_window_is_empty_and_nothing_more(self):
        """The other empty: the label exists and nothing was logged. That is
        a real answer, and a warning on it would be noise."""
        self.harness.vector = []
        result = self._terms("host")
        self.assertEqual(result.get("t"), [])
        self.assertEqual(result.warnings, ())

    def _aggregate(self, text, *aggregations, hours=1):
        import datetime as dt

        from wdash.hub import LogQuery, Scope, TimeWindow
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        self.harness.reset()
        return self.source.aggregate(
            LogQuery(window=TimeWindow.exact(now - dt.timedelta(hours=hours),
                                             now),
                     text=text),
            list(aggregations), Scope.unrestricted())

    # --- which interval a bucket counts ---
    #
    # `count_over_time(...[step])` evaluated at t counts the lines in
    # (t-step, t], so the sample Loki returns AT t is the bucket ENDING at t.
    # The adapter used the instant verbatim, so every Loki chart was drawn one
    # whole interval late and its first bar counted records from before the
    # window. Measured against the lab at a 1h interval: the bucket keyed
    # 12:00 held exactly the 79 lines of [11:00, 12:00), outside the window,
    # while [12:00, 13:00) really held 85.
    #
    #: 2026-08-04, on the hour, in epoch seconds. The window below is
    #: 09:00 -> 12:00, so the sample at 09:00 counts 08:00-09:00 and belongs
    #: to nobody.
    HOURS = {hour: 1785837600 + (hour - 10) * 3600 for hour in range(8, 14)}

    def _timeline(self, samples, hours=3):
        from wdash.hub.aggregation import DateHistogram
        self.harness.metric_streams = (
            ({"service_name": "api-gateway"},
             {self.HOURS[hour]: count for hour, count in samples.items()}),)
        result = self._aggregate(
            "*", DateHistogram(name="t", interval="1h", min_count=0),
            hours=hours)
        return [(bucket.key // 1000, bucket.count)
                for bucket in result.get("t")]

    def test_a_bucket_is_keyed_by_the_hour_it_counts(self):
        """The sample Loki returns at 12:00 is the count for 11:00-12:00."""
        self.assertEqual(self._timeline({10: 5, 11: 7, 12: 9}),
                         [(self.HOURS[9], 5), (self.HOURS[10], 7),
                          (self.HOURS[11], 9)])

    def test_the_sample_that_counts_only_the_past_is_dropped(self):
        """The first sample of a range query covers the step BEFORE the
        window. Kept, it made the chart wider than the range above it and
        opened it with a bar nobody asked for."""
        self.assertEqual(self._timeline({9: 400, 10: 5}),
                         [(self.HOURS[9], 5)])

    def test_the_key_text_agrees_with_the_key(self):
        """Two labels for one bucket, and the page reads whichever it likes."""
        from wdash.hub.aggregation import DateHistogram
        self.harness.metric_streams = (
            ({"service_name": "api-gateway"}, {self.HOURS[12]: 3}),)
        bucket = self._aggregate(
            "*", DateHistogram(name="t", interval="1h", min_count=0),
            hours=3).get("t")[0]
        self.assertEqual(bucket.key // 1000, self.HOURS[11])
        self.assertTrue(bucket.key_text.startswith("2026-08-04T11:00"),
                        bucket.key_text)

    def test_a_split_rides_the_same_key(self):
        """The sub-buckets are the same sample, so a split that stayed on
        the old key would stack under the wrong bar."""
        from wdash.hub.aggregation import DateHistogram, Terms
        self.harness.metric_streams = (
            ({"service_name": "api-gateway", "level": "error"},
             {self.HOURS[12]: 4}),)
        result = self._aggregate(
            "*", DateHistogram(name="t", interval="1h", min_count=0,
                               sub=(Terms(name="s", field="level"),)),
            hours=3)
        bucket = result.get("t")[0]
        self.assertEqual(bucket.key // 1000, self.HOURS[11])
        self.assertEqual([(b.key, b.count) for b in bucket.sub["s"]],
                         [("error", 4)])

    def test_a_panel_counts_what_the_query_selects_not_the_whole_stream(self):
        """count_over_time was built over the stream selector alone, so every
        panel on a Loki dashboard counted every line in its streams whatever
        the dashboard's query or the filter box said: on the lab's Loki, a
        level panel over `GET session` counted all 40 lines, where 10 match.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        self._aggregate("GET level:ERROR", Terms(name="levels", field="severity"),
                        DateHistogram(name="timeline"))
        sent = [request["params"]["query"] for request in self.harness.requests()]
        self.assertEqual(len(sent), 2, sent)
        for query in sent:
            inner = query[query.index("count_over_time(") + len("count_over_time("):
                          query.rindex("[")]
            selector_end = inner.index("}") + 1
            self.assertEqual(_line_filters_keep(
                inner[selector_end:inner.index(" | level")],
                ["GET session", "POST other"]), ["GET session"], query)
            self.assertEqual(_by_level(inner[inner.index(" | level"):],
                                       self.SPELLINGS),
                             {"error", "ERROR", "err", "Err"}, query)

    def test_a_filter_loki_cannot_express_fails_the_panel_rather_than_dropped(self):
        """Dropped, it counts MORE than was asked for — the one direction the
        search refuses to round in, and the panels rounded that way."""
        from wdash.hub.aggregation import Terms
        result = self._aggregate("service:a OR service:b",
                                 Terms(name="levels", field="severity"))
        self.assertTrue(result.failed)
        self.assertIn("Loki cannot express", " ".join(result.warnings))
        self.assertEqual(self.harness.requests(), [])

    # --- the split the default panel asks for ---

    def test_the_default_panels_split_is_made_by_loki(self):
        """A severity-split timeline drew the unsplit total and said so.

        It is the panel every dashboard is born with, so the gap was
        maximally exposed — and it was the adapter's, not Loki's: the `by`
        clause `_terms_buckets` had always built works here too, with no
        parser stage and no error filter. Measured on the lab's Loki 3.1.1
        over 24h, before 0 series under a legend promising a breakdown and
        after 4 (ERROR, INFO, UNSPECIFIED, WARN) summing to the 488 lines the
        unsplit total reported.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="severity"),)))

        rows = result.get("timeline")
        self.assertEqual([(row.key, row.count) for row in rows],
                         [(SAMPLE_KEY, 7), (NEXT_SAMPLE_KEY, 3)])
        self.assertEqual(
            [sorted((b.key, b.count) for b in row.sub["split"]) for row in rows],
            [[("ERROR", 2), ("INFO", 5)], [("INFO", 3)]])
        # The stack adds up to the line above it.
        for row in rows:
            self.assertEqual(sum(b.count for b in row.sub["split"]), row.count)
        self.assertEqual(result.warnings, ())
        self.assertIn("sum by (level, severity, detected_level)",
                      self.harness.requests()[0]["params"]["query"])

    def test_a_split_loki_cannot_make_is_still_said(self):
        """The other half, and the one that must not become a silent total.

        `host` is not a label on these streams, so Loki answers `sum by
        (host)` with ONE series carrying no labels and every line — right
        totals, no breakdown. The panel draws the total and says which half
        of the answer is missing.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="host"),)))

        rows = result.get("timeline")
        self.assertEqual([(row.key, row.count) for row in rows],
                         [(SAMPLE_KEY, 7), (NEXT_SAMPLE_KEY, 3)])
        self.assertEqual([row.sub for row in rows], [{}, {}])
        self.assertEqual(result.reasons("timeline"),
                         ("'host' is not a Loki label on these streams; "
                          "this is the total",))

    def test_a_half_labelled_split_says_what_is_missing_from_the_stack(self):
        """The worse state: a stack shorter than the line above it.

        One stream with no `level` label is counted in the total and in no
        series, so the breakdown is honest about the part it cannot show
        rather than leaving the difference for somebody to notice.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        self.harness.metric_streams = (
            ({"service_name": "api-gateway", "host": "node-1"},
             {SAMPLE_AT: 4}),
            ({"service_name": "payment-service", "host": "node-2"},
             {SAMPLE_AT: 2}),
            ({"service_name": "quiet-one"}, {SAMPLE_AT: 6}),
        )
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="host"),)))

        row = result.get("timeline")[0]
        self.assertEqual(row.count, 12)
        self.assertEqual(sorted((b.key, b.count) for b in row.sub["split"]),
                         [("node-1", 4), ("node-2", 2)])
        self.assertEqual(result.reasons("timeline"),
                         ("some streams carry no 'host' label; those lines "
                          "are counted in the total and not in the split",))

    def test_a_window_with_nothing_in_it_claims_nothing_about_the_label(self):
        """An empty answer is a quiet window, not a missing label.

        The adapter cannot ask Loki whether a name is a label; it INFERS it
        from an answer of one unlabelled series carrying every line. No
        series at all is not that answer, and reading it as one put "'level'
        is not a Loki label on these streams; this is the total" on a panel
        over streams that carry `level`, beside a total of nothing — a
        sentence that sends an author to fix a panel that is right.
        `_terms_buckets` has always required the same evidence.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        self.harness.metric_streams = ()

        for field in ("severity", "service"):
            result = self._aggregate("*", DateHistogram(
                name="timeline", sub=(Terms(name="split", field=field),)))
            self.assertEqual(result.get("timeline"), [], field)
            self.assertEqual(result.reasons("timeline"), (), field)
            self.assertEqual(result.warnings, (), field)
            self.assertFalse(result.failed, field)

        # And the other shape of nothing: a series that IS unlabelled, which
        # is the evidence this sentence rests on, carrying no points. There
        # is no breakdown to explain and no total to call it.
        self.harness.metric_streams = (({"service_name": "api-gateway"}, {}),)
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="host"),)))
        self.assertEqual(result.get("timeline"), [])
        self.assertEqual(result.reasons("timeline"), ())

    def test_a_split_cut_to_fit_the_legend_says_how_many_it_dropped(self):
        """The same visible gap as the half-labelled split, from truncation.

        The series kept are the largest `size` of them, so the stack is
        shorter than the line above it and the docstring's own argument
        applies: nothing said why. Measured on the lab, a 24h split by
        `service` at size 10 drew 473 of 488 lines with an empty note.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        self.harness.metric_streams = (
            ({"service_name": "a", "host": "node-1"}, {SAMPLE_AT: 4}),
            ({"service_name": "b", "host": "node-2"}, {SAMPLE_AT: 3}),
            ({"service_name": "c", "host": "node-3"}, {SAMPLE_AT: 2}),
            ({"service_name": "d", "host": "node-4"}, {SAMPLE_AT: 1}),
        )

        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="host", size=2),)))
        row = result.get("timeline")[0]
        self.assertEqual(row.count, 10)
        self.assertEqual(sorted((b.key, b.count) for b in row.sub["split"]),
                         [("node-1", 4), ("node-2", 3)])
        self.assertEqual(result.reasons("timeline"),
                         ("2 smaller 'host' values did not fit the legend; "
                          "those lines are counted in the total and not in "
                          "the split",))

        # One of them reads as one of them.
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="host", size=3),)))
        self.assertEqual(result.reasons("timeline"),
                         ("1 smaller 'host' value did not fit the legend; "
                          "those lines are counted in the total and not in "
                          "the split",))

        # And a split that fits says nothing at all.
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="host", size=4),)))
        self.assertEqual(result.reasons("timeline"), ())

    def test_a_split_by_a_name_logql_cannot_hold_is_refused_not_sent(self):
        """A dotted field is a PARSE error, not a narrower answer.

        The editor offers what the source can group by, and on Elasticsearch
        and VictoriaLogs that includes names like `log.level`. `sum by
        (log.level)` is HTTP 400 from Loki, which would reach the panel as a
        stack trace where its reason belongs — so the clause is never built
        and the unsplit total is drawn with the reason.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="log.level"),)))

        rows = result.get("timeline")
        self.assertEqual([(row.key, row.count) for row in rows],
                         [(SAMPLE_KEY, 7), (NEXT_SAMPLE_KEY, 3)])
        self.assertIn("cannot be a Loki label name",
                      " ".join(result.reasons("timeline")))
        for request in self.harness.requests():
            self.assertNotIn("log.level", request["params"]["query"])

    def test_a_second_split_is_reported_rather_than_dropped(self):
        """Loki splits a series one way, and the panel says which way.

        A second sub-aggregation quietly ignored is a legend that promises
        two breakdowns and draws one, with nothing on the card about it.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="severity"),
                                  Terms(name="also", field="service"))))

        row = result.get("timeline")[0]
        self.assertEqual(sorted((b.key, b.count) for b in row.sub["split"]),
                         [("ERROR", 2), ("INFO", 5)])
        self.assertEqual(list(row.sub), ["split"])
        self.assertEqual(result.reasons("timeline"),
                         ("Loki splits a series one way: service was not "
                          "applied",))

    def test_a_split_that_fails_degrades_to_the_total_and_not_to_an_error(self):
        """'maximum of series (500) reached' is a property of the data.

        A label set wider than the server's limit must leave the panel with
        the total it had before any split existed, and the reason — not a
        failed board.
        """
        from wdash.hub.aggregation import DateHistogram, Terms
        sent = []
        original = self.harness.get

        def refuse_the_split(url, params=None, **kw):
            sent.append((params or {}).get("query"))
            if " by (" in ((params or {}).get("query") or ""):
                return FakeResponse({}, status_code=500,
                                    text="maximum of series (500) reached")
            return original(url, params=params, **kw)

        self.harness.get = refuse_the_split
        result = self._aggregate("*", DateHistogram(
            name="timeline", sub=(Terms(name="split", field="severity"),)))

        self.assertFalse(result.failed)
        self.assertEqual([(row.key, row.count)
                          for row in result.get("timeline")],
                         [(SAMPLE_KEY, 7), (NEXT_SAMPLE_KEY, 3)])
        self.assertIn("could not split", " ".join(result.reasons("timeline")))
        self.assertIn("maximum of series", " ".join(result.reasons("timeline")))
        self.assertTrue(any(query and " by (" not in query and
                            "count_over_time" in query for query in sent),
                        f"no unsplit query was issued: {sent}")

    # --- what the editor may offer ---

    def test_the_group_by_offer_is_lokis_labels_and_not_four_names(self):
        """Two of the four names the editor offered every source — `host` and
        `environment` — are answered by Loki with nothing at all.

        Measured against the lab's Loki: `/loki/api/v1/labels` over 24h
        returns exactly `detected_level, level, service_name, severity`, which
        is `service` and `severity` in the neutral names a panel stores.
        """
        from wdash.hub import Scope
        self.assertEqual(self.source.group_by_fields(Scope.unrestricted()),
                         ["service", "severity"])

    def test_the_group_by_offer_is_asked_within_the_scope(self):
        """A label only a forbidden stream carries is not disclosed.

        Loki honours the selector here: measured on the lab,
        `/labels?query={service_name="billing"}` answers `[level,
        service_name]` where the unrestricted call answers four names.
        """
        from wdash.hub import Scope
        self.source.group_by_fields(
            Scope(principal="narrow", containers=("api-gateway",)))
        asked = [request for request in self.harness._requests
                 if request["path"].endswith("/labels")]
        self.assertEqual(len(asked), 1, asked)
        self.assertEqual(asked[0]["params"]["query"],
                         '{service_name="api-gateway"}')

    def test_a_scope_that_permits_nothing_asks_loki_nothing(self):
        from wdash.hub import Scope
        self.assertEqual(self.source.group_by_fields(Scope.nothing()), [])
        self.assertEqual([request for request in self.harness._requests
                          if request["path"].endswith("/labels")], [])

    # --- the catalogue ---

    def test_a_catalogue_that_cannot_be_read_is_an_error_and_not_an_empty_list(self):
        """It answered [] and logged the error. Every caller then told the
        person what [] means — 'No log indices found', 'your role has no
        access to any log indices', 'this pattern matches nothing on this
        installation' — while their Loki was down."""
        from wdash.hub import Scope
        from wdash.hub.adapters.loki import LokiError
        self.harness.fail_next()
        with self.assertRaises(LokiError) as caught:
            self.source.containers(Scope.unrestricted())
        self.assertIn("503", str(caught.exception))

    def test_the_catalogue_is_one_lookup_however_often_a_request_asks(self):
        """Keyed by `now`, the window-less catalogue missed its cache on every
        call: the logs page asked Loki twice per view and a search three
        times, and a Loki that answered the first and not the second failed
        half way through a page."""
        from wdash.hub import Scope
        self.harness.reset()
        self.source.containers(Scope.unrestricted())
        self.source.containers(Scope(principal="p", containers=("api-*",)))
        label_calls = [request for request in self.harness._requests
                       if "/label/" in request["path"]]
        self.assertEqual(len(label_calls), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
