"""
What every source must do, whatever it talks to.

A hub is only worth having if adding a backend is a day's work rather than a
security review. Right now it is the second, because the properties that keep
WDash safe are *adapter-local*: the hub cannot enforce them, and every one of
them has already been got wrong once in Elasticsearch.

Each check below exists because something broke:

  * **An empty scope must issue no query.** An empty index list means `*` to
    Elasticsearch — a user allowed nothing would have seen everything. Loki has
    the same trap in a different dialect: an empty matcher set is either
    invalid or matches all streams.

  * **The scope must be pushed INTO the query.** Filtering after the fact gave
    a restricted role an empty trace list, because `collapse` had already
    picked its top N from spans that role could not see. The page was blank and
    nothing was wrong.

  * **A failure must not look like emptiness.** "The query did not run" and
    "the query ran and matched nothing" are different answers, and a backend
    outage rendering as "traffic dropped to zero" is the most alarming untrue
    thing this application can say.

  * **Capabilities must be honest.** A declared capability has to work; an
    undeclared one has to refuse loudly rather than return something empty.

  * **The neutral model must not leak.** If `hits` or `_source` reaches a
    caller, the abstraction is decorative.

Usage — the adapter's own test module supplies a harness and inherits:

    class ElasticsearchLogConformance(LogSourceConformance, unittest.TestCase):
        def build(self):
            return ElasticsearchLogSource(...), MyHarness(...)

`build()` returns `(source, harness)`. The harness reports what the backend was
actually asked, which is the only way to check that a filter was pushed down
rather than applied afterwards.
"""

import datetime as dt

from wdash.hub import Capability, LogQuery, Scope, TimeWindow
from wdash.hub.aggregation import Terms
from wdash.hub.models import LogRecord, SourceRef, Span


class Harness:
    """What a conformance test needs to know about the backend underneath.

    Deliberately small. Anything bigger and each adapter ends up implementing a
    private simulator, which is a second thing to get wrong.
    """

    def requests(self):
        """Every request issued since the last reset, backend-shaped."""
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError

    def containers(self):
        """Container names the backend holds, newest first."""
        raise NotImplementedError

    def mentions(self, request, text):
        """Does this request mention `text` anywhere?

        Adapters speak different languages; only the adapter's own harness can
        answer whether a rendered query refers to something.
        """
        return text in str(request)

    def carries_window(self, request, window):
        """Does this request bound its search to `window`?

        Overridable because backends spell time differently: Elasticsearch
        takes ISO strings, Loki takes nanoseconds since the epoch. The property
        under test is the same for both — an unbounded scan is a way to take a
        cluster down from the UI — but only the harness can recognise it.
        """
        return window.start.date().isoformat() in str(request)


class _SourceConformanceBase:
    #: Overridden per adapter when a backend genuinely cannot do something.
    #: Skipping is a documented gap, not a silent pass.
    SKIP = frozenset()

    def build(self):
        raise NotImplementedError("supply (source, harness)")

    def setUp(self):
        self.source, self.harness = self.build()
        now = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)
        self.window = TimeWindow.exact(now - dt.timedelta(hours=1), now)

    def skip_unless(self, capability):
        if capability in self.SKIP:
            self.skipTest(f"{self.source.name} declares {capability} unsupported")
        if not self.source.supports(capability):
            self.skipTest(f"{self.source.name} does not declare {capability}")

    # ---------- identity ----------

    def test_the_source_has_a_name_and_a_backend(self):
        """Both are shown to people and stored on records; neither may be blank."""
        self.assertTrue(self.source.name)
        self.assertTrue(getattr(self.source, "backend", None))

    def test_capabilities_are_a_frozen_set_of_known_names(self):
        known = {value for name, value in vars(Capability).items()
                 if not name.startswith("_") and isinstance(value, str)}
        self.assertIsInstance(self.source.capabilities, frozenset)
        self.assertTrue(self.source.capabilities)
        self.assertTrue(self.source.capabilities <= known,
                        f"undeclared capability names: "
                        f"{self.source.capabilities - known}")

    def test_health_returns_a_pair(self):
        healthy, detail = self.source.health()
        self.assertIsInstance(healthy, bool)
        self.assertIsInstance(detail, str)

    #: (capability, method name, arguments) for the optional surface. Only
    #: methods the source class actually defines are checked — a TraceSource
    #: has no `field_stats`, and demanding one would be the suite inventing an
    #: interface rather than describing it.
    OPTIONAL = ()

    def test_an_undeclared_capability_refuses_loudly(self):
        """Returning empty would make a missing feature look like missing data."""
        for capability, method_name, arguments in self.OPTIONAL:
            method = getattr(self.source, method_name, None)
            if method is None or self.source.supports(capability):
                continue
            with self.assertRaises(NotImplementedError,
                                   msg=f"{method_name} is undeclared but did "
                                       f"not refuse"):
                method(*arguments())

    def test_a_declared_capability_is_callable_as_the_hub_calls_it(self):
        """The other half, and the half that was missing.

        The suite checked that an UNDECLARED capability refuses. Nothing
        checked that a declared one can actually be invoked the way the hub
        invokes it — so an adapter could declare FIELD_STATS, define
        `field_stats(self, query, fields, scope)` instead of
        `(self, query, scope)`, pass every test, and raise TypeError the first
        time a real request reached it. That is exactly what happened.
        """
        for capability, method_name, arguments in self.OPTIONAL:
            method = getattr(self.source, method_name, None)
            if method is None or not self.source.supports(capability):
                continue
            self.harness.reset()
            try:
                method(*arguments())
            except TypeError as exc:
                self.fail(f"{method_name} declares {capability} but does not "
                          f"take the arguments the hub passes: {exc}")
            except NotImplementedError:
                self.fail(f"{method_name} declares {capability} and then "
                          f"refuses it")
            except Exception:
                # Backend failures are somebody else's test. What is under
                # test here is the shape of the call.
                pass


class LogSourceConformance(_SourceConformanceBase):
    """Every LogSource must pass this."""

    @property
    def OPTIONAL(self):
        return (
            (Capability.FIELD_STATS, "field_stats",
             lambda: (self._query(), Scope.unrestricted())),
            (Capability.CONTEXT, "context",
             lambda: (SourceRef("x", "y", "z"), Scope.unrestricted())),
            (Capability.HISTOGRAM, "histogram",
             lambda: (self._query(), Scope.unrestricted())),
            (Capability.RAW_DOCUMENT, "raw",
             lambda: (SourceRef("x", "y", "z"), Scope.unrestricted())),
            (Capability.AGGREGATION, "aggregate",
             lambda: (self._query(), [Terms(name="x", field="severity")],
                      Scope.unrestricted())),
        )

    def _query(self, **overrides):
        arguments = {"window": self.window, "text": "*", "limit": 10}
        arguments.update(overrides)
        return LogQuery(**arguments)

    # ---------- fail closed ----------

    def test_an_empty_scope_issues_no_query_at_all(self):
        """An empty container list means "everything" to more than one backend.

        Returning early is the only safe answer: a user granted nothing must
        not become a user granted everything by way of a wildcard.
        """
        self.harness.reset()
        page = self.source.search(self._query(), Scope.nothing())

        self.assertEqual(self.harness.requests(), [],
                         "a query was issued for a scope that permits nothing")
        self.assertEqual(list(page.records), [])

    def test_an_empty_scope_lists_no_containers(self):
        self.assertEqual(self.source.containers(Scope.nothing()), [])

    def test_an_empty_scope_says_why_rather_than_looking_empty(self):
        """Otherwise "you may see nothing" is indistinguishable from "there is
        nothing", and the person spends an afternoon on the wrong question."""
        page = self.source.search(self._query(), Scope.nothing())
        self.assertTrue(page.warnings,
                        "an empty scope produced no records and no explanation")

    def test_a_scope_that_permits_nothing_blocks_aggregation_too(self):
        self.skip_unless(Capability.AGGREGATION)
        self.harness.reset()
        self.source.aggregate(self._query(),
                              [Terms(name="x", field="severity")],
                              Scope.nothing())
        self.assertEqual(self.harness.requests(), [])

    # ---------- the scope reaches the backend ----------

    def test_the_scope_narrows_which_containers_are_queried(self):
        available = self.harness.containers()
        if len(available) < 2:
            self.skipTest("needs at least two containers to tell them apart")

        permitted, forbidden = available[0], available[1]
        self.harness.reset()
        self.source.search(self._query(),
                           Scope(containers=(permitted,),
                                 permissions=frozenset({"logs:read"})))

        issued = self.harness.requests()
        self.assertTrue(issued, "no request was issued at all")
        for request in issued:
            self.assertFalse(
                self.harness.mentions(request, forbidden),
                f"a container outside the scope ({forbidden}) was queried")

    def test_the_query_carries_the_time_window(self):
        """An unbounded scan is a way to take a cluster down from the UI."""
        self.harness.reset()
        self.source.search(self._query(), Scope.unrestricted())
        issued = self.harness.requests()
        self.assertTrue(issued)
        self.assertTrue(
            any(self.harness.carries_window(request, self.window)
                for request in issued),
            "the time window did not reach the backend")

    # ---------- the neutral model ----------

    def test_search_returns_neutral_records(self):
        page = self.source.search(self._query(), Scope.unrestricted())
        if not page.records:
            self.skipTest("the harness holds no records to translate")

        record = page.records[0]
        self.assertIsInstance(record, LogRecord)
        self.assertIsNotNone(record.timestamp)
        self.assertIsInstance(record.resource, dict)
        self.assertIsInstance(record.attributes, dict)

    def expected_source_names(self):
        """Names a record may legitimately carry.

        A leaf source stamps its own name. A composite stamps the name of the
        MEMBER that produced the record — naming the aggregator would throw
        away the only thing the field is for, which is telling two backends
        apart.
        """
        members = getattr(self.source, "sources", None)
        if members:
            return {member.name for member in members}
        return {self.source.name}

    def test_records_say_which_source_answered(self):
        page = self.source.search(self._query(), Scope.unrestricted())
        if not page.records:
            self.skipTest("the harness holds no records to translate")
        self.assertIn(page.records[0].source, self.expected_source_names(),
                      "the record does not name the source that produced it")

    def test_the_record_handle_round_trips(self):
        """`ref` is opaque, but it has to survive being turned into a token."""
        page = self.source.search(self._query(), Scope.unrestricted())
        if not page.records or page.records[0].ref is None:
            self.skipTest("the harness holds no records with handles")

        ref = page.records[0].ref
        self.assertEqual(SourceRef.parse(ref.as_token()), ref)

    def test_no_backend_shape_reaches_the_caller(self):
        page = self.source.search(self._query(), Scope.unrestricted())
        rendered = str(page.to_dict())
        for leaked in ("_source", "'hits'", "streams", "resultType"):
            self.assertNotIn(leaked, rendered,
                             f"{leaked} leaked through the neutral model")

    def test_the_page_reports_what_it_queried(self):
        page = self.source.search(self._query(), Scope.unrestricted())
        self.assertIsInstance(page.containers, (list, tuple))
        self.assertIsInstance(page.total, int)

    # ---------- failure is not emptiness ----------

    def test_a_backend_failure_is_not_reported_as_no_data(self):
        """The distinction this codebase keeps having to defend."""
        self.harness.fail_next()
        page = self.source.search(self._query(), Scope.unrestricted())

        self.assertTrue(page.warnings or page.partial,
                        "a failed query came back looking like an empty result")

    def test_a_failed_aggregation_is_marked_failed(self):
        self.skip_unless(Capability.AGGREGATION)
        self.harness.fail_next()
        result = self.source.aggregate(
            self._query(), [Terms(name="x", field="severity")],
            Scope.unrestricted())
        self.assertTrue(result.failed or result.warnings,
                        "a failed aggregation is indistinguishable from zero")

    # ---------- batching ----------

    def test_multi_aggregate_answers_one_result_per_request(self):
        self.skip_unless(Capability.AGGREGATION)
        requests = [(self._query(), [Terms(name="a", field="severity")]),
                    (self._query(), [Terms(name="b", field="service")])]
        results = self.source.multi_aggregate(requests, Scope.unrestricted())
        self.assertEqual(len(results), len(requests))

    def test_a_failure_inside_a_batch_is_marked_too(self):
        """The batched path has its own error handling, and had its own bug.

        A backend that answers a multi-request with per-sub-query errors inside
        a successful response makes this easy to miss: nothing raises, and the
        failed member comes back looking like a zero.
        """
        self.skip_unless(Capability.AGGREGATION)
        self.harness.fail_next()
        results = self.source.multi_aggregate(
            [(self._query(), [Terms(name="a", field="severity")]),
             (self._query(), [Terms(name="b", field="service")])],
            Scope.unrestricted())

        self.assertTrue(
            any(result is None or result.failed or result.warnings
                for result in results),
            "a failed sub-query is indistinguishable from one that matched nothing")


class TraceSourceConformance(_SourceConformanceBase):
    """Every TraceSource must pass this."""

    @property
    def OPTIONAL(self):
        return (
            (Capability.TRACE_SEARCH, "search",
             lambda: (self._query(), Scope.unrestricted())),
        )

    def _query(self, **overrides):
        from wdash.hub.query import TraceQuery
        arguments = {"window": self.window, "limit": 10}
        arguments.update(overrides)
        return TraceQuery(**arguments)

    def test_an_empty_scope_issues_no_query(self):
        self.harness.reset()
        self.source.search(self._query(), Scope.nothing())
        self.assertEqual(self.harness.requests(), [],
                         "a query was issued for a scope that permits nothing")

    def test_an_empty_service_list_grants_nothing(self):
        """`None` means unrestricted and `()` means nothing.

        Collapsing the two either opens every service or closes them all, and
        the version that opens them is the one nobody notices.
        """
        self.harness.reset()
        self.source.search(self._query(),
                           Scope(containers=("*",), trace_containers=("*",),
                                 services=(),
                                 permissions=frozenset({"traces:read"})))
        for request in self.harness.requests():
            self.assertFalse(
                self.harness.mentions(request, "*"),
                "an empty service list was rendered as a wildcard")

    def test_the_service_filter_is_pushed_into_the_query(self):
        """Filtering afterwards leaves a restricted role with a blank page:
        the backend has already chosen its top N from rows the role cannot see,
        and nothing appears to be wrong."""
        services = [service.name for service
                    in self.source.services(self.window, Scope.unrestricted())]
        if not services:
            self.skipTest("the harness holds no services")

        self.harness.reset()
        self.source.search(self._query(),
                           Scope(containers=("*",), trace_containers=("*",),
                                 services=(services[0],),
                                 permissions=frozenset({"traces:read"})))

        issued = self.harness.requests()
        self.assertTrue(issued, "no request was issued at all")
        self.assertTrue(
            any(self.harness.mentions(request, services[0])
                for request in issued),
            "the service restriction never reached the backend")

    def test_spans_are_neutral_and_named(self):
        summaries = self.source.search(self._query(), Scope.unrestricted())
        if not summaries:
            self.skipTest("the harness holds no traces")

        trace = self.source.trace(summaries[0].trace_id, self.window,
                                  Scope.unrestricted())
        if trace is None or not trace.spans:
            self.skipTest("the harness holds no spans")

        span = trace.spans[0]
        self.assertIsInstance(span, Span)
        self.assertTrue(span.trace_id and span.span_id)
        self.assertEqual(span.source, self.source.name,
                         "the span does not name the source that produced it")

    def test_a_missing_trace_is_none_rather_than_an_empty_trace(self):
        """An empty Trace reads as "this request had no spans", which is a
        different and much more confusing statement."""
        self.assertIsNone(
            self.source.trace("no-such-trace-id", self.window,
                              Scope.unrestricted()))

    def test_services_are_neutral(self):
        for service in self.source.services(self.window, Scope.unrestricted()):
            self.assertTrue(service.name)
            self.assertGreaterEqual(service.span_count, 0)
            self.assertGreaterEqual(service.error_rate, 0.0)
            self.assertLessEqual(service.error_rate, 1.0)

    # ---------- failure is not emptiness ----------

    def test_a_backend_failure_is_not_reported_as_no_data(self):
        """The log side has had this check; the trace side had none.

        Every trace adapter answered a failure with what "nothing" looks
        like — an empty list, or None, which the route reads as "not found in
        the selected time range". A failure is raised, which the route turns
        into a 503 the page shows, or it comes back marked partial with a
        warning that says what is missing.
        """
        held = self.source.search(self._query(), Scope.unrestricted())
        trace_id = held[0].trace_id if held else "a-trace-id"
        for what, call in (
                ("search", lambda: self.source.search(self._query(),
                                                      Scope.unrestricted())),
                ("services", lambda: self.source.services(self.window,
                                                          Scope.unrestricted())),
                ("trace", lambda: self.source.trace(trace_id, self.window,
                                                    Scope.unrestricted()))):
            self.harness.fail_next()
            try:
                answer = call()
            except Exception:
                continue
            self.assertTrue(
                getattr(answer, "partial", False) and getattr(answer, "warnings", ()),
                f"a failed {what} came back looking like an answer: {answer!r}")
