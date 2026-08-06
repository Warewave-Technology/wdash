"""
Several trace backends behind one.

The hard part is not the merge. A distributed trace can genuinely be SPLIT
across backends — a request crossing from a service that exports to Jaeger
into one that exports to Tempo leaves spans of one trace in two stores, and
neither store knows the other half exists. Showing the halves separately is a
waterfall with holes in it that read as missing instrumentation.

A configured second trace source used to be reachable by nothing: it appeared
in the source list, the health check probed it, and every query went to
whichever one happened to be first. Registered and unreachable is worse than
absent, because the page says it is there.
"""

import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub import Scope, TimeWindow  # noqa: E402
from wdash.hub.fanout import FanOutTraceSource  # noqa: E402
from wdash.hub.models import Service, Span, Trace, TraceSummary  # noqa: E402
from wdash.hub.source import Capability, TraceSource  # noqa: E402

NOW = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)


def _span(span_id, service, parent=None, minutes=0, failed=False):
    from wdash.hub.models import STATUS_ERROR, STATUS_OK
    return Span(
        trace_id="trace-1", span_id=span_id, parent_span_id=parent,
        name=f"{service} op", service=service,
        start=NOW - dt.timedelta(minutes=minutes), duration_us=1000,
        status=STATUS_ERROR if failed else STATUS_OK)


class StubTraceSource(TraceSource):
    """A trace backend with no backend, so the merge is what is under test."""

    backend = "stub"

    def __init__(self, name, spans=(), services=(), summaries=(),
                 capabilities=None):
        self.name = name
        self._spans = list(spans)
        self._services = list(services)
        self._summaries = list(summaries)
        self._capabilities = frozenset(capabilities or {
            Capability.TRACE_LOOKUP, Capability.TRACE_SEARCH,
            Capability.SERVICE_LIST})
        self.fail = False

    @property
    def capabilities(self):
        return self._capabilities

    def health(self):
        return not self.fail, "ok" if not self.fail else "down"

    def containers(self, scope):
        return [] if scope.is_empty else [f"{self.name}-store"]

    def _guard(self):
        if self.fail:
            raise RuntimeError(f"{self.name} is unreachable")

    def trace(self, trace_id, window, scope):
        self._guard()
        spans = [s for s in self._spans if s.trace_id == trace_id]
        return Trace(trace_id=trace_id, spans=spans) if spans else None

    def services(self, window, scope):
        self._guard()
        return list(self._services)

    def search(self, query, scope):
        self._guard()
        return list(self._summaries)


def build_pair():
    """Two backends holding two halves of one trace."""
    first = StubTraceSource(
        "jaeger",
        spans=[_span("a", "api-gateway", minutes=5),
               _span("b", "auth-service", parent="a", minutes=4)],
        services=[Service(name="api-gateway", span_count=10, error_count=1)],
        summaries=[TraceSummary(trace_id="trace-1", service="api-gateway",
                                name="GET /orders", start=NOW,
                                duration_us=5000)])
    second = StubTraceSource(
        "tempo",
        spans=[_span("c", "payment-service", parent="b", minutes=3),
               _span("d", "postgres", parent="c", minutes=2, failed=True)],
        services=[Service(name="payment-service", span_count=4, error_count=0)],
        summaries=[TraceSummary(trace_id="trace-2", service="payment-service",
                                name="charge", start=NOW - dt.timedelta(hours=1),
                                duration_us=2000)])
    return first, second


class FanOutTestCase(unittest.TestCase):
    def setUp(self):
        self.first, self.second = build_pair()
        self.source = FanOutTraceSource([self.first, self.second])
        self.window = TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW)

    def trace(self, trace_id="trace-1"):
        return self.source.trace(trace_id, self.window, Scope.unrestricted())


class SplitTraceTest(FanOutTestCase):
    def test_a_trace_split_across_backends_comes_back_whole(self):
        """The property the whole class exists for."""
        trace = self.trace()
        self.assertEqual(sorted(span.span_id for span in trace.spans),
                         ["a", "b", "c", "d"])

    def test_the_waterfall_has_no_holes(self):
        """Halves shown separately look like missing instrumentation."""
        trace = self.trace()
        self.assertEqual(len(trace.waterfall()), 4)

    def test_the_service_breakdown_covers_both_halves(self):
        """The question a trace is opened to answer — where the time went —
        cannot be answered from one store."""
        services = {row["service"] for row in self.trace().service_breakdown()}
        self.assertEqual(services, {"api-gateway", "auth-service",
                                    "payment-service", "postgres"})

    def test_an_error_in_the_far_half_is_visible(self):
        self.assertTrue(self.trace().has_error)

    def test_a_trace_no_backend_has_is_still_none(self):
        """Not an empty trace. An empty waterfall reads as "this request did
        nothing", which is a different claim from "no store has this id"."""
        self.assertIsNone(self.trace("never-existed"))


class DuplicateSpanTest(FanOutTestCase):
    def test_a_span_exported_to_two_backends_is_drawn_once(self):
        """Collectors fan out. A span in two stores is one span, and drawing
        it twice reads as a retry that never happened."""
        self.second._spans.append(_span("a", "api-gateway", minutes=5))
        trace = self.trace()
        self.assertEqual(len(trace.spans), 4)
        self.assertEqual(len([s for s in trace.spans if s.span_id == "a"]), 1)


class PartialFailureTest(FanOutTestCase):
    def test_a_failed_backend_marks_the_trace_partial(self):
        """Otherwise "the payment service never ran" gets read off an
        incomplete picture."""
        self.second.fail = True
        trace = self.trace()
        self.assertTrue(trace.partial)

    def test_the_surviving_half_is_still_shown(self):
        self.second.fail = True
        self.assertEqual(sorted(s.span_id for s in self.trace().spans),
                         ["a", "b"])

    def test_a_partial_flag_from_a_member_survives_the_merge(self):
        original = self.first.trace

        def partial(trace_id, window, scope):
            found = original(trace_id, window, scope)
            if found:
                found.partial = True
            return found

        self.first.trace = partial
        self.assertTrue(self.trace().partial)

    def test_health_is_degraded_rather_than_down(self):
        self.second.fail = True
        healthy, detail = self.source.health()
        self.assertFalse(healthy)
        self.assertIn("tempo", detail)


class ServiceListTest(FanOutTestCase):
    def _services(self):
        return {s.name: s for s in
                self.source.services(self.window, Scope.unrestricted())}

    def test_services_from_every_backend_appear(self):
        self.assertEqual(sorted(self._services()), ["api-gateway",
                                                    "payment-service"])

    def test_the_same_service_in_two_backends_is_summed(self):
        """Two stores holding spans of one service hold DIFFERENT spans, so
        the counts add. Deduplicating would report one store's volume as the
        whole of it."""
        self.second._services.append(
            Service(name="api-gateway", span_count=5, error_count=2))
        api = self._services()["api-gateway"]
        self.assertEqual(api.span_count, 15)
        self.assertEqual(api.error_count, 3)

    def test_a_failed_backend_does_not_empty_the_list(self):
        self.second.fail = True
        self.assertIn("api-gateway", self._services())

    def test_services_are_ordered_by_volume(self):
        names = [s.name for s in
                 self.source.services(self.window, Scope.unrestricted())]
        self.assertEqual(names[0], "api-gateway")


class SearchTest(FanOutTestCase):
    def _search(self, limit=10):
        from wdash.hub.query import TraceQuery
        return self.source.search(
            TraceQuery(window=self.window, limit=limit), Scope.unrestricted())

    def test_summaries_come_from_every_backend(self):
        self.assertEqual(sorted(s.trace_id for s in self._search()),
                         ["trace-1", "trace-2"])

    def test_every_summary_says_which_backend_answered(self):
        """With two sources, "this trace is missing" and "you are looking at
        the wrong store" are different problems."""
        self.assertEqual({s.source for s in self._search()},
                         {"jaeger", "tempo"})

    def test_summaries_are_newest_first(self):
        found = self._search()
        self.assertEqual([s.trace_id for s in found], ["trace-1", "trace-2"])

    def test_the_limit_applies_to_the_merged_list(self):
        """Each backend honours the limit on its own, so the merged list is
        as many times too long as there are backends."""
        self.assertEqual(len(self._search(limit=1)), 1)

    def test_the_same_trace_from_two_backends_is_not_hidden(self):
        """Deliberately NOT deduplicated: two backends returning one trace id
        hold different halves of it, and hiding one is how somebody concludes
        a service was not involved."""
        self.second._summaries.append(
            TraceSummary(trace_id="trace-1", service="payment-service",
                         name="charge", start=NOW, duration_us=900))
        found = [s for s in self._search() if s.trace_id == "trace-1"]
        self.assertEqual(len(found), 2)
        self.assertEqual({s.source for s in found}, {"jaeger", "tempo"})


class CapabilityTest(unittest.TestCase):
    def test_capabilities_are_the_intersection(self):
        """Union would offer a feature that quietly answers from a subset."""
        first, second = build_pair()
        second._capabilities = frozenset({Capability.TRACE_LOOKUP})
        merged = FanOutTraceSource([first, second])
        self.assertEqual(merged.capabilities,
                         frozenset({Capability.TRACE_LOOKUP}))

    def test_a_fan_out_needs_a_source(self):
        with self.assertRaises(ValueError):
            FanOutTraceSource([])


class HubRoutingTest(unittest.TestCase):
    def test_one_source_is_not_wrapped(self):
        """A fan-out of one adds a thread pool and a merge to answer a
        question one object already answers."""
        from wdash.hub import Hub
        hub = Hub()
        only = StubTraceSource("only")
        hub.add_traces(only)
        self.assertIs(hub.traces("*"), only)

    def test_several_sources_fan_out(self):
        from wdash.hub import Hub
        hub = Hub()
        hub.add_traces(StubTraceSource("one"))
        hub.add_traces(StubTraceSource("two"))
        self.assertIsInstance(hub.traces("*"), FanOutTraceSource)

    def test_a_named_source_is_reachable(self):
        """The bug this fixes: a second source registered and nothing could
        ask it anything."""
        from wdash.hub import Hub
        hub = Hub()
        hub.add_traces(StubTraceSource("first"))
        hub.add_traces(StubTraceSource("second"))
        self.assertEqual(hub.traces("second").name, "second")

    def test_an_unknown_name_is_an_error(self):
        """Falling back to the default would quietly answer from a different
        store, which is how somebody concludes a trace does not exist."""
        from wdash.hub import Hub
        hub = Hub()
        hub.add_traces(StubTraceSource("first"))
        with self.assertRaises(KeyError):
            hub.traces("typo")


if __name__ == "__main__":
    unittest.main()
