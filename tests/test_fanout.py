"""
Searching every source at once.

The fan-out is presented as a LogSource, so it goes through the same
conformance suite as the backends it wraps — which is the point of the suite
being about behaviour rather than about Elasticsearch.

What the merge has to get right is not the merge:

  * one backend down must be VISIBLE, not just fewer rows
  * a merged total is a lie unless it says so
  * capabilities narrow to what every member can do, or a feature answers from
    a subset while looking like it answered from everything
"""

import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conformance import Harness, LogSourceConformance  # noqa: E402
from wdash.hub import Capability, LogQuery, Scope, TimeWindow  # noqa: E402
from wdash.hub.aggregation import (  # noqa: E402
    AggregationResult, Bucket, DateHistogram, Terms,
)
from wdash.hub.fanout import FanOutLogSource  # noqa: E402
from wdash.hub.models import LogPage, LogRecord, SourceRef  # noqa: E402
from wdash.hub.source import LogSource  # noqa: E402

NOW = dt.datetime(2026, 8, 4, 12, tzinfo=dt.timezone.utc)


class StubSource(LogSource):
    """A log source with no backend, so the merge is what is under test."""

    def __init__(self, name, backend, containers, records, total=None,
                 capabilities=None, counts=True):
        self.name = name
        self.backend = backend
        self._containers = list(containers)
        self._records = list(records)
        self._total = len(records) if total is None else total
        self._capabilities = frozenset(capabilities or {
            Capability.SEARCH, Capability.AGGREGATION, Capability.HISTOGRAM})
        self._counts = counts
        self.fail = False
        self.requests = []

    @property
    def capabilities(self):
        return self._capabilities

    def health(self):
        return not self.fail, "ok" if not self.fail else "down"

    def containers(self, scope):
        if scope.is_empty:
            return []
        return scope.resolve(self._containers)

    def _guard(self):
        if self.fail:
            raise RuntimeError(f"{self.name} is unreachable")

    def search(self, query, scope):
        self.requests.append({"search": query.text, "limit": query.limit,
                              "start": query.window.start})
        if scope.is_empty:
            return LogPage(warnings=("the scope permits no containers",))
        self._guard()
        allowed = self.containers(scope)
        records = [record for record in self._records][:query.limit]
        warnings = () if self._counts else (
            "reports no match count; the total shown is what was returned",)
        return LogPage(records=records, total=self._total, counted=self._counts,
                       containers=tuple(allowed), took_ms=5, warnings=warnings)

    def fetch(self, ref, scope):
        for record in self._records:
            if record.ref and record.ref.id == ref.id:
                return record
        return None

    def aggregate(self, query, aggregations, scope):
        self.requests.append({"aggregate": [a.name for a in aggregations]})
        if scope.is_empty:
            return AggregationResult(
                warnings=("the scope permits no containers",))
        try:
            self._guard()
        except RuntimeError as exc:
            return AggregationResult(warnings=(str(exc),), failed=True)

        buckets = {}
        for aggregation in aggregations:
            if isinstance(aggregation, DateHistogram):
                buckets[aggregation.name] = [
                    Bucket(key=1754305800000, key_text="t0", count=2),
                    Bucket(key=1754305860000, key_text="t1", count=3)]
            else:
                buckets[aggregation.name] = [
                    Bucket(key="INFO", count=self._total),
                    Bucket(key="ERROR", count=1)]
        return AggregationResult(total=self._total, buckets=buckets)


def _record(source_name, backend, container, at, body="line"):
    return LogRecord(timestamp=at, body=body, severity="INFO",
                     service="api-gateway", source=source_name,
                     ref=SourceRef(backend=backend, container=container,
                                   id=f"{backend}-{at.isoformat()}"))


def build_pair(**overrides):
    """Two sources with interleaved timestamps, so ordering is observable."""
    first = StubSource(
        "primary", "elasticsearch", ["app-logs"],
        [_record("primary", "elasticsearch", "app-logs",
                 NOW - dt.timedelta(minutes=minutes), f"es-{minutes}")
         for minutes in (1, 3, 5)],
        **overrides.get("first", {}))
    second = StubSource(
        "secondary", "loki", ["payment-service"],
        [_record("secondary", "loki", "payment-service",
                 NOW - dt.timedelta(minutes=minutes), f"loki-{minutes}")
         for minutes in (2, 4, 6)],
        **overrides.get("second", {}))
    return first, second


class FanOutHarness(Harness):
    """Reports what the member sources were asked."""

    def __init__(self, sources):
        self._sources = sources

    def requests(self):
        return [request for source in self._sources
                for request in source.requests]

    def reset(self):
        for source in self._sources:
            source.requests = []

    def containers(self):
        return ["app-logs", "payment-service"]

    def fail_next(self):
        self._sources[0].fail = True

    def carries_window(self, request, window):
        return request.get("start") == window.start


class FanOutConformanceTest(LogSourceConformance, unittest.TestCase):
    def build(self):
        first, second = build_pair()
        harness = FanOutHarness([first, second])
        return FanOutLogSource([first, second]), harness


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.first, self.second = build_pair()
        self.source = FanOutLogSource([self.first, self.second])
        self.window = TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW)

    def search(self, **overrides):
        arguments = {"window": self.window, "text": "*", "limit": 10}
        arguments.update(overrides)
        return self.source.search(LogQuery(**arguments), Scope.unrestricted())

    def test_records_from_every_source_appear(self):
        sources = {record.source for record in self.search().records}
        self.assertEqual(sources, {"primary", "secondary"})

    def test_the_merged_page_is_in_time_order(self):
        """Concatenating would interleave two sorted lists into an unsorted one."""
        timestamps = [record.timestamp for record in self.search().records]
        self.assertEqual(timestamps, sorted(timestamps, reverse=True))

    def test_ascending_order_is_honoured(self):
        timestamps = [record.timestamp
                      for record in self.search(ascending=True).records]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_the_page_is_capped_at_the_requested_limit(self):
        self.assertEqual(len(self.search(limit=2).records), 2)

    def test_each_source_is_asked_for_a_full_page(self):
        """Asking each for limit/N makes the merge wrong whenever the results
        are not evenly spread — which is the normal case."""
        self.search(limit=10)
        for source in (self.first, self.second):
            self.assertEqual(source.requests[0]["limit"], 10)

    def test_containers_from_every_source_are_reported(self):
        containers = set(self.search().containers)
        self.assertIn("app-logs", containers)
        self.assertIn("payment-service", containers)


class PartialFailureTest(unittest.TestCase):
    """One backend down must be visible, not just fewer rows."""

    def setUp(self):
        self.first, self.second = build_pair()
        self.source = FanOutLogSource([self.first, self.second])
        self.window = TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW)
        self.first.fail = True

    def search(self):
        return self.source.search(
            LogQuery(window=self.window, text="*", limit=10),
            Scope.unrestricted())

    def test_the_healthy_source_still_answers(self):
        self.assertTrue(self.search().records)

    def test_the_page_is_marked_partial(self):
        self.assertTrue(self.search().partial,
                        "a failed source produced quietly fewer results")

    def test_the_failing_source_is_named(self):
        """'Something failed' sends people looking in the wrong place."""
        warnings = " ".join(self.search().warnings)
        self.assertIn("primary", warnings)

    def test_health_reports_degraded_rather_than_down(self):
        healthy, detail = self.source.health()
        self.assertFalse(healthy)
        self.assertIn("primary", detail)

    def test_an_aggregation_over_a_failed_source_is_marked_failed(self):
        result = self.source.aggregate(
            LogQuery(window=self.window, text="*"),
            [Terms(name="levels", field="severity")], Scope.unrestricted())
        self.assertTrue(result.failed)
        self.assertTrue(any("primary" in warning
                            for warning in result.warnings))


class SourceBreakdownTest(unittest.TestCase):
    """Which source answered, attributed to the rows actually shown."""

    def setUp(self):
        self.first, self.second = build_pair()
        self.source = FanOutLogSource([self.first, self.second])
        self.window = TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW)

    def _page(self, limit=10):
        return self.source.search(
            LogQuery(window=self.window, text="*", limit=limit),
            Scope.unrestricted())

    def _by_name(self, page):
        return {entry["name"]: entry for entry in page.sources}

    def test_every_source_appears(self):
        self.assertEqual(sorted(self._by_name(self._page())),
                         ["primary", "secondary"])

    def test_counts_describe_the_rows_on_screen(self):
        """The merge trims to the limit; a count of what was fetched instead
        of what survived adds up to more rows than the page contains."""
        page = self._page(limit=4)
        breakdown = self._by_name(page)
        self.assertEqual(len(page.records), 4)
        self.assertEqual(sum(e["count"] for e in page.sources), 4)
        # Timestamps interleave 1,2,3,4 minutes ago, so the newest four are
        # two from each side.
        self.assertEqual(breakdown["primary"]["count"], 2)
        self.assertEqual(breakdown["secondary"]["count"], 2)

    def test_a_failed_source_is_present_and_marked(self):
        """Omitting the row makes a dead backend look like an empty one."""
        self.first.fail = True
        breakdown = self._by_name(self._page())
        self.assertIn("primary", breakdown)
        self.assertTrue(breakdown["primary"]["failed"])
        self.assertFalse(breakdown["secondary"]["failed"])

    def test_a_source_that_cannot_count_says_so(self):
        first, second = build_pair(second={"counts": False})
        page = FanOutLogSource([first, second]).search(
            LogQuery(window=self.window, text="*", limit=10),
            Scope.unrestricted())
        breakdown = {entry["name"]: entry for entry in page.sources}
        self.assertTrue(breakdown["primary"]["exact"])
        self.assertFalse(breakdown["secondary"]["exact"],
                         "an unknown total was reported as exact")


class InformationalTest(unittest.TestCase):
    """A merged page is only a note if every note in it is one."""

    def setUp(self):
        self.window = TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW)

    def _page(self, first_page=None, fail_second=False):
        first, second = build_pair()
        if first_page is not None:
            first.search = lambda query, scope: first_page
        if fail_second:
            second.fail = True
        return FanOutLogSource([first, second]).search(
            LogQuery(window=self.window, text="*", limit=10),
            Scope.unrestricted())

    def test_a_note_from_one_source_stays_a_note(self):
        quiet = LogPage(warnings=("nothing in this time range",),
                        informational=True)
        self.assertTrue(self._page(first_page=quiet).informational)

    def test_a_fault_anywhere_makes_the_page_a_fault(self):
        """Otherwise a dead backend rides along inside somebody else's note."""
        quiet = LogPage(warnings=("nothing in this time range",),
                        informational=True)
        self.assertFalse(self._page(first_page=quiet, fail_second=True)
                         .informational)

    def test_a_warning_that_claims_nothing_is_not_a_note(self):
        """A source that warns without saying it is only a note is a fault."""
        odd = LogPage(warnings=("something went sideways",))
        self.assertFalse(self._page(first_page=odd).informational)


class TotalHonestyTest(unittest.TestCase):
    """A merged total is a lie unless it says so."""

    def _page(self, **overrides):
        first, second = build_pair(**overrides)
        source = FanOutLogSource([first, second])
        return source.search(
            LogQuery(window=TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW),
                     text="*", limit=10),
            Scope.unrestricted())

    def test_totals_are_summed_when_every_source_can_count(self):
        page = self._page(first={"total": 40}, second={"total": 60})
        self.assertEqual(page.total, 100)
        self.assertFalse(any("exact count" in warning
                             for warning in page.warnings))

    def test_a_source_that_cannot_count_makes_the_sum_a_lower_bound(self):
        """Elasticsearch reports a real count; Loki returns up to `limit` and
        stops. Adding them gives a number that is neither."""
        page = self._page(first={"total": 40},
                          second={"total": 3, "counts": False})
        self.assertTrue(any("at least" in warning for warning in page.warnings),
                        "the sum was presented as an exact count")

    def test_a_capped_source_also_makes_it_a_lower_bound(self):
        """A source that returned exactly what it was asked for has more."""
        page = self._page(first={"total": 500})
        # `first` holds 3 records, so cap the request instead.
        first, second = build_pair(first={"total": 500})
        source = FanOutLogSource([first, second])
        capped = source.search(
            LogQuery(window=TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW),
                     text="*", limit=2),
            Scope.unrestricted())
        self.assertTrue(any("at least" in warning
                            for warning in capped.warnings))


class CapabilityTest(unittest.TestCase):
    """Capabilities narrow to what every member can do."""

    def test_a_delegated_capability_is_the_intersection(self):
        """Anything the fan-out passes through, one member at a time, has to
        be answerable by all of them — otherwise the feature quietly answers
        from a subset and labels it as everything."""
        first, second = build_pair(
            first={"capabilities": {Capability.SEARCH, Capability.AGGREGATION,
                                    Capability.CONTEXT}},
            second={"capabilities": {Capability.SEARCH,
                                     Capability.AGGREGATION}})
        source = FanOutLogSource([first, second])
        self.assertIn(Capability.SEARCH, source.capabilities)
        self.assertNotIn(Capability.CONTEXT, source.capabilities,
                         "a feature only one source can serve was offered")

    def test_field_statistics_survive_one_source_that_lacks_them(self):
        """The exception, and the reason it is one.

        The intersection was applied here too, and the effect was absurd: a
        Loki source holding a single line out of a hundred thousand removed
        the sidebar from the merged view entirely. The fan-out MERGES field
        statistics itself and names the sources that could not contribute, so
        the answer is attributed rather than pretended — which is what the
        rule was protecting against.
        """
        first, second = build_pair(
            first={"capabilities": {Capability.SEARCH, Capability.FIELD_STATS}},
            second={"capabilities": {Capability.SEARCH}})
        source = FanOutLogSource([first, second])
        self.assertIn(Capability.FIELD_STATS, source.capabilities)

    def test_no_member_with_field_statistics_means_none_offered(self):
        first, second = build_pair(
            first={"capabilities": {Capability.SEARCH}},
            second={"capabilities": {Capability.SEARCH}})
        source = FanOutLogSource([first, second])
        self.assertNotIn(Capability.FIELD_STATS, source.capabilities)

    def test_the_sources_that_could_not_contribute_are_nameable(self):
        """Without this the answer is a subset presented as the whole."""
        first, second = build_pair(
            first={"capabilities": {Capability.SEARCH, Capability.FIELD_STATS}},
            second={"capabilities": {Capability.SEARCH}})
        can, cannot = FanOutLogSource([first, second]).contributors(
            Capability.FIELD_STATS)
        self.assertEqual(can, ["primary"])
        self.assertEqual(cannot, ["secondary"])


class MergedFieldStatsTest(unittest.TestCase):
    """Counts from several sources are one set of counts, not several."""

    def setUp(self):
        from wdash.hub.models import FieldStat, FieldValue

        self.first, self.second = build_pair(
            first={"capabilities": {Capability.SEARCH, Capability.FIELD_STATS}},
            second={"capabilities": {Capability.SEARCH, Capability.FIELD_STATS}})
        self.first.field_stats = lambda query, scope, **kw: [
            FieldStat(field="level", values=[FieldValue("INFO", 100),
                                             FieldValue("ERROR", 10)]),
            FieldStat(field="host", values=[FieldValue("a", 60)])]
        self.second.field_stats = lambda query, scope, **kw: [
            FieldStat(field="level", values=[FieldValue("INFO", 5),
                                             FieldValue("WARN", 3)])]
        self.window = TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW)

    def _stats(self, sources=None):
        source = FanOutLogSource(sources or [self.first, self.second])
        found = source.field_stats(
            LogQuery(window=self.window, text="*"), Scope.unrestricted())
        return {stat.field: {v.value: v.count for v in stat.values}
                for stat in found}

    def test_counts_for_one_value_are_summed(self):
        """Not one source's answer shown as everything's."""
        self.assertEqual(self._stats()["level"]["INFO"], 105)

    def test_a_value_only_one_source_has_still_appears(self):
        self.assertEqual(self._stats()["level"]["WARN"], 3)

    def test_a_field_only_one_source_has_still_appears(self):
        self.assertEqual(self._stats()["host"], {"a": 60})

    def test_a_source_without_the_capability_is_skipped_not_asked(self):
        """Asking would raise, and catching the raise on every page load is
        a query the source cannot answer, issued anyway."""
        self.second._capabilities = frozenset({Capability.SEARCH})
        asked = []
        self.second.field_stats = lambda *a, **k: asked.append(1)
        self.assertEqual(self._stats()["level"]["INFO"], 100)
        self.assertEqual(asked, [])

    def test_one_source_failing_does_not_empty_the_sidebar(self):
        def explode(query, scope, **kw):
            raise RuntimeError("down")

        self.second.field_stats = explode
        self.assertEqual(self._stats()["level"]["INFO"], 100)

    def test_values_come_back_largest_first(self):
        values = list(self._stats()["level"])
        self.assertEqual(values[0], "INFO")


class RoutingTest(unittest.TestCase):
    """A handle says where it came from; that is what it is for."""

    def setUp(self):
        self.first, self.second = build_pair()
        self.source = FanOutLogSource([self.first, self.second])

    def test_fetch_goes_to_the_source_that_produced_the_record(self):
        page = self.source.search(
            LogQuery(window=TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW),
                     text="*", limit=10), Scope.unrestricted())
        loki_record = next(record for record in page.records
                           if record.source == "secondary")
        fetched = self.source.fetch(loki_record.ref, Scope.unrestricted())
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.source, "secondary")

    def test_an_unknown_backend_returns_none_rather_than_guessing(self):
        self.assertIsNone(
            self.source.fetch(SourceRef("nowhere", "x", "y"),
                              Scope.unrestricted()))


class AggregationMergeTest(unittest.TestCase):
    def setUp(self):
        self.first, self.second = build_pair(first={"total": 10},
                                             second={"total": 20})
        self.source = FanOutLogSource([self.first, self.second])
        self.window = TimeWindow.exact(NOW - dt.timedelta(hours=1), NOW)

    def aggregate(self, aggregations):
        return self.source.aggregate(
            LogQuery(window=self.window, text="*"), aggregations,
            Scope.unrestricted())

    def test_matching_buckets_are_added_rather_than_duplicated(self):
        buckets = self.aggregate([Terms(name="levels", field="severity")])
        by_key = {bucket.key: bucket.count for bucket in buckets.get("levels")}
        self.assertEqual(by_key["INFO"], 30)   # 10 + 20
        self.assertEqual(by_key["ERROR"], 2)   # 1 + 1

    def test_terms_come_back_largest_first(self):
        buckets = self.aggregate([Terms(name="levels", field="severity")])
        counts = [bucket.count for bucket in buckets.get("levels")]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_time_buckets_come_back_in_time_order(self):
        """Sorting a histogram by size would scramble the axis."""
        buckets = self.aggregate([DateHistogram(name="t", interval="1m")])
        keys = [bucket.key for bucket in buckets.get("t")]
        self.assertEqual(keys, sorted(keys))

    def test_the_readable_key_survives_the_merge(self):
        buckets = self.aggregate([DateHistogram(name="t", interval="1m")])
        self.assertTrue(buckets.get("t")[0].key_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
