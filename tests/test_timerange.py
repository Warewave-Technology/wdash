"""
Time range alignment tests.

The only purpose of this behaviour is to keep Elasticsearch's request cache key
stable. These tests protect two properties: key stability, and that rounding
never narrows the window.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.utils import timerange  # noqa: E402

NOW = datetime(2026, 8, 4, 12, 34, 56, 789012, tzinfo=timezone.utc)


class ParseRangeTest(unittest.TestCase):
    def test_supported_units(self):
        self.assertEqual(timerange.parse_range("30s"), timedelta(seconds=30))
        self.assertEqual(timerange.parse_range("15m"), timedelta(minutes=15))
        self.assertEqual(timerange.parse_range("6h"), timedelta(hours=6))
        self.assertEqual(timerange.parse_range("7d"), timedelta(days=7))
        self.assertEqual(timerange.parse_range("2w"), timedelta(weeks=2))

    def test_case_and_whitespace_tolerant(self):
        self.assertEqual(timerange.parse_range(" 1H "), timedelta(hours=1))

    def test_rejects_garbage(self):
        for value in ("", None, "abc", "1y", "-1h", "h1"):
            self.assertIsNone(timerange.parse_range(value), f"should have been rejected: {value}")


class BucketTest(unittest.TestCase):
    def test_bucket_grows_with_window(self):
        self.assertEqual(timerange.bucket_for(timedelta(minutes=15)), 60)
        self.assertEqual(timerange.bucket_for(timedelta(hours=6)), 60)
        self.assertEqual(timerange.bucket_for(timedelta(hours=24)), 300)
        self.assertEqual(timerange.bucket_for(timedelta(days=7)), 900)
        self.assertEqual(timerange.bucket_for(timedelta(days=90)), 3600)

    def test_bucket_is_monotonic(self):
        previous = 0
        for hours in (1, 6, 12, 24, 72, 168, 720):
            current = timerange.bucket_for(timedelta(hours=hours))
            self.assertGreaterEqual(current, previous)
            previous = current


class AlignTest(unittest.TestCase):
    def test_start_rounds_down_end_rounds_up(self):
        start = datetime(2026, 8, 4, 12, 34, 56, tzinfo=timezone.utc)
        end = datetime(2026, 8, 4, 13, 34, 56, tzinfo=timezone.utc)
        aligned_start, aligned_end = timerange.align(start, end)
        self.assertEqual(aligned_start, datetime(2026, 8, 4, 12, 34, tzinfo=timezone.utc))
        self.assertEqual(aligned_end, datetime(2026, 8, 4, 13, 35, tzinfo=timezone.utc))

    def test_window_never_shrinks(self):
        """Rounding must not lose data; the window may only widen."""
        for minutes in range(0, 180, 7):
            for seconds in (0, 1, 30, 59):
                start = NOW + timedelta(minutes=minutes, seconds=seconds)
                end = start + timedelta(hours=1)
                aligned_start, aligned_end = timerange.align(start, end)
                self.assertLessEqual(aligned_start, start)
                self.assertGreaterEqual(aligned_end, end)

    def test_naive_datetimes_treated_as_utc(self):
        naive_start = datetime(2026, 8, 4, 12, 0, 30)
        naive_end = datetime(2026, 8, 4, 13, 0, 30)
        aligned_start, aligned_end = timerange.align(naive_start, naive_end)
        self.assertEqual(aligned_start.tzinfo, timezone.utc)
        self.assertEqual(aligned_end.tzinfo, timezone.utc)

    def test_output_is_constant_across_the_whole_bucket(self):
        """The same result across the whole bucket, boundary included.

        A mathematical ceiling would be wrong here: it puts a value sitting on
        the boundary into the previous step and splits the key in two.
        """
        base = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)
        outputs = {
            timerange.align(base - timedelta(hours=1) + timedelta(seconds=offset,
                                                                 microseconds=micro),
                            base + timedelta(seconds=offset, microseconds=micro))
            for offset, micro in ((0, 0), (0, 1), (17, 0), (59, 999999))
        }
        self.assertEqual(len(outputs), 1)


class ResolveTest(unittest.TestCase):
    def test_requests_within_same_bucket_produce_identical_range(self):
        """Cache key stability — the reason this module exists."""
        ranges = {
            timerange.resolve("1h", now=NOW.replace(second=second, microsecond=micro))
            for second, micro in ((0, 0), (3, 1), (27, 500000), (59, 999999))
        }
        self.assertEqual(len(ranges), 1, "requests within the same minute must produce the same range")

    def test_different_buckets_produce_different_range(self):
        first = timerange.resolve("1h", now=NOW)
        later = timerange.resolve("1h", now=NOW + timedelta(minutes=2))
        self.assertNotEqual(first, later)

    def test_window_length_is_preserved_approximately(self):
        start, end = timerange.resolve("1h", now=NOW)
        span = (end - start).total_seconds()
        self.assertGreaterEqual(span, 3600)
        self.assertLess(span, 3600 + 2 * 60)

    def test_unknown_range_falls_back_to_default(self):
        fallback = timerange.resolve("nonsense", now=NOW)
        default = timerange.resolve(timerange.DEFAULT_RANGE, now=NOW)
        self.assertEqual(fallback, default)

    def test_result_has_no_sub_second_precision(self):
        """Any leftover microseconds would make the cache key unique again."""
        start, end = timerange.resolve("7d", now=NOW)
        self.assertEqual(start.microsecond, 0)
        self.assertEqual(end.microsecond, 0)


class ToEsTest(unittest.TestCase):
    def test_format_is_explicit_utc(self):
        moment = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(timerange.to_es(moment), "2026-08-04T12:00:00Z")

    def test_drops_sub_second_precision(self):
        moment = datetime(2026, 8, 4, 12, 0, 0, 987654, tzinfo=timezone.utc)
        self.assertEqual(timerange.to_es(moment), "2026-08-04T12:00:00Z")

    def test_converts_other_offsets_to_utc(self):
        moment = datetime(2026, 8, 4, 15, 0, 0, tzinfo=timezone(timedelta(hours=3)))
        self.assertEqual(timerange.to_es(moment), "2026-08-04T12:00:00Z")

    def test_none_passes_through(self):
        self.assertIsNone(timerange.to_es(None))


class AlignIsoTest(unittest.TestCase):
    def test_aligns_client_supplied_timestamps(self):
        start, end = timerange.align_iso(
            "2026-08-04T12:34:56.789012Z", "2026-08-04T13:34:56.789012Z")
        self.assertEqual(start, "2026-08-04T12:34:00Z")
        self.assertEqual(end, "2026-08-04T13:35:00Z")

    def test_same_minute_requests_collapse(self):
        results = {
            timerange.align_iso(f"2026-08-04T12:00:{s:02d}.{m:06d}Z",
                                f"2026-08-04T13:00:{s:02d}.{m:06d}Z")
            for s, m in ((1, 111111), (30, 500000), (59, 999999))
        }
        self.assertEqual(len(results), 1)

    def test_unparseable_values_pass_through_unchanged(self):
        """Alignment is an optimisation; unparseable input must not raise."""
        self.assertEqual(timerange.align_iso("garbage", "also-garbage"),
                         ("garbage", "also-garbage"))
        self.assertEqual(timerange.align_iso(None, None), (None, None))

    def test_inverted_range_passes_through(self):
        original = ("2026-08-04T13:00:00Z", "2026-08-04T12:00:00Z")
        self.assertEqual(timerange.align_iso(*original), original)

    def test_accepts_offset_notation(self):
        start, end = timerange.align_iso(
            "2026-08-04T12:34:56+00:00", "2026-08-04T13:34:56+00:00")
        self.assertEqual(start, "2026-08-04T12:34:00Z")


if __name__ == "__main__":
    unittest.main(verbosity=2)
