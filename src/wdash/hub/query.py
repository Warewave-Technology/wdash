"""Backend-independent query objects."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ..utils import timerange
from . import query_language as ql


@dataclass(frozen=True)
class TimeWindow:
    """A time range aligned to cache-friendly boundaries.

    Alignment happens here, in one place, so the same logical query produces
    the same bounds no matter which backend serves it. See utils.timerange.
    """
    start: datetime
    end: datetime

    @classmethod
    def of(cls, time_range="1h", now=None):
        start, end = timerange.resolve(time_range, now=now)
        return cls(start=start, end=end)

    @classmethod
    def between(cls, start, end):
        """An aligned range, for aggregation queries.

        Alignment stabilises the cache key but widens the window by up to one
        bucket. That is invisible in an aggregation; in a query that lists raw
        records it changes the result set, so use `exact` there.
        """
        aligned_start, aligned_end = timerange.align(start, end)
        return cls(start=aligned_start, end=aligned_end)

    @classmethod
    def exact(cls, start, end):
        """An unaligned range that preserves exactly what the caller asked for."""
        return cls(start=start, end=end)

    @property
    def duration_seconds(self):
        return (self.end - self.start).total_seconds()

    def suggest_interval(self):
        """A sensible histogram interval, aiming for roughly 60 points."""
        seconds = self.duration_seconds
        for limit, interval in ((900, "10s"), (3600, "1m"), (6 * 3600, "5m"),
                                (86400, "15m"), (7 * 86400, "1h"), (30 * 86400, "6h")):
            if seconds <= limit:
                return interval
        return "1d"

    def as_es_range(self):
        return {"gte": timerange.to_es(self.start), "lte": timerange.to_es(self.end)}


#: Default projection for the list view, in neutral field names.
#: trace_id is included: it is a single keyword field and it makes the
#: log-to-trace link visible in the list.
DEFAULT_LOG_FIELDS = ("timestamp", "body", "severity", "service", "host",
                      "environment", "trace_id")


@dataclass
class LogQuery:
    window: TimeWindow
    #: The text the user typed. Kept for storage and display; adapters use
    #: the parsed `filter` tree.
    text: str = "*"
    # Exact field filters: {"severity": "ERROR", "service": "api"}
    # Kept separate from the query text so they can live in filter context.
    filters: dict = field(default_factory=dict)
    exclude: dict = field(default_factory=dict)
    limit: int = 50
    cursor: Any = None
    ascending: bool = False
    #: Containers this query targets. INTERSECTED with the scope, never a
    #: replacement for it: this is a narrowing of scope, not a grant (for
    #: example a dashboard's index patterns). None = everything the scope allows.
    containers: Optional[tuple] = None
    #: The parsed form of `text`. Built by the constructor when not supplied.
    #: Adapters must ALWAYS use this, never the raw text.
    filter: Any = None
    #: Ask for a time histogram alongside the records. It rides on the SAME
    #: backend request — a separate call would double the round trips for
    #: something the search already has to scan.
    histogram: bool = False
    #: Fields to return, in neutral names. None = all of them.
    #: Keeping the list view narrow shrinks the response noticeably; the full
    #: record is fetched only when the detail view asks for it.
    fields: Optional[tuple] = None

    def __post_init__(self):
        # Parse the text once. A syntax error surfaces here, before the query
        # reaches the backend, with a message the caller can show.
        if self.filter is None:
            self.filter = ql.parse(self.text)

    def with_cursor(self, cursor):
        return LogQuery(window=self.window, text=self.text, filters=dict(self.filters),
                        exclude=dict(self.exclude), limit=self.limit, cursor=cursor,
                        ascending=self.ascending, fields=self.fields,
                        containers=self.containers, filter=self.filter)


#: How a trace list is ordered
SORT_RECENT = "recent"
SORT_SLOWEST = "slowest"


@dataclass
class TraceQuery:
    window: TimeWindow
    service: Optional[str] = None
    name: Optional[str] = None
    min_duration_us: Optional[int] = None
    only_errors: bool = False
    sort: str = SORT_RECENT
    limit: int = 50
