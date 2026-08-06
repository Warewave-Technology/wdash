"""
Time range parsing and cache-friendly alignment.

Why this exists
---------------
Elasticsearch keys its shard request cache on the ENTIRE query body. If the
time bounds are rendered at sub-second precision on every request, each
request produces a unique key and the cache never hits. Twenty users looking
at the same dashboard make Elasticsearch compute the same thing twenty times.

Measured difference (lab, app-logs-000001, five identical aggregations):

    sub-second precision  ->  0 hits, 5 misses
    rounded to the minute ->  4 hits, 1 miss

No staleness risk
-----------------
Alignment does not serve old data: Elasticsearch invalidates a shard's request
cache entries whenever that shard refreshes. Freshness is therefore bounded by
the index's refresh_interval, not by our bucket size. The bucket only stops us
asking the same question twice.

Direction of alignment
----------------------
Start rounds down, end rounds up. The window only ever widens slightly and
never narrows, so rounding cannot drop data.
"""

import re
from datetime import datetime, timedelta, timezone

# Default window, used when the value is missing or unrecognised
DEFAULT_RANGE = "1h"

_RANGE_PATTERN = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)

_UNIT_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}

# Coarser rounding as the window grows: minute precision is pointless over a
# long range, and a coarser bucket extends the cache's useful life.
#   (window upper bound in seconds, bucket size in seconds)
_BUCKETS = (
    (6 * 3600, 60),        # <= 6 hours -> 1 minute
    (24 * 3600, 300),      # <= 24 hours -> 5 minutes
    (7 * 86400, 900),      # <= 7 days -> 15 minutes
)
_MAX_BUCKET = 3600         # anything longer -> 1 hour


def parse_range(value):
    """'15m', '1h', '7d' -> timedelta, or None when unparseable."""
    if not value:
        return None
    match = _RANGE_PATTERN.match(str(value).strip())
    if not match:
        return None
    amount, unit = match.groups()
    try:
        return timedelta(seconds=int(amount) * _UNIT_SECONDS[unit.lower()])
    except (ValueError, KeyError):
        return None


def bucket_for(window):
    """The alignment bucket, in seconds, appropriate to the window length."""
    seconds = window.total_seconds() if isinstance(window, timedelta) else float(window)
    for limit, bucket in _BUCKETS:
        if seconds <= limit:
            return bucket
    return _MAX_BUCKET


def _floor(moment, bucket):
    epoch = int(moment.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % bucket), tz=timezone.utc)


def _next_boundary(moment, bucket):
    """The next boundary above the bucket.

    Deliberately NOT a mathematical ceiling. A ceiling puts a value sitting
    exactly on a boundary into the previous step: 12:34:00.000000 -> 12:34:00
    but 12:34:00.000001 -> 12:35:00. That splits the cache key once a second
    and defeats the point of aligning.

    What we want is a step function constant across the WHOLE bucket: every
    value in [kB, (k+1)B) maps to the same result.
    """
    return _floor(moment, bucket) + timedelta(seconds=bucket)


def align(start, end, bucket=None):
    """Snap a range onto cache-friendly boundaries.

    Start rounds down, end rounds up; the window never narrows.
    """
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if bucket is None:
        bucket = bucket_for(end - start)
    return _floor(start, bucket), _next_boundary(end, bucket)


def resolve(time_range=DEFAULT_RANGE, now=None):
    """Turn a relative range ('1h', '7d') into aligned absolute bounds.

    Returns (start, end), both UTC and on cache-friendly boundaries.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    window = parse_range(time_range) or parse_range(DEFAULT_RANGE)
    return align(now - window, now)


def to_es(moment):
    """The explicit UTC form Elasticsearch expects. Seconds are enough."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_es_millis(moment):
    """UTC with millisecond precision.

    Used for record timestamps: `to_es` truncates to the second, which makes
    logs within the same second indistinguishable. Seconds are fine (and
    cache-friendly) for query BOUNDS, but not for record VALUES.
    """
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def align_iso(start_iso, end_iso):
    """Align ISO timestamps supplied by a client.

    Called at the server boundary. Unparseable values pass through unchanged —
    alignment is an optimisation, not a correctness requirement.
    """
    start = parse_iso(start_iso)
    end = parse_iso(end_iso)
    if start is None or end is None or end <= start:
        return start_iso, end_iso
    aligned_start, aligned_end = align(start, end)
    return to_es(aligned_start), to_es(aligned_end)


def parse_iso(value):
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def now_utc():
    """Now, in UTC. Kept in one place so it can be stubbed in tests."""
    return datetime.now(timezone.utc)
