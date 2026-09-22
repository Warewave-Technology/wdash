"""
The neutral internal model.

Why not Elasticsearch's own shape
---------------------------------
If `hits`/`_source`/`aggregations` leak into the codebase, adding a second
backend becomes a rewrite. The price of being a hub is that the internal model
belongs to no backend.

Why OpenTelemetry semantic conventions
--------------------------------------
That is where the industry is heading, and OTel is on our roadmap. Elastic
donated ECS to OTel and the two schemas are actively converging. The ECS to
OTel conversion happens on read, inside the adapter; the internal model speaks
one language.

The vocabulary is OTel's: a log message is `body`, its level is `severity`,
and service or host information lives in `resource`.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# OTel severity texts. Adapters map backend-specific values onto these.
SEVERITIES = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL")
UNKNOWN_SEVERITY = "UNSPECIFIED"

#: Spellings of a level that are not one of `SEVERITIES`.
#:
#: Three standards are in here and each was half-covered, which is the shape
#: to look for: syslog had `crit`, `err`, `warning` and `notice` but not
#: `emerg` or `alert`; java.util.logging had `severe` and `fine` but not
#: `finer`, `finest` or `config`; and .NET had nothing at all.
#:
#: That last gap was reported from a real cluster. Serilog writes
#: `Information`, which is also `Microsoft.Extensions.Logging`'s name for it,
#: and it read UNSPECIFIED — so every informational line from every .NET
#: service in that cluster had no level, on a page whose main control is a
#: level filter.
_SEVERITY_ALIASES = {
    "WARNING": "WARN",
    "ERR": "ERROR",
    "CRIT": "FATAL",
    "CRITICAL": "FATAL",
    "SEVERE": "FATAL",
    "PANIC": "FATAL",
    "NOTICE": "INFO",
    "VERBOSE": "TRACE",
    "FINE": "DEBUG",
    # .NET: Serilog's own names and the `LogLevel` enum's, which agree.
    "INFORMATION": "INFO",
    # syslog RFC 5424, whose name for the same level is the longer one.
    "INFORMATIONAL": "INFO",
    "EMERG": "FATAL",
    "EMERGENCY": "FATAL",
    "ALERT": "FATAL",
    # java.util.logging, completing the pair already here.
    "FINER": "TRACE",
    "FINEST": "TRACE",
    "CONFIG": "DEBUG",
}


def iso_millis(moment):
    """Wire format for timestamps: UTC with millisecond precision.

    `isoformat()` emits microseconds; millisecond precision is what log tooling
    agrees on and is enough to distinguish records within the same second.
    """
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def normalise_severity(value):
    """Map a backend-specific level value onto its OTel equivalent."""
    if not value:
        return UNKNOWN_SEVERITY
    text = str(value).strip().upper()
    if text in SEVERITIES:
        return text
    return _SEVERITY_ALIASES.get(text, UNKNOWN_SEVERITY)


#: Every spelling `normalise_severity` recognises, lower case.
KNOWN_SEVERITY_SPELLINGS = tuple(sorted(
    {name.lower() for name in SEVERITIES}
    | {alias.lower() for alias in _SEVERITY_ALIASES}))


def severity_spellings(value):
    """The raw spellings, lower case, that normalise the way `value` does.

    For filtering a backend that stores what was written. A record's level
    is normalised and a panel counts it normalised, so a filter that matched
    only the spelling typed found none of the `error` lines for ERROR, and
    none of anything for the sidebar's merged WARN row. ERROR is
    ('error', 'err'); a value that is no severity is only itself, to be
    matched without regard to case. UNSPECIFIED is spelled by nothing — it
    is what a missing or unknown level becomes — so it gives (), and a
    filter for it is "none of KNOWN_SEVERITY_SPELLINGS".
    """
    text = str(value).strip()
    if text.upper() == UNKNOWN_SEVERITY:
        return ()
    canonical = normalise_severity(text)
    if canonical == UNKNOWN_SEVERITY:
        return (text.lower(),)
    return (canonical.lower(),) + tuple(sorted(
        alias.lower() for alias, target in _SEVERITY_ALIASES.items()
        if target == canonical))


def severity_from(values, fields):
    """(severity, raw) from the first of `fields` `values` carries.

    ONE rule, in one place, because three things have to agree about which
    field decides: the record reader, the filter an adapter renders for
    `level:ERROR`, and the panel that counts by level. They did not. The
    readers had always looked at several fields — Loki's `level`, `severity`
    and `detected_level`, VictoriaLogs' `level`, `severity`, `log.level` and
    `severity_text` — while the filter and the panels looked only at the
    first. A line written by an OTel collector was therefore drawn as ERROR,
    not found by `level:ERROR`, and counted under UNSPECIFIED.

    A field that is absent or empty is not carried: Loki drops an empty label
    at ingestion, and both backends match a missing field with `=""`, so the
    two states are one state everywhere this is used.
    """
    for field in fields:
        if values.get(field):
            return normalise_severity(values[field]), values[field]
    return UNKNOWN_SEVERITY, ""


@dataclass(frozen=True)
class SourceRef:
    """A backend-specific handle for a record.

    The internal model carries no backend detail, but fetching a record again
    later needs a handle. The web client reads the container and the id out
    of the token for the record views' URL and names the record's source
    beside them; what the container and the id mean — an index or a data
    stream, a document id — is the adapter's business.
    """
    backend: str        # 'elasticsearch', ...
    container: str      # index / stream / table
    id: str

    def as_token(self):
        return f"{self.backend}:{self.container}:{self.id}"

    @classmethod
    def parse(cls, token):
        parts = str(token).split(":", 2)
        if len(parts) != 3:
            raise ValueError(f"gecersiz kaynak tutamagi: {token!r}")
        return cls(*parts)


@dataclass
class LogRecord:
    timestamp: datetime
    body: str
    #: Normalised level (the text form of OTel's SeverityNumber)
    severity: str = UNKNOWN_SEVERITY
    #: The raw value as reported by the source (OTel SeverityText). "WARNING"
    #: normalises to "WARN", but what the user sees should not change.
    severity_text: str = ""
    service: str = ""
    resource: dict = field(default_factory=dict)   # host, environment, k8s ...
    attributes: dict = field(default_factory=dict)  # record-specific fields
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    ref: Optional[SourceRef] = None
    #: Which configured source answered. Not the backend type — two
    #: Elasticsearch sources both say "elasticsearch", and the whole point of
    #: showing this is telling them apart.
    source: Optional[str] = None

    @property
    def is_correlated(self):
        """Can this record be linked to a trace?"""
        return bool(self.trace_id)

    def to_dict(self):
        return {
            "timestamp": iso_millis(self.timestamp),
            "body": self.body,
            "severity": self.severity,
            "severity_text": self.severity_text or self.severity,
            "service": self.service,
            "resource": self.resource,
            "attributes": self.attributes,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "ref": self.ref.as_token() if self.ref else None,
            "source": self.source,
        }


@dataclass
class LogPage:
    records: list = field(default_factory=list)
    total: int = 0
    took_ms: int = 0
    cursor: Any = None            # opaque continuation handle
    containers: tuple = ()        # containers actually queried
    partial: bool = False         # some containers failed or timed out
    warnings: tuple = ()
    #: Time buckets, each split by severity. Empty unless the query asked.
    histogram: list = field(default_factory=list)
    #: Are the warnings notes rather than faults?
    #:
    #: "Nothing was logged in this window" and "this store did not answer" both
    #: arrive as an empty page with a warning, and the caller turned any such
    #: page into a red error. A quiet Sunday is not a failure, and reporting it
    #: as one sends somebody to their administrator over a narrow time picker.
    informational: bool = False
    #: Is `total` a match count, or a floor?
    #:
    #: Loki answers a range query by returning up to a limit and stopping, so
    #: its total is "at least this many". Stated rather than inferred: this
    #: used to be read off the warning text by looking for the word "count",
    #: which makes any future warning that happens to contain it downgrade an
    #: exact total.
    counted: bool = True
    #: Which sources contributed, and how much: [{name, count, total, failed}].
    #:
    #: Deliberately NOT part of field statistics. Those are a declared
    #: capability that Loki does not have, so a merged view narrows them away
    #: — and a merged view is exactly when "which source answered" matters.
    #: This comes from the search itself and is therefore always available.
    sources: list = field(default_factory=list)

    def __len__(self):
        return len(self.records)

    def to_dict(self):
        return {
            "records": [r.to_dict() for r in self.records],
            "total": self.total,
            "took_ms": self.took_ms,
            "cursor": self.cursor,
            "containers": list(self.containers),
            "partial": self.partial,
            "informational": self.informational,
            "counted": self.counted,
            "sources": self.sources,
            "warnings": list(self.warnings),
            "histogram": self.histogram,
        }


@dataclass
class LogContext:
    """The chronological neighbours of a record."""
    record: Optional[LogRecord] = None
    before: list = field(default_factory=list)
    after: list = field(default_factory=list)
    correlated_by: Optional[str] = None

    def to_dict(self):
        return {
            "record": self.record.to_dict() if self.record else None,
            "before": [r.to_dict() for r in self.before],
            "after": [r.to_dict() for r in self.after],
            "correlated_by": self.correlated_by,
        }


@dataclass
class FieldValue:
    value: Any
    count: int


@dataclass
class FieldStat:
    field: str
    values: list = field(default_factory=list)   # FieldValue

    def to_dict(self):
        return {"field": self.field,
                "values": [{"value": v.value, "count": v.count} for v in self.values]}


class PartialCounts(list):
    """Counts, and what is missing from them.

    `field_stats` and `histogram` answer with a list, and a list has nowhere
    to say that the counts in it were computed from a sixth of the shards.
    Elasticsearch fails a search outright only when EVERY shard fails; when
    some do it answers 200 with what the rest found, so the sidebar drew
    2789 records per field beside a result list reporting that five shards of
    six had failed.

    It is a list, so every caller that only reads the rows is unchanged; the
    route reads `warnings` and says so above the numbers.
    """

    def __init__(self, items=(), warnings=()):
        super().__init__(items)
        self.warnings = tuple(warnings)

    @property
    def partial(self):
        """Whether these counts cover less than they were asked to."""
        return bool(self.warnings)


# --------------------------------------------------------------------------
# Trace side
# --------------------------------------------------------------------------

SPAN_KINDS = ("INTERNAL", "SERVER", "CLIENT", "PRODUCER", "CONSUMER")

STATUS_OK = "OK"
STATUS_ERROR = "ERROR"
STATUS_UNSET = "UNSET"


@dataclass
class Span:
    trace_id: str
    span_id: str
    name: str
    service: str
    start: datetime
    duration_us: int
    parent_span_id: Optional[str] = None
    kind: str = "INTERNAL"
    status: str = STATUS_UNSET
    resource: dict = field(default_factory=dict)
    attributes: dict = field(default_factory=dict)
    ref: Optional[SourceRef] = None
    #: Which configured source answered.
    source: Optional[str] = None

    @property
    def is_root(self):
        return not self.parent_span_id

    @property
    def failed(self):
        return self.status == STATUS_ERROR

    def to_dict(self):
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "service": self.service,
            "kind": self.kind,
            "status": self.status,
            "start": iso_millis(self.start),
            "duration_us": self.duration_us,
            "resource": self.resource,
            "attributes": self.attributes,
            "ref": self.ref.as_token() if self.ref else None,
            "source": self.source,
        }


class PartialList(list):
    """Rows that can say they are not the whole answer.

    Trace search and the service list answer with lists, and a list has
    nowhere to say "one of the stores behind this did not answer". A failure
    had two ways out, then: raise and lose what the others answered, or leave
    the rows out and look exactly like a quieter hour. This is still a list —
    whatever iterates, counts or indexes the answer works unchanged — with
    the two things a LogPage carries for the same reason.
    """

    #: And a third thing, which is not a failure.
    #:
    #: `partial` means something could not be read, and the page prints
    #: "Part of this could not be loaded" above the rows. A list that IS
    #: whole can still be narrower than the control that asked for it —
    #: "Slowest" over a backend that cannot sort is the slowest of the page
    #: that backend returned, not of the window — and saying that under a
    #: warning about an outage would be a second untrue sentence.
    def __init__(self, rows=(), partial=False, warnings=(), notes=()):
        super().__init__(rows)
        self.partial = bool(partial)
        self.warnings = tuple(warnings)
        self.notes = tuple(notes)


@dataclass
class Trace:
    trace_id: str
    spans: list = field(default_factory=list)
    partial: bool = False        # some spans may be missing
    #: Spans the scope removed. Counted where they were dropped, so "some
    #: spans are hidden" is said when some were — not guessed from the rules.
    hidden: int = 0
    #: What could not be read, when `partial`: which store, and why.
    warnings: tuple = ()

    @property
    def root(self):
        for span in self.spans:
            if span.is_root:
                return span
        # No root found (sampling or missing data) — fall back to the earliest span
        return min(self.spans, key=lambda s: s.start) if self.spans else None

    @property
    def duration_us(self):
        root = self.root
        return root.duration_us if root else 0

    @property
    def services(self):
        return sorted({s.service for s in self.spans if s.service})

    @property
    def has_error(self):
        return any(s.failed for s in self.spans)

    def children_of(self, span_id):
        return sorted((s for s in self.spans if s.parent_span_id == span_id),
                      key=lambda s: s.start)

    def self_time_us(self, span):
        """Time spent in this span itself, excluding its children.

        This is what tells you WHERE the time went. A span lasting 2s is
        uninteresting if 1.9s of it was a child call; the same 2s is very
        interesting if it is all self time.

        Clamped at zero because concurrent children can overlap and sum to more
        than the parent — a negative number would be worse than a rough one.
        """
        children = self.children_of(span.span_id)
        return max(0, span.duration_us - sum(c.duration_us for c in children))

    def service_breakdown(self):
        """Self time aggregated per service, largest first.

        This is the question a trace is usually opened to answer: not "what
        happened" but "where did the time actually go". Summing self time is
        the only way to get that — summing total duration double-counts every
        parent.
        """
        totals, counts, errors = {}, {}, {}
        for span in self.spans:
            totals[span.service] = totals.get(span.service, 0) + self.self_time_us(span)
            counts[span.service] = counts.get(span.service, 0) + 1
            if span.failed:
                errors[span.service] = errors.get(span.service, 0) + 1

        overall = sum(totals.values()) or 1
        return sorted(
            ({"service": name,
              "self_time_us": value,
              "share": value / overall,
              "span_count": counts.get(name, 0),
              "error_count": errors.get(name, 0)}
             for name, value in totals.items()),
            key=lambda row: row["self_time_us"], reverse=True)

    def waterfall(self):
        """(span, depth) pairs starting from the root — the UI ordering.

        Cycle-safe: traces with a broken parent chain do occur in real data
        (sampling, truncated spans).
        """
        rows, seen = [], set()

        def walk(span, depth):
            if span.span_id in seen:
                return
            seen.add(span.span_id)
            rows.append((span, depth))
            for child in self.children_of(span.span_id):
                walk(child, depth + 1)

        root = self.root
        if root:
            walk(root, 0)
        # Do not lose spans unreachable from the root
        for span in sorted(self.spans, key=lambda s: s.start):
            if span.span_id not in seen:
                walk(span, 0)
        return rows

    def to_dict(self):
        return {
            "trace_id": self.trace_id,
            "spans": [s.to_dict() for s in self.spans],
            "duration_us": self.duration_us,
            "services": self.services,
            "has_error": self.has_error,
            "partial": self.partial,
            "warnings": list(self.warnings),
        }


@dataclass
class TraceSummary:
    """One row in a trace list.

    Field names are deliberately literal: `service` and `name` describe the
    span that MATCHED the search, which is not necessarily the trace root. A
    search for "payment-service" returns that service's entry span, not the
    api-gateway span above it. Calling it `root_service` would be a lie.

    `span_count` is None because the summary comes from a single span per
    trace; counting spans would need a second query per row.
    """
    trace_id: str
    service: str
    name: str
    start: datetime
    duration_us: int
    has_error: bool = False
    span_count: Optional[int] = None
    #: Which configured source answered. Not the backend type — two
    #: Elasticsearch sources both say "elasticsearch", and telling them apart
    #: is the whole point of showing this.
    source: Optional[str] = None

    def to_dict(self):
        return {
            "trace_id": self.trace_id,
            "service": self.service,
            "name": self.name,
            "start": iso_millis(self.start),
            "duration_us": self.duration_us,
            "has_error": self.has_error,
            "span_count": self.span_count,
            "source": self.source,
        }


@dataclass
class Service:
    name: str
    span_count: int = 0
    error_count: int = 0

    @property
    def error_rate(self):
        return (self.error_count / self.span_count) if self.span_count else 0.0

    def to_dict(self):
        return {"name": self.name, "span_count": self.span_count,
                "error_count": self.error_count, "error_rate": self.error_rate}


# ---------------------------------------------------------------------------
# Synthetic monitors
# ---------------------------------------------------------------------------
#
# A third signal. Logs say what happened inside the system; traces say how a
# request moved through it; a monitor says whether somebody outside can reach
# it at all. The three answer different questions and none substitutes for
# another — an application that logs nothing because it is unreachable looks
# healthy in the log search.
#
# The shape below is neutral, as everywhere else in the hub. It was derived
# from real Heartbeat 8.19 documents produced by the lab rather than from the
# documentation, because the two disagree in small ways that matter: `summary`
# is absent from non-final attempts, `monitor.status` and `summary.status` are
# different fields with different meanings, and the certificate lives under
# `tls.server.x509` while an older duplicate sits at `tls.certificate_*`.

#: A monitor is either reachable or it is not. Anything a backend cannot say
#: is UNKNOWN rather than assumed up — "no answer" is not "yes".
UP = "up"
DOWN = "down"
UNKNOWN = "unknown"


@dataclass
class Certificate:
    """The TLS certificate a monitor saw on its last check.

    Separate from the monitor because it is a different question with a
    different audience: "is the site up" is watched continuously, "when does
    this expire" is a diary entry. Kibana splits them into two tabs for the
    same reason.
    """
    common_name: str = ""
    issuer: str = ""
    not_before: object = None
    not_after: object = None
    #: Hex SHA-256, which is what a fingerprint comparison uses.
    fingerprint: str = ""
    key_algorithm: str = ""
    #: RSA certificates carry a size; ECDSA ones carry a curve and no size.
    #: Both are here because neither substitutes for the other, and reporting
    #: a missing size as `0` invents a fact — `ECDSA-0` is not a key.
    key_size: int = 0
    key_curve: str = ""
    signature_algorithm: str = ""
    serial_number: str = ""
    #: Whether the check that reported this certificate completed a VERIFIED
    #: handshake with the endpoint. Tri-state, and None is the default on
    #: purpose: it means the source did not say. Heartbeat never says — its
    #: documents carry no such field, and the lab's own configuration sets
    #: `ssl.verification_mode: none` — so defaulting to False would invent a
    #: finding and defaulting to True would invent a reassurance.
    #:
    #: About the HANDSHAKE, not about this certificate: the certificate here
    #: was read on a second, deliberately unverified connection, so on a host
    #: that answers two connections differently they are not necessarily the
    #: same certificate.
    verified: object = None

    def _remaining(self):
        if self.not_after is None:
            return None
        from datetime import datetime, timezone
        expiry = self.not_after
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry - datetime.now(timezone.utc)

    @property
    def days_remaining(self):
        """Days until expiry, ROUNDED. Negative once it has expired.

        Rounded rather than truncated, because `timedelta.days` throws away
        the remainder: a certificate with eleven days left is almost never
        exactly eleven days out, it is ten days and twenty-three hours, and
        `.days` calls that ten. Every number on the page would be one low,
        consistently, in the direction that makes an expiry look further away
        than it is.

        None when the backend gave no expiry — which must not become zero,
        because zero reads as "expires today" and is the loudest thing on the
        page.
        """
        remaining = self._remaining()
        if remaining is None:
            return None
        return round(remaining.total_seconds() / 86400)

    @property
    def key_description(self):
        """`RSA-2048`, `ECDSA P-256`, or empty. Never a fabricated number."""
        if not self.key_algorithm:
            return ""
        if self.key_curve:
            return f"{self.key_algorithm} {self.key_curve}"
        if self.key_size:
            return f"{self.key_algorithm}-{self.key_size}"
        return self.key_algorithm

    @property
    def expired(self):
        """From the timestamp, not from the rounded day count.

        A certificate that expired an hour ago rounds to zero days, and zero
        is not expired — it is "expires today". The sign of the interval is
        the only thing that answers this.
        """
        remaining = self._remaining()
        return remaining is not None and remaining.total_seconds() < 0


@dataclass
class Monitor:
    """One synthetic check, as it stood at its most recent run."""
    id: str
    name: str = ""
    #: http, tcp, icmp, browser — the backend's own word, lowercased.
    type: str = ""
    url: str = ""
    status: str = UNKNOWN
    #: When the last check ran.
    checked_at: object = None
    #: How long the check took. None when unknown; NOT zero, which would read
    #: as an instant response.
    duration_ms: float = None
    #: Why it is down. Empty when it is up.
    error: str = ""
    tags: tuple = field(default_factory=tuple)
    certificate: object = None
    #: This check's own TLS decision, as its DEFINITION states it: "verify",
    #: "expiry_only", or "" for a source that does not have the notion.
    #:
    #: From the definition rather than from the last result, because that is
    #: the only one of the two that is always there: a check whose agent has
    #: gone quiet, whose certificate could not be read, or that has never run
    #: still has a mode, and "this check does not verify the certificate" is
    #: a fact about how it is configured.
    tls_mode: str = ""
    #: Recent history, coarse enough to draw in a table cell. Empty unless the
    #: caller asked for it — the extra aggregation is not free, and the
    #: certificate screen has no use for it.
    series: tuple = field(default_factory=tuple)
    #: Which configured source this came from, so a merged page can say.
    source: str = ""
    #: Where the underlying document lives, for the raw view.
    ref: object = None

    @property
    def is_down(self):
        return self.status == DOWN

    @property
    def expiry_only(self):
        """Whether this check deliberately does not verify the certificate.

        One rule, read by the page and by the alert, so the chip and the
        sentence can never disagree. The mode is the fact: `verified is
        False` on a result also covers a verifying check whose handshake
        simply FAILED, and labelling that one "expiry only" would be a claim
        about a setting nobody chose.
        """
        return self.tls_mode == "expiry_only"

    @property
    def location(self):
        """Host and port, for a list that has to fit on one line."""
        from urllib.parse import urlparse
        if not self.url:
            return ""
        parsed = urlparse(self.url)
        return parsed.netloc or self.url


@dataclass
class MonitorPoint:
    """One bucket of a monitor's history.

    A bucket rather than a check, because a sparkline over a day cannot draw
    one mark per check without drawing thousands. `checks` is how many runs
    the bucket covers, and it is here so an empty bucket — the agent stopped —
    is distinguishable from a fast one.
    """
    timestamp: object
    #: Mean response time over the bucket, or None when nothing ran.
    duration_ms: float = None
    #: How many of the runs in this bucket failed.
    down: int = 0
    checks: int = 0

    @property
    def has_data(self):
        return self.checks > 0

    @property
    def is_down(self):
        """Any failure in the bucket. A bucket that was down for one run out
        of six is not healthy, and averaging the status away is how a
        five-minute outage disappears from a day-long chart."""
        return self.down > 0


@dataclass
class MonitorCheck:
    """One run of one monitor. The history behind the current status."""
    timestamp: object
    status: str = UNKNOWN
    duration_ms: float = None
    error: str = ""
    #: StepResult per step, for a browser journey. Empty for every other kind
    #: — which is what lets one table render both without a second page.
    steps: tuple = field(default_factory=tuple)
    #: The failure screenshot, when there is one.
    screenshot_id: str = None
    #: Where this check ran from — the agent that reported it, or the
    #: `observer.geo.name` Elastic stamps on it. Empty when the source does
    #: not say, which is a real state and not a default: a self-managed
    #: Heartbeat writes no observer at all until somebody configures one.
    #:
    #: Here rather than on Monitor because a check has ONE location and a
    #: monitor has as many as it has probes. Averaging the two together is
    #: how "87.5% available" ends up describing neither Frankfurt nor Dublin.
    location: str = ""

    @property
    def failed_step(self):
        return next((s for s in self.steps if s.status == STEP_FAILED), None)


#: How a step turned out. `skipped` is the important one — see JourneyRun.
STEP_PASSED = "passed"
STEP_FAILED = "failed"
STEP_SKIPPED = "skipped"


@dataclass
class StepResult:
    """One step of one journey run.

    Timed individually, because that is the whole reason a journey is not a
    request. "The checkout takes nine seconds" is a fact nobody can act on;
    "the basket page takes eight of the nine" is a fact somebody can fix.
    """
    index: int
    kind: str = ""
    #: What the step was, rendered — "Type into #password". Stored rather than
    #: derived so a run stays readable after the journey has been edited: the
    #: alternative shows last week's failure against this week's step 4.
    description: str = ""
    status: str = STEP_SKIPPED
    duration_us: int = None
    error: str = ""
    #: How to ask this step's SOURCE for the picture of the page, or None
    #: where the source keeps none per step. Opaque on purpose: WDash's own
    #: runs store one image per run and identify it by a row id, while
    #: Elastic stores one per step, in pieces, addressed by check group and
    #: step index. A page that had to know which is which would be a page
    #: that breaks when a third kind appears.
    screenshot_id: str = None

    @property
    def duration_ms(self):
        return None if self.duration_us is None else self.duration_us / 1000.0


@dataclass
class JourneyRun:
    """One run of a browser journey.

    A journey stops at the first failing step. The steps after it are
    `skipped`, NOT failed: marking them failed says seven things broke when
    one did, and the seven include every step that never ran.
    """
    monitor_id: str
    started_at: object = None
    status: str = UNKNOWN
    duration_us: int = None
    error: str = ""
    steps: tuple = field(default_factory=tuple)
    #: Set when a step failed and the agent could still reach the page.
    screenshot_id: str = None
    agent: str = ""

    @property
    def duration_ms(self):
        return None if self.duration_us is None else self.duration_us / 1000.0

    @property
    def failed_step(self):
        return next((s for s in self.steps if s.status == STEP_FAILED), None)

    @property
    def completed(self):
        """Steps that actually ran. The denominator on a progress line."""
        return sum(1 for s in self.steps if s.status != STEP_SKIPPED)


@dataclass
class MonitorPage:
    """What a monitor listing returns.

    Carries the same partial/warning machinery as LogPage, and for the same
    reason: with several sources merged, one of them failing must not look
    like "those monitors are gone".
    """
    monitors: list = field(default_factory=list)
    warnings: tuple = ()
    partial: bool = False
    #: Sources that answered, and sources that were asked and did not.
    sources: tuple = ()
    missing_sources: tuple = ()

    @property
    def counts(self):
        out = {UP: 0, DOWN: 0, UNKNOWN: 0}
        for monitor in self.monitors:
            out[monitor.status if monitor.status in out else UNKNOWN] += 1
        return out
