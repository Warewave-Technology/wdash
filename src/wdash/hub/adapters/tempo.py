"""
Grafana Tempo as a trace source.

Measured against a running Tempo, not remembered. The differences from Jaeger
are not cosmetic — three of them would have produced a page that looked like
it worked and was wrong.

**Two endpoints, two id encodings.** `/api/search` returns `traceID` as hex.
`/api/traces/{id}` returns OTLP JSON, where ids are protobuf `bytes` and
therefore **base64**: `"+ffbbT5EHZBxcU9vUPOPdw=="`, not
`"f9f7db6d3e441d90…"`. Reading them as hex yields garbage span ids, every
parent link dangles, and the waterfall comes out flat with no error anywhere —
the shape of a bug that looks like missing instrumentation.

**Enums are strings.** `kind: "SPAN_KIND_SERVER"`, `status.code:
"STATUS_CODE_ERROR"`. Not the integers OTLP uses on the wire.

**Search results carry `serviceStats`.** Per trace, per service, a `spanCount`
and an `errorCount`. That is what makes a summary's error flag and span count
free — Jaeger needs the whole trace fetched to know either.

**There is no service volume.** Tempo can list service NAMES from a tag query,
but per-service span counts need the metrics-generator writing to Prometheus,
which is a separate system. Counts are reported as zero rather than derived
from a bounded search: a number that describes the 20 traces that came back,
presented as the volume of a service, is worse than no number.

**TraceQL cannot express everything, and says so.** An unparseable query is an
HTTP 400 with a parse error. Anything the neutral query asks for that TraceQL
cannot say is refused here rather than dropped — a query that silently loses a
clause returns MORE than the caller asked for, which is the one direction an
access-controlled system must never round in.
"""

import base64
import binascii
from datetime import datetime, timezone

import requests

from ..models import (
    STATUS_ERROR, STATUS_OK, STATUS_UNSET, PartialList, Service, SourceRef,
    Span, Trace, TraceSummary,
)
from .. import patterns
from ..source import Capability, TraceSource

DEFAULT_TIMEOUT = 30

#: The attribute holding a service name. `resource.service.name` is the
#: OpenTelemetry spelling; `service.name` is what Tempo's v1 tag API uses.
SERVICE_ATTRIBUTE = "resource.service.name"

#: Matched spans returned per trace. They time a row whose root is hidden, so
#: the default of three would time a service by three of its spans.
SPANS_PER_SET = 100

_STATUS_BY_CODE = {
    "STATUS_CODE_OK": STATUS_OK,
    "STATUS_CODE_ERROR": STATUS_ERROR,
    "STATUS_CODE_UNSET": STATUS_UNSET,
}


class TempoError(RuntimeError):
    """Tempo could not answer."""


class TempoQueryError(TempoError):
    """TraceQL cannot express what was asked.

    Its own type because the answer is different: a connection failure means
    try again, this one means the query has to change.
    """


def _hex_id(value):
    """A protobuf `bytes` id as hex.

    Tempo's trace endpoint returns these base64-encoded because that is how
    protobuf JSON maps `bytes`. Its SEARCH endpoint returns the same ids as
    hex. Both shapes reach this adapter, so both are handled — a value that is
    already hex is passed through rather than being decoded into nonsense.
    """
    if not value:
        return ""
    text = str(value)
    # Hex ids are 16 or 32 characters of [0-9a-f]; base64 of the same bytes is
    # a different length and carries characters hex cannot.
    if len(text) in (16, 32):
        try:
            int(text, 16)
            return text.lower()
        except ValueError:
            pass
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4)).hex()
    except (binascii.Error, ValueError):
        return text


def _nanoseconds_to_datetime(value):
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000_000,
                                      tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def _extent(entry):
    """(start, duration in µs) of the spans Tempo matched in one trace.

    `spanSets` since Tempo 2.2, `spanSet` before; a span carries its start
    in nanoseconds and its duration in nanoseconds, both as strings.
    """
    sets = entry.get("spanSets") or [entry.get("spanSet") or {}]
    starts, ends = [], []
    for spanset in sets:
        for span in spanset.get("spans") or ():
            try:
                begin = int(span.get("startTimeUnixNano"))
                ends.append(begin + int(span.get("durationNanos") or 0))
                starts.append(begin)
            except (TypeError, ValueError):
                continue
    if not starts:
        return None, 0
    return (_nanoseconds_to_datetime(min(starts)),
            (max(ends) - min(starts)) // 1000)


def _attributes(raw):
    """OTLP's [{key, value:{stringValue|intValue|…}}] as a plain mapping."""
    out = {}
    for entry in raw or ():
        key = entry.get("key")
        if key is None:
            continue
        value = entry.get("value") or {}
        if not isinstance(value, dict):
            out[key] = value
            continue
        # One of stringValue / intValue / boolValue / doubleValue / arrayValue.
        for holder in ("stringValue", "intValue", "boolValue", "doubleValue"):
            if holder in value:
                out[key] = value[holder]
                break
        else:
            out[key] = value
    return out


def _quote(value):
    """A TraceQL string literal.

    Always quoted and always escaped: an unescaped quote closes the string and
    the rest of the value becomes syntax, which Tempo answers with a 400 —
    and a value containing `"} || {"` would otherwise be a way to widen the
    query past the scope.
    """
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


class TempoTraceSource(TraceSource):
    """Exposes Tempo as a neutral trace source."""

    backend = "tempo"

    def __init__(self, url, name="tempo", username=None, password=None,
                 tenant=None, verify_certs=True, timeout=DEFAULT_TIMEOUT,
                 session=None):
        self.name = name
        self._url = (url or "").rstrip("/")
        self._auth = (username, password) if username else None
        self._tenant = tenant
        self._verify = verify_certs
        self._timeout = timeout
        self._session = session or requests.Session()

    @property
    def capabilities(self):
        return frozenset({Capability.TRACE_LOOKUP, Capability.TRACE_SEARCH,
                          Capability.SERVICE_LIST})

    # ---------- transport ----------

    def _get(self, path, params=None, missing_is_none=False):
        """One GET. A 404 is a failure unless the caller says otherwise.

        Only a trace lookup may read a 404 as "I do not hold that". The same
        `_get` serves `/api/search`, the tag values and the service list, and
        mapping every 404 to None there turned a base URL with a stale path
        prefix — a proxy route that was removed, a Tempo too old for the v2
        tag API — into an empty service list and an empty trace list, with
        nothing said. The page called that "No spans in this time range."
        """
        headers = {}
        if self._tenant:
            # Tempo's multi-tenancy header, when the deployment enables it.
            headers["X-Scope-OrgID"] = self._tenant

        response = self._session.get(
            f"{self._url}{path}", params=params or {}, headers=headers,
            auth=self._auth, timeout=self._timeout, verify=self._verify)

        if missing_is_none and response.status_code == 404:
            return None          # "no such trace" — an answer, not a failure
        if response.status_code == 400:
            # Tempo's parse errors are precise and worth passing on verbatim:
            # "parse error at line 1, col 3: syntax error: unexpected
            # IDENTIFIER" tells somebody exactly what to fix.
            raise TempoQueryError(response.text[:300] or "Tempo refused the query")
        if response.status_code >= 400:
            raise TempoError(
                f"Tempo answered HTTP {response.status_code}: "
                f"{response.text[:200]}")
        try:
            return response.json()
        except ValueError as exc:
            raise TempoError(f"Tempo returned something that is not JSON: {exc}")

    def health(self):
        try:
            response = self._session.get(
                f"{self._url}/ready", auth=self._auth, timeout=5,
                verify=self._verify)
            text = (response.text or "").strip()
            # Tempo answers `/ready` with "Ingester not ready: …" while it is
            # starting, which is a 200 with a body that says otherwise.
            healthy = response.status_code < 400 and text.startswith("ready")
            return healthy, "ok" if healthy else (text[:120] or
                                                  f"HTTP {response.status_code}")
        except Exception as exc:
            return False, str(exc)

    # ---------- containers ----------

    def containers(self, scope):
        """The one container Tempo has: the store itself, by its source name.

        Tempo has no index a role can be granted, so a role's trace stores are
        matched against this source's NAME — `*`, `lab-tempo`, or
        `lab-tempo:*`. It used to ask only whether the role had any LOG
        container, so a role granted nothing but `otel-traces-*` in
        Elasticsearch read every trace in Tempo, while the role preview,
        which does match the name, said it reached none.
        """
        if scope.trace_is_empty:
            return []
        return scope.resolve_traces([self.name], source=self.name)

    def _granted(self, scope):
        return bool(self.containers(scope))

    # ---------- services ----------

    def _service_names(self, scope, window=None):
        params = {}
        if window is not None:
            params = {"start": int(window.start.timestamp()),
                      "end": int(window.end.timestamp())}

        names = []
        body = self._get(f"/api/v2/search/tag/{SERVICE_ATTRIBUTE}/values",
                         params)
        for entry in (body or {}).get("tagValues") or ():
            # v2 returns {type, value}; v1 returns bare strings.
            name = entry.get("value") if isinstance(entry, dict) else entry
            if name:
                names.append(name)

        return sorted({name for name in names
                       if scope.allows_service(name, source=self.name)})

    def services(self, window, scope):
        """Service names, without volume.

        Per-service span counts need the metrics-generator writing to
        Prometheus, which is a separate system this adapter does not talk to.
        Zero is reported rather than a count aggregated from a bounded search:
        that would describe the traces that came back, not the service.
        """
        if not self._granted(scope):
            return []
        # A failure is raised: an empty list is what a quiet hour looks like,
        # and the route turns the raise into a 503 the page shows.
        names = self._service_names(scope, window)
        return [Service(name=name, span_count=0, error_count=0)
                for name in names]

    # ---------- one trace ----------

    def trace(self, trace_id, window, scope):
        if not self._granted(scope):
            return None
        # Only a 404 is "no such trace", and only here: `missing_is_none`
        # keeps that reading to the trace lookup, where it is true.
        # Anything else is raised: caught here it became None as well, and
        # the page said "not found, widen the time range" during an outage.
        body = self._get(f"/api/traces/{trace_id}", missing_is_none=True)

        if not body:
            return None

        spans, hidden = [], 0
        for batch in body.get("batches") or ():
            resource = _attributes((batch.get("resource") or {})
                                   .get("attributes"))
            service = str(resource.get("service.name") or "")
            if not scope.allows_service(service, source=self.name):
                hidden += sum(len(group.get("spans") or ())
                              for group in batch.get("scopeSpans") or ())
                continue
            for scope_spans in batch.get("scopeSpans") or ():
                for raw in scope_spans.get("spans") or ():
                    span = self._to_span(raw, service, resource)
                    if span is not None:
                        spans.append(span)

        if not spans:
            # Either no such trace, or every span filtered out by the scope.
            # Reported as absence rather than an empty trace: an empty
            # waterfall reads as "this request did nothing".
            return None
        return Trace(trace_id=trace_id, spans=spans, hidden=hidden)

    def _to_span(self, raw, service, resource):
        span_id = _hex_id(raw.get("spanId"))
        trace_id = _hex_id(raw.get("traceId"))
        if not span_id or not trace_id:
            return None

        start = _nanoseconds_to_datetime(raw.get("startTimeUnixNano"))
        end = _nanoseconds_to_datetime(raw.get("endTimeUnixNano"))
        duration_us = 0
        if start and end:
            duration_us = max(0, int((end - start).total_seconds() * 1_000_000))

        status = (raw.get("status") or {}).get("code")
        kind = str(raw.get("kind") or "")

        return Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=_hex_id(raw.get("parentSpanId")) or None,
            name=raw.get("name") or "",
            service=service,
            start=start,
            duration_us=duration_us,
            status=_STATUS_BY_CODE.get(status, STATUS_UNSET),
            # "SPAN_KIND_SERVER" -> "SERVER", so the neutral model does not
            # carry one backend's prefix.
            kind=kind.replace("SPAN_KIND_", "") or "INTERNAL",
            attributes=_attributes(raw.get("attributes")),
            resource=resource,
            ref=SourceRef(self.backend, self.name, span_id),
            source=self.name,
        )

    # ---------- search ----------

    def _selectable(self, query, scope):
        """The services a search may choose traces by, or None for all.

        TraceQL evaluates every condition inside one `{ }` on ONE span. So
        the service names have to sit beside the other conditions: `status =
        error` alone matched the error of a service the role cannot see, and
        the trace came back — listed as error-free, because its counts are
        of the visible services — in exactly the errors-only list. The same
        went for a duration and an operation name.

        A service asked for by name is checked here, against this source's
        rules. It was pushed as it came, and the route allows it when ANY
        source does, so a merged view listed the Tempo traces a service ran
        in where a rule excluded it in Tempo alone.

        Patterns are resolved to names through Tempo's own list rather than
        translated into a regular expression, which would be a second
        pattern language. Loki does the same with label values.
        """
        wanted = getattr(query, "service", None)
        if wanted:
            allowed = scope.allows_service(wanted, source=self.name)
            return [wanted] if allowed else []
        if not patterns.narrows(scope.services, self.name, scope.sources):
            return None
        allow, _ = patterns.partition(
            patterns.for_source(scope.services, self.name, scope.sources))
        if not any("*" in name for name in allow):
            # Exact grants: nothing else can be allowed, and the check
            # applies every exclusion.
            return sorted({name for name in allow
                           if scope.allows_service(name, source=self.name)})
        return self._service_names(scope, getattr(query, "window", None))

    def _traceql(self, query, names):
        """The neutral query as TraceQL, choosing only by `names` (None: any).

        Every clause is pushed into the query rather than applied afterwards.
        A limit applied by Tempo has already chosen its traces, so filtering
        later returns a short page of the wrong ones — and for the scope it
        would leak which services exist by returning fewer rows.
        """
        clauses = []

        if names is not None:
            rendered = " || ".join(
                f"{SERVICE_ATTRIBUTE} = {_quote(name)}" for name in names)
            clauses.append(f"({rendered})" if len(names) > 1 else rendered)

        if getattr(query, "name", None):
            clauses.append(f"name = {_quote(query.name)}")
        if getattr(query, "only_errors", False):
            clauses.append("status = error")
        if getattr(query, "min_duration_us", None):
            clauses.append(f"duration > {int(query.min_duration_us)}us")

        return "{ " + " && ".join(clauses) + " }" if clauses else "{}"

    def search(self, query, scope):
        # The TRACE side's emptiness. This asked `is_empty`, which is about
        # log containers: a role with trace stores and no log index — a
        # trace-only role — got an empty page from Tempo and no error.
        if not self._granted(scope) or scope.services == ():
            return PartialList()
        names = self._selectable(query, scope)
        if names == []:
            return PartialList()

        from ..query import SORT_SLOWEST, sample_for_ranking

        asked = getattr(query, "limit", 20) or 20
        ranking = getattr(query, "sort", None) == SORT_SLOWEST
        # Tempo answers newest-first and takes no sort parameter, so the
        # ranking below happens over whatever came back. Pull a larger pool
        # when the caller wants the slowest — and say, on the answer, that
        # it is a pool.
        reach = sample_for_ranking(asked) if ranking else asked
        params = {"q": self._traceql(query, names),
                  "limit": reach,
                  # The matched spans are how a row whose root is hidden is
                  # timed; three, the default, is a guess at a service's
                  # extent rather than a measurement of it.
                  "spss": SPANS_PER_SET}
        window = getattr(query, "window", None)
        if window is not None:
            # Seconds. Nanoseconds here are silently accepted and match
            # nothing, which is an empty page with no error.
            params["start"] = int(window.start.timestamp())
            params["end"] = int(window.end.timestamp())

        # Not swallowed, whether TraceQL refused the query or Tempo could not
        # be reached: an empty list reads as "no traces match".
        body = self._get("/api/search", params) or {}

        summaries = []
        only_errors = getattr(query, "only_errors", False)
        for entry in body.get("traces") or ():
            summary = self._to_summary(entry, scope)
            # The query already chooses by visible errors; this holds if
            # Tempo ever answers with a trace whose only error is hidden.
            if summary is not None and not (only_errors and not summary.has_error):
                summaries.append(summary)

        if ranking:
            summaries.sort(key=lambda s: s.duration_us, reverse=True)
        else:
            summaries.sort(key=lambda s: s.start or datetime.min.replace(
                tzinfo=timezone.utc), reverse=True)

        # A full pool means there were more traces than the pool, so the
        # slowest of the window may not be in it. Said only then: a pool
        # that came back short IS the window, and a caveat on every list is
        # one nobody reads.
        notes = []
        if ranking and len(summaries) >= reach:
            notes.append(
                f"Tempo cannot rank by duration, so these are the slowest of "
                f"the {reach} most recent traces in this window, not of the "
                f"window. Narrow the range or the service to make the two "
                f"the same.")
        return PartialList(summaries[:asked], notes=notes)

    def _to_summary(self, entry, scope):
        """One row, told only through the services this scope may see.

        It dropped every trace whose ROOT service was out of scope — after
        TraceQL had already chosen the trace for a service that was in it.
        A role allowed `billing-api` saw nothing for the calls that entered
        through a gateway it may not see, which is most of them. The trace
        is kept when any of its services is allowed, and described by one of
        those: the root's name and operation are not shown when the root is
        not, and the counts are of the allowed services' spans.
        """
        root = entry.get("rootServiceName") or ""
        # `serviceStats` is per trace, per service: {svc: {spanCount,
        # errorCount}}. It is what makes the error flag and the span count
        # free here — Jaeger has to fetch the whole trace to know either.
        stats = {name: row for name, row
                 in (entry.get("serviceStats") or {}).items()
                 if scope.allows_service(name, source=self.name)}
        root_allowed = scope.allows_service(root, source=self.name)
        if not root_allowed and not stats:
            return None
        service = root if root_allowed else sorted(stats)[0]
        span_count = sum(int(row.get("spanCount") or 0)
                         for row in stats.values()) or None
        has_error = any(int(row.get("errorCount") or 0) > 0
                        for row in stats.values())

        # The trace's own start and `durationMs` are the root's, which is
        # the hidden service's timing when the root is hidden: the list said
        # 120 ms for a trace whose visible part took 80, and ranked
        # "slowest" by it. The spans Tempo matched are the visible ones —
        # the query chose by visible services only — so they are timed.
        start = _nanoseconds_to_datetime(entry.get("startTimeUnixNano"))
        # `durationMs` is the whole trace, and the neutral model is in
        # microseconds.
        duration_us = int(entry.get("durationMs") or 0) * 1000
        if not root_allowed:
            start, duration_us = _extent(entry)

        return TraceSummary(
            trace_id=entry.get("traceID") or "",
            service=service,
            name=(entry.get("rootTraceName") or "") if root_allowed else "",
            start=start,
            duration_us=duration_us,
            has_error=has_error,
            span_count=span_count,
            source=self.name,
        )
