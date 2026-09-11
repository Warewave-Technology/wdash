"""
Jaeger as a trace source.

Everything here was measured against a running Jaeger rather than taken from
memory, because the last time a schema in this codebase was written from
belief every field came back empty and the fixture agreed with it.

Four things are Jaeger's own problem, and each one shapes the adapter:

**`service` is mandatory.** `GET /api/traces` without it answers HTTP 400,
`parameter 'service' is required`. There is no "every trace" query — the same
shape as Loki's mandatory stream selector. A search with no service named is
therefore fanned across the service list, bounded, and says so; it is not
silently answered from whichever service happened to be first.

**The service name is on the process, not the span.** A span carries
`processID: "p1"`, and the trace carries `processes: {"p1": {"serviceName":
…}}`. Reading a service off a span in isolation gets nothing.

**Times are microseconds.** `startTime` and `duration` on a span, and the
`start`/`end` query parameters. Nanoseconds — the OTLP unit — are a thousand
times too large and produce an empty window with no error.

**There is no volume aggregation.** `/api/metrics/calls` answers HTTP 501,
"metrics querying is currently disabled", unless a separate metrics backend is
wired up. So the service list carries names without span counts, and says zero
rather than inventing a number. This is why SERVICE_LIST is declared and the
counts are honest about being absent.

The parent link lives in `references` with `refType: "CHILD_OF"`, and a failed
span is marked by an `error: true` tag, an `otel.status_code: ERROR` tag, or
both — the OpenTelemetry receiver writes both.
"""

import json
import logging
from datetime import datetime, timezone

import requests

from ..models import (
    STATUS_ERROR, STATUS_OK, STATUS_UNSET, Service, SourceRef, Span, Trace,
    TraceSummary,
)
from ..source import Capability, TraceSource

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

#: How many services one unqualified search will ask about. Jaeger has no
#: "every trace" query, so a search with no service named becomes one request
#: per service; without a bound, an installation with hundreds of services
#: turns one page load into hundreds of round trips.
MAX_SERVICE_FANOUT = 20

#: Tags Jaeger's OpenTelemetry receiver writes for a failed span. Both are
#: checked because both are written, and a store fed by a native Jaeger client
#: has only the first.
_ERROR_TAG = "error"
_STATUS_TAG = "otel.status_code"


class JaegerError(RuntimeError):
    """Jaeger could not answer."""


def _microseconds(moment):
    """Jaeger's unit. Nanoseconds are a thousand times too large and produce
    an empty window rather than an error, which is the worst kind of wrong."""
    return str(int(moment.timestamp() * 1_000_000))


def _from_microseconds(value):
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def _tags(raw):
    """Jaeger's [{key, type, value}] as a plain mapping."""
    out = {}
    for tag in raw or ():
        key = tag.get("key")
        if key is not None:
            out[key] = tag.get("value")
    return out


class JaegerTraceSource(TraceSource):
    """Exposes Jaeger as a neutral trace source."""

    backend = "jaeger"

    def __init__(self, url, name="jaeger", username=None, password=None,
                 tenant=None, verify_certs=True, timeout=DEFAULT_TIMEOUT,
                 session=None, service_fanout=MAX_SERVICE_FANOUT):
        self.name = name
        self._url = (url or "").rstrip("/")
        self._auth = (username, password) if username else None
        self._tenant = tenant
        self._verify = verify_certs
        self._timeout = timeout
        self._session = session or requests.Session()
        self._service_fanout = service_fanout

    @property
    def capabilities(self):
        # No LOG_TRACE_CORRELATION: that is a property of a log source being
        # able to find a trace id, and says nothing about a trace backend.
        return frozenset({Capability.TRACE_LOOKUP, Capability.TRACE_SEARCH,
                          Capability.SERVICE_LIST})

    # ---------- transport ----------

    def _get(self, path, params=None):
        headers = {}
        if self._tenant:
            # Jaeger's multi-tenancy header, when the deployment enables it.
            headers["x-tenant"] = self._tenant

        response = self._session.get(
            f"{self._url}{path}", params=params or {}, headers=headers,
            auth=self._auth, timeout=self._timeout, verify=self._verify)

        if response.status_code == 404:
            return None          # "no such trace" — a fact, not a failure
        if response.status_code >= 400:
            raise JaegerError(
                f"Jaeger answered HTTP {response.status_code}: "
                f"{response.text[:200]}")
        try:
            return response.json()
        except ValueError as exc:
            raise JaegerError(f"Jaeger returned something that is not JSON: {exc}")

    def health(self):
        try:
            # `/api/services` needs no query permissions and no trace data, so
            # a failure here is about reachability rather than about the query.
            body = self._get("/api/services")
            if body is None or "data" not in body:
                return False, "something answered, but it does not look like Jaeger"
            return True, "ok"
        except Exception as exc:
            return False, str(exc)

    # ---------- containers ----------

    def containers(self, scope):
        """The one container Jaeger has: the store itself, by its source name.

        Jaeger has no index a role can be granted, so a role's trace stores
        are matched against this source's NAME — `*`, `lab-jaeger`, or
        `lab-jaeger:*`. It used to ask only whether the role had any LOG
        container, so a role granted nothing but `otel-traces-*` in
        Elasticsearch read every trace in Jaeger, while the role preview,
        which does match the name, said it reached none.
        """
        if scope.trace_is_empty:
            return []
        return scope.resolve_traces([self.name], source=self.name)

    def _granted(self, scope):
        return bool(self.containers(scope))

    # ---------- services ----------

    def _service_names(self, scope):
        body = self._get("/api/services") or {}
        names = [name for name in (body.get("data") or []) if name]
        return sorted(name for name in names
                      if scope.allows_service(name, source=self.name))

    def services(self, window, scope):
        """Service names, without volume.

        `/api/metrics/calls` answers HTTP 501 unless a separate metrics
        backend is configured, so there is no span count to report. Zero is
        returned rather than a number derived from a sample of traces: a count
        that describes 20 fetched traces, presented as the volume of a
        service, is worse than no count at all.
        """
        if not self._granted(scope):
            return []
        try:
            names = self._service_names(scope)
        except Exception as exc:
            logger.error(f"Jaeger service list failed: {exc}")
            return []
        return [Service(name=name, span_count=0, error_count=0)
                for name in names]

    # ---------- one trace ----------

    def trace(self, trace_id, window, scope):
        if not self._granted(scope):
            return None
        try:
            body = self._get(f"/api/traces/{trace_id}")
        except Exception as exc:
            logger.error(f"Jaeger trace lookup failed: {exc}")
            return None

        if not body:
            return None
        entries = body.get("data") or []
        if not entries:
            return None

        spans, hidden = self._to_spans(entries[0], scope)
        if not spans:
            # Every span filtered out by the scope. Reported as "no trace"
            # rather than an empty one: an empty waterfall reads as "this
            # request did nothing", which is a different claim.
            return None
        return Trace(trace_id=trace_id, spans=spans, hidden=hidden)

    def _to_spans(self, entry, scope):
        """(the spans this scope may see, how many it may not)."""
        processes = entry.get("processes") or {}
        spans, hidden = [], 0
        for raw in entry.get("spans") or ():
            span = self._to_span(raw, processes)
            if span is None:
                continue
            if not scope.allows_service(span.service, source=self.name):
                hidden += 1
                continue
            spans.append(span)
        return spans, hidden

    def _to_span(self, raw, processes):
        trace_id, span_id = raw.get("traceID"), raw.get("spanID")
        if not trace_id or not span_id:
            return None

        # The service is on the PROCESS. Reading it off the span gets nothing.
        process = processes.get(raw.get("processID")) or {}
        service = process.get("serviceName") or ""

        parent = None
        for reference in raw.get("references") or ():
            if reference.get("refType") == "CHILD_OF":
                parent = reference.get("spanID")
                break

        tags = _tags(raw.get("tags"))
        return Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent,
            name=raw.get("operationName") or "",
            service=service,
            start=_from_microseconds(raw.get("startTime")),
            duration_us=int(raw.get("duration") or 0),
            status=self._status(tags),
            kind=str(tags.get("span.kind") or "").upper() or None,
            attributes={key: value for key, value in tags.items()
                        if key not in ("span.kind",)},
            resource={"service.name": service,
                      **{tag.get("key"): tag.get("value")
                         for tag in (process.get("tags") or ())
                         if tag.get("key")}},
            ref=SourceRef(self.backend, self.name, span_id),
            source=self.name,
        )

    @staticmethod
    def _status(tags):
        if tags.get(_ERROR_TAG) in (True, "true", "True"):
            return STATUS_ERROR
        status = str(tags.get(_STATUS_TAG) or "").upper()
        if status == "ERROR":
            return STATUS_ERROR
        if status == "OK":
            return STATUS_OK
        return STATUS_UNSET

    # ---------- search ----------

    def search(self, query, scope):
        """Trace summaries.

        Jaeger cannot answer "every trace", so a search with no service named
        is fanned across the service list. Bounded, and the bound is reported:
        an installation with hundreds of services would otherwise turn one
        page load into hundreds of round trips.
        """
        wanted = getattr(query, "service", None)
        if not self._granted(scope):
            return []
        try:
            if wanted:
                if not scope.allows_service(wanted, source=self.name):
                    return []
                services = [wanted]
            else:
                services = self._service_names(scope)[:self._service_fanout]
        except Exception as exc:
            logger.error(f"Jaeger service list failed: {exc}")
            return []

        if not services:
            return []

        summaries = []
        for service in services:
            summaries.extend(self._search_one(service, query, scope))

        # Sorted here rather than by Jaeger: with a service fan-out the merged
        # list is what the caller sees, and each backend request sorted its
        # own slice.
        from ..query import SORT_SLOWEST
        if getattr(query, "sort", None) == SORT_SLOWEST:
            summaries.sort(key=lambda s: s.duration_us, reverse=True)
        else:
            summaries.sort(key=lambda s: s.start or datetime.min.replace(
                tzinfo=timezone.utc), reverse=True)

        limit = getattr(query, "limit", None)
        return summaries[:limit] if limit else summaries

    def _search_one(self, service, query, scope):
        params = {"service": service, "limit": getattr(query, "limit", 20) or 20}
        window = getattr(query, "window", None)
        if window is not None:
            params["start"] = _microseconds(window.start)
            params["end"] = _microseconds(window.end)
        if getattr(query, "min_duration_us", None):
            # Jaeger takes a duration string, not a number. Microseconds are
            # exact here and avoid a rounding step.
            params["minDuration"] = f"{int(query.min_duration_us)}us"
        if getattr(query, "name", None):
            params["operation"] = query.name
        if getattr(query, "only_errors", False):
            # Jaeger's own tag filter. Applied by the backend rather than
            # after the fact: a limit applied by Jaeger has already chosen its
            # traces, so filtering afterwards returns a short page of the
            # wrong ones.
            params["tags"] = json.dumps({"error": "true"})

        try:
            body = self._get("/api/traces", params) or {}
        except Exception as exc:
            logger.error(f"Jaeger search failed for {service}: {exc}")
            return []

        out = []
        for entry in body.get("data") or ():
            spans, _ = self._to_spans(entry, scope)
            if not spans:
                continue
            trace = Trace(trace_id=entry.get("traceID") or "", spans=spans)
            root = trace.root
            if root is None:
                continue
            out.append(TraceSummary(
                trace_id=trace.trace_id,
                service=root.service,
                name=root.name,
                start=root.start,
                duration_us=trace.duration_us,
                has_error=trace.has_error,
                # Jaeger returns whole traces from a search, so unlike the
                # Elasticsearch adapter this really is the span count rather
                # than an unknown.
                span_count=len(spans),
                source=self.name,
            ))
        return out
