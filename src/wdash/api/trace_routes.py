"""
Trace endpoints.

These routes talk to the hub rather than to Elasticsearch. Nothing
Elasticsearch-specific appears here — only the neutral model.

Authorization has two stages:
  1. the `traces:read` permission -> access to the feature
  2. the Scope                    -> which stores and services are visible

Scope is a required parameter on the hub interface, so it cannot be forgotten.
"""

from datetime import timedelta

from flask import (
    Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required

from .access import request_scope
from ..hub import LogQuery, Scope, SourceRef, TimeWindow, TraceQuery, patterns
from ..hub.query import SORT_RECENT, SORT_SLOWEST
from ..hub.source import Capability

trace_bp = Blueprint("traces", __name__)

DEFAULT_RANGE = "24h"

#: What the services table offers. The same ladder the monitor detail page
#: offers, so two screens do not disagree about what "last hour" is called.
SERVICE_RANGES = (("15m", "last 15m"), ("1h", "last 1h"), ("6h", "last 6h"),
                  ("24h", "last 24h"), ("7d", "last 7d"))


def _reason(exc):
    """What went wrong, in the source's words, for the page."""
    return str(exc) or type(exc).__name__


def _scope():
    return request_scope()


def _denied(message="Access denied: you do not have permission to view traces."):
    return jsonify({"error": message, "error_type": "permission_denied"}), 403


class TraceSourceMissing(RuntimeError):
    """A request names a trace source that is not configured."""


def _may_see_service(scope, source, service):
    """Whether any source behind this request may show `service`.

    Asked of each source by its name, so a rule written for one source
    counts there and nowhere else; a merged view asks every member, and each
    adapter still applies the rule to its own spans.
    """
    return any(scope.allows_service(service, source=member.name)
               for member in _members(source))


def _members(source):
    return getattr(source, "sources", None) or [source]


def _completeness(answer):
    """Whether an answer is short of what was asked, and what it is missing.

    Sent on every answer, so a page can tell "these are all the traces" from
    "these are the traces the stores that answered hold".
    """
    return {"partial": bool(getattr(answer, "partial", False)),
            "warnings": list(getattr(answer, "warnings", ()) or ()),
            # Not a failure: what the answer IS, when that is narrower than
            # the control that asked for it. A whole list can still be the
            # slowest of one page rather than of the window.
            "notes": list(getattr(answer, "notes", ()) or ())}


def _services_narrowed(scope, sources):
    """Whether the service rules hide anything in any of these sources.

    For the page, before a trace is open. A trace says for itself whether
    spans were hidden (`Trace.hidden`), because a rule that could hide some
    and did are different claims.
    """
    return any(patterns.narrows(scope.services, source.name, scope.sources)
               for source in sources)


NO_STORES_ASSIGNED = ("Your role has no trace stores assigned. Ask an "
                      "administrator to give the role trace stores.")

NO_STORE_SUGGESTION = ("Your role reaches no trace store in {source}. Trace stores "
                       "are matched against index names in Elasticsearch and "
                       "against the source's own name in Tempo and Jaeger.")


def _reaches_no_store(source, scope):
    """An empty answer that is the role's doing, not the time range's.

    Only when the source HAS stores and this role reaches none of them. A
    source with no trace index yet told an administrator their role was the
    problem, and sent them to edit roles during an outage. A store list that
    could not be read is the other half: the Elasticsearch catalogue raises
    then, and the except branch below is what keeps an outage from being
    reported as the role's doing.

    Asked only after an empty answer, so a source whose store list costs a
    round trip pays it when there is something to explain.
    """
    try:
        return (not source.containers(scope)
                and bool(source.containers(Scope.unrestricted())))
    except Exception:
        return False


def _traces(name=None):
    """The trace source a request reads from, or None when none is configured.

    `source=*` and no source at all both mean every source. A trace id is
    globally unique and nobody pasting one knows which backend holds it, so a
    lookup by id has always fanned out; a service list or a search that named
    nothing used to read whichever source was registered first, and answered
    "Trace not found in the selected time range" for a trace sitting in the
    next store along. An unknown name is an error rather than a silent fall
    back to the rest: quietly answering from a different store is how
    somebody concludes a trace does not exist.
    """
    hub = getattr(current_app, "hub", None)
    if hub is None:
        return None
    if not name:
        return hub.traces()
    try:
        return hub.traces(name)
    except KeyError:
        raise TraceSourceMissing(f"There is no trace source called '{name}'.")


def _requested_source():
    return request.args.get("source") or None


def _trace_source_choices():
    """What the picker offers, or [] when there is nothing to pick."""
    hub = getattr(current_app, "hub", None)
    sources = hub.trace_sources if hub else []
    if len(sources) < 2:
        return []
    return [{"value": hub.ALL_SOURCES, "label": "All sources"}] + [
        {"value": source.name, "label": source.name} for source in sources]


def _multiple_trace_sources():
    hub = getattr(current_app, "hub", None)
    return len(hub.trace_sources) > 1 if hub else False


@trace_bp.route("/traces")
@login_required
def traces_page():
    if not current_user.has_permission("traces:read"):
        flash("Access denied: you do not have permission to view traces.", "error")
        return redirect(url_for("index"))

    hub = getattr(current_app, "hub", None)
    return render_template(
        "traces.html",
        user_role=current_user.role,
        # Showing the scope in the UI explains why some services are missing —
        # silent filtering is confusing.
        allowed_services=list(getattr(current_user, "allowed_services", []) or []),
        # Whether to say so. The template asked whether any rule was other
        # than `*`, so `*` beside `api-*` said spans were hidden when none
        # could be.
        services_narrowed=_services_narrowed(
            _scope(), hub.trace_sources if hub else []),
        default_range=DEFAULT_RANGE,
        source_choices=_trace_source_choices(),
    )


#: The shape of a row's three sparklines. Narrow because there are three of
#: them per row and a hundred rows: wider is a payload rather than a reading.
SPARK_WIDTH, SPARK_HEIGHT = 110, 26


def _spark(values):
    """A polyline over `values`, or None when there is nothing to draw.

    Server-rendered SVG, for the reason the monitor listing already gives:
    three hundred of these on a page would be three hundred canvases with
    three hundred redraw loops to draw shapes that never change. This is a
    string per sparkline and no JavaScript, which also means it survives a
    page with a strict CSP.

    None rather than a flat line when every value is zero or missing: an
    empty box reads as a measurement of nothing, and a line along the
    bottom reads as a measurement of zero, and only one of those is ever
    what happened.
    """
    usable = [v for v in values if v is not None]
    if len(usable) < 2 or not any(usable):
        return None
    highest = max(usable) or 1.0
    step = SPARK_WIDTH / max(1, len(values) - 1)
    span = SPARK_HEIGHT - 4
    runs, current = [], []
    for index, value in enumerate(values):
        if value is None:
            if len(current) > 1:
                runs.append(current)
            current = []
            continue
        x = round(index * step, 1)
        y = round(2 + span * (1 - value / highest), 1)
        current.append(f"{x},{y}")
    if len(current) > 1:
        runs.append(current)
    if not runs:
        return None
    return {"width": SPARK_WIDTH, "height": SPARK_HEIGHT,
            "runs": [" ".join(run) for run in runs], "peak": round(highest, 1)}


def _service_row(row):
    """One service as the table draws it.

    The three sparklines are built from the SAME slices, so a spike in one
    is at the same x as the dip in another — which is most of why they are
    beside each other rather than on three charts.
    """
    series = list(row.series)
    minutes = max(1e-9, (row.window_seconds / 60.0) / max(1, len(series)))
    return {
        "name": row.name,
        "environment": row.environment,
        "latency_ms": row.latency_ms,
        "per_minute": row.per_minute,
        "calls": row.calls,
        "failed": row.failed,
        "failed_ratio": row.failed_ratio,
        "latency_spark": _spark([p.latency_ms for p in series]),
        # Per minute in each slice, not the raw count: the number beside it
        # is a rate, and a sparkline on a different unit than its number is
        # two readings of one thing.
        "throughput_spark": _spark([p.calls / minutes for p in series]),
        # A share, so a service with ten calls and one failure reads as high
        # as a service with ten thousand and a thousand — which is what a
        # failure RATE means, and why the count is in the tooltip.
        "failed_spark": _spark([(p.failed / p.calls) if p.calls else None
                                for p in series]),
    }


@trace_bp.route("/services")
@login_required
def services_page():
    """One row per service: how fast, how much, how much of it failed.

    Its own page rather than a strip above the trace search. The two are
    asked at different moments — "which service is unwell" before "show me
    that request" — and one time picker cannot serve both without the
    search's query narrowing the table that is supposed to be the overview.
    """
    if not current_user.has_permission("traces:read"):
        flash("Access denied: you do not have permission to view traces.",
              "error")
        return redirect(url_for("index"))

    hub = getattr(current_app, "hub", None)
    window_label = request.args.get("window") or DEFAULT_RANGE
    source_name = request.args.get("source") or None
    rows, error, measured_by, blind = [], None, [], []

    sources = list(hub.trace_sources) if hub else []
    for source in sources:
        (measured_by if source.supports(Capability.SERVICE_METRICS)
         else blind).append(source.name)

    if sources and measured_by:
        try:
            source = hub.traces(source_name or hub.ALL_SOURCES)
            found = source.service_metrics(TimeWindow.of(window_label),
                                           _scope())
            rows = [_service_row(row) for row in found]
            warnings = list(getattr(found, "warnings", ()) or ())
        except Exception as exc:
            error, warnings = _reason(exc), []
    else:
        warnings = []

    return render_template(
        "services.html",
        rows=rows,
        error=error,
        warnings=warnings,
        window=window_label,
        ranges=SERVICE_RANGES,
        # Which sources this table is made of, and which were left out of
        # it. Named rather than counted: "1 source cannot measure services"
        # is a sentence nobody can act on.
        measured_by=measured_by,
        blind=blind,
        source_choices=_trace_source_choices(),
        source=source_name,
    )


@trace_bp.route("/api/traces/services")
@login_required
def api_services():
    if not current_user.has_permission("traces:read"):
        return _denied()

    try:
        source = _traces(_requested_source())
    except TraceSourceMissing as exc:
        return jsonify({"error": str(exc),
                        "error_type": "source_missing"}), 400
    if not source:
        return jsonify({"error": "No trace source configured.",
                        "error_type": "no_trace_source"}), 503

    scope = _scope()
    if scope.trace_is_empty:
        return jsonify({
            "services": [],
            "error_type": "no_accessible_trace_stores",
            "suggestion": NO_STORES_ASSIGNED,
        })

    window = TimeWindow.of(request.args.get("time_range", DEFAULT_RANGE))
    try:
        services = source.services(window, scope)
    except Exception as exc:
        current_app.logger.error(f"Trace services failed: {exc}")
        return jsonify({"error": "Unable to load services.",
                        "error_type": "trace_source_error", "details": str(exc)}), 503

    if not services and _reaches_no_store(source, scope):
        return jsonify({
            "services": [],
            "error_type": "no_accessible_trace_stores",
            "suggestion": NO_STORE_SUGGESTION.format(source=source.name),
            **_completeness(services),
        })

    return jsonify({
        "services": [s.to_dict() for s in services],
        "window": {"start": window.start.isoformat(), "end": window.end.isoformat()},
        "total_spans": sum(s.span_count for s in services),
        **_completeness(services),
    })


@trace_bp.route("/traces/<trace_id>")
@login_required
def trace_page(trace_id):
    """A trace gets its own page.

    In a side panel a waterfall competes for width with the list next to it,
    and there is no room for the things that make a trace worth opening: where
    the time went, and which log records belong to it.
    """
    if not current_user.has_permission("traces:read"):
        flash("Access denied: you do not have permission to view traces.", "error")
        return redirect(url_for("index"))

    return render_template(
        "trace_detail.html",
        trace_id=trace_id,
        user_role=current_user.role,
        time_range=request.args.get("time_range", DEFAULT_RANGE),
        can_read_logs=current_user.has_permission("logs:read"),
    )


@trace_bp.route("/api/traces/<trace_id>/logs")
@login_required
def api_trace_logs(trace_id):
    """Log records belonging to this trace.

    The search window is derived from the trace's own span times rather than
    the UI time range: a trace found in a 30-day window should not make us scan
    30 days of logs to find its handful of records.
    """
    if not (current_user.has_permission("traces:read")
            and current_user.has_permission("logs:read")):
        return _denied("You need both traces:read and logs:read.")

    hub = getattr(current_app, "hub", None)
    trace_source = _traces(_requested_source()) if hub else None
    # Every log source: the records of a trace found in one trace store may
    # sit in any log store, and the merged search is the one that finds
    # them wherever they are.
    log_source = hub.logs() if hub else None
    if not trace_source or not log_source:
        return jsonify({"records": [], "error_type": "no_source"}), 503

    scope = _scope()
    window = TimeWindow.of(request.args.get("time_range", DEFAULT_RANGE))
    # A trace that cannot be looked for is not a trace that is not there. This
    # call sat outside any try while the Elasticsearch catalogue answered []
    # for a cluster it could not reach; now that it raises, an outage made
    # this panel answer 500 and an HTML error page to a client reading JSON.
    try:
        trace = trace_source.trace(trace_id, window, scope)
    except Exception as exc:
        current_app.logger.error(f"Trace lookup for correlated logs failed: {exc}")
        return jsonify({"records": [], "error": "Unable to load the trace.",
                        "error_type": "trace_source_error",
                        "details": str(exc)}), 503
    if trace is None or not trace.spans:
        return jsonify({"records": [], "error_type": "trace_not_found"}), 404

    starts = [s.start for s in trace.spans if s.start]
    if not starts:
        return jsonify({"records": []})

    # A minute of slack on each side: log timestamps and span timestamps come
    # from different clocks and rarely line up exactly.
    slack = timedelta(minutes=1)
    span = timedelta(microseconds=trace.duration_us or 0)
    log_window = TimeWindow.exact(min(starts) - slack, max(starts) + span + slack)

    try:
        page = log_source.search(
            LogQuery(window=log_window, text=f'trace_id:"{trace_id}"',
                     limit=100, fields=None),
            scope)
    except Exception as exc:
        current_app.logger.error(f"Correlated log lookup failed: {exc}")
        return jsonify({"records": [], "error_type": "log_source_error",
                        "details": str(exc)}), 503

    return jsonify({
        "records": [r.to_dict() for r in page.records],
        "total": page.total,
        "window": {"start": log_window.start.isoformat(),
                   "end": log_window.end.isoformat()},
        # A log source turns a failed search into a page marked partial with
        # the reason. Dropped here, the page read the failure as "no record
        # carries this trace id" and blamed a missing field.
        **_completeness(page),
    })


@trace_bp.route("/api/traces")
@login_required
def api_search_traces():
    """List traces, optionally narrowed to one service.

    This is what makes the trace page usable: without it a user would have to
    already know a trace id to look anything up.
    """
    if not current_user.has_permission("traces:read"):
        return _denied()

    try:
        source = _traces(_requested_source())
    except TraceSourceMissing as exc:
        return jsonify({"error": str(exc),
                        "error_type": "source_missing"}), 400
    if not source:
        return jsonify({"error": "No trace source configured.",
                        "error_type": "no_trace_source"}), 503

    scope = _scope()
    if scope.trace_is_empty:
        return jsonify({
            "traces": [], "error_type": "no_accessible_trace_stores",
            # The trace list said "No traces match." here, beside a service
            # list that explained itself.
            "suggestion": NO_STORES_ASSIGNED})

    service = request.args.get("service") or None
    if service and not _may_see_service(scope, source, service):
        return _denied("Your role cannot see traces for that service.")

    sort = request.args.get("sort", SORT_RECENT)
    if sort not in (SORT_RECENT, SORT_SLOWEST):
        sort = SORT_RECENT

    try:
        limit = min(int(request.args.get("limit", 25)), 100)
    except ValueError:
        limit = 25

    query = TraceQuery(
        window=TimeWindow.of(request.args.get("time_range", DEFAULT_RANGE)),
        service=service,
        only_errors=request.args.get("errors") == "1",
        sort=sort,
        limit=limit,
    )

    try:
        traces = source.search(query, scope)
    except NotImplementedError:
        return jsonify({"error": "This trace source does not support search.",
                        "error_type": "unsupported"}), 501
    except Exception as exc:
        current_app.logger.error(f"Trace search failed: {exc}")
        return jsonify({"error": "Unable to search traces.",
                        "error_type": "trace_source_error", "details": str(exc)}), 503

    if not traces and _reaches_no_store(source, scope):
        return jsonify({"traces": [], "error_type": "no_accessible_trace_stores",
                        "suggestion": NO_STORE_SUGGESTION.format(source=source.name),
                        **_completeness(traces)})

    # The fan-out stamps this; a single source does not know it is being
    # asked by name. Filled in here so "which store answered" is answerable
    # whichever way the question was asked.
    for summary in traces:
        if getattr(summary, "source", None) is None:
            summary.source = source.name

    return jsonify({"traces": [t.to_dict() for t in traces],
                    # Whether the client should show which source answered.
                    # With one source the badge is noise on every row; with
                    # two it is the difference between "this trace is missing"
                    # and "you are looking at the wrong store".
                    "multiple_sources": _multiple_trace_sources(),
                    "source": _requested_source(),
                    "service": service, "sort": sort,
                    **_completeness(traces)})


@trace_bp.route("/api/traces/<trace_id>")
@login_required
def api_trace(trace_id):
    if not current_user.has_permission("traces:read"):
        return _denied()

    try:
        # By id, so look everywhere unless a source was named: a trace id is
        # globally unique, and the store that holds it is the one thing the
        # person pasting it does not know.
        source = _traces(_requested_source())
    except TraceSourceMissing as exc:
        return jsonify({"error": str(exc),
                        "error_type": "source_missing"}), 400
    if not source:
        return jsonify({"error": "No trace source configured.",
                        "error_type": "no_trace_source"}), 503

    scope = _scope()
    if scope.trace_is_empty:
        return _denied("Your role has no trace stores assigned.")

    window = TimeWindow.of(request.args.get("time_range", DEFAULT_RANGE))
    try:
        trace = source.trace(trace_id, window, scope)
    except Exception as exc:
        current_app.logger.error(f"Trace lookup failed for {trace_id}: {exc}")
        return jsonify({"error": "Unable to load trace.",
                        "error_type": "trace_source_error", "details": str(exc)}), 503

    if trace is None:
        return jsonify({
            "error": "Trace not found in the selected time range.",
            "error_type": "trace_not_found",
            "trace_id": trace_id,
            "suggestion": "Widen the time range, or check whether your role can see "
                          "the services in this trace.",
        }), 404

    payload = trace.to_dict()
    # Flatten the waterfall server-side so the hierarchy logic lives in one
    # place instead of being reimplemented by every client.
    # Depth and self time are structural facts about the trace, so they are
    # computed once here rather than in every client.
    payload["waterfall"] = [
        {"span_id": span.span_id, "depth": depth,
         "self_time_us": trace.self_time_us(span)}
        for span, depth in trace.waterfall()
    ]
    payload["service_breakdown"] = trace.service_breakdown()
    # Spans may have been dropped by the scope — tell the user.
    payload["scoped"] = trace.hidden > 0
    return jsonify(payload)


@trace_bp.route("/api/traces/capabilities")
@login_required
def api_capabilities():
    """What the backend supports, so the UI does not offer missing features."""
    if not current_user.has_permission("traces:read"):
        return _denied()

    try:
        source = _traces(_requested_source())
    except TraceSourceMissing as exc:
        return jsonify({"error": str(exc),
                        "error_type": "source_missing"}), 400
    if not source:
        return jsonify({"available": False, "capabilities": []})

    healthy, detail = source.health()
    return jsonify({
        "available": True,
        "source": source.name,
        "backend": source.backend,
        "healthy": healthy,
        "detail": detail,
        "capabilities": sorted(source.capabilities),
        "supports_search": source.supports(Capability.TRACE_SEARCH),
    })
