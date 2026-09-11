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
    source with no trace index yet, or one whose index list could not be
    read — the Elasticsearch catalogue answers [] then rather than raising —
    told an administrator their role was the problem, and sent them to edit
    roles during an outage.

    Asked only after an empty answer, so a source whose store list costs a
    round trip pays it when there is something to explain.
    """
    try:
        return (not source.containers(scope)
                and bool(source.containers(Scope.unrestricted())))
    except Exception:
        return False


def _traces(name=None, default_to_all=False):
    """The trace source a request reads from, or None when none is configured.

    `source=*` fans out across everything. An unknown name is an error rather
    than a silent fall back to the default: quietly answering from a different
    store is how somebody concludes a trace does not exist.

    `default_to_all` is for looking up a trace BY ID. A trace id is globally
    unique and nobody pasting one knows which backend holds it — answering
    from whichever source happens to be first produced "Trace not found in the
    selected time range" for a trace that was sitting in the next store along.
    """
    hub = getattr(current_app, "hub", None)
    if hub is None:
        return None
    if not name:
        return hub.traces(hub.ALL_SOURCES if default_to_all else None)
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
        })

    return jsonify({
        "services": [s.to_dict() for s in services],
        "window": {"start": window.start.isoformat(), "end": window.end.isoformat()},
        "total_spans": sum(s.span_count for s in services),
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
    trace_source = (_traces(_requested_source(), default_to_all=True)
                    if hub else None)
    log_source = hub.logs() if hub else None
    if not trace_source or not log_source:
        return jsonify({"records": [], "error_type": "no_source"}), 503

    scope = _scope()
    window = TimeWindow.of(request.args.get("time_range", DEFAULT_RANGE))
    trace = trace_source.trace(trace_id, window, scope)
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
                        "suggestion": NO_STORE_SUGGESTION.format(source=source.name)})

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
                    "service": service, "sort": sort})


@trace_bp.route("/api/traces/<trace_id>")
@login_required
def api_trace(trace_id):
    if not current_user.has_permission("traces:read"):
        return _denied()

    try:
        # By id, so look everywhere unless a source was named. A trace id is
        # globally unique; answering from whichever source happens to be
        # first reported a Jaeger trace as missing because the default source
        # was Elasticsearch.
        source = _traces(_requested_source(), default_to_all=True)
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
