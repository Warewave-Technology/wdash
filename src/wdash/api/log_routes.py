"""
Log endpoints.

The wire format is the neutral model: `records` / `body` / `severity` /
`resource` / `attributes`. Elasticsearch's `hits` and `_source` shape no longer
appears on the wire; it stays inside the adapter.

A record handle is a token in the `ref` field (`backend:container:id`). The web
client takes the container and the id from it for the record, raw and context
views — `/api/log/<container>/<id>` — and sends the record's own `source` as
`?source=`; it never needs to know which backend the record came from.

The one deliberate exception is `/api/log/<index>/<id>/raw`, which returns the
stored document in the backend's own shape. It is a diagnostic tool, gated
behind a declared capability, and nothing in WDash branches on what it returns.
"""

import json

from flask import (
    Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required

from .access import request_scope
from ..hub import Capability, LogQuery, Scope, SourceRef, TimeWindow
from ..hub.query_language import QueryError
from ..hub.query import DEFAULT_LOG_FIELDS
from ..utils import timerange

log_bp = Blueprint("logs", __name__)


def _logs(name=None):
    """The log source a request reads from.

    `source=*` fans out across everything. Without a name the default source is
    used, so a deployment that has always had one behaves exactly as it did.
    An unknown name is an error rather than a silent fall back to the default:
    quietly answering from a different store is how somebody concludes their
    data has disappeared.
    """
    hub = getattr(current_app, "hub", None)
    if hub is None:
        return None
    if not name:
        return hub.logs()
    try:
        return hub.logs(name)
    except KeyError:
        raise SourceMissing(f"There is no log source called '{name}'.")


class SourceMissing(RuntimeError):
    """A request names a source that is not configured."""


def _record_source():
    """The one source a single record lives in.

    Every record on the list carries the name of the source that answered
    it, and the detail, raw and context views pass it back as `source=`.
    They used to ask the DEFAULT source whatever the record's origin, with a
    hard-coded `elasticsearch` handle, and check the container without
    saying which source it was in — so a record from a second source opened
    as "not found" or as somebody else's document, and a role's
    source-qualified rules were not consulted at all.

    Without a name — an older link, a client that never sent one — the
    default source, as before. `*` is refused: one record lives in one place,
    and an id asked of every backend means something different in each.
    """
    hub = getattr(current_app, "hub", None)
    name = request.args.get("source") or None
    if hub is not None and name == hub.ALL_SOURCES:
        raise SourceMissing("A single record lives in one source; name it "
                            "rather than asking all of them.")
    return _logs(name)


def _record_refused(scope, source, index):
    """The 403 for a container this scope may not read in this source."""
    if scope.allows_container(index, source=source.name):
        return None
    return jsonify({"error": "Access denied to this index",
                    "error_type": "index_access_denied"}), 403


def _unreachable(source, exc):
    """The 503 for a record view whose source could not be asked.

    A record that cannot be looked for is not a record that is not there:
    with the index list unreadable these came back as 500s, or, before the
    list raised, as "Record not found".
    """
    current_app.logger.error(f"Record lookup in {source.name} failed: {exc}")
    return jsonify({"error": f"{source.name} could not be read: {exc}",
                    "error_type": "backend_error"}), 503


NO_SOURCE = ({"error": "No log source is configured.",
              "error_type": "no_source",
              "suggestion": "Add a source on the configuration page."}, 503)


def _no_source():
    """The answer when there is no log source at all.

    Distinct from "the source is down", which is a 503 an operator responds to
    by fixing something. This one is answered on the configuration page.
    """
    body, status = NO_SOURCE
    return jsonify(body), status


def _source_choices():
    """What the source picker offers, or [] when there is nothing to pick."""
    hub = getattr(current_app, "hub", None)
    sources = hub.log_sources if hub else []
    if len(sources) < 2:
        return []
    return [{"value": hub.ALL_SOURCES, "label": "All sources"}] + [
        {"value": source.name, "label": source.name} for source in sources]


def _scope():
    return request_scope()


def _source_count():
    hub = getattr(current_app, "hub", None)
    return len(hub.log_sources) if hub else 0


@log_bp.route("/logs")
@login_required
def logs_page():
    if not current_user.has_permission("logs:read"):
        flash("Access denied: You do not have permission to view logs. "
              "Please contact your administrator.", "error")
        return redirect(url_for("index"))

    # Every source, not the default one. A role granted only a second
    # source's indices was shown "No Access to Log Indices" and no form, while
    # the search API answered it from that source. The picker starts on "All
    # sources", so the page's first search asks the same question this does.
    hub = getattr(current_app, "hub", None)
    source = _logs(hub.ALL_SOURCES) if hub is not None else None
    choices = _source_choices()
    if source is None:
        # No source at all is a different thing from a source that is down,
        # and it has a different answer: add one, rather than go and fix one.
        flash("No log source is configured. Add one on the configuration "
              "page.", "warning")
        return render_template("logs.html", indices=[],
                               user_role=current_user.role, no_source=True)

    scope = _scope()
    try:
        all_indices = source.containers(Scope.unrestricted())
        allowed = source.containers(scope)
    except Exception as exc:
        current_app.logger.error(f"Error loading logs page: {exc}")
        flash(f"Unable to connect to {source.name}. Please check the "
              f"connection and try again.", "error")
        return render_template("logs.html", indices=[], user_role=current_user.role,
                               elasticsearch_error=True, source_name=source.name,
                               source_choices=choices)

    if not allowed:
        if not all_indices:
            flash("No log indices found in Elasticsearch. Please check if logs "
                  "are being ingested.", "warning")
        else:
            flash(f'Access denied: Your role "{current_user.role}" does not have '
                  f"access to any log indices. {_unreadable_named(all_indices)}",
                  "error")
        return render_template("logs.html", indices=[], user_role=current_user.role,
                               no_access=True, source_choices=choices)

    return render_template("logs.html", indices=allowed,
                           user_role=current_user.role, no_access=False,
                           source_choices=choices,
                           per_page=current_app.config.get("LOGS_PER_PAGE", 50))


def _unreadable(names):
    """What a role that reads nothing here is told about what is here.

    Names only for an administrator. They are what a boundary holds back —
    `payment-fraud-investigation` says something whether or not it can be
    opened — and the dashboards stopped naming them for that reason while
    this page and the search API went on listing another source's indices
    to any role that reached none of them. Everybody else gets a count.
    """
    if current_user.has_permission("system:admin"):
        return {"available_indices": list(names[:10]),
                "total_containers": len(names)}
    return {"total_containers": len(names)}


def _unreadable_named(names):
    shown = _unreadable(names)
    if "available_indices" not in shown:
        return f"{shown['total_containers']} exist that it cannot read."
    more = "..." if len(names) > 5 else ""
    return f"Available indices: {', '.join(names[:5])}{more}"


@log_bp.route("/api/search")
@login_required
def api_search():
    # Searching IS reading. The two used to be separate permissions, and
    # neither resulting role was usable: `logs:read` alone opened a page where
    # every search returned 403, and `logs:search` alone worked in the API
    # while the page itself refused to load.
    if not current_user.has_permission("logs:read"):
        return jsonify({"error": "Access denied: You do not have permission to "
                                 "read logs.",
                        "error_type": "permission_denied"}), 403

    try:
        source = _logs(request.args.get("source"))
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    if source is None:
        return jsonify({
            "error": "No log source is configured.",
            "error_type": "no_source",
            "suggestion": "Add a source on the configuration page."}), 503
    scope = _scope()

    try:
        size = min(int(request.args.get(
                       "size", current_app.config.get("LOGS_PER_PAGE", 50))),
                   current_app.config["MAX_SEARCH_RESULTS"])
    except ValueError as exc:
        return jsonify({"error": f"Invalid search parameters: {exc}",
                        "error_type": "invalid_parameters"}), 400

    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")

    if start_time and end_time and start_time >= end_time:
        return jsonify({"error": "Start time must be before end time.",
                        "error_type": "validation_error"}), 400

    try:
        search_after_raw = request.args.get("search_after")
        cursor = json.loads(search_after_raw) if search_after_raw else None
    except (ValueError, TypeError) as exc:
        return jsonify({"error": f"Invalid search parameters: {exc}",
                        "error_type": "invalid_parameters"}), 400

    # Resolve accessible indices first: the difference between "no indices
    # exist" and "you cannot see any" matters to the user. Done BEFORE the time
    # range check so error responses carry the index metadata too.
    try:
        all_indices = source.containers(Scope.unrestricted())
        allowed = source.containers(scope)
    except Exception as exc:
        current_app.logger.error(f"Failed to get containers from {source.name}: {exc}")
        return jsonify({"error": f"Unable to connect to {source.name}. Please "
                                 f"check the connection.",
                        "error_type": "elasticsearch_connection",
                        "details": str(exc)}), 503

    if not allowed:
        if not all_indices:
            return jsonify({"error": "No log indices found in Elasticsearch.",
                            "error_type": "no_indices",
                            "suggestion": "Please check if logs are being ingested "
                                          "into Elasticsearch."}), 404
        return jsonify({"error": f'Your role "{current_user.role}" does not have '
                                 "access to any indices.",
                        "error_type": "no_accessible_containers",
                        **_unreadable(all_indices),
                        "suggestion": "Please contact your administrator to grant "
                                      "access to log indices."}), 403

    # A time range is mandatory — we refuse to scan whole indices
    if not start_time:
        return jsonify({"records": [], "total": 0, "took_ms": 0,
                        "error": "A time range is required. Please select a time "
                                 "range before searching.",
                        "error_type": "time_range_required",
                        "accessible_containers": allowed,
                        "containers": [],
                        "user_role": current_user.role,
                        "total_accessible_containers": len(allowed)})

    parsed_start = timerange.parse_iso(start_time)
    if parsed_start is None:
        return jsonify({"error": "Invalid search parameters: unparseable start_time",
                        "error_type": "invalid_parameters"}), 400
    parsed_end = timerange.parse_iso(end_time) if end_time else None

    # NO ALIGNMENT: this query returns raw records, and widening the window
    # would change the result set. There is no cache benefit either (size > 0),
    # so the caller's bounds are preserved exactly.
    window = TimeWindow.exact(parsed_start,
                              parsed_end or timerange.now_utc())

    try:
        query = LogQuery(
            window=window,
            text=request.args.get("q", "*") or "*",
            limit=size,
            cursor=cursor,
            fields=DEFAULT_LOG_FIELDS,
            # Only on the first page: the histogram covers the whole window and
            # does not change as the user pages through it.
            histogram=(cursor is None),
        )
    except QueryError as exc:
        # Syntax error caught before the query left the process; the message is
        # detailed enough to show the user.
        return jsonify({"error": f"Invalid query syntax: {exc}",
                        "error_type": "invalid_query"}), 400

    try:
        page = source.search(query, scope)
    except Exception as exc:
        current_app.logger.error(f"Search error: {exc}")
        return jsonify({"error": "An unexpected error occurred during search.",
                        "error_type": "search_error", "details": str(exc)}), 500

    # An empty page carrying only notes is an empty result, not a failure. A
    # time range with nothing in it used to come back as a red error quoting
    # "the scope permits no streams", which reads as an access problem and
    # sends people to their administrator over a narrow time picker.
    if page.warnings and not page.records and not page.informational:
        return jsonify({"records": [], "total": 0, "took_ms": 0,
                        "error": page.warnings[0], "error_type": "search_error"})

    payload = page.to_dict()
    if not payload["sources"]:
        # Only the fan-out fills this in, because only it has more than one
        # answer to attribute. A single source still gets a row so the panel
        # has one shape rather than two.
        payload["sources"] = [{"name": source.name, "count": len(page.records),
                               "total": page.total, "failed": page.partial,
                               "exact": page.counted}]
    payload.update({
        "accessible_containers": allowed,
        "total_accessible_containers": len(allowed),
        "user_role": current_user.role,
        # Whether the client should show which source each record came from.
        # With one source the badge is noise on every row; with two it is the
        # difference between "this is missing" and "you are looking at the
        # wrong store".
        "multiple_sources": _source_count() > 1,
        "source": request.args.get("source") or None,
    })
    return jsonify(payload)


@log_bp.route("/api/log/<index>/<doc_id>")
@login_required
def api_get_log(index, doc_id):
    """Fetch one record with all its fields, for the detail view."""
    if not current_user.has_permission("logs:read"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403

    scope = _scope()
    try:
        source = _record_source()
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    if source is None:
        return _no_source()
    refused = _record_refused(scope, source, index)
    if refused:
        return refused

    try:
        record = source.fetch(SourceRef(source.backend, index, doc_id), scope)
    except Exception as exc:
        return _unreachable(source, exc)
    if record is None:
        return jsonify({"found": False, "error": "Record not found",
                        "error_type": "not_found"}), 404

    return jsonify({"found": True, "record": record.to_dict()})


@log_bp.route("/api/log/<index>/<doc_id>/raw")
@login_required
def api_get_log_raw(index, doc_id):
    """The stored document, untranslated.

    Separate from the record endpoint on purpose. `record` is the neutral model
    and is a contract; this is the backend's own shape and is explicitly NOT
    one — it exists so an operator can answer "did this field never arrive, or
    did we fail to map it?" without shelling into the cluster. It costs an
    extra request, so it is only fetched when the raw tab is actually opened.
    """
    if not current_user.has_permission("logs:read"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403

    scope = _scope()
    try:
        source = _record_source()
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    if source is None:
        return _no_source()
    refused = _record_refused(scope, source, index)
    if refused:
        return refused
    if not source.supports(Capability.RAW_DOCUMENT):
        return jsonify({"error": f"{source.name} does not expose raw documents",
                        "error_type": "unsupported"}), 501

    try:
        document = source.raw(SourceRef(source.backend, index, doc_id), scope)
    except Exception as exc:
        return _unreachable(source, exc)
    if document is None:
        return jsonify({"found": False, "error": "Record not found",
                        "error_type": "not_found"}), 404

    return jsonify({"found": True, "backend": source.backend, "document": document})


@log_bp.route("/api/log/<index>/<doc_id>/context")
@login_required
def api_log_context(index, doc_id):
    if not current_user.has_permission("logs:read"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403

    scope = _scope()
    try:
        source = _record_source()
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    if source is None:
        return _no_source()
    refused = _record_refused(scope, source, index)
    if refused:
        return refused
    if not source.supports(Capability.CONTEXT):
        return jsonify({"error": f"{source.name} cannot show the records "
                                 f"around one",
                        "error_type": "unsupported"}), 501

    try:
        count = min(int(request.args.get("count", 10)), 50)
    except ValueError:
        count = 10

    try:
        context = source.context(
            SourceRef(source.backend, index, doc_id), scope,
            before=count, after=count,
            correlate_by=request.args.get("field") or None,
        )
    except Exception as exc:
        return _unreachable(source, exc)

    if context.record is None:
        return jsonify({"found": False, "error": "Record not found",
                        "error_type": "not_found"}), 404
    if context.record.timestamp is None:
        return jsonify({"error": "Document has no timestamp",
                        "error_type": "no_timestamp"}), 400

    return jsonify(context.to_dict())


def _stats_failed(source, exc):
    """The 503 for field statistics that could not be read.

    Distinct from `{"fields": []}`, which is what a quiet window is. Both
    were answered as the second — a search that timed out and a mapping an
    account may not read alike — and the sidebar said "No field data
    available" beside a page full of results.
    """
    current_app.logger.error(f"Field statistics from {source.name} failed: {exc}")
    return jsonify({"error": f"{source.name} could not answer: {exc}",
                    "error_type": "backend_error"}), 503


@log_bp.route("/api/field-stats")
@login_required
def api_field_stats():
    if not current_user.has_permission("logs:read"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403

    # The SAME source the results came from. This read `_logs()` with no
    # argument, so the sidebar answered from the default source whatever the
    # page was showing — Elasticsearch statistics beside VictoriaLogs rows,
    # with service names that appear nowhere in the results.
    try:
        source = _logs(request.args.get("source"))
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    scope = _scope()
    if source is None:
        return _no_source()

    # Asked BEFORE the query. Loki declares no field statistics and the base
    # class raises for it — which reached the client as an HTTP 500 and an
    # empty sidebar, so a source that is working perfectly looked broken.
    #
    # A merged view is the same story for a different reason: capabilities
    # intersect, so one member without the capability removes it from the
    # whole.
    if not source.supports(Capability.FIELD_STATS):
        return jsonify({
            "fields": [],
            "unsupported": True,
            "reason": f"{source.name} does not provide field statistics.",
        })

    try:
        if not source.containers(scope):
            return jsonify({})
    except Exception as exc:
        return _stats_failed(source, exc)

    # Aligned at the server boundary: these aggregations run with
    # request_cache, and an unaligned timestamp makes every request unique.
    start_time, end_time = timerange.align_iso(
        request.args.get("start_time"), request.args.get("end_time"))

    parsed_start = timerange.parse_iso(start_time)
    parsed_end = timerange.parse_iso(end_time)
    if parsed_start is None or parsed_end is None:
        window = TimeWindow.of("1h")
    else:
        window = TimeWindow.between(parsed_start, parsed_end)

    try:
        stats = source.field_stats(
            LogQuery(window=window, text=request.args.get("q", "*") or "*"), scope)
    except QueryError:
        return jsonify({"fields": []})
    except Exception as exc:
        return _stats_failed(source, exc)

    payload = {"fields": [stat.to_dict() for stat in stats]}
    # Members of a merged view whose statistics could not be read: the
    # counts are the others', and the sidebar says whose are missing.
    failed = list(getattr(stats, "failed", ()) or ())
    if failed:
        payload["partial"] = True
        payload["failed_sources"] = failed

    # What the counts themselves are short of. Elasticsearch answers 200 when
    # only some shards fail, so these were numbers from a fraction of the
    # window drawn as the window: on the lab, 2789 per field from one shard of
    # six, beside a result list that reported the failure.
    warnings = list(getattr(stats, "warnings", ()) or ())
    if warnings:
        payload["partial"] = True
        payload["warnings"] = warnings

    # Which members of a merged view could not contribute. An answer from a
    # subset is fine; an answer from a subset that does not say so is the
    # thing the intersection rule was avoiding, and removing the feature
    # entirely was the wrong way to avoid it.
    contributors = getattr(source, "contributors", None)
    if contributors is not None:
        can, cannot = contributors(Capability.FIELD_STATS)
        if cannot:
            payload["partial"] = True
            payload["missing_sources"] = cannot
            payload["counted_sources"] = can

    return jsonify(payload)


@log_bp.route("/api/indices")
@login_required
def api_indices():
    if not current_user.has_permission("logs:read"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403
    # The source asked about, as /api/search takes it. This answered for the
    # default source whatever was named.
    try:
        source = _logs(request.args.get("source"))
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    scope = _scope()
    if source is None:
        return _no_source()
    try:
        all_indices = source.containers(Scope.unrestricted())
        allowed = source.containers(scope)
    except Exception as exc:
        current_app.logger.error(f"Error getting indices: {exc}")
        return jsonify({"error": f"Unable to retrieve containers from {source.name}.",
                        "error_type": "elasticsearch_connection",
                        "details": str(exc)}), 503

    return jsonify({"containers": allowed,
                    "total_containers": len(all_indices),
                    "accessible_containers": len(allowed),
                    "user_role": current_user.role})
