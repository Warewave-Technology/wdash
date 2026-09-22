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

    `source=*` and no source at all both mean every source — the question
    the page's picker asks on its first search, and the one a request that
    names nothing asks now. It used to be answered from one source,
    whichever was registered first, with nothing in the answer to say so.
    An unknown name is an error rather than a silent fall back to the rest:
    quietly answering from a different store is how somebody concludes
    their data has disappeared.
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


def _public_name(source):
    """The name a request may send back to get this source again.

    A fan-out's own name is "all-sources", which no picker holds and no
    request can name; the value that means it on the wire is `*`.
    """
    hub = getattr(current_app, "hub", None)
    if _fanned_out(source) and hub is not None:
        return hub.ALL_SOURCES
    return source.name


def _fanned_out(source):
    """Whether this source is several, by the shape of its member list —
    not by the presence of the attribute, which a stand-in that answers
    every name would also have."""
    return isinstance(getattr(source, "sources", None), (list, tuple))


class SourceMissing(RuntimeError):
    """A request names a source that is not configured."""


def _search_dashboard():
    """The dashboard a search is scoped to, None, or a refusal to return.

    `?dashboard=<id>` is what a click-through from a dashboard sends. The
    dashboard is loaded and checked HERE — its own permission, its own
    visibility rule — rather than trusting a pattern list off the URL, which
    would make the query string a way around the boundary instead of a way
    into it.
    """
    dashboard_id = request.args.get("dashboard") or None
    if not dashboard_id:
        return None

    from .dashboard_routes import (UNCHECKED, VISIBLE,
                                   _load as _load_dashboard,
                                   _unreachable, _view_verdict)
    if not current_user.has_permission("dashboard:view"):
        return jsonify({"error": "Access denied: You do not have permission to "
                                 "view dashboards.",
                        "error_type": "permission_denied"}), 403
    dashboard = _load_dashboard(dashboard_id)
    if not dashboard:
        return jsonify({"error": "Dashboard not found.",
                        "error_type": "dashboard_not_found"}), 404

    verdict, failure = _view_verdict(dashboard)
    if verdict == UNCHECKED:
        # The rule would have let this through; the source could not say what
        # the dashboard reaches, so nobody knows. Answering "not found" made
        # a drill-down from a shared dashboard report an outage as an absence
        # — and the identical request without `dashboard=` answered 503 and
        # named the source, in the same second. The author's own dashboard
        # already answered 503 too, because the rule lets an author through
        # without consulting the reach at all, so the same outage said two
        # different things depending on who was clicking.
        return jsonify(_unreachable(dashboard, failure)), 503
    if verdict != VISIBLE:
        # Not there and not visible answer alike, as everywhere else: a
        # distinct "you may not see this" turns the parameter into a way to
        # find out which dashboards exist. An outage does not widen this —
        # a dashboard the rule hides is HIDDEN above whether or not the
        # source answered.
        return jsonify({"error": "Dashboard not found.",
                        "error_type": "dashboard_not_found"}), 404
    return dashboard


def _record_source():
    """The one source a single record lives in.

    Every record on the list carries the name of the source that answered
    it, and the detail, raw and context views pass it back as `source=`.
    They used to ask the DEFAULT source whatever the record's origin, with a
    hard-coded `elasticsearch` handle, and check the container without
    saying which source it was in — so a record from a second source opened
    as "not found" or as somebody else's document, and a role's
    source-qualified rules were not consulted at all.

    Without a name — an older link, a client that never sent one — the one
    source there is, when there is one. With several, every source is what
    an unnamed request means everywhere else, and for a single record that
    is refused, as `*` has always been: one record lives in one place, and
    an id asked of every backend means something different in each. It used
    to be answered from whichever source was registered first, which is the
    same record from the wrong store, said with confidence.
    """
    source = _logs(request.args.get("source") or None)
    if _fanned_out(source):
        raise SourceMissing("A single record lives in one source; name it "
                            "rather than asking all of them.")
    return source


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

    # A drill-down from a dashboard names it, and is answered inside that
    # dashboard's reach.
    #
    # It was not. A dashboard queries its own patterns ∩ the viewer's scope,
    # and the click-through sent only the query and the window — so the Logs
    # screen answered from every container the ROLE allows. Measured against
    # the lab: a dashboard over `app-logs-*`, read by a role holding
    # `*-logs-*`, counted 30,576 records over seven days, and its total card
    # opened 91,407 across five indices. Resolved here rather than trusted
    # from the URL, because a client-supplied pattern list is not a boundary.
    dashboard = _search_dashboard()
    if isinstance(dashboard, tuple):        # a refusal, already shaped
        return dashboard

    try:
        source = _logs(getattr(dashboard, "source", None) if dashboard
                       else request.args.get("source"))
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
        if dashboard is not None:
            from .dashboard_routes import _targets
            _, _, allowed = _targets(dashboard, scope)
        else:
            allowed = source.containers(scope)
    except Exception as exc:
        current_app.logger.error(f"Failed to get containers from {source.name}: {exc}")
        return jsonify({"error": f"Unable to connect to {source.name}. Please "
                                 f"check the connection.",
                        "error_type": "elasticsearch_connection",
                        # Named as a field, not only inside the sentence: the
                        # page draws its own suggestions beside this message,
                        # and it used to advise checking Elasticsearch
                        # whichever backend had gone away.
                        "source": source.name,
                        "details": str(exc)}), 503

    if not allowed:
        if not all_indices:
            return jsonify({"error": "No log indices found in Elasticsearch.",
                            "error_type": "no_indices",
                            "suggestion": "Please check if logs are being ingested "
                                          "into Elasticsearch."}), 404
        if dashboard is not None:
            # The role may well reach plenty; this dashboard's patterns reach
            # none of it, and saying "your role has no access" would be false.
            return jsonify({
                "error": f'This dashboard\'s data — {", ".join(dashboard.index_patterns)} '
                         f"— is outside your access.",
                "error_type": "no_accessible_containers",
                "dashboard": dashboard.name,
                "dashboard_id": dashboard.id,
                "suggestion": "Please contact your administrator to grant "
                              "access to this dashboard's data."}), 403
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
            # Named only for a dashboard drill-down. Without it the query runs
            # over everything the scope allows, which is what made a
            # drill-down widen the result set rather than narrow it.
            containers=tuple(allowed) if dashboard is not None else None,
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
        "source": (_public_name(source) if dashboard is not None
                   else request.args.get("source") or None),
    })
    if dashboard is not None:
        # Said on the page, because a narrowed result set that does not say it
        # is narrowed is a wrong number: the reader came here from a chart and
        # has every reason to think this is "the logs".
        payload["dashboard"] = {"id": dashboard.id, "name": dashboard.name,
                                "containers": list(allowed),
                                # Which store answered. A dashboard may be
                                # pinned to one, and this endpoint prefers it
                                # over `?source=` — while the Logs page's own
                                # picker sits on its first option and re-sends
                                # that on every later search from the page. The
                                # control said one store and the answer came
                                # from another, with nothing on screen to say
                                # so; the badge sets the picker from this. As
                                # the picker spells it: `*` for every source.
                                "source": _public_name(source)}
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


#: Where the sidebar's chosen fields live: one setting holding
#: {source name: [field, ...]}.
#:
#: One row rather than one per source, because it is read on every search
#: and a dict is one query whatever the number of sources. In `settings`
#: rather than in each source's own config, so that choosing fields does not
#: rewrite a row holding credentials and index patterns — and so a source
#: can be re-pointed without the choice following it into a cluster where
#: none of those names exist.
STATS_FIELDS_SETTING = "logs.stats_fields"

#: How many a source may be asked to count at once. Each one is a terms
#: aggregation in the same request, and the sidebar is a sidebar.
MAX_STATS_FIELDS = 40


def _chosen_stats_fields(store, source_name):
    """The fields somebody chose for this source, or () for "you decide"."""
    chosen = store.settings.get(STATS_FIELDS_SETTING) or {}
    if not isinstance(chosen, dict):
        return ()
    return tuple(chosen.get(source_name) or ())


def _gone(names):
    """What to say about chosen fields this cluster no longer maps."""
    return (f"{', '.join(sorted(names))} "
            f"{'is' if len(names) == 1 else 'are'} no longer mapped by this "
            f"source, so nothing is counted for "
            f"{'it' if len(names) == 1 else 'them'}.")


def _resolve_chosen(source, scope, chosen):
    """({shown name: path}, [names this cluster no longer has]).

    A name that has gone is NAMED rather than dropped. A mapping changes —
    an index rolls over, a source is re-pointed — and a picker that quietly
    stops showing a field somebody chose is a panel that got shorter for no
    reason anybody can see.

    Asked of `resolve_stats_fields` and not of the offer: the offer is cut
    for display, so resolving against it reported every field past the cut
    as one the cluster had lost — and the answer carries the aggregation
    PATH, which for a text field is its `keyword` sub-field rather than its
    own name.
    """
    try:
        resolved = source.resolve_stats_fields(scope, chosen)
    except NotImplementedError:
        return None, []
    return resolved, [name for name in chosen if name not in resolved]


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

    chosen = _chosen_stats_fields(current_app.store, source.name)
    missing = []
    fields = None
    if chosen:
        try:
            fields, missing = _resolve_chosen(source, scope, chosen)
        except Exception as exc:
            return _stats_failed(source, exc)
        if fields is not None and not fields:
            # Every chosen field has gone. Answering with the source's own
            # ten would look like the choice was never saved.
            return jsonify({"fields": [], "chosen": list(chosen),
                            "partial": True,
                            "warnings": [_gone(missing)]})

    try:
        stats = source.field_stats(
            LogQuery(window=window, text=request.args.get("q", "*") or "*"),
            scope, **({"fields": fields} if fields else {}))
    except QueryError:
        return jsonify({"fields": []})
    except Exception as exc:
        return _stats_failed(source, exc)

    payload = {"fields": [stat.to_dict() for stat in stats]}
    if chosen:
        payload["chosen"] = list(chosen)
    if missing:
        payload["partial"] = True
        payload.setdefault("warnings", []).append(_gone(missing))
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
        payload["warnings"] = payload.get("warnings", []) + warnings

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


@log_bp.route("/api/field-stats/fields", methods=["GET"])
@login_required
def api_stats_fields():
    """What the picker offers, and what is chosen now.

    Readable by anybody who can read logs — the list itself is the field
    NAMES of a source they are already searching — and writable below by
    an administrator, because which fields a cluster's sidebar shows is a
    property of the deployment rather than of whoever opened the page.
    """
    if not current_user.has_permission("logs:read"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403
    try:
        source = _logs(request.args.get("source"))
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    if source is None:
        return _no_source()

    chosen = list(_chosen_stats_fields(current_app.store, source.name))
    editable = current_user.has_permission("system:admin")
    if not source.supports(Capability.FIELD_STATS):
        return jsonify({"fields": [], "chosen": chosen, "editable": editable,
                        "unsupported": True,
                        "reason": f"{source.name} does not provide field "
                                  f"statistics."})
    # Searched on the SERVER when asked, because the offer is cut: a filter
    # that only narrows what was already sent cannot reach the field the cut
    # left out, which is the same failure as the sidebar's own ten-by-name
    # one level up. Measured on the lab: 439 fields, 300 offered, and
    # `kubernetes.container_name` in neither the panel nor the picker.
    wanted = (request.args.get("q") or "").strip()
    try:
        available = source.stats_fields(_scope(), matching=wanted or None)
    except NotImplementedError:
        # Answers field statistics but cannot list what it could count: a
        # picker with nothing to pick from, said as that rather than drawn
        # as an empty list.
        return jsonify({"fields": [], "chosen": chosen, "editable": editable,
                        "unsupported": True,
                        "reason": f"{source.name} does not list the fields "
                                  f"it can count."})
    except Exception as exc:
        return _stats_failed(source, exc)

    warnings = list(getattr(available, "warnings", ()) or ())
    payload = {"fields": list(available), "chosen": chosen,
               "editable": editable, "source": source.name}
    # A chosen field the mapping no longer has is still shown as chosen, so
    # unticking it is possible. Silently dropping it makes a stored choice
    # nobody can see and nobody can clear. Not while searching, though: a
    # search that always returned the chosen ones is a search whose answer
    # does not match what was asked.
    if not wanted:
        payload["fields"] = sorted(set(payload["fields"]) | set(chosen))
    if warnings:
        payload["partial"] = True
        payload["warnings"] = warnings
    return jsonify(payload)


@log_bp.route("/api/field-stats/fields", methods=["POST"])
@login_required
def api_save_stats_fields():
    """Choose which fields the sidebar counts for one source.

    `system:admin`, like every other thing that changes what a source does.
    An empty list means "you decide" and removes the entry rather than
    storing an empty one, so that a cleared choice and a never-made one are
    the same state instead of two that behave differently.
    """
    if not current_user.has_permission("system:admin"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403
    body = request.get_json(silent=True) or {}
    # Resolved, not taken from the body. A page showing ONE source renders
    # no source select, so the body names none — and the first version
    # refused that with "No source named." on the commonest installation
    # there is. `_logs` answers the default source for an empty name, which
    # is what every read on this page already does.
    try:
        source = _logs((body.get("source") or "").strip())
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    if source is None:
        return jsonify({"error": "No log source is configured."}), 400
    name = source.name
    fields = body.get("fields")
    if not isinstance(fields, list) or any(not isinstance(f, str)
                                           for f in fields):
        return jsonify({"error": "fields must be a list of field names."}), 400
    # Bounded, and the bound is the offer's: a body with ten thousand names
    # in it is a request to run ten thousand aggregations on every search.
    if len(fields) > MAX_STATS_FIELDS:
        return jsonify({"error": f"At most {MAX_STATS_FIELDS} fields can be "
                                 f"counted at once."}), 400

    store = current_app.store
    chosen = store.settings.get(STATS_FIELDS_SETTING) or {}
    if not isinstance(chosen, dict):
        chosen = {}
    cleaned = []
    for field in fields:
        field = field.strip()
        if field and field not in cleaned:
            cleaned.append(field)
    if cleaned:
        chosen[name] = cleaned
    else:
        chosen.pop(name, None)
    store.settings.set(STATS_FIELDS_SETTING, chosen,
                       updated_by=current_user.username)
    return jsonify({"source": name, "chosen": cleaned})


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
                        "source": source.name,
                        "details": str(exc)}), 503

    return jsonify({"containers": allowed,
                    "total_containers": len(all_indices),
                    "accessible_containers": len(allowed),
                    "user_role": current_user.role})
