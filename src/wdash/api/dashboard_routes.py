"""
Dashboard endpoints, served through the hub.

`/data` feeds every panel from a SINGLE Elasticsearch request and is the
endpoint the UI uses. The per-panel endpoints (stats, timeline, log-levels,
services, heatmap) remain for API compatibility but the UI no longer calls
them.

Bucket shape is the neutral model: `key` / `count` / `key_text`, with nested
aggregations under `sub`. Elasticsearch's `doc_count` / `key_as_string` /
`{buckets: [...]}` form no longer appears on the wire.
"""

import json

from flask import (
    Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required

from datetime import timedelta

from .access import request_scope
from ..hub import (
    Capability, DateHistogram, LogQuery, Scope, Terms, TimeWindow,
)
from ..hub.query import DEFAULT_LOG_FIELDS
from ..dashboard import DashboardStorageError
from ..store.objects import ObjectConflict as DashboardConflict
from ..hub.query_language import QueryError, parse
from ..dashboard.thresholds import (
    METRICS, ThresholdError, evaluate as evaluate_thresholds,
    normalise as normalise_thresholds,
)
from ..dashboard.visibility import VISIBILITIES, can_view, explain
from ..dashboard.panels import (
    AGGREGATABLE_FIELDS, PanelError, normalise_all,
)

dashboard_bp = Blueprint("dashboards", __name__)

#: Buckets per panel. Derived from the window rather than mapped from the
#: time-range string: a hardcoded map has to be edited every time the picker
#: gains an option, and when that is forgotten the range silently falls to a
#: default. It did — adding "15m" and "6h" to the picker left both collapsing
#: into a single bucket, which renders as one dot.
_HEATMAP_BARS = 24


def _logs(dashboard=None):
    """The log source a dashboard reads from.

    A dashboard may name one. Without a name it gets the default, which is
    what every dashboard stored before there was more than one source does —
    and what most deployments will always want.

    A dashboard naming a source that no longer exists is an error rather than
    a silent fall back to the default: quietly answering from a different store
    is how somebody concludes their data has disappeared.
    """
    hub = getattr(current_app, "hub", None)
    if hub is None:
        return None

    name = getattr(dashboard, "source", None) if dashboard is not None else None
    if not name:
        return hub.logs()
    try:
        return hub.logs(name)
    except KeyError:
        raise SourceMissing(
            f"This dashboard reads from the source '{name}', which is not "
            f"configured. Check the configuration page.")


class SourceMissing(RuntimeError):
    """A dashboard names a source that is not registered."""


def _scope():
    return request_scope()


def _manager():
    return current_app.dashboard_manager


# --------------------------------------------------------------------------

def _buckets(buckets):
    return [b.to_dict() for b in buckets]


def _level_counts(buckets):
    """Derive error/warn/info counts from level buckets.

    The mapping is deliberately broad: sources emit variants such as FATAL and
    WARNING, and users do not want those counted separately.
    """
    counts = {"error": 0, "warn": 0, "info": 0}
    for bucket in buckets:
        level = str(bucket.key).upper()
        if level in ("ERROR", "FATAL"):
            counts["error"] += bucket.count
        elif level in ("WARN", "WARNING"):
            counts["warn"] += bucket.count
        elif level == "INFO":
            counts["info"] += bucket.count
    return counts


def _baseline_query(dashboard, allowed, time_range, narrow=None):
    """The same query over the window immediately before this one.

    A count on its own says nothing: 1,700 errors is only meaningful next to
    what it was yesterday. Returns None if the query cannot be built — the
    comparison is a nice-to-have and must never take the dashboard down.
    """
    try:
        window = TimeWindow.of(time_range)
        span = window.end - window.start
        earlier = TimeWindow.exact(window.start - span, window.start)
        return LogQuery(window=earlier,
                        text=_effective_query(dashboard, narrow),
                        containers=tuple(allowed))
    except Exception as exc:
        current_app.logger.warning(f"Baseline query could not be built: {exc}")
        return None


def _compare(current, before, baseline_query):
    """Fold the baseline aggregation into a comparison block.

    Returns None when the baseline did not run. Showing its empty result as a
    real zero would render a backend hiccup as "-100%, traffic has stopped" —
    the most alarming thing this page can say, and untrue. No comparison is
    the honest answer; the rest of the response is unaffected.
    """
    if before is None or getattr(before, "failed", False):
        return None

    counts = _level_counts(before.get("log_levels"))
    now_counts = _level_counts(current.get("log_levels"))

    def change(now, then):
        if not then:
            # No baseline to compare against; a "+100%" here would be noise.
            return None
        return (now - then) / then

    return {
        "total_hits": before.total,
        "error_count": counts["error"],
        "warn_count": counts["warn"],
        "info_count": counts["info"],
        "error_rate": (counts["error"] / before.total) if before.total else 0.0,
        "change": {
            "total_hits": change(current.total, before.total),
            "error_count": change(now_counts["error"], counts["error"]),
            "warn_count": change(now_counts["warn"], counts["warn"]),
            "info_count": change(now_counts["info"], counts["info"]),
        },
        "window": {"start": baseline_query.window.start.isoformat(),
                   "end": baseline_query.window.end.isoformat()},
    }


def _timeline_interval(window):
    """Line-chart resolution: roughly 60 points across the window."""
    return window.suggest_interval()


def _heatmap_interval(window):
    """Stacked-bar resolution: chunkier than the line, at most ~30 bars.

    A shared bucket size would make one of the two panels wrong — 60 stacked
    bars is a smear, and 24 points is a jagged line.

    Chosen by the bar count it actually produces rather than by dividing the
    window: a nominal 24-hour range is a little over 24 hours in practice, and
    a "seconds per bar" rule tips it over the hourly boundary and halves the
    resolution for a rounding artefact.
    """
    seconds = window.duration_seconds
    for size, name in ((60, "1m"), (300, "5m"), (900, "15m"), (1800, "30m"),
                       (3600, "1h"), (3 * 3600, "3h"), (6 * 3600, "6h"),
                       (12 * 3600, "12h")):
        if seconds / size <= _HEATMAP_BARS * 1.25:
            return name
    return "1d"


def _trace_panels(panels, window, scope):
    """Fill in the trace-backed panels.

    Traces are a different source, so they cannot ride the log batch — one
    extra round trip, taken once no matter how many trace panels there are.
    A missing or failing trace backend costs those panels, never the page.
    """
    wanted = [p for p in panels if p["type"] == "trace_services"]
    if not wanted:
        return {}

    hub = getattr(current_app, "hub", None)
    traces = hub.traces() if hub else None
    if traces is None or not traces.supports(Capability.SERVICE_LIST):
        return {p["id"]: {"error": "No trace backend is configured."}
                for p in wanted}

    try:
        services = traces.services(window, scope)
    except Exception as exc:
        current_app.logger.warning(f"Trace panel failed: {exc}")
        return {p["id"]: {"error": "Trace data could not be loaded."}
                for p in wanted}

    orders = {
        "spans": lambda s: s.span_count,
        "errors": lambda s: s.error_count,
        "error_rate": lambda s: s.error_rate,
    }

    out = {}
    for panel in wanted:
        ranked = sorted(services, key=orders[panel["sort"]], reverse=True)
        out[panel["id"]] = {"rows": [s.to_dict() for s in ranked[:panel["size"]]]}
    return out


def _panel_aggregations(panels, window):
    """Translate the panel list into neutral aggregations.

    Each aggregation is named after its panel id, so results come back keyed by
    panel with no positional bookkeeping — which matters once panels can be
    reordered and deleted.
    """
    aggregations = []
    for panel in panels:
        if panel["type"] not in ("timeseries", "terms"):
            continue          # answered by another source
        if panel["type"] == "timeseries":
            sub = ()
            if panel.get("split_by"):
                sub = (Terms(name="split", field=panel["split_by"], size=10),)
            aggregations.append(DateHistogram(
                name=panel["id"], interval=_heatmap_interval(window),
                min_count=0, sub=sub))
        elif panel["type"] == "terms":
            aggregations.append(Terms(
                name=panel["id"], field=panel["field"], size=panel["size"],
                missing="unknown" if panel["field"] != "severity" else None))
    return aggregations


def _panel_results(panels, result, extra=None):
    """Attach each panel's data to its definition for the wire."""
    extra = extra or {}
    out = []
    for panel in panels:
        rendered = dict(panel)
        if panel["id"] in extra:
            rendered.update(extra[panel["id"]])
        else:
            rendered["buckets"] = _buckets(result.get(panel["id"]))
        out.append(rendered)
    return out


def _load(dashboard_id):
    """Load a dashboard, refreshing the cache and retrying once if not found."""
    manager = _manager()
    dashboard = manager.get_dashboard(dashboard_id)
    if dashboard:
        return dashboard
    current_app.logger.warning(f"Dashboard not found: {dashboard_id} "
                               f"(user: {current_user.username})")
    manager.refresh_cache()
    return manager.get_dashboard(dashboard_id)


def _targets(dashboard, scope):
    """Dashboard patterns ∩ scope. Returns (all, resolved, allowed).

    `allowed` is what the SOURCE says this scope may read, not a pattern
    check made without saying which source: that check ignored every
    source-qualified rule, so a role granted `elasticsearch:app-*` saw no
    shared dashboard at all, and an exclusion qualified the same way did not
    exclude.
    """
    source = _logs(dashboard)
    available = source.containers(Scope.unrestricted())
    resolved = dashboard.get_resolved_indices(available)
    readable = set(source.containers(scope))
    allowed = [name for name in resolved if name in readable]
    return available, resolved, allowed


def _shown(resolved, allowed):
    """The resolved containers a caller may be shown by name.

    A dashboard's patterns can resolve to containers the viewer may not read,
    and naming them is the information the visibility rule exists to hold
    back — `payment-fraud-investigation` over `fraud-*` says something
    whether or not you can open the index. An administrator sees them all;
    everybody else sees what they can read, and a count of the rest.
    """
    if current_user.has_permission("system:admin"):
        return list(resolved)
    return list(allowed)


def _effective_query(dashboard, narrow=None):
    """The dashboard's query, optionally narrowed by an ad-hoc filter.

    The narrowing is ANDed, never substituted: a shared dashboard link that
    silently dropped its own query would show data the dashboard was never
    scoped to, which is both wrong and a way to leak past an index pattern the
    author chose deliberately.
    """
    base = (dashboard.query or "*").strip()
    narrow = (narrow or "").strip()
    if not narrow or narrow == "*":
        return base or "*"
    # Parsed on its own first. Joined as text, `service:none) OR (*` closed
    # the parenthesis around it and replaced the dashboard's query rather
    # than narrowing it. A filter that parses by itself has balanced
    # parentheses — the tokeniser makes each one a token and escapes none
    # outside quotes — so it cannot leave the group it is put in.
    parse(narrow)
    if not base or base == "*":
        return narrow
    return f"({base}) AND ({narrow})"


def _query(dashboard, allowed, time_range, narrow=None):
    """Build a LogQuery from the dashboard's stored query.

    Raises QueryError when the stored query is malformed; the caller turns that
    into a panel error rather than letting the whole dashboard fail to open.
    """
    return LogQuery(
        window=TimeWindow.of(time_range),
        text=_effective_query(dashboard, narrow),
        containers=tuple(allowed),
    )


def _panel(dashboard_id, aggregations, empty):
    """Shared flow for the per-panel endpoints.

    Returns (payload, status); the payload is handed straight to jsonify.
    """
    if not current_user.has_permission("dashboard:view"):
        return {"error": "Access denied", "error_type": "permission_denied"}, 403

    dashboard = _load(dashboard_id)
    if not dashboard or not _may_view(dashboard):
        return {"error": "Dashboard not found",
                "error_type": "dashboard_not_found"}, 404

    scope = _scope()
    try:
        _, _, allowed = _targets(dashboard, scope)
    except SourceMissing as exc:
        # Not a connection problem, and reporting it as one sends whoever is
        # looking to check a cluster that is perfectly healthy.
        return {"error": str(exc), "error_type": "source_missing"}, 400
    except Exception as exc:
        return {"error": str(exc), "error_type": "elasticsearch_connection"}, 503

    if not allowed:
        return dict(empty), 200

    time_range = request.args.get("time_range", "1h")
    try:
        query = _query(dashboard, allowed, time_range)
    except QueryError as exc:
        return {"error": f"Invalid dashboard query: {exc}",
                "error_type": "invalid_query"}, 400
    return _logs(dashboard).aggregate(query, aggregations, scope), None


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

def _visible(dashboards):
    """Filter a list to what this person may know exists.

    The same helper backs the list page and every dashboard endpoint. Using it
    in one place only would make the API the way around the list, which is not
    a boundary, it is a speed bump.
    """
    scope = _scope()
    username = current_user.username
    is_admin = current_user.has_permission("system:admin")

    out = []
    for dashboard in dashboards:
        try:
            _, _, allowed = _targets(dashboard, scope)
        except Exception:
            # Cannot tell what it reaches — treat it as unreachable rather than
            # visible. A source being down must not open the list up.
            allowed = []
        if can_view(dashboard, username, is_admin, allowed):
            out.append(dashboard)
    return out


def _may_view(dashboard):
    scope = _scope()
    try:
        _, _, allowed = _targets(dashboard, scope)
    except Exception:
        allowed = []
    return can_view(dashboard, current_user.username,
                    current_user.has_permission("system:admin"), allowed)


#: Enough that a normal installation never sees a second page, small enough
#: that a large one cannot build a response nobody can load.
DASHBOARDS_PER_PAGE = 24


@dashboard_bp.route("/dashboards")
@login_required
def dashboards_page():
    if not current_user.has_permission("dashboard:view"):
        flash("Access denied: insufficient permissions", "error")
        return redirect(url_for("index"))

    everything = _manager().get_all_dashboards()
    visible = _visible(everything)

    # Paged AFTER the visibility filter, deliberately.
    #
    # Pushing LIMIT/OFFSET into the store would save reading the table, but
    # visibility is a per-user rule — shared, private, owner, administrator —
    # and it lives in one place (`dashboard/visibility.py`). Teaching three
    # stores to express it in SQL, in a Lucene query and in a Python
    # comprehension would give the product three answers to one question,
    # which is the trap it has already fallen into once with index patterns.
    #
    # The cost is reading a metadata table with tens of rows in it. The
    # benefit was a seven-megabyte response, which is what this page produced
    # with three thousand dashboards on it.
    try:
        page = max(0, int(request.args.get("page", 0)))
    except ValueError:
        page = 0

    pages = max(1, (len(visible) + DASHBOARDS_PER_PAGE - 1) // DASHBOARDS_PER_PAGE)
    # A stale link to page 9 of a list that now has two pages should show the
    # last page, not an empty one that reads as "your dashboards are gone".
    page = min(page, pages - 1)
    start = page * DASHBOARDS_PER_PAGE

    return render_template(
        "dashboards.html",
        dashboards=visible[start:start + DASHBOARDS_PER_PAGE],
        total=len(visible),
        page=page,
        pages=pages,
        page_size=DASHBOARDS_PER_PAGE,
        # Said plainly rather than left as a gap in a list: "there are 4 more
        # you cannot see" is information somebody needs to ask the right
        # question, and hiding the count only makes them ask the wrong one.
        hidden_count=len(everything) - len(visible),
        can_create=current_user.has_permission("dashboard:create"))


@dashboard_bp.route("/dashboard/<dashboard_id>")
@login_required
def view_dashboard(dashboard_id):
    if not current_user.has_permission("dashboard:view"):
        flash("Access denied: insufficient permissions", "error")
        return redirect(url_for("index"))

    dashboard = _load(dashboard_id)
    # Not visible and not there are answered the same way on purpose: a
    # distinct "you may not see this" turns the URL into a way to find out
    # which dashboards exist.
    if not dashboard or not _may_view(dashboard):
        flash("Dashboard not found. It may have been deleted or there may be a "
              "synchronization issue.", "error")
        return redirect(url_for("dashboards.dashboards_page"))
    return render_template("dashboard_view.html", dashboard=dashboard)


def _form_indices():
    try:
        source = _logs()
        # No source means no containers, which is what a dashboard over a
        # deployment with nothing configured should resolve to.
        return source.containers(_scope()) if source is not None else []
    except Exception as exc:
        current_app.logger.error(f"Error getting indices: {exc}")
        return []


def _dashboard_form():
    """Validate the create/edit form. Returns (fields, error_message).

    The query is PARSED here rather than at render time. It used to be stored
    unchecked, so a typo saved cleanly and then every view of that dashboard
    returned "Invalid dashboard query" — the mistake surfaced far from where it
    was made, and the only way out was to guess and edit again.
    """
    name = (request.form.get("name") or "").strip()
    query = (request.form.get("query") or "").strip()

    if not name:
        return None, "A name is required."
    if not query:
        return None, "A query is required. Use * to match everything."

    try:
        parse(query)
    except QueryError as exc:
        return None, f"That query cannot be parsed: {exc}"

    # Panels travel as a JSON blob from the editor. Absent means "leave the
    # default set", which is what an untouched dashboard should keep doing —
    # it must NOT freeze today's defaults into the stored document.
    raw_panels = (request.form.get("panels") or "").strip()
    panels = None
    if raw_panels:
        try:
            panels = normalise_all(json.loads(raw_panels))
        except json.JSONDecodeError:
            return None, "The panel layout could not be read."
        except PanelError as exc:
            return None, str(exc)

    thresholds = {}
    for metric in METRICS:
        levels = {}
        for level in ("warning", "critical"):
            raw = (request.form.get(f"threshold_{metric}_{level}") or "").strip()
            if raw:
                levels[level] = raw
        if levels:
            thresholds[metric] = levels
    try:
        thresholds = normalise_thresholds(thresholds)
    except ThresholdError as exc:
        return None, str(exc)

    return {
        "name": name,
        "description": (request.form.get("description") or "").strip(),
        "query": query,
        "index_patterns": request.form.getlist("index_patterns") or ["*"],
        "panels": panels,
        "thresholds": thresholds,
        "visibility": request.form.get("visibility"),
    }, None


@dashboard_bp.route("/dashboard/create", methods=["GET", "POST"])
@login_required
def create_dashboard():
    if not current_user.has_permission("dashboard:create"):
        flash("Access denied: insufficient permissions", "error")
        return redirect(url_for("dashboards.dashboards_page"))

    indices = _form_indices()
    if request.method == "POST":
        fields, error = _dashboard_form()
        if error:
            flash(error, "error")
            return render_template("dashboard_create.html", indices=indices,
                                   visibilities=VISIBILITIES)

        try:
            dashboard = _manager().create_dashboard(
                created_by=current_user.username, **fields)
        except DashboardStorageError as exc:
            current_app.logger.error(f"Dashboard could not be saved: {exc}")
            flash("The dashboard could not be saved and has NOT been created. "
                  "Check the server logs and try again.", "error")
            return render_template("dashboard_create.html", indices=indices,
                                   visibilities=VISIBILITIES)

        flash("Dashboard created successfully", "success")
        return redirect(url_for("dashboards.view_dashboard", dashboard_id=dashboard.id))

    return render_template("dashboard_create.html", indices=indices,
                           visibilities=VISIBILITIES)


def _supports_revisions():
    """Whether the configured store tracks a revision per dashboard."""
    import inspect
    try:
        signature = inspect.signature(_manager().update_dashboard)
    except (TypeError, ValueError):
        return False
    return "revision" in signature.parameters


@dashboard_bp.route("/dashboard/<dashboard_id>/edit", methods=["GET", "POST"])
@login_required
def edit_dashboard(dashboard_id):
    if not current_user.has_permission("dashboard:edit"):
        flash("Access denied: insufficient permissions", "error")
        return redirect(url_for("dashboards.dashboards_page"))

    dashboard = _load(dashboard_id)
    if not dashboard:
        flash("Dashboard not found. It may have been deleted or there may be a "
              "synchronization issue.", "error")
        return redirect(url_for("dashboards.dashboards_page"))

    if (dashboard.created_by != current_user.username
            and not current_user.has_permission("system:admin")):
        flash("Access denied: you can only edit your own dashboards", "error")
        return redirect(url_for("dashboards.dashboards_page"))
    if not _may_view(dashboard):
        flash("Dashboard not found.", "error")
        return redirect(url_for("dashboards.dashboards_page"))

    if request.method == "POST":
        fields, error = _dashboard_form()
        if error:
            flash(error, "error")
            return render_template("dashboard_edit.html", dashboard=dashboard,
                                   indices=_form_indices(),
                                   panels=dashboard.get_panels(),
                                   aggregatable_fields=list(AGGREGATABLE_FIELDS),
                           thresholds=dashboard.thresholds,
                           visibilities=VISIBILITIES)
        # The revision the form was rendered from. The database store refuses
        # a write against a stale one — its docstring said "the edit form
        # passes it", and the form did not, so optimistic locking was
        # implemented, tested and never reached. Two people editing the same
        # dashboard silently lost one of the two edits.
        #
        # `None` when the store does not track revisions, which is
        # last-write-wins and what a script wants.
        submitted = request.form.get("revision")
        if submitted and _supports_revisions():
            try:
                fields["revision"] = int(submitted)
            except ValueError:
                pass

        try:
            updated = _manager().update_dashboard(dashboard_id=dashboard_id, **fields)
        except DashboardConflict as exc:
            # Not a storage failure: somebody else's work is at stake, so the
            # answer is "look at what changed", not "try again".
            flash(str(exc), "warning")
            updated = None
        except DashboardStorageError as exc:
            current_app.logger.error(f"Dashboard could not be saved: {exc}")
            flash("The dashboard could not be saved and your changes were NOT "
                  "applied. Check the server logs and try again.", "error")
            updated = None

        if updated:
            flash("Dashboard updated successfully", "success")
            return redirect(url_for("dashboards.view_dashboard",
                                    dashboard_id=dashboard_id))

    return render_template("dashboard_edit.html", dashboard=dashboard,
                           indices=_form_indices(),
                           panels=dashboard.get_panels(),
                           aggregatable_fields=list(AGGREGATABLE_FIELDS),
                           thresholds=dashboard.thresholds,
                           visibilities=VISIBILITIES)


@dashboard_bp.route("/dashboard/<dashboard_id>/delete", methods=["POST"])
@login_required
def delete_dashboard(dashboard_id):
    if not current_user.has_permission("dashboard:delete"):
        return jsonify({"error": "Access denied"}), 403

    dashboard = _manager().get_dashboard(dashboard_id)
    if not dashboard:
        return jsonify({"error": "Dashboard not found"}), 404
    if (dashboard.created_by != current_user.username
            and not current_user.has_permission("system:admin")):
        return jsonify({"error": "Access denied"}), 403

    try:
        deleted = _manager().delete_dashboard(dashboard_id)
    except DashboardStorageError as exc:
        current_app.logger.error(f"Dashboard could not be deleted: {exc}")
        return jsonify({"error": "The dashboard could not be deleted; it is "
                                 "still there.",
                        "error_type": "storage_error"}), 500
    if not deleted:
        return jsonify({"error": "Dashboard not found"}), 404
    return jsonify({"success": True})


# --------------------------------------------------------------------------
# Combined data endpoint
# --------------------------------------------------------------------------

@dashboard_bp.route("/api/dashboard/<dashboard_id>/data")
@login_required
def api_dashboard_data(dashboard_id):
    if not current_user.has_permission("dashboard:view"):
        return jsonify({"error": "Access denied: You do not have permission to "
                                 "view dashboards.",
                        "error_type": "permission_denied"}), 403

    dashboard = _load(dashboard_id)
    if not dashboard:
        return jsonify({"error": "Dashboard not found. It may have been deleted or "
                                 "there may be a synchronization issue.",
                        "error_type": "dashboard_not_found",
                        "dashboard_id": dashboard_id}), 404

    if not _may_view(dashboard):
        return jsonify({"error": "Dashboard not found.",
                        "error_type": "dashboard_not_found",
                        "dashboard_id": dashboard_id}), 404

    scope = _scope()
    try:
        _, resolved, allowed = _targets(dashboard, scope)
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    except Exception as exc:
        return jsonify({"error": "Unable to connect to Elasticsearch.",
                        "error_type": "elasticsearch_connection",
                        "details": str(exc)}), 503

    if not allowed:
        # Returning empty data beats an error: the dashboard opens with a blank panel
        return jsonify({"error": "No accessible indices for dashboard data.",
                        "error_type": "no_accessible_containers",
                        "dashboard_patterns": dashboard.index_patterns,
                        "resolved_containers": _shown(resolved, allowed),
                        "total_resolved": len(resolved),
                        "total_hits": 0, "panels": [],
                        "queried_containers": []}), 200

    # Every panel from a SINGLE Elasticsearch request. This used to mean
    # separate queries plus a second round of "retry with service if
    # service.keyword fails".
    time_range = request.args.get("time_range", "1h")
    # An ad-hoc filter carried in the URL. Together with time_range this makes
    # a dashboard link reproduce what the sender was actually looking at —
    # "the dashboard" and "the dashboard, this window, this filter" are
    # different things, and only the second is worth pasting into a thread.
    narrow = request.args.get("q") or None
    try:
        query = _query(dashboard, allowed, time_range, narrow)
    except QueryError as exc:
        message = (f"Invalid filter: {exc}" if narrow
                   else f"Invalid dashboard query: {exc}")
        return jsonify({"error": message,
                        "error_type": "invalid_query"}), 400
    # Both windows go out in ONE batch. The comparison is a separate query —
    # it covers a different time range — but not a separate round trip.
    try:
        panels = dashboard.get_panels()
    except PanelError as exc:
        return jsonify({"error": f"This dashboard's panels are invalid: {exc}",
                        "error_type": "invalid_panels"}), 400

    # Every panel plus the summary counts in ONE request. Adding a panel costs
    # an aggregation, not a round trip — which is what makes an arbitrary panel
    # list affordable at all.
    aggregations = _panel_aggregations(panels, query.window)
    # The stat cards are not a panel: they are the summary every dashboard
    # carries, so their aggregation is always present regardless of the list.
    aggregations.append(Terms(name="_levels", field="severity", size=10))
    batch = [(query, aggregations)]

    baseline_query = _baseline_query(dashboard, allowed, time_range, narrow)
    if baseline_query is not None:
        batch.append((baseline_query,
                      [Terms(name="_levels", field="severity", size=10)]))

    results = _logs(dashboard).multi_aggregate(batch, scope)
    result = results[0]
    previous = _compare(result, results[1], baseline_query) if len(results) > 1 else None

    counts = _level_counts(result.get("_levels"))
    payload = {
        "total_hits": result.total,
        # The counts the stat cards need ship in this response too, so the
        # per-panel endpoints do not have to be called separately.
        "error_count": counts["error"],
        "warn_count": counts["warn"],
        "info_count": counts["info"],
        # Error rate needs the total to mean anything on its own.
        "error_rate": (counts["error"] / result.total) if result.total else 0.0,
        "previous_period": previous,
        # None when nothing is configured. "ok" is a claim that someone
        # defined normal and this is inside it — not the same statement.
        "status": evaluate_thresholds(dashboard.thresholds, {
            "error_rate": (counts["error"] / result.total) if result.total else 0.0,
            "error_count": counts["error"],
        }),
        "thresholds": dashboard.thresholds,
        "panels": _panel_results(panels, result,
                                 _trace_panels(panels, query.window, scope)),
        "dashboard_patterns": dashboard.index_patterns,
        "resolved_containers": _shown(resolved, allowed),
        "total_resolved": len(resolved),
        "accessible_containers": allowed,
        "queried_containers": allowed,
        "total_accessible_containers": len(allowed),
        # Echoed so the client can show what is actually being asked, rather
        # than only what the dashboard was saved with.
        "time_range": time_range,
        "filter": narrow,
        "effective_query": query.text,
    }
    if result.warnings:
        payload["warnings"] = list(result.warnings)
    return jsonify(payload)


@dashboard_bp.route("/api/dashboard/<dashboard_id>/patterns")
@login_required
def api_dashboard_patterns(dashboard_id):
    if not current_user.has_permission("dashboard:view"):
        return jsonify({"error": "Access denied: You do not have permission to "
                                 "view dashboards.",
                        "error_type": "permission_denied"}), 403

    dashboard = _manager().get_dashboard(dashboard_id)
    if not dashboard or not _may_view(dashboard):
        return jsonify({"error": "Dashboard not found.",
                        "error_type": "dashboard_not_found"}), 404

    try:
        _, resolved, allowed = _targets(dashboard, _scope())
    except Exception as exc:
        current_app.logger.error(f"Error getting dashboard patterns: {exc}")
        return jsonify({"error": "Unable to resolve index patterns.",
                        "error_type": "pattern_resolution_error",
                        "details": str(exc)}), 500

    return jsonify({"dashboard_id": dashboard_id,
                    "index_patterns": dashboard.index_patterns,
                    "resolved_containers": _shown(resolved, allowed),
                    "accessible_containers": allowed,
                    "total_resolved": len(resolved),
                    "total_accessible": len(allowed)})


# --------------------------------------------------------------------------
# Per-panel endpoints (kept for API compatibility)
# --------------------------------------------------------------------------

@dashboard_bp.route("/api/dashboard/<dashboard_id>/stats")
@login_required
def api_dashboard_stats(dashboard_id):
    empty = {"total_hits": 0, "error_count": 0, "warn_count": 0,
             "info_count": 0, "queried_containers": []}
    result, status = _panel(dashboard_id,
                            [Terms(name="log_levels", field="severity", size=10)],
                            empty)
    if status is not None:
        return jsonify(result), status
    if isinstance(result, dict):
        return jsonify(result)

    counts = _level_counts(result.get("log_levels"))
    dashboard = _load(dashboard_id)
    _, _, allowed = _targets(dashboard, _scope())
    return jsonify({"total_hits": result.total,
                    "error_count": counts["error"],
                    "warn_count": counts["warn"],
                    "info_count": counts["info"],
                    "queried_containers": allowed})


@dashboard_bp.route("/api/dashboard/<dashboard_id>/timeline")
@login_required
def api_dashboard_timeline(dashboard_id):
    window = TimeWindow.of(request.args.get("time_range", "1h"))
    result, status = _panel(
        dashboard_id,
        [DateHistogram(name="timeline", interval=_timeline_interval(window),
                       min_count=0)],
        {"timeline": []})
    if status is not None:
        return jsonify(result), status
    if isinstance(result, dict):
        return jsonify(result)
    return jsonify({"timeline": _buckets(result.get("timeline"))})


@dashboard_bp.route("/api/dashboard/<dashboard_id>/log-levels")
@login_required
def api_dashboard_log_levels(dashboard_id):
    result, status = _panel(dashboard_id,
                            [Terms(name="log_levels", field="severity", size=10)],
                            {"log_levels": []})
    if status is not None:
        return jsonify(result), status
    if isinstance(result, dict):
        return jsonify(result)
    return jsonify({"log_levels": _buckets(result.get("log_levels"))})


@dashboard_bp.route("/api/dashboard/<dashboard_id>/services")
@login_required
def api_dashboard_services(dashboard_id):
    result, status = _panel(
        dashboard_id,
        [Terms(name="services", field="service", size=10, missing="unknown")],
        {"services": []})
    if status is not None:
        return jsonify(result), status
    if isinstance(result, dict):
        return jsonify(result)
    return jsonify({"services": _buckets(result.get("services"))})


@dashboard_bp.route("/api/dashboard/<dashboard_id>/heatmap")
@login_required
def api_dashboard_heatmap(dashboard_id):
    result, status = _panel(
        dashboard_id,
        [DateHistogram(name="heatmap_data",
                       interval=_heatmap_interval(
                           TimeWindow.of(request.args.get("time_range", "1h"))),
                       min_count=0,
                       sub=(Terms(name="log_levels", field="severity", size=10),))],
        {"heatmap_data": []})
    if status is not None:
        return jsonify(result), status
    if isinstance(result, dict):
        return jsonify(result)
    return jsonify({"heatmap_data": _buckets(result.get("heatmap_data"))})


@dashboard_bp.route("/api/dashboard/<dashboard_id>/recent-logs")
@login_required
def api_dashboard_recent_logs(dashboard_id):
    if not current_user.has_permission("dashboard:view"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403

    dashboard = _load(dashboard_id)
    if not dashboard:
        return jsonify({"records": []})

    scope = _scope()
    try:
        _, _, allowed = _targets(dashboard, scope)
    except Exception:
        return jsonify({"records": []})
    if not allowed:
        return jsonify({"records": []})

    # The previous version had NO time range here and scanned every index in
    # full. Fixed deliberately: the panel shows "recent records", so there is no
    # reason for an unbounded scan.
    page = _logs(dashboard).search(
        LogQuery(window=TimeWindow.of(request.args.get("time_range", "1h")),
                 text=dashboard.query or "*",
                 containers=tuple(allowed), limit=10,
                 fields=DEFAULT_LOG_FIELDS),
        scope)
    return jsonify({"records": [r.to_dict() for r in page.records]})
