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


#: Which raw level names each stat card stands for.
#:
#: Deliberately broad: sources emit variants such as FATAL and WARNING, and
#: users do not want those counted separately. One definition, because there
#: used to be two — this one behind the NUMBER on the card, and `level:ERROR`
#: written into the click that opens it — and they disagreed. Measured
#: against the lab over seven days: the error card read 3,086 and opened
#: 2,767, the cluster holding 2,766 ERROR and 319 FATAL in that window, so
#: the FATAL records the card had counted could not be reached from the
#: number counting them. `_level_queries` derives the click from this table.
LEVEL_GROUPS = {
    "error": ("ERROR", "FATAL"),
    "warn": ("WARN", "WARNING"),
    "info": ("INFO",),
}

#: The name the stat cards' severity aggregation rides under in the batch.
#:
#: Named once because it was written twice and spelled two ways: the batch
#: built `_levels` and the comparison asked for `log_levels`, which no result
#: carries, so the previous window's error, warning and info counts were the
#: empty list's — zero — and the page printed "none in previous period" under
#: all three. Measured on the demo at 24h over the baseline window
#: 2026-09-10T09:15Z .. 2026-09-11T09:20Z, which held 19,732 records, of
#: which the cluster really had ERROR 1,750 + FATAL 220, WARN 2,372 and INFO
#: 13,737. The window is named because it slides: the same measurement a day
#: later, over 2026-09-10T10:00Z .. 2026-09-11T10:05Z, reads 20,527 records
#: with 2,031 in the error group, WARN 2,443 and INFO 14,323 — two unnamed
#: snapshots of a rolling 24 hours read as a contradiction.
#: The per-panel endpoints below keep `log_levels`: that one is a KEY IN
#: THEIR JSON, not an internal name.
LEVELS_AGGREGATION = "_levels"


def _level_counts(buckets):
    """Derive error/warn/info counts from level buckets."""
    counts = {group: 0 for group in LEVEL_GROUPS}
    for bucket in buckets:
        level = str(bucket.key).upper()
        for group, members in LEVEL_GROUPS.items():
            if level in members:
                counts[group] += bucket.count
                break
    return counts


def _level_queries():
    """The query behind each stat card, in the language the Logs page speaks.

    Parenthesised even for a single level, because the drill-down ANDs this
    onto the dashboard's own query and `a AND b OR c` is not what the card
    means.
    """
    return {group: "(" + " OR ".join(f"level:{level}" for level in members) + ")"
            for group, members in LEVEL_GROUPS.items()}


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

    A baseline that PARTLY answered is the case in between, and it decided on
    `failed` alone: a window whose aggregation warned came back as exact
    numbers with its warnings thrown away, because the payload carries the
    current result's warnings only. Measured on the lab, where both windows
    hit the same shard failure ("Fielddata is disabled on [level] in
    [bad-logs-000001]"): bad-logs-000001 holds 1,720 records in the baseline
    window of which 158 match level:ERROR, so error_count 2,031 is short by
    158 while total_hits 20,527 counts all 1,720 — an error rate of 9.9%
    where the records say 10.7%. Today the current window fails identically
    and the page warns; a baseline-only failure would have been silent. The
    counts still ship — they are the best floor there is — carrying the
    reason they are a floor.
    """
    if before is None or getattr(before, "failed", False):
        return None

    counts = _level_counts(before.get(LEVELS_AGGREGATION))
    now_counts = _level_counts(current.get(LEVELS_AGGREGATION))

    def change(now, then):
        if not then:
            # No baseline to compare against; a "+100%" here would be noise.
            return None
        return (now - then) / then

    compared = {
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
    notes = [note for note in (getattr(before, "warnings", ()) or ()) if note]
    if notes:
        compared["partial"] = True
        compared["warnings"] = notes
    return compared


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

    # A service list with one backend missing from it is not a shorter list,
    # it is a list nobody can read as one: the services that store held are
    # absent, and the span counts of the ones it shares are short. The
    # fan-out says so on the answer, and this threw that away — so a store
    # that did not reply rendered as a service having gone quiet.
    partial = bool(getattr(services, "partial", False))
    notes = [str(note) for note in (getattr(services, "warnings", ()) or ())]

    orders = {
        "spans": lambda s: s.span_count,
        "errors": lambda s: s.error_count,
        "error_rate": lambda s: s.error_rate,
    }

    out = {}
    for panel in wanted:
        ranked = sorted(services, key=orders[panel["sort"]], reverse=True)
        rendered = {"rows": [s.to_dict() for s in ranked[:panel["size"]]]}
        if partial:
            rendered["partial"] = True
            rendered["warnings"] = notes
        out[panel["id"]] = rendered
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
        return _unreachable(dashboard, exc), 503

    if not allowed:
        return dict(empty), 200

    time_range = request.args.get("time_range", "1h")
    try:
        query = _query(dashboard, allowed, time_range)
    except QueryError as exc:
        return {"error": f"Invalid dashboard query: {exc}",
                "error_type": "invalid_query"}, 400
    result = _logs(dashboard).aggregate(query, aggregations, scope)
    if _did_not_run(result):
        return _did_not_run(result), 502
    return result, None


def _did_not_run(result):
    """The error for an aggregation that produced nothing at all, or None.

    Its zeros are not an answer, and served as one they draw a quiet hour: a
    VictoriaLogs query holding a range used to raise out of the adapter and
    reach the page as an HTML 500, which at least looked broken; answered as
    a failure it came back 200 with every count at zero.

    The page prints this above the panel grid, warnings and all. It used to
    hand the message to a toast manager no page defines, so the reader got
    "Failed to load" and a grid saying the panels could not be loaded, with
    the reason nowhere on screen — which is why the warnings travel as a
    list of their own rather than only joined into the sentence.
    """
    if not result.failed or result.buckets:
        return None
    return {"error": "; ".join(result.warnings) or "The query did not run.",
            "error_type": "query_failed",
            "warnings": list(result.warnings)}


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

#: The three answers to "may this person see that this dashboard exists?".
#: There used to be two, and one of them was doing the work of both: a
#: dashboard hidden because the rule says so and a dashboard hidden because
#: nobody could ask are different facts, and every screen that had only "no"
#: had to pick one of them to say.
VISIBLE, HIDDEN, UNCHECKED = "visible", "hidden", "unchecked"

#: A stand-in for "suppose the source HAD answered, and it reached something".
#: `can_view` only asks whether this list is empty, so the contents never
#: leave `_decide` — it is the question "would the rule have hidden it
#: anyway?" written in the one vocabulary the rule has.
_SOME_REACH = ("<the source could not be asked>",)


def _decide(dashboard, scope, username, is_admin):
    """VISIBLE, HIDDEN or UNCHECKED, with the failure behind an UNCHECKED.

    UNCHECKED is for a dashboard hidden ONLY because its source could not say
    what it reaches. It is still hidden — a source being down must never open
    the list up — but it is hidden for a reason that will go away, and the
    reader deserves to be told which kind of hidden they are looking at.

    The second `can_view` is what keeps the two apart. Failing the first one
    during an outage does not mean the outage is why: somebody else's PRIVATE
    dashboard is hidden whatever its store says. Asked again with the reach
    granted, the rule answers the question the outage was hiding — "would you
    have seen this if the backend were up?" — and only a yes is UNCHECKED.
    """
    try:
        _, _, allowed = _targets(dashboard, scope)
        failure = None
    except Exception as exc:
        # Cannot tell what it reaches — treat it as unreachable rather than
        # visible. A source being down must not open the list up.
        allowed, failure = [], exc

    if can_view(dashboard, username, is_admin, allowed):
        return VISIBLE, None
    if failure is None:
        return HIDDEN, None
    if can_view(dashboard, username, is_admin, _SOME_REACH):
        return UNCHECKED, failure
    return HIDDEN, None


def _visible(dashboards):
    """Split a list into what this person may know exists, and what could not
    be decided. Returns (visible, unchecked, sources).

    `unchecked` holds the dashboards hidden only because their source could
    not say what they reach. They stay hidden — a source being down must not
    open the list up — but "hidden because you may not see it" and "hidden
    because nothing could be checked" are different facts, and the page said
    only the first: three dashboards behind an unreachable Loki were reported
    as "not shown: either private to their authors, or covering data outside
    your access", which sends the reader to their administrator to ask for
    access they already have.

    And then it said the second about all three, which is the same mistake
    the other way up. One of them was alice's private dashboard: bob was told
    "there is no saying what they can reach" about a dashboard he could never
    have seen, so the count promised something the backend coming back would
    not deliver.
    """
    scope = _scope()
    username = current_user.username
    is_admin = current_user.has_permission("system:admin")

    out, unchecked, sources = [], [], {}
    for dashboard in dashboards:
        verdict, failure = _decide(dashboard, scope, username, is_admin)
        if verdict == VISIBLE:
            out.append(dashboard)
        elif verdict == UNCHECKED:
            unchecked.append(dashboard)
            sources[_source_name(dashboard)] = str(failure)
    return out, unchecked, sorted(sources)


def _source_name(dashboard):
    """Which source a dashboard reads from, for a message about it failing."""
    name = getattr(dashboard, "source", None)
    if name:
        return str(name)
    hub = getattr(current_app, "hub", None)
    try:
        return hub.logs().name if hub is not None else "the log source"
    except Exception:
        return "the log source"


def _unreachable(dashboard, exc):
    """What to say when a source could not tell us what a dashboard reaches.

    It said "Unable to connect to Elasticsearch" whatever the backend was, so
    a Loki or VictoriaLogs outage sent whoever was looking to a cluster the
    deployment may not even have. The name is a field of its own as well as
    part of the sentence, because the client draws its own suggestions beside
    the message — see the same shape in `log_routes.api_search`.
    """
    name = _source_name(dashboard)
    return {"error": f"Unable to connect to {name}. Please check the "
                     f"connection.",
            "error_type": "elasticsearch_connection",
            "source": name,
            "details": str(exc)}


def _view_verdict(dashboard):
    """`_decide` for the current request. Returns (verdict, failure)."""
    return _decide(dashboard, _scope(), current_user.username,
                   current_user.has_permission("system:admin"))


def _may_view(dashboard):
    """The two-answer form, for the callers that only have two answers.

    UNCHECKED is a no here, as it has always been. A caller that can say
    something better than "not found" about a source that is down should ask
    `_view_verdict` instead — `log_routes._search_dashboard` does.
    """
    return _view_verdict(dashboard)[0] == VISIBLE


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
    visible, unchecked, unchecked_sources = _visible(everything)

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
        #
        # The ones nothing could be checked for are counted apart from it. A
        # backend outage folded into "private, or outside your access" is a
        # failure wearing the clothes of a boundary, and the reader acts on
        # the wrong one.
        hidden_count=len(everything) - len(visible) - len(unchecked),
        unchecked_count=len(unchecked),
        unchecked_sources=unchecked_sources,
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

    # Which source this dashboard reads from. Validated against the names the
    # hub actually has: a stored name that is not configured is reported to
    # every reader for ever ("reads from 'loki', which is not configured"),
    # and the place to catch that is here, once, where it was typed.
    source = (request.form.get("source") or "").strip()
    if source and source not in _source_names():
        return None, (f"There is no log source called '{source}'. "
                      f"Configured: {', '.join(_source_names()) or 'none'}.")

    fields = {
        "name": name,
        "description": (request.form.get("description") or "").strip(),
        "query": query,
        "index_patterns": request.form.getlist("index_patterns") or ["*"],
        "panels": panels,
        "thresholds": thresholds,
        "visibility": request.form.get("visibility"),
    }
    # Present-and-empty and absent are DIFFERENT, and the key travels only for
    # the first. Both stores read "" as the deliberate choice "the default
    # source" and `None`/absent as "leave it alone", so returning "" whenever
    # the field had not been rendered wiped the stored source on every edit:
    # `dashboard_edit.html` hides the select inside `{% if sources|length > 1 %}`,
    # so on a single-source installation the browser cannot send it and every
    # edit through the UI repointed the dashboard at whatever the default
    # source happens to be — quietly, which is the one thing `_logs()` and
    # README's "reads from a source that is not configured" both exist to
    # prevent. `visibility` above has always used this convention.
    if "source" in request.form:
        fields["source"] = source
    return fields, None


def _source_names():
    """The configured log sources, in the order the hub holds them."""
    hub = getattr(current_app, "hub", None)
    return [source.name for source in (hub.log_sources if hub else [])]


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
                                   sources=_source_names(),
                                   visibilities=VISIBILITIES)

        try:
            dashboard = _manager().create_dashboard(
                created_by=current_user.username, **fields)
        except DashboardStorageError as exc:
            current_app.logger.error(f"Dashboard could not be saved: {exc}")
            flash("The dashboard could not be saved and has NOT been created. "
                  "Check the server logs and try again.", "error")
            return render_template("dashboard_create.html", indices=indices,
                                   sources=_source_names(),
                                   visibilities=VISIBILITIES)

        flash("Dashboard created successfully", "success")
        return redirect(url_for("dashboards.view_dashboard", dashboard_id=dashboard.id))

    return render_template("dashboard_create.html", indices=indices,
                           sources=_source_names(),
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
                           sources=_source_names(),
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
                           sources=_source_names(),
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
        return jsonify(_unreachable(dashboard, exc)), 503

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
    aggregations.append(Terms(name=LEVELS_AGGREGATION, field="severity", size=10))
    batch = [(query, aggregations)]

    baseline_query = _baseline_query(dashboard, allowed, time_range, narrow)
    if baseline_query is not None:
        batch.append((baseline_query,
                      [Terms(name=LEVELS_AGGREGATION, field="severity", size=10)]))

    results = _logs(dashboard).multi_aggregate(batch, scope)
    result = results[0]
    if _did_not_run(result):
        return jsonify(_did_not_run(result)), 502
    previous = _compare(result, results[1], baseline_query) if len(results) > 1 else None

    counts = _level_counts(result.get(LEVELS_AGGREGATION))
    payload = {
        "total_hits": result.total,
        # The counts the stat cards need ship in this response too, so the
        # per-panel endpoints do not have to be called separately.
        "error_count": counts["error"],
        "warn_count": counts["warn"],
        "info_count": counts["info"],
        # And the query each of those numbers stands for, so the click that
        # opens a card asks for what the card counted rather than for a
        # severity name somebody typed into the client to match.
        "level_queries": _level_queries(),
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
                    "level_queries": _level_queries(),
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
    """The newest records a dashboard reaches, behind the same gates as every
    other panel.

    It had none of them. Measured: a viewer who was not the author got 404
    from data, log-levels, patterns and stats for somebody's PRIVATE
    dashboard, and 200 from here, with its query run for them. A dashboard
    that did not exist and one out of reach answered alike, with no records,
    and a stored query that did not parse was a 500.
    """
    if not current_user.has_permission("dashboard:view"):
        return jsonify({"error": "Access denied",
                        "error_type": "permission_denied"}), 403

    dashboard = _load(dashboard_id)
    if not dashboard or not _may_view(dashboard):
        return jsonify({"error": "Dashboard not found",
                        "error_type": "dashboard_not_found"}), 404

    scope = _scope()
    try:
        _, _, allowed = _targets(dashboard, scope)
    except SourceMissing as exc:
        return jsonify({"error": str(exc), "error_type": "source_missing"}), 400
    except Exception as exc:
        # Not "no records": the source could not say what the dashboard
        # reaches, which is a different answer and needs a different look.
        return jsonify(_unreachable(dashboard, exc)), 503
    if not allowed:
        return jsonify({"records": []})

    # The previous version had NO time range here and scanned every index in
    # full. Fixed deliberately: the panel shows "recent records", so there is no
    # reason for an unbounded scan.
    try:
        query = LogQuery(window=TimeWindow.of(request.args.get("time_range", "1h")),
                         text=_effective_query(dashboard),
                         containers=tuple(allowed), limit=10,
                         fields=DEFAULT_LOG_FIELDS)
    except QueryError as exc:
        return jsonify({"error": f"Invalid dashboard query: {exc}",
                        "error_type": "invalid_query"}), 400
    page = _logs(dashboard).search(query, scope)
    return jsonify({"records": [r.to_dict() for r in page.records]})
