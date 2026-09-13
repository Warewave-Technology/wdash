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
    Capability, DateHistogram, Hub, LogQuery, Scope, Terms, TimeWindow,
    TraceQuery,
)
from ..hub.models import DOWN, UNKNOWN, UP
from ..hub.query import DEFAULT_LOG_FIELDS, SORT_RECENT, SORT_SLOWEST
from ..utils import timerange
from ..dashboard import DashboardStorageError
from ..store.objects import ObjectConflict as DashboardConflict
from ..hub.query_language import QueryError, parse
from ..dashboard.thresholds import (
    METRICS, ThresholdError, evaluate as evaluate_thresholds,
    normalise as normalise_thresholds,
)
from ..dashboard.visibility import PRIVATE, VISIBILITIES, can_view, explain
from ..dashboard.panels import (
    AGGREGATABLE_FIELDS, MAX_SIZE, MONITOR_VIEWS, PANEL_HEIGHTS, PanelError,
    check_group_by, default_panels, needs_logs, normalise_all, signal_of,
)
from ..hub.aggregation import AggregationResult
# The certificate bands and the scope monitors are read under come from the
# Monitors page rather than being written again here. A dashboard that
# invented its own "expiring soon" would give the product two thresholds, and
# a dashboard that narrowed monitors by the viewer's LOG scope would
# contradict ElasticsearchMonitorSource.containers, which says in as many
# words that monitor visibility is a permission and not an index pattern.
from . import monitor_routes
# And the trace boundary comes from the Traces page for the same reason: a
# dashboard that decided for itself which services a role may see would give
# the product two answers to one question. `_may_see_service` asks each
# member source by name, which is what makes a rule written for one source
# count there and nowhere else.
from . import trace_routes

dashboard_bp = Blueprint("dashboards", __name__)

#: Buckets per panel. Derived from the window rather than mapped from the
#: time-range string: a hardcoded map has to be edited every time the picker
#: gains an option, and when that is forgotten the range silently falls to a
#: default. It did — adding "15m" and "6h" to the picker left both collapsing
#: into a single bucket, which renders as one dot.
_HEATMAP_BARS = 24

#: The signals this route knows how to answer, and nothing more.
#:
#: "logs" rides the batched aggregation; "traces" is `_trace_panels` and
#: "monitors" is `_monitor_panels`. A panel type registered in `PANEL_TYPES`
#: with any other signal has nothing to fill it, and the cost of forgetting
#: that is the one failure this package exists to remove: `_panel_results`
#: would read the panel's id out of the LOG result, find nothing, and send an
#: empty bucket list, which the client draws as "No data in this window" — a
#: claim about the data, made about a question nobody asked. So a panel no
#: filler answered gets a reason instead, and `tests.test_panel_reasons`
#: fails the day a row is added here without one.
#:
#: "monitors" was the worked example of that failure when this set was
#: written — a row registered with no filler, measured as a card reading
#: quiet. It has a filler now, and the guard is the same guard.
#:
#: One caveat this set cannot express: a "logs" panel is not necessarily
#: answered by the batch. A records panel asks for RECORDS, which is a search
#: and not an aggregation, so it has a filler of its own (`_records_panels`)
#: while still being a log panel in every other way — it needs the containers
#: and it shares the log source's fate. A log-signal panel with no
#: aggregation and no filler reads its empty result out of the batch, which
#: is the same "No data in this window" the set above exists to prevent.
#:
#: "alerts" is `_alert_panels`, off WDash's own store. Like traces and
#: monitors it needs the window and the caller's scope and nothing else, so
#: it is filled in an Elasticsearch outage too.
FILLED_SIGNALS = frozenset({"logs", "traces", "monitors", "alerts"})


def _pinned_name(dashboard):
    """The source a dashboard is pinned to, or None for every source."""
    if dashboard is None:
        return None
    return getattr(dashboard, "source", None) or None


def _logs(dashboard=None):
    """The log source a dashboard reads from.

    A dashboard may be pinned to one. Unpinned, it reads every log source at
    once — the same question the Logs page asks on its first search — which
    is what every dashboard stored before there was a choice now means.
    It used to mean one source, whichever was registered first: the
    environment's cluster while there was one, the oldest stored row after
    that. Measured on the demo the day the environment path went, the board
    fell from 18,169 records to 1,213 because its oldest stored source was a
    Loki, with nothing on screen to say so.

    A dashboard pinned to a source that no longer exists is an error rather
    than a silent fall back to the rest: quietly answering from a different
    store is how somebody concludes their data has disappeared.
    """
    hub = getattr(current_app, "hub", None)
    if hub is None:
        return None

    name = _pinned_name(dashboard)
    if not name:
        return hub.logs()
    try:
        return hub.logs(name)
    except KeyError:
        raise SourceMissing(_not_configured(name))


def _signal_source(dashboard, signal):
    """The trace or monitor source a dashboard's panels of that signal read.

    A pin is the SOURCE, not the log side of it. Pinned to a cluster that
    serves logs, traces and monitors, a board reads all three from that
    cluster; its trace panels used to read whichever trace source was
    registered first whatever the board was pinned to — measured on the
    demo, a trace list for api-gateway went empty on a board pinned to the
    cluster holding three of its traces, because the oldest trace source was
    a Tempo with no such service.

    Where the pinned source does not serve the signal — a Loki serves no
    traces — the panels read every source of it, because there is nowhere
    else they could come from, and each panel says which answered. A pin
    naming a source nothing serves any more is refused for these panels as
    it is for the log ones.
    """
    hub = getattr(current_app, "hub", None)
    if hub is None:
        return None
    lookup = getattr(hub, signal)
    name = _pinned_name(dashboard)
    if not name:
        return lookup()
    try:
        return lookup(name)
    except KeyError:
        if hub.signals_of(name):
            return lookup()
        raise SourceMissing(_not_configured(name))


def _not_configured(name):
    return (f"This dashboard reads from the source '{name}', which is not "
            f"configured. Check the configuration page.")


def _fanned_out(source):
    """The members of a fan-out, or None for a source that is one thing.

    By the SHAPE of `sources` and not its presence: a source that answers
    every attribute — a test's dead stand-in does — must read as one source
    that is down, not as a fan-out over a function.
    """
    members = getattr(source, "sources", None)
    return list(members) if isinstance(members, (list, tuple)) else None


def _members(source):
    """The names behind a source: a fan-out's members, or the source itself."""
    return [member.name for member in (_fanned_out(source) or [source])]


def _attribution(source, answer=None):
    """Which sources a panel's rows came from, and which were asked and did
    not answer, as {"sources": [...], "missing_sources": [...]}.

    On every trace and monitor panel, so that a doubled count — two stored
    rows over one cluster, each answering the same spans — is two names
    under one number rather than one number that is quietly double, and a
    board pinned to a source that serves no traces says whose traces these
    are. The log side carries the same thing as the page's `sources`.
    """
    members = _members(source)
    answered = [str(name) for name in (getattr(answer, "sources", ()) or ())]
    if not answered:
        missing = {str(name)
                   for name in (getattr(answer, "missing_sources", ()) or ())}
        answered = [name for name in members if name not in missing]
    return {"sources": answered,
            "missing_sources": [name for name in members
                                if name not in answered]}


def _log_attribution(source, result):
    """Which log sources the board's counts were added up from, and how
    much each gave: [{name, total, failed}]. The fan-out fills it in; a
    single source names itself, so the page has one shape to draw."""
    rows = [dict(entry) for entry in (getattr(result, "sources", ()) or ())]
    if rows:
        return rows
    return [{"name": source.name, "total": result.total,
             "failed": bool(result.failed)}]


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


class TimeRangeError(ValueError):
    """The window this request asks for cannot be built."""


def _requested_window(args=None):
    """The window this request is asking for, built ONCE.

    `start` and `end` name an absolute range — "last Tuesday 14:00 to 15:00",
    which is the one question the five relative options cannot be pointed at
    and the reason anybody opens a dashboard a second time. Without them the
    relative `time_range` string resolves exactly as it always has.

    Returns (window, time_range). `time_range` is None for an absolute range
    because it is ECHOED to the client, and echoing "1h" beside bounds from
    last Tuesday would describe a view nobody is looking at.

    Aligned — `TimeWindow.between` — because every panel this window feeds is
    an aggregation, where alignment is invisible and stabilises the cache key.
    A panel listing raw records would need `exact` instead; there is none on a
    dashboard, and the day there is, it needs its own window and not this one.
    """
    args = request.args if args is None else args
    time_range = args.get("time_range") or timerange.DEFAULT_RANGE
    start, end = args.get("start"), args.get("end")
    if not start and not end:
        # A relative range nobody can read is refused rather than defaulted.
        # `TimeWindow.of` answers the last hour for anything `parse_range`
        # cannot parse, and this route's own picker started emitting one:
        # `?time_range=custom` is what the address bar holds while the two
        # absolute boxes are being filled in, and a link copied at that moment
        # opened on the last hour with "custom" echoed back and no warning.
        # An hour of real data under a control naming a different window is
        # the failure the absolute refusal above exists to prevent.
        if timerange.parse_range(time_range) is None:
            raise TimeRangeError(
                f"'{time_range}' is not a time range. Use one of the offered "
                f"ranges (for example 1h or 24h), or a start and an end.")
        return TimeWindow.of(time_range), time_range
    # Half a range is refused rather than completed from `now`. "From last
    # Tuesday 14:00 until whenever this page loaded" is a window nobody asked
    # for, and it would be indistinguishable on screen from one they did.
    if not (start and end):
        raise TimeRangeError("An absolute range needs both a start and an "
                             "end. Only one was given.")
    parsed_start = timerange.parse_iso(start)
    parsed_end = timerange.parse_iso(end)
    if parsed_start is None or parsed_end is None:
        raise TimeRangeError("That start or end could not be read. Use an ISO "
                             "timestamp, for example 2026-09-09T14:00:00Z.")
    if parsed_end <= parsed_start:
        raise TimeRangeError("The start of a range must be before its end.")
    return TimeWindow.between(parsed_start, parsed_end), None


def _window_payload(window):
    """The bounds actually queried, for the client to show and to share.

    Echoed for every request, relative or absolute: `time_range` alone cannot
    say what "1h" resolved to, and the alignment moves both ends.
    """
    return {"start": window.start.isoformat(), "end": window.end.isoformat()}


def _baseline_query(dashboard, allowed, window, narrow=None):
    """The same query over the window immediately before this one.

    A count on its own says nothing: 1,700 errors is only meaningful next to
    what it was yesterday. Returns None if the query cannot be built — the
    comparison is a nice-to-have and must never take the dashboard down.

    The window is THREADED IN rather than rebuilt here from the time-range
    string. Rebuilding it was the same defect D4 had, on the same four
    numbers: with an absolute range there is no string to rebuild from, so
    `TimeWindow.of(time_range)` fell back to the default hour and "the
    previous period" quietly became the hour before NOW. A reviewer reading
    last Tuesday 14:00-15:00 would have been told "+180% vs previous period"
    about 13:00-14:00 today, an hour with no incident in it — and the whole
    function is inside a try/except that logs and returns None, so nothing on
    the page would have said a word.
    """
    try:
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


def _trace_panels(panels, window, scope, dashboard=None):
    """Fill in the trace-backed panels.

    Traces are a different source, so they cannot ride the log batch — one
    extra round trip, taken once no matter how many trace panels there are.
    A missing or failing trace backend costs those panels, never the page.

    Read from the board's own source where it serves traces, and from every
    trace source otherwise (`_signal_source`).
    """
    wanted = [p for p in panels if p["type"] == "trace_services"]
    if not wanted:
        return {}

    try:
        traces = _signal_source(dashboard, "traces")
    except SourceMissing as exc:
        return {p["id"]: {"error": str(exc)} for p in wanted}
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
    answered = _attribution(traces, services)
    for panel in wanted:
        ranked = sorted(services, key=orders[panel["sort"]], reverse=True)
        rendered = {"rows": [s.to_dict() for s in ranked[:panel["size"]]],
                    **answered}
        if partial:
            rendered["partial"] = True
            rendered["warnings"] = notes
        out[panel["id"]] = rendered
    return out


#: Which TraceQuery each trace-list view asks for.
#:
#: "errors" is not an ordering — it is the newest list with the successful
#: requests taken out — so the mapping is written once here rather than as an
#: `if` in the filler that the next view would be forgotten in.
_TRACE_LIST_QUERIES = {
    "slowest": (SORT_SLOWEST, False),
    "recent": (SORT_RECENT, False),
    "errors": (SORT_RECENT, True),
}


def _empty_trace_list_reason(traces, scope, service, window, listed):
    """Why a trace list came back empty, when "empty" is not the answer.

    Asked ONLY after an empty answer — the same bargain
    `trace_routes._reaches_no_store` strikes — so a source whose service list
    costs a round trip pays for it when there is something to explain and not
    on every load of a board that works. `listed` caches that list across the
    panels of one dashboard load.

    Two reasons, in the order of what the reader can do about them.

    The STORE boundary first. `traces:read` says whether a role may read
    traces at all and the service rule says which services; this says which
    stores, and it is the one this panel never asked. Measured on the lab
    through the route, Jaeger, service=billing-api, 24h: a role whose stores
    match nothing got rows=0 and error=None, and the card drew "No trace
    through billing-api in this window" — a role boundary rendered as a quiet
    service. The traces page has answered the same role with a sentence about
    its role all along.

    Then the gap in what the source can list. A trace list is built from the
    span where a request ENTERED a service, so a service that is only ever
    called by another one has none. Measured on the lab's Elasticsearch trace
    indices at 24h: `postgres` (2,579 spans, all Client), `redis` (1,794),
    `elasticsearch` (1,177) and `stripe-api` (873) each answer a trace list
    with nothing at all — four of the nine services the trace_services panel
    on the SAME board ranks by traffic. "No trace through postgres in this
    window" printed beside a bar saying postgres did 1,048 spans is the
    loudest kind of wrong, and an author picking a service from that bar
    chart has no way to know which half of it this panel can answer for.

    Silence stays silence when the source does not list the service: a window
    in which nothing ran is a real answer and must not be dressed as a fault.
    """
    if trace_routes._reaches_no_store(traces, scope):
        return trace_routes.NO_STORE_SUGGESTION.format(source=traces.name)

    if not traces.supports(Capability.SERVICE_LIST):
        return None
    if "names" not in listed:
        try:
            listed["names"] = {getattr(found, "name", None)
                               for found in traces.services(window, scope)}
        except Exception as exc:
            # A service list that could not be read is not evidence of
            # anything, least of all of a gap. Same reasoning as the except
            # branch in `_reaches_no_store`: an outage must not be reported
            # as a property of the data.
            current_app.logger.warning(f"Trace service list failed: {exc}")
            listed["names"] = set()
    if service not in listed["names"]:
        return None

    return (f"This source lists '{service}' but returned no trace that "
            f"entered through it in this window. A service only ever called "
            f"by another one — a database, a cache — has no entry span to "
            f"list, so this may be a gap in what can be read here rather "
            f"than a quiet window.")


def _trace_list_panels(panels, window, scope, dashboard=None):
    """Fill in the trace-LIST panels: individual traces, one service each.

    A different question from `_trace_panels` and a different request. That
    one calls `traces.services(...)`, which answers "how much traffic, how
    many errors, per service"; a list of individual requests comes from
    `traces.search(...)`, which is a separate adapter method and a separate
    round trip. It cannot ride the other panel's call, so the cost is one
    request per distinct question on the board — panels asking the same
    thing share one, which is what the grouping below is for.

    Every panel names a service (`panels.normalise` refuses one that does
    not), and that is what keeps the cost honest on Jaeger: with no service
    named it searches every service it knows, measured at 8 HTTP requests
    against the lab's 7-service Jaeger versus 1 with a service named.

    `traces:read` and the service boundary are checked HERE, at the moment
    the panel is filled, the same shape `_monitor_panels` uses: a shared
    dashboard must not become a way to read traces for a service a role was
    never granted, and a colleague who lacks the permission must still be
    able to read the rest of the board. So the PANEL is refused with a
    reason, never the dashboard.
    """
    wanted = [p for p in panels if p["type"] == "trace_list"]
    if not wanted:
        return {}

    def refuse(reason, only=None):
        return {p["id"]: {"error": reason} for p in (only or wanted)}

    if not scope.has("traces:read"):
        return refuse("Traces need the traces:read permission, which this "
                      "role does not have. The rest of this dashboard is "
                      "unaffected.")

    try:
        traces = _signal_source(dashboard, "traces")
    except SourceMissing as exc:
        return refuse(str(exc))
    if traces is None or not traces.supports(Capability.TRACE_SEARCH):
        return refuse("No trace backend that can list traces is configured.")

    if scope.trace_is_empty:
        # The third boundary, and the one this panel shipped without. A role
        # with no trace store assigned is not a role looking at a quiet
        # service — and an empty table is what it got. Refused before the
        # search rather than after it: there is nothing to ask.
        return refuse(trace_routes.NO_STORES_ASSIGNED)

    out, groups, listed = {}, {}, {}
    for panel in wanted:
        service = panel["service"]
        if not trace_routes._may_see_service(scope, traces, service):
            # Named, because the reader is the person who has to ask for it.
            # An empty table here would read as "that service ran nothing".
            out[panel["id"]] = {"error": (
                f"Your role cannot see traces for '{service}'. That is a "
                f"boundary, not an empty window.")}
            continue
        groups.setdefault(
            (service, panel["view"], panel["size"]), []).append(panel)

    for (service, view, size), members in groups.items():
        sort, only_errors = _TRACE_LIST_QUERIES[view]
        query = TraceQuery(window=window, service=service, sort=sort,
                           only_errors=only_errors, limit=size)
        try:
            found = traces.search(query, scope)
        except Exception as exc:
            # The reason travels. Tempo refuses a window over 168 hours
            # outright — measured on the lab, the dashboard's own "Last 7
            # days" comes back "range specified by start and end exceeds
            # 168h0m0s" — and a card reading "no traces" would send the
            # reader looking for a service that had stopped.
            current_app.logger.warning(f"Trace list panel failed: {exc}")
            out.update(refuse(f"Traces could not be read: {exc}", members))
            continue

        if not found:
            reason = _empty_trace_list_reason(traces, scope, service, window,
                                              listed)
            if reason:
                out.update(refuse(reason, members))
                continue

        rows = []
        for summary in found:
            # The fan-out stamps this; a single source does not know it is
            # being asked by name. Filled in for the same reason the traces
            # page fills it: the row's link carries the source, and without
            # it the detail page looks in whichever store is first and
            # reports a Jaeger trace as missing.
            if getattr(summary, "source", None) is None:
                summary.source = traces.name
            rows.append(summary.to_dict())

        completeness = trace_routes._completeness(found)
        answered = _attribution(traces, found)
        for panel in members:
            rendered = {"rows": rows, **answered}
            if completeness["partial"]:
                # Tempo and Jaeger sort the rows they fetched rather than the
                # window, and a store that did not answer is not a quieter
                # hour. `_completeness` is what already carries both.
                rendered["partial"] = True
                rendered["warnings"] = completeness["warnings"]
            out[panel["id"]] = rendered
    return out


def _count_disagreement(page, headline):
    """The sentence a records footer owes its reader when the two counts differ.

    "Showing 5 of 15,402 matching records" and the total hits on the stat card
    above it answer the SAME question — how many records this board's query
    matches — by two different routes: this panel's SEARCH reports its hit
    count, the aggregation batch that drew every chart reports its total. On a
    healthy backend they agree to the record, and the panel was written so the
    table and the bars could not disagree.

    They can still disagree above the panel's head. Elasticsearch answers 200
    with what the shards that worked found, so an index whose mapping a terms
    aggregation cannot read drops OUT of the aggregation's total while the
    search keeps it. Measured on the lab over `*-logs-*` at 24h:
    total_hits 13,898 against a records total of 14,998, the 1,100 records of
    `bad-logs-000001`, whose `level` is mapped as text; with `q=level:ERROR`
    on, 1,222 against 1,316. Both numbers looked exact and nothing on either
    card said why they were not the same number.

    So the card says it. NOT by marking itself `partial`: this panel's own
    answer is the complete one — it is the board's count that came back short
    — and claiming otherwise would trade one wrong number for another. The
    reason the aggregation gave travels with the sentence, because "5 of 9
    shards failed: Fielddata is disabled on [level] in [bad-logs-000001]" is
    the thing an administrator can actually act on.

    Only when this panel's total is a COUNT. Loki returns up to a limit and
    stops, so its total is a floor, the footer never claims "of N" for it, and
    comparing a floor against a count would fire on every Loki board.
    """
    if headline is None or not page.counted:
        return None
    total = getattr(headline, "total", None)
    if total is None or total == page.total:
        return None
    sentence = (f"This search found {page.total:,} matching records and the "
                f"board's own count says {total:,}: the two were measured "
                f"different ways and one of them is short.")
    reasons = [str(note) for note in (getattr(headline, "warnings", ()) or ())
               if note]
    return " ".join([sentence] + reasons)


def _records_panels(panels, query, dashboard, scope, headline=None):
    """Fill in the records panels: the newest records the board matches.

    ONE search for however many records panels the board holds. They all ask
    the same question — the dashboard's effective query over the window,
    newest first — so the only thing that differs is how many rows each shows,
    and the search runs at the largest of them and is sliced. Two records
    panels are one round trip, not two.

    The query is the SAME `LogQuery` the charts were built from, ad-hoc filter
    and all: a records table that disagreed with the chart beside it is worse
    than no table, and `q` is the door that disagreement would come through.
    The window is the charts' window too, alignment included. `TimeWindow.of`
    widens a range by up to one bucket and `query.py` says to use `exact` when
    listing raw records — which is right for a page of records on its own, and
    wrong here: measured on the lab at 24h, the aligned window holds 5,015
    records and the exact one 5,005, and those ten records are counted by
    every bar on the board. The list has to hold what the bars count.

    `total` and `counted` both ship, because the footer is a claim about the
    backend. Measured at 24h over the lab: Elasticsearch 10 of 5,015 with
    counted=True, VictoriaLogs 10 of 681 counted=True, and Loki 10 records
    with total=10 and counted=False — Loki returns up to a limit and stops,
    so "10 of 10" would be a total nobody measured.

    `headline` is the aggregation the board's stat cards were drawn from, and
    it is here for one reason: two exact-looking answers to one question have
    to agree or say why not. `_count_disagreement` is where that is decided.
    """
    wanted = [p for p in panels if p["type"] == "records"]
    if not wanted:
        return {}

    limit = max(panel["size"] for panel in wanted)
    try:
        page = _logs(dashboard).search(
            LogQuery(window=query.window, text=query.text,
                     containers=query.containers, limit=limit,
                     fields=DEFAULT_LOG_FIELDS, filter=query.filter),
            scope)
    except Exception as exc:
        # A search that failed is not a window with nothing in it, and this
        # one runs after the aggregation batch has already answered — so the
        # rest of the board is on screen and only this card is empty.
        #
        # The backend's own words travel, the way the trace filler beside
        # this one already sends Tempo's 168-hour refusal through. A logged
        # reason is a reason the reader never sees: Loki answers a wide range
        # HTTP 400 with "the query time range exceeds the limit (query
        # length: 2161h0m0s, limit: 30d1h)", which names the fix, and "The
        # records could not be read." names nothing anybody can act on.
        current_app.logger.warning(f"Records panel failed: {exc}")
        return {p["id"]: {"error": f"The records could not be read: {exc}"}
                for p in wanted}

    rows = [record.to_dict() for record in page.records]
    notes = [str(note) for note in (page.warnings or ()) if note]
    disagreement = _count_disagreement(page, headline)
    if disagreement:
        # First: it is a statement about the footer directly under it.
        notes.insert(0, disagreement)

    out = {}
    for panel in wanted:
        rendered = {
            "rows": rows[:panel["size"]],
            "total": page.total,
            # Not inferred from the numbers: `len(rows) == total` is true of
            # a quiet hour on Elasticsearch too, and calling that uncounted
            # would print "this source does not report a total" about a
            # source that does.
            "counted": bool(page.counted),
        }
        if notes:
            rendered["warnings"] = notes
        if page.partial:
            rendered["partial"] = True
        out[panel["id"]] = rendered
    return out


#: Panel kinds a monitor source answers.
_MONITOR_PANELS = ("monitors", "monitor_certificates")

#: Down first, then the checks nothing has reported, then the healthy ones.
#:
#: A monitor whose agent has gone quiet is NOT filed with the ones that
#: passed. "Unknown" is the state this whole signal exists to make visible —
#: a check that has stopped running looks exactly like a quiet night from
#: every other panel on the board — so it sorts above "up" and never below
#: it.
_STATUS_ORDER = {DOWN: 0, UNKNOWN: 1, UP: 2}


def _monitor_availability(monitor):
    """Availability over the window, counted in RUNS rather than in buckets.

    `MonitorPoint.checks` is how many runs a bucket covers and `.down` how
    many of them failed, so the sums over the series are the window's own
    arithmetic. Counting buckets instead would call a bucket holding six runs
    of which one failed one failure out of one — the reasoning
    `monitor_routes._availability` sets out at length, borrowed rather than
    re-derived.

    `None` when nothing ran, never 100.0: zero of zero is not "available",
    and "100%" printed over an agent that has been silent all week is the
    loudest possible lie on the board. The check count ships beside the
    percentage for the same reason — 100% of 12 checks and 100% of 2,832 are
    not the same claim.
    """
    checks = sum(point.checks for point in monitor.series)
    down = sum(point.down for point in monitor.series)
    return {"checks": checks, "down": down,
            "availability": (round(100.0 * (checks - down) / checks, 2)
                             if checks else None)}


def _monitor_row(monitor, view):
    row = {
        "id": monitor.id,
        "name": monitor.name or monitor.id,
        "status": monitor.status,
        "type": monitor.type,
        "location": monitor.location,
        "checked_at": (monitor.checked_at.isoformat()
                       if monitor.checked_at else None),
        "duration_ms": (round(monitor.duration_ms, 1)
                        if monitor.duration_ms is not None else None),
        "error": monitor.error,
        "source": monitor.source,
    }
    if view == "availability":
        row.update(_monitor_availability(monitor))
    return row


def _certificate_row(monitor):
    certificate = monitor.certificate
    return {
        "id": monitor.id,
        "name": monitor.name or monitor.id,
        "location": monitor.location,
        "common_name": certificate.common_name,
        "issuer": certificate.issuer,
        "not_after": (certificate.not_after.isoformat()
                      if certificate.not_after else None),
        "days_remaining": certificate.days_remaining,
        "expired": certificate.expired,
        # Computed here, exactly as the Monitors page computes it, so the
        # dashboard cannot grow a second set of expiry bands.
        "state": monitor_routes._certificate_state(certificate),
        "key": certificate.key_description,
        # Tri-state, and `None` means the source did not say — Heartbeat
        # never does. The renderer must print nothing for it: rendered as
        # "not verified" it would be a finding invented on every row.
        "verified": certificate.verified,
        "tls_mode": monitor.tls_mode,
    }


def _monitor_panels(panels, scope, window, dashboard=None):
    """Fill in the monitor-backed panels.

    Monitors are a third source, so like traces they cannot ride the log
    batch: one extra round trip for the listing however many status panels
    the board holds, and a second only when a certificate panel is on it.
    A missing or failing monitor backend costs those panels, never the page.

    Read from the board's own source where it serves monitors, and from
    every monitor source otherwise (`_signal_source`) — the merged view
    these panels have always read, because asking one region at a time is
    how an outage in the other one is missed.

    `monitors:read` is checked HERE, on the scope, at the moment the panel is
    filled — not on the route, which asks only about `dashboard:*`. Both
    halves of that matter. A shared dashboard must not become a way to see
    monitors a role was never granted, which is why the check exists at all;
    and a colleague who lacks the permission must still be able to read the
    rest of the board, which is why it refuses THIS PANEL with a reason
    instead of widening the dashboard's visibility rule.

    The listing itself is read under the monitors' own scope rather than the
    viewer's log scope, which is what `monitor_routes._scope` builds. A
    role's index patterns are about log data;
    `ElasticsearchMonitorSource.containers` says so and refuses to filter by
    them, and a dashboard that did would show an empty grid to almost
    everybody — a failure wearing the clothes of "nothing is down".
    """
    wanted = [p for p in panels if p["type"] in _MONITOR_PANELS]
    if not wanted:
        return {}

    def refuse(reason, only=None):
        return {p["id"]: {"error": reason} for p in (only or wanted)}

    if not scope.has("monitors:read"):
        return refuse("Monitors need the monitors:read permission, which "
                      "this role does not have. The rest of this dashboard "
                      "is unaffected.")

    try:
        source = _signal_source(dashboard, "monitors")
    except SourceMissing as exc:
        return refuse(str(exc))
    if source is None or not source.supports(Capability.MONITOR_LIST):
        return refuse("No monitor backend is configured.")

    out = {}
    listings = [p for p in wanted if p["type"] == "monitors"]
    if listings:
        try:
            # Carries the monitor scope, and says whether the per-check
            # series came with it: a source written against the two-argument
            # interface has no history to give, and availability counted over
            # the series it did not send is a number nobody measured.
            page, history = monitor_routes._series_listing(source, window)
        except Exception as exc:
            current_app.logger.warning(f"Monitor panel failed: {exc}")
            out.update(refuse("Monitor data could not be loaded.", listings))
        else:
            ordered = sorted(
                page.monitors,
                key=lambda m: (_STATUS_ORDER.get(m.status, _STATUS_ORDER[UNKNOWN]),
                               (m.name or m.id).lower()))
            notes = [str(note) for note in (page.warnings or ()) if note]
            answered = _attribution(source, page)
            for panel in listings:
                # The view reaches the client on the panel DEFINITION, which
                # every filled panel is built from — repeating it here was a
                # second copy of one fact, and a mutation that deleted it
                # changed nothing, which is how it was found.
                view = panel.get("view") or MONITOR_VIEWS[0]
                if view == "availability" and not history:
                    # Not "0 of 0 checks", which the grid draws as "no check
                    # ran" — beside a timestamp from a second ago and a green
                    # "up" chip. That cell contradicts itself and it asserts
                    # the agent is silent when it is not. Refused in the
                    # source's name, the shape a missing capability already
                    # takes, and only this VIEW of the panel: the same source
                    # answers "is it up now" perfectly well.
                    out[panel["id"]] = {"error": (
                        f"{source.name} does not keep monitor history, so "
                        f"availability over this window cannot be counted. "
                        f"That is a gap in what can be read here, not a run "
                        f"of checks that all passed. The status view of this "
                        f"panel still works.")}
                    continue
                rendered = {"counts": page.counts,
                            "rows": [_monitor_row(m, view) for m in ordered],
                            **answered}
                if page.partial:
                    # One source of several not answering is not "those
                    # checks are all passing": it is a shorter list nobody
                    # can read as one.
                    rendered["partial"] = True
                    rendered["warnings"] = notes
                out[panel["id"]] = rendered

    certificates = [p for p in wanted if p["type"] == "monitor_certificates"]
    if certificates:
        if not source.supports(Capability.TLS_CERTIFICATES):
            out.update(refuse(
                f"{source.name} does not report TLS certificates. That is a "
                f"gap in what can be read here, not evidence that the "
                f"endpoints have none.", certificates))
        else:
            try:
                seen = source.certificates(window, monitor_routes._scope())
            except Exception as exc:
                current_app.logger.warning(f"Certificate panel failed: {exc}")
                out.update(refuse("TLS certificates could not be loaded.",
                                  certificates))
            else:
                # What expires first, first — the only order this list is
                # read in. A monitor whose expiry the source did not give
                # sorts last rather than as "expires today".
                rows = sorted(
                    (_certificate_row(m) for m in seen if m.certificate),
                    key=lambda r: (r["days_remaining"] is None,
                                   r["days_remaining"] or 0))
                # The fan-out keeps a member that could not be asked out of
                # the merge, so without this the panel drew a list missing a
                # whole region's endpoints and said nothing — and an empty
                # one reads as "none of these checks use TLS", which is a
                # claim about the endpoints made when nobody could be asked.
                short = [str(note)
                         for note in (getattr(seen, "warnings", ()) or ())
                         if note]
                answered = _attribution(source, seen)
                for panel in certificates:
                    rendered = {
                        "rows": rows,
                        "warning_days": monitor_routes.EXPIRY_WARNING_DAYS,
                        "critical_days": monitor_routes.EXPIRY_CRITICAL_DAYS,
                        **answered,
                    }
                    if getattr(seen, "missing_sources", ()) or short:
                        rendered["partial"] = True
                        rendered["warnings"] = short
                    out[panel["id"]] = rendered
    return out


#: Panel kinds WDash's own alert history answers.
_ALERT_PANELS = ("alerts", "alerts_undelivered")


def _alert_panels(panels, window, scope):
    """Fill in the panels off WDash's own alert history.

    A fourth source, and the cheapest one on the board: it is the store the
    application is already sitting on, so these panels need no log, trace or
    monitor backend and a deployment with none of them can still carry them.
    At most four queries however many alert panels a board holds — the rule
    names, the window's rows, how many fired and how many of those reached
    nobody — and none at all if it holds none.

    `monitors:read` is checked HERE, on the scope, at panel-fill time, for
    the same two reasons `_monitor_panels` checks it: a shared dashboard must
    not become a way to read alert history a role was never granted, and a
    colleague who lacks the permission must still be able to read the rest of
    the board, so it refuses THIS PANEL with a reason rather than widening
    the dashboard's visibility rule. The permission is `monitors:read`
    because that is the one the Alerts page itself asks for
    (`alert_routes.history`) — a board that invented a second answer to "who
    may see what fired" would be a second place to get it wrong.

    The window is honoured in the STORE (`since`/`until`), not by filtering
    rows here: "the last 100 alerts, of which these fell in the hour" is a
    different and much more expensive question than "the alerts in this
    hour", and it gets the row count wrong as soon as the window is quiet.

    And a board with no alert RULE on it is told so rather than shown a zero.
    "Nothing fired" and "nothing can fire" are the two readings of the same
    empty answer, and the one that matters — alerting is not configured — is
    the one a 0 hides.
    """
    wanted = [p for p in panels if p["type"] in _ALERT_PANELS]
    if not wanted:
        return {}

    def refuse(reason, only=None):
        return {p["id"]: {"error": reason} for p in (only or wanted)}

    if not scope.has("monitors:read"):
        return refuse("Alert history needs the monitors:read permission, "
                      "which this role does not have — the same permission "
                      "the Alerts page asks for. The rest of this dashboard "
                      "is unaffected.")

    store = getattr(current_app, "store", None)
    if store is None:
        return refuse("WDash's own store is not available, so what fired "
                      "cannot be read. That is a gap in what can be read "
                      "here, not a window in which nothing fired.")

    try:
        # Borrowed from the Alerts page unchanged, so a row reads "Payments
        # API" rather than a pair of uuids. EVERY rule, including the
        # disabled ones: history written by a rule somebody has since
        # switched off must still read by name.
        rules = {rule["id"]: rule for rule in store.rules.all()}
        # What can fire, which is a different list and the one the guard
        # below is about. The evaluator that writes this history runs
        # `rules.all(enabled_only=True)` (alerts/runner.py), so a rule that
        # is switched off is not a rule that can have fired.
        live = store.rules.all(enabled_only=True)
    except Exception as exc:
        current_app.logger.warning(f"Alert panel failed: {exc}")
        return refuse("Alert history could not be read.")

    if not rules:
        return refuse("No alert rule is configured, so nothing can have "
                      "fired. That is a gap in what is set up, not a quiet "
                      "window — configure a rule on the Alerts page and this "
                      "panel starts answering.")

    if not live:
        # The same failure one step along, and the one the first guard let
        # through: asking `rules.all()` counts a switched-off rule as
        # configured, so a board whose rules are all off drew an empty table
        # under "No alert fired in this window" and a 0 beside it, for a
        # store in which nothing can fire.
        return refuse(f"{len(rules):,} alert rule{'' if len(rules) == 1 else 's'} "
                      f"{'is' if len(rules) == 1 else 'are'} configured and "
                      f"every one of them is switched off, so nothing can "
                      f"fire. That is a gap in what is set up, not a quiet "
                      f"window — switch one on from the Alerts page and this "
                      f"panel starts answering.")

    history = store.alert_history
    listings = [p for p in wanted if p["type"] == "alerts"]
    numbers = [p for p in wanted if p["type"] == "alerts_undelivered"]
    try:
        fired = history.count(since=window.start, until=window.end)
        # One search for however many listing panels the board holds, at the
        # largest of them, sliced per panel — the shape `_records_panels`
        # already uses.
        rows = (history.recent(limit=max(p["size"] for p in listings),
                               since=window.start, until=window.end)
                if listings else [])
        undelivered = (history.count(undelivered_only=True,
                                     since=window.start, until=window.end)
                       if numbers else 0)
    except Exception as exc:
        current_app.logger.warning(f"Alert panel failed: {exc}")
        return refuse("Alert history could not be read.")

    def row(entry):
        rule = rules.get(entry["rule_id"]) or {}
        return {
            "at": entry["at"].isoformat() if entry["at"] else None,
            "rule": rule.get("name") or entry["rule_id"],
            # The name it had when it fired, which is what the row is about:
            # history is most often read about something since renamed or
            # deleted.
            "subject": entry.get("subject_label") or entry["subject"],
            "transition": entry["transition"],
            "delivered": bool(entry["delivered"]),
            "delivery_error": entry.get("delivery_error"),
        }

    out = {}
    for panel in listings:
        out[panel["id"]] = {"rows": [row(e) for e in rows[:panel["size"]]],
                            "total": fired}
    for panel in numbers:
        out[panel["id"]] = {
            "number": undelivered,
            # The number is meaningless without what it is out of, and the
            # panel says which definition of "never delivered" it is using:
            # the Alerts page's own, the last word on each rule and subject,
            # so the board and the page cannot report two different numbers
            # for one question.
            "question": (f"of the {fired:,} alert"
                         f"{'' if fired == 1 else 's'} in this window "
                         f"reached nobody"),
            "fired": fired,
        }
    return out


def _without_log_containers(dashboard, scope, window, time_range, failure, status):
    """Answer the panels the log source is not needed for, and say why the
    rest are empty. Returns (payload, status) for jsonify.

    The log source decided the whole page. Six things that have nothing to do
    with a trace panel took it down with them: the log backend unreachable
    while resolving containers (503, and the client's `showLoadError` then
    wipes the grid), the dashboard naming a source that is gone (400), a
    scope that reaches none of the dashboard's containers (200 with
    `panels: []`, an empty grid under one sentence), a filter the query
    language refuses (400), a search that ran and failed (502) and a search
    that raised on the way (an HTML 500 out of Flask, with no payload at
    all). The last three are the ones a running worker meets: an
    Elasticsearch catalogue that has fetched its index list once keeps
    serving it through an outage, so `_targets` succeeds and the failure
    arrives at the search.

    A trace panel needs the window and the caller's scope and nothing else —
    `_trace_panels` has had that shape since traces arrived — and the monitor
    and certificate panels are that same shape again, which is why they are
    filled here by the same two lines and not by a second copy of this
    function. An operator opens a board in an Elasticsearch outage precisely
    to tell a dead shipper from a quiet night, and the monitor grid is the
    panel that answers it: until this existed it was the FIRST thing to
    disappear in that outage, because `_targets` resolves the log source
    before any panel is filled. The alert panels coming after are the same
    shape once more.

    So: fill what can be filled, and give every panel that cannot a reason of
    its own instead of an empty card.

    The status code is only lowered to 200 when something CAN be answered. A
    board of log panels alone has nothing to show, and saying so in the status
    line — which is what the client's error path reads — beats a 200 carrying
    an empty grid. The counts are left OUT of the payload rather than sent as
    zeros: `total_hits: 0` under a dead backend is the same lie the panels
    were just stopped from telling, and the client prints an em dash for a
    number that did not run.
    """
    try:
        panels = dashboard.get_panels()
    except PanelError:
        # The panel list itself is unreadable; there is nothing to fill and
        # the failure in hand is still the true one.
        return failure, status

    if status != 200 and all(needs_logs(panel) for panel in panels):
        return failure, status

    reason = failure.get("error") or "The log source could not be reached."
    standalone = [panel for panel in panels if not needs_logs(panel)]
    # One line per signal this route can answer, over the panels the log
    # source is not needed for. `standalone` rather than `panels`, so a
    # filler is never handed a panel that belongs to another source.
    filled = _trace_panels(standalone, window, scope, dashboard)
    filled.update(_trace_list_panels(standalone, window, scope, dashboard))
    filled.update(_monitor_panels(standalone, scope, window, dashboard))
    filled.update(_alert_panels(standalone, window, scope))
    for panel in panels:
        if needs_logs(panel):
            filled[panel["id"]] = {"buckets": [], "error": reason}

    payload = dict(failure)
    payload.update({
        "panels": _panel_results(panels, AggregationResult(), filled),
        "previous_period": None,
        # Not `evaluate_thresholds` over zeros: "within thresholds" is a claim
        # about numbers, and there are none.
        "status": None,
        "thresholds": dashboard.thresholds,
        "level_queries": _level_queries(),
        "time_range": time_range,
        "window": _window_payload(window),
    })
    return payload, 200


def _panel_aggregations(panels, window):
    """Translate the panel list into neutral aggregations.

    Each aggregation is named after its panel id, so results come back keyed by
    panel with no positional bookkeeping — which matters once panels can be
    reordered and deleted.
    """
    aggregations = []
    for panel in panels:
        if panel["type"] not in ("timeseries", "terms", "count"):
            continue          # answered by another source
        if panel["type"] == "count":
            # A single number rides the batch as a terms aggregation over
            # its own field, named after the panel like every other one. Not
            # a search (a Loki total is the page size), not the batch's own
            # `total` (on Loki that is the largest aggregation's sum, and a
            # date histogram there overcounts), and not a new aggregation
            # type. It carries the same `missing` label the terms panel
            # beside it uses, and that label is what makes the CUT visible:
            # `_count_panels` reads a short bucket list as a complete one,
            # which is only sound while the source answers with a bucket per
            # row it asked for. VictoriaLogs cuts server-side (`| sort by
            # (hits desc) | limit N`) and its adapter then drops every
            # returned row carrying no value for the field, so an unlabelled
            # list came back SHORT of the ceiling however hard it was cut —
            # and a host below the cut was drawn as a confident 0. Measured
            # on the lab at 24h over `host` (15 hosts, 76 records with none):
            #
            #     size  2  3  5  50      unlabelled  1  2  4  15
            #                            labelled    2  3  5  16
            #
            # The cost is the one the terms panel already pays: records with
            # no value are counted under a name, and an author may ask this
            # panel for that name — where it now answers the same number the
            # terms panel draws beside it, rather than two different ones.
            aggregations.append(Terms(
                name=panel["id"], field=panel["field"], size=COUNT_VALUES,
                missing="unknown" if panel["field"] != "severity" else None))
        elif panel["type"] == "timeseries":
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


#: How many values of the field a single-number panel's terms aggregation
#: asks for.
#:
#: It is a ceiling on how far down the list the panel can find the value it
#: was asked about, and NOT a licence to guess past it: a value that is not
#: among these is refused by name rather than reported as zero. Fifty is the
#: same bound a terms panel may be set to, so the number panel can reach any
#: value a terms panel on the same board could have drawn.
COUNT_VALUES = MAX_SIZE


def _merged_sources(dashboard):
    """The member names of a fan-out log source, or () for a single source.

    A board reading every source at once gets `FanOutLogSource`, whose
    `aggregate` merges the members' bucket lists BY KEY — so the list a panel
    reads is a union of up to one list per source, and its length is nobody's
    cut. `_count_panels` needs to know that to say a true sentence about it.
    """
    try:
        source = _logs(dashboard)
    except SourceMissing:
        return ()
    return tuple(getattr(member, "name", "?")
                 for member in getattr(source, "sources", ()) or ())


def _count_panels(panels, result, merged=()):
    """Fill in the single-number panels from the batch that already ran.

    No round trip of its own: the panel's terms aggregation went out with
    every other panel's, named after the panel, so this is a lookup in the
    result — which is what makes a number affordable on a board that already
    has six charts on it.

    The whole panel is one claim, so the four ways it can end are separate
    on purpose:

      * the value is there                  -> the count
      * the aggregation could not run       -> its reason, never a number
      * the value is absent and the list is
        COMPLETE (short of the ceiling)     -> a real zero
      * the value is absent and the list
        came back FULL                      -> refused by name

    The last is the one that would otherwise lie. A terms aggregation
    returns the commonest values; a value below the cut comes back missing,
    exactly as a value with no records does, and drawing a big confident 0
    over "this host is not in the fifty busiest" is the emptiness failure
    with a number on it.

    "The list came back full" is the only evidence of a cut there is, and it
    is evidence at all only because the aggregation labels the records that
    carry no value (`_panel_aggregations`): without that, VictoriaLogs cut
    its rows server-side, dropped the valueless ones on the way back and
    handed this a SHORT list it read as complete — a measured 0 for a host
    holding 25 records.

    On a board reading several sources at once the length means less again:
    `fanout.aggregate` merges the members' lists by key, so what arrives is
    their UNION and no member's ceiling. Refusing is still the safe
    direction — a member that cut is invisible from here — but the sentence
    has to be about the merge, because "not among the 50 commonest values in
    this window" describes a list nobody asked for. Measured on the lab over
    three sources at size 14: members 6, 11 and 13 buckets, none of them
    cut, merged list 21.

    The answer is sent as `number` rather than as `value`, because `value` is
    already on this panel: it is what the author asked to be counted, and it
    is a string. One key holding "ERROR" on a refusal and 7 on an answer
    would reach the client as `Number("ERROR")` — a card reading NaN in the
    one case the panel exists to report honestly.

    The case-insensitive near miss is the same failure one step earlier.
    Severity is written ERROR by Elasticsearch and error by Loki and
    VictoriaLogs (measured on the lab at 24h), so an author who types the
    wrong casing gets a zero that is arithmetically true about a value that
    does not exist. Named rather than silently matched: two keys differing
    only in case are two values, and summing them would invent a total the
    source never reported.
    """
    wanted = [p for p in panels if p["type"] == "count"]
    out = {}
    for panel in wanted:
        question = _count_question(panel)
        reasons = list(result.reasons(panel["id"]))
        if reasons:
            # A field this source cannot aggregate has no count, and "0" is
            # an answer to a question that was never asked.
            out[panel["id"]] = {"error": " ".join(reasons),
                                "question": question}
            continue

        buckets = result.get(panel["id"])
        wants = panel["value"]
        exact = [b for b in buckets if str(b.key) == wants]
        if exact:
            out[panel["id"]] = {"number": sum(b.count for b in exact),
                                "question": question}
            continue
        if len(buckets) >= COUNT_VALUES:
            out[panel["id"]] = {"error": (
                (f"'{wants}' is not in the list of {panel['field']} values "
                 f"this board merged from its {len(merged)} sources "
                 f"({', '.join(merged)}). Each source reports only its own "
                 f"commonest values, so a value missing from the merge "
                 f"cannot be told apart from one that fell below a member's "
                 f"cut."
                 if merged else
                 f"'{wants}' is not among the {COUNT_VALUES} commonest "
                 f"values of {panel['field']} in this window, and the count "
                 f"of a value further down the list was not asked for.")
                + " This is not a count of zero."), "question": question}
            continue
        near = [b for b in buckets if str(b.key).lower() == wants.lower()]
        if near:
            other = near[0]
            out[panel["id"]] = {"error": (
                f"No record has {panel['field']} exactly '{wants}' in this "
                f"window. {other.count:,} have '{other.key}', which differs "
                f"only in case — this source writes it that way."),
                "question": question}
            continue
        out[panel["id"]] = {"number": 0, "question": question}
    return out


def _count_question(panel):
    """What a single-number panel's number is the answer to.

    Written here rather than in the client, because it is a statement about
    what was counted and it belongs beside the counting. The title is the
    author's — "Checkout errors" — and a big number under a title nobody
    else wrote is a number nobody else can check.
    """
    return (f"records where {panel['field']} is “{panel['value']}”, "
            f"in this window and this board's query")


def _panel_results(panels, result, extra=None):
    """Attach each panel's data to its definition for the wire.

    And the reason it has none, when the source gave one. A panel that could
    not be answered drew "No data in this window" — a literal in the client —
    while the reason sat in the page-level alert, which names the source and
    not the panel. Measured on the lab: an Elasticsearch panel grouping by a
    field that index maps as text is dropped from the aggregation entirely, so
    `result.get(panel_id)` is [] and the only "'severity' cannot be aggregated
    on these indices" on screen was one line among the page's warnings, with
    nothing saying WHICH of two panels over that field it was about.

    `notes` is keyed by aggregation name, and `_panel_aggregations` names
    every aggregation after its panel, so this is a lookup. Matching the
    warning TEXT was the cheaper-looking option and does not work: only Loki
    prefixes the aggregation name, and a fan-out puts the source name in
    front of everything.
    """
    extra = extra or {}
    out = []
    for panel in panels:
        rendered = dict(panel)
        if panel["id"] in extra:
            rendered.update(extra[panel["id"]])
        elif not needs_logs(panel):
            # Nothing filled this panel and its question never goes to the log
            # source, so the log result holds no answer to look up — reading
            # it there produced `buckets: []`, which is "No data in this
            # window" on screen. Measured by registering a panel type with
            # signal "monitors" and no filler: status 200 and a card reading
            # that the window was quiet, with no error, no warning and
            # nothing anywhere saying the question had not been asked.
            #
            # `needs_logs` classifies a panel; it does not fill one. This is
            # the second half, and it is deliberately the DEFAULT for
            # forgetting: the next panel type is a row in `PANEL_TYPES` plus
            # a filler, and getting only as far as the row costs a visible
            # error rather than a plausible empty chart.
            rendered["buckets"] = []
            rendered["error"] = f"No {signal_of(panel)} backend is configured."
        else:
            rendered["buckets"] = _buckets(result.get(panel["id"]))
            reasons = list(result.reasons(panel["id"]))
            if reasons:
                # The same pair the trace panels use, so the client learns one
                # shape: `partial` puts the reason in the card header when
                # there are numbers beside it, and `renderPanel` prefers it to
                # the empty-window literal when there are none.
                rendered["partial"] = True
                rendered["warnings"] = reasons
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


def _query(dashboard, allowed, window, narrow=None):
    """Build a LogQuery from the dashboard's stored query.

    Takes the window the caller already built rather than a range string, so
    that one request asks one window of everything — the panels, the baseline
    and the backend — instead of three callers each re-deriving it.

    Raises QueryError when the stored query is malformed; the caller turns that
    into a panel error rather than letting the whole dashboard fail to open.
    """
    return LogQuery(
        window=window,
        text=_effective_query(dashboard, narrow),
        containers=tuple(allowed),
    )


def _panel(dashboard_id, aggregations, empty):
    """Shared flow for the per-panel endpoints.

    `aggregations` is either a list or a callable taking the window, for the
    two endpoints whose histogram interval has to follow it.

    Returns (payload, status); the payload is handed straight to jsonify.
    """
    if not current_user.has_permission("dashboard:view"):
        return {"error": "Access denied", "error_type": "permission_denied"}, 403

    dashboard = _load(dashboard_id)
    if not dashboard or not _may_view(dashboard):
        return {"error": "Dashboard not found",
                "error_type": "dashboard_not_found"}, 404

    # The same window `/data` builds, from the same place, before anything is
    # asked. These endpoints used to read `time_range` alone and IGNORE an
    # absolute range rather than refuse it, so a caller asking for last
    # Tuesday was answered about the last hour — measured on the lab, a window
    # holding 26 errors read as 0 here while `/data` read 26, and
    # `/log-levels` and `/services` answered empty lists. A quiet hour and a
    # question nobody asked are indistinguishable on the wire, which is the
    # one failure this product refuses to ship.
    try:
        window, _ = _requested_window()
    except TimeRangeError as exc:
        return {"error": str(exc), "error_type": "invalid_time_range"}, 400

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

    # The window first, THEN the aggregations that are shaped by it. Two of
    # these endpoints choose a histogram interval, and they used to choose it
    # from a second window built separately from the range string — so any
    # window not derivable from that string would have been queried at an
    # interval belonging to another one. Handing them the window is what makes
    # "ask for seven days" and "draw seven days" the same decision.
    if callable(aggregations):
        aggregations = aggregations(window)
    try:
        query = _query(dashboard, allowed, window)
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
    """Which source a dashboard reads from, for a message about it failing.

    Every one of them, named, for a board that reads every source: the
    fan-out raises only when no member could be asked, so "Unable to connect
    to lab-elasticsearch, lab-loki and lab-victorialogs" is the true
    sentence, and "all-sources" is a name nobody configured.
    """
    name = _pinned_name(dashboard)
    if name:
        return str(name)
    hub = getattr(current_app, "hub", None)
    try:
        source = hub.logs() if hub is not None else None
    except Exception:
        source = None
    if source is None:
        return "the log source"
    return _listed(_members(source))


def _listed(names):
    """`A`, `A and B`, `A, B and C`."""
    names = [str(name) for name in names]
    if len(names) < 2:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


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


def _matching(dashboards, term):
    """The dashboards whose name or description holds `term`.

    Applied in Python, over the list the visibility pass has already produced
    and BEFORE the page is sliced. Both halves matter.

    Before the slice, because a filter applied after it would search 24 cards
    rather than the list — a box that finds nothing on page 1 and the answer
    on page 3 is worse than no box, since nothing on screen says it only
    looked at what was already drawn.

    In Python rather than in the store, because paging is deliberately applied
    after the per-user visibility rule (see `dashboards_page`), and a WHERE
    clause here would be the first step towards teaching three stores a rule
    that lives in `dashboard/visibility.py`. The cost is the same full-table
    read the page already performs.

    Name and description, because that is what a card shows. Case-folded so
    that "payments" finds "Payments"; substring rather than prefix, because
    nobody remembers which word a board's name starts with.
    """
    term = (term or "").strip().casefold()
    if not term:
        return list(dashboards)
    return [dashboard for dashboard in dashboards
            if term in (dashboard.name or "").casefold()
            or term in (dashboard.description or "").casefold()]


@dashboard_bp.route("/dashboards")
@login_required
def dashboards_page():
    if not current_user.has_permission("dashboard:view"):
        flash("Access denied: insufficient permissions", "error")
        return redirect(url_for("index"))

    everything = _manager().get_all_dashboards()
    visible, unchecked, unchecked_sources = _visible(everything)

    # Filtered AFTER the visibility pass and BEFORE the page slice. The
    # counts below keep describing visibility — a dashboard left out because
    # it does not match the box has not been hidden from anybody, and folding
    # the two into one number would tell the reader to ask an administrator
    # for access they already have.
    search = (request.args.get("q") or "").strip()
    matching = _matching(visible, search)

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

    pages = max(1, (len(matching) + DASHBOARDS_PER_PAGE - 1) // DASHBOARDS_PER_PAGE)
    # A stale link to page 9 of a list that now has two pages should show the
    # last page, not an empty one that reads as "your dashboards are gone".
    page = min(page, pages - 1)
    start = page * DASHBOARDS_PER_PAGE

    return render_template(
        "dashboards.html",
        dashboards=matching[start:start + DASHBOARDS_PER_PAGE],
        total=len(matching),
        page=page,
        pages=pages,
        page_size=DASHBOARDS_PER_PAGE,
        # What was typed and how many of the visible dashboards it left out.
        # An empty page under a filter is a search that found nothing, not an
        # installation with no dashboards in it, and the page has to be able
        # to tell the reader which one they are looking at.
        search=search,
        filtered_out=len(visible) - len(matching),
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
    return render_template("dashboard_view.html", dashboard=dashboard,
                           source_note=_pin_description(dashboard))


def _pin_description(dashboard):
    """What the board's source setting means, in words, for its header.

    Beside the query and the index patterns, which the page has always
    printed: the source was the one thing about a board's question it did
    not say, and it is the one that decides whether the trace list on it
    reads the cluster the board is pinned to or every trace store there is.
    """
    hub = getattr(current_app, "hub", None)
    name = _pinned_name(dashboard)
    if not name:
        return ("all sources — every log, trace and monitor source, and the "
                "board says which answered")
    signals = hub.signals_of(name) if hub is not None else frozenset()
    if not signals:
        return (f"{name}, which is not configured, so nothing answers this "
                f"board — check the configuration page")
    served = [signal for signal in ("logs", "traces", "monitors")
              if signal in signals]
    elsewhere = [signal for signal in ("traces", "monitors")
                 if signal not in signals]
    text = f"{name} for {_listed(served)}"
    if elsewhere:
        text += (f"; {_listed(elsewhere)} from every source, because "
                 f"{name} serves {'neither' if len(elsewhere) == 2 else 'none'}")
    return text


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
    #
    # "All sources" is the empty string, and `*` — the search API's spelling
    # of the same choice — is read as the empty string too, so a board holds
    # ONE value for it: none. Two stored spellings of one meaning is a
    # question every reader of the row would have to answer again.
    source = (request.form.get("source") or "").strip()
    if source == Hub.ALL_SOURCES:
        source = ""
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
    # the first. Both stores read "" as the deliberate choice "all sources"
    # and `None`/absent as "leave it alone", so returning "" whenever the
    # field had not been rendered wiped the stored source on every edit:
    # `dashboard_edit.html` hides the select when there is nothing to
    # choose, so on a single-source installation the browser cannot send it
    # and every edit through the UI repointed the dashboard at every source
    # — quietly, which is the one thing `_logs()` and README's "reads from a
    # source that is not configured" both exist to prevent. `visibility`
    # above has always used this convention.
    if "source" in request.form:
        fields["source"] = source
    return fields, None


def _source_names():
    """The configured log sources — the names a board may be pinned to — in
    the order the hub holds them, which is by name."""
    hub = getattr(current_app, "hub", None)
    return [source.name for source in (hub.log_sources if hub else [])]


def _pins_on_offer():
    """The sources the form offers to pin a board to, or [] when there is
    nothing to choose.

    A control is worth drawing only where the choice changes what a panel
    reads: more than one log source, or a lone log source whose other
    signals have company — a cluster serving logs, traces and monitors
    beside a Tempo is one log source and a real choice for the trace panels
    (that cluster's traces, or every trace store's). One log source and
    nothing else: hidden, so an edit through the form cannot repoint
    anything, which is the installation `_dashboard_form`'s present-and-
    empty rule was written for.
    """
    hub = getattr(current_app, "hub", None)
    names = _source_names()
    if len(names) != 1 or hub is None:
        return names
    company = {"traces": hub.trace_sources, "monitors": hub.monitor_sources}
    for signal in hub.signals_of(names[0]) - {"logs"}:
        if len(company[signal]) > 1:
            return names
    return []


def _group_by_fields(name):
    """(fields, reason) the editor may offer for the source called `name`.

    Both halves always sensible, because the editor has one select to fill and
    an empty one is the same dead end whatever caused it. So: the source's own
    list and no reason, or the standard names and the sentence saying why they
    are the standard names — never a blank select, and never the standard four
    presented as though the source had chosen them.

    ADVISORY. Nothing here validates a stored panel: `normalise_all` runs on
    every READ of a dashboard and a refusal there is a 400 for the whole
    board, so a field this list does not hold is refused by the source that
    cannot answer it, as one panel carrying the reason.

    Advisory in ONE direction, though. A name the SAVE refuses must never be
    offered: the editor re-renders from the stored list when a save is
    refused, so one unusable option costs the author every panel they built
    in that sitting. So the offer is filtered by `check_group_by` itself —
    the function the save calls — rather than by a second copy of its rules
    that would drift from it. Measured on the lab's own cluster: the
    Heartbeat index maps eleven keyword fields whose names carry a hyphen
    (`http.response.headers.Content-Type` and its neighbours), which
    discovery finds and `normalise` refuses.
    """
    standard = list(AGGREGATABLE_FIELDS)
    try:
        source = _logs(_NamedSource(name) if name else None)
    except SourceMissing as exc:
        return standard, str(exc)
    if source is None:
        return standard, "No log source is configured."

    # A board over every source is asked nothing: each member lists its own
    # fields, and a name one of them groups by is a name the others refuse.
    # The standard four are what every adapter answers, and picking one
    # source in the select is how an author sees what it alone can do.
    if _fanned_out(source):
        return standard, ("A board over all sources offers the standard "
                          "fields, because each source lists different ones; "
                          "pick one source to see what it can group by.")
    # Absent as well as declined: a source object that is not a `LogSource`
    # subclass reaches here, and "there is no such method" is the same fact
    # as "not implemented".
    ask = getattr(source, "group_by_fields", None)
    if ask is None:
        return standard, (f"'{source.name}' does not list the fields it can "
                          f"group by; these are the standard ones.")
    try:
        answer = ask(_scope())
    except NotImplementedError:
        return standard, (f"'{source.name}' does not list the fields it can "
                          f"group by; these are the standard ones.")
    except Exception as exc:
        current_app.logger.warning(
            f"group-by fields could not be read from {source.name}: {exc}")
        # The reason, not a shrug: a cluster that is down and a cluster with
        # nothing to group by look identical in an empty select, and only one
        # of them is worth waiting out.
        #
        # The class of the failure and not its text: an Elasticsearch or Loki
        # client puts the backend's host and port in the message, and this
        # sentence is rendered into a page anyone with dashboard:edit can
        # open. The full exception is in the log above, where the person
        # fixing it looks.
        return standard, (f"The fields of '{source.name}' could not be read "
                          f"({type(exc).__name__}); these are the standard "
                          f"ones.")

    # A source that answered with a PartialList says what its list is not:
    # the Elasticsearch offer is cut to fifty names, and a select showing the
    # first fifty of fifteen hundred reads exactly like the whole answer.
    cut = tuple(getattr(answer, "warnings", ()) or ())

    found, unnameable = [], 0
    for field in answer:
        try:
            check_group_by("", field)
        except PanelError:
            unnameable += 1
            continue
        found.append(field)

    if not found:
        if unnameable:
            return standard, (f"None of the {unnameable} field names "
                              f"'{source.name}' reports can name a panel; "
                              f"these are the standard ones.")
        return standard, (f"'{source.name}' reported no fields your role can "
                          f"group by; these are the standard ones.")
    return found, (" ".join(cut) or None)


class _NamedSource:
    """Just enough of a dashboard for `_logs` to resolve a source by name.

    The create form has no dashboard yet and the edit form's select can point
    at one the stored board does not name, so the editor asks by NAME. Reusing
    `_logs` is what keeps "the source is not configured" one sentence in one
    place rather than two that drift.
    """

    def __init__(self, source):
        self.source = source


@dashboard_bp.route("/api/dashboard/group-by-fields")
@login_required
def api_group_by_fields():
    """What the panel editor may offer as a group-by, for one source."""
    if not (current_user.has_permission("dashboard:create")
            or current_user.has_permission("dashboard:edit")):
        return jsonify({"error": "Access denied: You do not have permission "
                                 "to edit dashboards.",
                        "error_type": "permission_denied"}), 403

    name = (request.args.get("source") or "").strip()
    fields, reason = _group_by_fields(name)
    # ONE list, and the reason it is that one. A `standard` beside it was a
    # second answer to the same question that no client read: the editor
    # fills its select from `fields`, and `_group_by_fields` has already
    # fallen back to the standard names when it had to.
    return jsonify({"source": name, "fields": fields, "reason": reason})


def _editor_context(panels, thresholds, defaulted, source=""):
    """What the shared panel-and-threshold editor needs, said once.

    Both forms render the same include, so the day a control is added it is
    added once. Before this the create form had neither control: every
    dashboard was born with the three default panels and no thresholds, and
    its author's first act was to open Edit.

    `defaulted` says whether `panels` is the standard set rather than a list
    somebody chose. The editor sends its hidden field EMPTY while the list is
    still that untouched set, because absent and "today's defaults" are
    different records — `_dashboard_form` reads absent as "leave the default
    set", and `Dashboard.to_dict` only writes `panels` once customised, so
    that a board nobody has edited keeps following the defaults instead of
    freezing the version of them that happened to be current the day it was
    made.
    """
    fields, reason = _group_by_fields(source)
    return {"panels": panels,
            "panels_are_default": defaulted,
            # Rendered with the page rather than fetched by it, so the select
            # is never briefly wrong: the form comes back with the source's
            # own fields already in it, and the endpoint above is for the
            # source SELECT changing under the author.
            "group_by_fields": fields,
            "group_by_reason": reason,
            "panel_heights": [list(pair) for pair in PANEL_HEIGHTS],
            "thresholds": thresholds}


def _resubmitted(panels, defaulted, source=""):
    """The editor context for a form that was REFUSED, holding what was typed.

    A validation error re-rendered the editor from the stored (or default)
    list, so a board built in the editor and then refused for a mistyped query
    came back as somebody else's panels — and, on the create form, marked as
    the default set, which made the next press post an empty field and store a
    board with no panels at all. The author's work disappeared with nothing on
    the page saying it had.

    That mattered nowhere before this form had an editor. It is the whole
    point of the create form now, which is why the submitted list comes back
    instead: a refusal is "fix this one field", not "start again".

    Falls back to what was passed in when the field is absent (the editor
    posts it empty while the list is still the untouched default set) or when
    it cannot be read at all — there is no third list to show, and a form that
    renders no panels cannot be corrected.
    """
    raw = (request.form.get("panels") or "").strip()
    if raw:
        try:
            panels, defaulted = normalise_all(json.loads(raw)), False
        except (json.JSONDecodeError, PanelError):
            pass

    # The four threshold boxes come back AS TYPED, unparsed: when the refusal
    # is about one of them ("a warning threshold must be below its critical
    # one"), the number to correct has to still be on screen. An empty box is
    # an empty box — this runs only on a POST, so the form said what it said.
    typed = {}
    for metric in METRICS:
        levels = {level: (request.form.get(f"threshold_{metric}_{level}") or "").strip()
                  for level in ("warning", "critical")}
        levels = {level: value for level, value in levels.items() if value}
        if levels:
            typed[metric] = levels
    # And the group-by list for the source that was CHOSEN on the refused
    # form, not for the one the board is stored with: the author may have
    # been repointing it, and a refusal about the query would otherwise
    # re-render the select against the old source's fields.
    return _editor_context(panels, typed, defaulted,
                           (request.form.get("source") or source).strip())


@dashboard_bp.route("/dashboard/create", methods=["GET", "POST"])
@login_required
def create_dashboard():
    if not current_user.has_permission("dashboard:create"):
        flash("Access denied: insufficient permissions", "error")
        return redirect(url_for("dashboards.dashboards_page"))

    indices = _form_indices()
    editor = _editor_context(default_panels(), {}, True)
    if request.method == "POST":
        fields, error = _dashboard_form()
        if error:
            flash(error, "error")
            # With what was typed, not with the defaults this page was
            # rendered from: the board was built in that editor.
            return render_template("dashboard_create.html", indices=indices,
                                   sources=_pins_on_offer(),
                                   visibilities=VISIBILITIES,
                                   **_resubmitted(default_panels(), True))

        try:
            dashboard = _manager().create_dashboard(
                created_by=current_user.username, **fields)
        except DashboardStorageError as exc:
            current_app.logger.error(f"Dashboard could not be saved: {exc}")
            flash("The dashboard could not be saved and has NOT been created. "
                  "Check the server logs and try again.", "error")
            return render_template("dashboard_create.html", indices=indices,
                                   sources=_pins_on_offer(),
                                   visibilities=VISIBILITIES,
                                   **_resubmitted(default_panels(), True))

        flash("Dashboard created successfully", "success")
        return redirect(url_for("dashboards.view_dashboard", dashboard_id=dashboard.id))

    return render_template("dashboard_create.html", indices=indices,
                           sources=_pins_on_offer(),
                           visibilities=VISIBILITIES, **editor)


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

    # `dashboard.panels` rather than `get_panels()` decides whether this board
    # is still on the standard set: `get_panels()` resolves the defaults, and
    # a form that cannot tell "the defaults" from "a list somebody chose"
    # freezes the first into the record the moment anybody presses Save.
    editor = _editor_context(dashboard.get_panels(), dashboard.thresholds,
                             not dashboard.panels, dashboard.source or "")
    if request.method == "POST":
        fields, error = _dashboard_form()
        if error:
            flash(error, "error")
            return render_template("dashboard_edit.html", dashboard=dashboard,
                                   indices=_form_indices(),
                                   sources=_pins_on_offer(),
                                   visibilities=VISIBILITIES,
                                   **_resubmitted(dashboard.get_panels(),
                                                  not dashboard.panels,
                                                  dashboard.source or ""))
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
                           sources=_pins_on_offer(),
                           visibilities=VISIBILITIES, **editor)


@dashboard_bp.route("/dashboard/<dashboard_id>/duplicate", methods=["POST"])
@login_required
def duplicate_dashboard(dashboard_id):
    """Copy a board under a new name, so the thirteenth starts from the twelfth.

    Two things are decided here rather than inherited, because inheriting
    either one is a way to be surprised:

    **The copy belongs to whoever duplicated it.** `created_by` is the
    duplicator, not the original author. Carrying the author over would make a
    board somebody else can edit and its author cannot, since `edit_dashboard`
    reads `created_by` — and it would put a stranger's name on a board they
    never wrote.

    **The copy starts private, whatever the original was.** Visibility is
    never copied. Copying "shared" is how a board becomes visible to a room
    nobody chose: the duplicate carries the original's query and patterns
    under a new name, and the person who pressed the button was making a
    draft. Private is the one choice that cannot widen anything; making it
    shared afterwards is one radio button on the edit form.

    Everything else is copied whole — query, patterns, panels, thresholds and
    the log source — because a copy that answers a different question from the
    board it came from is not a copy. `panels` is copied as STORED rather than
    as resolved: a board that never customised its panels has none, and
    freezing today's `default_panels()` into the duplicate would make the copy
    stop following the defaults the moment it was made.

    Requires `dashboard:create`, which is what it does, AND `dashboard:view`,
    because it reads a board — both halves of `view_dashboard`'s gate, in its
    order. The second was missing: only `_may_view` was asked, and
    `dashboard:view` was not, so a role holding create without view — which
    the permission model lets anybody write — could copy a shared board it was
    not allowed to open and then read its query and its description on the
    copy's own edit form. A dashboard's name and query ARE information; that
    is why `dashboard/visibility.py` exists. Past that gate the source is read
    the way `view_dashboard` reads it, 404 and not 403, so this route cannot
    become a way to find out which dashboard ids exist.
    """
    if not (current_user.has_permission("dashboard:create")
            and current_user.has_permission("dashboard:view")):
        flash("Access denied: insufficient permissions", "error")
        return redirect(url_for("dashboards.dashboards_page"))

    dashboard = _load(dashboard_id)
    if not dashboard or not _may_view(dashboard):
        flash("Dashboard not found. It may have been deleted or there may be a "
              "synchronization issue.", "error")
        return redirect(url_for("dashboards.dashboards_page"))

    try:
        copy = _manager().create_dashboard(
            name=f"{dashboard.name} (copy)",
            description=dashboard.description,
            query=dashboard.query,
            created_by=current_user.username,
            index_patterns=list(dashboard.index_patterns),
            panels=dashboard.panels,
            thresholds=dict(dashboard.thresholds or {}),
            visibility=PRIVATE,
            source=dashboard.source)
    except DashboardStorageError as exc:
        current_app.logger.error(f"Dashboard could not be copied: {exc}")
        flash("The dashboard could not be copied and NOTHING has been "
              "created. Check the server logs and try again.", "error")
        return redirect(url_for("dashboards.dashboards_page"))

    flash(f"Copied to \"{copy.name}\". The copy is yours and is private "
          f"until you share it.", "success")
    return redirect(url_for("dashboards.view_dashboard", dashboard_id=copy.id))


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
    # Built before the log source is resolved, because the panels that do not
    # need it are answerable whatever it says — and built ONCE, because every
    # caller that re-derived a window from the string was a caller that could
    # derive a different one.
    try:
        window, time_range = _requested_window()
    except TimeRangeError as exc:
        # No panel on this board can be answered without a window, so there is
        # nothing to fill and nothing to half-answer. Said in the status line,
        # which is what the client's error path reads, with the reason in it.
        return jsonify({"error": str(exc),
                        "error_type": "invalid_time_range"}), 400

    try:
        _, resolved, allowed = _targets(dashboard, scope)
    except SourceMissing as exc:
        payload, status = _without_log_containers(
            dashboard, scope, window, time_range,
            {"error": str(exc), "error_type": "source_missing"}, 400)
        return jsonify(payload), status
    except Exception as exc:
        payload, status = _without_log_containers(
            dashboard, scope, window, time_range,
            _unreachable(dashboard, exc), 503)
        return jsonify(payload), status

    if not allowed:
        # Returning empty data beats an error: the dashboard opens, every
        # panel that needs a container it may not read saying so in its own
        # card. The counts really are zero here — no container was queried —
        # which is not the same statement as a backend that did not answer.
        payload, status = _without_log_containers(
            dashboard, scope, window, time_range,
            {"error": "No accessible indices for dashboard data.",
             "error_type": "no_accessible_containers",
             "dashboard_patterns": dashboard.index_patterns,
             "resolved_containers": _shown(resolved, allowed),
             "total_resolved": len(resolved),
             "total_hits": 0, "error_count": 0, "warn_count": 0,
             "info_count": 0, "error_rate": 0.0,
             "queried_containers": []}, 200)
        return jsonify(payload), status

    # An ad-hoc filter carried in the URL. Together with time_range this makes
    # a dashboard link reproduce what the sender was actually looking at —
    # "the dashboard" and "the dashboard, this window, this filter" are
    # different things, and only the second is worth pasting into a thread.
    narrow = request.args.get("q") or None
    try:
        query = _query(dashboard, allowed, window, narrow)
    except QueryError as exc:
        message = (f"Invalid filter: {exc}" if narrow
                   else f"Invalid dashboard query: {exc}")
        # A filter the log query language cannot parse is the log source's
        # problem, and it is the one door of the four that a typo opens: the
        # trace panel beside it never honoured `q` in the first place, and
        # answering 400 for the whole board took it down for a quote nobody
        # closed. A board of log panels alone still answers 400 — there is
        # nothing to show and the status line is what the client reads.
        payload, status = _without_log_containers(
            dashboard, scope, window, time_range,
            {"error": message, "error_type": "invalid_query"}, 400)
        return jsonify(payload), status
    # Both windows go out in ONE batch. The comparison is a separate query —
    # it covers a different time range — but not a separate round trip.
    try:
        panels = dashboard.get_panels()
    except PanelError as exc:
        return jsonify({"error": f"This dashboard's panels are invalid: {exc}",
                        "error_type": "invalid_panels"}), 400

    # Every panel plus the summary counts in ONE request. Adding a panel costs
    # an aggregation, not a round trip — which is what makes an arbitrary panel
    # list affordable at all. It used to mean separate queries per panel plus a
    # second round of "retry with service if service.keyword fails".
    aggregations = _panel_aggregations(panels, query.window)
    # The stat cards are not a panel: they are the summary every dashboard
    # carries, so their aggregation is always present regardless of the list.
    aggregations.append(Terms(name=LEVELS_AGGREGATION, field="severity", size=10))
    batch = [(query, aggregations)]

    baseline_query = _baseline_query(dashboard, allowed, query.window, narrow)
    if baseline_query is not None:
        batch.append((baseline_query,
                      [Terms(name=LEVELS_AGGREGATION, field="severity", size=10)]))

    # The door a running worker actually walks through. `_targets` asks the
    # source for its container list, and the Elasticsearch catalogue serves a
    # STALE list indefinitely once it has fetched one (elasticsearch.py:226)
    # rather than pretending the cluster is empty — so in an ordinary outage
    # `_targets` SUCCEEDS and the failure lands here instead. Measured on the
    # lab: with the client replaced by a dead one and the catalogue warm,
    # `containers()` still answered 11 indices while this returned 502 with
    # no `panels` key at all, and the client's `showLoadError` wiped the grid
    # — the trace panel with it. Only a worker that has never read the index
    # list reaches the earlier door.
    source = _logs(dashboard)
    try:
        results = source.multi_aggregate(batch, scope)
    except Exception as exc:
        # And a search that RAISES rather than answering `failed` reached no
        # handler at all: Flask answered an HTML 500, so the browser got no
        # payload, no panel and no sentence.
        current_app.logger.warning(f"Dashboard search failed: {exc}")
        payload, status = _without_log_containers(
            dashboard, scope, window, time_range,
            _unreachable(dashboard, exc), 503)
        return jsonify(payload), status
    result = results[0]
    if _did_not_run(result):
        payload, status = _without_log_containers(
            dashboard, scope, window, time_range, _did_not_run(result), 502)
        return jsonify(payload), status
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
        # Which log sources the four numbers above were added up from, and
        # how much each gave — the same breakdown the Logs page prints. A
        # board over three sources is three rows here; a board pinned to
        # one is one row naming it.
        "sources": _log_attribution(source, result),
        "panels": _panel_results(
            panels, result,
            {**_trace_panels(panels, query.window, scope, dashboard),
             **_trace_list_panels(panels, query.window, scope, dashboard),
             **_monitor_panels(panels, scope, query.window, dashboard),
             **_alert_panels(panels, query.window, scope),
             # A log panel with no chart: the number is read out of the
             # batch above rather than fetched, so it costs one aggregation
             # and no round trip — but it is filled HERE rather than in
             # `_panel_results` because a terms list is not what this panel
             # shows, and a value missing from it is a reason and not a zero.
             **_count_panels(panels, result,
                             merged=_merged_sources(dashboard)),
             # The only LOG panel with a filler of its own: a list of records
             # is a search, not an aggregation, so it cannot ride the batch
             # above. It is still a log panel — it needs the containers, and
             # it dies with the log source rather than drawing an empty table
             # through an outage.
             # `result` rides along so the footer's "of N" and the total hits
             # on the stat card cannot present two different numbers for one
             # question as though both were exact.
             **_records_panels(panels, query, dashboard, scope,
                               headline=result)}),
        "dashboard_patterns": dashboard.index_patterns,
        "resolved_containers": _shown(resolved, allowed),
        "total_resolved": len(resolved),
        "accessible_containers": allowed,
        "queried_containers": allowed,
        "total_accessible_containers": len(allowed),
        # Echoed so the client can show what is actually being asked, rather
        # than only what the dashboard was saved with. `time_range` is None
        # for an absolute range, where there is no relative name for what was
        # asked; `window` carries the bounds either way, which is the only
        # thing that says what "1h" resolved to after alignment.
        "time_range": time_range,
        "window": _window_payload(query.window),
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
    result, status = _panel(
        dashboard_id,
        lambda window: [DateHistogram(name="timeline",
                                      interval=_timeline_interval(window),
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
        lambda window: [DateHistogram(
            name="heatmap_data",
            interval=_heatmap_interval(window),
            min_count=0,
            sub=(Terms(name="log_levels", field="severity", size=10),))],
        {"heatmap_data": []})
    if status is not None:
        return jsonify(result), status
    if isinstance(result, dict):
        return jsonify(result)
    return jsonify({"heatmap_data": _buckets(result.get("heatmap_data"))})
