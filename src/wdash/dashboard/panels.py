"""
What a dashboard actually asks.

A dashboard used to be one query rendered four fixed ways. You could not add a
panel, remove one, or put two services side by side — which is the thing people
open a dashboard to do. This module makes the panel list data.

Design notes
------------
A panel is a QUESTION, not a chart. `type` says what is being asked ("how did
volume move", "which values dominate"); how it is drawn is the client's
business. That split is what lets a future backend answer the same panel
without knowing anything about Chart.js.

Panels are validated on the way in and normalised to a full dict, so the rest
of the application never has to defend against a half-specified panel loaded
from a file somebody edited by hand.
"""

import re
import uuid

#: Panel kinds and the fields each one needs.
#:
#: `signal` records which source answers it, and it is now read rather than
#: decorative: four signals are in this table — logs, traces, monitors,
#: alerts — and a panel kind is filled, classified and kept off the log
#: source's fate by the row alone, not by a special case threaded through the
#: renderer.
#: `needs_logs` and `dashboard_routes.FILLED_SIGNALS` are the two readers, and
#: a row whose signal nothing fills fails the suite rather than a card.
PANEL_TYPES = {
    "timeseries": {
        "label": "Volume over time",
        "signal": "logs",
        "description": "Counts bucketed over the window, optionally split by a field.",
        "fields": ("split_by",),
    },
    "terms": {
        "label": "Top values",
        "signal": "logs",
        "description": "The most common values of a field.",
        "fields": ("field", "size"),
    },
    "records": {
        "label": "Recent records",
        "signal": "logs",
        "description": "The newest records the dashboard's query matches — "
                       "timestamp, severity, service, message.",
        "fields": ("size",),
    },
    "count": {
        "label": "A single number",
        "signal": "logs",
        "description": "How many records in this window have one value of "
                       "one field — one number, under a label of your own.",
        "fields": ("field", "value"),
    },
    "trace_services": {
        "label": "Services by traffic",
        "signal": "traces",
        "description": "Span counts and error rates per service, from traces.",
        "fields": ("size", "sort"),
    },
    "trace_list": {
        "label": "Traces for one service",
        "signal": "traces",
        "description": "Individual requests through one service — the "
                       "slowest, the newest, or only the ones that failed.",
        "fields": ("service", "view", "size"),
    },
    "monitors": {
        "label": "Monitor status",
        "signal": "monitors",
        "description": "One cell per check — is it up now, or how much of "
                       "the window was it up for.",
        "fields": ("view",),
    },
    "monitor_certificates": {
        "label": "TLS certificates",
        "signal": "monitors",
        "description": "What the checks saw on the wire, and how long each "
                       "certificate is still valid.",
        "fields": (),
    },
    "alerts": {
        "label": "Alerts that fired",
        "signal": "alerts",
        "description": "What WDash's own alerting said in this window — the "
                       "rule, what it was about, and whether it was "
                       "delivered.",
        "fields": ("size",),
    },
    "alerts_undelivered": {
        "label": "Alerts nobody received",
        "signal": "alerts",
        "description": "How many of this window's alerts never reached a "
                       "channel. An alert nobody received reads as nothing "
                       "being wrong.",
        "fields": (),
    },
}

#: How a trace service panel is ordered.
TRACE_SORTS = ("spans", "errors", "error_rate")

#: What a trace list panel asks. Three questions people open the traces page
#: for, named rather than expressed as a sort plus a flag: "errors" is not an
#: ordering, and a panel offering `sort` and `only_errors` separately would
#: put four combinations on a board where three are ever asked for.
TRACE_LIST_VIEWS = ("slowest", "recent", "errors")

#: What a monitor panel asks. Two questions, one panel type and one fetch:
#: "is it up now" and "was it up all week" come out of the SAME listing —
#: `MonitorPoint.down` and `.checks` ride along with the current state — so
#: a second panel type would buy a second round trip and nothing else.
#:
#: Which one a panel is showing has to be said ON the panel: a grid reading
#: 100% and a grid reading "up" look alike and mean different things, and the
#: one that is wrong is the one nobody checked the caption of.
MONITOR_VIEWS = ("status", "availability")

#: Fields the editor offers when the source has not said what it holds.
#:
#: These four used to be the whole vocabulary, and a closed list of four is a
#: UI constant rather than a backend limit. Measured on the lab: the
#: Elasticsearch index maps ten fields that group cleanly — `http_status`
#: (200: 885, 404: 332, 201: 300, 503: 300, 400: 298), `user_id`,
#: `correlation_id`, `request_id`, `duration_ms` and `trace_id` beside these —
#: none of which a board could ask for, while Loki carries no `host` and no
#: `environment` label at all and answered both with nothing. So the list a
#: source can really group by is read FROM the source
#: (`LogSource.group_by_fields`), and these are what the editor shows while
#: nobody has answered: a deployment with one of everything still recognises
#: them, and a discovery call that fails leaves a list rather than a blank
#: select.
AGGREGATABLE_FIELDS = ("severity", "service", "host", "environment")

#: Neutral names that are the log LINE rather than a value to count. Refused
#: outright, whatever the source says: an aggregation on an analysed text
#: field either fails or returns tokenised nonsense, one word per bucket.
UNCOUNTABLE_FIELDS = ("body", "message", "_msg", "line", "log")

#: The shape a group-by field name must have.
#:
#: This is the static vocabulary `normalise` validates against, and it is a
#: SHAPE rather than a list on purpose. `models.Dashboard.get_panels` calls
#: `normalise_all` on every READ, and a PanelError there is a 400 for the
#: whole dashboard — so a rule that consults a backend, or a closed list that
#: a re-pointed board can fall outside of, turns one stale panel into a board
#: that will not open. Whether this source can answer `http_status` today is
#: the SOURCE's answer, given per panel at fill time; whether `http_status` is
#: a field name at all is decidable here, forever, offline.
#:
#: Strict for a second reason: the name is interpolated into a LogQL `sum by
#: (...)` clause and a LogsQL filter. Letters, digits, underscore and dot
#: cannot close a quote, a brace or a pipeline stage.
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,63}\Z")

DEFAULT_SIZE = 10
MAX_SIZE = 50

#: Rows a records panel will list.
#:
#: Lower than MAX_SIZE on purpose: a bucket is two numbers and a record is a
#: message, a resource map and an attribute map. Measured on the lab over
#: `app-logs-000001` at 24h: 381 bytes of JSON per record against 41 per
#: terms bucket, so a board of four records panels at MAX_SIZE would put
#: 76 kB on the wire for four cards 300 pixels tall.
MAX_RECORDS = 25

#: Rows a trace list panel shows unless it says otherwise. "The five slowest"
#: is the question people ask; twenty-five of them is a list nobody reads.
DEFAULT_TRACE_ROWS = 5

#: Rows an alerts panel lists. Same ceiling as records and for the same
#: reason: a row is a rule name, a subject and a delivery error, not two
#: numbers, and a window with more alerts in it than this needs the Alerts
#: page rather than a taller card.
MAX_ALERT_ROWS = 25
MIN_WIDTH = 3
MAX_WIDTH = 12

#: How tall a panel's chart area is, in pixels.
#:
#: Every panel used to be exactly 300, hardcoded in the card template, so a
#: one-row service table left two thirds of its card empty and a twenty-row
#: table scrolled inside a box. One clamped int beside `width` and no
#: migration: the panel record is schemaless JSON, and a panel written before
#: this existed gets the default it already had.
#:
#: Deliberately NOT a layout system. There is no position, no row, no drag: a
#: panel says how wide and how tall, and the grid flows. The heights offered
#: by the editor are a short list rather than a free number — see
#: PANEL_HEIGHTS — because "how tall should this be" has about four useful
#: answers and a spinner invites the other four hundred.
MIN_HEIGHT = 120
MAX_HEIGHT = 900
DEFAULT_HEIGHT = 300

#: The heights the editor offers, and what each one is for. Any integer
#: between MIN_HEIGHT and MAX_HEIGHT is accepted on the way in — a stored
#: board is not invalidated by this list changing — but these are the ones
#: with a name.
PANEL_HEIGHTS = (
    (180, "short — a few rows"),
    (300, "standard"),
    (450, "tall"),
    (600, "very tall — a long table"),
)


class PanelError(ValueError):
    """A panel definition that cannot be rendered."""


def check_group_by(title, field, verb="group by"):
    """Refuse a field name no source could ever group by. Raises PanelError.

    Deliberately NOT "refuse a field THIS source cannot group by". That
    question has a different answer per source and per day, it costs a
    request to ask, and it is asked where the panel is drawn — one card
    saying why, out of `AggregationResult.notes`. Asked here it would be
    asked on every read of the dashboard, and answered with a 400 for the
    board.
    """
    if field in UNCOUNTABLE_FIELDS:
        raise PanelError(
            f"'{title}': cannot {verb} '{field}' — that is the log line "
            f"itself, not a value to count. Fields most sources hold: "
            f"{', '.join(AGGREGATABLE_FIELDS)}; the editor offers what this "
            f"dashboard's source actually carries.")
    if not _FIELD_NAME.match(field):
        raise PanelError(
            f"'{title}': cannot {verb} '{field}' — a field name starts with "
            f"a letter and holds letters, digits, underscores and dots. "
            f"Fields most sources hold: {', '.join(AGGREGATABLE_FIELDS)}.")


def signals(panels):
    """Which sources a panel list needs.

    Logs, traces and monitors live in different stores with different
    schemas, so they cannot share one batched search. A dashboard of log
    panels stays at one round trip; adding a trace panel costs a second and a
    monitor panel a third. That is a real cost and the code says so rather
    than hiding it.

    Read from the table rather than branched on per type: a `signal` a panel
    kind declares is one edit, and a chain of `if panel["type"] == ...` here
    is a place the next panel kind gets forgotten and quietly counted as a
    log panel — which is exactly how it would end up sharing the log
    source's fate.
    """
    return {PANEL_TYPES[panel["type"]]["signal"] for panel in panels}


def signal_of(panel):
    """Which source answers this panel, as a name fit to say out loud.

    `needs_logs` is enough to classify a panel; it is not enough to fill one.
    A panel type whose signal nothing fills yet has to SAY that, and saying
    it needs the signal's name — so this is the other half of the row, and
    the reason a forgotten filler reads as an error rather than as an empty
    card.
    """
    return PANEL_TYPES[panel["type"]]["signal"]


def needs_logs(panel):
    """Does this panel's question go to the log source?

    One route fills every panel, and it resolved the LOG source's containers
    before filling any of them — so a log backend that was down, or a scope
    that reached none of the dashboard's containers, took down panels that
    never ask it anything. A panel whose signal is not "logs" is answerable
    from the window and the caller's scope alone.

    A predicate rather than a list of type names, so the next panel type
    answers this by filling in its `signal` row above and nothing else.
    """
    return PANEL_TYPES[panel["type"]]["signal"] == "logs"


def default_panels():
    """The panels a dashboard gets when it does not specify any.

    These reproduce what every dashboard showed before panels existed, so
    stored dashboards keep rendering exactly as they did.
    """
    return [
        normalise({"type": "timeseries", "title": "Volume by Severity",
                   "split_by": "severity", "width": 12},
                  panel_id="default-volume"),
        normalise({"type": "terms", "title": "Log Levels",
                   "field": "severity", "size": 10, "width": 4},
                  panel_id="default-levels"),
        normalise({"type": "terms", "title": "Top Services",
                   "field": "service", "size": 10, "width": 8},
                  panel_id="default-services"),
    ]


def normalise(panel, panel_id=None):
    """Validate one panel and return it complete. Raises PanelError.

    Everything downstream reads the result of this function, so a panel that
    gets past here is guaranteed renderable — no `.get(...)` guards scattered
    through the query builder and the template.
    """
    if not isinstance(panel, dict):
        raise PanelError("A panel must be an object.")

    kind = (panel.get("type") or "").strip()
    if kind not in PANEL_TYPES:
        raise PanelError(f"Unknown panel type: {kind or '(none)'}")

    title = (panel.get("title") or "").strip() or PANEL_TYPES[kind]["label"]

    try:
        width = int(panel.get("width", 6))
    except (TypeError, ValueError):
        raise PanelError(f"'{title}': width must be a number.")
    width = max(MIN_WIDTH, min(MAX_WIDTH, width))

    try:
        height = int(panel.get("height", DEFAULT_HEIGHT))
    except (TypeError, ValueError):
        raise PanelError(f"'{title}': height must be a number.")
    height = max(MIN_HEIGHT, min(MAX_HEIGHT, height))

    out = {
        "id": panel.get("id") or panel_id or str(uuid.uuid4()),
        "type": kind,
        "title": title,
        "width": width,
        "height": height,
    }

    if kind == "terms":
        field = (panel.get("field") or "").strip()
        check_group_by(title, field)
        try:
            size = int(panel.get("size", DEFAULT_SIZE))
        except (TypeError, ValueError):
            raise PanelError(f"'{title}': size must be a number.")
        out["field"] = field
        out["size"] = max(1, min(MAX_SIZE, size))

    elif kind == "records":
        try:
            size = int(panel.get("size", DEFAULT_SIZE))
        except (TypeError, ValueError):
            raise PanelError(f"'{title}': size must be a number.")
        out["size"] = max(1, min(MAX_RECORDS, size))

    elif kind == "count":
        # One number, and both halves of the question are required.
        #
        # A field, because the number has to come from an AGGREGATION: a
        # search total is a floor on Loki (`counted=False`), and the batch's
        # own `total` is whatever the largest aggregation in it summed to,
        # which on a board of timeseries panels is Loki's overlapping
        # `count_over_time` — measured against the lab over two Loki streams
        # at 24h: 181, 199, 240, 309 and 565 at the five bucket sizes, over
        # 170 records. A terms aggregation over one field answered 170 at
        # every size, on all three backends.
        #
        # A value, because a terms aggregation is the only count available —
        # no new aggregation type this round — and it counts VALUES. A panel
        # that summed the whole terms list would be reporting "records whose
        # service is one of the fifty commonest", under a label the author
        # wrote, with no way to see the difference.
        field = (panel.get("field") or "").strip()
        if field not in AGGREGATABLE_FIELDS:
            raise PanelError(
                f"'{title}': cannot count by '{field}'. "
                f"Available: {', '.join(AGGREGATABLE_FIELDS)}")
        value = str(panel.get("value") or "").strip()
        if not value:
            raise PanelError(
                f"'{title}': a single number counts one value of one field, "
                f"so it needs the value to count — for example '{field}' is "
                f"ERROR. Without one there is no question for the number to "
                f"answer.")
        out["field"] = field
        out["value"] = value

    elif kind == "alerts":
        try:
            size = int(panel.get("size", DEFAULT_SIZE))
        except (TypeError, ValueError):
            raise PanelError(f"'{title}': size must be a number.")
        out["size"] = max(1, min(MAX_ALERT_ROWS, size))

    elif kind == "trace_list":
        service = (panel.get("service") or "").strip()
        if not service:
            # Required, and the reason is a cost rather than taste. Jaeger
            # cannot answer "every trace": with no service named it lists the
            # services and then searches each one (jaeger.py:307-322, bounded
            # at MAX_SERVICE_FANOUT = 20). Measured on the lab's 7-service
            # Jaeger at 24h: 8 HTTP requests and 52 ms with no service named,
            # 1 request and 3 ms with one — and every dashboard refresh pays
            # it again. An installation past the bound loses the traces that
            # ran only through the rest, which reads as a quieter hour.
            #
            # Refused here rather than defaulted, because the panel would be
            # affordable on Elasticsearch and Tempo and ruinous on Jaeger:
            # a board that answers one question on one backend and a
            # different, more expensive one on another is not a panel anyone
            # can reason about.
            raise PanelError(
                f"'{title}': a trace list needs a service to list traces "
                f"for. Without one, a Jaeger backend has to search every "
                f"service it knows, on every refresh.")
        view = (panel.get("view") or TRACE_LIST_VIEWS[0]).strip()
        if view not in TRACE_LIST_VIEWS:
            raise PanelError(
                f"'{title}': cannot show '{view}'. "
                f"Available: {', '.join(TRACE_LIST_VIEWS)}")
        try:
            size = int(panel.get("size", DEFAULT_TRACE_ROWS))
        except (TypeError, ValueError):
            raise PanelError(f"'{title}': size must be a number.")
        out["service"] = service
        out["view"] = view
        out["size"] = max(1, min(MAX_SIZE, size))

    elif kind == "trace_services":
        try:
            size = int(panel.get("size", DEFAULT_SIZE))
        except (TypeError, ValueError):
            raise PanelError(f"'{title}': size must be a number.")
        sort = (panel.get("sort") or "spans").strip()
        if sort not in TRACE_SORTS:
            raise PanelError(
                f"'{title}': cannot sort by '{sort}'. "
                f"Available: {', '.join(TRACE_SORTS)}")
        out["size"] = max(1, min(MAX_SIZE, size))
        out["sort"] = sort

    elif kind == "monitors":
        view = (panel.get("view") or "status").strip()
        if view not in MONITOR_VIEWS:
            raise PanelError(
                f"'{title}': cannot show '{view}'. "
                f"Available: {', '.join(MONITOR_VIEWS)}")
        out["view"] = view

    elif kind == "timeseries":
        split_by = (panel.get("split_by") or "").strip()
        if split_by:
            check_group_by(title, split_by, verb="split by")
        out["split_by"] = split_by or None

    return out


def normalise_all(panels):
    """Validate a whole panel list, keeping ids unique.

    A duplicate id would make two panels overwrite each other's results, since
    results come back keyed by id — silent and very confusing.
    """
    if panels is None:
        return default_panels()
    if not isinstance(panels, (list, tuple)):
        raise PanelError("Panels must be a list.")
    if not panels:
        raise PanelError("A dashboard needs at least one panel.")

    out, seen = [], set()
    for panel in panels:
        normalised = normalise(panel)
        if normalised["id"] in seen:
            normalised["id"] = str(uuid.uuid4())
        seen.add(normalised["id"])
        out.append(normalised)
    return out
