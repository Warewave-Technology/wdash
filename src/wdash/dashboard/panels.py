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

import uuid

#: Panel kinds and the fields each one needs.
#:
#: `signal` records which source answers it. Everything here reads logs today;
#: it exists so a trace panel is an added row rather than a special case
#: threaded through the renderer.
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
    "trace_services": {
        "label": "Services by traffic",
        "signal": "traces",
        "description": "Span counts and error rates per service, from traces.",
        "fields": ("size", "sort"),
    },
}

#: How a trace service panel is ordered.
TRACE_SORTS = ("spans", "errors", "error_rate")

#: Fields a terms panel may aggregate on. Restricted deliberately: an
#: aggregation on an analysed text field either fails or returns tokenised
#: nonsense, and letting anyone type a field name makes that a support burden
#: rather than an impossible state.
AGGREGATABLE_FIELDS = ("severity", "service", "host", "environment")

DEFAULT_SIZE = 10
MAX_SIZE = 50
MIN_WIDTH = 3
MAX_WIDTH = 12


class PanelError(ValueError):
    """A panel definition that cannot be rendered."""


def signals(panels):
    """Which sources a panel list needs.

    Logs and traces live in different indices with different schemas, so they
    cannot share one batched search. A dashboard of log panels stays at one
    round trip; adding a trace panel costs a second. That is a real cost and
    the code says so rather than hiding it.
    """
    return {PANEL_TYPES[panel["type"]]["signal"] for panel in panels}


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

    out = {
        "id": panel.get("id") or panel_id or str(uuid.uuid4()),
        "type": kind,
        "title": title,
        "width": width,
    }

    if kind == "terms":
        field = (panel.get("field") or "").strip()
        if field not in AGGREGATABLE_FIELDS:
            raise PanelError(
                f"'{title}': cannot group by '{field}'. "
                f"Available: {', '.join(AGGREGATABLE_FIELDS)}")
        try:
            size = int(panel.get("size", DEFAULT_SIZE))
        except (TypeError, ValueError):
            raise PanelError(f"'{title}': size must be a number.")
        out["field"] = field
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

    elif kind == "timeseries":
        split_by = (panel.get("split_by") or "").strip()
        if split_by and split_by not in AGGREGATABLE_FIELDS:
            raise PanelError(
                f"'{title}': cannot split by '{split_by}'. "
                f"Available: {', '.join(AGGREGATABLE_FIELDS)}")
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
