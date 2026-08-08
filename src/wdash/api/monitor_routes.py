"""
Synthetic monitors and the certificates they see.

One screen for both, because they are two views of one act of measurement:
the TLS certificate is something a check observes on its way to asking "did
this answer". Kibana splits them into separate apps and the split shows —
a certificate expiring on an endpoint nobody monitors any more is a row with
no context, and an endpoint that started failing its TLS handshake appears in
one place as "down" and in the other not at all.

Authorization is deliberately coarser here than for logs and traces. Those are
narrowed twice: a permission opens the screen, and the role's containers
decide what is inside it. A monitor has no container to be narrowed by — it is
about an endpoint, and a role's index patterns say nothing about which
endpoints somebody may see. Inventing a mapping would be a boundary nobody
could reason about. `monitors:read` opens the screen and shows everything the
configured sources report; a deployment that needs finer separation runs a
second source.
"""

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..hub.models import DOWN, UNKNOWN, UP, MonitorPage
from ..hub.query import TimeWindow
from ..hub.source import Capability

monitor_bp = Blueprint("monitors", __name__)

#: Below this many days the certificate row is a warning rather than a fact.
#: Thirty is the number every certificate authority sends its first renewal
#: reminder at, so it is the one operators already have in mind.
EXPIRY_WARNING_DAYS = 30
#: And below this, it is the most urgent thing on the page.
EXPIRY_CRITICAL_DAYS = 7


def _require():
    return current_user.has_permission("monitors:read")


def _source(name=None):
    """The monitor source to read, or None when none is configured.

    Defaults to the fan-out over everything, unlike the log and trace screens
    which default to a single source. There is no reason to look at one
    agent's monitors in isolation — the question is always "is anything
    down", and asking it of one region at a time is how an outage in the
    other one is missed.
    """
    hub = getattr(current_app, "hub", None)
    if hub is None:
        return None
    return hub.monitors(name or hub.ALL_SOURCES)


def _window():
    """How far back to look for the LATEST state of each monitor.

    Not a search range: monitors are a current-state screen. The window only
    has to be long enough to contain one check of the slowest monitor, and
    short enough that a monitor deleted last week stops appearing. An hour is
    generous for schedules measured in seconds and minutes; a monitor on a
    six-hour schedule needs this raised, which is what the selector is for.
    """
    requested = (request.args.get("window") or "1h").strip()
    try:
        return TimeWindow.of(requested), requested
    except Exception:
        return TimeWindow.of("1h"), "1h"


def _certificate_state(certificate):
    """`ok`, `warning`, `critical` or `expired` — never a bare number.

    The template must not do this arithmetic. A page that decides its own
    colours from a number ends up with two thresholds, and the one nobody
    remembers is the one in the HTML.
    """
    if certificate is None:
        return None
    if certificate.expired:
        return "expired"
    days = certificate.days_remaining
    if days is None:
        return None
    if days <= EXPIRY_CRITICAL_DAYS:
        return "critical"
    if days <= EXPIRY_WARNING_DAYS:
        return "warning"
    return "ok"


#: Sparkline geometry. Fixed rather than responsive because it is drawn once,
#: server-side, into a table cell — an SVG that scales would need a viewBox
#: per row and buy nothing.
SPARK_WIDTH = 110
SPARK_HEIGHT = 26


def sparkline(points):
    """An SVG polyline for a monitor's recent response times.

    Server-rendered SVG rather than a charting library: fifty rows means fifty
    chart instances, each holding a canvas and a redraw loop, to draw fifty
    shapes that never change. This is one string per row and no JavaScript at
    all — which also means it survives a page with a strict CSP and no CDN.

    Returns None when there is nothing to draw, so the template can say
    "no data" rather than render an empty box that reads as a flat line at
    zero.
    """
    usable = [p for p in points if p.has_data and p.duration_ms is not None]
    if len(usable) < 2:
        return None

    highest = max(p.duration_ms for p in usable) or 1.0
    step = SPARK_WIDTH / max(1, len(points) - 1)
    # Two units of padding top and bottom so the peak is not clipped by the
    # viewport edge and a flat line does not sit exactly on it.
    span = SPARK_HEIGHT - 4

    coordinates, gaps, failures = [], [], []
    for index, point in enumerate(points):
        x = index * step
        if not point.has_data or point.duration_ms is None:
            # A gap breaks the line. Joining across it would draw a monitor
            # that was not reporting as one that was reporting steadily.
            gaps.append(round(x, 1))
            coordinates.append(None)
            continue
        y = 2 + span * (1 - (point.duration_ms / highest))
        coordinates.append((round(x, 1), round(y, 1)))
        if point.is_down:
            failures.append((round(x, 1), round(y, 1)))

    # Split into runs of consecutive points, so each gap ends a polyline.
    runs, current = [], []
    for coordinate in coordinates:
        if coordinate is None:
            if len(current) > 1:
                runs.append(current)
            current = []
        else:
            current.append(coordinate)
    if len(current) > 1:
        runs.append(current)

    return {
        "width": SPARK_WIDTH, "height": SPARK_HEIGHT,
        "runs": [" ".join(f"{x},{y}" for x, y in run) for run in runs],
        "failures": failures,
        "peak_ms": round(highest, 1),
        "gaps": len(gaps),
    }


def _payload(page, certificates):
    """One JSON shape, used by the page and by the API."""
    def monitor(m):
        certificate = None
        if m.certificate:
            certificate = {
                "common_name": m.certificate.common_name,
                "issuer": m.certificate.issuer,
                "not_after": (m.certificate.not_after.isoformat()
                              if m.certificate.not_after else None),
                "days_remaining": m.certificate.days_remaining,
                "expired": m.certificate.expired,
                "state": _certificate_state(m.certificate),
                "fingerprint": m.certificate.fingerprint,
                "key": m.certificate.key_description,
                "signature_algorithm": m.certificate.signature_algorithm,
            }
        return {
            "id": m.id, "name": m.name, "type": m.type, "url": m.url,
            "location": m.location, "status": m.status,
            "checked_at": m.checked_at.isoformat() if m.checked_at else None,
            "duration_ms": (round(m.duration_ms, 1)
                            if m.duration_ms is not None else None),
            "error": m.error, "tags": list(m.tags), "source": m.source,
            "certificate": certificate,
        }

    return {
        "monitors": [monitor(m) for m in page.monitors],
        "certificates": [monitor(m) for m in certificates],
        "counts": page.counts,
        # Named so the page can say WHICH source is missing. "Partial" on its
        # own tells somebody that something is wrong and nothing about what.
        "partial": page.partial,
        "sources": list(page.sources),
        "missing_sources": list(page.missing_sources),
        "warnings": list(page.warnings),
    }


@monitor_bp.route("/monitors")
@login_required
def monitors_page():
    if not _require():
        flash("Access denied: monitors require the monitors:read permission.",
              "error")
        return redirect(url_for("index"))

    source = _source(request.args.get("source"))
    window, window_label = _window()

    if source is None:
        return render_template("monitors.html", data=None, no_source=True,
                               window=window_label, sources=_source_names())

    # `series=True` only where it is drawn. The certificate tab has no use for
    # it, and the extra aggregation is not free.
    page = _with_series(source, window)
    certificates = (source.certificates(window, _scope())
                    if source.supports(Capability.TLS_CERTIFICATES) else [])
    sparklines = {m.id: sparkline(m.series) for m in page.monitors}
    return render_template(
        "monitors.html", data=_payload(page, certificates), no_source=False,
        sparklines=sparklines,
        window=window_label, sources=_source_names(),
        # So the page can say "this backend cannot report certificates"
        # rather than showing an empty tab that reads as "none found".
        certificates_supported=source.supports(Capability.TLS_CERTIFICATES),
        warning_days=EXPIRY_WARNING_DAYS, critical_days=EXPIRY_CRITICAL_DAYS)


def _with_series(source, window):
    """Ask for sparkline data, and cope with a source that cannot give it.

    `monitors(window, scope, series=True)` is an extension to the interface,
    not part of it — a backend written against MonitorSource has a two-argument
    method and must keep working. Falling back rather than requiring every
    implementation to grow a keyword.
    """
    try:
        return source.monitors(window, _scope(), series=True)
    except TypeError:
        return source.monitors(window, _scope())


def _source_names():
    hub = getattr(current_app, "hub", None)
    return [s.name for s in (hub.monitor_sources if hub else [])]


def _scope():
    """Monitors are not narrowed by container scope — see the module docstring.

    Still passed, because every source method requires one and a source that
    grows a use for it later must not have to change its signature.
    """
    from ..hub.scope import Scope
    return Scope(principal=getattr(current_user, "username", "anonymous"),
                 containers=("*",))


@monitor_bp.route("/api/monitors")
@login_required
def monitors_json():
    if not _require():
        return jsonify({"error": "monitors:read is required",
                        "error_type": "permission_denied"}), 403

    source = _source(request.args.get("source"))
    if source is None:
        return jsonify({"error": "No monitor source is configured.",
                        "error_type": "no_monitor_source",
                        "monitors": [], "certificates": []}), 503

    window, _ = _window()
    certificates = (source.certificates(window, _scope())
                    if source.supports(Capability.TLS_CERTIFICATES) else [])
    return jsonify(_payload(source.monitors(window, _scope()), certificates))


@monitor_bp.route("/api/monitors/<monitor_id>/history")
@login_required
def monitor_history(monitor_id):
    if not _require():
        return jsonify({"error": "monitors:read is required",
                        "error_type": "permission_denied"}), 403

    source = _source(request.args.get("source"))
    if source is None:
        return jsonify({"error": "No monitor source is configured.",
                        "error_type": "no_monitor_source"}), 503
    if not source.supports(Capability.MONITOR_HISTORY):
        return jsonify({"checks": [], "unsupported": True,
                        "reason": f"{source.name} keeps no monitor history."})

    window, _ = _window()
    checks = source.history(monitor_id, window, _scope())
    return jsonify({"checks": [
        {"timestamp": c.timestamp.isoformat() if c.timestamp else None,
         "status": c.status,
         "duration_ms": round(c.duration_ms, 1) if c.duration_ms is not None else None,
         "error": c.error}
        for c in checks]})


@monitor_bp.route("/monitors/<monitor_id>")
@login_required
def monitor_detail(monitor_id):
    """One monitor: its response time over the window and its recent runs.

    Both, because they answer different halves of "what is wrong with this".
    The chart says WHEN — a step at 14:20, a slow creep since Tuesday. The run
    list says WHAT, because only an individual check carries the error message,
    and "received status code 500" is not something a chart can show.
    """
    if not _require():
        flash("Access denied: monitors require the monitors:read permission.",
              "error")
        return redirect(url_for("index"))

    source = _source(request.args.get("source"))
    window, window_label = _window()
    if source is None:
        return redirect(url_for("monitors.monitors_page"))

    page = _with_series(source, window)
    monitor = next((m for m in page.monitors if m.id == monitor_id), None)
    if monitor is None:
        # Not a 404: the monitor may simply not have reported inside the
        # window, which is a different thing from not existing and has a
        # different fix — a longer window.
        flash(f"No check from '{monitor_id}' in the last {window_label}.",
              "warning")
        return redirect(url_for("monitors.monitors_page", window=window_label))

    points = _series_for(source, monitor_id, window)
    page_number = max(1, request.args.get("page", type=int) or 1)
    checks, total = _checks_page(source, monitor_id, window, page_number)

    # Clamp AFTER the count is known, then fetch again. `?page=99` on ten
    # pages used to render an empty table under a pager insisting it was on
    # page ten — the table and the control disagreeing about where you are,
    # which reads as "the checks were deleted".
    pages = max(1, (total + CHECKS_PER_PAGE - 1) // CHECKS_PER_PAGE)
    if page_number > pages:
        page_number = pages
        checks, total = _checks_page(source, monitor_id, window, page_number)

    # Availability comes from the WHOLE window, not from the page on screen.
    # Computed from twenty-five rows it would change every time somebody
    # turned a page, which is a number nobody can act on.
    everything = (source.history(monitor_id, window, _scope())
                  if source.supports(Capability.MONITOR_HISTORY) else [])

    return render_template(
        "monitor_detail.html",
        monitor=_payload(MonitorPage(monitors=[monitor]), [])["monitors"][0],
        chart=response_chart(points),
        checks=[_check(c) for c in checks],
        pager=_pager(page_number, total),
        summary=_availability(points, everything),
        window=window_label,
        history_supported=source.supports(Capability.MONITOR_HISTORY),
        warning_days=EXPIRY_WARNING_DAYS, critical_days=EXPIRY_CRITICAL_DAYS)


#: Rows of check history per page. A monitor on a fifteen-second schedule
#: writes 5,760 checks a day; the table is for reading the recent ones and
#: finding an error message, not for scrolling a day.
CHECKS_PER_PAGE = 25


def _checks_page(source, monitor_id, window, page_number):
    """One page of checks, newest first, and how many there are in total."""
    if not source.supports(Capability.MONITOR_HISTORY):
        return [], 0

    offset = (page_number - 1) * CHECKS_PER_PAGE
    try:
        rows = source.history(monitor_id, window, _scope(),
                              offset=offset, limit=CHECKS_PER_PAGE)
    except TypeError:
        # A source written against the two-argument interface. Paged here
        # instead — worse, but working, and better than the screen refusing to
        # render because a backend has not caught up.
        rows = source.history(monitor_id, window, _scope())
        total = len(rows)
        newest = list(reversed(rows))
        return newest[offset:offset + CHECKS_PER_PAGE], total

    total = getattr(rows, "total", len(rows))
    # `history` returns oldest-first for the chart; the table reads newest
    # first, which is the order somebody looking for "what just broke" wants.
    return list(reversed(rows)), total


def _pager(page_number, total):
    """What the pagination control needs, or None when there is one page.

    A pager over a single page is a control that cannot do anything, and a
    control that cannot do anything is one somebody clicks before believing
    it.
    """
    pages = max(1, (total + CHECKS_PER_PAGE - 1) // CHECKS_PER_PAGE)
    if pages <= 1:
        return None
    page_number = min(page_number, pages)
    first = (page_number - 1) * CHECKS_PER_PAGE + 1
    return {
        "page": page_number,
        "pages": pages,
        "total": total,
        "first": first,
        "last": min(total, page_number * CHECKS_PER_PAGE),
        "has_previous": page_number > 1,
        "has_next": page_number < pages,
        # A window of numbers rather than all of them: 231 pages of check
        # history would be a pager wider than the table.
        "numbers": [n for n in range(page_number - 2, page_number + 3)
                    if 1 <= n <= pages],
    }


def _series_for(source, monitor_id, window):
    """The finer per-monitor series, when the backend has one."""
    getter = getattr(source, "series", None)
    if getter is None:
        return []
    try:
        return getter(monitor_id, window, _scope())
    except Exception:
        return []


def _check(check):
    return {
        "timestamp": check.timestamp.isoformat() if check.timestamp else None,
        "status": check.status,
        "duration_ms": (round(check.duration_ms, 1)
                        if check.duration_ms is not None else None),
        "error": check.error,
        "steps": [_step(s) for s in getattr(check, "steps", ())],
        "screenshot_id": getattr(check, "screenshot_id", None),
    }


def _step(step):
    return {
        "index": step.index,
        "description": step.description,
        "status": step.status,
        "duration_ms": (round(step.duration_ms, 1)
                        if step.duration_ms is not None else None),
        "error": step.error,
    }


def _availability(points, checks):
    """Numbers for the header. Computed from the RUNS, not the buckets.

    A bucket that holds six runs of which one failed is one failure out of
    six, and counting buckets would call it one failure out of one. Bucket
    counts are for drawing; run counts are for arithmetic.
    """
    total = len(checks)
    failed = sum(1 for c in checks if c.status == DOWN)
    durations = sorted(c.duration_ms for c in checks
                       if c.duration_ms is not None)
    summary = {
        "checks": total,
        "failed": failed,
        "availability": (round(100.0 * (total - failed) / total, 2)
                         if total else None),
        "median_ms": None, "p95_ms": None, "worst_ms": None,
    }
    if durations:
        summary["median_ms"] = round(durations[len(durations) // 2], 1)
        # Nearest-rank, so the value shown is one that actually happened
        # rather than an interpolation between two that did.
        rank = max(0, min(len(durations) - 1,
                          int(round(0.95 * len(durations))) - 1))
        summary["p95_ms"] = round(durations[rank], 1)
        summary["worst_ms"] = round(durations[-1], 1)
    return summary


def response_chart(points):
    """Response time over the window, as data for Chart.js.

    NOT server-rendered SVG, unlike the sparklines, and the reason is measured
    rather than assumed. Chart.js is loaded by base.html on every page
    already, so a chart here costs no download; one instance is cheap where a
    hundred would not be; and what it buys is the part a static drawing cannot
    do — hover a point and read the exact time and value, which is most of
    why somebody opens this page.

    The sparklines stay SVG for the opposite reasons: a hundred rows would be
    a hundred canvases, each with its own resize observer and animation loop,
    to draw a hundred shapes that never change. Measured, that markup is
    1.1 KB a row and compresses to about 15% of it — 16 KB over a hundred
    monitors, against a hundred chart instances.

    Two series, because the average alone hides the thing usually being looked
    for: one slow request among a hundred fast ones moves the mean by a
    percent and the maximum by a factor.
    """
    usable = [p for p in points if p.has_data and p.duration_ms is not None]
    if len(usable) < 2:
        return None

    labels, average, worst, failures = [], [], [], []
    for point in points:
        labels.append(point.timestamp.isoformat() if point.timestamp else None)
        # `None` rather than 0 for a bucket with no check. Chart.js breaks the
        # line at a null and draws straight through a zero, and a zero would
        # be a response time of nothing — the fastest reading on the chart at
        # the moment the agent stopped reporting.
        if point.has_data and point.duration_ms is not None:
            average.append(round(point.duration_ms, 1))
            slowest = getattr(point, "worst_ms", None)
            worst.append(round(slowest, 1) if slowest is not None else None)
        else:
            average.append(None)
            worst.append(None)
        failures.append(point.down or None)

    measured = [v for v in average if v is not None]
    peaks = [v for v in worst if v is not None]
    return {
        "labels": labels,
        "average": average,
        "worst": worst,
        # One entry per bucket, so the marks line up with the x axis without
        # the page having to match timestamps back to positions.
        "failures": failures,
        "failure_count": sum(f for f in failures if f),
        "peak_ms": round(max(peaks + measured), 1),
    }


@monitor_bp.route("/monitors/screenshot/<screenshot_id>")
@login_required
def journey_screenshot(screenshot_id):
    """The picture taken when a journey step failed.

    Served from here rather than inlined into the page as a data URI: a run
    list of twenty-five checks would carry twenty-five images in the HTML,
    most of which nobody opens. Behind the same permission as the rest of the
    monitoring pages — a screenshot of a signed-in session is at least as
    sensitive as the check that produced it.
    """
    if not _require():
        flash("Access denied: monitors require the monitors:read permission.",
              "error")
        return redirect(url_for("index"))

    store = getattr(current_app, "store", None)
    image = store.results.screenshot(screenshot_id) if store else None
    if image is None:
        # 404 rather than a redirect: this is an <img> target, and a redirect
        # to a page renders as a broken image with no explanation.
        return ("No such screenshot. They are kept for a week — long enough "
                "to look at a failure, short enough not to fill the database "
                "with pictures of pages that were fine.", 404)

    response = current_app.response_class(image["image"],
                                          mimetype=image["content_type"])
    # Immutable: the id is content, not a name that gets reused.
    response.headers["Cache-Control"] = "private, max-age=86400, immutable"
    response.headers["Content-Disposition"] = (
        f'inline; filename="journey-{screenshot_id[:8]}.jpg"')
    return response
