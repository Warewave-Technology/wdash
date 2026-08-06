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

from ..hub.models import DOWN, UNKNOWN, UP
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

    page = source.monitors(window, _scope())
    certificates = (source.certificates(window, _scope())
                    if source.supports(Capability.TLS_CERTIFICATES) else [])
    return render_template(
        "monitors.html", data=_payload(page, certificates), no_source=False,
        window=window_label, sources=_source_names(),
        # So the page can say "this backend cannot report certificates"
        # rather than showing an empty tab that reads as "none found".
        certificates_supported=source.supports(Capability.TLS_CERTIFICATES),
        warning_days=EXPIRY_WARNING_DAYS, critical_days=EXPIRY_CRITICAL_DAYS)


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
