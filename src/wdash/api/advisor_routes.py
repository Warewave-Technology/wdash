"""
HTTP layer for the Advisor.

The advisor package is deliberately unaware of Flask — pure rules over pure
data. Wiring it to the web happens here.
"""

import threading
import time

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..advisor import analyze, all_rules

advisor_bp = Blueprint("advisor", __name__)

# Producing a report means a dozen or so Elasticsearch calls. A short-lived
# cache keeps page refreshes from hammering the cluster.
#
# Note: this cache is per process. Each gunicorn worker keeps its own copy, so
# there is no consistency between workers. Acceptable while the report is
# advisory and the TTL is short; report history should move to shared storage
# alongside the rest of the metadata.
_CACHE_TTL = 300
#: One entry per source. Keyed by name because two sources of the same kind
#: are two different deployments, and serving one's report for the other is
#: worse than no cache.
_cache = {}
_lock = threading.Lock()


class NoCluster(RuntimeError):
    """There is no Elasticsearch to analyse.

    Its own exception rather than a generic failure, because the two need
    different words on screen: "unable to analyse the cluster" sends somebody
    to look at a cluster that does not exist. An empty report would be worse
    still — it reads as "your cluster is perfect".
    """


#: The environment-configured Elasticsearch, which has no entry in the source
#: table and is what the Advisor has always meant by "the cluster".
ENVIRONMENT_SOURCE = "elasticsearch"


def _advisable_sources():
    """Every source the Advisor can say something about.

    A source it cannot inspect is left OUT rather than listed and skipped: an
    entry that produces nothing reads as a clean bill of health for a backend
    that was never looked at.
    """
    from ..advisor.backends import COLLECTORS

    out = []
    if getattr(current_app, "es_client", None) is not None:
        out.append({"value": ENVIRONMENT_SOURCE,
                    "label": "Elasticsearch (environment)",
                    "backend": "elasticsearch"})

    store = getattr(current_app, "store", None)
    if store is None:
        return out

    try:
        rows = store.sources.all(enabled_only=True)
    except Exception as exc:
        current_app.logger.error(f"Could not list sources: {exc}")
        return out

    for row in rows:
        kind = row["kind"]
        if kind == "elasticsearch" or kind in COLLECTORS:
            out.append({"value": row["name"], "label": row["name"],
                        "backend": kind})
    return out


def _named(report, source):
    """Stamp the source name onto a report that does not carry one.

    `analyze()` inspects a cluster it was handed and has no idea what the
    configuration page calls it. The non-Elasticsearch collectors do know —
    they are given the source name — so only this path needs it. Without it a
    report about `lab-elastic` is anonymous, which is unreadable as soon as
    there is more than one, and the source picker has nothing to agree with.

    Overwrites rather than fills in: the route is what knows the configured
    name, and a report carrying anything else under this name is the failure
    being fixed.
    """
    if report is not None:
        report.source = source
    return report


def _default_source():
    """Which source a bare `/advisor` means.

    It used to mean the environment cluster unconditionally, from when that
    was the only cluster there could be. Once ELASTICSEARCH_URL is unset and
    every source is declared on the configuration page, that default turns
    into "no Elasticsearch is configured" on a screen that is simultaneously
    listing five sources it can analyse — and picking any of them makes it
    work, so the fault reads as intermittent rather than as a wrong default.

    The environment cluster still wins when it exists, because
    `_advisable_sources` already lists it first — checking for it again here
    would be a second place deciding the same order, and the two would drift.

    Returns None only when there is genuinely nothing to analyse.
    """
    entries = _advisable_sources()
    return entries[0]["value"] if entries else None


def _build_report(source):
    """One report for one source. Raises NoCluster when there is nothing."""
    from ..advisor.backends import collect
    from ..advisor.models import run_rules

    if source in (None, ""):
        raise NoCluster(
            "The Advisor has no source to analyse. Add one on the "
            "configuration page, or set ELASTICSEARCH_URL.")

    if source == ENVIRONMENT_SOURCE:
        client = getattr(current_app, "es_client", None)
        if client is None:
            raise NoCluster(
                "The Cluster Advisor reads Elasticsearch settings, and no "
                "Elasticsearch is configured.")
        return _named(analyze(client.es), ENVIRONMENT_SOURCE)

    store = getattr(current_app, "store", None)
    row = None
    if store is not None:
        row = next((r for r in store.sources.all(enabled_only=True)
                    if r["name"] == source), None)
    if row is None:
        raise NoCluster(f"There is no source called '{source}'.")

    config = row["config"] or {}
    credential = None
    try:
        credential = store.sources.credential(row["id"])
    except Exception:
        pass
    auth = ((config.get("username"), credential)
            if config.get("username") and credential else None)

    if row["kind"] == "elasticsearch":
        from elasticsearch import Elasticsearch
        arguments = {"hosts": [config["url"]],
                     "verify_certs": config.get("verify_certs", True)}
        if auth:
            arguments["basic_auth"] = auth
        return _named(analyze(Elasticsearch(**arguments)), source)

    snapshot = collect(row["kind"], config["url"], row["name"], auth=auth,
                       verify=config.get("verify_certs", True))
    if snapshot is None:
        raise NoCluster(
            f"There is nothing the Advisor can inspect on a "
            f"{row['kind']} source.")
    return run_rules(snapshot)


def _get_report(force=False, source=None):
    """Return the cached report for one source, regenerating it when needed.

    Returns (report, age_seconds, is_fresh).
    """
    # Resolved once, then used for BOTH the cache key and the build. Keying on
    # the unresolved value would file every bare request under one name while
    # the report underneath it changed with the configuration.
    source = source or _default_source()
    key = source or ENVIRONMENT_SOURCE
    with _lock:
        entry = _cache.get(key)
        age = time.time() - entry["at"] if entry else _CACHE_TTL
        if not force and entry is not None and age < _CACHE_TTL:
            return entry["report"], age, False

        report = _build_report(source)
        _cache[key] = {"report": report, "at": time.time()}
        return report, 0.0, True


def _selected():
    """What the picker should show for this request."""
    return request.args.get("source") or _default_source() or ""


def _require_admin():
    return current_user.has_permission("system:admin")


@advisor_bp.route("/advisor")
@login_required
def advisor_page():
    if not _require_admin():
        flash("Access denied: Advisor requires administrator privileges.", "error")
        return redirect(url_for("index"))

    try:
        report, age, _ = _get_report(
            force=request.args.get("refresh") == "1",
            source=request.args.get("source"))
    except NoCluster as exc:
        flash(str(exc), "warning")
        return render_template("advisor.html", report=None, age=0,
                               no_cluster=True, rule_count=len(all_rules()),
                               sources=_advisable_sources(),
                               selected=_selected())
    except Exception as exc:
        current_app.logger.error(f"Advisor report failed: {exc}")
        flash(f"Unable to analyse the cluster: {exc}", "error")
        # WITH the source list. Dropping it means one unreachable backend
        # takes away the control you would use to pick a reachable one, and
        # the only way back is to edit the URL.
        return render_template("advisor.html", report=None, age=0,
                               rule_count=len(all_rules()),
                               sources=_advisable_sources(),
                               selected=_selected())

    return render_template(
        "advisor.html",
        report=report,
        age=int(age),
        # The rules that COULD have run here, not the whole registry: "31
        # checks" beside a Loki report claims a coverage that does not exist.
        rule_count=len(all_rules(report.backend)),
        sources=_advisable_sources(),
        # The report's own name, not the request's: a bare /advisor asked for
        # nothing in particular, and a picker showing nothing next to a report
        # about lab-elastic is a picker that disagrees with the page.
        selected=report.source or _selected(),
    )


@advisor_bp.route("/api/advisor/report")
@login_required
def advisor_report_json():
    if not _require_admin():
        return jsonify({"error": "Admin access required",
                        "error_type": "permission_denied"}), 403

    try:
        report, age, fresh = _get_report(
            force=request.args.get("refresh") == "1",
            source=request.args.get("source"))
    except NoCluster as exc:
        return jsonify({"error": str(exc), "error_type": "no_cluster"}), 503
    except Exception as exc:
        current_app.logger.error(f"Advisor report failed: {exc}")
        return jsonify({"error": "Unable to analyse the cluster",
                        "error_type": "advisor_error",
                        "details": str(exc)}), 503

    payload = report.to_dict()
    payload["cache"] = {"age_seconds": int(age), "fresh": fresh, "ttl_seconds": _CACHE_TTL}
    return jsonify(payload)


@advisor_bp.route("/api/advisor/rules")
@login_required
def advisor_rules():
    """Catalogue of registered rules, for documentation and UI filters."""
    if not _require_admin():
        return jsonify({"error": "Admin access required",
                        "error_type": "permission_denied"}), 403

    return jsonify({
        "total": len(all_rules()),
        "rules": [
            {
                "id": r.id,
                "category": r.category,
                "title": r.title,
                "min_version": ".".join(map(str, r.min_version)) if r.min_version else None,
                "distributions": list(r.distributions) if r.distributions else None,
            }
            for r in all_rules()
        ],
    })
