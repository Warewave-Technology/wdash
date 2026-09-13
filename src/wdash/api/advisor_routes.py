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


def _advisable_sources():
    """Every source the Advisor can say something about, by name.

    A source it cannot inspect is left OUT rather than listed and skipped: an
    entry that produces nothing reads as a clean bill of health for a backend
    that was never looked at.

    In the repository's order. It was creation order once, to agree with the
    hub about which source an unnamed query meant; no query means one source
    by naming none any more, and the Advisor has no first entry to fall back
    on either — see `_resolve`.
    """
    from ..advisor.backends import COLLECTORS

    store = getattr(current_app, "store", None)
    if store is None:
        return []

    try:
        rows = store.sources.all(enabled_only=True)
    except Exception as exc:
        current_app.logger.error(f"Could not list sources: {exc}")
        return []

    out = []
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


class ChooseSource(RuntimeError):
    """A bare request, and more than one source it could mean.

    The Advisor analyses ONE cluster, and does not fan out: a report is a
    list of findings about a deployment, and findings from two deployments
    in one list would be a report about neither. So a request that names no
    source, on an installation with several, is not answered from any of
    them. It used to be answered from the oldest stored one — the hub's own
    rule for an unnamed query, while the hub had one — and with that rule
    gone there is nothing left that could honestly be called "the" source.
    The page offers the list to choose from instead; the JSON endpoint says
    which names it would take.
    """

    def __init__(self, choices):
        self.choices = list(choices)
        super().__init__(
            "Name the source to analyse (?source=): one of "
            + ", ".join(self.choices) + ".")


def _resolve(requested):
    """The source a request means.

    Named, that one. Unnamed, the only source the Advisor can inspect when
    there is exactly one — there is no choice to make, so none is asked for
    — and `ChooseSource` when there are several. With nothing to analyse at
    all it is None, which `_build_report` refuses as NoCluster.
    """
    if requested:
        return requested
    entries = [entry["value"] for entry in _advisable_sources()]
    if len(entries) > 1:
        raise ChooseSource(entries)
    return entries[0] if entries else None


def _build_report(source):
    """One report for one source. Raises NoCluster when there is nothing."""
    from ..advisor.backends import collect
    from ..advisor.models import run_rules

    if source in (None, ""):
        raise NoCluster(
            "The Advisor has no source to analyse. Add one on the "
            "configuration page.")

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
    # the report underneath it changed with the configuration. With nothing
    # to resolve to, the build below refuses before anything is cached.
    source = _resolve(source)
    key = source
    with _lock:
        entry = _cache.get(key)
        age = time.time() - entry["at"] if entry else _CACHE_TTL
        if not force and entry is not None and age < _CACHE_TTL:
            return entry["report"], age, False

        report = _build_report(source)
        _cache[key] = {"report": report, "at": time.time()}
        return report, 0.0, True


def _selected():
    """What the picker should show for this request: the source named, or
    the only one there is, or nothing — a picker that highlighted its first
    entry beside a page analysing nothing would be a picker disagreeing
    with the page."""
    try:
        return _resolve(request.args.get("source")) or ""
    except ChooseSource:
        return ""


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
    except ChooseSource:
        # Nothing analysed, nothing claimed: the picker, and a sentence
        # saying it is waiting for a choice. Not an error — nothing failed.
        return render_template("advisor.html", report=None, age=0,
                               choose=True, rule_count=len(all_rules()),
                               sources=_advisable_sources(), selected="")
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
    except ChooseSource as exc:
        return jsonify({"error": str(exc), "error_type": "source_required",
                        "sources": exc.choices}), 400
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
