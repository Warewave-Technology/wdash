"""
The configuration screen.

Everything an administrator can change without a restart: data sources, the
identity provider, and who gets which role. It became possible only once
authorization moved out of the session cookie — a page that edits roles while
permissions are frozen at sign-in shows a revocation that has not happened,
which is worse than having no such page.

Three rules run through every handler here:

  * `system:admin` on every route, checked per request
  * secrets are written but never rendered; the form shows "set" or "not set"
  * every change is logged with who made it, because this is the screen that
    decides who can see what

Changes take effect within the resolver's cache window (about ten seconds) on
every worker. The local process is invalidated immediately so the person who
made the change sees it at once, which is what makes the page feel truthful.
"""

import logging

from flask import (
    Blueprint, current_app, flash, jsonify, redirect, render_template, request,
    session, url_for,
)
from flask_login import current_user, login_required

from ..dashboard.invariants import (
    refuses_mapping_save, refuses_role_delete, refuses_role_save,
)
from ..hub import Scope, TimeWindow
from ..permissions import grouped as permission_groups
from ..permissions import normalise as normalise_permissions
from ..store import SOURCE_KINDS, SourceError
from ..store.secrets import SecretsUnavailable
from ..store.settings_repo import AUDIT_FORWARDING, LDAP, OIDC

logger = logging.getLogger(__name__)

config_bp = Blueprint("config", __name__, url_prefix="/admin")


def _store():
    return getattr(current_app, "store", None)


def _require_admin():
    """Returns a response when the caller must be turned away, else None."""
    if not current_user.has_permission("system:admin"):
        if request.path.startswith("/admin/api/"):
            return jsonify({"error": "Access denied",
                            "error_type": "permission_denied"}), 403
        flash("Access denied: administrator permission required.", "error")
        return redirect(url_for("index"))
    return None


def _audit(action, subject=None, state=None, **details):
    """Every configuration change, with who made it.

    Written to the log AND to the audit table. The log is for whoever is
    watching now; the table is for whoever asks, months later, what a role
    could see on the day something went wrong.
    """
    actor = getattr(current_user, "username", "unknown")
    logger.warning(
        "config change by %s: %s %s", actor, action,
        " ".join(f"{k}={v!r}" for k, v in details.items()))

    store = _store()
    if store is None:
        return
    try:
        from ..store.signin import client_address
        store.audit.record(
            actor, action, subject=subject,
            address=client_address(
                request, current_app.config.get("TRUSTED_PROXY_COUNT", 0)),
            state=state if state is not None else details or None)
    except Exception as exc:
        # Guarded here as well as inside AuditLog. Losing an audit row is bad;
        # refusing an administrator's repair because the audit trail is
        # unhappy is worse, and this is the boundary where that decision is
        # actually made.
        logger.error(f"Audit entry '{action}' could not be written: {exc}")


@config_bp.route("/config")
@login_required
def config_page():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    return render_template(
        "config.html",
        sources=store.sources.all(),
        source_kinds=SOURCE_KINDS,
        # Two registrations of one system. Detected at startup; shown here
        # because a warning in a log file is a warning nobody reads, and the
        # symptom — a merged total that is quietly too big — never points at
        # its cause.
        duplicate_sources=list(getattr(current_app, "duplicate_sources", [])),
        # {kind: [signals]} for the form. Derived here rather than written
        # out in JavaScript, so adding a backend cannot leave the two
        # disagreeing about what it serves.
        signal_map={kind: list(d["signals"])
                    for kind, d in SOURCE_KINDS.items()},
        roles=store.roles.all(),
        permission_groups=permission_groups(),
        default_role=store.settings.get("rbac.default_role", "viewer"),
        user_roles=store.settings.get("rbac.user_roles", {}) or {},
        oidc=store.settings.all(prefix="auth.").get(OIDC, {}),
        ldap=store.settings.all(prefix="auth.").get(LDAP, {}),
        secrets_available=store.secrets.available,
        cache_seconds=int(store.rbac._ttl),
    )


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------

@config_bp.route("/sources", methods=["POST"])
@login_required
def save_source():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    source_id = request.form.get("id") or None
    form = request.form

    # Signals are checkboxes now: one source serves whichever of them it
    # holds. Two rows for one cluster meant two credentials to rotate and two
    # TLS settings that could drift apart.
    signals = form.getlist("signals") or ([form.get("signal")]
                                          if form.get("signal") else [])

    config = {
        "url": form.get("url"),
        "username": form.get("username"),
        "tenant": form.get("tenant"),
        "stream_label": form.get("stream_label"),
        "stream_field": form.get("stream_field"),
        "verify_certs": form.get("verify_certs") == "on",
        # Per signal, because one cluster holding both needs a different
        # pattern for each.
        "logs": {
            "index_patterns": form.get("logs_index_patterns"),
            "exclude_patterns": form.get("logs_exclude_patterns"),
        },
        "traces": {
            "index_patterns": form.get("traces_index_patterns"),
        },
    }
    password = form.get("password") or None

    try:
        if source_id:
            saved = store.sources.update(
                source_id, name=form.get("name"), config=config,
                signals=signals or None,
                secret=password, enabled=form.get("enabled") == "on")
            if saved is None:
                flash("That source no longer exists.", "error")
                return redirect(url_for("config.config_page"))
            _audit("source updated", name=saved["name"], id=source_id)
        else:
            saved = store.sources.create(
                name=form.get("name"), signal=signals,
                kind=form.get("kind"), config=config, secret=password,
                enabled=form.get("enabled") == "on")
            _audit("source created", name=saved["name"], kind=saved["kind"])
        flash(f"Source '{saved['name']}' saved. "
              f"Restart WDash for it to be used for queries.", "success")
    except SecretsUnavailable as exc:
        flash(str(exc).split("\n")[0], "error")
    except SourceError as exc:
        flash(str(exc), "error")

    return redirect(url_for("config.config_page"))


@config_bp.route("/sources/<source_id>/delete", methods=["POST"])
@login_required
def delete_source(source_id):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    source = store.sources.get(source_id)
    if source and store.sources.delete(source_id):
        _audit("source deleted", name=source["name"], id=source_id)
        flash(f"Source '{source['name']}' deleted.", "success")
    else:
        flash("That source no longer exists.", "warning")
    return redirect(url_for("config.config_page"))


@config_bp.route("/api/sources/test", methods=["POST"])
@login_required
def test_source():
    """Check that a source is reachable before anyone relies on it.

    Uses the submitted form values rather than the stored ones, so a
    connection can be tested BEFORE it is saved — otherwise the only way to
    find out a URL is wrong is to save it and watch the dashboards break.
    """
    denied = _require_admin()
    if denied:
        return denied

    payload = request.get_json(silent=True) or {}
    store = _store()

    try:
        from ..store.sources import validate_url
        url = validate_url(payload.get("url"))
    except SourceError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 200

    password = payload.get("password")
    if not password and payload.get("id"):
        # Testing a saved source without retyping its password.
        try:
            password = store.sources.credential(payload["id"])
        except Exception:
            password = None

    from ..hub.probe import probe_source
    result = probe_source(kind=payload.get("kind"), url=url,
                          username=payload.get("username"),
                          password=password,
                          verify_certs=bool(payload.get("verify_certs")))
    return jsonify(result), 200


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

@config_bp.route("/auth", methods=["POST"])
@login_required
def save_auth():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    which = request.form.get("provider")

    if which == "oidc":
        value = {
            "client_id": (request.form.get("client_id") or "").strip(),
            "discovery_url": (request.form.get("discovery_url") or "").strip(),
            "redirect_uri": (request.form.get("redirect_uri") or "").strip(),
            "enabled": request.form.get("enabled") == "on",
        }
        secret = request.form.get("client_secret") or None
        key, label = OIDC, "OIDC"
    elif which == "ldap":
        value = {
            "server": (request.form.get("server") or "").strip(),
            "bind_dn": (request.form.get("bind_dn") or "").strip(),
            "base_dn": (request.form.get("base_dn") or "").strip(),
            "user_filter": (request.form.get("user_filter") or "").strip(),
            "group_attribute": (request.form.get("group_attribute") or "").strip(),
            "enabled": request.form.get("enabled") == "on",
        }
        secret = request.form.get("bind_password") or None
        key, label = LDAP, "LDAP"
    else:
        flash("Unknown provider.", "error")
        return redirect(url_for("config.config_page"))

    try:
        store.settings.set(key, value, secret=secret,
                           updated_by=current_user.username)
    except SecretsUnavailable as exc:
        flash(str(exc).split("\n")[0], "error")
        return redirect(url_for("config.config_page"))

    _audit(f"{label} settings updated", enabled=value.get("enabled"))
    flash(f"{label} settings saved and in force now — no restart needed.",
          "success")
    return redirect(url_for("config.config_page"))


# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------

def _lines(value):
    """Split a textarea into a list, dropping blanks."""
    return [line.strip() for line in (value or "").replace(",", "\n").splitlines()
            if line.strip()]


@config_bp.route("/api/available")
@login_required
def available_targets():
    """What actually exists, for the role editor to offer.

    Patterns cannot be replaced by a picker: containers rotate, so a role
    granted `app-logs-000001` by name silently loses access the day
    `-000002` appears. That is a worse failure than a typo, so the editor
    keeps patterns and offers this list alongside them — you write the rule,
    but you are not writing it blind.
    """
    denied = _require_admin()
    if denied:
        return denied

    hub = getattr(current_app, "hub", None)
    unrestricted = Scope.unrestricted()

    def listing(sources):
        out = []
        for source in sources or ():
            try:
                out.append({"source": source.name,
                            "containers": source.containers(unrestricted)})
            except Exception as exc:
                out.append({"source": source.name, "containers": [],
                            "error": str(exc)[:120]})
        return out

    services = []
    for source in (hub.trace_sources if hub else []):
        try:
            services.extend(
                service.name for service
                in source.services(TimeWindow.of("24h"), unrestricted))
        except Exception:
            continue

    return jsonify({
        "logs": listing(hub.log_sources if hub else []),
        "traces": listing(hub.trace_sources if hub else []),
        "services": sorted(set(services)),
    })


def _reachable(scope, sources, trace_side=False):
    """Container names a scope reaches, across every source."""
    out = set()
    for source in sources or ():
        try:
            if trace_side:
                out.update(scope.resolve_traces(
                    source.containers(Scope.unrestricted()), source=source.name))
            else:
                out.update(source.containers(scope))
        except Exception:
            continue
    return out


def _describe_change(previous, scope, logs, traces):
    """What this edit adds and removes, in containers and in permissions."""
    hub = getattr(current_app, "hub", None)

    before_scope = Scope(
        principal="before",
        containers=tuple(previous.get("containers") or ()),
        trace_containers=tuple(previous.get("trace_containers") or ()),
        services=(tuple(previous["services"])
                  if previous.get("services") is not None else None),
        permissions=frozenset(previous.get("permissions") or ()))

    before_logs = _reachable(before_scope, hub.log_sources if hub else [])
    before_traces = _reachable(before_scope, hub.trace_sources if hub else [],
                               trace_side=True)
    after_logs = {name for entry in logs for name in entry["containers"]}
    after_traces = {name for entry in traces for name in entry["containers"]}

    before_permissions = set(previous.get("permissions") or ())

    return {
        "logs_added": sorted(after_logs - before_logs),
        "logs_removed": sorted(before_logs - after_logs),
        "traces_added": sorted(after_traces - before_traces),
        "traces_removed": sorted(before_traces - after_traces),
        "permissions_added": sorted(scope.permissions - before_permissions),
        "permissions_removed": sorted(before_permissions - scope.permissions),
        # Widening is the direction worth pointing at. Narrowing is usually
        # deliberate; widening is usually a pattern that did not do what the
        # person meant.
        "widens": bool((after_logs - before_logs)
                       or (after_traces - before_traces)
                       or (scope.permissions - before_permissions)),
    }


@config_bp.route("/api/roles/preview", methods=["POST"])
@login_required
def preview_role():
    """What would this role actually reach?

    An administrator writes patterns and, until now, guessed at the result.
    Patterns are the part of a role that is easy to get wrong and impossible
    to check by reading: `app-*` looks obviously correct right up until the
    indices are called `application-*`.

    Read-only and computed from the live sources, so it answers about this
    installation rather than about the pattern language.
    """
    denied = _require_admin()
    if denied:
        return denied

    payload = request.get_json(silent=True) or {}
    services = payload.get("services")

    scope = Scope(
        principal="preview",
        containers=tuple(payload.get("containers") or ()),
        trace_containers=tuple(payload.get("trace_containers") or ()),
        # Blank means unrestricted on the trace side; the form says so, and the
        # preview has to agree with the form or it teaches the wrong thing.
        services=None if not services else tuple(services),
        permissions=frozenset(payload.get("permissions") or ()))

    hub = getattr(current_app, "hub", None)
    logs, traces, warnings = [], [], []

    for source in (hub.log_sources if hub else []):
        try:
            reachable = source.containers(scope)
        except Exception as exc:
            warnings.append(f"{source.name} could not be listed: {exc}")
            continue
        try:
            everything = source.containers(Scope.unrestricted())
        except Exception:
            everything = reachable
        logs.append({"source": source.name, "containers": reachable,
                     "count": len(reachable), "total": len(everything)})

    for source in (hub.trace_sources if hub else []):
        try:
            everything = source.containers(Scope.unrestricted())
            reachable = scope.resolve_traces(everything, source=source.name)
        except Exception as exc:
            warnings.append(f"{source.name} could not be listed: {exc}")
            continue
        traces.append({"source": source.name, "containers": reachable,
                       "count": len(reachable), "total": len(everything)})

    # Two outcomes are worth calling out, and only one of them was.
    #
    # Reaching nothing is usually a typo. Reaching EVERYTHING is the dangerous
    # direction: `*` typed where `app-*` was meant looks like a working
    # pattern, saves cleanly, and grants the whole cluster. Nothing said so.
    def covers_all(entries, patterns):
        if not patterns:
            return False
        return all(entry["count"] == entry["total"] and entry["total"]
                   for entry in entries)

    # What CHANGES, not just what the result is.
    #
    # The end state is what the form already shows; the delta is what an
    # access-control review is actually about. `ap-*` where `app-*` was meant
    # produces a plausible-looking count and a completely different set, and
    # "grants 3 containers it did not have" is the sentence that catches it.
    change = None
    editing = (payload.get("name") or "").strip()
    store = _store()
    if editing and store is not None:
        previous = store.roles.get(editing)
        if previous is not None:
            change = _describe_change(previous, scope, logs, traces)

    return jsonify({
        "change": change,
        "logs": logs,
        "traces": traces,
        "services": ("every service" if scope.services is None
                     else list(scope.services)),
        "permissions": sorted(scope.permissions),
        "warnings": warnings,
        "reaches_nothing": not any(entry["count"] for entry in logs)
                           and not any(entry["count"] for entry in traces),
        "reaches_everything": {
            "logs": covers_all(logs, scope.containers),
            "traces": covers_all(traces, scope.trace_containers),
            "services": scope.services is None,
        },
    })


@config_bp.route("/roles", methods=["POST"])
@login_required
def save_role():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("A role name is required.", "error")
        return redirect(url_for("config.config_page"))

    # Checkboxes when the form is used; a textarea still works for anything
    # posting directly. Either way the names are validated against the
    # catalogue — a permission that grants nothing while looking configured is
    # worse than a rejected one.
    # `getlist` returns one item per checkbox, but a client posting a textarea
    # yields a single item holding every line. Splitting each item covers both
    # without the caller having to say which shape it sent.
    submitted = [name
                 for entry in request.form.getlist("permissions")
                 for name in _lines(entry)]
    permissions, unknown, renamed = normalise_permissions(submitted)

    if unknown:
        flash(f"Not a permission WDash knows: {', '.join(unknown)}. "
              f"The role was not saved.", "error")
        return redirect(url_for("config.config_page"))
    if renamed:
        flash("Renamed since this role was written: "
              + ", ".join(f"{old_name} is now {new_name}"
                          for old_name, new_name in renamed), "info")

    # System invariants, checked before anything is written. These are not
    # permission checks — an administrator with every permission still must
    # not be able to leave the installation with nobody able to administer it.
    refusal = refuses_role_save(store.roles.all(), name, permissions,
                                getattr(current_user, "role", None))
    if refusal:
        # Recorded too: an attempt to remove the last administrator is more
        # worth knowing about than a change that went through.
        _audit("role save refused", subject=f"role:{name}",
               state={"reason": refusal, "permissions": permissions})
        flash(refusal, "error")
        return redirect(url_for("config.config_page"))

    # Creating something that already exists is almost always a mistake, and
    # the mistake silently replaces a working role. Trailing whitespace makes
    # it easy to hit by accident.
    if request.form.get("mode") == "create" and store.roles.get(name):
        flash(f"A role called '{name}' already exists. Edit it instead, or "
              f"choose another name.", "error")
        return redirect(url_for("config.config_page"))

    services = request.form.get("services")
    store.roles.upsert(
        name,
        permissions=permissions,
        containers=_lines(request.form.get("containers")),
        trace_containers=_lines(request.form.get("trace_containers")),
        # Blank means unrestricted on the trace side, which is different from
        # a list containing nothing. Collapsing the two would either open every
        # service or close them all.
        services=(None if not (services or "").strip() else _lines(services)),
        groups=_lines(request.form.get("groups")),
        description=request.form.get("description"))

    store.rbac.invalidate()
    _audit("role saved", subject=f"role:{name}", state=store.roles.get(name))
    flash(f"Role '{name}' saved. It reaches every worker within "
          f"{int(store.rbac._ttl)} seconds.", "success")
    return redirect(url_for("config.config_page"))


@config_bp.route("/roles/<name>/delete", methods=["POST"])
@login_required
def delete_role(name):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()

    refusal = refuses_role_delete(store.roles.all(), name,
                                  getattr(current_user, "role", None))
    if refusal:
        flash(refusal, "error")
        return redirect(url_for("config.config_page"))

    removed = store.roles.get(name)
    if store.roles.delete(name):
        store.rbac.invalidate()
        _audit("role deleted", subject=f"role:{name}", state=removed)
        flash(f"Role '{name}' deleted.", "success")
    else:
        flash("That role no longer exists.", "warning")
    return redirect(url_for("config.config_page"))


@config_bp.route("/mappings", methods=["POST"])
@login_required
def save_mappings():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    known = {role["name"] for role in store.roles.all()}

    default_role = (request.form.get("default_role") or "").strip()
    if default_role and default_role not in known:
        flash(f"'{default_role}' is not a role.", "error")
        return redirect(url_for("config.config_page"))

    mappings, rejected = {}, []
    for line in _lines(request.form.get("user_roles")):
        if "=" not in line:
            rejected.append(line)
            continue
        identifier, role = line.split("=", 1)
        identifier, role = identifier.strip(), role.strip()
        if not identifier or role not in known:
            rejected.append(line)
            continue
        mappings[identifier] = role

    if rejected:
        # Silently dropping a mapping is silently changing somebody's access.
        flash(f"These mappings were not understood and have been ignored: "
              f"{', '.join(rejected)}", "warning")

    refusal = refuses_mapping_save(
        store.roles.all(), default_role, mappings,
        getattr(current_user, "role", None),
        actor_identifiers=(current_user.username, current_user.email),
        actor_local_role=session.get("user_data", {}).get("local_role"))
    if refusal:
        flash(refusal, "error")
        return redirect(url_for("config.config_page"))

    store.settings.set("rbac.default_role", default_role or "viewer",
                       updated_by=current_user.username)
    store.settings.set("rbac.user_roles", mappings,
                       updated_by=current_user.username)
    store.rbac.invalidate()
    _audit("mappings updated", subject="rbac:mappings",
           state={"default_role": default_role or "viewer",
                  "user_roles": mappings})
    flash("Role mappings saved.", "success")
    return redirect(url_for("config.config_page"))


# ---------------------------------------------------------------------------
# The audit trail
#
# Two tables, one screen. Configuration changes and sign-in attempts answer
# different halves of the same question — "who could see what, and who was
# trying to" — and an administrator chasing an incident should not have to
# know that they are stored apart.
#
# Read-only, deliberately and without an exception. There is no delete, no
# edit, and no retention control in the UI: a trail an administrator can prune
# from the same screen they are being audited on is not a trail. Pruning
# sign-in attempts happens on a fixed schedule inside the guard, where nobody
# chooses when.
# ---------------------------------------------------------------------------

AUDIT_PAGE_SIZE = 100


def _secret_present(store, key):
    """Whether a secret is stored, without reading it into the page."""
    try:
        return store.settings.secret(key) is not None
    except Exception:
        return False


def _parse_moment(raw):
    """A datetime-local value, or None. Bad input filters nothing."""
    if not raw:
        return None
    import datetime as dt
    for shape in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(raw, shape).replace(
                tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def _audit_filters():
    return {
        "actor": (request.args.get("actor") or "").strip() or None,
        "action": (request.args.get("action") or "").strip() or None,
        "subject": (request.args.get("subject") or "").strip() or None,
        "since": _parse_moment(request.args.get("since")),
        "until": _parse_moment(request.args.get("until")),
    }


@config_bp.route("/audit")
@login_required
def audit_page():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    if store is None:
        flash("No metadata store is configured, so there is no audit trail.",
              "warning")
        return redirect(url_for("config.config_page"))

    filters = _audit_filters()
    try:
        page = max(0, int(request.args.get("page", 0)))
    except ValueError:
        page = 0

    entries = store.audit.recent(limit=AUDIT_PAGE_SIZE,
                                 offset=page * AUDIT_PAGE_SIZE, **filters)
    total = store.audit.count(**filters)

    # Sign-in attempts are not filtered by the same fields — they have no
    # action or subject — so they are shown as their own list rather than
    # pretending the filters apply to them.
    attempts = store.signin.recent(limit=50)

    forwarding = store.settings.get(AUDIT_FORWARDING) or {}
    pending = 0
    if forwarding.get("enabled"):
        try:
            forwarder = _forwarder(forwarding)
            pending = forwarder.pending() if forwarder else 0
        except Exception as exc:
            logger.error(f"Could not inspect the forwarding queue: {exc}")

    return render_template(
        "audit.html",
        forwarding=forwarding,
        forwarding_kinds=AUDIT_DESTINATIONS,
        forwarding_pending=pending,
        forwarding_secret_set=bool(_secret_present(store, AUDIT_FORWARDING)),
        entries=entries,
        total=total,
        page=page,
        page_size=AUDIT_PAGE_SIZE,
        pages=max(1, (total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE),
        filters={key: request.args.get(key, "") for key in
                 ("actor", "action", "subject", "since", "until")},
        actions=store.audit.actions(),
        attempts=attempts,
    )


@config_bp.route("/audit/export")
@login_required
def audit_export():
    """The filtered trail as JSON lines, for whoever asks for evidence.

    JSON lines rather than a single array: it is what every log pipeline on
    the receiving end already reads, it streams, and a truncated download is
    still parseable up to the truncation instead of being one broken document.

    Capped. An unbounded export of an append-only table is a way to run the
    process out of memory from a URL.
    """
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    if store is None:
        return jsonify({"error": "No metadata store is configured."}), 503

    limit = min(int(request.args.get("limit", 10000)), 50000)
    entries = store.audit.recent(limit=limit, **_audit_filters())

    import json

    def lines():
        for entry in entries:
            row = dict(entry)
            at = row.get("at")
            row["at"] = at.isoformat() if hasattr(at, "isoformat") else at
            yield json.dumps(row, default=str) + "\n"

    from flask import Response
    return Response(
        lines(), mimetype="application/x-ndjson",
        headers={"Content-Disposition":
                 'attachment; filename="wdash-audit.jsonl"'})


# ---------------------------------------------------------------------------
# Where the audit trail goes next
#
# The sweep runs on request rather than on a timer: there is no scheduler in
# this process, and inventing one to ship an audit trail would be a background
# thread that fails silently at three in the morning. The Forward button and
# the health of the queue are both on this page, so "is it flowing" is a
# question with an answer on screen instead of in a log file.
# ---------------------------------------------------------------------------

AUDIT_DESTINATIONS = ("splunk", "elasticsearch")


def _forwarder(settings=None):
    """A forwarder for the stored destination, or None when it is off."""
    from ..store.forwarding import AuditForwarder, build_sink

    store = _store()
    if store is None:
        return None
    settings = settings if settings is not None else store.settings.get(
        AUDIT_FORWARDING)
    if not settings:
        return None

    credential = None
    try:
        credential = store.settings.secret(AUDIT_FORWARDING)
    except SecretsUnavailable:
        pass

    sink = build_sink(settings, credential)
    if sink is None:
        return None
    return AuditForwarder(store.engine, sink)


@config_bp.route("/audit/forwarding", methods=["POST"])
@login_required
def save_audit_forwarding():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    if store is None:
        flash("No metadata store is configured.", "error")
        return redirect(url_for("config.audit_page"))

    kind = (request.form.get("kind") or "").strip()
    if kind not in AUDIT_DESTINATIONS:
        flash(f"Unknown destination '{kind}'.", "error")
        return redirect(url_for("config.audit_page"))

    value = {
        "kind": kind,
        "enabled": request.form.get("enabled") == "on",
        "url": (request.form.get("url") or "").strip(),
        "index": (request.form.get("index") or "").strip(),
        "username": (request.form.get("username") or "").strip(),
        "verify_certs": request.form.get("verify_certs") == "on",
    }

    # Same rule as every other secret on this page: written, never rendered,
    # and left alone when the field comes back empty. Otherwise saving any
    # other field would quietly erase the token.
    credential = request.form.get("credential") or None

    try:
        store.settings.set(AUDIT_FORWARDING, value=value, secret=credential,
                           updated_by=getattr(current_user, "username", None))
    except SecretsUnavailable as exc:
        flash(str(exc), "error")
        return redirect(url_for("config.audit_page"))
    except Exception as exc:
        logger.error(f"Could not save audit forwarding: {exc}")
        flash("The destination could not be saved.", "error")
        return redirect(url_for("config.audit_page"))

    _audit("audit forwarding updated", subject="audit:forwarding",
           state={key: item for key, item in value.items()})
    flash("Audit forwarding saved.", "success")
    return redirect(url_for("config.audit_page"))


@config_bp.route("/audit/forward", methods=["POST"])
@login_required
def run_audit_forwarding():
    """Ship whatever is waiting, now.

    Reports what happened in both directions. A forwarder that says nothing on
    success and nothing on failure is one an administrator has to go and check
    somewhere else, which means nobody checks it.
    """
    denied = _require_admin()
    if denied:
        return denied

    from ..store.forwarding import SinkError

    try:
        forwarder = _forwarder()
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("config.audit_page"))

    if forwarder is None:
        flash("Audit forwarding is not configured, or is switched off.",
              "warning")
        return redirect(url_for("config.audit_page"))

    try:
        shipped = forwarder.drain()
    except SinkError as exc:
        # Not audited as a configuration change, because nothing changed. It
        # is logged, and the queue depth on the page tells the same story.
        logger.error(f"Audit forwarding failed: {exc}")
        flash(f"Forwarding failed, and nothing was marked as sent: {exc}",
              "error")
        return redirect(url_for("config.audit_page"))

    flash(f"{shipped:,} entr{'y' if shipped == 1 else 'ies'} forwarded."
          if shipped else "Nothing was waiting.", "success")
    return redirect(url_for("config.audit_page"))
