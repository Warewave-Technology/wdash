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

from ..auth.providers import (
    FIELDS as PROVIDER_FIELDS, LABELS, directory, listed, malformed, missing,
    refuses_second_directory, why_unusable,
)
from ..dashboard.invariants import (
    FEW, few, refuses_account_change, refuses_directory_off,
    refuses_mapping_save, refuses_role_delete, refuses_role_save,
)
from .access import source_names
from ..hub import Scope, TimeWindow
from ..permissions import grouped as permission_groups
from ..permissions import normalise as normalise_permissions
from ..store import SOURCE_KINDS, SourceError, WeakPassword
from ..alerts.evaluate import RULE_KINDS
from ..store.alerting import AlertingError
from ..store.monitoring import MONITOR_KINDS, MonitoringError
from ..store.secrets import SecretsUnavailable
from ..store.settings_repo import AUDIT_FORWARDING, LDAP, OIDC

logger = logging.getLogger(__name__)

config_bp = Blueprint("config", __name__, url_prefix="/admin")


def _reloaded(saved=None):
    """Put the change into force here and now, and say what happened.

    Returns (sentence, flash category).

    The hub reloads its configured sources by itself within a few seconds, so
    this is not what makes the edit take effect — it is what makes it take
    effect BEFORE the redirect renders the page the administrator is about to
    read. Without it the screen that just accepted a source would still be
    listing the sources from before it.

    The sentence is part of the job. "Saved" with nothing after it leaves
    somebody wondering whether they now have to restart something, which is
    exactly the doubt this feature exists to remove.

    And it has to be TRUE. `reload()` does not raise when one row out of
    several cannot be built — it logs that row and returns a count — so the
    only branch that said anything but "in use now" was dead, and a source
    whose credential would not decrypt was reported as in use while every
    query naming it answered "no log source named it". When `saved` is given,
    the row is looked for among the sources the hub now holds.
    """
    hub = getattr(current_app, "hub", None)
    if hub is None or not hasattr(hub, "reload"):
        return ".", "success"
    try:
        hub.reload()
    except Exception:
        current_app.logger.exception("Could not reload sources after a save")
        return (". It could not be put into use straight away — restart "
                "WDash, and check the log for why."), "error"

    if saved is not None and not saved.get("enabled", True):
        return (". It is disabled, so nothing queries it — tick Enabled to "
                "put it into use."), "success"
    missing = _not_live(hub, saved) if saved is not None else None
    if missing:
        return (f", but it is NOT in use: {missing} Until that is fixed, "
                f"every query naming it fails."), "error"
    return " and in use now. Other workers pick it up within a few seconds.", \
        "success"


def _not_live(hub, saved):
    """Why a just-saved source is not answering queries, or None."""
    # A hub that does not rebuild from the store answers 0 to everything, and
    # "your source could not be built" is not what that means.
    if not getattr(hub, "rebuilds_from_store", True):
        return None

    # The hub's own answer first. A name FOUND in the registry is not proof
    # that this row is the one answering to it: when the name is a base one,
    # the source WDash registers itself is holding it, every signal looks
    # live, and the save flashed "saved and in use now" in green on the very render
    # that drew "not in use" beside the row it was about. Two sentences about
    # one row, in one response, disagreeing.
    reasons = getattr(hub, "source_failures", None) or {}
    recorded = reasons.get(saved["name"])
    if recorded:
        return recorded

    live = {}
    for signal in saved.get("signals") or ():
        try:
            sources = getattr(hub, {"logs": "log_sources",
                                    "traces": "trace_sources",
                                    "monitors": "monitor_sources"}[signal])
        except KeyError:
            continue
        live[signal] = {source.name for source in sources}
    absent = [signal for signal, names in live.items()
              if saved["name"] not in names]
    if not absent:
        return None
    # Absent and unexplained: a rebuild that failed wholesale keeps the last
    # good picture and records nothing about this row.
    return f"nothing is registered for {', '.join(absent)}. The log says why."


def _directory_conflict():
    """Two directories configured here, or one that cannot be read, in words.

    Read from the app, and tolerant of an app object that has not caught up.
    It is the same sentence the startup log and the audit row carry, because
    they read the same function — a banner that can disagree with the log is
    worse than no banner.
    """
    conflict = getattr(current_app, "directory_conflict", None)
    if callable(conflict):
        try:
            return conflict()
        except Exception:
            current_app.logger.exception("Could not resolve the directory")
    return None


def _shadowed_sources(rows):
    """{source id: the signals another source of the same name also serves}.

    The hub keys one registry per signal by name, so two enabled sources
    sharing a name within one signal leave exactly one of them reachable and
    the other answering nothing — in the `*` fan-out too. The repository
    refuses to make such a pair now, and migration 15 reported the pairs a
    store already had, once, at upgrade time. Neither covers a collision that
    arrives afterwards: a pg_restore, an UPDATE run straight against the
    database, an older node still writing rows. Until this, the page listed
    both as ordinary healthy sources and the only signal was a log line at
    the next hub reload.

    Computed from the rows the page already holds, so it is one pass over a
    list rather than another query. Disabled rows are left out: they are
    built into no adapter, so they shadow nothing, and marking them would be
    the same untrue sentence pointing the other way.
    """
    live = [row for row in rows if row.get("enabled")]
    shared = {}
    for index, row in enumerate(live):
        for other in live[index + 1:]:
            if row["name"] != other["name"]:
                continue
            both = set(row["signals"]) & set(other["signals"])
            if both:
                shared.setdefault(row["id"], set()).update(both)
                shared.setdefault(other["id"], set()).update(both)
    return {key: sorted(value) for key, value in shared.items()}


def _store():
    return getattr(current_app, "store", None)


def _why(exc, limit=200):
    """An exception as a bounded sentence for the page, cut in the MIDDLE.

    `str(exc)[:120]` kept the head, and the head of a refused connection is
    the URL requests has just repeated back: every one of them read
    "HTTPConnectionPool(host='...', port=1): Max retries exceeded with url:
    /api/v2/search/tag/resource.ser" and stopped there. The cause is the LAST
    clause of that message — "[Errno 61] Connection refused" — so the only
    part worth showing was the only part guaranteed to be cut.

    Both ends are kept: which store and which call, then what happened.
    Bounded still, because this goes onto a screen and not into a log.
    """
    text = " ".join(str(exc).split())
    if len(text) <= limit:
        return text
    head = (limit - 3) // 2
    return f"{text[:head]}...{text[len(text) - (limit - 3 - head):]}"


def _source_failures():
    """Stored sources the hub is not answering from, as {name: why}.

    Tolerates a hub built by something that has not caught up, the way the
    duplicate warning does.
    """
    hub = getattr(current_app, "hub", None)
    try:
        return dict(getattr(hub, "source_failures", None) or {})
    except Exception:
        current_app.logger.exception("Could not read the source failures")
        return {}


def _require_admin():
    """Returns a response when the caller must be turned away, else None."""
    if not current_user.has_permission("system:admin"):
        if request.path.startswith("/admin/api/"):
            return jsonify({"error": "Access denied",
                            "error_type": "permission_denied"}), 403
        flash("Access denied: administrator permission required.", "error")
        return redirect(url_for("index"))
    return None


def _actor():
    """Who is asking, in the shape the invariants resolve.

    Identity, not the resolved role: the invariants ask the resolver's own
    rule where this person would land AFTER a change, so they need what the
    resolver needs — email, username, the groups the identity provider
    asserted, and the role stored on a local account.
    """
    data = session.get("user_data") or {}
    username = getattr(current_user, "username", None)
    local_role = data.get("local_role")
    if data.get("provider") == "local account":
        # READ NOW, not taken from the cookie — the same thing
        # `load_user_from_session` does, for the same reason, which is why
        # the two disagreeing mattered. `local_role` is written at sign-in
        # and never rewritten, so authorization was fresh and the lockout
        # question was stale: measured, an account promoted to admin after
        # signing in still answered `viewer` here, and the invariants that
        # ask "would this change leave nobody able to administer" were
        # answering about a picture that had already changed.
        account = _store().users.by_username(username)
        local_role = account["role"] if account else None
    return {"email": getattr(current_user, "email", None),
            "username": username,
            "groups": list(getattr(current_user, "groups", None) or ()),
            "local_role": local_role,
            # Which door this session came through, for the rule about turning
            # a directory off. Absent in a session written before it was
            # recorded, and then nothing is claimed about it.
            "provider": data.get("provider")}


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
    sources = store.sources.all()
    return render_template(
        "config.html",
        sources=_readable_sources(sources),
        # Two sources of one name inside one signal, as the store stands right
        # now. A collision can arrive after the upgrade that reported the ones
        # it found, and the row it breaks is on this page.
        shadowed_sources=_shadowed_sources(sources),
        source_kinds=SOURCE_KINDS,
        # {name: why} for a row that is stored and answers nothing. The list
        # used to be the stored rows alone, with no built or live state at
        # all, so a source whose credential would not decrypt sat in the
        # table looking exactly like one that works.
        source_failures=_source_failures(),
        # Two directories configured, or the one in force unreadable. Computed
        # on demand, not at startup: a conflict can be made on this page while
        # the process runs, and a warning that waits for a restart is a
        # warning about something somebody has already walked away from.
        directory_conflict=_directory_conflict(),
        # {kind: [signals]} for the form. Derived here rather than written
        # out in JavaScript, so adding a backend cannot leave the two
        # disagreeing about what it serves.
        signal_map={kind: list(d["signals"])
                    for kind, d in SOURCE_KINDS.items()},
        # Every signal any backend can serve, in declaration order. The form's
        # checkboxes are rendered from this rather than written out, so a
        # signal added to SOURCE_KINDS cannot end up known to the page and
        # impossible to tick.
        all_signals=list(dict.fromkeys(
            signal for d in SOURCE_KINDS.values() for signal in d["signals"])),
        # The checks WDash runs itself. Separate from `sources`, which is
        # where it reads checks something else ran.
        # Alerting. `alert_state` is not shown: it is the state machine's
        # memory, and a screen full of failure counters invites somebody to
        # edit one.
        channels=store.channels.all(),
        rules=store.rules.all(),
        silences=store.silences.all(),
        rule_kinds=RULE_KINDS,
        rule_descriptions=RULE_DESCRIPTIONS,
        # Each rule rendered as a sentence. Built here rather than in the
        # template because it is a statement about what the rule DOES, and a
        # template assembling it out of `kind`, `threshold` and `selector`
        # produces three jargon fragments side by side — which is what the
        # first version did, and nobody could read it.
        rule_sentences={r["id"]: _describe_rule(r, store.channels.all())
                        for r in store.rules.all()},
        undelivered=store.alert_history.count(undelivered_only=True),
        own_agents=store.agents.all(),
        own_monitors=store.monitors.all(),
        monitor_kinds=MONITOR_KINDS,
        step_kinds=journey_step_kinds(),
        roles=store.roles.all(),
        # The local accounts, on the Authentication tab. Read here rather
        # than in the template so the page cannot ask the database while it
        # renders — and so the one list answers both the table and the
        # "which of these names a mapping also names" note beside the role.
        local_accounts=store.users.all(),
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

def _unusable_ca_file(path):
    """Why a CA file cannot be used, or None — read the way a sign-in will
    read it. A mistyped path was saved without a word and surfaced at sign-in
    as "the directory could not be reached", which it could."""
    import ssl
    try:
        ssl.create_default_context(cafile=path)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return getattr(exc, "strerror", None) or str(exc) or type(exc).__name__
    return None


def _where(url):
    """scheme://host:port of a URL — where a secret sent to it goes."""
    from ..store.secrets import destination
    scheme, host, port = destination(url)
    return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"


def _moves_secret(stored, submitted, url_key, verify_key=None):
    """What a change does to where a stored secret is sent, in words.

    Empty when nothing, and the secret may stay. Otherwise it may not: a
    blank password box means "keep it", and keeping it for a new destination
    is how a stored password is collected without ever being shown — see
    rule 4 in store/secrets.py. Turning certificate checks off counts: the
    destination is then whoever answers for it.

    The account is not part of it. A new username or client id sends the
    secret to the server it was saved for, which already has it.
    """
    from ..store.secrets import may_follow
    moved = []
    if not may_follow(stored.get(url_key), submitted.get(url_key)):
        moved.append(f"points it at {_where(submitted.get(url_key))} instead "
                     f"of {_where(stored.get(url_key))}")
    if (verify_key and stored.get(verify_key, True) is not False
            and not submitted.get(verify_key)):
        moved.append("turns certificate checks off")
    return moved


def _without_password(url):
    """A URL with any password in it replaced, for a row people read.

    The store's, because the upgrade step that reports these rows has to mask
    them identically and a second implementation is the one that drifts.
    """
    from ..store.sources import without_password
    return without_password(url)


def _readable_sources(sources):
    """The source rows as the page may show them.

    `validate_url` refuses a password in an address now, so nothing saved
    from here on has one — but a row written by an older build still does,
    and this page printed it twice: in the URL cell and inside the edit
    button's `data-source` JSON, which is the copy an administrator's browser
    hands to anything that can read the DOM.

    Masking the value is safe in a way it would not have been before: the
    masked form carries a password too as far as `validate_url` is concerned,
    so saving the row back is refused for the same reason the real one is,
    and nobody can turn `***` into their password by pressing Save. Which is
    also the only way that row gets cleaned — the refusal names the boxes.
    """
    out = []
    for source in sources:
        config = dict(source.get("config") or {})
        if config.get("url"):
            config["url"] = _without_password(config["url"])
        out.append({**source, "config": config})
    return out


def _source_state(source, **extra):
    """What a source is after a change, for the audit row: all of it but
    the password, which is recorded as there or not."""
    config = dict(source.get("config") or {})
    if config.get("url"):
        config["url"] = _without_password(config["url"])
    return {"name": source["name"], "kind": source["kind"],
            "signals": source.get("signals"), "enabled": source.get("enabled"),
            "config": config, "has_secret": source.get("has_secret"), **extra}


def _pairs(text):
    """`Name: value` a line at a time.

    A textarea rather than a repeating row widget: an operator pasting five
    headers out of a curl command should be able to paste them, and the
    parsing is one line of code against a control that is several hundred.
    """
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        if name.strip():
            out[name.strip()] = value.strip()
    return out


def _signals_with_fields():
    """Signals whose configuration is per-signal rather than shared.

    Read from the catalogue so a new signal cannot be offered by the form and
    ignored by the save.
    """
    return [signal for kind in SOURCE_KINDS.values()
            if kind.get("signal_fields")
            for signal in kind["signals"]]


@config_bp.route("/sources", methods=["POST"])
@login_required
def save_source():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    source_id = request.form.get("id") or None
    form = request.form
    # Read once, here: the save needs the row it is replacing both to carry
    # forward the fields the form does not carry and to check what a rename
    # would do to the roles.
    existing = store.sources.get(source_id) if source_id else None

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
    }

    # Per-signal blocks, because one cluster holding several signals needs a
    # different pattern for each — flattened into one key, a trace search
    # scans the log indices.
    #
    # BUILT FROM THE CATALOGUE, not written out. Two blocks were listed here
    # by hand while SOURCE_KINDS declared which fields each signal takes, so
    # adding `monitors` gave the form a box somebody could type into and the
    # save silently dropped it. A field that accepts input and discards it is
    # worse than one that is missing.
    #
    # And a field the form does not carry AT ALL is carried forward from the
    # stored row rather than written blank. The catalogue declares
    # `exclude_patterns` for every signal and the modal has one box for it —
    # the log one — so an edit made to rename a source or rotate its password
    # emptied `traces.exclude_patterns` and `monitors.exclude_patterns`: the
    # monitor-pattern fault again, one field further along. `None` is "no such
    # box on this form"; `""` is a box that is there and was cleared, which
    # means empty and is saved as empty.
    stored = (existing or {}).get("config") or {}
    for signal in _signals_with_fields():
        block = {}
        for field in SOURCE_KINDS["elasticsearch"]["signal_fields"]:
            value = form.get(f"{signal}_{field}")
            if value is None:
                kept = (stored.get(signal) or {}).get(field)
                if kept:
                    block[field] = list(kept)
                continue
            block[field] = value
        config[signal] = block
    password = form.get("password") or None
    # A blank box means "keep what is stored", so there has to be something
    # that means "there should be none". Ignored when a password is also
    # typed: that submission is a replacement, and treating it as a removal
    # would throw away what somebody just entered.
    forget = form.get("forget_password") == "on" and not password

    # A source that does not verify is talking to whatever answered, so it
    # must not hold a credential. The same rule a check has had since the
    # monitor TLS work, arrived at here from the other side: this used to be
    # allowed as long as the password was TYPED AGAIN — measured, an
    # Elasticsearch at https://es.internal:9200 saved with `verify_certs`
    # off and its password re-entered, and WDash then sent that password on
    # every query to whatever answered for that address.
    #
    # Retyping is consent, and consent is not protection: the connection is
    # still unverified and the secret still leaves. The stored-secret rule
    # below is a different question — may a secret FOLLOW a change — and
    # keeps its retype.
    #
    # The remedy is not a box on this form. A check needs its own pasted
    # certificate because the agent that makes the connection runs on
    # somebody else's host; this connection is made by the WDash server
    # itself, so a private authority belongs in that host's trust store,
    # where every other client on it will also find it.
    #
    # Over TLS only, because that is what the switch is about. A Loki at
    # `http://localhost:3100` has no certificate to check and `verify_certs`
    # decides nothing there — refusing it would be a rule about a box
    # rather than about a connection. What a credential over plain HTTP
    # costs is a different question and this is not an answer to it.
    over_tls = (config.get("url") or "").strip().lower().startswith("https://")
    holds_secret = bool(password) or bool(
        existing and existing["has_secret"] and not forget)
    if over_tls and holds_secret and not config["verify_certs"]:
        flash("A source that does not verify the certificate is talking to "
              "whatever answered, and this one holds a credential it would "
              "send there on every query. Leave verification on — install a "
              "private authority in this server's trust store if that is what "
              "it needs — or clear the credential. Nothing was saved.",
              "error")
        _audit("source save refused", subject=f"source:{source_id}"
               if source_id else None,
               state={"name": form.get("name"),
                      "url": _without_password(config.get("url")),
                      "reason": "a credential with certificate checks off"})
        return redirect(url_for("config.config_page"))

    # A rename must not quietly change what a role reaches. Role patterns
    # name sources — `primary:app-*`, `-primary:secret-*` — and the qualifier
    # is compared by exact name, so renaming `primary` made every such grant
    # stop granting and every such EXCLUSION stop excluding: a role of `*`
    # with `-primary:secret-*` could read `secret-*` the moment the page
    # saved, with no preview and nothing in the audit row but the new name.
    if source_id:
        new_name = (form.get("name") or "").strip()
        # Nothing to move when the credential is being removed. Without
        # this, the one save that CLEARS a password while turning
        # verification off was refused for sending a secret it was in the
        # act of deleting — the remedy refused by the rule it satisfies.
        moved = (_moves_secret(existing["config"], config, "url",
                               "verify_certs")
                 if existing and existing["has_secret"] and not password
                 and not forget
                 else [])
        if moved:
            flash(f"The stored password is only sent where it was saved for, "
                  f"and this change {' and '.join(moved)}. Type the password "
                  f"again to save it. Nothing was saved.", "error")
            _audit("source update refused", subject=f"source:{source_id}",
                   state={"name": existing["name"],
                          "url": _without_password(config.get("url")),
                          "reason": moved})
            return redirect(url_for("config.config_page"))
        if existing and new_name != existing["name"]:
            naming = _roles_naming_source(store, existing["name"], new_name,
                                          existing.get("kind"))
            if naming:
                flash(f"Renaming '{existing['name']}' to '{new_name}' would "
                      f"change what these roles reach: {', '.join(naming)}. "
                      f"Their patterns name one of the two — rules for the "
                      f"old name would stop applying, rules for the new one "
                      f"would start. Change those patterns first. "
                      f"Nothing was saved.", "error")
                _audit("source rename refused", subject=f"source:{source_id}",
                       state={"name": existing["name"], "to": new_name,
                              "roles": naming})
                return redirect(url_for("config.config_page"))

    try:
        if source_id:
            saved = store.sources.update(
                source_id, name=form.get("name"), config=config,
                signals=signals or None, clear_secret=forget,
                secret=password, enabled=form.get("enabled") == "on")
            if saved is None:
                flash("That source no longer exists.", "error")
                return redirect(url_for("config.config_page"))
            _audit("source updated", subject=f"source:{source_id}",
                   state=_source_state(saved, previous_name=existing["name"],
                                       secret_replaced=bool(password),
                                       secret_forgotten=forget))
        else:
            new_name = (form.get("name") or "").strip()
            naming = _roles_naming_source(store, new_name) if new_name else []
            if naming:
                # A colon qualifies a rule only when a source has that name,
                # so these rules are plain names today. A source called this
                # would make them rules for it: a grant of `staging:*` would
                # hand over everything in it.
                flash(f"These roles have rules starting '{new_name}:': "
                      f"{', '.join(naming)}. A source called '{new_name}' "
                      f"would turn them from names into rules for it. Change "
                      f"those patterns first. Nothing was saved.", "error")
                _audit("source creation refused", subject=f"source:{new_name}",
                       state={"name": new_name, "roles": naming})
                return redirect(url_for("config.config_page"))
            saved = store.sources.create(
                name=form.get("name"), signal=signals,
                kind=form.get("kind"), config=config, secret=password,
                enabled=form.get("enabled") == "on")
            _audit("source created", subject=f"source:{saved['id']}",
                   state=_source_state(saved))
        note, tone = _reloaded(saved)
        flash(f"Source '{saved['name']}' saved{note}", tone)
    except SecretsUnavailable as exc:
        flash(str(exc).split("\n")[0], "error")
    except SourceError as exc:
        flash(str(exc), "error")
        # The store's refusals leave a trail too. Every refusal written out
        # in this function already did; these were the ones raised a layer
        # down — a password in the address, a scheme that is not http, the
        # metadata address — and they were the refusals worth reading later.
        # Masked, because one of them is about a credential and the row must
        # not be the place it finally gets written down.
        _audit("source save refused",
               subject=f"source:{source_id}" if source_id else None,
               state={"name": form.get("name"),
                      "url": _without_password(config.get("url")
                                               or form.get("url")),
                      "reason": str(exc)})

    return redirect(url_for("config.config_page"))


def _unqualified(rules, names):
    """A warning for each rule whose colon names no source.

    Such a rule is a plain name — `unknown_service:java` — which is right
    when that is the service's name and a typo when a source was meant.
    Only the person writing it knows which, so it is said, not guessed.
    """
    from ..hub.patterns import parse
    said, out = set(), []
    for rule in rules:
        qualifier = parse(rule)[1]
        if qualifier is None or qualifier in names or qualifier in said:
            continue
        said.add(qualifier)
        out.append(f"'{rule}' is read as a name: no source is called "
                   f"'{qualifier}'. A colon holds a rule to one source only "
                   f"when a source has that name.")
    return out


#: Sources whose one trace store is the source itself, matched by its name.
NAMED_STORE_KINDS = frozenset({"tempo", "jaeger"})


def _roles_naming_source(store, name, new_name=None, kind=None):
    """Roles whose patterns would mean something else after a rename.

    Any pattern qualified by `name` — log store, trace store or service,
    granting or excluding — or by the NEW name: `staging:*`, left from a
    deleted source or written ahead of one, reaches nothing until a source
    is called `staging`, and renaming one to that handed the role all of it.
    And for Tempo or Jaeger, whose trace store is matched by the source's
    name, any trace-store pattern that answers differently for the new one:
    `-lab-tempo` beside `*` stops excluding once the source is called
    anything else.
    """
    from ..hub.patterns import matches_for_source, parse

    names = {name} | ({new_name} if new_name else set())
    naming = []
    for role in store.roles.all():
        stores = role.get("trace_containers") or []
        rules = ((role.get("containers") or []) + stores
                 + (role.get("services") or []))
        qualified = any(parse(pattern)[1] in names for pattern in rules)
        renamed_store = (
            kind in NAMED_STORE_KINDS and new_name is not None
            and matches_for_source(stores, name, name)
            != matches_for_source(stores, new_name, new_name))
        if qualified or renamed_store:
            naming.append(role["name"])
    return naming


@config_bp.route("/sources/<source_id>/delete", methods=["POST"])
@login_required
def delete_source(source_id):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    source = store.sources.get(source_id)
    if source and store.sources.delete(source_id):
        _audit("source deleted", subject=f"source:{source_id}",
               state=_source_state(source))
        flash(f"Source '{source['name']}' deleted{_reloaded()[0]}", "success")
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
        # Audited like every other refusal on this page. This one is the
        # SSRF guard — the link-local address SECURITY.md is about — and it
        # was the one refusal that left no row anywhere: `_audit` writes to
        # the logger AND the table, so skipping it wrote to neither.
        # Measured: six refusals through this route and the save beside it,
        # including `http://169.254.169.254/latest/meta-data/`, and zero new
        # audit rows.
        _audit("source test refused",
               subject=f"source:{payload['id']}" if payload.get("id") else None,
               state={"target": _where(payload.get("url")),
                      "reason": str(exc)})
        return jsonify({"ok": False, "error": str(exc)}), 200

    password = payload.get("password")
    stored = store.sources.get(payload["id"]) if payload.get("id") else None
    reused = False
    if not password and stored and stored["has_secret"]:
        # Testing a saved source without retyping its password — the
        # connection it was saved for, and no other. The form's values used
        # to be taken as they came: any URL, the stored password, and a
        # listener of an administrator's choosing received it, with nothing
        # written down.
        moved = _moves_secret(stored["config"], {**payload, "url": url},
                              "url", "verify_certs")
        if payload.get("kind") != stored["kind"]:
            moved.append("changes the type")
        if moved:
            _audit("source test refused", subject=f"source:{stored['id']}",
                   state={"target": _where(url), "reason": moved})
            return jsonify({
                "ok": False,
                "message": f"The stored password is only sent where it was "
                           f"saved for, and this test {' and '.join(moved)}. "
                           f"Type the password to test it."}), 200
        try:
            password = store.sources.credential(stored["id"])
            reused = password is not None
        except Exception as exc:
            # NOT a probe without the password. It used to be, and the far
            # end's answer was then reported as a success — so one render of
            # this page carried the red "not in use" badge and the sentence
            # about a secret that could not be decrypted for a source whose
            # Test connection answered ok, on the same row. Measured after a
            # key rotation: `hub.logs('lab-es')` raising KeyError for every
            # query while the button said the connection was fine.
            #
            # `reused` could not have said so either: it is False both for
            # "no password is stored" and for "the stored one could not be
            # read", which are the two facts this has to tell apart.
            logger.warning(f"source {stored['id']} could not be tested: {exc}")
            _audit("source test refused", subject=f"source:{stored['id']}",
                   state={"target": _where(url),
                          "reason": "the stored password could not be read"})
            return jsonify({
                "ok": False,
                "message": "The stored password could not be read, so this "
                           "connection cannot be tested as it is saved. "
                           "WDASH_ENCRYPTION_KEY has probably changed since "
                           "it was written; type the password to test and "
                           "save it again."}), 200

    from ..hub.probe import probe_source
    result = probe_source(kind=payload.get("kind"), url=url,
                          username=payload.get("username"),
                          password=password,
                          verify_certs=bool(payload.get("verify_certs")))
    # Every test, not only the ones that use a stored password: it is the
    # server making a request to a host an administrator named.
    _audit("source tested",
           subject=f"source:{stored['id']}" if stored else None,
           state={"kind": payload.get("kind"), "target": _where(url),
                  "username": payload.get("username") or "",
                  "stored_password": reused, "ok": bool(result.get("ok"))})
    return jsonify(result), 200


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def _back_to_auth(which=None):
    """Back to the card this save came from.

    Every one of these used to be a bare `/admin/config`, which opens on
    Sources: somebody who had just saved LDAP was returned to a different
    tab and had to find their way back to read the flash about what they
    had done. The Checks and Alerts tabs have sent people back to
    themselves since they were written; Authentication could not, because
    it was one pane holding three unrelated things and there was nowhere
    more precise to point at than the pane. There is now.
    """
    pane = {"oidc": "#tab-auth-oidc", "ldap": "#tab-auth-ldap",
            "local": "#tab-auth-local"}.get(which, "#tab-auth")
    return redirect(url_for("config.config_page") + pane)


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
            # Blank is "use the default", and saved as blank so a default
            # that changes reaches this installation too. The scopes as
            # well: blank asks for what auth.DEFAULT_SCOPES says.
            "scopes": (request.form.get("scopes") or "").strip(),
            "username_claim": (request.form.get("username_claim") or "").strip(),
            "email_claim": (request.form.get("email_claim") or "").strip(),
            "groups_claim": (request.form.get("groups_claim") or "").strip(),
            "trust_unverified_email":
                request.form.get("trust_unverified_email") == "on",
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
            "verify_certs": request.form.get("verify_certs") == "on",
            "ca_certs": (request.form.get("ca_certs") or "").strip(),
            "enabled": request.form.get("enabled") == "on",
        }
        secret = request.form.get("bind_password") or None
        key, label = LDAP, "LDAP"
        unusable = (_unusable_ca_file(value["ca_certs"])
                    if value["ca_certs"] and value["verify_certs"] else None)
        if unusable:
            flash(f"The CA file {value['ca_certs']} cannot be used: {unusable}. "
                  f"Every ldaps:// sign-in would fail on it. Nothing was "
                  f"saved.", "error")
            return _back_to_auth(which)
    else:
        flash("Unknown provider.", "error")
        return _back_to_auth(which)

    # Read here rather than further down: what is already stored decides
    # whether the blank secret field means "there is none" or "keep the one
    # you have", and the checks after the directory rules turn on that.
    held = store.settings.all(prefix=key).get(key) or {}
    has_secret = bool(secret) or bool(held.get("has_secret"))

    # Which directory this installation signs people in through, before and
    # after. Both refusals below and the sentence at the end are computed from
    # the SAME resolution, so "which is in force" and "which counts as the
    # other one" can never be decided on different footings.
    before = directory(current_app)
    refusal = refuses_second_directory(current_app, which, value["enabled"])
    if refusal is None and not value["enabled"] and before["in_force"] == which:
        # Who the resolution hands the installation to on this very save. On
        # an installation with both stored and enabled, that handover is the
        # switch, and it is the ONLY in-page direction there is: enabling the
        # other one is refused by the rule above. Read from the same
        # resolution, so the refusal cannot claim a lockout the resolution
        # does not say.
        takes_over = ({"name": before["shadowed"],
                       "unusable": why_unusable(current_app,
                                                before["shadowed"])}
                      if before["shadowed"] else None)
        refusal = refuses_directory_off(which, _actor(), store.roles.all(),
                                        store.users.all(), takes_over)
    if refusal:
        flash(refusal, "error")
        _audit(f"{label} settings refused", subject=f"auth:{which}",
               state={**value, "reason": refusal})
        return _back_to_auth(which)

    # Now the card itself. AFTER the two rules above, on the same
    # principle the role editor states: "this installation may have one
    # directory" is a property of the system and "this card is not filled
    # in" is a property of the form, and the message a person reads should
    # be the larger of the two things that are wrong.
    #
    # A card with nothing in it and no secret behind it. Saved, it wrote a
    # row of empty strings that counted as a configured directory — enough
    # to be in force, to refuse the other one as a second directory, and to
    # be reported as "saved and in force now" while no sign-in was ever
    # offered through it.
    #
    # Only where nothing is stored either. Blanking a card that exists is how
    # a provider is removed — there is no delete button — and an empty card
    # somebody then switches ON is refused by the completeness rule below,
    # which names the fields instead of saying "empty".
    filled = [field for field in PROVIDER_FIELDS[which]
              if (value.get(field) or "").strip()]
    if not filled and not has_secret and not held:
        flash(f"There is nothing to save: every {label} field is empty. "
              f"Fill the card in, or leave it alone.", "error")
        return _back_to_auth(which)

    # Shape first, and whether or not the card is being switched on: an
    # address with no protocol is wrong in a draft too, and the alternative
    # is finding out at somebody's next sign-in.
    wrong = malformed(which, value)
    if wrong:
        flash(f"{label} was not saved: {wrong}.", "error")
        _audit(f"{label} settings refused", subject=f"auth:{which}",
               state={**value, "reason": wrong})
        return _back_to_auth(which)

    # Completeness, only where it decides anything. A half-filled card that
    # is switched off is a draft somebody is coming back to; switched on it
    # is a directory that cannot sign anybody in, and the page said it was
    # in force.
    absent = missing(which, value, has_secret) if value["enabled"] else []
    if absent:
        said = (f"{label} cannot be switched on without "
                f"{listed(absent)}. Nothing was saved.")
        flash(said, "error")
        _audit(f"{label} settings refused", subject=f"auth:{which}",
               state={**value, "reason": said})
        return _back_to_auth(which)

    url_key, verify_key, what = (
        ("discovery_url", None, "client secret") if key == OIDC
        else ("server", "verify_certs", "bind password"))
    moved = (_moves_secret(held.get("value") or {}, value, url_key, verify_key)
             if held.get("has_secret") and secret is None else [])
    if moved:
        flash(f"The stored {what} is only sent where it was saved for, and "
              f"this change {' and '.join(moved)}. Type the {what} again to "
              f"save it. Nothing was saved.", "error")
        _audit(f"{label} settings refused", subject=f"auth:{which}",
               state={**value, "reason": moved})
        return _back_to_auth(which)

    try:
        store.settings.set(key, value, secret=secret,
                           updated_by=current_user.username)
    except SecretsUnavailable as exc:
        flash(str(exc).split("\n")[0], "error")
        return _back_to_auth(which)

    after = directory(current_app)
    # A switch is the save where the RESOLUTION changes, not the save where a
    # checkbox does. With both directories stored and enabled the handover
    # happens on the save that turns the one in force OFF — the other takes
    # over on that very save, and no second save follows; keyed to the
    # checkbox, the sentence would never appear.
    switched = (after["in_force"] is not None
                and after["in_force"] != before["in_force"])
    inherited = _inherited(store) if switched else None

    # The resulting state, as for roles and mappings: which provider this
    # installation trusted, and from when, is what an investigation asks.
    recorded = _recorded(inherited)
    _audit(f"{label} settings updated", subject=f"auth:{which}",
           state={**value, "secret_replaced": secret is not None,
                  "directory_in_force": after["in_force"],
                  "directory_was": before["in_force"],
                  **({"inherited": recorded} if switched else {})})
    if (before["in_force"], before["shadowed"]) != (after["in_force"],
                                                    after["shadowed"]):
        # Audited where it CHANGES, not only where the process starts:
        # otherwise a conflict created while WDash is running never reaches
        # the trail, and the banner says one thing while the trail says
        # another.
        _audit("directory in force changed", subject="auth",
               state={"was": before["in_force"], "now": after["in_force"],
                      "shadowed": after["shadowed"], "reason": after["reason"],
                      **({"inherited": recorded} if switched else {})})

    flash(f"{label} settings saved and in force now — no restart needed."
          + (" " + _switch_sentence(before["in_force"], after["in_force"],
                                    inherited) if switched else ""),
          "warning" if switched else "success")
    return _back_to_auth(which)


def _plural(count, noun):
    """`1 dashboard`, `3 dashboards` — or a count that is not a count.

    A read that failed must not arrive as a zero. "0 dashboards belong to
    names that are not local accounts" is a sentence somebody acts on, and it
    would be the one thing the page could not know.
    """
    if count is None:
        return f"an unknown number of {noun}s (the log says why)"
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _inherited(store):
    """What names that are not local accounts already own here.

    Read at the moment the directory changes, because that is the moment the
    site can still act on it: ownership is the username, with no provider
    attached to it, so whoever signs in as one of these names at the new
    directory gets what the name holds. Nothing is migrated and nothing is
    scoped — a name keeping its dashboards is what makes a deliberate switch
    work at all.
    """
    local = {account["username"] for account in store.users.all()}
    try:
        owners = [dashboard.created_by for dashboard
                  in current_app.dashboard_manager.get_all_dashboards()
                  if dashboard.created_by and dashboard.created_by not in local]
    except Exception:
        current_app.logger.exception("Could not read the dashboard owners")
        owners = None
    mapped = [name for name in (store.settings.get("rbac.user_roles") or {})
              if name not in local]
    return {"dashboards": None if owners is None else len(owners),
            "mappings": len(mapped),
            "names": sorted(set(owners or ()) | set(mapped))}


def _recorded(inherited):
    """What the audit row keeps of a switch: the counts, and the same few
    names the sentence showed.

    The full list is a copy of somebody's directory. An installation with
    thousands of directory-owned dashboards wrote all of them into one row on
    one save, while the sentence beside it was showing five — the trail should
    record what happened, not the directory it happened to.
    """
    if inherited is None:
        return None
    return {**inherited, "names": inherited["names"][:FEW],
            "name_count": len(inherited["names"])}


def _switch_sentence(was, now, inherited):
    """What this installation just handed to the other directory."""
    said = (f"{LABELS[now]} is now the directory this installation signs "
            f"people in through"
            + (f" (it was {LABELS[was]})." if was else "."))
    if inherited and (inherited["names"] or inherited["dashboards"] is None):
        said += (f" Ownership here is the name: "
                 f"{_plural(inherited['dashboards'], 'dashboard')} and "
                 f"{_plural(inherited['mappings'], 'role mapping')} belong to "
                 f"names that are not local accounts "
                 f"({few(inherited['names'])}), along with any saved searches "
                 f"those names own — counted by nobody, because the database "
                 f"repository has no read-them-all method on purpose. Whoever "
                 f"signs in as one of those names through {LABELS[now]} gets "
                 f"them.")
    return said


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
                            "error": _why(exc)})
        return out

    # A store that could not be asked is NAMED, not skipped. Tempo and Jaeger
    # raise now instead of answering an empty list, and `except Exception:
    # continue` turned that into a shorter list of services — which reads as
    # a quiet week, and the role written against it silently names fewer
    # services than exist.
    services, service_errors = [], []
    for source in (hub.trace_sources if hub else []):
        try:
            services.extend(
                service.name for service
                in source.services(TimeWindow.of("24h"), unrestricted))
        except Exception as exc:
            logger.warning(
                "Trace source '%s' could not list its services: %s",
                source.name, exc)
            service_errors.append({"source": source.name,
                                   "error": _why(exc)})

    return jsonify({
        "logs": listing(hub.log_sources if hub else []),
        "traces": listing(hub.trace_sources if hub else []),
        "services": sorted(set(services)),
        "service_errors": service_errors,
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


#: How the change block names the unrestricted side of a services boundary.
EVERY_SERVICE = "every service"


def _service_change(before, after):
    """(grants added, grants removed, exclusions added, exclusions removed),
    where None on either side is EVERY service.

    Blank is the widest thing the services box can hold, so clearing it is
    the widest edit a role can take — and the diff used to leave services out
    entirely, so that edit produced no change block and `widens: false`.

    Exclusions are told apart from grants because they point the other way:
    as plain strings, taking `-payments` off a role of `*` was "removes
    services: -payments" and "narrows access", on the edit that made
    payments visible; putting it on was "grants services" and "widens".
    """
    if before is None and after is None:
        return [], [], [], []
    if after is None:
        return [EVERY_SERVICE], [], [], []
    if before is None:
        return [], [EVERY_SERVICE], [], []

    from ..hub.patterns import parse
    names = source_names()

    def split(rules):
        grants, exclusions = set(), set()
        for rule in rules:
            (exclusions if parse(rule, names)[0] else grants).add(rule)
        return grants, exclusions

    grants_before, exclusions_before = split(before)
    grants_after, exclusions_after = split(after)
    return (sorted(grants_after - grants_before),
            sorted(grants_before - grants_after),
            sorted(exclusions_after - exclusions_before),
            sorted(exclusions_before - exclusions_after))


def _describe_change(previous, scope, logs, traces, groups=None):
    """What this edit adds and removes: containers, services, permissions,
    and the groups that hand the role out.

    `groups` is the role's group list after the edit; None leaves groups out
    of the comparison, for a caller that does not send them.
    """
    hub = getattr(current_app, "hub", None)

    before_scope = Scope(
        principal="before",
        containers=tuple(previous.get("containers") or ()),
        trace_containers=tuple(previous.get("trace_containers") or ()),
        services=(tuple(previous["services"])
                  if previous.get("services") is not None else None),
        permissions=frozenset(previous.get("permissions") or ()),
        sources=source_names())

    before_logs = _reachable(before_scope, hub.log_sources if hub else [])
    before_traces = _reachable(before_scope, hub.trace_sources if hub else [],
                               trace_side=True)
    after_logs = {name for entry in logs for name in entry["containers"]}
    after_traces = {name for entry in traces for name in entry["containers"]}

    before_permissions = set(previous.get("permissions") or ())

    (services_added, services_removed,
     exclusions_added, exclusions_removed) = _service_change(
        previous.get("services"),
        list(scope.services) if scope.services is not None else None)

    # A group is who gets the role, not what the role reaches — but adding
    # one hands everything the role reaches to a whole directory group, which
    # is a widening in every sense an access review cares about.
    before_groups = set(previous.get("groups") or ())
    after_groups = before_groups if groups is None else set(groups)

    return {
        "logs_added": sorted(after_logs - before_logs),
        "logs_removed": sorted(before_logs - after_logs),
        "traces_added": sorted(after_traces - before_traces),
        "traces_removed": sorted(before_traces - after_traces),
        "services_added": services_added,
        "services_removed": services_removed,
        "exclusions_added": exclusions_added,
        "exclusions_removed": exclusions_removed,
        "permissions_added": sorted(scope.permissions - before_permissions),
        "permissions_removed": sorted(before_permissions - scope.permissions),
        "groups_added": sorted(after_groups - before_groups),
        "groups_removed": sorted(before_groups - after_groups),
        # Widening is the direction worth pointing at. Narrowing is usually
        # deliberate; widening is usually a pattern that did not do what the
        # person meant.
        "widens": bool((after_logs - before_logs)
                       or (after_traces - before_traces)
                       or services_added or exclusions_removed
                       or (scope.permissions - before_permissions)
                       or (after_groups - before_groups)),
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
        permissions=frozenset(payload.get("permissions") or ()),
        sources=source_names())

    hub = getattr(current_app, "hub", None)
    logs, traces, warnings = [], [], []
    warnings.extend(_unqualified(
        list(scope.containers) + list(scope.trace_containers)
        + list(scope.services or ()), scope.sources))

    def unlisted(source, exc):
        # Kept, and marked. Left out, a source nobody could list read the
        # same as one whose containers the pattern matched none of — "matches
        # nothing on this installation" under a correct pattern, whose
        # obvious fix is a wider one.
        warnings.append(f"{source.name} could not be listed: {exc}")
        return {"source": source.name, "containers": [], "count": 0,
                "total": 0, "error": str(exc)[:200]}

    for source in (hub.log_sources if hub else []):
        try:
            reachable = source.containers(scope)
        except Exception as exc:
            logs.append(unlisted(source, exc))
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
            traces.append(unlisted(source, exc))
            continue
        traces.append({"source": source.name, "containers": reachable,
                       "count": len(reachable), "total": len(everything)})

    # Two outcomes are worth calling out, and only one of them was.
    #
    # Reaching nothing is usually a typo. Reaching EVERYTHING is the dangerous
    # direction: `*` typed where `app-*` was meant looks like a working
    # pattern, saves cleanly, and grants the whole cluster. Nothing said so.
    def covers_all(entries, patterns):
        # Judged on the sources that answered: one that could not be listed
        # must not hide `*` granting everything on the rest.
        answered = [entry for entry in entries if "error" not in entry]
        if not patterns or not answered:
            return False
        return all(entry["count"] == entry["total"] and entry["total"]
                   for entry in answered)

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
            groups = payload.get("groups")
            change = _describe_change(
                previous, scope, logs, traces,
                groups=None if groups is None else list(groups))

    return jsonify({
        "change": change,
        "logs": logs,
        "traces": traces,
        "services": ("every service" if scope.services is None
                     else list(scope.services)),
        "permissions": sorted(scope.permissions),
        "warnings": warnings,
        # Not knowable while a source could not be listed; its warning says
        # so instead.
        "reaches_nothing": not any(entry["count"] for entry in logs + traces)
                           and not any("error" in entry for entry in logs + traces),
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
    refusal = refuses_role_save(
        store.roles.all(), name, permissions, _actor(),
        groups=_lines(request.form.get("groups")),
        user_roles=store.settings.get("rbac.user_roles", {}) or {},
        default_role=store.settings.get("rbac.default_role", "viewer"))
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

    refusal = refuses_role_delete(
        store.roles.all(), name, _actor(),
        default_role=store.settings.get("rbac.default_role", "viewer"),
        user_roles=store.settings.get("rbac.user_roles", {}) or {},
        local_accounts=store.users.all())
    if refusal:
        # Recorded like a refused save: README and SECURITY both say refused
        # attempts sit beside the successful ones, and this one did not.
        _audit("role delete refused", subject=f"role:{name}",
               state={"reason": refusal})
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

    # Never substituted. A blank default used to be saved as "viewer" —
    # whether or not a role of that name existed — and an unknown one is what
    # the form sends when the role it pointed at has gone. Both are refused,
    # so the default only ever changes to something somebody chose.
    default_role = (request.form.get("default_role") or "").strip()
    if not default_role:
        flash("Choose a default role: it is what everybody no mapping names "
              "gets. Nothing was saved.", "error")
        return redirect(url_for("config.config_page"))
    if default_role not in known:
        flash(f"The default role '{default_role}' no longer exists. Choose one "
              f"of the roles that do. Nothing was saved.", "error")
        return redirect(url_for("config.config_page"))

    # Absent is not empty. The page's default-role form does not carry the
    # mappings at all any more — each one is its own record, saved through
    # `save_mapping` below — and a handler that read a missing field as "no
    # mappings" would empty the table every time somebody changed the
    # default. An EMPTY field still means none: that is a submission saying
    # so, and the bulk form is still how a whole set is replaced at once.
    if "user_roles" not in request.form:
        return _save_default_role(store, default_role)

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

    refusal = refuses_mapping_save(store.roles.all(), default_role, mappings,
                                   _actor())
    if refusal:
        _audit("mappings save refused", subject="rbac:mappings",
               state={"reason": refusal, "default_role": default_role,
                      "user_roles": mappings})
        flash(refusal, "error")
        return redirect(url_for("config.config_page"))

    store.settings.set("rbac.default_role", default_role,
                       updated_by=current_user.username)
    store.settings.set("rbac.user_roles", mappings,
                       updated_by=current_user.username)
    store.rbac.invalidate()
    _audit("mappings updated", subject="rbac:mappings",
           state={"default_role": default_role, "user_roles": mappings})
    flash("Role mappings saved.", "success")
    return redirect(url_for("config.config_page"))


def _stored_mappings(store):
    """The mappings as they stand, for a change that touches one of them."""
    return dict(store.settings.get("rbac.user_roles") or {})


def _save_mappings(store, mappings, action, subject, state, message):
    """Write a changed mapping set, or refuse it as one.

    Every path in and out of the table goes through here, so the lockout
    check, the cache invalidation and the audit row cannot be remembered on
    one route and forgotten on the next. The default role is read rather than
    submitted: it is not on the form that changed a mapping, and taking it
    from anywhere else would let one form quietly rewrite the other's field.
    """
    default_role = store.settings.get("rbac.default_role") or ""
    refusal = refuses_mapping_save(store.roles.all(), default_role, mappings,
                                   _actor())
    if refusal:
        _audit(f"{action} refused", subject=subject,
               state=dict(state, reason=refusal))
        flash(refusal, "error")
        return redirect(url_for("config.config_page", _anchor="tab-roles"))

    store.settings.set("rbac.user_roles", mappings,
                       updated_by=current_user.username)
    store.rbac.invalidate()
    _audit(action, subject=subject, state=dict(state, user_roles=mappings))
    flash(message, "success")
    return redirect(url_for("config.config_page", _anchor="tab-roles"))


def _save_default_role(store, default_role):
    """The default role on its own, from the form that now carries only it.

    The stored mappings are read and passed through the invariant unchanged:
    the default is what somebody lands on when no mapping names them, so
    whether this change locks the administrator out is a question about both.
    """
    mappings = _stored_mappings(store)
    refusal = refuses_mapping_save(store.roles.all(), default_role, mappings,
                                   _actor())
    if refusal:
        _audit("default role save refused", subject="rbac:mappings",
               state={"reason": refusal, "default_role": default_role})
        flash(refusal, "error")
        return redirect(url_for("config.config_page", _anchor="tab-roles"))

    store.settings.set("rbac.default_role", default_role,
                       updated_by=current_user.username)
    store.rbac.invalidate()
    _audit("default role updated", subject="rbac:mappings",
           state={"default_role": default_role})
    flash(f"Everybody no mapping names now gets '{default_role}'.", "success")
    return redirect(url_for("config.config_page", _anchor="tab-roles"))


@config_bp.route("/mappings/entry", methods=["POST"])
@login_required
def save_mapping():
    """One mapping, added or edited.

    A row on the table is a record. It used to be one line of a textarea's
    worth of rows that a single save carried in full, so adding one person
    re-submitted everybody — and a row somebody had half-filled went with
    them.

    `original` is which mapping this was, so that changing the identifier
    MOVES it. Without that, editing `alice@example.com` into `alice` leaves
    the old row in place beside the new one, still granting.
    """
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    known = {role["name"] for role in store.roles.all()}

    identifier = (request.form.get("identifier") or "").strip()
    role = (request.form.get("role") or "").strip()
    original = (request.form.get("original") or "").strip()

    def refuse(message):
        flash(f"{message} Nothing was saved.", "error")
        return redirect(url_for("config.config_page", _anchor="tab-roles"))

    if not identifier:
        return refuse("Type the email address or username this role is for.")
    # Both are refused rather than defaulted, for the reason the empty option
    # exists on the form: a select with nothing chosen submits its FIRST
    # option, and the first role is `admin`.
    if not role:
        return refuse(f"Choose a role for '{identifier}'.")
    if role not in known:
        return refuse(f"There is no role called '{role}'. A mapping to a role "
                      f"that does not exist grants nothing, silently.")

    mappings = _stored_mappings(store)
    replaced = mappings.get(identifier)
    if original and original != identifier:
        mappings.pop(original, None)
    mappings[identifier] = role

    if original and original != identifier:
        message = f"'{original}' is now '{identifier}', mapped to {role}."
    elif replaced is not None:
        message = f"'{identifier}' is now mapped to {role}."
    else:
        message = f"'{identifier}' is mapped to {role}."

    return _save_mappings(
        store, mappings, "mapping updated" if original else "mapping added",
        f"rbac:mapping:{identifier}",
        {"identifier": identifier, "role": role,
         "was": {"identifier": original or identifier, "role": replaced}},
        message)


@config_bp.route("/mappings/delete", methods=["POST"])
@login_required
def delete_mapping():
    """One mapping, removed.

    Through the same invariant as a save: removing the mapping that is what
    makes you an administrator drops you to the default role, which empties
    the page you would need to put it back.
    """
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    identifier = (request.form.get("identifier") or "").strip()
    mappings = _stored_mappings(store)
    if identifier not in mappings:
        flash("That mapping is no longer there.", "warning")
        return redirect(url_for("config.config_page", _anchor="tab-roles"))

    removed = mappings.pop(identifier)
    return _save_mappings(
        store, mappings, "mapping removed", f"rbac:mapping:{identifier}",
        {"identifier": identifier, "was": removed},
        f"The mapping for '{identifier}' is gone.")


# ---------------------------------------------------------------------------
# Local accounts
#
# On the Authentication tab rather than beside Roles, because that tab is the
# page's one answer to "how do people get in" — OIDC, LDAP, and the sentence
# at the bottom saying local accounts are not a directory. Until now that
# sentence pointed at something no screen in the product could show: an
# account could only be made by first-run setup or by `python -m
# wdash.store.recover`, so the break-glass path was the one path with no way
# to see who held it. Roles & access answers a different question — what a
# role may reach — and a role is not a person.
#
# The same three rules as every other handler here: `system:admin` per
# request, a password written and never rendered back, and an audit row for
# every change including the refused ones.
# ---------------------------------------------------------------------------

def _account_state(account, was=None, **extra):
    """One account as an audit row records it.

    The hash is dropped as deliberately as the password is: an audit trail
    that carries password hashes is a cracking target with a retention policy,
    and the trail is exported from this same screen.

    `was` is the value the change moved away from. The trail stores the
    resulting state rather than a diff, which answers "what was it then"
    without replaying history — and leaves "what did this row CHANGE"
    needing the row before it. For a role that is one field, and one field is
    worth carrying so that the answer is in the row somebody is reading.
    """
    state = {key: value for key, value in (account or {}).items()
             if key not in ("password_hash", "totp_secret")}
    if was is not None:
        state["previous_role"] = was
    state.update(extra)
    return state


def _back():
    """Back to Local accounts, which is where every one of these was done.

    It was `/admin/config` with no fragment, so a person who had just
    deleted an account, reset a password or been REFUSED one of those
    landed on Sources — with the sentence explaining the refusal at the top
    of a tab that has nothing to do with accounts.
    """
    return _back_to_auth("local")


def _refused(action, username, refusal):
    """Say no in the project's idiom: the reason, an audit row, no write."""
    _audit(f"{action} refused", subject=f"user:{username}",
           state={"reason": refusal})
    flash(refusal, "error")
    return _back()


@config_bp.route("/accounts", methods=["POST"])
@login_required
def create_account():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    role = (request.form.get("role") or "").strip()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""

    if not username:
        flash("A username is required. Nothing was saved.", "error")
        return _back()
    # Chosen rather than typed, and checked anyway: a role that does not exist
    # grants nothing, silently, and the account would land on the default role
    # with nothing on any page to say why.
    if role not in {definition["name"] for definition in store.roles.all()}:
        flash(f"There is no role called '{role}'. Nothing was saved.", "error")
        return _back()
    if password != confirm:
        flash("The two passwords do not match. Nothing was saved.", "error")
        return _back()

    try:
        account = store.users.create(username, password, role, email=email)
    except WeakPassword as exc:
        flash(str(exc), "error")
        return _back()
    except ValueError as exc:
        flash(str(exc), "error")
        return _back()

    _audit("account created", subject=f"user:{account['username']}",
           state=_account_state(account))
    flash(f"Local account '{account['username']}' created.", "success")
    return _back()


@config_bp.route("/accounts/<username>", methods=["POST"])
@login_required
def save_account(username):
    """The account's role, and nothing else.

    It used to carry the enabled switch too, read as
    `not request.form.get("enabled")` — so a submission that did not MENTION
    the switch disabled the account. Measured: a POST of `role=admin` alone
    left the account disabled, flashed "Account 'reader' saved." and signed
    that person out on their very next request, because a disabled account's
    open session now ends at once.

    An unticked checkbox and an absent one are the same thing on the wire, so
    there is no reading of this form that can tell them apart. The switch
    therefore moved OUT of it, to `enable_account` and `disable_account`
    below, rather than being propped up with a hidden marker beside the box:
    a marker fixes this form and leaves the trap one level down for the next
    one to fall into, while a route that cannot change the enabled state
    cannot be made to by any request at all. It is also the shape this page
    already uses for the acts whose consequences differ from an edit — the
    password and the delete each have their own route — and switching an
    account off is now one of those: it ends a session somebody is using.
    """
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    account = store.users.by_username(username)
    if account is None:
        flash(f"There is no local account called '{username}'.", "warning")
        return _back()

    role = (request.form.get("role") or "").strip()
    if role not in {definition["name"] for definition in store.roles.all()}:
        flash(f"There is no role called '{role}'. Nothing was saved.", "error")
        return _back()

    # `disabled` is not passed, which is the invariant's own word for "leave
    # it alone" — the same question a password reset asks.
    refusal = refuses_account_change(
        store.users.all(), store.roles.all(), account["username"], _actor(),
        role=role,
        user_roles=store.settings.get("rbac.user_roles", {}) or {},
        default_role=store.settings.get("rbac.default_role", "viewer"))
    if refusal:
        return _refused("account save", account["username"], refusal)

    store.users.set_role(account["username"], role)
    # The role a local account holds is what the resolver reads first, so a
    # change here has to reach the resolver the way a role edit does.
    store.rbac.invalidate()
    saved = store.users.by_username(account["username"])
    _audit("account role changed", subject=f"user:{account['username']}",
           state=_account_state(saved, was=account["role"]))
    # Named, not "saved": what a save did is the thing somebody reading the
    # flash is checking, and this page now has three ways to change an
    # account that all used to end in the same word.
    flash(f"Account '{account['username']}' now holds '{role}'.", "success")
    return _back()


def _switch(username, disabled):
    """Enable or disable one account. The two routes below differ by a flag.

    Its own act, not a field on the save above. Disabling ends that person's
    open session on their next request, which is a different kind of thing
    from moving them to another role, and the flash and the audit action say
    which of the two happened rather than both reading "saved".
    """
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    account = store.users.by_username(username)
    if account is None:
        flash(f"There is no local account called '{username}'.", "warning")
        return _back()

    word = "disable" if disabled else "enable"
    if bool(account["disabled"]) == disabled:
        flash(f"Account '{account['username']}' is already "
              f"{'disabled' if disabled else 'enabled'}.", "info")
        return _back()

    refusal = refuses_account_change(
        store.users.all(), store.roles.all(), account["username"], _actor(),
        disabled=disabled,
        user_roles=store.settings.get("rbac.user_roles", {}) or {},
        default_role=store.settings.get("rbac.default_role", "viewer"))
    if refusal:
        return _refused(f"account {word}", account["username"], refusal)

    store.users.set_disabled(account["username"], disabled)
    store.rbac.invalidate()
    _audit(f"account {word}d", subject=f"user:{account['username']}",
           state=_account_state(store.users.by_username(account["username"])))
    if disabled:
        flash(f"Account '{account['username']}' is disabled. It cannot sign "
              f"in, and a session it already had open ends on its next "
              f"request.", "warning")
    else:
        flash(f"Account '{account['username']}' is enabled. It can sign in "
              f"again, with its password and its authenticator.", "success")
    return _back()


@config_bp.route("/accounts/<username>/disable", methods=["POST"])
@login_required
def disable_account(username):
    return _switch(username, disabled=True)


@config_bp.route("/accounts/<username>/enable", methods=["POST"])
@login_required
def enable_account(username):
    return _switch(username, disabled=False)


@config_bp.route("/accounts/<username>/password", methods=["POST"])
@login_required
def reset_account_password(username):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    account = store.users.by_username(username)
    if account is None:
        flash(f"There is no local account called '{username}'.", "warning")
        return _back()

    password = request.form.get("password") or ""
    if password != (request.form.get("confirm") or ""):
        flash("The two passwords do not match. Nothing was saved.", "error")
        return _back()
    try:
        store.users.set_password(account["username"], password)
    except WeakPassword as exc:
        flash(str(exc), "error")
        return _back()

    # What was set is not recorded, anywhere. The row says that a reset
    # happened and who did it, which is the auditable fact; the value is not
    # one, and an audit trail this page can export is the last place for it.
    _audit("account password reset", subject=f"user:{account['username']}",
           state={"username": account["username"]})
    flash(f"The password for '{account['username']}' was reset.", "success")
    return _back()


@config_bp.route("/accounts/<username>/totp/reset", methods=["POST"])
@login_required
def reset_account_totp(username):
    """Forget an account's authenticator, so it enrols again.

    The recovery path a mandatory second factor needs: a lost or wiped phone
    otherwise locks somebody out of an account whose password they still know,
    and the only way back would be the database.

    What it costs is worth saying: until that person enrols again, their
    password alone gets in. That is why it is audited, and why the button asks
    first.
    """
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    account = store.users.by_username(username)
    if account is None:
        flash(f"There is no local account called '{username}'.", "warning")
        return _back()
    if not account["totp_enrolled"]:
        flash(f"'{account['username']}' has no authenticator set up; it will "
              f"set one up at its next sign-in.", "info")
        return _back()

    store.users.clear_totp(account["username"])
    _audit("account totp reset", subject=f"user:{account['username']}",
           state={"username": account["username"],
                  "consequence": "until this account enrols again, its "
                                 "password alone signs it in"})
    flash(f"The authenticator for '{account['username']}' was reset. They set "
          f"up a new one at their next sign-in; until then their password "
          f"alone signs them in.", "warning")
    return _back()


@config_bp.route("/accounts/<username>/delete", methods=["POST"])
@login_required
def delete_account(username):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    account = store.users.by_username(username)
    if account is None:
        flash(f"There is no local account called '{username}'.", "warning")
        return _back()

    refusal = refuses_account_change(
        store.users.all(), store.roles.all(), account["username"], _actor(),
        deleting=True,
        user_roles=store.settings.get("rbac.user_roles", {}) or {},
        default_role=store.settings.get("rbac.default_role", "viewer"))
    if refusal:
        return _refused("account delete", account["username"], refusal)

    try:
        store.users.delete(account["username"])
    except ValueError as exc:
        # The repository's own last-account rule. Reachable when the last
        # account is not an administrator, which the invariant above says
        # nothing about.
        return _refused("account delete", account["username"], str(exc))

    store.rbac.invalidate()
    _audit("account deleted", subject=f"user:{account['username']}",
           state=_account_state(account))
    flash(f"Local account '{account['username']}' deleted.", "success")
    return _back()


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


def _driver_message(exc):
    """The first line of a driver's message, for a person to read.

    SQLAlchemy's `str(exc)` carries the whole statement and its bind
    parameters — the actor, action and subject somebody filtered by among
    them — after the first line. Rendered into an alert on the page it is a
    multi-line SQL dump where one sentence was wanted, and repeated in the
    export's JSON `detail`. The full text is already in the log, which is
    where it belongs and where somebody debugging this will look.
    """
    lines = str(exc).strip().splitlines()
    return lines[0] if lines else exc.__class__.__name__


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

    # The reads raise now, and the page is the place that decides what a
    # failure looks like. It is NOT an empty trail: the two halves are caught
    # apart from each other so a screen that can still show one of them does,
    # and each one that cannot says so where its rows would have been.
    entries, total, actions, trail_error = [], 0, [], None
    try:
        entries = store.audit.recent(limit=AUDIT_PAGE_SIZE,
                                     offset=page * AUDIT_PAGE_SIZE, **filters)
        total = store.audit.count(**filters)
        actions = store.audit.actions()
    except Exception as exc:
        logger.error(f"Could not read the audit trail: {exc}")
        trail_error = _driver_message(exc)

    # Sign-in attempts are not filtered by the same fields — they have no
    # action or subject — so they are shown as their own list rather than
    # pretending the filters apply to them.
    attempts, attempts_error = [], None
    try:
        attempts = store.signin.recent(limit=50)
    except Exception as exc:
        logger.error(f"Could not read sign-in attempts: {exc}")
        attempts_error = _driver_message(exc)

    # The third panel, and it answered the same broken table with the same
    # emptiness: `pending` swallowed every error into 0 and the card read
    # "0 entries waiting to be sent". A queue nobody could count is not a
    # queue that is drained.
    forwarding = store.settings.get(AUDIT_FORWARDING) or {}
    pending, forwarding_error = 0, None
    if forwarding.get("enabled"):
        try:
            forwarder = _forwarder(forwarding)
            pending = forwarder.pending() if forwarder else 0
        except Exception as exc:
            logger.error(f"Could not inspect the forwarding queue: {exc}")
            forwarding_error = _driver_message(exc)

    return render_template(
        "audit.html",
        forwarding=forwarding,
        forwarding_kinds=AUDIT_DESTINATIONS,
        forwarding_pending=pending,
        forwarding_error=forwarding_error,
        forwarding_secret_set=bool(_secret_present(store, AUDIT_FORWARDING)),
        entries=entries,
        total=total,
        page=page,
        page_size=AUDIT_PAGE_SIZE,
        pages=max(1, (total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE),
        filters={key: request.args.get(key, "") for key in
                 ("actor", "action", "subject", "since", "until")},
        actions=actions,
        attempts=attempts,
        trail_error=trail_error,
        attempts_error=attempts_error,
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
    try:
        entries = store.audit.recent(limit=limit, **_audit_filters())
    except Exception as exc:
        # 503 and not an empty file. Somebody downloading this is collecting
        # evidence, and a zero-length wdash-audit.jsonl with a 200 on it is
        # evidence of the wrong thing.
        logger.error(f"Could not export the audit trail: {exc}")
        return jsonify({"error": "The audit trail could not be read, so "
                                 "this export would understate it.",
                        "detail": _driver_message(exc)}), 503

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
        # Not audited as a configuration change, because the configuration
        # did not change. The QUEUE may well have: a destination that refuses
        # one document out of a batch has the rest, and those rows are marked
        # before the error is re-raised. Saying "nothing was marked as sent"
        # over the top of that sends an administrator to look for entries
        # that have already gone.
        logger.error(f"Audit forwarding failed: {exc}")
        marked = getattr(exc, "marked", 0)
        if marked:
            flash(f"Forwarding stopped: {exc}. "
                  f"{marked:,} entr{'y' if marked == 1 else 'ies'} the "
                  f"destination did accept {'was' if marked == 1 else 'were'} "
                  f"marked as sent.", "error")
        else:
            flash(f"Forwarding failed, and nothing was marked as sent: {exc}",
                  "error")
        return redirect(url_for("config.audit_page"))
    except Exception as exc:
        # The queue itself could not be read. This used to be a 0 out of
        # `sweep`, which arrived here as "Nothing was waiting." on a green
        # flash — an administrator told the backlog was clear by the one
        # button whose job is to clear it.
        logger.error(f"Could not read the audit forwarding queue: {exc}")
        flash(f"The forwarding queue could not be read, so nothing was sent "
              f"and nothing was marked. This is not an empty queue: "
              f"{_driver_message(exc)}", "error")
        return redirect(url_for("config.audit_page"))

    flash(f"{shipped:,} entr{'y' if shipped == 1 else 'ies'} forwarded."
          if shipped else "Nothing was waiting.", "success")
    return redirect(url_for("config.audit_page"))


# ---------------------------------------------------------------------------
# The checks WDash runs itself
# ---------------------------------------------------------------------------

@config_bp.route("/agents", methods=["POST"])
@login_required
def create_agent():
    """Register an agent and show its token ONCE.

    Flashed rather than stored anywhere readable: only the hash is kept, so
    there is no screen that can show it again. Somebody who loses it rotates
    rather than recovers, which is the only honest offer a store that cannot
    read its own secrets can make.
    """
    denied = _require_admin()
    if denied:
        return denied

    try:
        agent, token = _store().agents.create(request.form.get("name"))
    except MonitoringError as exc:
        flash(str(exc), "error")
        return redirect(url_for("config.config_page") + "#tab-monitors")

    _audit("agent registered", subject=agent["name"])
    # The token itself is NOT audited. An audit trail readable by every
    # administrator is a worse place for a live credential than the form that
    # is about to be closed.
    #
    # Flashed ALONE, with the explanation in the template: the block is
    # `user-select-all`, so anything else in it is copied along with the
    # token — and a token pasted into a config file with "Its token is shown
    # once, now:" in front of it fails authentication for a reason nobody can
    # see.
    flash(f"Agent '{agent['name']}' registered.", "success")
    flash(token, "token")
    return redirect(url_for("config.config_page") + "#tab-monitors")


@config_bp.route("/agents/<agent_id>/rotate", methods=["POST"])
@login_required
def rotate_agent(agent_id):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    agent = store.agents.get(agent_id)
    token = store.agents.rotate_token(agent_id)
    if token is None:
        flash("No such agent.", "error")
    else:
        _audit("agent token rotated", subject=agent["name"])
        # No grace period, and the message says so: an agent left running
        # with the old token stops reporting, and somebody has to know that
        # before they walk away.
        flash(f"New token for '{agent['name']}'. The old one stopped working "
              f"immediately, so this agent is reporting nothing until it is "
              f"restarted with the new one.", "warning")
        flash(token, "token")
    return redirect(url_for("config.config_page") + "#tab-monitors")


@config_bp.route("/agents/<agent_id>/delete", methods=["POST"])
@login_required
def delete_agent(agent_id):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    agent = store.agents.get(agent_id)
    if agent is None:
        flash("No such agent.", "error")
    else:
        stopped = store.agents.delete(agent_id)
        _audit("agent removed", subject=agent["name"],
               monitors_switched_off=stopped)
        # Results are NOT deleted with it. They are measurements of a target,
        # not property of the agent, and throwing away history because the
        # thing that collected it was retired is how an investigation loses
        # the week before the incident.
        if stopped:
            flash(f"Agent '{agent['name']}' removed. Its past results are "
                  f"kept. These checks ran only on it and are now switched "
                  f"off: {', '.join(stopped)}. A check assigned to no agent "
                  f"runs on every one, so give them an agent before switching "
                  f"them back on.", "warning")
        else:
            flash(f"Agent '{agent['name']}' removed. Its past results are "
                  f"kept.", "success")
    return redirect(url_for("config.config_page") + "#tab-monitors")


@config_bp.route("/monitors", methods=["POST"])
@login_required
def save_monitor():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    form = request.form
    monitor_id = form.get("id") or None

    assertions = {}
    statuses = [int(s) for s in (form.get("status") or "").replace(",", " ").split()
                if s.strip().isdigit()]
    if statuses:
        assertions["status"] = statuses
    if (form.get("body_contains") or "").strip():
        assertions["body_contains"] = form["body_contains"].strip()
    if (form.get("max_duration_ms") or "").strip().isdigit():
        assertions["max_duration_ms"] = int(form["max_duration_ms"])

    present = [h.strip() for h in
               (form.get("headers_present") or "").replace(",", "\n").split("\n")
               if h.strip()]
    if present:
        assertions["headers_present"] = present
    matches = _pairs(form.get("headers_match"))
    if matches:
        assertions["headers_match"] = matches

    # NOT named `request`: that is Flask's, and assigning to the name here
    # makes Python treat every mention in this function as local — including
    # `request.form` twenty lines above, which then raises UnboundLocalError
    # before anything else runs.
    request_config = {
        "headers": _pairs(form.get("request_headers")),
        "cookies": _pairs(form.get("request_cookies")),
    }
    auth_type = (form.get("auth_type") or "").strip()
    if auth_type == "basic":
        request_config["auth"] = {"type": "basic",
                                  "username": form.get("auth_username"),
                                  "password": form.get("auth_password") or None}
    elif auth_type == "bearer":
        request_config["auth"] = {"type": "bearer",
                                  "token": form.get("auth_token") or None}

    # What this check trusts, or waives. Always read, including the empty
    # shape: "verify against the public roots" is a decision the form can
    # make, so a submission that clears the certificate has to clear it in
    # the store rather than leaving the old one behind.
    tls = {"mode": form.get("tls_mode") or "verify",
           "certificate": form.get("tls_certificate"),
           "expected_name": form.get("tls_expected_name")}

    fields = dict(
        name=form.get("name"), kind=form.get("kind"),
        target=form.get("target"),
        interval_seconds=form.get("interval_seconds"),
        timeout_seconds=form.get("timeout_seconds"),
        assertions=assertions,
        request=request_config,
        tls=tls,
        agent_ids=form.getlist("agent_ids"))

    if form.get("kind") == "browser":
        # A journey has no request configuration and no HTTP assertions: a
        # browser sends its own headers, and what makes a journey pass is its
        # expect steps. Passing them anyway would store boxes the http form
        # left filled in from a previous edit.
        fields.update(assertions={}, request=None,
                      target=None, steps=form.get("steps") or "[]")
        # `journey_secret_<name>`, one per placeholder the steps mention.
        #
        # Passed through as submitted, blanks included. The store drops empty
        # values and keeps what is already stored — an edit that does not
        # retype the password keeps it. Filtering here as well could not be
        # made to fail: every case the route would catch the store catches
        # too, and untestable redundancy is what somebody edits next while
        # believing it does something.
        fields["journey_secrets"] = {
            key[len("journey_secret_"):]: value
            for key, value in form.items()
            if key.startswith("journey_secret_")}

    dropped = ""
    try:
        if monitor_id:
            before = store.monitors.get(monitor_id)
            saved = store.monitors.update(
                monitor_id, enabled=form.get("enabled") == "on",
                # The only way a check that sends something can become one
                # that does not verify. Without it the refusal is a dead end:
                # measured, a stored credential cannot otherwise be removed
                # at all, and the administrator would have to delete the
                # check and build it again.
                forget_request=form.get("forget_request") == "on",
                **fields)
            if saved is None:
                flash("No such monitor.", "error")
                return redirect(url_for("config.config_page") + "#tab-monitors")
            if (before and before["has_credentials"]
                    and not saved["has_credentials"] and saved["kind"] != "browser"):
                dropped = (f" Its stored credentials were for "
                           f"{_where(before['target'])} and were not carried "
                           f"to {_where(saved['target'])}: type them again if "
                           f"that needs them.")
            if (before and tls.get("certificate")
                    and not saved["tls"].get("certificate")):
                # Said for the same reason the credentials are: a certificate
                # is pasted because THAT endpoint presents it, so it does not
                # follow the check to another host — and a person who cannot
                # see that it was dropped is a person whose check is now down
                # for a reason the form does not show.
                dropped += (f" The certificate it was told to trust was for "
                            f"{_where(before['target'])} and was not carried "
                            f"to {_where(saved['target'])}: paste the new "
                            f"one.")
            _audit("monitor updated", subject=saved["name"],
                   target=_without_password(saved["target"]),
                   has_credentials=saved["has_credentials"],
                   credentials_dropped=bool(dropped))
        else:
            saved = store.monitors.create(
                created_by=getattr(current_user, "username", None), **fields)
            _audit("monitor created", subject=saved["name"])
    except MonitoringError as exc:
        # Audited, not only flashed. A refusal that a check does not verify
        # its certificate AND holds a credential is the record of an attempt
        # to send one somewhere nothing vouches for — the same treatment a
        # refused source save gets, and the copy still there next week.
        _audit("monitor save refused", subject=form.get("name") or monitor_id,
               state={"reason": str(exc), "target": _without_password(
                   form.get("target") or ""), "tls_mode": tls["mode"]})
        flash(str(exc), "error")
        return redirect(url_for("config.config_page") + "#tab-monitors")

    flash(f"Monitor '{saved['name']}' saved. Agents pick it up within a "
          f"minute — they poll for configuration rather than being pushed to, "
          f"which is what lets them run behind NAT.{dropped}",
          "warning" if dropped else "success")
    return redirect(url_for("config.config_page") + "#tab-monitors")


@config_bp.route("/monitors/<monitor_id>/delete", methods=["POST"])
@login_required
def delete_monitor(monitor_id):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    monitor = store.monitors.get(monitor_id)
    if monitor is None:
        flash("No such monitor.", "error")
    else:
        store.monitors.delete(monitor_id)
        _audit("monitor removed", subject=monitor["name"])
        # Results DO go with it, unlike an agent's. They are about a check
        # that no longer exists, and a page cannot show them without a
        # definition to name them.
        flash(f"Monitor '{monitor['name']}' and its results were removed.",
              "success")
    return redirect(url_for("config.config_page") + "#tab-monitors")


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

#: What each rule kind watches, in a sentence somebody can check against what
#: they meant. The identifiers — monitor_down, agent_silent — are for the
#: database; nobody should have to learn them to configure an alert.
def journey_step_kinds():
    """The step vocabulary, for the editor.

    Rendered from the same dictionary the server validates against rather than
    written out again in JavaScript: a form that offers a verb the validator
    does not have is a form that produces an error on save, and a validator
    with a verb the form does not offer is a feature nobody can reach.
    """
    from ..journeys.steps import STEP_KINDS
    return {name: {"label": spec.label, "selector": spec.selector,
                   "value": spec.value, "value_label": spec.value_label,
                   "asserts": spec.asserts, "hint": spec.hint}
            for name, spec in STEP_KINDS.items()}


RULE_DESCRIPTIONS = {
    "monitor_down": (
        "A check stops answering",
        "Fires when a monitor fails. NOT when its agent goes quiet — that "
        "says nothing about the target, and paging somebody because a probe "
        "restarted is how a channel gets muted."),
    "agent_silent": (
        "A probe stops reporting",
        "Fires when an agent has not checked in. A different fact with a "
        "different audience: whoever runs the probes, not whoever owns the "
        "thing being probed."),
    "certificate_expiring": (
        "A certificate is running out",
        "Fires once a certificate is inside the warning window. A diary "
        "entry rather than an outage — it is still working when this "
        "arrives."),
}


def _describe_rule(rule, channels):
    """One sentence saying what this rule does."""
    channel = next((c["name"] for c in channels
                    if c["id"] == rule["channel_id"]), None)

    selector = rule.get("selector") or {}
    # SINGULAR. A rule watching fifty monitors fires fifty times, once per
    # monitor — "monitors labelled x fails" is both ungrammatical and the
    # wrong mental model: it reads as one alert for the whole group.
    which = ("any monitor" if not selector else
             "any monitor labelled " + ", ".join(
                 f"{k}={v}" for k, v in selector.items()))

    kind = rule.get("kind")
    if kind == "certificate_expiring":
        what = (f"a certificate on {which} is within "
                f"{rule.get('days_before') or 30} days of expiring")
    elif kind == "agent_silent":
        what = "an agent stops reporting"
    else:
        times = rule.get("threshold") or 1
        what = (f"{which} fails "
                f"{'one check' if times == 1 else f'{times} checks in a row'}")

    repeat = rule.get("repeat_minutes") or 0
    again = (f", and again every {repeat} minutes until it recovers"
             if repeat else ", once")

    if channel is None:
        # Said as a fault rather than folded into the sentence: a rule with no
        # channel fires into nothing, and that is the thing to notice.
        return (f"Fires when {what}{again} — but its channel no longer "
                f"exists, so nobody is told.")
    return f"Tells {channel} when {what}{again}."


def _alerts_tab():
    return redirect(url_for("config.config_page") + "#tab-alerts")


@config_bp.route("/channels", methods=["POST"])
@login_required
def save_channel():
    denied = _require_admin()
    if denied:
        return denied

    try:
        channel = _store().channels.create(
            name=request.form.get("name"),
            url=request.form.get("url"),
            headers=_pairs(request.form.get("headers")),
            secret_headers=_pairs(request.form.get("secret_headers")))
    except AlertingError as exc:
        flash(str(exc), "error")
        return _alerts_tab()

    # The URL is NOT audited. For Slack and Teams the path is the credential,
    # and an audit trail every administrator can read is a worse place for it
    # than the form that is about to be closed.
    _audit("alert channel added", subject=channel["name"],
           host=channel["host"])
    flash(f"Alerts can now be sent to '{channel['name']}' ({channel['host']}). "
          f"The URL is stored encrypted and is not shown again.", "success")
    return _alerts_tab()


@config_bp.route("/channels/<channel_id>/delete", methods=["POST"])
@login_required
def delete_channel(channel_id):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    channel = store.channels.get(channel_id)
    if channel is None:
        flash("No such channel.", "error")
        return _alerts_tab()

    using = [r["name"] for r in store.rules.all()
             if r["channel_id"] == channel_id]
    if using:
        # Refused rather than cascaded. Deleting the channel would leave those
        # rules evaluating and failing to deliver — alerts that fire into
        # nothing, which is the failure mode this whole feature exists to
        # prevent.
        flash(f"'{channel['name']}' is still used by: {', '.join(using)}. "
              f"Point those rules somewhere else first.", "error")
        return _alerts_tab()

    store.channels.delete(channel_id)
    _audit("alert channel removed", subject=channel["name"])
    flash(f"Channel '{channel['name']}' removed.", "success")
    return _alerts_tab()


@config_bp.route("/rules", methods=["POST"])
@login_required
def save_rule():
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    form = request.form
    rule_id = form.get("id") or None
    selector = _pairs(form.get("selector"))

    try:
        if rule_id:
            saved = store.rules.update(
                rule_id, name=form.get("name"),
                threshold=int(form.get("threshold") or 3),
                repeat_minutes=int(form.get("repeat_minutes") or 0),
                days_before=(int(form["days_before"])
                             if (form.get("days_before") or "").isdigit()
                             else None),
                selector=selector, channel_id=form.get("channel_id"),
                enabled=form.get("enabled") == "on")
            if saved is None:
                flash("No such rule.", "error")
                return _alerts_tab()
            _audit("alert rule updated", subject=saved["name"])
        else:
            saved = store.rules.create(
                name=form.get("name"), kind=form.get("kind"),
                channel_id=form.get("channel_id"),
                threshold=form.get("threshold") or 3,
                repeat_minutes=form.get("repeat_minutes") or 0,
                days_before=form.get("days_before"),
                selector=selector,
                created_by=getattr(current_user, "username", None))
            _audit("alert rule created", subject=saved["name"],
                   kind=saved["kind"])
    except (AlertingError, ValueError) as exc:
        flash(str(exc), "error")
        return _alerts_tab()

    flash(f"Rule '{saved['name']}' saved. It is evaluated by "
          f"`python -m wdash.alerts`, which has to be running — nothing in "
          f"the web process sends alerts.", "success")
    return _alerts_tab()


@config_bp.route("/rules/<rule_id>/delete", methods=["POST"])
@login_required
def delete_rule(rule_id):
    denied = _require_admin()
    if denied:
        return denied

    store = _store()
    rule = store.rules.get(rule_id)
    if rule is None:
        flash("No such rule.", "error")
    else:
        store.rules.delete(rule_id)
        _audit("alert rule removed", subject=rule["name"])
        # State goes with it. Keeping it would mean a rule recreated with the
        # same name inherits failure counters from a previous life.
        flash(f"Rule '{rule['name']}' removed.", "success")
    return _alerts_tab()


@config_bp.route("/silences", methods=["POST"])
@login_required
def save_silence():
    denied = _require_admin()
    if denied:
        return denied

    from datetime import datetime, timedelta, timezone
    hours = request.form.get("hours") or "1"
    try:
        until = datetime.now(timezone.utc) + timedelta(hours=float(hours))
    except ValueError:
        flash("That is not a number of hours.", "error")
        return _alerts_tab()

    try:
        _store().silences.create(
            subject=request.form.get("subject"), until=until,
            reason=request.form.get("reason"),
            created_by=getattr(current_user, "username", None))
    except AlertingError as exc:
        flash(str(exc), "error")
        return _alerts_tab()

    subject = request.form.get("subject")
    _audit("alerts silenced", subject=subject, until=until.isoformat())
    flash(f"Alerts for '{subject}' are silenced until "
          f"{until:%H:%M}. Recoveries are still sent — silencing the noise of "
          f"something being broken is not the same as wanting to believe it "
          f"still is.", "success")
    return _alerts_tab()


@config_bp.route("/silences/<silence_id>/delete", methods=["POST"])
@login_required
def delete_silence(silence_id):
    denied = _require_admin()
    if denied:
        return denied
    _store().silences.delete(silence_id)
    _audit("silence lifted", subject=silence_id)
    return _alerts_tab()
