"""
Which identity provider settings are actually in force.

Two places can configure a provider: the environment (how it has always
worked) and the configuration page (how it works now). Both have to keep
working, so the rule is stated once here rather than guessed at each call site:

    a provider configured in the store wins; otherwise the environment is used

The store wins because it is the thing an administrator just edited. If the
environment took precedence, the config page would save successfully and change
nothing — the same illusion that made permissions-in-the-cookie a bug.

`enabled` is honoured separately from completeness. Turning a provider off must
disable it even though its settings are still filled in, or the switch is
decoration.

Read on the request that needs them rather than cached at startup: sign-in is
rare, a database round trip is nothing next to an OIDC redirect, and it means
an administrator can fix a broken provider without a restart — which is exactly
the situation in which nobody wants to be told to restart.

And at most ONE DIRECTORY signs people in: either LDAP or OIDC, never both.
Local accounts are not a directory and none of this touches them.

The reason is ownership. A dashboard belongs to `created_by == username` and a
role mapping is written against a name, so the username is one namespace with
no provider attached to it. With two directories open, a principal at one of
them who can choose `preferred_username` takes a name that belongs to somebody
at the other, with their dashboards and their role — measured end to end
(C147): an OIDC principal signed in as the directory user `alice`, got her
admin mapping and opened her private dashboard, and the audit trail showed two
ordinary sign-in rows.

Which one is in force is decided here, once, from CONFIGURATION — a settings
row that exists and is enabled, or, for OIDC only, the environment pair when
no row exists at all. Deliberately not from usability: deciding it from
"usable" while refusing the second one from "configured" means an LDAP whose
bind password can no longer be decrypted stops shadowing an environment OIDC,
and the installation silently changes directory with no banner and no audit
row. Usability is reported separately, and a directory in force that cannot be
used takes the sign-in door with it rather than handing it to the other one.

    1. Configured in the store beats configured only in the environment.
    2. Both stored and enabled: the row saved most recently is in force, ties
       broken in favour of LDAP, so the answer never depends on row order.
    3. Neither: no directory. Local accounts are unaffected.

`directory(app)` answers in NAMES and a sentence and never returns the
settings themselves, because that answer goes to templates, to the log and to
audit rows, while the settings dicts hold a decrypted client secret and bind
password.
"""

import logging

logger = logging.getLogger(__name__)

OIDC_KEY = "auth.oidc"
LDAP_KEY = "auth.ldap"

#: How each directory is named in a sentence somebody reads.
LABELS = {"ldap": "LDAP", "oidc": "OpenID Connect"}

#: The other one.
OTHER = {"ldap": "oidc", "oidc": "ldap"}

#: How to choose a directory without the configuration page. Named in the
#: refusals, the banner and the startup warning, because a rule whose recovery
#: is "write SQL" is a lockout with better wording.
RECOVERY = "python -m wdash.store.recover --use-directory <ldap|oidc|none>"


def _store(app):
    return getattr(app, "store", None)


def _later(one, other):
    """True when `one` was saved strictly after `other`."""
    if one is None:
        return False
    if other is None:
        return True
    try:
        return one > other
    except TypeError:
        # One dialect hands back naive datetimes and another aware ones. Never
        # within one store, but a comparison that raises here would take the
        # sign-in page down, and the tie-break has a defined answer.
        return False


def resolve(rows, environment_oidc=False):
    """Which directory is in force, from configuration alone.

    `rows` is `store.settings.all(prefix="auth.")`, `environment_oidc` says
    whether OIDC_CLIENT_ID and OIDC_DISCOVERY_URL are both set. Pure, so the
    page, the sign-in form, the startup check and the recovery tool all get
    the same answer from the same rule.

    Returns {"in_force", "shadowed", "sources"}, where `sources` is
    {"ldap": "configuration"|None, "oidc": "configuration"|"environment"|None}.
    """
    def stored(key):
        row = rows.get(key) or {}
        return row.get("value"), row.get("updated_at")

    ldap_value, ldap_at = stored(LDAP_KEY)
    oidc_value, oidc_at = stored(OIDC_KEY)

    sources = {"ldap": None, "oidc": None}
    if ldap_value and ldap_value.get("enabled"):
        sources["ldap"] = "configuration"
    if oidc_value is not None:
        # A stored row answers for OIDC whether it is on or off. That is what
        # makes "save the card with Enabled unchecked" turn an environment
        # provider off, which is the only in-page way to do it.
        if oidc_value and oidc_value.get("enabled"):
            sources["oidc"] = "configuration"
    elif environment_oidc:
        sources["oidc"] = "environment"

    both = bool(sources["ldap"] and sources["oidc"])
    if both:
        in_force = ("ldap" if sources["oidc"] == "environment"
                    else ("oidc" if _later(oidc_at, ldap_at) else "ldap"))
    elif sources["ldap"]:
        in_force = "ldap"
    elif sources["oidc"]:
        in_force = "oidc"
    else:
        in_force = None

    return {"in_force": in_force,
            "shadowed": OTHER[in_force] if both else None,
            "sources": sources}


def _state(app):
    store = _store(app)
    rows = store.settings.all(prefix="auth.") if store is not None else {}
    return resolve(rows, bool(app.config.get("OIDC_CLIENT_ID")
                              and app.config.get("OIDC_DISCOVERY_URL")))


def _where(source):
    return ("on this page" if source == "configuration"
            else "in the environment")


def _reason(state, unusable):
    """The whole sentence for an administrator: log, banner, audit row.

    Names and instructions only — never a setting, never a secret.
    """
    in_force, shadowed = state["in_force"], state["shadowed"]
    said = []
    if shadowed:
        how = (f"turn {LABELS[in_force]} off on this page and save, then "
               f"enable {LABELS[shadowed]}"
               if state["sources"][shadowed] == "configuration"
               else f"turn {LABELS[in_force]} off on this page and save")
        said.append(
            f"Two directories are configured here and WDash signs people in "
            f"through one at a time. {LABELS[in_force]} is in force "
            f"(configured {_where(state['sources'][in_force])}); "
            f"{LABELS[shadowed]} is configured "
            f"{_where(state['sources'][shadowed])} and is not in use. To use "
            f"{LABELS[shadowed]} instead, {how}. From the command line: "
            f"{RECOVERY}.")
    if in_force is not None and unusable:
        said.append(
            f"{LABELS[in_force]} is the directory in force here and its saved "
            f"settings cannot be used: {unusable}. No directory sign-in is "
            f"offered until that is fixed — local accounts are unaffected. To "
            f"hand the installation to the other directory instead: "
            f"{RECOVERY}.")
    return " ".join(said) or None


def why_unusable(app, which, if_enabled=False):
    """Why `which` could not sign anybody in, or None — a clause, never a
    setting.

    Asked of EITHER directory, not only the one in force, because two callers
    need it about a directory they are about to hand the installation to: the
    page, before it accepts a save that turns the current one off, and the
    recovery tool, before it puts one in force. A refusal that says "nobody
    would be able to open this page" while the other directory would take over
    on the same save is a false sentence, and the answer to "would it work?"
    has to come from the same place as the answer to "would it take over?".

    `if_enabled` asks it of a directory that is switched off, which is what
    the recovery tool is looking at: a row saying `enabled: False` is not a
    complaint about the settings, and silence there is how the tool came to
    enable a blank card and leave an installation with no directory at all.
    """
    if which not in LABELS:
        return None
    effective = _ldap_effective if which == "ldap" else _oidc_effective
    return effective(app, if_enabled)[1]


def directory(app):
    """Which directory signs people in here, in names and a sentence.

    {"in_force", "shadowed", "sources", "unusable", "reason"} — never the
    settings, so a template or an audit row physically cannot receive a
    decrypted secret through this path.
    """
    state = _state(app)
    unusable = (why_unusable(app, state["in_force"])
                if state["in_force"] is not None else None)
    return {**state, "unusable": unusable, "reason": _reason(state, unusable)}


def shadow_notice(app):
    """One neutral sentence for the sign-in page, or None.

    It names nothing and offers nothing, but it exists: without it a directory
    user whose directory has just been shadowed — or whose directory cannot be
    read — is told "Invalid username or password", which is a failure that
    looks like their own mistake.
    """
    state = directory(app)
    said = []
    if state["unusable"]:
        # First: this is the one that explains why the person's own sign-in
        # has just failed.
        said.append("Directory sign-in is unavailable here: the directory's "
                    "saved settings cannot be used. Local accounts still "
                    "work — ask an administrator.")
    if state["shadowed"]:
        said.append("Another sign-in method is configured here but is not in "
                    "use. If that is the one you normally use, ask an "
                    "administrator.")
    return " ".join(said) or None


def refuses_second_directory(app, which, enabling):
    """Why enabling this directory must be refused, or None.

    Decided from `directory()`, so the rule that refuses and the rule that
    resolves cannot drift apart. A save of the directory ALREADY in force is
    never "the second directory": that is how an administrator edits the one
    they are using, and re-saving it cannot change which is in force.
    """
    if not enabling:
        return None
    in_force = _state(app)["in_force"]
    if in_force is None or in_force == which:
        return None

    source = _state(app)["sources"][in_force]
    how = ("turn it off on this page and save"
           if source == "configuration" else
           "save the OpenID Connect card with Enabled unchecked, which stores "
           "a disabled row and turns the environment's provider off")
    return (f"{LABELS[in_force]} is the directory in use here"
            f"{'' if source == 'configuration' else ' (configured in the environment)'}"
            f", and WDash signs people in through one directory at a time — "
            f"otherwise a name at one directory belongs to somebody at the "
            f"other. {LABELS[which]} was not enabled and nothing was saved. To "
            f"switch: {how}, then enable {LABELS[which]}. From the command "
            f"line: {RECOVERY}.")


#: Which claims name a person, unless something more specific says otherwise.
DEFAULT_CLAIMS = {"username_claim": "preferred_username",
                  "email_claim": "email", "groups_claim": "groups"}


def _claims(app, configured):
    """The claim names and the email rule, from the most specific place.

    This provider's own settings first, then the `claim_mappings` block
    rbac.yaml was imported with, then the defaults. That block was shipped,
    documented and never read: an operator whose provider sends groups as
    `roles` edited it and every OIDC user still landed on the default role.
    """
    store = _store(app)
    seeded = {}
    if store is not None:
        try:
            seeded = store.settings.get("rbac.claim_mappings") or {}
        except Exception:
            seeded = {}
    configured = configured or {}
    claims = {key: (configured.get(key) or seeded.get(key) or default)
              for key, default in DEFAULT_CLAIMS.items()}
    claims["trust_unverified_email"] = bool(configured.get("trust_unverified_email"))
    return claims


def _oidc_effective(app, if_enabled=False):
    """(settings, why they cannot be used) for OIDC as configured here.

    The settings dict holds the decrypted client secret and must not be
    logged or put into a template. The second half is a clause for a person,
    and holds no setting at all.

    `if_enabled` reads a switched-off row as though it were on, which is the
    question asked of a directory nobody is using yet.
    """
    store = _store(app)
    if store is not None:
        stored = store.settings.get(OIDC_KEY)
        if stored is not None and (stored.get("enabled") or if_enabled):
            try:
                secret = store.settings.secret(OIDC_KEY)
            except Exception as exc:
                # A key that has changed since the secret was written. Say so:
                # falling back to the environment here would sign people in
                # against a provider the administrator thought they had
                # replaced.
                logger.error(f"OIDC client secret could not be read: {exc}")
                return None, "the client secret could not be decrypted"
            if stored.get("client_id") and stored.get("discovery_url"):
                return {
                    "client_id": stored["client_id"],
                    "client_secret": secret or "",
                    "discovery_url": stored["discovery_url"],
                    "redirect_uri": stored.get("redirect_uri")
                    or app.config.get("OIDC_REDIRECT_URI"),
                    "source": "configuration",
                    **_claims(app, stored),
                }, None
            logger.warning(
                "OIDC is enabled but incomplete (client id and discovery URL "
                "are both required); it will not be offered")
            return None, ("a client id and a discovery URL are both required "
                          "and one of them is blank")
        if stored is not None and not stored.get("enabled"):
            # Explicitly turned off. Do NOT fall back to the environment —
            # that would make the switch do nothing on a deployment that has
            # both, which is every deployment that has just migrated.
            return None, None

    if app.config.get("OIDC_CLIENT_ID") and app.config.get("OIDC_DISCOVERY_URL"):
        return {
            "client_id": app.config["OIDC_CLIENT_ID"],
            "client_secret": app.config.get("OIDC_CLIENT_SECRET") or "",
            "discovery_url": app.config["OIDC_DISCOVERY_URL"],
            "redirect_uri": app.config.get("OIDC_REDIRECT_URI"),
            "source": "environment",
            **_claims(app, {
                "username_claim": app.config.get("OIDC_USERNAME_CLAIM"),
                "email_claim": app.config.get("OIDC_EMAIL_CLAIM"),
                "groups_claim": app.config.get("OIDC_GROUPS_CLAIM"),
                "trust_unverified_email":
                    app.config.get("OIDC_TRUST_UNVERIFIED_EMAIL"),
            }),
        }, None
    return None, None


def oidc_settings(app):
    """Effective OIDC settings, or None when OIDC is not the directory in
    force here, or is and cannot be used.

    Returns a dict with client_id / client_secret / discovery_url /
    redirect_uri. The secret is decrypted here and must not be logged or put
    into a template.

    Every caller obeys the one-directory rule by calling this: the sign-in
    page, /auth/oidc and /auth/callback each ask the same question and cannot
    answer it differently.
    """
    if _state(app)["in_force"] != "oidc":
        return None
    return _oidc_effective(app)[0]


def ldap_settings(app):
    """Effective LDAP settings, or None when LDAP is not the directory in
    force here, or is and cannot be used."""
    if _state(app)["in_force"] != "ldap":
        return None
    return _ldap_effective(app)[0]


def _ldap_effective(app, if_enabled=False):
    """(settings, why they cannot be used) for LDAP as configured here.

    `if_enabled` reads a switched-off row as though it were on — see
    `why_unusable`.
    """
    store = _store(app)
    if store is None:
        return None, None

    stored = store.settings.get(LDAP_KEY)
    if not stored or not (stored.get("enabled") or if_enabled):
        return None, None
    if not stored.get("server") or not stored.get("base_dn"):
        logger.warning(
            "LDAP is enabled but incomplete (server and base DN are both "
            "required); it will not be offered")
        return None, ("a server and a base DN are both required and one of "
                      "them is blank")

    try:
        password = store.settings.secret(LDAP_KEY)
    except Exception as exc:
        logger.error(f"LDAP bind password could not be read: {exc}")
        return None, "the bind password could not be decrypted"

    return {
        "server": stored["server"],
        "bind_dn": stored.get("bind_dn") or "",
        "bind_password": password or "",
        "base_dn": stored["base_dn"],
        "user_filter": stored.get("user_filter") or "(uid={username})",
        "group_attribute": stored.get("group_attribute") or "memberOf",
        # On unless somebody turned it off: settings saved before the switch
        # existed have no key, and they get the check.
        "verify_certs": stored.get("verify_certs", True) is not False,
        "ca_certs": stored.get("ca_certs") or None,
    }, None
