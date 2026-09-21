"""
Which identity provider settings are actually in force.

A provider is configured in one place — the configuration page, whose card
is stored in the metadata database — so the rule that decides which one
signs people in is a function of the stored rows and nothing else. There
used to be a second place: the environment could declare an OpenID Connect
provider, a stored row shadowed it, and every rule here carried a flag for
"is one configured in the environment". That path is gone.

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
row that exists and is enabled. Deliberately not from usability: deciding it
from "usable" while refusing the second one from "configured" means an LDAP
whose bind password can no longer be decrypted stops shadowing the other
directory, and the installation silently changes directory with no banner and
no audit row. Usability is reported separately, and a directory in force that
cannot be used takes the sign-in door with it rather than handing it to the
other one.

    1. Both stored and enabled: the row saved most recently is in force, ties
       broken in favour of LDAP, so the answer never depends on row order.
    2. One: that one.
    3. Neither: no directory. Local accounts are unaffected.

`directory(app)` answers in NAMES and a sentence and never returns the
settings themselves, because that answer goes to templates, to the log and to
audit rows, while the settings dicts hold a decrypted client secret and bind
password.
"""

import logging

from ..store.roles import DEFAULT_CLAIM_MAPPINGS

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

#: What a directory cannot sign anybody in without, named as the card names
#: the field. ONE list: the page refuses a save that would enable a provider
#: missing any of these, and `_oidc_effective` and `_ldap_effective` below
#: refuse to offer one. Two lists would let the page accept a card the
#: sign-in then declines, which is how a blank OpenID Connect card came to be
#: saved, enabled, reported as "in force now", and never offered to anybody.
REQUIRED = {
    "oidc": (("client_id", "a Client ID"),
             ("discovery_url", "a Discovery URL")),
    "ldap": (("server", "a Server"), ("base_dn", "a Base DN")),
}

#: Every field either card holds, for "is there anything here at all".
FIELDS = {
    "oidc": ("client_id", "discovery_url", "redirect_uri", "scopes",
             "username_claim", "email_claim", "groups_claim"),
    "ldap": ("server", "bind_dn", "base_dn", "user_filter",
             "group_attribute", "ca_certs"),
}


def listed(names):
    """"a, b and c" — a list somebody reads rather than a Python repr.

    Public, like `invariants.few()` and for the same reason: the
    configuration page builds the same kind of sentence out of the same
    names, and reaching across a module boundary for a name with a leading
    underscore says one thing while the import says another.
    """
    names = list(names)
    if len(names) <= 1:
        return names[0] if names else ""
    return ", ".join(names[:-1]) + " and " + names[-1]


def needs_secret(which, value):
    """The secret this provider cannot work without, named, or None.

    OpenID Connect always: WDash is a confidential client and the token
    request carries it. LDAP only where a bind DN names a service account to
    bind AS — a DN with no password binds anonymously under a name, which a
    directory reports as "the service account could not bind", two screens
    away from the field that is empty.
    """
    if which == "oidc":
        return "a Client secret"
    if which == "ldap" and ((value or {}).get("bind_dn") or "").strip():
        return "a Bind password"
    return None


def missing(which, value, has_secret=False):
    """Which required fields are blank, in the words the card uses for them.

    `has_secret` is whether one is stored or was typed on this submission —
    the field itself is blank on every visit after the first, because a
    sealed secret is replaced rather than shown.
    """
    value = value or {}
    names = [label for field, label in REQUIRED.get(which, ())
             if not str(value.get(field) or "").strip()]
    wanted = needs_secret(which, value)
    if wanted and not has_secret:
        names.append(wanted)
    return names


def malformed(which, value):
    """Why a field that IS filled in could not work, or None.

    Separate from `missing` because it applies to a draft as well: a server
    address with no protocol is wrong whether or not anybody has switched the
    card on, and saving it and finding out at the next sign-in is the long
    way round.
    """
    value = value or {}
    if which == "ldap":
        server = (value.get("server") or "").strip()
        if server and not server.lower().startswith(("ldap://", "ldaps://")):
            return (f"the Server has to start with ldap:// or ldaps:// — "
                    f"'{server}' names no protocol")
    if which == "oidc":
        from ..store.sources import SourceError, validate_url
        for field, label in (("discovery_url", "Discovery URL"),
                             ("redirect_uri", "Redirect URI")):
            address = (value.get(field) or "").strip()
            if not address:
                continue
            try:
                # The same check a source address gets, for the same reason:
                # WDash's own server fetches the discovery document, so an
                # address naming cloud instance metadata is a request it
                # would make on somebody's behalf.
                validate_url(address)
            except SourceError as exc:
                said = str(exc)
                return (f"the {label} cannot be used: "
                        f"{said[:1].lower()}{said[1:]}")
    return None


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


def resolve(rows):
    """Which directory is in force, from the stored rows alone.

    `rows` is `store.settings.all(prefix="auth.")`. Pure, so the page, the
    sign-in form, the startup check and the recovery tool all get the same
    answer from the same rule. It took a second argument once — whether the
    environment configured an OpenID Connect provider — and every branch
    below had a case for it; there is one place a provider comes from now.

    Returns {"in_force", "shadowed", "sources"}, where `sources` is
    {"ldap": "configuration"|None, "oidc": "configuration"|None} — a row that
    exists and is enabled, or nothing.
    """
    def stored(key):
        row = rows.get(key) or {}
        return row.get("value"), row.get("updated_at")

    ldap_value, ldap_at = stored(LDAP_KEY)
    oidc_value, oidc_at = stored(OIDC_KEY)

    sources = {"ldap": None, "oidc": None}
    if ldap_value and ldap_value.get("enabled"):
        sources["ldap"] = "configuration"
    if oidc_value and oidc_value.get("enabled"):
        sources["oidc"] = "configuration"

    both = bool(sources["ldap"] and sources["oidc"])
    if both:
        in_force = "oidc" if _later(oidc_at, ldap_at) else "ldap"
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
    return resolve(rows)


def _reason(state, unusable):
    """The whole sentence for an administrator: log, banner, audit row.

    Names and instructions only — never a setting, never a secret.
    """
    in_force, shadowed = state["in_force"], state["shadowed"]
    said = []
    if shadowed:
        said.append(
            f"Two directories are configured here and WDash signs people in "
            f"through one at a time. {LABELS[in_force]} is in force; "
            f"{LABELS[shadowed]} is configured and is not in use. To use "
            f"{LABELS[shadowed]} instead, turn {LABELS[in_force]} off on this "
            f"page and save, then enable {LABELS[shadowed]}. From the "
            f"command line: {RECOVERY}.")
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

    return (f"{LABELS[in_force]} is the directory in use here, and WDash "
            f"signs people in through one directory at a time — otherwise a "
            f"name at one directory belongs to somebody at the other. "
            f"{LABELS[which]} was not enabled and nothing was saved. To "
            f"switch: turn it off on this page and save, then enable "
            f"{LABELS[which]}. From the command line: {RECOVERY}.")


#: Which claims name a person, unless something more specific says otherwise.
#: The same object a new installation stores, so the two cannot disagree.
DEFAULT_CLAIMS = DEFAULT_CLAIM_MAPPINGS


def _claims(app, configured):
    """The claim names and the email rule, from the most specific place.

    This provider's own settings first, then the claim mappings stored for
    this installation, then the defaults. A new installation stores the
    defaults. One that imported `claim_mappings` from an rbac.yaml at an
    earlier version keeps what it imported — which is the reason this is
    read at all: that block was once shipped, documented and never read, and
    an operator whose provider sends groups as `roles` edited it and every
    OIDC user still landed on the default role.
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
    if store is None:
        return None, None

    stored = store.settings.get(OIDC_KEY)
    if stored is None or not (stored.get("enabled") or if_enabled):
        return None, None
    try:
        secret = store.settings.secret(OIDC_KEY)
    except Exception as exc:
        # A key that has changed since the secret was written. Say so, and
        # offer nothing: signing people in against some other provider would
        # be worse than signing nobody in.
        logger.error(f"OIDC client secret could not be read: {exc}")
        return None, "the client secret could not be decrypted"
    # `has_secret=True`, like the LDAP one below: whether a secret is there
    # is asked at the gate, where somebody can type one, and not here. An
    # installation that already has OpenID Connect enabled with no stored
    # secret goes on being offered exactly as it was — it fails at the token
    # request, which is the provider's answer and not ours to change on an
    # upgrade. The configuration page refuses to switch one on without it.
    absent = missing("oidc", stored, has_secret=True)
    if absent:
        logger.warning(
            f"OIDC is enabled and incomplete ({', '.join(absent)} "
            f"{'are' if len(absent) > 1 else 'is'} blank); it will not be "
            f"offered")
        return None, (f"{listed(absent)} {'are' if len(absent) > 1 else 'is'} "
                      f"required and blank")
    return {
        "client_id": stored["client_id"],
        "client_secret": secret or "",
        "discovery_url": stored["discovery_url"],
        # Blank is left blank: the route that starts a sign-in derives this
        # WDash's own callback from the request, which this function — also
        # run by the recovery tool, outside any request — cannot.
        "redirect_uri": stored.get("redirect_uri") or None,
        # Blank means the default the sign-in asks for; see auth.init_oauth.
        "scopes": stored.get("scopes") or None,
        "source": "configuration",
        **_claims(app, stored),
    }, None


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
    absent = missing("ldap", stored, has_secret=True)
    if absent:
        logger.warning(
            f"LDAP is enabled and incomplete ({', '.join(absent)} "
            f"{'are' if len(absent) > 1 else 'is'} blank); it will not be "
            f"offered")
        return None, (f"{listed(absent)} {'are' if len(absent) > 1 else 'is'} "
                      f"required and blank")

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
