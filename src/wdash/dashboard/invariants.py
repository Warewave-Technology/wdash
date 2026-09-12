"""
Changes that must never be allowed to succeed.

Not permission checks — those decide whether *you* may act. These decide
whether the resulting SYSTEM is still operable, regardless of who is asking.
An administrator with every permission still must not be able to leave the
installation with nobody able to administer it.

Why this is a hazard rather than an inconvenience: `system:admin` is not a
superuser. It gates the administration tools and nothing else, so no other
permission can be used to recover. Once the last role carrying it is gone, the
configuration page is unreachable and the only way back is the database.

Each rule answers with a message or None. The caller turns a message into a
refusal; a rule never mutates anything and never raises.

"Would this lock you out?" is answered by asking the resolver's own rule,
`choose_role`, about the picture AFTER the change. These rules used to carry a
shorter copy of it — username before email, no groups — and so refused an
administrator who reached the page through a group from changing the default
role, and let somebody whose email mapped them to a lesser role save a change
that demoted them, because the copy looked at their username first.

`actor` is who is asking: a mapping with `email`, `username`, `groups` and,
for a local account, `local_role` — the role stored with the account.
"""

from ..store.rbac import choose_role

ADMIN_PERMISSION = "system:admin"


def _carriers(roles, exclude=None):
    """Roles that grant administration, ignoring one by name."""
    return [role for role in roles
            if role["name"] != exclude
            and ADMIN_PERMISSION in (role.get("permissions") or [])]


def _lands_on(roles, user_roles, default_role, actor):
    """The role `actor` would resolve to in this picture, and its definition."""
    by_name = {role["name"]: role for role in roles}
    actor = actor or {}
    name = choose_role(by_name, user_roles or {}, default_role,
                       email=actor.get("email"),
                       username=actor.get("username"),
                       groups=actor.get("groups") or (),
                       explicit=actor.get("local_role"))
    return name, by_name.get(name)


def _administers(definition):
    return (definition is not None
            and ADMIN_PERMISSION in (definition.get("permissions") or []))


#: How many names a message shows before it starts counting instead. Public
#: with `few()`: the configuration page builds the same kind of sentence, and
#: reaching across a module boundary for a name with a leading underscore said
#: one thing while the import said another.
FEW = 5


def few(names, limit=FEW):
    names = sorted(names)
    shown = ", ".join(names[:limit])
    return shown if len(names) <= limit else f"{shown} and {len(names) - limit} more"


def refuses_role_save(roles, name, permissions, actor, groups=None,
                      user_roles=None, default_role=None):
    """Why this role must not be saved as asked, or None.

    Two separate rules, and the order matters. "Nobody would be left able to
    administer" is a property of the system; "you would lock yourself out" is a
    property of the person asking. Reporting the system one first means the
    message says what is actually wrong rather than what it means for you.

    `groups` is the role's group list after the save; None keeps the stored
    one. It is part of the question because a role's groups are how a
    directory principal gets it: taking your own group off the role that makes
    you an administrator locks you out as surely as taking the permission off.
    """
    permissions = list(permissions or [])
    grants_admin = ADMIN_PERMISSION in permissions

    # Existing role losing admin, and it was the last one that had it.
    known = {role["name"]: role for role in roles}
    if name in known and not grants_admin:
        if not _carriers(roles, exclude=name):
            return (f"'{name}' is the only role that can administer WDash. "
                    f"Removing {ADMIN_PERMISSION} from it would leave nobody "
                    f"able to reach this page, and there is no other permission "
                    f"that can recover it. Give another role "
                    f"{ADMIN_PERMISSION} first.")

    # You, in the picture after the save.
    before, _ = _lands_on(roles, user_roles, default_role, actor)
    edited = dict(known.get(name) or {"name": name})
    edited["permissions"] = permissions
    if groups is not None:
        edited["groups"] = list(groups)
    after_roles = [role for role in roles if role["name"] != name] + [edited]
    landed, definition = _lands_on(after_roles, user_roles, default_role, actor)
    if not _administers(definition):
        if landed == name:
            return (f"'{name}' is your own role. Saving it without "
                    f"{ADMIN_PERMISSION} would lock you out of this page "
                    f"immediately. Assign yourself another role first.")
        return (f"'{name}' is how you are an administrator: its groups are "
                f"what gives you '{before}'. Saved like this you would land on "
                f"'{landed}', which cannot administer WDash — that would lock "
                f"you out of this page immediately.")

    return None


def refuses_role_delete(roles, name, actor, default_role=None,
                        user_roles=None, local_accounts=()):
    """Why this role must not be deleted, or None.

    Deleting a role never used to ask who depended on it. The default role
    could go, and so could a role that mappings named, and the configuration
    page then offered its first role — `admin` — in every select that had
    pointed at the one deleted: the next "Save mappings", for whatever
    reason, made those people administrators, or with the default role made
    EVERYBODY unmapped one. Now a role something still points at stays until
    that something points elsewhere.
    """
    if len(roles) <= 1:
        return ("This is the last role. Removing it would leave nobody able "
                "to do anything.")

    if not _carriers(roles, exclude=name):
        return (f"'{name}' is the only role that can administer WDash. "
                f"Deleting it would leave the configuration page unreachable.")

    if default_role and name == default_role:
        return (f"'{name}' is the default role: everybody no mapping names "
                f"gets it. Choose another default role under \"Who gets which "
                f"role\" first.")

    mapped = [who for who, role in (user_roles or {}).items() if role == name]
    if mapped:
        return (f"These mappings still give '{name}': {few(mapped)}. Map them "
                f"to another role, or remove them, first.")

    # You before the local accounts: when the account holding it is yours,
    # "you would lock yourself out" is the sentence that says what happens.
    after_roles = [role for role in roles if role["name"] != name]
    before, _ = _lands_on(roles, user_roles, default_role, actor)
    landed, definition = _lands_on(after_roles, user_roles, default_role, actor)
    if before == name and not _administers(definition):
        return (f"'{name}' is your own role. Removing it would lock you out "
                f"of this page — assign yourself another role first.")

    holders = [account.get("username") for account in local_accounts or ()
               if account.get("role") == name and not account.get("disabled")]
    if holders:
        return (f"The local account {few(holders)} holds '{name}'. A local "
                f"account whose role is gone falls back to the default role, "
                f"which normally cannot administer — and a local account is "
                f"the way back in when the identity provider is not. Move it "
                f"to another role first: python -m wdash.store.recover "
                f"--set-role <username> <role>.")

    return None


def _enabled_administrators(accounts, roles, user_roles, default_role):
    """The local accounts that could sign in AND reach the configuration page.

    Both halves matter. A disabled account holding an administering role is
    not a way back in — `verify()` refuses it before the password is checked
    — and an enabled account whose role cannot administer is not one either.
    Which role an account lands on is asked of the resolver rather than read
    off the row: a stored role that no longer exists falls through to the
    mappings and then to the default, and that fall-through is exactly the
    case where reading the column gives the wrong answer.
    """
    names = []
    for account in accounts or ():
        if account.get("disabled"):
            continue
        _, definition = _lands_on(roles, user_roles, default_role, {
            "email": account.get("email"),
            "username": account.get("username"),
            "local_role": account.get("role")})
        if _administers(definition):
            names.append(account.get("username"))
    return names


def _to_an_account(role, disabled, deleting):
    """What the edit does, as the subject of a sentence."""
    if deleting:
        return "Deleting it"
    parts = []
    if disabled:
        parts.append("disabling it")
    if role is not None:
        parts.append(f"moving it to '{role}'")
    if not parts:
        return "This change"
    return " and ".join(parts).capitalize()


def refuses_account_change(accounts, roles, username, actor, role=None,
                           disabled=None, deleting=False, user_roles=None,
                           default_role=None):
    """Why this change to a local account must not be saved, or None.

    The fifth way to lose administration, and the one an accounts page in the
    product creates: until there was one, a local account could only be made
    by first-run setup or by the recovery tool, and neither can demote,
    disable or delete the account that reaches this page. Now a form can.

    Asked as "what would this edit leave behind?" rather than carried as a
    second copy of the reasoning: the caller hands over the accounts as they
    stand and the edit as it was asked for, and this builds the picture
    AFTER it. `role=None` and `disabled=None` mean "unchanged", which is what
    lets a password reset ask the same question and be told nothing is wrong.

    Two rules, and the order matters for the same reason it does in
    `refuses_role_save`: "nobody would be left able to administer" is a
    property of the system and "you would lock yourself out" is a property of
    the person asking, and when both are true the system one is the sentence
    that says what is actually wrong.

    An installation that ALREADY has no enabled local administrator is not
    refused: the first rule fires on the change that empties the set, not on
    every change made afterwards. Refusing there would make the page unable
    to repair a store somebody had already broken with `--set-role`.
    """
    name = (username or "").strip().lower()

    after = []
    for account in accounts or ():
        if account.get("username") != name:
            after.append(account)
            continue
        if deleting:
            continue
        after.append({**account,
                      "role": account.get("role") if role is None else role,
                      "disabled": (account.get("disabled") if disabled is None
                                   else bool(disabled))})

    what = _to_an_account(role, disabled, deleting)
    had = _enabled_administrators(accounts, roles, user_roles, default_role)
    left = _enabled_administrators(after, roles, user_roles, default_role)

    if had and not left:
        return (f"'{name}' is the only local account that is enabled and can "
                f"administer WDash. {what} would leave nobody able to sign in "
                f"locally and open this page — and a local account is the way "
                f"back in when the identity provider is not. Give another "
                f"local account an administering role first.")

    actor = actor or {}
    mine = ((actor.get("provider") == "local account"
             or actor.get("local_role"))
            and (actor.get("username") or "").strip().lower() == name)
    if mine and name not in left:
        return (f"'{name}' is the account you are signed in with. {what} "
                f"would lock you out of this page immediately, and nothing on "
                f"it can undo that. Ask another administrator, or run "
                f"python -m wdash.store.recover --grant-admin {name}.")

    return None


#: What the session records about the door somebody came through, as the
#: directory it names. Anything else — including a session written before the
#: field existed — is unknown, and is never claimed to be either one.
_ARRIVED = {"directory": "ldap", "oidc": "oidc"}

#: How each directory is named in a sentence. `auth.providers` has the same
#: map; it is not imported here because the recovery tool imports this module
#: and must run when Flask is not importable.
_LABELS = {"ldap": "LDAP", "oidc": "OpenID Connect"}


def refuses_directory_off(which, actor, roles, local_accounts=(),
                          takes_over=None):
    """Why this directory must not be turned off, or None.

    The fourth way to lose administration, and the one the one-directory rule
    creates: with at most one directory signing people in, turning it off
    takes every non-local administrator with it. A local account is unaffected
    — that is what it is for — so the rule is only about the case where there
    is no usable local account left.

    Who is asking matters, and it is READ rather than guessed: a session
    survives a change of directory, so "not a local account" does not mean
    "arrived through this one". An administrator who arrived through the other
    directory is allowed, because turning this one off is exactly how she
    resolves a conflict in her own favour.

    `takes_over` is who the resolution hands the installation to on this very
    save — {"name", "unusable"} or None — and it is the difference between a
    lockout and a SWITCH. On an installation with both directories stored and
    enabled, turning the one in force off is the whole of how an administrator
    resolves the conflict, and it is the only in-page direction that exists:
    enabling the other one is refused by the one-directory rule. Measured
    before this was passed in: both directions refused, and the refusal said
    "nobody would be able to open this page" while LDAP would have taken over
    on that same save.
    """
    actor = actor or {}
    if actor.get("local_role") or actor.get("provider") == "local account":
        return None

    arrived = _ARRIVED.get(actor.get("provider"))
    if arrived is not None and arrived != which:
        return None

    successor = takes_over or {}
    if successor.get("name") and not successor.get("unusable"):
        return None

    carriers = {role["name"] for role in _carriers(roles)}
    accounts = list(local_accounts or ())
    if any(account.get("role") in carriers and not account.get("disabled")
           for account in accounts):
        return None

    label = _LABELS.get(which, which)
    disabled = [account.get("username") for account in accounts
                if account.get("role") in carriers and account.get("disabled")]
    way_back = (
        f"Re-enable one: python -m wdash.store.recover --enable "
        f"{disabled[0]}." if disabled else
        "Give a local account an administering role first: python -m "
        "wdash.store.recover --grant-admin <username>.")
    # What actually happens, rather than one sentence for two situations: an
    # installation whose other directory would take over is not losing its
    # last door, it is being handed to one that does not work.
    what = (f"Turning {label} off would hand this installation to "
            f"{_LABELS.get(successor['name'], successor['name'])}, and its "
            f"saved settings cannot be used: {successor['unusable']}. Nobody "
            f"would be able to open this page"
            if successor.get("name") else
            f"Turning {label} off would leave nobody able to open this page")
    return (f"You did not sign in with a local account, and no local account "
            f"here can administer WDash"
            + (f" ({few(disabled)} could, but is disabled)" if disabled else "")
            + f". {what}, so nothing was saved. {way_back}")


def refuses_mapping_save(roles, default_role, mappings, actor):
    """Why these role mappings must not be saved, or None.

    The mapping table is the third way to lose administration: reassigning the
    only administrator to another role empties the set just as surely as
    editing permissions does, and it is much less obvious that it would.

    A local account needs no exemption of its own: its stored role comes first
    in the resolver's order, so the picture after the save already leaves it
    where it was — which is exactly what makes it the way back in.
    """
    landed, definition = _lands_on(roles, mappings, default_role, actor)
    if not _administers(definition):
        return (f"That would move you to '{landed}', which cannot "
                f"administer WDash — you would lose access to this page. "
                f"Map yourself to a role with {ADMIN_PERMISSION}.")

    return None
