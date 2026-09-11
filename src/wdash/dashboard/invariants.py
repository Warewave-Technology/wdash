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


def _few(names, limit=5):
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
        return (f"These mappings still give '{name}': {_few(mapped)}. Map them "
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
        return (f"The local account {_few(holders)} holds '{name}'. A local "
                f"account whose role is gone falls back to the default role, "
                f"which normally cannot administer — and a local account is "
                f"the way back in when the identity provider is not. Move it "
                f"to another role first: python -m wdash.store.recover "
                f"--set-role <username> <role>.")

    return None


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
