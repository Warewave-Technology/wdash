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
"""

ADMIN_PERMISSION = "system:admin"


def _carriers(roles, exclude=None):
    """Roles that grant administration, ignoring one by name."""
    return [role for role in roles
            if role["name"] != exclude
            and ADMIN_PERMISSION in (role.get("permissions") or [])]


def refuses_role_save(roles, name, permissions, actor_role):
    """Why this role must not be saved as asked, or None.

    Two separate rules, and the order matters. "Nobody would be left able to
    administer" is a property of the system; "you would lock yourself out" is a
    property of the person asking. Reporting the system one first means the
    message says what is actually wrong rather than what it means for you.
    """
    permissions = list(permissions or [])
    grants_admin = ADMIN_PERMISSION in permissions

    # Existing role losing admin, and it was the last one that had it.
    known = {role["name"] for role in roles}
    if name in known and not grants_admin:
        if not _carriers(roles, exclude=name):
            return (f"'{name}' is the only role that can administer WDash. "
                    f"Removing {ADMIN_PERMISSION} from it would leave nobody "
                    f"able to reach this page, and there is no other permission "
                    f"that can recover it. Give another role "
                    f"{ADMIN_PERMISSION} first.")

    # Your own role, losing the permission you are using right now.
    if name == actor_role and not grants_admin:
        return (f"'{name}' is your own role. Saving it without "
                f"{ADMIN_PERMISSION} would lock you out of this page "
                f"immediately. Assign yourself another role first.")

    return None


def refuses_role_delete(roles, name, actor_role):
    """Why this role must not be deleted, or None."""
    if len(roles) <= 1:
        return ("This is the last role. Removing it would leave nobody able "
                "to do anything.")

    if not _carriers(roles, exclude=name):
        return (f"'{name}' is the only role that can administer WDash. "
                f"Deleting it would leave the configuration page unreachable.")

    if name == actor_role:
        return (f"'{name}' is your own role. Removing it would lock you out "
                f"of this page — assign yourself another role first.")

    return None


def refuses_mapping_save(roles, default_role, mappings, actor_role,
                         actor_identifiers=(), actor_local_role=None):
    """Why these role mappings must not be saved, or None.

    The mapping table is the third way to lose administration: reassigning the
    only administrator to another role empties the set just as surely as
    editing permissions does, and it is much less obvious that it would.

    A local account is exempt, and deliberately so: its role is stored with the
    account and beats every mapping, which is exactly what makes it the way
    back in. Refusing the change for somebody these mappings cannot move would
    block an ordinary edit for no reason.
    """
    by_name = {role["name"]: role for role in roles}

    if actor_local_role and actor_local_role in by_name:
        return None

    reassigned = None
    for identifier in actor_identifiers:
        if identifier and identifier in mappings:
            reassigned = mappings[identifier]
            break
    if reassigned is None:
        reassigned = default_role if default_role else actor_role

    target = by_name.get(reassigned)
    if target is not None and ADMIN_PERMISSION not in (target.get("permissions") or []):
        return (f"That would move you to '{reassigned}', which cannot "
                f"administer WDash — you would lose access to this page. "
                f"Map yourself to a role with {ADMIN_PERMISSION}.")

    return None
