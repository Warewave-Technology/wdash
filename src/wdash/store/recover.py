"""
Getting back in.

The invariants in `dashboard/invariants.py` are meant to make administrative
lockout impossible. This exists because "impossible" is a claim about code that
has been reasoned about, and the cost of being wrong is an installation nobody
can configure. A recovery path that does not depend on the thing being
recovered is cheap; needing one and not having it is not.

Requires access to the database, which is the correct bar: whoever can read the
metadata store can already do this by hand, so this only saves them from
writing SQL under pressure.

    PYTHONPATH=src python -m wdash.store.recover --status
    PYTHONPATH=src python -m wdash.store.recover --grant-admin alice
    PYTHONPATH=src python -m wdash.store.recover --set-role alice admin
    PYTHONPATH=src python -m wdash.store.recover --reset-password alice
"""

import argparse
import getpass
import os
import sys

from . import Store
from ..dashboard.invariants import ADMIN_PERMISSION

RECOVERY_ROLE = "recovery-admin"


def status(store):
    roles = store.roles.all()
    carriers = [role["name"] for role in roles
                if ADMIN_PERMISSION in (role.get("permissions") or [])]
    accounts = store.users.all()

    print(f"Store:    {store.describe()}")
    print(f"Roles:    {', '.join(role['name'] for role in roles) or '(none)'}")
    print(f"Can administer: {', '.join(carriers) or '(NOBODY)'}")
    print(f"Local accounts:")
    for account in accounts:
        marker = " [disabled]" if account["disabled"] else ""
        reachable = account["role"] in carriers
        print(f"  {account['username']} -> {account['role']}"
              f"{marker}{'' if reachable else '   (cannot administer)'}")

    if not carriers:
        print("\nNo role grants administration. Run --grant-admin <username>.")
    return 0


def grant_admin(store, username):
    """Give one account a role that can administer, creating it if needed.

    A dedicated role rather than editing an existing one: repairing a system
    should not also change what everybody else can do.
    """
    account = store.users.by_username(username)
    if account is None:
        print(f"No local account called '{username}'.", file=sys.stderr)
        print("Existing accounts: "
              + ", ".join(a["username"] for a in store.users.all()),
              file=sys.stderr)
        return 1

    existing = store.roles.get(RECOVERY_ROLE)
    permissions = sorted(set((existing or {}).get("permissions") or []) |
                         {ADMIN_PERMISSION})
    store.roles.upsert(
        RECOVERY_ROLE, permissions=permissions,
        containers=(existing or {}).get("containers") or [],
        trace_containers=(existing or {}).get("trace_containers") or [],
        services=None, groups=(existing or {}).get("groups") or [],
        description="Created by the recovery tool.")

    with store.engine.begin() as connection:
        from .schema import users
        connection.execute(users.update()
                           .where(users.c.username == account["username"])
                           .values(role=RECOVERY_ROLE))

    store.rbac.invalidate()
    print(f"'{username}' now holds '{RECOVERY_ROLE}', which grants "
          f"{ADMIN_PERMISSION}.")
    print("Sign in and repair the roles from /admin/config.")
    print("The recovery role grants NO log or trace access; that is "
          "deliberate — it exists to reach the configuration page, not to "
          "read data.")
    return 0


def set_role(store, username, role):
    """Put one local account on a role that already exists.

    The configuration page refuses to delete a role a local account holds,
    and has no control for a local account's role — so this is the one way to
    move the account first. `--grant-admin` could not stand in for it: it
    always moves the account to `recovery-admin`, which left that role, once
    created, impossible to delete from the page.
    """
    account = store.users.by_username(username)
    if account is None:
        print(f"No local account called '{username}'.", file=sys.stderr)
        return 1
    definition = store.roles.get(role)
    if definition is None:
        print(f"No role called '{role}'. Roles: "
              + ", ".join(r["name"] for r in store.roles.all()),
              file=sys.stderr)
        return 1

    with store.engine.begin() as connection:
        from .schema import users
        connection.execute(users.update()
                           .where(users.c.username == account["username"])
                           .values(role=role))

    store.rbac.invalidate()
    administers = ADMIN_PERMISSION in (definition.get("permissions") or [])
    print(f"'{account['username']}' now holds '{role}'."
          + ("" if administers else
             f" It does NOT grant {ADMIN_PERMISSION}: this account is no "
             f"longer a way back in to the configuration page."))
    return 0


def reset_password(store, username, password=None):
    account = store.users.by_username(username)
    if account is None:
        print(f"No local account called '{username}'.", file=sys.stderr)
        return 1

    if password is None:
        password = getpass.getpass("New password: ")
        if password != getpass.getpass("Confirm: "):
            print("The two passwords do not match.", file=sys.stderr)
            return 1

    try:
        store.users.set_password(username, password)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Password for '{username}' reset.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--status", action="store_true",
                        help="who can administer, and who cannot")
    parser.add_argument("--grant-admin", metavar="USERNAME")
    parser.add_argument("--set-role", nargs=2, metavar=("USERNAME", "ROLE"),
                        help="move a local account to an existing role")
    parser.add_argument("--reset-password", metavar="USERNAME")
    parser.add_argument("--password", help="for scripted use; prompts otherwise")
    arguments = parser.parse_args(argv)

    store = Store.open(arguments.database_url)

    if arguments.grant_admin:
        return grant_admin(store, arguments.grant_admin)
    if arguments.set_role:
        return set_role(store, *arguments.set_role)
    if arguments.reset_password:
        return reset_password(store, arguments.reset_password,
                              arguments.password)
    return status(store)


if __name__ == "__main__":
    sys.exit(main())
