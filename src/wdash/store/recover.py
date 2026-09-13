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
    PYTHONPATH=src python -m wdash.store.recover --reset-totp alice
    PYTHONPATH=src python -m wdash.store.recover --enable alice
    PYTHONPATH=src python -m wdash.store.recover --use-directory ldap

`--reset-totp` is the one a mandatory second factor makes necessary. A local
account cannot sign in without a code, so the operator who is the only
administrator and has lost their phone has no way in at all — the accounts
page that would reset it is behind the sign-in that needs it.

The last two exist because the one-directory rule can be lost from the other
side. WDash signs people in through at most one directory; on an installation
that had both enabled, the one saved most recently wins, and every
administrator at the other one is out. The configuration page cannot help —
nobody can reach it — and a rule whose only way back is SQL is a lockout with
better wording. `--use-directory` writes the enabled flags from here, and
`--enable` undoes a disabled local account, which `--grant-admin` never did.
"""

import argparse
import getpass
import os
import sys

from . import Store
from ..dashboard.invariants import ADMIN_PERMISSION

RECOVERY_ROLE = "recovery-admin"


def _rule():
    """The one-directory rule, imported where it is used.

    Not at module scope: the recovery tool has to run when the application
    does not, and `wdash.auth` pulls in Flask and authlib on the way past.
    """
    from ..auth.providers import LABELS, LDAP_KEY, OIDC_KEY, resolve
    return LABELS, LDAP_KEY, OIDC_KEY, resolve


def _installation(store):
    """Enough of an application for `auth.providers` to answer about.

    It asks one thing of one: `store`. Built here rather than importing the
    app, because this tool exists for the case where the app cannot start,
    and because the alternative is a second copy of "can this directory be
    used", which is the drift the whole package is about.
    """
    class _Installation:
        pass

    installation = _Installation()
    installation.store = store
    return installation


def _directory_line(store):
    """Which directory would sign people in, as one line for --status."""
    labels, ldap_key, oidc_key, resolve = _rule()
    state = resolve(store.settings.all(prefix="auth."))
    if state["in_force"] is None:
        return "Directory: (none — local accounts only)"
    line = f"Directory: {labels[state['in_force']]}"
    if state["shadowed"]:
        line += f"; {labels[state['shadowed']]} is configured and NOT in use"
    return line


def use_directory(store, which):
    """Make one directory — or neither — the one in force.

    Writes only the `enabled` flags, so nothing an administrator typed is
    lost. An absent row is a directory that was never configured, and stays
    absent: nothing else configures one.

    Two things it asks before it writes anything, both learned by measuring
    what it used to do:

      * whether the chosen directory CAN be used, from `why_unusable` — the
        same answer the page and the banner read. It used to ask whether a
        settings ROW existed, so on a blank OIDC card `--use-directory oidc`
        enabled the blank row, disabled the LDAP that worked, and printed
        "OpenID Connect is now the directory in force." Both directories
        were then unusable: every directory user locked out, in a message
        that said it had succeeded.
      * whether a row is a CONFIGURATION or only an off-switch. A row holding
        nothing but `enabled: False` — which an earlier version wrote to turn
        off a provider read from the environment, and which is still in
        databases — is not a directory; treating it as one made this tool
        enable a blank card as the directory in force.
    """
    labels, ldap_key, oidc_key, _ = _rule()
    from ..auth.providers import directory as resolution, why_unusable

    if which not in ("ldap", "oidc", "none"):
        print(f"--use-directory takes ldap, oidc or none, not '{which}'.",
              file=sys.stderr)
        return 1

    stored = {key: store.settings.get(key) for key in (ldap_key, oidc_key)}

    def typed(key):
        """What somebody actually put in the card, `enabled` aside."""
        return {field: value for field, value in (stored[key] or {}).items()
                if field != "enabled" and value not in (None, "")}

    if which != "none" and not typed(ldap_key if which == "ldap" else oidc_key):
        print(f"No {labels[which] if which == 'ldap' else 'OIDC'} settings "
              f"are stored, so {labels[which] if which == 'ldap' else 'OIDC'} "
              f"cannot be put in force. Configure it on the page first.",
              file=sys.stderr)
        return 1

    if which != "none":
        unusable = why_unusable(_installation(store), which, if_enabled=True)
        if unusable:
            print(f"{labels[which]} is configured here but cannot be used as "
                  f"it stands: {unusable}. Putting it in force would leave "
                  f"this installation with no directory sign-in at all, so "
                  f"nothing was changed. Fix it on the configuration page, or "
                  f"choose the other directory.", file=sys.stderr)
            return 1

    for key, name in ((ldap_key, "ldap"), (oidc_key, "oidc")):
        row = stored[key]
        if name == which:
            store.settings.set(key, {**row, "enabled": True},
                               updated_by="recover")
        elif row is not None:
            store.settings.set(key, {**row, "enabled": False},
                               updated_by="recover")

    # Reported from `directory()` — what the sign-in page, the banner and the
    # startup log all read — rather than from the rows this function just
    # wrote, so success is claimed by the thing that decides it.
    state = resolution(_installation(store))
    if state["in_force"] is None:
        print("No directory is in force. Local accounts still sign in.")
    else:
        print(f"{labels[state['in_force']]} is now the directory in force.")
    print("Ownership here is the username: whoever signs in as a name that "
          "already owns dashboards or holds a role mapping gets them.")
    return 0


def enable(store, username, disabled=False):
    """Re-enable (or disable) a local account.

    `--grant-admin` moves an account to an administering role and stops there,
    so a disabled account with the recovery role still cannot sign in —
    `verify()` refuses it before the password is checked. A refusal whose way
    out cannot be taken is a lockout with better wording.
    """
    account = store.users.by_username(username)
    if account is None:
        print(f"No local account called '{username}'.", file=sys.stderr)
        print("Existing accounts: "
              + ", ".join(a["username"] for a in store.users.all()),
              file=sys.stderr)
        return 1
    store.users.set_disabled(username, disabled)
    print(f"'{account['username']}' is now "
          f"{'disabled' if disabled else 'enabled'}.")
    if not disabled and account["role"] not in [
            role["name"] for role in store.roles.all()
            if ADMIN_PERMISSION in (role.get("permissions") or [])]:
        print(f"It holds '{account['role']}', which does NOT grant "
              f"{ADMIN_PERMISSION}. Run --grant-admin {account['username']} "
              f"to make it a way back in to the configuration page.")
    return 0


def status(store):
    roles = store.roles.all()
    carriers = [role["name"] for role in roles
                if ADMIN_PERMISSION in (role.get("permissions") or [])]
    accounts = store.users.all()

    print(f"Store:    {store.describe()}")
    print(_directory_line(store))
    print(f"Roles:    {', '.join(role['name'] for role in roles) or '(none)'}")
    print(f"Can administer: {', '.join(carriers) or '(NOBODY)'}")
    print(f"Local accounts:")
    for account in accounts:
        marker = " [disabled]" if account["disabled"] else ""
        # Whether it has an authenticator, because the answer changes what
        # the next sign-in will ask for — and "not yet" is not a fault: the
        # account enrols at its next sign-in.
        marker += "" if account.get("totp_enrolled") else " [no authenticator]"
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


def reset_totp(store, username):
    """Forget an account's authenticator, so its next sign-in enrols again.

    For the operator who is the only administrator and has lost their phone:
    the accounts page can do this too, and it is behind the sign-in that needs
    the code.

    Says what it costs. Until that account enrols again its password alone
    signs it in, and somebody running this to help a colleague should know
    that before they walk away from the terminal.
    """
    account = store.users.by_username(username)
    if account is None:
        print(f"No local account called '{username}'.", file=sys.stderr)
        print("Existing accounts: "
              + ", ".join(a["username"] for a in store.users.all()),
              file=sys.stderr)
        return 1

    if not account["totp_enrolled"]:
        print(f"'{account['username']}' has no authenticator set up. Its next "
              f"sign-in will set one up.")
        return 0

    store.users.clear_totp(account["username"])
    print(f"The authenticator for '{account['username']}' has been reset.")
    print("Its next sign-in sets up a new one. Until then, the password "
          "alone signs that account in.")
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
    parser.add_argument("--reset-totp", metavar="USERNAME",
                        help="forget an account's authenticator, so its next "
                             "sign-in sets up a new one")
    parser.add_argument("--password", help="for scripted use; prompts otherwise")
    parser.add_argument("--enable", metavar="USERNAME",
                        help="undo a disabled local account")
    parser.add_argument("--disable", metavar="USERNAME")
    parser.add_argument("--use-directory", metavar="WHICH",
                        choices=("ldap", "oidc", "none"),
                        help="ldap, oidc or none: which directory signs "
                             "people in. WDash uses one at a time")
    arguments = parser.parse_args(argv)

    store = Store.open(arguments.database_url)

    if arguments.use_directory:
        return use_directory(store, arguments.use_directory)
    if arguments.enable:
        return enable(store, arguments.enable)
    if arguments.disable:
        return enable(store, arguments.disable, disabled=True)
    if arguments.grant_admin:
        return grant_admin(store, arguments.grant_admin)
    if arguments.set_role:
        return set_role(store, *arguments.set_role)
    if arguments.reset_password:
        return reset_password(store, arguments.reset_password,
                              arguments.password)
    if arguments.reset_totp:
        return reset_totp(store, arguments.reset_totp)
    return status(store)


if __name__ == "__main__":
    sys.exit(main())
