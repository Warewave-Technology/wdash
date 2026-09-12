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
    PYTHONPATH=src python -m wdash.store.recover --enable alice
    PYTHONPATH=src python -m wdash.store.recover --use-directory ldap

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

    It asks two things of one: `store`, and `config` for the OIDC variables —
    which the application itself loads straight out of the environment. Built
    here rather than importing the app, because this tool exists for the case
    where the app cannot start, and because the alternative is a second copy
    of "can this directory be used", which is the drift the whole package is
    about.
    """
    class _Installation:
        pass

    installation = _Installation()
    installation.store = store
    installation.config = os.environ
    return installation


def _environment_oidc():
    return bool(os.environ.get("OIDC_CLIENT_ID")
                and os.environ.get("OIDC_DISCOVERY_URL"))


def _directory_line(store):
    """Which directory would sign people in, as one line for --status."""
    labels, ldap_key, oidc_key, resolve = _rule()
    state = resolve(store.settings.all(prefix="auth."), _environment_oidc())
    if state["in_force"] is None:
        return "Directory: (none — local accounts only)"
    where = ("on the page"
             if state["sources"][state["in_force"]] == "configuration"
             else "in the environment")
    line = f"Directory: {labels[state['in_force']]} (configured {where})"
    if state["shadowed"]:
        line += f"; {labels[state['shadowed']]} is configured and NOT in use"
    return line


def use_directory(store, which):
    """Make one directory — or neither — the one in force.

    Writes only the `enabled` flags, so nothing an administrator typed is
    lost. Turning OIDC off means STORING a row that says so: an absent row
    lets the environment configure it, which is the whole reason an
    installation can end up with two directories without anybody enabling a
    second one.

    Two things it asks before it writes anything, both learned by measuring
    what it used to do:

      * whether the chosen directory CAN be used, from `why_unusable` — the
        same answer the page and the banner read. It used to ask whether a
        settings ROW existed, so on the commonest shape of all (a blank OIDC
        card saved to suppress an environment provider) `--use-directory
        oidc` enabled the blank row, disabled the LDAP that worked, and
        printed "OpenID Connect is now the directory in force." Both
        directories were then unusable: every directory user locked out, in a
        message that said it had succeeded.
      * whether a row is a CONFIGURATION or only an off-switch. A row holding
        nothing but `enabled: False` is what turns an environment-configured
        OIDC off; treating it as configuration made this tool one-way, since
        the row it wrote itself then looked like a directory to put in force.
    """
    labels, ldap_key, oidc_key, _ = _rule()
    from ..auth.providers import directory as resolution, why_unusable

    if which not in ("ldap", "oidc", "none"):
        print(f"--use-directory takes ldap, oidc or none, not '{which}'.",
              file=sys.stderr)
        return 1

    environment = _environment_oidc()
    stored = {key: store.settings.get(key) for key in (ldap_key, oidc_key)}

    def typed(key):
        """What somebody actually put in the card, `enabled` aside."""
        return {field: value for field, value in (stored[key] or {}).items()
                if field != "enabled" and value not in (None, "")}

    # Nothing was ever typed into the OIDC card and the environment does
    # configure one: the environment IS the configuration, and any stored row
    # — the off-switch this tool and the page both write — suppresses it.
    # Choosing OIDC therefore means removing that row, which is what lets the
    # tool go back the way it came.
    through_environment = (which == "oidc" and not typed(oidc_key)
                           and environment)

    if which == "ldap" and not typed(ldap_key):
        print("No LDAP settings are stored, so LDAP cannot be put in force. "
              "Configure it on the page first.", file=sys.stderr)
        return 1
    if which == "oidc" and not typed(oidc_key) and not environment:
        print("No OIDC settings are stored and the environment does not "
              "configure one, so OIDC cannot be put in force.", file=sys.stderr)
        return 1

    if which != "none" and not through_environment:
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
            if through_environment:
                store.settings.delete(key)
                continue
            store.settings.set(key, {**row, "enabled": True},
                               updated_by="recover")
        elif row is not None:
            store.settings.set(key, {**row, "enabled": False},
                               updated_by="recover")
        elif name == "oidc" and environment:
            # Nothing stored, but the environment configures one, and turning
            # that off means STORING the row that says so. LDAP has no
            # environment path, so for it an absent row is already off and a
            # written one would be a configuration that never existed —
            # which then defeated this tool's own "not configured" guard.
            store.settings.set(key, {"enabled": False}, updated_by="recover")

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
    return status(store)


if __name__ == "__main__":
    sys.exit(main())
