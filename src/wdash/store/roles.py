"""
Roles and their boundaries — what config/rbac.yaml used to hold.

Moving this into the database is what makes the config page possible, and it
carries one consequence worth stating plainly: permissions are currently baked
into the session cookie at sign-in, so an edit here does not reach anyone until
they sign in again. An administrator who revokes access and watches it not
happen has been given a dangerous illusion. `auth` must resolve the role per
request before the config page ships.

The three boundaries stay independent, exactly as they were in the file: a role
may read logs without reaching traces, and may reach a trace store without
being allowed to see every service inside it.

Fail closed remains the rule. A boundary that is not declared grants nothing.
"""

import logging
import os
from datetime import datetime, timezone

from sqlalchemy import select

from .database import upsert
from .schema import roles

logger = logging.getLogger(__name__)

#: Shipped so a fresh installation is usable before anyone opens the config
#: page. Mirrors the roles config/rbac.yaml has always contained.
#: What a fresh installation gets when there is no `config/rbac.yaml` to
#: import from.
#:
#: These used to disagree with that file, and which world you landed in
#: depended on whether it happened to be present: this named the roles admin,
#: EDITOR and viewer with the groups `wdash-*`, while the file named them
#: admin, DEVELOPER and viewer with the groups `admins`, `developers` and
#: `viewers`. Two answers to "what roles does a fresh install have", and the
#: seeding runs once, so whichever you got was the one you kept.
#:
#: One vocabulary now, taking the better half of each. The role names come
#: from the file, because that is what a fresh clone of this repository has
#: always produced. The group names come from here, and that is a security
#: choice rather than a preference: a directory almost certainly already has
#: a group called `admins`, it usually means domain administrators, and
#: mapping it to `system:admin` by default hands WDash's highest privilege to
#: whoever is in it.
#:
#: The BOUNDARIES come from the file too, and that is the same kind of choice.
#: They had drifted the other way from the names: this gave `developer` every
#: log container and every service while the file gave it `app-*`, `service-*`
#: and six application services, and this gave `viewer` every service while
#: the file gave it one. So an installation that found no file — a pip install
#: run outside the repository, a renamed ConfigMap key, a mount that is not
#: there yet — seeded the WIDER set, and seeding runs once, so those
#: boundaries stayed. Where the two spellings differ without differing in
#: meaning they are left alone: `services: None` is "no service restriction"
#: and the file's `["*"]` is a pattern that matches every service, which come
#: to the same thing, and the test that compares the two sets treats them as
#: equal rather than demanding one spelling.
DEFAULT_ROLES = {
    "admin": {
        "description": "Full access, including cluster tools and others' dashboards.",
        "permissions": ["logs:read", "traces:read", "monitors:read",
                        "dashboard:view", "dashboard:create", "dashboard:edit",
                        "dashboard:delete", "system:admin"],
        "containers": ["*"],
        "trace_containers": ["*"],
        "services": None,
        "groups": ["wdash-admins"],
    },
    "developer": {
        "description": "Can build dashboards, cannot administer the system.",
        "permissions": ["logs:read", "traces:read", "monitors:read",
                        "dashboard:view", "dashboard:create", "dashboard:edit"],
        "containers": ["app-*", "service-*"],
        "trace_containers": ["*"],
        # Application services are visible; infrastructure spans (postgres,
        # redis, elasticsearch, stripe-api) are not.
        "services": ["api-gateway", "auth-*", "payment-*", "user-*",
                     "search-*", "notification-*"],
        "groups": ["wdash-developers"],
    },
    "viewer": {
        "description": "Read-only.",
        # `traces:read` is here because the file's viewer has always had it,
        # and because this definition already declared trace containers — a
        # boundary drawn around a permission the role did not hold, which is
        # what an omission looks like rather than a decision.
        "permissions": ["logs:read", "traces:read", "dashboard:view"],
        "containers": ["app-*"],
        "trace_containers": ["*"],
        "services": ["api-gateway"],
        "groups": ["wdash-viewers"],
    },
}


class RoleRepository:
    def __init__(self, engine):
        self._engine = engine

    def all(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(roles).order_by(roles.c.name)).mappings().all()
        return [dict(row) for row in rows]

    def get(self, name):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(roles).where(roles.c.name == name)).mappings().first()
        return dict(row) if row else None

    def as_config(self):
        """The shape models.User already understands.

        Returning the old file's structure keeps the change to one layer: the
        RBAC consumer does not need to learn that its source moved.
        """
        return {"roles": {
            role["name"]: {
                "permissions": role["permissions"] or [],
                "indices": role["containers"] or [],
                "trace_indices": role["trace_containers"] or [],
                "services": role["services"],
                "groups": role["groups"] or [],
            }
            for role in self.all()
        }}

    def upsert(self, name, permissions, containers, trace_containers,
               services=None, groups=None, description=None):
        record = {
            "description": description,
            "permissions": list(permissions or []),
            "containers": list(containers or []),
            "trace_containers": list(trace_containers or []),
            "services": list(services) if services is not None else None,
            "groups": list(groups or []),
            "updated_at": datetime.now(timezone.utc),
        }
        with self._engine.begin() as connection:
            upsert(connection, roles, {"name": name}, record)
        return dict(record, name=name)

    def delete(self, name):
        with self._engine.begin() as connection:
            result = connection.execute(roles.delete().where(roles.c.name == name))
        return result.rowcount > 0

    def seed(self, from_file=None, settings_repository=None):
        """Populate an empty installation, importing rbac.yaml if it is there.

        Config now lives in the database, but an existing deployment has its
        roles in a file and must not lose them silently on upgrade. This runs
        ONCE, when the table is empty: after that the file is ignored, so an
        edit made in the UI is never quietly overwritten on the next restart.

        The whole file is imported, not just the `roles:` block. An earlier
        version took the roles and dropped `group_roles`, `user_roles` and
        `default_role` — so every principal would have fallen through to the
        default and the entire organisation would have been quietly demoted to
        viewer on upgrade. Losing a mapping is losing access control.
        """
        if self.all():
            return False

        parsed = _read_rbac_file(from_file) if from_file else None
        # `_read_rbac_file` returns either None or a file with a non-empty
        # `roles` mapping, so this is one source or the other and never half
        # of each. It used to be able to be half: a file whose `roles:` block
        # was empty was still "parsed", so the built-in roles were seeded
        # while the file's group_roles, user_roles and default_role were
        # applied on top of them and the log named the file as the source.
        roles_source = parsed["roles"] if parsed else DEFAULT_ROLES

        if parsed:
            _warn_about_unknown_roles(from_file, parsed, roles_source)

        # The file maps group -> role; this table stores groups per role, so
        # the mapping is inverted on the way in.
        groups_for = {}
        for group, role in ((parsed or {}).get("group_roles") or {}).items():
            groups_for.setdefault(role, []).append(group)

        for name, definition in roles_source.items():
            self.upsert(
                name,
                permissions=definition.get("permissions"),
                containers=definition.get("indices", definition.get("containers")),
                trace_containers=definition.get(
                    "trace_indices", definition.get("trace_containers")),
                services=definition.get("services"),
                groups=groups_for.get(name, definition.get("groups")),
                description=definition.get("description"))

        if settings_repository is not None:
            settings_repository.set(
                "rbac.default_role", (parsed or {}).get("default_role", "viewer"))
            settings_repository.set(
                "rbac.user_roles", (parsed or {}).get("user_roles") or {})

        logger.info(
            f"Seeded {len(roles_source)} roles from "
            f"{os.path.abspath(from_file) if parsed else 'built-in defaults'}")
        return True


def _warn_about_unknown_roles(path, parsed, roles_source):
    """Say which of the file's mappings point at a role it does not define.

    A group mapped to an undefined role is dropped outright: the inversion
    above can only attach groups to a role that is being seeded, so
    `corp-devs: developers` against a file whose roles are `ops` and `viewer`
    left `corp-devs` mapped to nothing. A user or a default mapped to one is
    stored as written and resolves to a role that is not there, which is no
    permissions at all. Both were silent, and seeding runs once, so both
    stayed. Warnings rather than a refusal: the rest of the file is usable
    and an administrator can repair a mapping on the roles page, which they
    cannot do if the installation will not start.
    """
    known = set(roles_source)
    where = os.path.abspath(path)

    for group, role in (parsed.get("group_roles") or {}).items():
        if role not in known:
            logger.warning(
                f"{where} maps the group '{group}' to '{role}', which it "
                f"does not define. That group grants nothing.")
    for person, role in (parsed.get("user_roles") or {}).items():
        if role not in known:
            logger.warning(
                f"{where} maps '{person}' to '{role}', which it does not "
                f"define. That person falls through to the default role.")

    default_role = parsed.get("default_role")
    if default_role is None:
        # 'viewer' is the fallback this code supplies, not a name the file
        # gave: reported as "<path> names 'viewer' as the default role", it
        # sent an operator to the file to find a `default_role: viewer` line
        # that is not in it. The alarm is the same — everybody with no
        # mapping of their own gets nothing — and the repair is different.
        if "viewer" not in known:
            logger.warning(
                f"{where} names no default_role, so the built-in default "
                f"'viewer' is used — and this file does not define a role "
                f"called 'viewer'. Everybody with no mapping of their own "
                f"gets no permissions at all. Name a default_role this file "
                f"defines, or define viewer.")
    elif default_role not in known:
        logger.warning(
            f"{where} names '{default_role}' as the default role and does "
            f"not define it. Everybody with no mapping of their own gets no "
            f"permissions at all.")


def import_claims(from_file, settings_repository):
    """rbac.yaml's `claim_mappings`, for an installation that has none stored.

    Not part of `seed`, which runs only on an empty installation: an
    installation seeded before the block was read never got it, so its
    operator's `groups_claim: roles` was still ignored after the upgrade
    that said it no longer would be. Imported on its own, the first time a
    start finds none stored; after that, as with the rest of the file, the
    file does not overwrite what is stored.
    """
    if settings_repository is None or from_file is None:
        return False
    if settings_repository.get("rbac.claim_mappings") is not None:
        return False
    # The parsed document, not `_read_rbac_file`: that one answers "can this
    # file's roles be seeded from", and these mappings name the claims an
    # identity provider sends, which has nothing to do with roles. Read
    # through the stricter question, a file whose `roles` block was empty or
    # mis-indented lost its claim_mappings too — so an installation whose
    # provider sends `memberOf` went back to reading `groups`, every group
    # mapping resolved nothing, and everybody fell to the default role.
    #
    # Quietly: `seed` has already said whatever there is to say about this
    # file, and it says it in terms of seeding — which is not what is
    # happening here, and on a start after the first is not happening at all.
    mappings = (_parse_rbac_file(from_file, report=False)
                or {}).get("claim_mappings")
    if not mappings:
        return False
    settings_repository.set("rbac.claim_mappings", dict(mappings))
    logger.info(f"Imported claim_mappings from {from_file}")
    return True


def _parse_rbac_file(path, report=True):
    """The document, or None when the file itself cannot be read at all.

    Separate from the `roles` question below, because they are two questions
    and one caller asks only this one: `import_claims` wants the claim names
    an identity provider sends, which a file with an unusable `roles` block
    carries perfectly well.

    Every way of returning None says so, with the absolute path. Two of them
    used to be silent, and they are the two that happen: a file that is not
    where the configuration says it is (a renamed ConfigMap key, a mount path
    that moved, a pip install run outside the repository), and a file that is
    not a mapping of blocks at all.

    Not fatal, deliberately: falling back leaves an installation somebody can
    sign in to and repair. It is loud instead. `report=False` is for the
    caller that reads the same file again for its `claim_mappings`, so one
    unusable file does not produce two of every line.
    """
    where = os.path.abspath(path)
    try:
        import yaml
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except FileNotFoundError:
        if report:
            logger.warning(
                f"No RBAC file at {where}. The built-in default roles are "
                f"being seeded instead, and no group, user or default-role "
                f"mapping is applied. Seeding happens once: fix the path "
                f"before the first start, or edit the roles on the "
                f"configuration page afterwards.")
        return None
    except Exception as exc:
        if report:
            logger.error(
                f"Could not import {where}, using default roles: {exc}")
        return None

    if not isinstance(data, dict):
        if report:
            logger.error(
                f"{where} is a {type(data).__name__}, not a mapping of "
                f"blocks, so it declares no roles. The built-in default "
                f"roles are being seeded instead and nothing in this file "
                f"is applied.")
        return None
    return data


def _read_rbac_file(path, report=True):
    """The document when its `roles` block can be seeded from, else None.

    A `roles` block that is mis-indented, misnamed — `role:` — or empty was
    silent, and the last of the three was worse than silent: it parsed, so
    the built-in roles were seeded while the file's own group_roles,
    user_roles and default_role were applied on top of them. Seeding runs
    once, so what was dropped stayed dropped.
    """
    data = _parse_rbac_file(path, report)
    if data is None:
        return None

    where = os.path.abspath(path)
    block = data.get("roles")
    if not isinstance(block, dict) or not block:
        if report:
            logger.error(
                f"{where} defines no roles: `roles` is "
                f"{_describe(block)}. The built-in default roles are being "
                f"seeded instead, and this file's group_roles, user_roles "
                f"and default_role are NOT applied either — importing the "
                f"mappings from one place and the roles they name from "
                f"another is how a group ends up pointing at a role nobody "
                f"wrote. Its claim_mappings, which name claims and not "
                f"roles, are still read.")
        return None
    return data


def _describe(block):
    if block is None:
        return "missing"
    if isinstance(block, dict):
        return "an empty mapping"
    return f"a {type(block).__name__}, not a mapping"
