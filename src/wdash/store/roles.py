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
from datetime import datetime, timezone

from sqlalchemy import select

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
        "containers": ["*"],
        "trace_containers": ["*"],
        "services": None,
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
        "services": None,
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
            existing = connection.execute(
                select(roles.c.name).where(roles.c.name == name)).first()
            if existing:
                connection.execute(
                    roles.update().where(roles.c.name == name).values(**record))
            else:
                connection.execute(roles.insert().values(name=name, **record))
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
        roles_source = (parsed or {}).get("roles") or DEFAULT_ROLES

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
            f"{from_file if parsed else 'built-in defaults'}")
        return True


def _read_rbac_file(path):
    """Read the legacy YAML, returning None if it is absent or unreadable."""
    try:
        import yaml
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return None
    except Exception as exc:
        # Not fatal: falling back to defaults leaves a usable installation,
        # and an admin can fix the roles in the UI.
        logger.error(f"Could not import {path}, using default roles: {exc}")
        return None

    if not isinstance(data, dict) or not isinstance(data.get("roles"), dict):
        return None
    return data
