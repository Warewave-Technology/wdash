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

from .database import upsert
from .schema import roles

logger = logging.getLogger(__name__)

#: What an installation with no roles is given, so that it is usable before
#: anybody opens the configuration page.
#:
#: The one definition. There were three: this, `config/rbac.yaml`, and the
#: copy of that file in the Kubernetes ConfigMap — and which one an
#: installation got depended on whether a file happened to be where the
#: configuration said it was. Seeding happens once, so whichever it got was
#: the one it kept. They had drifted apart in names, in groups and in
#: boundaries. A test held two of them together; the ConfigMap's copy was
#: held to nothing, and it gave `developer` every service. An installation
#: made from it has that stored, and keeps it: nothing here changes a role
#: that exists.
#:
#: The group names are namespaced, and that is a security choice rather than
#: a preference: a directory almost certainly already has a group called
#: `admins`, it usually means domain administrators, and mapping it to
#: `system:admin` by default hands WDash's highest privilege to whoever is in
#: it.
#:
#: The boundaries are the narrow set. `developer` reaches `app-*`, `service-*`
#: and six application services rather than every log container and every
#: service, and `viewer` reaches one service. `services: None` on `admin` is
#: "no service restriction"; the file wrote `["*"]`, a pattern matching every
#: service, and the scope answers every question the adapters ask of it the
#: same way for both.
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

#: Which claims name a person, when neither the provider's own settings nor
#: the environment name one.
#:
#: Stored with the roles for an installation that has none, and read by
#: `auth.providers` as its last fallback — one object, so what a new
#: installation stores and what one with nothing stored reads cannot drift
#: apart. The values are the `claim_mappings` block `config/rbac.yaml`
#: shipped, which every installation made from this repository has stored.
DEFAULT_CLAIM_MAPPINGS = {
    "email_claim": "email",
    "username_claim": "preferred_username",
    "groups_claim": "groups",
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

    def seed(self, settings_repository):
        """Give an installation with no roles the built-in ones.

        Does nothing once any role exists, so an edit made on the
        configuration page is never overwritten by a restart, and an
        installation that imported its roles from an rbac.yaml at an earlier
        version keeps exactly what it imported.

        A claim mapping already stored is kept. It is the one setting here
        that may predate the roles table being empty — and replacing it is
        the regression that sent an installation whose provider sends
        `memberOf` back to reading `groups`, where every group mapping
        resolves nothing and everybody lands on the default role.
        """
        if self.all():
            return False

        for name, definition in DEFAULT_ROLES.items():
            self.upsert(
                name,
                permissions=definition["permissions"],
                containers=definition["containers"],
                trace_containers=definition["trace_containers"],
                services=definition["services"],
                groups=definition["groups"],
                description=definition["description"])

        settings_repository.set("rbac.default_role", "viewer")
        settings_repository.set("rbac.user_roles", {})
        if settings_repository.get("rbac.claim_mappings") is None:
            settings_repository.set("rbac.claim_mappings",
                                    dict(DEFAULT_CLAIM_MAPPINGS))

        logger.info(f"Seeded the {len(DEFAULT_ROLES)} built-in roles")
        return True
