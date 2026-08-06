"""
Resolving a principal to a role, on every request.

Why not once at sign-in
-----------------------
Permissions used to be written into the session cookie when somebody signed
in. That was survivable while roles lived in a file nobody edited at runtime.
It stops being survivable the moment roles are editable in the UI: an
administrator revokes access, watches the change save, and the person keeps
their access until they happen to sign out. The administrator has been given a
dangerous illusion — the most expensive kind of bug in an authorization system.

So the session now carries IDENTITY only — who you are and which groups the
identity provider asserted. What you may do is resolved from the store on every
request.

The cache
---------
Resolving per request means reading roles per request. A short TTL keeps that
to one query every few seconds per worker, and bounds how long a revocation
takes to reach every process: at most TTL seconds, everywhere, with no
coordination between workers. That is a guarantee that can be written down,
unlike "until they sign in again", which is unbounded.

The cache is deliberately not invalidated across processes. A pub/sub channel
would cut the window to zero and add a dependency whose failure mode is stale
authorization — worse than the thing it fixes.
"""

import logging
import threading
import time

logger = logging.getLogger(__name__)

DEFAULT_TTL = 10.0

#: Used when the store cannot be read at all. Narrow on purpose: a resolver
#: that fails open would turn a database blip into an access-control incident.
FALLBACK = {
    "role": "viewer",
    "permissions": ["logs:read", "dashboard:view"],
    "containers": [],
    "trace_containers": [],
    "services": [],
}


class RoleResolver:
    def __init__(self, roles_repository, settings_repository, ttl=DEFAULT_TTL):
        self._roles = roles_repository
        self._settings = settings_repository
        self._ttl = ttl
        self._lock = threading.Lock()
        self._cached = None
        self._cached_at = 0.0

    # ---------- cache ----------

    def _snapshot(self):
        """Roles and mappings as one consistent picture."""
        now = time.monotonic()
        with self._lock:
            if self._cached is not None and (now - self._cached_at) < self._ttl:
                return self._cached

        try:
            roles = {role["name"]: role for role in self._roles.all()}
            default_role = self._settings.get("rbac.default_role", "viewer")
            user_roles = self._settings.get("rbac.user_roles", {}) or {}
        except Exception:
            # Serve the last good picture rather than locking everyone out over
            # a transient database error; fall back only if there is none.
            with self._lock:
                return self._cached if self._cached is not None else None

        snapshot = {"roles": roles, "default_role": default_role,
                    "user_roles": user_roles}
        with self._lock:
            self._cached = snapshot
            self._cached_at = now
        return snapshot

    def invalidate(self):
        """Drop the cache in THIS process. Other workers expire on their TTL."""
        with self._lock:
            self._cached = None
            self._cached_at = 0.0

    # ---------- resolution ----------

    def role_for(self, email=None, username=None, groups=(), explicit=None):
        """Which role a principal gets.

        `explicit` is the role stored on a local account, which wins: the
        break-glass administrator must not lose access because somebody edited
        a group mapping.
        """
        snapshot = self._snapshot()
        if snapshot is None:
            return FALLBACK["role"]

        if explicit:
            if explicit in snapshot["roles"]:
                return explicit
            # The role was deleted after the account was created. Falling back
            # keeps the person able to sign in and fix it; granting nothing
            # would lock the break-glass account out of the very screen that
            # repairs roles. It is a quiet privilege change either way, so it
            # is logged rather than left to be discovered.
            logger.warning(
                f"Account is assigned role '{explicit}', which no longer "
                f"exists; falling back to the default role")

        mapped = snapshot["user_roles"]
        for identifier in (email, username):
            if identifier and identifier in mapped:
                candidate = mapped[identifier]
                if candidate in snapshot["roles"]:
                    return candidate

        # Group mapping. Sorted so two groups matching two roles resolve the
        # same way every time rather than depending on assertion order.
        for group in sorted(groups or ()):
            for name, definition in sorted(snapshot["roles"].items()):
                if group in (definition.get("groups") or []):
                    return name

        return snapshot["default_role"]

    def resolve(self, email=None, username=None, groups=(), explicit=None):
        """Role plus every boundary, ready to put on a User.

        Fail closed throughout: an unknown role grants nothing rather than
        falling through to something permissive.
        """
        snapshot = self._snapshot()
        if snapshot is None:
            return dict(FALLBACK)

        role = self.role_for(email, username, groups, explicit)
        definition = snapshot["roles"].get(role)
        if definition is None:
            return {"role": role, "permissions": [], "containers": [],
                    "trace_containers": [], "services": []}

        from ..permissions import normalise

        # Retired names are translated on the way out. A stored role written
        # before `logs:search` was folded into `logs:read` must not quietly
        # lose the ability to search on upgrade.
        permissions, _, _ = normalise(definition.get("permissions") or [])

        return {
            "role": role,
            "permissions": permissions,
            "containers": list(definition.get("containers") or []),
            "trace_containers": list(definition.get("trace_containers") or []),
            # None means unrestricted on the trace side; the distinction between
            # None and [] is load-bearing and must survive this hop.
            "services": (list(definition["services"])
                         if definition.get("services") is not None else None),
        }
