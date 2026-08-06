"""
Scope — the authorization boundary every query must carry.

Why it is a required parameter
------------------------------
Elasticsearch's Basic licence has NO document- or field-level security. All
authorization therefore lives in the application, and WDash has to be the only
door to the cluster. In a design like that the most dangerous failure is
someone forgetting to filter.

So Scope is a required parameter on every source method. A query CANNOT be
built without one — forgetting it is a call error rather than a silent data
leak. We do not leave this to code review.

Related: the SEC001 advisor rule reminds you that Elasticsearch should only be
reachable from WDash at the network level. If the application layer is the only
gate, it must not be possible to walk around it.
"""

from dataclasses import dataclass, field
from typing import Optional


from .patterns import matches as _matches  # noqa: F401
from .patterns import matches_for_source


@dataclass(frozen=True)
class Scope:
    """What a principal is allowed to reach.

    `containers` maps to index patterns on the log side. `services` is the
    distinction that matters for traces: for logs the meaningful unit is the
    index, for traces it is the service. None means unrestricted.
    """

    principal: str = "anonymous"
    #: Log containers (index patterns)
    containers: tuple = ("*",)
    #: Trace stores. Separate from logs: a role may see logs but not traces,
    #: and trace indices do not match log patterns.
    trace_containers: tuple = ()
    #: Visible services. None = unrestricted, () = none at all.
    services: Optional[tuple] = None
    permissions: frozenset = field(default_factory=frozenset)

    # ---------- constructors ----------

    @classmethod
    def unrestricted(cls, principal="system"):
        """Access to everything. Internal use and tests only."""
        return cls(principal=principal, containers=("*",),
                   trace_containers=("*",), services=None)

    @classmethod
    def nothing(cls, principal="anonymous"):
        """Access to nothing. The safe default."""
        return cls(principal=principal, containers=(),
                   trace_containers=(), services=())

    @classmethod
    def from_user(cls, user):
        """Bridge from models.User to a Scope.

        The difference between an empty list and a missing attribute is
        deliberate:

          - attribute ABSENT -> a legacy User object; do not impose a service
                                restriction, so log behaviour is unchanged
          - attribute EMPTY  -> the operator deliberately granted nothing;
                                access to nothing

        This distinction matters: writing `[] or None` would turn an empty list
        into "unrestricted", the exact opposite of failing closed.
        """
        services_raw = getattr(user, "allowed_services", None)
        trace_raw = getattr(user, "allowed_trace_indices", None)

        return cls(
            principal=getattr(user, "username", "anonymous"),
            containers=tuple(getattr(user, "allowed_indices", None) or ()),
            # Traces are a newer capability: no attribute means no access.
            trace_containers=() if trace_raw is None else tuple(trace_raw),
            services=None if services_raw is None else tuple(services_raw),
            permissions=frozenset(getattr(user, "permissions", None) or ()),
        )

    # ---------- queries ----------

    def allows_container(self, name, source=None):
        """Is this log container permitted?

        `source` lets a role be written per source (`es-logs:app-*`). A bare
        pattern still applies to every source, so no existing role changes
        meaning — qualifying is opt-in precision, not a new requirement.
        """
        return matches_for_source(self.containers, name, source)

    def allows_trace_container(self, name, source=None):
        return matches_for_source(self.trace_containers, name, source)

    def allows_service(self, name):
        if self.services is None:
            return True
        return any(_matches(p, name) for p in self.services)

    def has(self, permission):
        return permission in self.permissions

    @property
    def is_empty(self):
        """No access to any log container?

        Adapters must check this: a query must NOT be issued with an empty
        scope. Sending an empty index list to Elasticsearch means '*' — so a
        user with access to nothing would see everything.
        """
        return not self.containers

    @property
    def trace_is_empty(self):
        """No access to any trace store? The same trap, on the trace side."""
        return not self.trace_containers

    def resolve(self, available, source=None):
        """Filter a list of log containers through the scope.

        Adapters must ALWAYS derive the index list they send to the backend
        from this method. Passing `source` is what makes a source-qualified
        grant take effect; an adapter that omits it simply behaves as before.
        """
        return [name for name in available
                if self.allows_container(name, source)]

    def resolve_traces(self, available, source=None):
        """Filter a list of trace stores through the scope."""
        return [name for name in available
                if self.allows_trace_container(name, source)]

    def filter_services(self, names):
        return [name for name in names if self.allows_service(name)]

    def __str__(self):
        services = "*" if self.services is None else (",".join(self.services) or "-")
        return (f"Scope({self.principal}: "
                f"logs={','.join(self.containers) or '-'} "
                f"traces={','.join(self.trace_containers) or '-'} "
                f"services={services})")


class ScopeViolation(Exception):
    """An access outside the scope was attempted.

    This is a programming error rather than a user error: it means an adapter
    failed to filter correctly.
    """
