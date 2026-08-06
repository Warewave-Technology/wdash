"""
WDash's own state.

Separate from the hub on purpose. The hub reads observability signals from
whatever backends are configured; this holds what WDash itself knows — who may
sign in, what a role may reach, which sources exist, and the dashboards people
saved. Coupling the two is what made dashboards-in-Elasticsearch look correct
right up until Elasticsearch became optional.
"""

from .database import DatabaseError, build_engine, describe, is_sqlite
from .migrations import migrate
from .monitoring import AgentRepository, MonitorRepository, ResultRepository
from .objects import (
    DashboardRepository, ObjectConflict, SavedSearchRepository,
)
from .audit import AuditLog
from .signin import SignInGuard
from .rbac import RoleResolver
from .roles import RoleRepository
from .settings_repo import SettingsRepository
from .sources import SourceError, SourceRepository, SOURCE_KINDS
from .secrets import SecretBox, SecretsCorrupt, SecretsUnavailable
from .users import SetupClosed, UserRepository, WeakPassword

__all__ = [
    "build_engine", "describe", "is_sqlite", "migrate", "DatabaseError",
    "UserRepository", "SetupClosed", "WeakPassword",
    "RoleRepository", "RoleResolver", "SettingsRepository", "AuditLog",
    "SourceRepository", "SourceError", "SOURCE_KINDS",
    "DashboardRepository", "SavedSearchRepository", "ObjectConflict",
    "SecretBox", "SecretsUnavailable", "SecretsCorrupt",
]


class Store:
    """Everything WDash persists, behind one object.

    Held on the app so a route reaches `current_app.store.dashboards` rather
    than assembling repositories itself — the same reason the hub exists on the
    reading side.
    """

    def __init__(self, engine, secret_box=None):
        self.engine = engine
        self.secrets = secret_box or SecretBox.from_environment()
        self.users = UserRepository(engine)
        self.roles = RoleRepository(engine)
        self.settings = SettingsRepository(engine, self.secrets)
        self.sources = SourceRepository(engine, self.secrets)
        self.audit = AuditLog(engine)
        self.signin = SignInGuard(engine)
        #: Resolves a principal to a role on every request. See rbac.py for why
        #: this is not done once at sign-in.
        self.rbac = RoleResolver(self.roles, self.settings)
        self.dashboards = DashboardRepository(engine)
        self.saved_searches = SavedSearchRepository(engine)
        #: Checks WDash runs itself, through its own agents. Separate from
        #: `sources`, which is where it reads checks something else ran.
        self.agents = AgentRepository(engine)
        self.monitors = MonitorRepository(engine)
        self.results = ResultRepository(engine)

    @classmethod
    def open(cls, url=None, rbac_file=None, secret_box=None):
        """Build the store, migrate, and seed roles on a fresh installation."""
        engine = build_engine(url)
        migrate(engine)
        store = cls(engine, secret_box)
        store.roles.seed(rbac_file, store.settings)
        return store

    def describe(self):
        return describe(self.engine)

    @property
    def needs_setup(self):
        """No local account yet, so first-run setup is still open."""
        return not self.users.any_exist()
