"""
Tables WDash owns.

Not observability data — WDash's own state: who may sign in, what a role may
reach, which sources are configured, and the dashboards people saved. That
distinction is the whole reason this exists. Dashboards were briefly stored in
Elasticsearch, which was right while Elasticsearch was the only backend and
wrong the moment it became one source among several: a Loki-only deployment
would have nowhere to put them, and a search index is a poor home for a
password hash or a client secret.

Deliberately small and deliberately relational. Two things here genuinely need
a database rather than a document store:

  * uniqueness — exactly one account per username, and exactly one first admin,
    even when two workers process the setup form at the same moment
  * transactions — a role and its boundaries must appear together or not at all

JSON columns carry the shapes that are read back whole and never queried by
their contents (panels, permission lists). Modelling those as tables would buy
joins nobody performs.
"""

from sqlalchemy import (
    Boolean, Column, DateTime, Integer, MetaData, String, Table, Text,
    UniqueConstraint,
)
from sqlalchemy.types import JSON

metadata = MetaData()

#: Bumped by migrations.py. A row, not a file, so it travels with the data.
schema_version = Table(
    "wdash_schema_version", metadata,
    Column("version", Integer, primary_key=True),
    Column("applied_at", DateTime(timezone=True), nullable=False),
)

#: Local accounts. OIDC and LDAP users are NOT stored here — they are
#: authenticated elsewhere and their role is resolved per request. This table
#: holds the break-glass admin created at first run, which must keep working
#: when the identity provider does not.
users = Table(
    "wdash_users", metadata,
    Column("id", String(64), primary_key=True),
    Column("username", String(255), nullable=False),
    Column("email", String(255)),
    # Argon2. Never a reversible form: WDash must be unable to reveal it.
    Column("password_hash", Text, nullable=False),
    Column("role", String(64), nullable=False),
    Column("disabled", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("last_login_at", DateTime(timezone=True)),
    # Case-insensitive uniqueness is enforced by storing the username folded;
    # see users repository. The constraint is what makes the first-run race
    # safe rather than merely unlikely.
    UniqueConstraint("username", name="uq_wdash_users_username"),
)

#: Roles and their boundaries — what config/rbac.yaml used to hold.
#:
#: The three boundaries stay independent, as they are in the file: a role may
#: read logs without reaching traces, and may reach a trace store without being
#: allowed to see every service in it.
roles = Table(
    "wdash_roles", metadata,
    Column("name", String(64), primary_key=True),
    Column("description", Text),
    Column("permissions", JSON, nullable=False),
    Column("containers", JSON, nullable=False),         # log index patterns
    Column("trace_containers", JSON, nullable=False),
    Column("services", JSON),                           # null = unrestricted
    # Which identity-provider groups map onto this role.
    Column("groups", JSON, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

#: Configured data sources. `config` carries whatever the adapter needs; the
#: parts that are secret live in `secrets` and are encrypted.
sources = Table(
    "wdash_sources", metadata,
    Column("id", String(64), primary_key=True),
    Column("name", String(128), nullable=False),
    #: Legacy. One row used to mean one signal, so an Elasticsearch cluster
    #: holding both logs and traces needed two entries — two sets of
    #: credentials to rotate, two `verify_certs` that could drift apart, and
    #: two health rows for one system. Still written because the column is NOT
    #: NULL and dropping a column is not a migration worth the risk; never
    #: read. `signals` is the answer.
    Column("signal", String(16), nullable=False),
    #: Which signals this one source serves: ["logs"], ["traces"] or both.
    Column("signals", JSON),
    Column("kind", String(32), nullable=False),         # elasticsearch | loki | ...
    Column("config", JSON, nullable=False),
    Column("secrets", Text),                            # encrypted blob, or null
    Column("enabled", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    #: The name alone. It used to be (name, signal), which let two rows share
    #: a name — the very duplication `signals` removes.
    UniqueConstraint("name", "signal", name="uq_wdash_sources_name"),
)

#: Application settings: OIDC, LDAP, and anything else the config page edits.
#: One row per key so a concurrent edit to OIDC cannot clobber an edit to LDAP.
settings = Table(
    "wdash_settings", metadata,
    Column("key", String(128), primary_key=True),
    Column("value", JSON),
    Column("secret_value", Text),                       # encrypted, or null
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("updated_by", String(255)),
)

dashboards = Table(
    "wdash_dashboards", metadata,
    Column("id", String(64), primary_key=True),
    Column("name", String(255), nullable=False),
    Column("description", Text),
    Column("query", Text, nullable=False),
    Column("created_by", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("containers", JSON, nullable=False),         # was index_patterns
    Column("panels", JSON),
    Column("thresholds", JSON),
    # Which source answers this dashboard. Null means the default, so every
    # dashboard stored before there was more than one keeps working.
    Column("source", String(128)),
    #: shared | private. See dashboard/visibility.py.
    Column("visibility", String(16), nullable=False, default="shared",
           server_default="shared"),
    # Optimistic concurrency: two people editing the same dashboard is the one
    # case where last-write-wins loses work somebody is actively doing.
    Column("revision", Integer, nullable=False, default=1),
)

saved_searches = Table(
    "wdash_saved_searches", metadata,
    Column("id", String(64), primary_key=True),
    Column("name", String(255), nullable=False),
    Column("query", Text, nullable=False),
    Column("time_range", String(32), nullable=False),
    Column("created_by", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("source", String(128)),
    Column("revision", Integer, nullable=False, default=1),
)


#: Who changed what, in the authorization configuration.
#:
#: Logging said a change happened; it could not answer "what could this role
#: see last Tuesday". That question comes up exactly once — after something has
#: gone wrong — and by then the log has rotated and the current state is the
#: only state anybody can see.
#:
#: Deliberately append-only and deliberately not deletable from the UI: an
#: audit trail an administrator can edit is not one.
audit = Table(
    "wdash_audit", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("at", DateTime(timezone=True), nullable=False, index=True),
    Column("actor", String(255), nullable=False),
    Column("action", String(64), nullable=False),
    Column("subject", String(255)),
    #: Where the actor was. A column rather than a key inside `state`, because
    #: "everything from this address" is a question somebody asks during an
    #: incident, and it should not need a JSON scan to answer.
    Column("address", String(64)),
    #: The whole object as it was left. Storing the new state rather than a
    #: diff means one row answers "what was it then" without replaying history.
    Column("state", JSON),
    #: When this row reached the configured external destination, if there is
    #: one. Null means "still waiting", which is what makes the table its own
    #: queue: point WDash at a Splunk instance today and everything from before
    #: today goes too. Indexed because the sweep asks for exactly this.
    Column("forwarded_at", DateTime(timezone=True), index=True),
)


#: Every sign-in attempt, successful or not.
#:
#: Rate limiting needs history, and history of authentication attempts is
#: itself something an administrator has to be able to look at — "when did this
#: account start failing, and from where" is the first question after a
#: suspected compromise. One table answers both.
#:
#: Deliberately separate from `wdash_audit`: attempts are high-volume and get
#: pruned, and mixing a pruned table into an append-only trail makes the trail
#: something less than append-only.
signin_attempts = Table(
    "wdash_signin_attempts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("at", DateTime(timezone=True), nullable=False, index=True),
    #: Lowercased. Stored even when no such account exists — a burst of
    #: attempts against names that were never real is the clearest signal
    #: there is, and dropping them loses it.
    Column("username", String(255), nullable=False, index=True),
    #: Best available client address. See `client_address` for what "best"
    #: means and why it is not simply REMOTE_ADDR.
    Column("address", String(64), nullable=False, index=True),
    #: 'success', 'failure' or 'locked' — a refused attempt while locked out
    #: is worth keeping, because it says the pressure is still on.
    Column("outcome", String(16), nullable=False),
)
