"""
Shared test helpers.

Authorization is resolved from the metadata store on every request, so a test
can no longer grant itself permissions by writing them into the session. That
is the point: a signed cookie the server wrote is still stale data, and
trusting it is how a revoked role kept working.

`grant` puts a role in the store and maps the test principal onto it, which is
the same path a real deployment takes.
"""

TEST_ROLE = "test-role"


#: Argon2 is deliberately expensive, which is right in production and wrong in
#: a setUp that runs hundreds of times. Hashed once per process; the real
#: hashing path is exercised by tests/test_identity.py.
_CACHED_HASH = None


def claim(app):
    """Complete first-run setup, so the setup gate is open.

    A test exercises a running installation, not an unclaimed one. Without an
    account every route redirects to /setup and every assertion is about the
    setup page rather than the thing under test.
    """
    global _CACHED_HASH

    store = app.store
    if not store.needs_setup:
        return

    from datetime import datetime, timezone

    from wdash.store.schema import users
    from wdash.store.users import SETUP_SENTINEL, hash_password
    from wdash.store.schema import settings

    if _CACHED_HASH is None:
        _CACHED_HASH = hash_password("test-owner-password")

    now = datetime.now(timezone.utc)
    with store.engine.begin() as connection:
        connection.execute(settings.insert().values(
            key=SETUP_SENTINEL, value={"completed_by": "test-owner"},
            updated_at=now, updated_by="test-owner"))
        connection.execute(users.insert().values(
            id="test-owner-id", username="test-owner", email=None,
            password_hash=_CACHED_HASH, role="admin", disabled=False,
            created_at=now, last_login_at=None))


def grant(app, username="u", permissions=(), indices=("*",),
          trace_indices=("*",), services=None):
    """Give the test principal exactly these permissions and boundaries."""
    claim(app)
    store = app.store
    store.roles.upsert(
        TEST_ROLE,
        permissions=list(permissions),
        containers=list(indices),
        trace_containers=list(trace_indices),
        services=list(services) if services is not None else None,
        groups=[],
        description="Created by the test suite.")

    mapped = dict(store.settings.get("rbac.user_roles", {}) or {})
    mapped[username] = TEST_ROLE
    store.settings.set("rbac.user_roles", mapped)
    # The resolver caches for a few seconds; a test cannot wait for that.
    store.rbac.invalidate()


def session_for(username="u", user_id="1", email="u@x", groups=()):
    """The identity half of a session. Authorization comes from the store."""
    return {"id": user_id, "email": email, "username": username,
            "groups": list(groups)}


def use_role(app, username, role_name):
    """Map a principal onto a role that already exists in the store."""
    claim(app)
    store = app.store
    mapped = dict(store.settings.get("rbac.user_roles", {}) or {})
    mapped[username] = role_name
    store.settings.set("rbac.user_roles", mapped)
    store.rbac.invalidate()


# ---------------------------------------------------------------------------
# Standing in for elasticsearch-py
# ---------------------------------------------------------------------------

import inspect as _inspect  # noqa: E402

from elasticsearch import Elasticsearch as _RealElasticsearch  # noqa: E402

#: What the installed client actually accepts. Read from the library rather
#: than listed here, so a fake cannot drift into accepting something the real
#: client refuses — which would turn every test using it into a test of the
#: fake.
SEARCH_PARAMETERS = frozenset(
    _inspect.signature(_RealElasticsearch.search).parameters) - {"self"}

#: Keyword arguments that are transport options, not request-body fields.
SEARCH_OPTIONS = ("timeout", "request_cache", "error_trace", "filter_path",
                  "human", "pretty", "routing", "preference",
                  "allow_no_indices", "ignore_unavailable")

#: The client's name for a body field, where the two differ. Mirrors
#: `_BODY_TO_KEYWORD` in the adapter, inverted.
KEYWORD_TO_BODY = {"source": "_source"}


def search_body(kwargs):
    """Rebuild a request body from the keywords elasticsearch-py 8.x takes.

    `body=` is deprecated and a future major removes it, so the adapters pass
    the fields as keyword arguments. Four fakes across this suite stand in for
    the client, and each one used to accept `body=`. Rebuilding the body here
    keeps every assertion written against a body dict — while checking, as the
    real client does, that no field is passed under a name it would reject.

    The check matters: `_source` in the JSON body is `source` in the
    signature. A fake that takes `_source=` and files it away happily lets the
    adapter's translation be deleted with every test still green, and the
    failure surfaces the first time somebody opens the context view.
    """
    assert "body" not in kwargs, (
        "elasticsearch-py deprecated body=; pass the fields as keywords")
    unknown = sorted(set(kwargs) - SEARCH_PARAMETERS)
    assert not unknown, (
        f"elasticsearch-py's search() has no parameter(s) {unknown}. A body "
        f"field whose name differs from the keyword must be translated in the "
        f"adapter, not accepted here.")
    return {KEYWORD_TO_BODY.get(key, key): value
            for key, value in kwargs.items()
            if key not in SEARCH_OPTIONS}


# ---------------------------------------------------------------------------
# A log source that answers without a network
# ---------------------------------------------------------------------------

class StubLogSource:
    """Enough of `LogSource` for a test that is about something else.

    Most of the tests that reach for this are about AUTHORIZATION: does a role
    with `logs:read` get a 200, does revoking it take effect without signing
    out. `/api/search` is the probe, and what it searches is beside the point.

    Which is exactly how they came to depend on a live cluster. `Config`
    defaults `ELASTICSEARCH_URL` to `http://localhost:9200`, so with the
    development lab running they passed against real Elasticsearch and nobody
    could tell — until the lab was switched off and fourteen tests failed at
    once, none of which was about Elasticsearch.

    A stub keeps the dependency where a reader can see it: the test declares
    the source it wants and the assertion is about the permission again.
    """

    backend = "stub"

    def __init__(self, name="stub-logs", containers=("logs-app", "logs-web"),
                 records=(), fail=None):
        self.name = name
        self._containers = tuple(containers)
        self._records = list(records)
        #: Set to an exception to make every call raise, for the paths that
        #: are about a source being down.
        self.fail = fail
        self.searches = []

    # ---------- Source ----------

    @property
    def capabilities(self):
        from wdash.hub.source import Capability
        # SEARCH and HISTOGRAM — the names the catalogue has. This said
        # LOG_SEARCH and LOG_HISTOGRAM, which do not exist, so reading the
        # property raised; it held only because no route had asked a stub
        # what it could do.
        return frozenset({Capability.SEARCH, Capability.HISTOGRAM})

    def supports(self, capability):
        return capability in self.capabilities

    def health(self):
        if self.fail:
            return False, str(self.fail)
        return True, "stub"

    def containers(self, scope):
        if self.fail:
            raise self.fail
        # Through the scope, not around it: a stub that ignores boundaries
        # would make every RBAC test pass.
        return tuple(c for c in self._containers
                     if scope.allows_container(c, self.name))

    # ---------- LogSource ----------

    def search(self, query, scope):
        from wdash.hub.models import LogPage
        if self.fail:
            raise self.fail
        self.searches.append(query)
        reachable = self.containers(scope)
        records = list(self._records) if reachable else []
        return LogPage(records=records, total=len(records),
                       containers=reachable, sources=[
                           {"name": self.name, "count": len(records),
                            "total": len(records), "failed": False}])

    def fetch(self, ref, scope):
        return next((r for r in self._records
                     if r.ref and r.ref.id == ref.id), None)

    def histogram(self, query, scope):
        if self.fail:
            raise self.fail
        return []


def with_stub_logs(app, **kwargs):
    """Give an app a log source that answers. Returns the stub.

    Replaces whatever the environment produced, so a test says what it depends
    on instead of inheriting it.
    """
    source = StubLogSource(**kwargs)
    app.hub.replace_all(logs=[source],
                        traces=list(app.hub._traces.values()),
                        monitors=list(app.hub._monitors.values()))
    return source
