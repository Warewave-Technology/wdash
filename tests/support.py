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


#: How often a test server's loop looks for a request to stop.
#:
#: `serve_forever` looks every half second by default, and `shutdown()` waits
#: for it to look. A server started per test therefore cost every test half a
#: second in its tearDown, whether or not it was sent anything: measured, the
#: sixty-odd tests of test_alert_delivery took 0.51s each, and together with
#: test_secret_destinations that was about forty-five seconds of a two-and-a-
#: half-minute suite spent waiting for a loop to notice it was told to stop.
POLL_SECONDS = 0.01


def serve_in_background(server):
    """Start `server` on a daemon thread, stoppable at once. Returns it."""
    import threading
    threading.Thread(target=server.serve_forever,
                     kwargs={"poll_interval": POLL_SECONDS}, daemon=True).start()
    return server


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


#: What `set_up` uses when a test does not care. Long enough to pass the
#: length rule, which is the only rule there is.
SETUP_PASSWORD = "a-sufficiently-long-password"


def _secret_on(page):
    """The shared secret the enrolment page is showing, without its spaces.

    Read off the page rather than out of the database, because that is what a
    person does: the page shows it in groups of four precisely so it can be
    typed into an authenticator by hand.
    """
    import re
    found = re.search(r'id="totpSecret">([^<]+)<', page)
    if not found:
        raise AssertionError(
            "the enrolment page showed no secret; it may not be the enrolment "
            "page at all:\n" + page[:400])
    return "".join(found.group(1).split())


def enrol(client):
    """Finish the authenticator enrolment a held sign-in is waiting on.

    Returns the secret, so a later sign-in by the same client can produce a
    code for it. Drives the real pages — a test that forges the session
    instead would pass with the whole second factor removed.
    """
    from wdash.auth import totp

    page = client.get("/auth/totp/enrol", follow_redirects=True).data.decode()
    secret = _secret_on(page)
    response = client.post("/auth/totp/enrol", data={"code": totp.code(secret)},
                           follow_redirects=False)
    assert response.status_code == 302, (
        f"enrolment was refused: {response.status_code}")
    return secret


def set_up(client, username="owner", password=SETUP_PASSWORD, email=None):
    """Complete first-run setup AND the enrolment it now requires.

    `POST /setup` no longer starts a session: a local account needs an
    authenticator, and the first administrator enrols like everybody else, so
    setup leaves the browser holding a half-finished sign-in. Returns the TOTP
    secret.
    """
    form = {"username": username, "password": password, "confirm": password}
    if email is not None:
        form["email"] = email
    client.post("/setup", data=form)
    return enrol(client)


def sign_in(client, username, password, secret=None, app=None):
    """Sign a client in through both halves, as a person does.

    With no `secret` the account has not enrolled yet, and this enrols it —
    which is exactly what its first sign-in does. Returns the final response.

    A code can be used ONCE. Enrolling uses the current step, so the next step
    is tried first: a test that enrols and then signs in would otherwise
    replay the step it just used, which is refused — correctly — and recorded
    as a failure counting towards the lockout the next test is about.

    Three steps is all the drift allowance holds, so a test that signs the
    same account in three times inside thirty seconds runs out. `app` is the
    way out of that and the only thing here that reaches past the pages: it
    forgets the last step used, because a test does in a millisecond what a
    person does over minutes. The replay refusal itself is measured against
    the real pages in tests/test_totp.py, not here.
    """
    import time

    from wdash.auth import totp

    if app is not None and secret is not None:
        app.store.users.record_totp_step(username, None)

    client.post("/auth/login",
                data={"username": username, "password": password})
    if secret is None:
        page = client.get("/auth/totp/enrol",
                          follow_redirects=True).data.decode()
        fresh = _secret_on(page)
        return client.post("/auth/totp/enrol",
                           data={"code": totp.code(fresh)})

    response = None
    for ahead in (totp.STEP, 0, -totp.STEP):
        response = client.post(
            "/auth/totp",
            data={"code": totp.code(secret, at=time.time() + ahead)})
        if response.status_code == 302:
            return response
    return response


def sign_in_in_browser(page, base, username, password, secret=None, app=None):
    """Drive a real browser through both halves of a local sign-in.

    The pages are driven rather than the session forged, because this IS the
    flow now: a cookie written by hand would pass with the second factor
    removed entirely. Enrols when the account has not yet, and returns the
    secret either way.

    `app` forgets the last step used first, for the same reason `sign_in`
    takes one: a suite signs the same account in several times inside one
    thirty-second step, and a person does not.
    """
    from wdash.auth import totp

    if app is not None:
        app.store.users.record_totp_step(username, None)

    page.goto(f"{base}/auth/login", wait_until="networkidle")
    page.fill("input[name=username]", username)
    page.fill("input[name=password]", password)
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")

    if "/auth/totp/enrol" in page.url:
        secret = "".join(page.inner_text("#totpSecret").split())
    elif secret is None:
        # Said rather than left to fail as a wrong code: this account has
        # already enrolled, so the caller has to hand back the secret the
        # first sign-in returned.
        raise AssertionError(
            f"{username} has already enrolled and no secret was given; the "
            f"page is {page.url}")
    page.fill("input[name=code]", totp.code(secret))
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")
    return secret


def sign_in_after_key_change(client, username, password, app):
    """Sign in on a worker whose encryption key is not the one that sealed
    this account's authenticator.

    A rotated `WDASH_ENCRYPTION_KEY` makes every local account's second factor
    unreadable, exactly as it does a source password, and the way back is
    `python -m wdash.store.recover --reset-totp` followed by a fresh
    enrolment against the new key. That is what this does: the recovery, not a
    shortcut past it.
    """
    app.store.users.clear_totp(username)
    return sign_in(client, username, password)


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


def install_dashboard(app, dashboard):
    """Put a ready-made `Dashboard` into whichever store the app is using.

    Tests used to write straight into `app.dashboard_manager.dashboards`,
    which is the JSON manager's in-memory cache and exists on nothing else.
    Dashboards default to the database now, so those tests failed on an
    AttributeError rather than on the panel behaviour they were about.

    The two stores are reached differently on purpose: the file manager
    invents its own id and cannot be told one, while the repository takes
    `dashboard_id` — the parameter the migration needs for exactly this
    reason, that identity has to survive.
    """
    manager = app.dashboard_manager
    if hasattr(manager, "dashboards"):          # the JSON file manager
        manager.dashboards[dashboard.id] = dashboard
        return dashboard
    manager.create_dashboard(
        dashboard_id=dashboard.id, name=dashboard.name,
        description=dashboard.description, query=dashboard.query,
        created_by=dashboard.created_by, created_at=dashboard.created_at,
        index_patterns=list(dashboard.index_patterns),
        panels=dashboard.panels, thresholds=dashboard.thresholds,
        visibility=dashboard.visibility, source=dashboard.source)
    return manager.get_dashboard(dashboard.id)


def change_dashboard(app, dashboard, **changes):
    """Change a fixture dashboard so the next request through a route sees it.

    Tests assigned to the object — `self.dashboard.panels = [...]` — and then
    fetched it back through a route. That is a write on the JSON file manager
    and ONLY there: it hands out the object it stores, so the assignment and
    the store are the same thing. The database hands out a fresh object per
    read, so the same line changed a copy nothing would look at again and the
    request answered the fixture's original panels — a test that passes while
    measuring nothing.

    Which is why twenty-four methods covering panel rendering, thresholds and
    unreachable sources were pinned to DASHBOARD_STORAGE=file when the default
    moved: it was the fixture shape that did not survive, not the behaviour.
    This is the shape that survives both.

    Keyword arguments are `Dashboard` attributes — panels, query, thresholds,
    source, name, description, index_patterns, visibility. The object in hand
    is updated too, so a test can go on reading it.
    """
    manager = app.dashboard_manager
    for attribute, value in changes.items():
        setattr(dashboard, attribute, value)
    if hasattr(manager, "dashboards"):          # the JSON file manager
        manager.dashboards[dashboard.id] = dashboard
        return dashboard
    manager.update_dashboard(dashboard.id, **changes)
    return dashboard


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

    Which is exactly how they came to depend on a live cluster. `Config` once
    defaulted the cluster address to `http://localhost:9200`, so with the
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


# ---------------------------------------------------------------------------
# An Elasticsearch that answers the query it is sent
# ---------------------------------------------------------------------------
#
# The fakes above return the same hits whatever the body says. That is enough
# to test what the adapter does with an answer, and it is how a test asserted
# rows a real cluster would never return: the adapter asked for root spans
# only, beside the service rule, and the fake answered with every span. This
# one evaluates the parts of the query DSL the adapters use — bool, term,
# terms, exists, wildcard, range, match_all/none, sort, collapse with
# inner_hits and terms aggregations with filter sub-aggregations — so a
# search that could not match anything returns nothing.

_MISSING = object()


def es_field(source, path):
    """A dotted path, read the way Elasticsearch indexes an object: nested
    keys and dotted keys alike (`{"service": {"name": x}}` and
    `{"service.name": x}` are the same field)."""
    def walk(node, parts):
        if not parts:
            return node
        if not isinstance(node, dict):
            return _MISSING
        for cut in range(len(parts), 0, -1):
            key = ".".join(parts[:cut])
            if key in node:
                found = walk(node[key], parts[cut:])
                if found is not _MISSING:
                    return found
        return _MISSING
    return walk(source, path.split("."))


def lucene_wildcard(value):
    """Lucene's wildcard syntax: `*`, `?`, and `\\` escaping the next one."""
    import re
    out, index = [], 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            out.append(re.escape(value[index + 1]))
            index += 2
            continue
        out.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
        index += 1
    return re.compile("".join(out), re.DOTALL)


def _comparable(value):
    from datetime import datetime
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def _values(source, field):
    found = es_field(source, field)
    if found is _MISSING or found is None:
        return []
    return list(found) if isinstance(found, list) else [found]


def _words(value):
    """Text as the standard analyzer splits it: lower case, word characters."""
    import re
    return re.findall(r"\w+", str(value).lower())


def _mapped_type(mapping, field):
    """The type a mapping gives `field`, or None when it maps nothing.

    Walks `properties` the way a mapping is written: a property can hold a
    dotted name of its own (`deployment.environment`), and a multi-field
    hangs its keyword off `fields`.
    """
    def walk(properties, parts):
        for count in range(len(parts), 0, -1):
            node = properties.get(".".join(parts[:count]))
            if not isinstance(node, dict):
                continue
            rest = parts[count:]
            if not rest:
                return node.get("type")
            found = walk(node.get("properties") or {}, rest)
            if found is None and len(rest) == 1:
                found = ((node.get("fields") or {}).get(rest[0]) or {}).get("type")
            if found is not None:
                return found
        return None

    return walk(mapping or {}, str(field).split("."))


def _projected(source, includes, prefix=""):
    """`_source` as Elasticsearch returns it for a list of `includes`: those
    paths and nothing else, whether a document nests its keys or dots them."""
    out = {}
    for key, value in source.items():
        path = prefix + key
        if any(path == name or path.startswith(name + ".") for name in includes):
            out[key] = value
        elif isinstance(value, dict) and any(name.startswith(path + ".")
                                             for name in includes):
            inner = _projected(value, includes, path + ".")
            if inner:
                out[key] = inner
    return out


def es_query_matches(query, source, doc_id=None, mapping=None):
    """Whether Elasticsearch would keep a document with this `_source`.

    `mapping` is the index's `properties`, and what it is for is `match`:
    without it every field is analysed, which is more permissive than the
    cluster and lets a test pass over a query that answers nothing.
    """
    if not query or "match_all" in query:
        return True
    if "match_none" in query:
        return False
    if "ids" in query:
        return doc_id in (query["ids"].get("values") or ())
    if "match" in query or "match_phrase" in query:
        # `match` keeps a value holding ANY of the words (the default `or`);
        # `match_phrase` one holding all of them, in order and side by side.
        kind = "match" if "match" in query else "match_phrase"
        (field, wanted), = query[kind].items()
        if isinstance(wanted, dict):
            wanted = wanted.get("query")
        # Elasticsearch does not analyse a keyword field: on one, both of
        # these build a term query on the whole input. Measured on the lab's
        # app-logs-000001, where `service` is a keyword holding
        # 'search-service': match_phrase "search" answers 0 hits and
        # "search-service" 5140. A field the mapping does not know is analysed
        # here, which is what dynamic mapping would make of it.
        if _mapped_type(mapping, field) not in (None, "text", "match_only_text"):
            values = _values(source, field)
            if not values and "." in field:
                # A multi-field (`severity_text.keyword`) is indexed from its
                # parent's value and is not in `_source` at all. Only a parent
                # that HAS a type is one: an object has properties instead.
                parent = field.rpartition(".")[0]
                if _mapped_type(mapping, parent) is not None:
                    values = _values(source, parent)
            return any(str(value) == str(wanted) for value in values)
        words = _words(wanted)

        def holds(value):
            have = _words(value)
            if kind == "match":
                return any(word in have for word in words)
            return any(have[at:at + len(words)] == words
                       for at in range(len(have) - len(words) + 1))
        return bool(words) and any(holds(v) for v in _values(source, field))
    if "prefix" in query:
        (field, wanted), = query["prefix"].items()
        if isinstance(wanted, dict):
            wanted = wanted.get("value")
        return any(str(v).startswith(str(wanted)) for v in _values(source, field))
    if "term" in query:
        (field, wanted), = query["term"].items()
        if isinstance(wanted, dict):
            wanted = wanted.get("value")
        return wanted in _values(source, field)
    if "terms" in query:
        (field, wanted), = query["terms"].items()
        return any(v in wanted for v in _values(source, field))
    if "exists" in query:
        return bool(_values(source, query["exists"]["field"]))
    if "wildcard" in query:
        (field, wanted), = query["wildcard"].items()
        if isinstance(wanted, dict):
            wanted = wanted.get("value")
        pattern = lucene_wildcard(wanted)
        return any(pattern.fullmatch(str(v)) for v in _values(source, field))
    if "range" in query:
        (field, bounds), = query["range"].items()
        checks = {"gte": lambda a, b: a >= b, "gt": lambda a, b: a > b,
                  "lte": lambda a, b: a <= b, "lt": lambda a, b: a < b}
        return any(all(checks[op](_comparable(v), _comparable(bound))
                       for op, bound in bounds.items() if op in checks)
                   for v in _values(source, field))
    if "bool" in query:
        clause = query["bool"]

        def listed(key):
            value = clause.get(key) or []
            return value if isinstance(value, list) else [value]

        required = listed("must") + listed("filter")
        if not all(es_query_matches(q, source, doc_id, mapping)
                   for q in required):
            return False
        if any(es_query_matches(q, source, doc_id, mapping)
               for q in listed("must_not")):
            return False
        should = listed("should")
        minimum = clause.get("minimum_should_match")
        if minimum is None:
            minimum = 0 if required else (1 if should else 0)
        return sum(es_query_matches(q, source, doc_id, mapping)
                   for q in should) >= int(minimum)
    raise NotImplementedError(f"the model does not know {list(query)}")


def _sorted_hits(hits, sort):
    """Hits in `sort` order: a list of {field: {order, missing}}."""
    ordered = list(hits)
    for spec in reversed(sort or []):
        (field, options), = spec.items()
        if isinstance(options, str):
            options = {"order": options}
        descending = options.get("order") == "desc"
        missing_first = options.get("missing") == "_first"

        def key(hit, field=field):
            values = _values(hit["_source"], field)
            return None if not values else _comparable(values[0])

        present = [h for h in ordered if key(h) is not None]
        absent = [h for h in ordered if key(h) is None]
        present.sort(key=key, reverse=descending)
        ordered = absent + present if missing_first else present + absent
    return ordered


class ModelledES:
    """A cluster of one or more indices that answers what it is asked.

    `indices` maps an index name to (mapping properties, documents), each
    document a `_source` dict carrying its own `_id` under "_id".
    """

    def __init__(self, indices):
        self._indices = {
            name: (properties, [{"_index": name, "_id": doc.pop("_id"),
                                 "_source": doc} for doc in docs])
            for name, (properties, docs) in indices.items()}
        self.requests = []

    def ping(self):
        return True

    @property
    def cat(self):
        outer = self

        class Cat:
            def indices(self, **kw):
                return [{"index": name, "creation.date": "0"}
                        for name in outer._indices]
        return Cat()

    @property
    def indices(self):
        outer = self

        class Indices:
            def get_mapping(self, index=None, **kw):
                names = str(index or "").split(",")
                return {name: {"mappings": {"properties": outer._indices[name][0]}}
                        for name in names if name in outer._indices}
        return Indices()

    def _docs(self, index):
        names = str(index or "").split(",")
        return [hit for name in names if name in self._indices
                for hit in self._indices[name][1]]

    def _mapping_of(self, hit):
        """The mapping of the index a hit came from: what says whether a
        field is analysed."""
        entry = self._indices.get(hit.get("_index"))
        return entry[0] if entry else None

    def search(self, index=None, **kwargs):
        body = search_body(kwargs)
        self.requests.append({"index": index, "body": body})
        hits = [hit for hit in self._docs(index)
                if es_query_matches(body.get("query"), hit["_source"],
                                    hit["_id"], self._mapping_of(hit))]
        ordered = _sorted_hits(hits, body.get("sort"))

        collapse = body.get("collapse")
        if collapse:
            groups, order = {}, []
            for hit in ordered:
                values = _values(hit["_source"], collapse["field"])
                group = values[0] if values else None
                if group not in groups:
                    groups[group] = []
                    order.append(group)
                groups[group].append(hit)
            collapsed = []
            for group in order:
                top = dict(groups[group][0])
                inner = collapse.get("inner_hits")
                if inner:
                    chosen = _sorted_hits(groups[group], inner.get("sort"))
                    top["inner_hits"] = {inner["name"]: {"hits": {
                        "hits": chosen[:inner.get("size", 3)]}}}
                collapsed.append(top)
            ordered = collapsed

        returned = ordered[:body.get("size", 10)]
        includes = body.get("_source")
        if isinstance(includes, (list, tuple)):
            # Only what was asked for, which is what makes a list view that
            # asks for too little read differently from the record it lists.
            returned = [dict(hit, _source=_projected(hit["_source"], includes))
                        for hit in returned]
        response = {"took": 1,
                    "hits": {"total": {"value": len(hits)},
                             "hits": returned}}
        if body.get("aggs"):
            # The indices being searched, for `_aggregate` to read the
            # mapping out of. Not a parameter: three test files subclass this
            # and override `_aggregate(self, spec, hits)`, and a fourth
            # argument would break them all for a fact only one branch wants.
            self._searching = index
            response["aggregations"] = {
                name: self._aggregate(spec, hits)
                for name, spec in body["aggs"].items()}
        return response

    #: Mapped types that read a terms `missing` as a number, and so reject a
    #: word. Elasticsearch parses `missing` as the field's own type before it
    #: looks at any document, and the whole `_search` answers 400 — every
    #: aggregation in the batch, not the one that asked. Modelled here because
    #: a fixture that accepts what the real cluster refuses is how a panel
    #: that kills its board passes its tests: measured on the lab,
    #: `{"terms": {"field": "http_status", "missing": "unknown"}}` on a
    #: `short` answers `For input string: "unknown"`.
    _NUMERIC_TYPES = frozenset({"integer", "short", "byte", "long", "float",
                                "double", "half_float", "scaled_float"})

    def _mapped_type(self, index, field):
        field = field[:-len(".keyword")] if field.endswith(".keyword") else field
        for name in str(index or "").split(","):
            properties = (self._indices.get(name) or (None,))[0] or {}
            node = properties
            for part in field.split("."):
                node = (node or {}).get(part) or (node or {}).get(
                    "properties", {}).get(part)
                if node is None:
                    break
            if isinstance(node, dict) and node.get("type"):
                return node["type"]
        return None

    def _aggregate(self, spec, hits):
        if "filter" in spec:
            return {"doc_count": sum(1 for hit in hits
                                     if es_query_matches(spec["filter"], hit["_source"],
                                                         hit["_id"],
                                                         self._mapping_of(hit)))}
        terms = spec["terms"]
        missing = terms.get("missing")
        if isinstance(missing, str) and not missing.lstrip("-").isdigit():
            index = getattr(self, "_searching", None)
            if self._mapped_type(index, terms["field"]) in self._NUMERIC_TYPES:
                raise RuntimeError(
                    f'BadRequestError(400, \'search_phase_execution_exception\', '
                    f'\'For input string: "{missing}"\')')
        buckets = {}
        for hit in hits:
            values = _values(hit["_source"], terms["field"])
            # What `missing` is FOR: a document without the field is counted
            # under that key rather than left out. Modelled so that dropping
            # the parameter is visible as the bucket it removes.
            if not values and missing is not None:
                values = [missing]
            for value in values:
                buckets.setdefault(value, []).append(hit)
        out = []
        for key, members in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            bucket = {"key": key, "doc_count": len(members)}
            for name, sub in (spec.get("aggs") or {}).items():
                bucket[name] = self._aggregate(sub, members)
            out.append(bucket)
        return {"buckets": out[:terms.get("size", 10)]}

    def msearch(self, searches=None, **kw):
        pairs = zip(searches[0::2], searches[1::2])
        return {"responses": [self.search(index=header.get("index"), **body)
                              for header, body in pairs]}
