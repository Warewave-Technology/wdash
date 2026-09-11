"""
Agents, the monitors they run, and what they found.

WDash still does not probe anything. An agent pulls its configuration from
here, runs the checks on its own schedule, and pushes results back — so the
network path, the retries and the timing belong to the agent, and restarting
WDash misses no check.

Two things in here are load-bearing and easy to get wrong:

**Tokens are not password hashes.** Argon2 exists to make a low-entropy secret
expensive to guess. An agent token is 256 bits of machine-generated
randomness; there is no dictionary to attack, and running Argon2 on every
result batch would burn CPU for no security while giving anybody who can reach
the ingest endpoint a way to exhaust the server. A SHA-256 lookup is the right
tool, and the difference is written down because "why is this not Argon2 like
everything else" is the obvious question.

**A silent agent is not a failing target.** If an agent stops reporting, its
monitors go `unknown`. Reporting them as `down` turns a dead agent into a
false outage, and a false outage is how a monitoring system trains people to
ignore it.
"""

import hashlib
import json
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, insert, select, update

from .schema import (
    agents, journey_screenshots, monitor_agents, monitor_results, monitors,
)

logger = logging.getLogger(__name__)

#: How long after its last word an agent is treated as gone. Three intervals
#: of the slowest sensible schedule: long enough that one missed beat is not an
#: alarm, short enough that a dead agent is noticed within minutes.
AGENT_STALE_AFTER = timedelta(minutes=5)

#: What a check can be. Still short on purpose — ICMP needs a raw socket and
#: so a privileged container, which is a decision rather than a type that
#: quietly appears in a list. `browser` earned the same decision and got it:
#: it runs on a different agent image, and where no such agent is assigned the
#: journey reports as unknown instead of pretending to pass.
MONITOR_KINDS = ("http", "tcp", "browser")
BROWSER = "browser"

#: A journey does more than one thing, so it needs longer than a request. Ten
#: minutes is the ceiling; the default per journey is far below it.
MAX_JOURNEY_TIMEOUT = 600

#: How long a failure screenshot is kept. Much shorter than results: "step 4
#: failed" a month later is still a data point, the picture of a login page
#: from a month ago is a megabyte nobody will open.
SCREENSHOT_RETENTION_DAYS = 7
SCREENSHOT_RETENTION_SETTING = "monitoring.screenshot_retention_days"

#: Largest screenshot accepted from an agent. A full-page capture of a long
#: page can be several megabytes, and an agent that sends one every minute
#: fills the database faster than the results do. The agent downscales; this
#: is the backstop for one that does not.
MAX_SCREENSHOT_BYTES = 512 * 1024

#: The pictures a failure screenshot may be, told by their first bytes.
_IMAGE_SIGNATURES = ((b"\xff\xd8\xff", "image/jpeg", "jpg"),
                     (b"\x89PNG\r\n\x1a\n", "image/png", "png"))


def image_type(data):
    """(content type, extension) of an image these bytes are, or None.

    From the bytes, never from what the sender said. The type an agent sent
    was stored and served back inline from WDash's own origin, so a result
    carrying `text/html` — any holder of an agent token can send one — was
    a page that ran in every viewer's session, admins' included.
    """
    for signature, kind, extension in _IMAGE_SIGNATURES:
        if data.startswith(signature):
            return kind, extension
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp", "webp"
    return None

#: How long results are kept, unless an operator says otherwise. Thirty days
#: because a monitoring page is used to answer "when did this start", and a
#: week cannot answer it for anything that started a fortnight ago.
DEFAULT_RETENTION_DAYS = 30

#: The settings key an operator changes it with.
RETENTION_SETTING = "monitoring.retention_days"

#: Least often the ingest path will consider pruning. The DELETE is cheap and
#: indexed, but running it on every batch would put a table scan behind every
#: fifteen-second report from every agent.
PRUNE_EVERY = timedelta(hours=1)

#: Rows per INSERT statement. Nine columns each, so this stays well under
#: SQLite's 32,766-variable ceiling with room for the column count to grow.
INSERT_CHUNK = 1000

#: Where the last prune is recorded. In the settings table rather than in a
#: process variable, so four gunicorn workers do not each keep their own idea
#: of when it last ran and prune four times an hour between them.
PRUNE_MARKER = "monitoring.last_pruned_at"


#: Bounds on a schedule. Below the floor an agent is a load generator; above
#: the ceiling the monitor is a daily report and the window selector on the
#: page cannot reach it.
MIN_INTERVAL = 10
MAX_INTERVAL = 3600
MAX_TIMEOUT = 120


class MonitoringError(ValueError):
    """A definition the store will not accept."""


def _now():
    return datetime.now(timezone.utc)


def hash_token(token):
    """Hex SHA-256. See the module docstring for why this is not Argon2."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token():
    """A token with no structure worth guessing at."""
    return secrets.token_urlsafe(32)


def _aware(value):
    """Timestamps come back naive from SQLite and aware from Postgres.

    Comparing the two raises, and the comparison here decides whether an agent
    is considered alive — so a dialect difference would make agents look dead
    on one database and fine on the other.
    """
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


class AgentRepository:
    def __init__(self, engine):
        self._engine = engine

    # ---------- writing ----------

    def create(self, name, labels=None):
        """Register an agent. Returns (row, token).

        The token is returned ONCE and never stored — only its hash is. An
        operator who loses it rotates rather than recovers, which is the only
        honest thing a store that cannot read its own secrets can offer.
        """
        name = (name or "").strip()
        if not name:
            raise MonitoringError("An agent needs a name.")

        token = new_token()
        row = {
            "id": str(uuid.uuid4()),
            "name": name,
            "token_hash": hash_token(token),
            "labels": labels or {},
            "last_seen_at": None,
            "version": None,
            "enabled": True,
            "created_at": _now(),
        }
        with self._engine.begin() as connection:
            try:
                connection.execute(insert(agents).values(**row))
            except Exception as exc:
                raise MonitoringError(
                    f"An agent called '{name}' already exists.") from exc
        return self._public(row), token

    def rotate_token(self, agent_id):
        """A new token, and the old one stops working immediately.

        No grace period: an overlap window is exactly what somebody rotating a
        leaked token does not want.
        """
        token = new_token()
        with self._engine.begin() as connection:
            result = connection.execute(
                update(agents).where(agents.c.id == agent_id)
                .values(token_hash=hash_token(token)))
        return token if result.rowcount else None

    def seen(self, agent_id, version=None):
        """Record that an agent is alive. Called on every exchange."""
        values = {"last_seen_at": _now()}
        if version:
            values["version"] = version
        with self._engine.begin() as connection:
            connection.execute(
                update(agents).where(agents.c.id == agent_id).values(**values))

    def set_enabled(self, agent_id, enabled):
        with self._engine.begin() as connection:
            connection.execute(
                update(agents).where(agents.c.id == agent_id)
                .values(enabled=bool(enabled)))

    def delete(self, agent_id):
        with self._engine.begin() as connection:
            connection.execute(
                delete(monitor_agents).where(
                    monitor_agents.c.agent_id == agent_id))
            connection.execute(delete(agents).where(agents.c.id == agent_id))

    # ---------- reading ----------

    def by_token(self, token):
        """The agent this token belongs to, or None.

        Looked up by hash rather than compared one by one, so the cost does
        not grow with the number of agents — and so there is no loop whose
        duration leaks how far down the list a token was found.
        """
        if not token:
            return None
        with self._engine.connect() as connection:
            row = connection.execute(
                select(agents).where(
                    agents.c.token_hash == hash_token(token))).mappings().first()
        if row is None or not row["enabled"]:
            return None
        return self._public(row)

    def all(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(agents).order_by(agents.c.name)).mappings().all()
        return [self._public(r) for r in rows]

    def get(self, agent_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(agents).where(agents.c.id == agent_id)).mappings().first()
        return self._public(row) if row else None

    @staticmethod
    def _public(row):
        """Never the token hash. It leaves this class in no direction."""
        last_seen = _aware(row["last_seen_at"])
        return {
            "id": row["id"],
            "name": row["name"],
            "labels": row["labels"] or {},
            "last_seen_at": last_seen,
            "version": row["version"],
            "enabled": bool(row["enabled"]),
            "created_at": _aware(row["created_at"]),
            "stale": (last_seen is None
                      or (_now() - last_seen) > AGENT_STALE_AFTER),
        }


#: Headers a check may not set. Each is decided by the transport or by the
#: agent, and letting a monitor override it produces a request that is not the
#: one anybody configured — a wrong Host reaches a different vhost, a wrong
#: Content-Length truncates the body.
RESERVED_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
    "upgrade", "te", "trailer", "expect",
})

#: Header names whose VALUE is a credential wherever it appears. Stored
#: encrypted whatever the operator ticks, because somebody pasting a bearer
#: token into the plain header box should not have it stored in clear as a
#: result of a checkbox they did not notice.
ALWAYS_SECRET_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie",
    "x-api-key", "x-auth-token", "api-key",
})


def _check_header(name, value):
    """Refuse anything that would inject a second header.

    A value containing CR or LF ends the header and starts another one. That
    turns a monitor definition into a way to add arbitrary headers — and, on
    a proxy that reads them, arbitrary requests.
    """
    name = (name or "").strip()
    if not name:
        raise MonitoringError("A header needs a name.")
    if any(character in name for character in "\r\n:\0 \t"):
        raise MonitoringError(
            f"'{name}' is not a header name: no spaces, colons or newlines.")
    if name.lower() in RESERVED_HEADERS:
        raise MonitoringError(
            f"'{name}' is set by the transport and cannot be overridden.")
    text = "" if value is None else str(value)
    if any(character in text for character in "\r\n\0"):
        raise MonitoringError(
            f"The value of '{name}' contains a newline, which would inject a "
            f"second header.")
    return name, text


def split_request(request):
    """Separate a request configuration into what is safe to show and what is not.

    Returns (public, secret). The split is by header NAME as well as by which
    box it was typed into: `Authorization` is a credential wherever somebody
    puts it, and storing it in clear because a checkbox went unticked is a
    mistake the form should not be able to make.
    """
    request = dict(request or {})
    public = {}
    secret = {}

    headers = {}
    secret_headers = {}
    for name, value in (request.get("headers") or {}).items():
        name, value = _check_header(name, value)
        if name.lower() in ALWAYS_SECRET_HEADERS:
            secret_headers[name] = value
        else:
            headers[name] = value
    for name, value in (request.get("secret_headers") or {}).items():
        name, value = _check_header(name, value)
        secret_headers[name] = value
    if headers:
        public["headers"] = headers
    if secret_headers:
        secret["headers"] = secret_headers

    # Cookies are session tokens far more often than they are preferences, so
    # the NAMES are shown and the values are sealed. A screen that lists the
    # names is enough to say what is being sent.
    cookies = {}
    for name, value in (request.get("cookies") or {}).items():
        if any(character in str(name) for character in "\r\n;="):
            raise MonitoringError(f"'{name}' is not a cookie name.")
        if any(character in str(value) for character in "\r\n;"):
            raise MonitoringError(
                f"The value of cookie '{name}' contains a separator.")
        cookies[str(name)] = str(value)
    if cookies:
        public["cookie_names"] = sorted(cookies)
        secret["cookies"] = cookies

    auth = request.get("auth") or {}
    kind = (auth.get("type") or "").strip().lower()
    if kind == "basic":
        username = (auth.get("username") or "").strip()
        if not username:
            raise MonitoringError("Basic auth needs a username.")
        public["auth"] = {"type": "basic", "username": username}
        if auth.get("password"):
            secret["auth_password"] = auth["password"]
    elif kind == "bearer":
        public["auth"] = {"type": "bearer"}
        if auth.get("token"):
            secret["auth_token"] = auth["token"]
    elif kind:
        raise MonitoringError(
            f"'{kind}' is not an authentication type. Available: basic, bearer.")

    return public, secret


#: Response assertions that name a header.
def _check_response_headers(assertions):
    for name in (assertions.get("headers_present") or ()):
        _check_header(name, "")
    for name, value in (assertions.get("headers_match") or {}).items():
        _check_header(name, "")
        if not str(value).strip():
            raise MonitoringError(
                f"Expecting header '{name}' to match nothing is the same as "
                f"expecting it to exist — use the presence check instead.")


class MonitorRepository:
    def __init__(self, engine, secret_box=None):
        self._engine = engine
        self._secrets = secret_box

    # ---------- validation ----------

    @staticmethod
    def validate(kind, target, interval, timeout):
        kind = (kind or "").strip().lower()
        if kind not in MONITOR_KINDS:
            raise MonitoringError(
                f"'{kind}' is not a check type. Available: "
                f"{', '.join(MONITOR_KINDS)}.")

        target = (target or "").strip()
        if not target:
            raise MonitoringError("A monitor needs something to check.")
        if kind == BROWSER and not target.startswith(("http://", "https://")):
            # The caller derives this from step one rather than asking for it
            # twice; reaching here means the steps were not validated first.
            raise MonitoringError(
                "A journey's address comes from its first step.")
        if kind == "http" and not target.startswith(("http://", "https://")):
            raise MonitoringError(
                "An http check needs a URL beginning http:// or https://.")
        if kind == "tcp":
            host, _, port = target.rpartition(":")
            if not host or not port.isdigit() or not 0 < int(port) < 65536:
                raise MonitoringError(
                    "A tcp check needs host:port, for example db.internal:5432.")

        interval = int(interval or 60)
        if not MIN_INTERVAL <= interval <= MAX_INTERVAL:
            raise MonitoringError(
                f"The interval has to be between {MIN_INTERVAL} and "
                f"{MAX_INTERVAL} seconds.")

        timeout = int(timeout or 10)
        # A journey is a sequence, so its ceiling is the sum of its steps
        # rather than one request's patience.
        ceiling = MAX_JOURNEY_TIMEOUT if kind == BROWSER else MAX_TIMEOUT
        if not 1 <= timeout <= ceiling:
            raise MonitoringError(
                f"The timeout has to be between 1 and {ceiling} seconds.")
        if timeout >= interval:
            # Otherwise a slow check is still running when the next one is due,
            # and the agent either overlaps them or silently skips.
            raise MonitoringError(
                "The timeout has to be shorter than the interval, or a slow "
                "check is still running when the next one is due.")
        return kind, target, interval, timeout

    # ---------- writing ----------

    def create(self, name, kind, target, interval_seconds=60,
               timeout_seconds=10, assertions=None, labels=None,
               agent_ids=(), created_by=None, request=None, steps=None,
               journey_secrets=None):
        steps, target = self._journey(kind, steps, target)
        kind, target, interval, timeout = self.validate(
            kind, target, interval_seconds, timeout_seconds)
        name = (name or "").strip()
        if not name:
            raise MonitoringError("A monitor needs a name.")
        assertions = assertions or {}
        _check_response_headers(assertions)
        public, secret = split_request(request)
        if kind == BROWSER:
            # A journey's credentials are named, because its steps refer to
            # them by name. Nothing else about the request shape applies: a
            # browser sends its own headers.
            secret = self._journey_secrets(steps, journey_secrets)
            public = None
        elif kind != "http" and (public or secret):
            # A tcp check opens a socket. Headers and auth on one are boxes
            # somebody filled in that will never be used, and a form that
            # accepts them teaches that they work.
            raise MonitoringError(
                "Headers, cookies and authentication apply to http checks only.")

        now = _now()
        row = {
            "id": str(uuid.uuid4()),
            "name": name, "kind": kind, "target": target,
            "interval_seconds": interval, "timeout_seconds": timeout,
            "assertions": assertions,
            "request": public,
            "secrets": self._seal(secret),
            "steps": [x.as_dict() for x in steps] if steps else None,
            "labels": labels or {},
            "enabled": True,
            "created_by": created_by,
            "created_at": now, "updated_at": now,
        }
        with self._engine.begin() as connection:
            connection.execute(insert(monitors).values(**row))
            self._assign(connection, row["id"], agent_ids)
        return self.get(row["id"])

    def update(self, monitor_id, agent_ids=None, request=None, steps=None,
               journey_secrets=None, **changes):
        allowed = {"name", "kind", "target", "interval_seconds",
                   "timeout_seconds", "assertions", "labels", "enabled"}
        values = {k: v for k, v in changes.items() if k in allowed}
        if steps is not None:
            current = self.get(monitor_id)
            if current is None:
                return None
            kind = values.get("kind", current["kind"])
            parsed, values["target"] = self._journey(kind, steps, None)
            values["steps"] = [x.as_dict() for x in parsed]
            # Written even when empty, unlike the http path.
            #
            # There, an empty submission means "the password box was left
            # alone" and wiping the credential would break the check on every
            # unrelated edit. Here the merge with what is stored has already
            # happened, so empty means something else entirely: no step refers
            # to a secret any more. Leaving the old one behind keeps a
            # credential nobody can see and nobody knows is there.
            secret = self._journey_secrets(parsed, journey_secrets,
                                           existing=self.credentials(monitor_id))
            values["secrets"] = self._seal(secret) if secret else None
        if "assertions" in values:
            _check_response_headers(values["assertions"] or {})
        if request is not None:
            public, secret = split_request(request)
            values["request"] = public
            # Only replaced when something new was supplied. A form that
            # submits an empty password box would otherwise wipe the stored
            # credential every time somebody edited the interval.
            if secret:
                values["secrets"] = self._seal(secret)
        if {"kind", "target", "interval_seconds", "timeout_seconds"} & set(values):
            current = self.get(monitor_id)
            if current is None:
                return None
            kind, target, interval, timeout = self.validate(
                values.get("kind", current["kind"]),
                values.get("target", current["target"]),
                values.get("interval_seconds", current["interval_seconds"]),
                values.get("timeout_seconds", current["timeout_seconds"]))
            values.update(kind=kind, target=target,
                          interval_seconds=interval, timeout_seconds=timeout)
        values["updated_at"] = _now()

        with self._engine.begin() as connection:
            result = connection.execute(
                update(monitors).where(monitors.c.id == monitor_id)
                .values(**values))
            if not result.rowcount:
                return None
            if agent_ids is not None:
                connection.execute(delete(monitor_agents).where(
                    monitor_agents.c.monitor_id == monitor_id))
                self._assign(connection, monitor_id, agent_ids)
        return self.get(monitor_id)

    def delete(self, monitor_id):
        with self._engine.begin() as connection:
            connection.execute(delete(monitor_agents).where(
                monitor_agents.c.monitor_id == monitor_id))
            connection.execute(delete(monitor_results).where(
                monitor_results.c.monitor_id == monitor_id))
            # And the screenshots. They are the only thing a monitor owns that
            # lives in its own table, and leaving them behind means a deleted
            # journey's pictures sit there until a retention sweep happens to
            # reach them — a week of images of a page nobody is checking any
            # more, and rows that no longer belong to anything.
            connection.execute(delete(journey_screenshots).where(
                journey_screenshots.c.monitor_id == monitor_id))
            result = connection.execute(
                delete(monitors).where(monitors.c.id == monitor_id))
        return bool(result.rowcount)

    @staticmethod
    def _assign(connection, monitor_id, agent_ids):
        rows = [{"monitor_id": monitor_id, "agent_id": a}
                for a in dict.fromkeys(agent_ids or ())]
        if rows:
            connection.execute(insert(monitor_agents).values(rows))

    # ---------- reading ----------

    def all(self, enabled_only=False):
        query = select(monitors).order_by(monitors.c.name)
        if enabled_only:
            query = query.where(monitors.c.enabled.is_(True))
        with self._engine.connect() as connection:
            rows = connection.execute(query).mappings().all()
            assignments = self._assignments(connection)
        return [self._public(r, assignments.get(r["id"], [])) for r in rows]

    def get(self, monitor_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(monitors).where(
                    monitors.c.id == monitor_id)).mappings().first()
            if row is None:
                return None
            assignments = self._assignments(connection, monitor_id)
        return self._public(row, assignments.get(monitor_id, []))

    def for_agent(self, agent_id):
        """What this agent should be checking.

        A monitor with NO assignment is run by every agent. That is the useful
        default — one agent, everything on it — without making the common case
        require bookkeeping. Explicitly assigning it to nobody would mean a
        monitor that exists and is never checked, which looks like a broken
        agent.
        """
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(monitors).where(monitors.c.enabled.is_(True))
                .order_by(monitors.c.name)).mappings().all()
            assignments = self._assignments(connection)
        out = []
        for row in rows:
            assigned = assignments.get(row["id"], [])
            if not assigned or agent_id in assigned:
                out.append(self._public(row, assigned))
        return out

    @staticmethod
    def _assignments(connection, monitor_id=None):
        query = select(monitor_agents)
        if monitor_id:
            query = query.where(monitor_agents.c.monitor_id == monitor_id)
        out = {}
        for row in connection.execute(query).mappings():
            out.setdefault(row["monitor_id"], []).append(row["agent_id"])
        return out

    @staticmethod
    def _journey(kind, steps, target):
        """Validate a journey's steps and take its address from step one.

        Derived rather than asked for a second time: a form with both a URL
        box and a `goto` step has two answers to one question, and they drift
        the first time somebody edits only one of them.
        """
        from ..journeys import StepError, parse
        if kind != BROWSER:
            if steps:
                raise MonitoringError(
                    "Only a browser journey has steps.")
            return None, target
        try:
            parsed = parse(steps)
        except StepError as exc:
            raise MonitoringError(str(exc)) from exc
        return parsed, parsed[0].value

    @staticmethod
    def _journey_secrets(steps, supplied, existing=None):
        """The named secrets a journey's steps refer to.

        Anything supplied that no step uses is dropped rather than stored: a
        credential kept for a step somebody deleted is a credential nobody
        knows is there.
        """
        from ..journeys import secret_names
        wanted = secret_names(steps or ())
        have = dict(existing or {})
        have.update({k: v for k, v in (supplied or {}).items() if v})
        kept = {name: have[name] for name in wanted if name in have}
        missing = [n for n in wanted if n not in kept]
        if missing:
            raise MonitoringError(
                f"This journey uses {{{{ secret.{missing[0]} }}}} and there is "
                f"no such secret. Add it, or correct the step.")
        return kept

    def _seal(self, secret):
        if not secret:
            return None
        import json

        from .secrets import SecretsUnavailable
        if self._secrets is None:
            raise MonitoringError(
                "WDASH_ENCRYPTION_KEY is not set, so credentials cannot be "
                "stored. Set it, or define this check without them.")
        try:
            return self._secrets.seal(json.dumps(secret))
        except SecretsUnavailable as exc:
            # Translated rather than propagated: the route catches
            # MonitoringError and flashes it, so letting this through turns
            # "you have no encryption key" into a 500 — a page that says
            # nothing about the one thing the person has to fix.
            raise MonitoringError(str(exc)) from exc

    def credentials(self, monitor_id):
        """The decrypted request secrets. For the AGENT endpoint only.

        Never on the public shape and never in a template: the agent needs
        them to make the request, and there is nowhere else they belong.
        """
        import json
        with self._engine.connect() as connection:
            row = connection.execute(
                select(monitors.c.secrets).where(
                    monitors.c.id == monitor_id)).first()
        if not row or not row[0] or self._secrets is None:
            return {}
        try:
            return json.loads(self._secrets.open(row[0]) or "{}")
        except Exception:
            logger.error(f"could not read the credentials for {monitor_id}")
            return {}

    @staticmethod
    def _public(row, agent_ids):
        return {
            "id": row["id"], "name": row["name"], "kind": row["kind"],
            "target": row["target"],
            "interval_seconds": row["interval_seconds"],
            "timeout_seconds": row["timeout_seconds"],
            "assertions": row["assertions"] or {},
            #: What the request looks like, minus every value that is a
            #: credential. `has_credentials` says one exists without saying
            #: what it is — enough to answer "is this check authenticating?"
            #: without a screen that can leak the answer.
            "request": row["request"] or {},
            "has_credentials": bool(row["secrets"]),
            #: The step list, for a journey. The placeholders are shown as
            #: written — `{{ secret.password }}` is not a password.
            "steps": row["steps"] or [],
            #: WHICH secrets are stored, never their values. Enough for the
            #: editor to say "stored — leave empty to keep it" rather than
            #: showing an empty box that looks like the password was lost.
            "secret_names": _journey_secret_names(row),
            "labels": row["labels"] or {},
            "enabled": bool(row["enabled"]),
            "created_by": row["created_by"],
            #: Bumped by every edit, including one that only rotates a
            #: credential. The agent's configuration version is derived from
            #: it, so a new password reaches the agent — `has_credentials`
            #: alone does not move when a secret is REPLACED.
            "updated_at": row["updated_at"],
            "agent_ids": list(agent_ids),
        }


def _journey_secret_names(row):
    """The placeholder names a journey's steps mention. No values.

    Read off the STEPS rather than by decrypting the secrets: this runs on
    every listing, and a screen that opens the box to count what is in it is a
    screen that can drop one.
    """
    from ..journeys import SECRET_PATTERN
    names = []
    for step in (row["steps"] or []):
        for name in SECRET_PATTERN.findall(str(step.get("value") or "")):
            if name not in names:
                names.append(name)
    return names


def _steps_of(result):
    """The per-step results an agent reported, trimmed to what is storable.

    Trimmed HERE rather than trusted: this arrives over an ingest endpoint
    that a compromised agent can post to, and an unbounded list of unbounded
    strings inside a JSON column is a way to fill a disk without a single
    failed check.
    """
    from ..journeys import MAX_STEPS
    steps = result.get("steps")
    if not isinstance(steps, (list, tuple)) or not steps:
        return None
    out = []
    for index, step in enumerate(steps[:MAX_STEPS], start=1):
        if not isinstance(step, dict):
            continue
        status = step.get("status")
        out.append({
            "index": index,
            "kind": str(step.get("kind") or "")[:32],
            "description": str(step.get("description") or "")[:255],
            "status": status if status in ("passed", "failed", "skipped")
                      else "skipped",
            "duration_us": step.get("duration_us"),
            "error": str(step.get("error") or "")[:1000] or None,
        })
    return out or None


class ResultRepository:
    def __init__(self, engine):
        self._engine = engine

    def record(self, agent_id, results):
        """Store a batch. Returns how many were kept.

        Results for monitors this agent is not assigned are DROPPED rather
        than stored: an ingest endpoint that accepts anything is a way to
        paint the whole board green, and a compromised agent should be able to
        lie about its own checks and nothing else.
        """
        if not results:
            return 0

        allowed = {m["id"] for m in MonitorRepository(self._engine)
                   .for_agent(agent_id)}
        received = _now()
        rows = []
        for result in results:
            monitor_id = result.get("monitor_id")
            if monitor_id not in allowed:
                logger.warning(
                    f"agent {agent_id} reported for monitor {monitor_id}, "
                    f"which it does not run")
                continue
            started = result.get("started_at")
            if isinstance(started, str):
                started = datetime.fromisoformat(started.replace("Z", "+00:00"))
            rows.append({
                "monitor_id": monitor_id,
                "agent_id": agent_id,
                "started_at": started or received,
                "received_at": received,
                "status": "down" if result.get("status") == "down" else "up",
                "duration_us": result.get("duration_us"),
                "error": (result.get("error") or "")[:2000] or None,
                "http_status": result.get("http_status"),
                "tls": result.get("tls"),
                "steps": _steps_of(result),
                "screenshot_id": self._keep_screenshot(monitor_id, result),
            })
        if not rows:
            return 0
        with self._engine.begin() as connection:
            # Chunked. A single multi-VALUES insert binds eleven parameters
            # per row, and SQLite refuses the statement past its limit —
            # "too many SQL variables", which says nothing about the batch
            # being too big. The endpoint caps at 500, so the live path never
            # reached it; this is a public repository method, and a caller
            # passing a day's backlog should get a working insert rather than
            # a dialect error.
            for start in range(0, len(rows), INSERT_CHUNK):
                connection.execute(
                    insert(monitor_results).values(rows[start:start + INSERT_CHUNK]))
        return len(rows)

    def _keep_screenshot(self, monitor_id, result):
        """Store the failure screenshot, if the agent sent one usable.

        Returns its id, or None. Never raises: a picture that could not be
        decoded must not cost the result it came with — the fact that the
        journey failed is the part somebody needs.
        """
        shot = result.get("screenshot")
        if not shot:
            return None
        try:
            import base64
            raw = shot.get("base64") if isinstance(shot, dict) else shot
            image = base64.b64decode(raw or "", validate=True)
        except Exception:
            logger.warning(f"monitor {monitor_id} sent a screenshot that "
                           f"could not be decoded")
            return None
        if not image:
            return None
        if len(image) > MAX_SCREENSHOT_BYTES:
            logger.warning(
                f"monitor {monitor_id} sent a {len(image) // 1024}KB "
                f"screenshot; the ceiling is "
                f"{MAX_SCREENSHOT_BYTES // 1024}KB")
            return None
        kind = image_type(image)
        if kind is None:
            logger.warning(f"monitor {monitor_id} sent a screenshot that is "
                           f"not a JPEG, PNG or WebP image; it was not kept")
            return None
        row = {
            "id": str(uuid.uuid4()), "monitor_id": monitor_id,
            "captured_at": _now(),
            "content_type": kind[0],
            "bytes": len(image), "image": image,
        }
        try:
            with self._engine.begin() as connection:
                connection.execute(insert(journey_screenshots).values(**row))
        except Exception as exc:
            logger.warning(f"could not store a screenshot: {exc}")
            return None
        return row["id"]

    def screenshot(self, screenshot_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(journey_screenshots).where(
                    journey_screenshots.c.id == screenshot_id)).mappings().first()
        return dict(row) if row else None

    def prune_screenshots(self, older_than_days):
        """Drop images past their own, shorter retention."""
        cutoff = _now() - timedelta(days=max(1, int(older_than_days)))
        with self._engine.begin() as connection:
            return connection.execute(
                delete(journey_screenshots).where(
                    journey_screenshots.c.captured_at < cutoff)).rowcount or 0

    def prune(self, older_than_days):
        """Delete results past the retention period. Returns how many went.

        Retention exists from the first version rather than being added later,
        because a table that grows without bound is noticed when it is already
        too large to clean up cheaply. Thirty days by default: a monitoring
        page is used to answer "when did this start", and a week cannot answer
        it for anything that started a fortnight ago.
        """
        if not older_than_days:
            return 0
        cutoff = _now() - timedelta(days=int(older_than_days))
        with self._engine.begin() as connection:
            result = connection.execute(
                delete(monitor_results).where(
                    monitor_results.c.started_at < cutoff))
        return result.rowcount or 0

    def latest(self, window_start=None):
        """The most recent result per (monitor, agent).

        Per PAIR, not per monitor: one check running from two places is two
        answers, and collapsing them throws away the only thing the second
        agent was installed to say.

        One query, with a window function. The first version found each pair's
        newest timestamp and then read every row from the OLDEST of those
        onward — so a single monitor that last reported an hour ago dragged an
        hour of every other monitor's results into memory to discard them.
        Measured on 8.6 million rows, that took 1.7 seconds to produce fifty
        rows; this takes 30 milliseconds.

        `row_number()` needs SQLite 3.25 (2018) and any Postgres. Both are far
        below what SQLAlchemy 2 already requires.
        """
        ranked = select(
            monitor_results,
            func.row_number().over(
                partition_by=(monitor_results.c.monitor_id,
                              monitor_results.c.agent_id),
                order_by=monitor_results.c.started_at.desc(),
            ).label("rank"),
        )
        if window_start:
            ranked = ranked.where(monitor_results.c.started_at >= window_start)

        subquery = ranked.subquery()
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(subquery).where(subquery.c.rank == 1)).mappings().all()
        return [dict(r) for r in rows]

    def latest_series(self, window_start, window_end):
        """Every result in the window, grouped by monitor.

        One query for the whole page. Asking per monitor was fifty queries to
        draw fifty sparklines — the same shape as the N+1 the Elasticsearch
        adapter avoids with a sub-aggregation, and it cost 1.1 seconds of the
        3.1 the listing took.
        """
        query = select(
            monitor_results.c.monitor_id, monitor_results.c.started_at,
            monitor_results.c.status, monitor_results.c.duration_us,
        ).where(
            monitor_results.c.started_at >= window_start,
            monitor_results.c.started_at <= window_end,
        ).order_by(monitor_results.c.started_at)

        out = {}
        with self._engine.connect() as connection:
            for row in connection.execute(query).mappings():
                out.setdefault(row["monitor_id"], []).append(dict(row))
        return out

    def series(self, monitor_id, start, end, agent_id=None):
        """Every result for one monitor in a window, oldest first."""
        query = select(monitor_results).where(
            monitor_results.c.monitor_id == monitor_id,
            monitor_results.c.started_at >= start,
            monitor_results.c.started_at <= end,
        ).order_by(monitor_results.c.started_at)
        if agent_id:
            query = query.where(monitor_results.c.agent_id == agent_id)
        with self._engine.connect() as connection:
            return [dict(r) for r in
                    connection.execute(query).mappings().all()]

    def prune_if_due(self, settings, now=None):
        """Prune, but not more than once an hour across the installation.

        Called from the ingest path rather than from a timer. The endpoint
        that grows the table is the natural place to shrink it: no scheduler,
        no extra thread, and it works with any number of workers — an
        installation nobody reports into has nothing to prune, and one that is
        busy prunes exactly as often as it needs to.

        `last pruned` lives in the settings table, not in a module variable,
        so four workers do not each keep their own clock and prune four times
        an hour between them.

        Returns how many rows went, or None when it was not due.
        """
        now = now or _now()
        try:
            days = int(settings.get(RETENTION_SETTING, DEFAULT_RETENTION_DAYS))
        except (TypeError, ValueError):
            days = DEFAULT_RETENTION_DAYS
        if days <= 0:
            # Retention off ON PURPOSE is a choice somebody can make. It is
            # not the default, because a table that grows without bound is
            # noticed when it is already too large to clean up cheaply.
            return None

        marker = settings.get(PRUNE_MARKER)
        if marker:
            try:
                last = datetime.fromisoformat(str(marker))
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if now - last < PRUNE_EVERY:
                    return None
            except ValueError:
                pass

        # Written BEFORE the delete. If the delete is slow and another worker
        # arrives mid-way, it should skip rather than start a second one over
        # the same rows.
        settings.set(PRUNE_MARKER, now.isoformat())
        removed = self.prune(days)
        if removed:
            logger.info(f"pruned {removed:,} monitor result(s) older than "
                        f"{days} days")

        # Screenshots on the same pass, by their own and shorter clock. On the
        # same pass because a second schedule is a second thing that can be
        # off; by their own clock because they are a hundred times the size
        # per row and worth a fraction as much a month later.
        try:
            shot_days = int(settings.get(SCREENSHOT_RETENTION_SETTING,
                                         SCREENSHOT_RETENTION_DAYS))
        except (TypeError, ValueError):
            shot_days = SCREENSHOT_RETENTION_DAYS
        if shot_days > 0:
            gone = self.prune_screenshots(min(shot_days, days))
            if gone:
                logger.info(f"pruned {gone:,} journey screenshot(s)")
        return removed

    def count(self, monitor_id=None):
        query = select(func.count()).select_from(monitor_results)
        if monitor_id:
            query = query.where(monitor_results.c.monitor_id == monitor_id)
        with self._engine.connect() as connection:
            return connection.execute(query).scalar() or 0
