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

from .secrets import may_follow
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

#: Rows per INSERT statement. Twelve columns each, so this stays well under
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
        """Remove an agent. Returns the names of the monitors it alone ran,
        which are switched off in the same transaction.

        A monitor assigned to nobody runs on every agent, so removing the one
        agent a monitor was kept on handed it — decrypted credentials and
        all — to every other agent, including the ones it was kept away
        from, and a journey landed on agents with no browser. Measured: a
        check assigned only to `dmz-browser` was in `branch-office`'s
        configuration, token and all, the moment `dmz-browser` was removed.

        Refusing the removal is not the answer: an agent is removed because
        it is lost or compromised, and that has to work at once. So the
        monitor stops instead of spreading, and the caller says which.
        """
        with self._engine.begin() as connection:
            holders = {}
            for monitor_id, holder in connection.execute(select(
                    monitor_agents.c.monitor_id, monitor_agents.c.agent_id)):
                holders.setdefault(monitor_id, set()).add(holder)
            alone = sorted(m for m, held in holders.items() if held == {agent_id})
            names = []
            if alone:
                connection.execute(
                    update(monitors).where(monitors.c.id.in_(alone))
                    .values(enabled=False, updated_at=_now()))
                names = sorted(connection.execute(
                    select(monitors.c.name).where(monitors.c.id.in_(alone)))
                    .scalars())
            connection.execute(
                delete(monitor_agents).where(
                    monitor_agents.c.agent_id == agent_id))
            connection.execute(delete(agents).where(agents.c.id == agent_id))
        return names

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


#: What a check may decide about TLS.
#:
#: `verify` is what every check does today and what a NULL column means: the
#: certificate is verified, against the public roots unless the check names a
#: certificate of its own. `expiry_only` is the explicit waiver — do not
#: verify, read the certificate anyway — and it is the reason the rest of this
#: section exists: a check that does not verify is talking to whatever
#: answered, so it must send nothing.
TLS_MODES = ("verify", "expiry_only")
VERIFY, EXPIRY_ONLY = TLS_MODES

#: Bounds on the pasted PEM. It goes into a JSON column, into the public
#: shape, and into every /api/agent/config response for every agent on every
#: poll — the same reason `_steps_of` bounds a journey's steps. A private CA
#: and its intermediates are two or three certificates and a few kilobytes;
#: anything past this is somebody pasting a bundle.
MAX_TLS_PEM_BYTES = 16 * 1024
MAX_TLS_CERTIFICATES = 8


def tls_mode(tls):
    """The mode of a stored `tls` blob. "verify" for NULL and for nonsense.

    One place, because "no setting" and "verify" must never be two different
    answers: a monitor written before the column existed verifies, and so does
    one whose setting somebody hand-edited into something this version does
    not know.
    """
    mode = ((tls or {}).get("mode") or VERIFY)
    return mode if mode in TLS_MODES else VERIFY


def split_tls(tls, kind, target):
    """This check's TLS decision, checked against what it can act on.

    Returns the blob to store, or None for "verify against the public roots".

    Every refusal here is about a setting that would be STORED AND IGNORED,
    which is the shape this package exists to remove: a monitor whose pasted
    certificate does nothing is a monitor whose owner believes it is trusted.
    """
    tls = dict(tls or {})
    mode = (tls.get("mode") or VERIFY).strip().lower()
    pem = (tls.get("certificate") or "").strip()
    expected = (tls.get("expected_name") or "").strip()

    if mode not in TLS_MODES:
        raise MonitoringError(
            f"'{mode}' is not a TLS setting. Available: "
            f"{', '.join(TLS_MODES)}.")
    if mode == VERIFY and not pem and not expected:
        # Nothing to store. NULL and "verify against the public roots" are
        # the same fact, and writing a blob that says so would make every
        # existing monitor differ from every new one for no reason.
        return None

    if kind == "tcp":
        raise MonitoringError(
            "A tcp check opens a socket and never sees a certificate, so a "
            "TLS setting on one would be stored and ignored.")
    if not (target or "").lower().startswith("https://"):
        raise MonitoringError(
            "A plain http check has no certificate to trust or to waive. "
            "Point this check at https://, or leave the TLS setting alone.")

    if mode == EXPIRY_ONLY and pem:
        raise MonitoringError(
            "Naming a certificate to trust and then not verifying it are "
            "opposite instructions. Pick one.")
    if expected and not pem:
        raise MonitoringError(
            "An expected certificate name only applies to a certificate this "
            "check was given to trust. Paste that certificate, or leave the "
            "name empty and the address is what the certificate has to name.")
    if expected and kind == BROWSER:
        # Measured, Chromium 151: a pinned key is accepted whatever name the
        # certificate carries — the same run answers 200 against a leaf that
        # names payments.internal reached at 127.0.0.1. A name typed here
        # would be stored and never consulted.
        raise MonitoringError(
            "A journey's browser trusts a certificate by its public key, "
            "whatever name it carries, so an expected name here would be "
            "stored and ignored.")

    out = {"mode": mode}
    if pem:
        out["certificate"] = _trusted_pem(pem)
    if expected:
        out["expected_name"] = _expected_name(expected)
    return out


def _trusted_pem(pem):
    """The pasted PEM, parsed and bounded. Raises with what is wrong with it.

    Parsed rather than stored as typed: a PEM that is not a certificate
    reaches the agent, fails to build a trust store there, and turns into a
    check that is down for a reason nobody looking at the form can see.
    """
    from cryptography import x509

    if len(pem.encode("utf-8", "replace")) > MAX_TLS_PEM_BYTES:
        raise MonitoringError(
            f"That certificate is over {MAX_TLS_PEM_BYTES // 1024}KB. Paste "
            f"the one authority that signed this endpoint, not a bundle.")
    if "PRIVATE KEY" in pem:
        # Said rather than quietly dropped: somebody who pasted a key has
        # pasted it into a form, a browser's history and this process's
        # memory, and the only useful sentence is the one that says so.
        raise MonitoringError(
            "That is a private key, not a certificate. Paste the "
            "certificate — and rotate the key you just pasted. Nothing was "
            "saved.")
    try:
        found = x509.load_pem_x509_certificates(pem.encode())
    except Exception as exc:
        raise MonitoringError(
            f"That is not a certificate in PEM form ({type(exc).__name__}). "
            f"It begins -----BEGIN CERTIFICATE-----.") from exc
    if not found:
        raise MonitoringError(
            "There is no certificate in what was pasted. It begins "
            "-----BEGIN CERTIFICATE-----.")
    if len(found) > MAX_TLS_CERTIFICATES:
        raise MonitoringError(
            f"That is {len(found)} certificates. At most "
            f"{MAX_TLS_CERTIFICATES} — an authority and its intermediates, "
            f"not a trust store.")
    return pem


def _expected_name(name):
    """The name the certificate has to carry, checked as a host name."""
    if len(name) > 253 or any(c.isspace() for c in name):
        raise MonitoringError(
            f"'{name[:60]}' is not a host name. It is the name the "
            f"certificate carries, for example payments.internal.")
    return name


def _sends(public, has_secrets):
    """What a check would put on the wire, named. Empty when it sends nothing.

    Asked about the REQUEST rather than about the secret box. Only six header
    names are sealed wherever they are typed; `X-Tenant-Token` typed into the
    plain header box is stored in the open, leaves `has_credentials` False,
    and still goes out on the wire — over the deliberately unverified channel,
    to whatever answered.
    """
    public = public or {}
    out = []
    headers = sorted(public.get("headers") or {})
    if headers:
        out.append(f"the {', '.join(headers)} header(s)")
    cookies = sorted(public.get("cookie_names") or ())
    if cookies:
        out.append(f"the {', '.join(cookies)} cookie(s)")
    auth = public.get("auth") or {}
    if auth.get("type") == "basic":
        # A username with no stored password still goes out as a real
        # Authorization header: `requests` prepares ('svc', '') as
        # `Basic c3ZjOg==`.
        out.append(f"basic authentication as '{auth.get('username')}'")
    elif auth.get("type") == "bearer":
        out.append("a bearer token")
    if has_secrets:
        out.append("its stored credentials")
    return out


def _credentials_in_address(*addresses):
    """The user name one of these URLs carries, or "".

    `https://svc:P4SS@host/` counts.

    The fourth channel, and the one that is in none of the others: a password
    typed into the ADDRESS is not in `secrets`, not in `request.headers` and
    not in `auth`, so a rule asked only about those says a check sends
    nothing while `requests` prepares `Authorization: Basic …` from the URL
    itself (`PreparedRequest.prepare_auth` falls back to
    `get_auth_from_url`). Measured: a monitor targeting
    `https://svc:P4SSW0RD@host/` saved as expiry_only sent
    `Basic c3ZjOlA0U1NXMFJE` over the connection it had deliberately not
    verified. The repository already knows targets carry passwords —
    `config_routes._without_password` exists for the audit row.

    A journey is asked about every `goto` it makes, not only its first: the
    address on the form is step one's, and step four is just as much a
    request this check makes.
    """
    from urllib.parse import urlsplit
    for address in addresses:
        try:
            parts = urlsplit(address or "")
        except ValueError:
            # An address this malformed is refused by `validate`; saying "no
            # credentials" here would be a claim about a string nobody parsed.
            continue
        if parts.username or parts.password:
            return parts.username or "the account in its address"
    return ""


def _addresses_of(kind, target, steps):
    """Every address this check will ask for, as configured.

    One place, because the http answer and the journey answer are not the
    same: a journey's target is its FIRST step's URL, and the rule below is
    about all of them.
    """
    if kind != BROWSER:
        return (target,)
    return tuple((step or {}).get("value") or ""
                 for step in (steps or ())
                 if (step or {}).get("kind") == "goto")


def _refuse_unverified_request(mode, kind, public, has_secrets, addresses=()):
    """A check that does not verify must send nothing. Both directions.

    Evaluated against the state the save WOULD LEAVE BEHIND rather than the
    row as it stands, because one submission can retarget a check, turn
    verification off and clear what it sends, and a rule that reads the
    current row refuses that save for a credential it is in the act of
    removing.
    """
    if mode != EXPIRY_ONLY:
        return
    account = _credentials_in_address(*addresses)
    if account:
        # Its own refusal rather than one more entry in `_sends`, because the
        # remedy is a different one: "Forget what this check sends" empties
        # the request and cannot touch the address, and a journey — which has
        # no such tick at all — carries this in the URL of its first step.
        raise MonitoringError(
            f"The address of this check carries credentials for "
            f"'{account}', and a check that does not verify the certificate "
            f"would send them to whatever answered. Take them out of the "
            f"address and put them in the credential boxes, or leave "
            f"verification on.")
    if kind == BROWSER:
        if has_secrets:
            raise MonitoringError(
                "This journey signs in, and a journey that does not verify "
                "the certificate types its password into whatever answered. "
                "Paste the certificate this endpoint presents — the browser "
                "will accept that key and no other — or remove the step that "
                "uses the secret.")
        return
    sending = _sends(public, has_secrets)
    if sending:
        raise MonitoringError(
            f"This check does not verify the certificate, so it is talking "
            f"to whatever answered — and it would still send "
            f"{'; '.join(sending)}. Tick 'Forget what this check sends' and "
            f"save, or leave verification on.")


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


#: "This save did not mention it", for a column whose stored value can also
#: be None. `tls=None` means "verify against the public roots"; leaving the
#: argument out means "keep whatever is there".
_KEEP = object()


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
               journey_secrets=None, tls=None):
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

        setting = split_tls(tls, kind, target)
        steps_rows = [x.as_dict() for x in steps] if steps else None
        _refuse_unverified_request(
            tls_mode(setting), kind, public, bool(secret),
            _addresses_of(kind, target, steps_rows))

        now = _now()
        row = {
            "id": str(uuid.uuid4()),
            "name": name, "kind": kind, "target": target,
            "interval_seconds": interval, "timeout_seconds": timeout,
            "assertions": assertions,
            "request": public,
            "secrets": self._seal(secret),
            "tls": setting,
            "steps": steps_rows,
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
               journey_secrets=None, tls=_KEEP, forget_request=False,
               **changes):
        """Change a check. `tls` left alone keeps the stored setting.

        A sentinel rather than None, because None is a value this column
        holds: it is what "verify against the public roots" is stored as, and
        a caller clearing the setting must not be indistinguishable from one
        that never mentioned it.
        """
        allowed = {"name", "kind", "target", "interval_seconds",
                   "timeout_seconds", "assertions", "labels", "enabled"}
        values = {k: v for k, v in changes.items() if k in allowed}
        # Read once, up front. Three branches below write `values['secrets']`
        # and two of them used to fetch this themselves; the TLS rule has to
        # be evaluated against what all of them leave behind, so there is one
        # `current` and one place that decides.
        current = self.get(monitor_id)
        if current is None:
            return None
        if steps is not None:
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
        moved = False
        if {"kind", "target", "interval_seconds", "timeout_seconds"} & set(values):
            kind, target, interval, timeout = self.validate(
                values.get("kind", current["kind"]),
                values.get("target", current["target"]),
                values.get("interval_seconds", current["interval_seconds"]),
                values.get("timeout_seconds", current["timeout_seconds"]))
            values.update(kind=kind, target=target,
                          interval_seconds=interval, timeout_seconds=timeout)
            moved = not may_follow(current["target"], target)
            if (steps is None and "secrets" not in values
                    and current["has_credentials"] and moved):
                # Not carried to a new destination: a blank box means "keep
                # it", and keeping it meant retargeting a check at a listener
                # collected its sealed headers, cookies and password without
                # any of them ever being shown. Rule 4 in store/secrets.py.
                values["secrets"] = None

        kind = values.get("kind", current["kind"])
        target = values.get("target", current["target"])
        if forget_request:
            if kind == BROWSER:
                raise MonitoringError(
                    "A journey's secrets are named by its steps, so forgetting "
                    "them would leave a step with nothing to type. Remove the "
                    "step that uses the secret, or paste the certificate this "
                    "journey should trust.")
            # The whole request, not only the sealed half. A header typed into
            # the plain box is stored in the open and still goes out on the
            # wire, so an escape that only emptied `secrets` would leave the
            # check sending exactly what the refusal was about.
            values["request"] = None
            values["secrets"] = None
        if tls is not _KEEP:
            values["tls"] = split_tls(tls, kind, target)
        if moved:
            # A certificate is pasted because THAT endpoint presents it, so it
            # does not follow the check to another host any more than a
            # password does. The MODE does: "do not verify" is a radio on the
            # form, part of every submission, and carries nothing anywhere.
            # Unlike a password, the certificate is shown on the form, so
            # pasting it again for the new host is one deliberate act rather
            # than a lost secret — and the save says it was dropped.
            after = dict((values["tls"] if "tls" in values
                          else current["tls"]) or {})
            # Both popped, never short-circuited: a name left behind with its
            # certificate removed is a setting `split_tls` refuses, and the
            # whole save would be refused with a message about a box nobody
            # touched.
            dropped = after.pop("certificate", None)
            dropped = after.pop("expected_name", None) or dropped
            if dropped:
                values["tls"] = split_tls(after, kind, target)

        after_request = (values["request"] if "request" in values
                         else current["request"])
        after_secrets = (bool(values["secrets"]) if "secrets" in values
                         else current["has_credentials"])
        after_tls = values["tls"] if "tls" in values else current["tls"]
        after_steps = (values["steps"] if "steps" in values
                       else current["steps"])
        _refuse_unverified_request(
            tls_mode(after_tls), kind, after_request, after_secrets,
            _addresses_of(kind, target, after_steps))
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
        """Pin a monitor to agents, refusing an agent that does not exist.

        It used to insert whatever it was handed — the schema declares no
        foreign keys — and `for_agent` reads "has an assignment" as "is
        pinned", so one row naming a dead agent is strictly worse than no
        row at all: it suppresses the fallback the comment there calls the
        useful default, and the monitor is enabled, listed on the page, and
        checked by nobody.

        Reachable through the product's own pages, measured: two agents, a
        monitor pinned to `singapore`, `singapore` deleted (which correctly
        switches the monitor off and clears its assignments), and then a
        first administrator's edit form — opened before the deletion, with
        `singapore` still ticked — saved. The monitor came back enabled,
        pinned to an agent that was gone, and ran nowhere.
        """
        wanted = list(dict.fromkeys(agent_ids or ()))
        if not wanted:
            return
        known = set(connection.execute(
            select(agents.c.id).where(agents.c.id.in_(wanted))).scalars())
        missing = [a for a in wanted if a not in known]
        if missing:
            raise MonitoringError(
                f"{'This agent is' if len(missing) == 1 else 'These agents are'}"
                f" no longer registered: {', '.join(sorted(missing))}. "
                f"Reload the page and choose from the agents that are.")
        connection.execute(insert(monitor_agents).values(
            [{"monitor_id": monitor_id, "agent_id": a} for a in wanted]))

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

        Raises `MonitoringError` when the box will not open. Returning {} on a
        changed key sent the agent a bearer block with no token and a journey
        with no secrets, so the target answered 401 and every authenticated
        check reported the TARGET as down — while the page still said the
        check has credentials, and editing it said the secret does not exist.
        The one thing anybody could act on, the server's key, was the one
        thing nothing said.
        """
        import json

        from .secrets import SecretsCorrupt, SecretsUnavailable

        with self._engine.connect() as connection:
            row = connection.execute(
                select(monitors.c.secrets).where(
                    monitors.c.id == monitor_id)).first()
        if not row or not row[0]:
            return {}
        try:
            # No `self._secrets is None` guard: see ChannelRepository —
            # the Store always hands a box in, and `SecretBox.open` says it
            # better for a keyless one. The single repository built without a
            # box (`ResultRepository.record`) only lists an agent's monitors
            # and never opens a secret.
            return json.loads(self._secrets.open(row[0]) or "{}")
        except (SecretsCorrupt, SecretsUnavailable) as exc:
            logger.error(f"could not read the credentials for {monitor_id}: "
                         f"{exc}")
            raise MonitoringError(str(exc)) from exc
        except Exception as exc:
            logger.error(f"could not read the credentials for {monitor_id}: "
                         f"{exc}")
            raise MonitoringError(
                f"This check's stored credentials could not be read "
                f"({type(exc).__name__}).") from exc

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
            #: This check's own TLS decision. Shown back in full, certificate
            #: included: a certificate is public, and the one question the
            #: form has to be able to answer is WHICH one this check trusts.
            #: `{}` reads as mode "verify" everywhere (see `tls_mode`).
            "tls": row["tls"] or {},
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


#: What a BIGINT column holds. JSON has no integer limit, so `10**30` is a
#: legal thing for an agent to send — and it type-checked, reached the INSERT
#: and raised there: OverflowError on SQLite, DataError on Postgres, neither
#: of them raised while the row was being built and neither in the per-result
#: guard. One such number took the whole batch, the endpoint answered 500 and
#: the agent retried it for ever. The type check alone was not enough; the
#: range is where a number stops being storable.
INT64 = 2 ** 63 - 1

#: What an `Integer` column holds, which is what `duration_us` actually is
#: (schema.py declares `Integer`, four bytes on Postgres). Bounding it to
#: INT64 checked it against a column it is not: measured on the lab Postgres,
#: `duration_us = 3_000_000_000` passed the guard, reached the INSERT and
#: raised `NumericValueOutOfRange` — outside the per-result try/except, which
#: wraps `_row` and not the insert, so all three results in the batch were
#: lost and the endpoint answered 500 to an agent that then retried it.
#:
#: SQLite stores it happily, so this was a fault on one dialect only — the
#: reason to name the column's real width rather than the widest integer
#: there is. INT32 is 35 minutes in microseconds, past every timeout this
#: product allows (120s for a check, 600s for a journey).
INT32 = 2 ** 31 - 1

#: What an HTTP status can be. RFC 9110: three digits, the first 1-5.
HTTP_STATUS_RANGE = (100, 599)


def _whole_number(value, low=-INT64 - 1, high=INT64):
    """An integer column's value, or None when it is not one the column takes.

    Not a string, not a dictionary, not a number too big for the column, and
    not an infinity — `json.loads` accepts `Infinity` and `NaN`, so both reach
    here from an ingest endpoint. Anything else costs the field rather than
    the measurement it came with.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = int(value)
    except (OverflowError, ValueError):
        # float('inf') and float('nan').
        return None
    return number if low <= number <= high else None


#: Largest certificate an agent may attach to a result. `_describe` builds ten
#: short fields — a few hundred bytes — and this is the backstop for an agent
#: that does not, the way `_steps_of` is for its steps. Measured before it: a
#: five-megabyte `tls` value was stored whole, in a JSON column, per result.
MAX_TLS_BYTES = 16 * 1024


def _certificate_of(monitor_id, result):
    """The certificate an agent attached, trimmed to what is storable."""
    tls = result.get("tls")
    if not isinstance(tls, dict) or not tls:
        return None
    if len(json.dumps(tls, default=str)) > MAX_TLS_BYTES:
        logger.warning(f"monitor {monitor_id} sent a certificate over "
                       f"{MAX_TLS_BYTES // 1024}KB; it was not kept")
        return None
    return tls


class ResultRepository:
    def __init__(self, engine):
        self._engine = engine

    def record(self, agent_id, results):
        """Store a batch. Returns how many were kept.

        Results for monitors this agent is not assigned are DROPPED rather
        than stored: an ingest endpoint that accepts anything is a way to
        paint the whole board green, and a compromised agent should be able to
        lie about its own checks and nothing else.

        One unreadable result costs itself and nothing else. Everything here
        arrives over an ingest endpoint, so every field is a claim rather than
        a value: a `started_at` that is not a time, a `monitor_id` that is a
        list, a result that is not even a dictionary used to raise out of the
        loop — the endpoint answered 500, the agent kept the batch and sent it
        again, and each attempt left the good results' screenshots behind
        because those were stored before the rows were built. Measured: three
        results, a bad one last, stored 0 results and 2 more orphan images per
        attempt, for ever.

        The same loop, twice over: a `duration_us` of `10**30` is legal JSON
        and the right TYPE, so it passed the guard and raised at the INSERT
        instead — OverflowError on SQLite, DataError on Postgres — which is
        neither in the guard nor inside it. Measured through the endpoint:
        HTTP 500, 0 results and 3 more orphan images per attempt. Fields are
        bounded to what the column holds, the guard catches everything, and
        the images go in after the rows they belong to.
        """
        if not results:
            return 0

        allowed = {m["id"] for m in MonitorRepository(self._engine)
                   .for_agent(agent_id)}
        received = _now()
        with self._engine.begin() as connection:
            rows, images = [], []
            for result in results:
                try:
                    row = self._row(agent_id, result, allowed, received)
                except Exception as exc:
                    # Every exception, not a list of the four that were
                    # measured: this is an ingest endpoint, the next agent to
                    # be modified will find a fifth, and the whole point of
                    # the guard is that finding one costs its own result.
                    logger.warning(
                        f"agent {agent_id} sent a result that could not be "
                        f"read ({type(exc).__name__}: {exc}); it was skipped")
                    continue
                if row is None:
                    continue
                # Read and checked now, stored after the rows are in: an
                # image kept for a row that never arrives is a megabyte
                # nothing points at.
                image = self._screenshot_row(row["monitor_id"], result)
                row["screenshot_id"] = image["id"] if image else None
                if image:
                    images.append(image)
                rows.append(row)
            if not rows:
                return 0
            # Chunked. A single multi-VALUES insert binds twelve parameters
            # per row, and SQLite refuses the statement past its limit —
            # "too many SQL variables", which says nothing about the batch
            # being too big. The endpoint caps at 500, so the live path never
            # reached it; this is a public repository method, and a caller
            # passing a day's backlog should get a working insert rather than
            # a dialect error.
            for start in range(0, len(rows), INSERT_CHUNK):
                connection.execute(
                    insert(monitor_results).values(rows[start:start + INSERT_CHUNK]))
            # AFTER the rows, in the same transaction. Before them it was not
            # in the same transaction at all on SQLite, whatever the savepoint
            # said: pysqlite emits no BEGIN of its own, so a SAVEPOINT that is
            # the first statement in the block opens a transaction of its own
            # and RELEASE commits it — measured, the image survived the
            # rollback of the block it was written in, and every retry of a
            # batch that could not store left another copy of it behind.
            for image in images:
                self._keep_screenshot(connection, image)
        return len(rows)

    def _row(self, agent_id, result, allowed, received):
        """One result as a row, or None when this agent may not report it.

        Raises on anything it cannot read — a `started_at` that is not a time
        raises ValueError, and the next agent somebody modifies will find a
        kind nobody listed — which the caller turns into "this one is
        skipped". Every value that reaches a column is bounded HERE rather
        than at the INSERT, because an INSERT that refuses one row refuses the
        whole batch with it.
        """
        monitor_id = result.get("monitor_id")
        if not isinstance(monitor_id, str) or monitor_id not in allowed:
            logger.warning(
                f"agent {agent_id} reported for monitor {monitor_id!r}, "
                f"which it does not run")
            return None

        started = result.get("started_at")
        if isinstance(started, str):
            started = datetime.fromisoformat(started.replace("Z", "+00:00"))
        elif not isinstance(started, datetime):
            # A number, a dictionary, nothing at all: the one time we know is
            # ours, and `received_at` beside it says it is not the agent's.
            started = None
        return {
            "monitor_id": monitor_id,
            "agent_id": agent_id,
            "started_at": started or received,
            "received_at": received,
            "status": "down" if result.get("status") == "down" else "up",
            "duration_us": self._number(agent_id, monitor_id, result,
                                        "duration_us", -INT32 - 1, INT32),
            # `str` before the slice: an error that arrived as a dictionary
            # raised TypeError on the slice and took the whole batch with it.
            "error": str(result.get("error") or "")[:2000] or None,
            "http_status": self._number(agent_id, monitor_id, result,
                                        "http_status", *HTTP_STATUS_RANGE),
            "tls": _certificate_of(monitor_id, result),
            #: A claim like every other field here, so only a real boolean is
            #: kept: an agent that sends "yes" says nothing, and NULL already
            #: means "this run does not say".
            "handshake_verified": (result["handshake_verified"]
                                   if isinstance(result.get("handshake_verified"),
                                                 bool) else None),
            "steps": _steps_of(result),
        }

    @staticmethod
    def _number(agent_id, monitor_id, result, field, low=-INT64 - 1,
                high=INT64):
        """One numeric field, and a line when it had to be dropped.

        Said rather than silently blanked: every other discard in `record`
        logs — an unreadable result, a monitor this agent does not run, an
        oversized certificate — and a duration that arrives as `"ages"` used
        to reach the page as an empty cell with nothing anywhere saying why.
        """
        raw = result.get(field)
        number = _whole_number(raw, low, high)
        if number is None and raw is not None:
            logger.warning(
                f"agent {agent_id} sent monitor {monitor_id} a {field} that "
                f"is not a number this column holds ({raw!r:.80}); the field "
                f"is blank and the rest of the result was kept")
        return number

    def _screenshot_row(self, monitor_id, result):
        """The failure screenshot as a row, if the agent sent one usable.

        Returns the row, with the id the result will point at, or None. Never
        raises: a picture that could not be decoded must not cost the result
        it came with — the fact that the journey failed is the part somebody
        needs.
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
        return {
            "id": str(uuid.uuid4()), "monitor_id": monitor_id,
            "captured_at": _now(),
            "content_type": kind[0],
            "bytes": len(image), "image": image,
        }

    @staticmethod
    def _keep_screenshot(connection, image):
        """Store one image beside the row that already points at it.

        On a savepoint, which here is inside a transaction that has already
        written: an image that will not store must not cost the results it
        came with, and on Postgres a failed statement poisons the transaction
        it is in unless it is rolled back to one. When it does fail, the
        result stops pointing at a picture nobody can fetch.
        """
        try:
            with connection.begin_nested():
                connection.execute(insert(journey_screenshots).values(**image))
        except Exception as exc:
            logger.warning(f"could not store a screenshot: {exc}")
            connection.execute(
                update(monitor_results)
                .where(monitor_results.c.screenshot_id == image["id"])
                .values(screenshot_id=None))

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
