"""
Configured data sources.

A source is a connection to somewhere telemetry lives. Adding one from a web
form means the server will make requests to an address a user typed, so this
module carries the validation as well as the storage — the two belong together
because a source that fails validation must never reach the database, let alone
the hub.

Credentials are stored encrypted and never returned. The config page shows
whether a password is set, and offers to replace it; it cannot show it. A
settings screen that renders stored credentials is an exfiltration endpoint for
anyone who reaches an administrator session, which is a much lower bar than
reaching the database.
"""

import ipaddress
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select

from .schema import sources

#: Source kinds and the fields each needs. `secret_fields` are encrypted and
#: never read back out; everything else is plain configuration.
SOURCE_KINDS = {
    "elasticsearch": {
        "label": "Elasticsearch",
        # `monitors` is the synthetic-check signal: Heartbeat and the Fleet
        # Synthetics integration write into the same cluster, and a third
        # index pattern is all that separates them from logs and traces.
        "signals": ("logs", "traces", "monitors"),
        # Shared across every signal this source serves.
        "fields": ("url", "username", "verify_certs"),
        # Per signal, because one cluster holding both needs a different
        # pattern for each — flattened into one key, a trace search scans the
        # log indices.
        "signal_fields": ("index_patterns", "exclude_patterns"),
        "secret_fields": ("password",),
        "required": ("url",),
    },
    "loki": {
        "label": "Grafana Loki",
        "signals": ("logs",),
        # `stream_label` is required in spirit: LogQL cannot express "every
        # stream", so something has to name what a container is. It defaults
        # rather than being mandatory because service_name is what almost every
        # pipeline sets.
        "fields": ("url", "username", "tenant", "stream_label", "verify_certs"),
        "secret_fields": ("password",),
        "required": ("url",),
    },
    "jaeger": {
        "label": "Jaeger",
        # Traces only. Jaeger v2 receives OTLP logs too, but it stores and
        # serves traces; claiming logs would offer a screen that answers
        # nothing.
        "signals": ("traces",),
        "fields": ("url", "username", "tenant", "verify_certs"),
        "secret_fields": ("password",),
        "required": ("url",),
    },
    "tempo": {
        "label": "Grafana Tempo",
        "signals": ("traces",),
        "fields": ("url", "username", "tenant", "verify_certs"),
        "secret_fields": ("password",),
        "required": ("url",),
    },
    "victorialogs": {
        "label": "VictoriaLogs",
        "signals": ("logs",),
        # `stream_field` plays the part Loki's stream_label does: it names
        # what a container is, so a role has something to be granted. The
        # default is `service` because that is what most pipelines write, and
        # it must be one of the stream fields the data was ingested with or
        # every query becomes a full scan.
        "fields": ("url", "username", "tenant", "stream_field", "verify_certs"),
        "secret_fields": ("password",),
        "required": ("url",),
    },
}

ALLOWED_SCHEMES = ("http", "https")


class SourceError(ValueError):
    """A source definition that cannot be stored or connected to."""


def validate_url(url, allow_link_local=False):
    """Check a source URL before the server is ever asked to fetch it.

    Two things are refused:

    * anything that is not http or https — `file://` and friends turn "add a
      source" into "read a file off the server"
    * link-local addresses, which is where cloud instance metadata lives.
      169.254.169.254 is the canonical server-side request forgery target: it
      hands out instance credentials to anything that can ask.

    Private and loopback addresses are deliberately ALLOWED. Elasticsearch and
    Loki live on internal networks essentially always, and blocking them would
    make the feature useless while providing no real protection — an operator
    who can configure sources can already reach those hosts.
    """
    url = (url or "").strip()
    if not url:
        raise SourceError("A URL is required.")

    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SourceError(
            f"Only {' and '.join(ALLOWED_SCHEMES)} URLs are supported.")
    if not parsed.hostname:
        raise SourceError("The URL has no host.")

    if allow_link_local:
        return url

    try:
        resolved = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        # Unresolvable now does not mean unresolvable later (DNS, startup
        # ordering, a host that is not up yet). Storing it is fine; the
        # connection test is where the operator finds out.
        return url

    for entry in resolved:
        address = ipaddress.ip_address(entry[4][0])
        if address.is_link_local:
            raise SourceError(
                f"{parsed.hostname} resolves to a link-local address "
                f"({address}). That is where cloud instance metadata lives, "
                f"and WDash will not fetch from it.")
    return url


def normalise_signals(kind, signals):
    """The signals a source serves, checked against what the kind can do.

    Accepts a single string as well as a list, because one source used to mean
    one signal and every existing caller passes a string.
    """
    if isinstance(signals, str):
        signals = [signals]
    wanted = [s for s in (signals or ()) if s]
    if not wanted:
        raise SourceError("A source has to serve at least one signal.")

    definition = SOURCE_KINDS.get(kind)
    if definition is None:
        raise SourceError(f"Unknown source type: {kind}")

    for signal in wanted:
        if signal not in definition["signals"]:
            raise SourceError(
                f"{definition['label']} cannot serve {signal}. "
                f"It serves: {', '.join(definition['signals'])}.")

    # Ordered by the kind's own declaration rather than by what the form
    # happened to submit, so two identical sources compare equal.
    return [s for s in definition["signals"] if s in wanted]


def validate(kind, signals, config):
    """Check a source definition. Returns the cleaned config."""
    if kind not in SOURCE_KINDS:
        raise SourceError(f"Unknown source type: {kind}")

    definition = SOURCE_KINDS[kind]
    normalise_signals(kind, signals)

    cleaned = {}
    for field in definition["fields"]:
        value = config.get(field)
        if field.endswith("_patterns"):
            if isinstance(value, str):
                value = [p.strip() for p in value.split(",") if p.strip()]
            cleaned[field] = list(value or [])
        elif field == "verify_certs":
            cleaned[field] = bool(value)
        elif field == "stream_label":
            cleaned[field] = (value or "").strip() or "service_name"
        else:
            cleaned[field] = (value or "").strip() if isinstance(value, str) else value

    for field in definition["required"]:
        if not cleaned.get(field):
            raise SourceError(f"{field} is required for {definition['label']}.")

    cleaned["url"] = validate_url(cleaned.get("url"))

    # Per-signal settings, kept in their own block. An Elasticsearch cluster
    # holding both signals needs a different index pattern for each, and
    # flattening them into one key is how a trace search ends up scanning the
    # log indices.
    for signal in normalise_signals(kind, signals):
        block = config.get(signal)
        if not isinstance(block, dict):
            continue
        cleaned[signal] = {
            field: ([p.strip() for p in block[field].split(",") if p.strip()]
                    if isinstance(block.get(field), str)
                    else list(block.get(field) or []))
            for field in definition.get("signal_fields", ())
            if field in block
        }
    return cleaned


class SourceRepository:
    def __init__(self, engine, secret_box=None):
        self._engine = engine
        self._secrets = secret_box

    def all(self, signal=None, enabled_only=False):
        with self._engine.connect() as connection:
            query = select(sources).order_by(sources.c.name)
            rows = connection.execute(query).mappings().all()
        out = [self._public(row) for row in rows
               if not enabled_only or row["enabled"]]
        if signal is None:
            return out
        return [row for row in out if signal in row["signals"]]

    def get(self, source_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(sources).where(sources.c.id == source_id)).mappings().first()
        return self._public(row) if row else None

    @staticmethod
    def _public(row):
        """Everything except the credential."""
        # `signals` is authoritative; `signal` is carried so a reader written
        # before the column existed still works, and is always the first entry
        # rather than a second answer to the same question.
        signals = row["signals"] or [row["signal"]]
        return {
            "id": row["id"], "name": row["name"],
            "signals": list(signals), "signal": signals[0],
            "kind": row["kind"], "config": row["config"] or {},
            "enabled": row["enabled"],
            # Whether one is set is all a caller needs; the value never leaves.
            "has_secret": bool(row["secrets"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def credential(self, source_id):
        """Decrypt a stored credential. For building a client, not for display."""
        with self._engine.connect() as connection:
            row = connection.execute(
                select(sources.c.secrets).where(sources.c.id == source_id)).first()
        if not row or not row[0]:
            return None
        if self._secrets is None:
            raise SourceError("No secret box configured for this store.")
        return self._secrets.open(row[0])

    def create(self, name, signal, kind, config, secret=None, enabled=True):
        signals = normalise_signals(kind, signal)
        cleaned = validate(kind, signals, config)
        record = {
            "id": str(uuid.uuid4()), "name": (name or "").strip(),
            # The legacy column stays populated because it is NOT NULL. It is
            # never read back.
            "signal": signals[0], "signals": signals,
            "kind": kind, "config": cleaned,
            "secrets": self._seal(secret), "enabled": bool(enabled),
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        if not record["name"]:
            raise SourceError("A name is required.")
        try:
            with self._engine.begin() as connection:
                connection.execute(sources.insert().values(**record))
        except Exception as exc:
            if "UNIQUE" in str(exc) or "duplicate" in str(exc).lower():
                raise SourceError(
                    f"A source called '{record['name']}' already exists."
                ) from exc
            raise SourceError(str(exc)) from exc
        return self.get(record["id"])

    def update(self, source_id, name=None, config=None, secret=None,
               enabled=None, clear_secret=False, signals=None):
        existing = self.get(source_id)
        if existing is None:
            return None

        changes = {"updated_at": datetime.now(timezone.utc)}
        if name is not None:
            changes["name"] = name.strip()
        if signals is not None:
            changes["signals"] = normalise_signals(existing["kind"], signals)
            changes["signal"] = changes["signals"][0]
        if config is not None:
            changes["config"] = validate(
                existing["kind"],
                changes.get("signals") or existing["signals"], config)
        if enabled is not None:
            changes["enabled"] = bool(enabled)

        # A blank credential field means "leave it alone", not "delete it".
        # Treating blank as deletion means anybody who saves this form without
        # retyping the password silently breaks the connection.
        if secret:
            changes["secrets"] = self._seal(secret)
        elif clear_secret:
            changes["secrets"] = None

        with self._engine.begin() as connection:
            connection.execute(
                sources.update().where(sources.c.id == source_id).values(**changes))
        return self.get(source_id)

    def delete(self, source_id):
        with self._engine.begin() as connection:
            result = connection.execute(
                sources.delete().where(sources.c.id == source_id))
        return result.rowcount > 0

    def _seal(self, secret):
        if not secret:
            return None
        if self._secrets is None:
            raise SourceError("No secret box configured for this store.")
        return self._secrets.seal(secret)
