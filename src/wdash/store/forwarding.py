"""
Shipping the audit trail somewhere else.

The database stays authoritative and doubles as the queue. Every row carries a
`forwarded_at`, and forwarding is a sweep over the rows that do not have one
yet. That shape is chosen over an in-memory queue for two reasons:

  * **History is shippable.** Point WDash at a Splunk instance today and the
    entries from before today go too, because "not forwarded" is a fact stored
    per row rather than a thing that only existed while the process was up.
  * **A restart loses nothing.** An in-memory queue drops whatever it held,
    and the rows it dropped look identical to rows that were delivered.

Delivery is at-least-once, never at-most-once. If a batch is written to Splunk
and the process dies before the rows are marked, the batch goes again on the
next sweep. Duplicated audit entries are a nuisance; missing ones are the
failure this whole subsystem exists to prevent, so the choice is not close.

Sinks are deliberately small and dependency-free — an HTTP POST each. Anything
richer (retry policies, backpressure, batching strategy) belongs in the
collector on the other end, which every one of these destinations already has.
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select, update

from .schema import audit

logger = logging.getLogger(__name__)

#: How many rows one sweep ships. Bounded so a first run against months of
#: history does not build one request the far end refuses.
BATCH = 500


class SinkError(RuntimeError):
    """A destination refused a batch. The rows stay unforwarded."""


class Sink:
    """Somewhere audit entries go."""

    name = "sink"

    def send(self, entries):
        """Deliver a batch. Raise `SinkError` to leave the rows unmarked."""
        raise NotImplementedError


class SplunkSink(Sink):
    """Splunk's HTTP Event Collector.

    One JSON object per event, concatenated — HEC's own format, which is not
    JSON lines and not a JSON array. Getting this wrong produces a 400 that
    reads like an authentication problem.
    """

    name = "splunk"

    def __init__(self, url, token, index=None, source="wdash",
                 verify_certs=True, timeout=15, session=None):
        self._url = url.rstrip("/")
        self._token = token
        self._index = index
        self._source = source
        self._verify = verify_certs
        self._timeout = timeout
        self._session = session

    def _http(self):
        if self._session is not None:
            return self._session
        import requests
        return requests

    def send(self, entries):
        payload = "".join(
            json.dumps({
                # HEC wants epoch seconds. An ISO string here is accepted and
                # then silently indexed as the time of receipt, so every event
                # arrives stamped with when the sweep ran rather than when it
                # happened.
                "time": _epoch(entry["at"]),
                "host": "wdash",
                "source": self._source,
                "sourcetype": "_json",
                **({"index": self._index} if self._index else {}),
                "event": _serialisable(entry),
            }) for entry in entries)

        try:
            response = self._http().post(
                f"{self._url}/services/collector/event",
                data=payload.encode("utf-8"),
                headers={"Authorization": f"Splunk {self._token}",
                         "Content-Type": "application/json"},
                timeout=self._timeout, verify=self._verify)
        except Exception as exc:
            raise SinkError(f"Splunk is unreachable: {exc}") from exc

        if response.status_code >= 400:
            raise SinkError(
                f"Splunk answered HTTP {response.status_code}: "
                f"{response.text[:200]}")


class ElasticsearchSink(Sink):
    """An Elasticsearch index, through the bulk API.

    A separate cluster from the one WDash reads logs from, usually — the point
    of shipping the trail off the box is that it survives the box.
    """

    name = "elasticsearch"

    def __init__(self, url, index="wdash-audit", username=None, password=None,
                 verify_certs=True, timeout=15, session=None):
        self._url = url.rstrip("/")
        self._index = index
        self._auth = (username, password) if username and password else None
        self._verify = verify_certs
        self._timeout = timeout
        self._session = session

    def _http(self):
        if self._session is not None:
            return self._session
        import requests
        return requests

    def send(self, entries):
        lines = []
        for entry in entries:
            # The row id as the document id, so a re-sent batch overwrites
            # rather than duplicating. Delivery is at-least-once by design;
            # this is what keeps at-least-once from meaning "eventually many".
            lines.append(json.dumps(
                {"index": {"_index": self._index, "_id": str(entry["id"])}}))
            lines.append(json.dumps(_serialisable(entry)))
        payload = "\n".join(lines) + "\n"

        try:
            response = self._http().post(
                f"{self._url}/_bulk", data=payload.encode("utf-8"),
                headers={"Content-Type": "application/x-ndjson"},
                auth=self._auth, timeout=self._timeout, verify=self._verify)
        except Exception as exc:
            raise SinkError(f"Elasticsearch is unreachable: {exc}") from exc

        if response.status_code >= 400:
            raise SinkError(
                f"Elasticsearch answered HTTP {response.status_code}: "
                f"{response.text[:200]}")

        # A 200 from _bulk says the request was accepted, not that the
        # documents were. `errors: true` with a 200 is the standard way to
        # lose data while believing it was written.
        try:
            body = response.json()
        except Exception:
            return
        if body.get("errors"):
            first = next((item for item in body.get("items", [])
                          if item.get("index", {}).get("error")), {})
            raise SinkError(
                f"Elasticsearch rejected part of the batch: "
                f"{first.get('index', {}).get('error')}")


class AuditForwarder:
    """Walks unforwarded rows into a sink."""

    def __init__(self, engine, sink):
        self._engine = engine
        self._sink = sink

    def pending(self):
        """How many rows are still waiting. For the configuration screen."""
        from sqlalchemy import func
        try:
            with self._engine.connect() as connection:
                return connection.execute(
                    select(func.count()).select_from(audit)
                    .where(audit.c.forwarded_at.is_(None))).scalar() or 0
        except Exception as exc:
            logger.error(f"Could not count unforwarded audit rows: {exc}")
            return 0

    def sweep(self, batch=BATCH):
        """Ship one batch. Returns how many rows were delivered.

        Rows are marked only after the sink accepts them. The other order —
        mark, then send — turns any failure into permanent silent loss, which
        is precisely what an audit trail must not do.
        """
        try:
            with self._engine.connect() as connection:
                rows = connection.execute(
                    select(audit)
                    .where(audit.c.forwarded_at.is_(None))
                    .order_by(audit.c.id)
                    .limit(batch)).mappings().all()
        except Exception as exc:
            logger.error(f"Could not read unforwarded audit rows: {exc}")
            return 0

        if not rows:
            return 0

        entries = [dict(row) for row in rows]
        self._sink.send(entries)          # raises SinkError; rows stay unmarked

        identifiers = [entry["id"] for entry in entries]
        with self._engine.begin() as connection:
            connection.execute(
                update(audit).where(audit.c.id.in_(identifiers))
                .values(forwarded_at=datetime.now(timezone.utc)))
        return len(identifiers)

    def drain(self, limit=50, batch=BATCH):
        """Sweep until nothing is left, or `limit` batches have gone.

        Bounded, because "until empty" against months of backlog is an
        unbounded loop holding a database connection.
        """
        total = 0
        for _ in range(limit):
            shipped = self.sweep(batch=batch)
            total += shipped
            if shipped < batch:
                break
        return total


def build_sink(settings, credential, session=None):
    """Turn stored settings into a sink, or None when forwarding is off."""
    if not settings or not settings.get("enabled"):
        return None

    kind = settings.get("kind")
    if kind == "splunk":
        if not settings.get("url") or not credential:
            raise ValueError("Splunk forwarding needs a URL and an HEC token.")
        return SplunkSink(
            url=settings["url"], token=credential,
            index=settings.get("index") or None,
            verify_certs=settings.get("verify_certs", True), session=session)

    if kind == "elasticsearch":
        if not settings.get("url"):
            raise ValueError("Elasticsearch forwarding needs a URL.")
        return ElasticsearchSink(
            url=settings["url"], index=settings.get("index") or "wdash-audit",
            username=settings.get("username") or None, password=credential,
            verify_certs=settings.get("verify_certs", True), session=session)

    raise ValueError(f"Unknown audit destination: {kind}")


def _epoch(moment):
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _serialisable(entry):
    """A row as JSON-safe values, with the queue bookkeeping left behind."""
    out = {}
    for key, value in entry.items():
        if key == "forwarded_at":
            continue          # our bookkeeping, not the receiver's business
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
        else:
            out[key] = value
    return out
