"""
Elastic Heartbeat and Synthetics, as a neutral monitor source.

Everything in here was derived from documents a real Heartbeat 8.19 wrote into
a real cluster, not from the reference. The two differ in ways that decide
whether the page is right:

  * **`monitor.status` and `summary.status` are different fields.** The first
    is the outcome of one attempt; the second is the outcome of the retry
    group. A monitor configured with `max_attempts: 2` that fails once and
    succeeds writes `monitor.status: down` on the first document and
    `summary.status: up` on the last. Reading the wrong one reports flapping
    that the operator deliberately configured away.

  * **`summary` is absent from intermediate attempts.** Filtering on
    `exists: summary.status` is what separates "the result of a check" from
    "one attempt inside a check". Without it the same check is counted twice.

  * **The certificate is in two places.** `tls.certificate_not_valid_after` is
    the older flat field, `tls.server.x509.not_after` the ECS one; both are
    written. Only the second carries the issuer, the key size and the
    fingerprint, so that is the one read here, with the flat field as a
    fallback for older agents.

  * **Browser monitors are not covered.** `monitor.type: browser` writes
    journey and step documents in a shape this adapter has never seen, and
    guessing it would produce a page that looks complete and is wrong. They
    are reported as monitors with their summary status — which is real — and
    the per-step detail is left for when it can be measured.
"""

from datetime import datetime, timezone

from ..models import (
    DOWN, UNKNOWN, UP, Certificate, Monitor, MonitorCheck, MonitorPage,
    SourceRef,
)
from ..source import Capability, MonitorSource

#: Where Heartbeat and the Fleet-managed Synthetics integration write.
DEFAULT_PATTERNS = ("heartbeat-*", "synthetics-*")

#: How many monitors a listing will return. A deployment with more than this
#: has a naming problem rather than a paging problem, but the cap keeps one
#: aggregation from trying to hold everything in memory.
MAX_MONITORS = 500

#: How many past checks a history returns.
MAX_HISTORY = 500


def _parse_time(value):
    """Elasticsearch timestamps, with the Z that fromisoformat used to refuse."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _dig(document, path, default=None):
    """`a.b.c` through nested mappings, tolerating a missing branch.

    Duck-typed on `.get` rather than checked with `isinstance(x, dict)`,
    because the top level of a response is elasticsearch-py's
    `ObjectApiResponse`: it subscripts and `.get`s like a dictionary, and is
    neither a `dict` nor a `Mapping`. An isinstance check therefore returned
    the default for EVERY path starting at the response — the listing came
    back empty against a cluster with six monitors in it, and empty is what
    "no monitors configured" looks like.

    A fake that hands back a plain dict cannot reproduce that. This one was
    found by pointing the adapter at a real cluster.
    """
    current = document
    for part in path.split("."):
        getter = getattr(current, "get", None)
        if getter is None:
            return default
        current = getter(part, _MISSING)
        if current is _MISSING:
            return default
    return current


#: A sentinel, so a stored `None` is told apart from an absent key.
_MISSING = object()


def _status(source):
    """Up, down, or an honest unknown.

    `summary.status` first: it is the result of the whole retry group, which
    is what the operator configured. `monitor.status` is one attempt, and a
    single failed attempt inside a check that ultimately succeeded is not an
    outage.
    """
    value = _dig(source, "summary.status") or _dig(source, "monitor.status")
    if value in (UP, DOWN):
        return value
    return UNKNOWN


def _certificate(source):
    """The TLS certificate, or None for a check that saw none."""
    x509 = _dig(source, "tls.server.x509") or {}
    not_after = _parse_time(x509.get("not_after")
                            or _dig(source, "tls.certificate_not_valid_after"))
    if not_after is None:
        return None
    return Certificate(
        common_name=(_dig(x509, "subject.common_name")
                     or _dig(x509, "subject.distinguished_name") or ""),
        issuer=(_dig(x509, "issuer.common_name")
                or _dig(x509, "issuer.distinguished_name") or ""),
        not_before=_parse_time(x509.get("not_before")
                               or _dig(source, "tls.certificate_not_valid_before")),
        not_after=not_after,
        fingerprint=_dig(source, "tls.server.hash.sha256") or "",
        key_algorithm=x509.get("public_key_algorithm") or "",
        key_size=int(x509.get("public_key_size") or 0),
        key_curve=x509.get("public_key_curve") or "",
        signature_algorithm=x509.get("signature_algorithm") or "",
        serial_number=str(x509.get("serial_number") or ""),
    )


class ElasticsearchMonitorSource(MonitorSource):
    """Reads what Heartbeat writes. Never writes anything itself."""

    backend = "elasticsearch"

    def __init__(self, client, name="elasticsearch-monitors",
                 patterns=DEFAULT_PATTERNS, catalogue=None):
        self._es = client
        self.name = name
        self._patterns = tuple(patterns) or DEFAULT_PATTERNS
        self._catalogue = catalogue

    @property
    def capabilities(self):
        return frozenset({Capability.MONITOR_LIST, Capability.MONITOR_HISTORY,
                          Capability.TLS_CERTIFICATES, Capability.RAW_DOCUMENT})

    def health(self):
        try:
            if self._es.ping():
                return True, "ok"
            return False, "ping failed: no response from the cluster"
        except Exception as exc:
            return False, str(exc)

    def containers(self, scope):
        """The indices this source reads.

        Deliberately NOT filtered through the log scope. A role's index
        patterns are about log data; applying them here would hide the
        monitors from everybody whose scope happens not to mention
        `heartbeat-*`, which is everybody. Monitor visibility is a permission
        (`monitors:read`), enforced at the route.
        """
        return list(self._patterns)

    # ---------- reading ----------

    def _search(self, body):
        from .elasticsearch import _search
        return _search(self._es, ",".join(self._patterns), body,
                       timeout="30s", ignore_unavailable=True,
                       allow_no_indices=True)

    @staticmethod
    def _window_filter(window):
        return {"range": {"@timestamp": {
            "gte": window.start.isoformat(), "lte": window.end.isoformat()}}}

    def _summaries_only(self, window):
        """Checks, not attempts.

        `summary.status` exists only on the last document of a retry group, so
        this is what makes one check count once.
        """
        return {"bool": {"filter": [
            self._window_filter(window),
            {"exists": {"field": "summary.status"}},
        ]}}

    def monitors(self, window, scope):
        body = {
            "size": 0,
            "query": self._summaries_only(window),
            "aggs": {"monitors": {
                "terms": {"field": "monitor.id", "size": MAX_MONITORS},
                # One document per monitor: the most recent check. A terms
                # aggregation alone would give counts, and a count cannot say
                # whether the thing is up NOW.
                "aggs": {"latest": {"top_hits": {
                    "size": 1, "sort": [{"@timestamp": {"order": "desc"}}]}}},
            }},
        }
        try:
            response = self._search(body)
        except Exception as exc:
            return MonitorPage(partial=True, sources=(self.name,),
                               warnings=(f"{self.name}: {exc}",))

        buckets = _dig(response, "aggregations.monitors.buckets") or []
        monitors = []
        for bucket in buckets:
            hits = _dig(bucket, "latest.hits.hits") or []
            if not hits:
                continue
            monitors.append(self._to_monitor(hits[0]))

        # Down first, then by name: a list sorted by id puts the one thing
        # that needs attention wherever the alphabet happens to place it.
        monitors.sort(key=lambda m: (m.status != DOWN, m.name.lower(), m.id))

        page = MonitorPage(monitors=monitors, sources=(self.name,))
        if len(buckets) >= MAX_MONITORS:
            page.warnings = (
                f"{self.name}: showing the first {MAX_MONITORS} monitors.",)
        return page

    def _to_monitor(self, hit):
        source = hit.get("_source") or {}
        duration = _dig(source, "monitor.duration.us")
        return Monitor(
            id=_dig(source, "monitor.id") or "",
            name=_dig(source, "monitor.name") or _dig(source, "monitor.id") or "",
            type=(_dig(source, "monitor.type") or "").lower(),
            url=_dig(source, "url.full") or "",
            status=_status(source),
            checked_at=_parse_time(source.get("@timestamp")),
            duration_ms=(duration / 1000.0) if duration is not None else None,
            error=_dig(source, "error.message") or "",
            tags=tuple(source.get("tags") or ()),
            certificate=_certificate(source),
            source=self.name,
            ref=SourceRef(backend=self.backend, container=hit.get("_index", ""),
                          id=hit.get("_id", "")),
        )

    def history(self, monitor_id, window, scope):
        body = {
            "size": MAX_HISTORY,
            "query": {"bool": {"filter": [
                self._window_filter(window),
                {"exists": {"field": "summary.status"}},
                {"term": {"monitor.id": monitor_id}},
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["@timestamp", "summary.status", "monitor.status",
                        "monitor.duration.us", "error.message"],
        }
        try:
            response = self._search(body)
        except Exception:
            return []

        checks = []
        for hit in _dig(response, "hits.hits") or []:
            source = hit.get("_source") or {}
            duration = _dig(source, "monitor.duration.us")
            checks.append(MonitorCheck(
                timestamp=_parse_time(source.get("@timestamp")),
                status=_status(source),
                duration_ms=(duration / 1000.0) if duration is not None else None,
                error=_dig(source, "error.message") or ""))
        # Oldest first: a chart reads left to right.
        checks.reverse()
        return checks

    def certificates(self, window, scope):
        """Every monitor that saw a certificate, its certificate attached.

        Built from the monitor listing rather than from a separate query, so
        the two screens cannot disagree about what is on the wire.
        """
        page = self.monitors(window, scope)
        with_certificates = [m for m in page.monitors if m.certificate]
        # Soonest to expire first. That is the only order this list is ever
        # read in — a certificate list sorted by name is a list nobody scans.
        with_certificates.sort(
            key=lambda m: (m.certificate.days_remaining is None,
                           m.certificate.days_remaining or 0))
        return with_certificates

    def raw(self, ref, scope):
        """The stored document, for the detail view."""
        try:
            return self._es.get(index=ref.container, id=ref.id)["_source"]
        except Exception:
            return None
