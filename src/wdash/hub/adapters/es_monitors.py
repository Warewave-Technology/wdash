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

  * **Browser monitors write somewhere else entirely.** Not into
    `heartbeat-*`: a `type: browser` monitor writes to the
    `synthetics-browser-*` data stream, with its network requests and its
    screenshots in two more beside it. An adapter reading only the heartbeat
    indices sees no browser monitors at all and says so by showing none.

  * **A browser check is six documents, not one.** `synthetics/metadata`,
    `journey/start`, one `step/end` per step, `journey/end`, and the
    `heartbeat/summary` that carries `summary.status` and the total duration.
    `monitor.check_group` is what ties them together — the same value on the
    summary and on every step of that run.

  * **`synthetics.payload.source` is the step's SOURCE CODE, and it is not
    read here.** It arrives with whatever the journey's author typed into it,
    which in the lab's own failing journey is a literal password. WDash
    redacts secrets out of its own journeys; putting Elastic's script bodies
    on the same page would hand back the thing that redaction exists to
    prevent.

Measured against a real Heartbeat 8.19.9 running @elastic/synthetics 1.22.0,
not transcribed from the reference. One complete run of each of the lab's two
journeys — one passing, one failing at its second step — is kept in
`tests/fixtures/elastic-browser-journey.json`.
"""

from datetime import datetime, timezone

from ..models import (
    DOWN, STEP_FAILED, STEP_PASSED, STEP_SKIPPED, UNKNOWN, UP, Certificate,
    Monitor, MonitorCheck, MonitorPage, MonitorPoint, SourceRef, StepResult,
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

#: What Elastic calls a step outcome, in the words WDash already uses for its
#: own journeys. The three mean the same thing on both sides, including the
#: one that matters: a step after a failure is `skipped`, not failed, because
#: it never ran.
STEP_STATUS = {
    "succeeded": STEP_PASSED,
    "failed": STEP_FAILED,
    "skipped": STEP_SKIPPED,
}

#: Steps read per check. A journey longer than this has a different problem.
MAX_STEPS = 50

#: Ceiling on one step lookup. Elasticsearch refuses a plain search asking for
#: more than `index.max_result_window`, which is 10,000 by default — and the
#: refusal would arrive as an exception, which this adapter turns into "no
#: steps", which reads on the page as "these runs had no steps".
#:
#: 500 checks × 50 steps is 25,000, so the cap is real rather than defensive.
#: When it bites, the newest runs keep their steps: the query takes them
#: newest-first, so what gets dropped is the far end of the history rather
#: than a scattering of rows somebody is looking at.
MAX_STEP_DOCUMENTS = 10_000

#: Buckets in the sparkline drawn beside each monitor in the list. Small
#: because it is drawn in a table cell forty pixels tall — more points would
#: be smaller than a pixel each and cost an aggregation to compute.
SPARKLINE_POINTS = 24


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


class _CheckList(list):
    """A list of checks that also knows how many there are in total.

    A subclass rather than a (checks, total) tuple so that `history` keeps the
    return type every caller already handles. A backend that cannot count says
    nothing and the length stands in, which is exactly what an unpaged list
    means.
    """
    total = 0
    offset = 0


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

    @staticmethod
    def _bucket_interval(window, points):
        """A fixed interval that divides the window into roughly `points`.

        Fixed rather than calendar-based: a sparkline is a shape, and a
        calendar interval makes the buckets different widths across a daylight
        saving boundary, which bends the shape for a reason that has nothing
        to do with the monitor.
        """
        seconds = max(1, int((window.end - window.start).total_seconds()))
        step = max(30, seconds // max(1, points))
        return f"{step}s"

    def monitors(self, window, scope, series=False):
        aggregations = {
            # One document per monitor: the most recent check. A terms
            # aggregation alone would give counts, and a count cannot say
            # whether the thing is up NOW.
            "latest": {"top_hits": {
                "size": 1, "sort": [{"@timestamp": {"order": "desc"}}]}},
        }
        if series:
            # In the SAME query as the listing. A second round trip per
            # monitor would be one request per row, and a page that issues
            # fifty requests to draw fifty sparklines is a page that stops
            # working at a hundred monitors.
            aggregations["series"] = {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": self._bucket_interval(
                        window, SPARKLINE_POINTS),
                    # Empty buckets are the point: a gap means the agent
                    # stopped reporting, and dropping them would join the line
                    # across an outage as though nothing happened.
                    "min_doc_count": 0,
                    # And the histogram has to span the WINDOW, not the
                    # monitor's own documents. Without this a monitor added an
                    # hour ago produces fifteen buckets while its neighbours
                    # produce twenty-three, and drawn to the same width the
                    # two sparklines put different moments above each other —
                    # a chart whose x-axis means something different per row.
                    "extended_bounds": {
                        "min": int(window.start.timestamp() * 1000),
                        "max": int(window.end.timestamp() * 1000),
                    },
                },
                "aggs": {
                    "duration": {"avg": {"field": "monitor.duration.us"}},
                    "down": {"filter": {"term": {"summary.status": DOWN}}},
                },
            }

        body = {
            "size": 0,
            "query": self._summaries_only(window),
            "aggs": {"monitors": {
                "terms": {"field": "monitor.id", "size": MAX_MONITORS},
                "aggs": aggregations,
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
            monitor = self._to_monitor(hits[0])
            if series:
                monitor.series = self._to_series(bucket)
            monitors.append(monitor)

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

    @staticmethod
    def _to_series(bucket):
        points = []
        for point in _dig(bucket, "series.buckets") or ():
            microseconds = _dig(point, "duration.value")
            points.append(MonitorPoint(
                timestamp=_parse_time(point.get("key_as_string")),
                duration_ms=(microseconds / 1000.0
                             if microseconds is not None else None),
                down=int(_dig(point, "down.doc_count") or 0),
                checks=int(point.get("doc_count") or 0)))
        return tuple(points)

    def series(self, monitor_id, window, scope, points=120):
        """A finer history for one monitor, for the detail page.

        Separate from `history` because they answer different questions: this
        is a shape over time at a chosen resolution, that is the list of
        individual runs with their error messages. Drawing a chart from the
        run list would put a point per check on an axis that cannot hold
        them; reading errors from this would have nothing to read.
        """
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                self._window_filter(window),
                {"exists": {"field": "summary.status"}},
                {"term": {"monitor.id": monitor_id}},
            ]}},
            "aggs": {"series": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": self._bucket_interval(window, points),
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": int(window.start.timestamp() * 1000),
                        "max": int(window.end.timestamp() * 1000),
                    },
                },
                "aggs": {
                    "duration": {"avg": {"field": "monitor.duration.us"}},
                    "down": {"filter": {"term": {"summary.status": DOWN}}},
                    # The slowest run in the bucket. An average hides the one
                    # request that took four seconds, which is usually the
                    # thing being looked for.
                    "worst": {"max": {"field": "monitor.duration.us"}},
                },
            }},
        }
        try:
            response = self._search(body)
        except Exception:
            return []
        points_out = []
        for point in _dig(response, "aggregations.series.buckets") or ():
            average = _dig(point, "duration.value")
            worst = _dig(point, "worst.value")
            entry = MonitorPoint(
                timestamp=_parse_time(point.get("key_as_string")),
                duration_ms=(average / 1000.0 if average is not None else None),
                down=int(_dig(point, "down.doc_count") or 0),
                checks=int(point.get("doc_count") or 0))
            entry.worst_ms = (worst / 1000.0 if worst is not None else None)
            points_out.append(entry)
        return points_out

    def history(self, monitor_id, window, scope, offset=0, limit=None):
        """Past checks, newest LAST. `offset`/`limit` page at the backend.

        Paged in Elasticsearch rather than in Python: a monitor on a
        fifteen-second schedule writes 5,760 checks a day, and fetching all of
        them to show twenty-five is the kind of thing that works in a lab and
        falls over on the first real deployment.

        `total` is reported alongside so a pager can say "of 5,760" — a page
        list that has to guess how many pages there are guesses wrong at the
        end.
        """
        size = MAX_HISTORY if limit is None else max(1, min(limit, MAX_HISTORY))
        body = {
            "size": size,
            "from": max(0, int(offset)),
            "query": {"bool": {"filter": [
                self._window_filter(window),
                {"exists": {"field": "summary.status"}},
                {"term": {"monitor.id": monitor_id}},
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["@timestamp", "summary.status", "monitor.status",
                        "monitor.duration.us", "error.message",
                        # A browser check's steps are separate documents,
                        # joined to this one by check_group.
                        "monitor.type", "monitor.check_group"],
            # Exact rather than the 10,000 cap: this number is shown to
            # somebody as "of N", and "of 10,000+" on a page of 12,000 checks
            # is a number that is simply wrong.
            "track_total_hits": True,
        }
        try:
            response = self._search(body)
        except Exception:
            return []

        hits = _dig(response, "hits.hits") or []
        steps = self._steps_for(hits)
        checks = []
        for hit in hits:
            source = hit.get("_source") or {}
            duration = _dig(source, "monitor.duration.us")
            checks.append(MonitorCheck(
                timestamp=_parse_time(source.get("@timestamp")),
                status=_status(source),
                duration_ms=(duration / 1000.0) if duration is not None else None,
                error=_dig(source, "error.message") or "",
                steps=steps.get(_dig(source, "monitor.check_group"), ())))
        # Oldest first: a chart reads left to right.
        checks.reverse()
        # The total travels on the list rather than in a tuple, so every
        # existing caller — the fan-out, the detail page's chart — keeps
        # working unchanged. A second return value would have been a signature
        # change for every implementation of MonitorSource.
        checks = _CheckList(checks)
        checks.total = int(_dig(response, "hits.total.value") or len(checks))
        checks.offset = max(0, int(offset))
        return checks

    def _steps_for(self, hits):
        """The steps of every browser check in `hits`, by check group.

        One extra query for a whole page, not one per check: a page of
        twenty-five journeys would otherwise be twenty-six round trips, and
        that is the shape of page that works in a lab and stops working on a
        deployment with any latency to its cluster.

        Only for browser checks. An HTTP monitor has no steps, and asking for
        them would be a second request per page for nothing.

        For every check in the response, not only for a page of them. The
        first version fetched steps only when the caller had asked for a
        bounded page — which sounded careful and meant that steps never
        appeared at all in the normal case: the fan-out pages in Python, on
        purpose, so it asks every source for the whole window and every
        journey came back with no steps on any deployment with more than one
        monitor source. Measuring it through the adapter alone hid that
        completely.
        """
        groups = [_dig(hit.get("_source") or {}, "monitor.check_group")
                  for hit in hits
                  if (_dig(hit.get("_source") or {}, "monitor.type") or
                      "").lower() == "browser"]
        groups = [group for group in groups if group]
        if not groups:
            return {}

        body = {
            "size": min(len(groups) * MAX_STEPS, MAX_STEP_DOCUMENTS),
            "query": {"bool": {"filter": [
                {"terms": {"monitor.check_group": groups}},
                {"term": {"synthetics.type": "step/end"}},
            ]}},
            # Newest first, so the cap costs the far end of the history rather
            # than the rows anybody is reading. Order WITHIN a run is put back
            # below, in Python.
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["monitor.check_group", "synthetics.step",
                        "synthetics.error.message", "error.message"],
        }
        try:
            response = self._search(body)
        except Exception:
            # No steps rather than no history. The check itself is real and
            # already read; losing the detail should not lose the page.
            return {}

        found = {}
        for hit in _dig(response, "hits.hits") or []:
            source = hit.get("_source") or {}
            group = _dig(source, "monitor.check_group")
            if not group:
                continue
            status = (_dig(source, "synthetics.step.status") or "").lower()
            duration = _dig(source, "synthetics.step.duration.us")
            found.setdefault(group, []).append(StepResult(
                index=_dig(source, "synthetics.step.index") or 0,
                kind="browser",
                # What the journey's author called the step. Not
                # `synthetics.payload.source`, which is the step's code and
                # carries whatever literal was typed into it.
                description=_dig(source, "synthetics.step.name") or "",
                # Passed through when it is not one of the three measured
                # values: an agent that reports something new should show what
                # it said, rather than have it translated into one of ours.
                status=STEP_STATUS.get(status, status or STEP_SKIPPED),
                duration_us=duration,
                # The synthetics message, which is the browser's own; the ECS
                # one prefixes it with "error executing step: ".
                error=(_dig(source, "synthetics.error.message")
                       or _dig(source, "error.message") or "")))
        # By step index, so a run reads in the order it ran. Sorted here
        # rather than by the query, which is sorted by time to make the cap
        # drop the oldest runs — and because two steps finishing inside the
        # same millisecond would then be in whichever order the cluster
        # happened to return them.
        return {group: tuple(sorted(steps, key=lambda step: step.index))
                for group, steps in found.items()}

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
