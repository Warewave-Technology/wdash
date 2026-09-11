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
from ..source import Capability, MonitorSource, MonitorSourceError

#: Where Heartbeat and the Fleet-managed Synthetics integration write.
DEFAULT_PATTERNS = ("heartbeat-*", "synthetics-*")

#: How many monitors a listing will return. A deployment with more than this
#: has a naming problem rather than a paging problem, but the cap keeps one
#: aggregation from trying to hold everything in memory.
MAX_MONITORS = 500

#: Places one monitor is checked from, per listing row. Elastic's own
#: service offers about a dozen locations. The cap keeps the listing inside
#: the cluster's bucket limit (65,536 by default): 500 monitors, this many
#: places each and a sparkline each come to about 38,000.
MAX_LOCATIONS = 25

#: How many past checks a history returns.
MAX_HISTORY = 500

#: Screenshot blocks fetched per request. A 1280x720 screenshot is 64 blocks
#: and, measured, holds far fewer distinct ones — 14 was typical — so this is
#: one request in practice. It is a cap rather than a promise: a taller page
#: is more blocks, and one query asking for a thousand ids is a query that
#: eventually times out instead of returning a picture.
MAX_BLOCK_LOOKUP = 128

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


def _location(source):
    """Where the agent that wrote this document was standing, or "".

    `observer.geo.name` is what Fleet-managed synthetics stamp on every
    document and what the lab's Heartbeat was configured to write once this
    was measured — before that, the whole `observer` object was absent, which
    is why "" is a real answer here rather than a bug.

    `observer.name` second: it is the same string in the lab, and a
    deployment that names its probes without giving them a geography should
    not have the column go blank.
    """
    return (_dig(source, "observer.geo.name")
            or _dig(source, "observer.name") or "")


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
    #: The header figures over every check in the window, counted by the
    #: cluster — see `_whole_window`. None on a page of checks.
    whole_window = None
    #: What could not be read beside the checks — a journey's steps.
    warnings = ()


def _whole_window(response, total):
    """The detail page's header figures, from the history's aggregations.

    Counts and the slowest check are exact. The median and p95 are the
    cluster's estimates, and marked so: the page's own figures are
    nearest-rank, a value that actually happened, and these are not.
    """
    def ms(value):
        return None if value is None else round(float(value) / 1000.0, 1)

    spread = _dig(response, "aggregations.spread.values") or {}
    return {
        "checks": total,
        "failed": int(_dig(response, "aggregations.down.doc_count") or 0),
        "median_ms": ms(spread.get("50.0")),
        "p95_ms": ms(spread.get("95.0")),
        "worst_ms": ms(_dig(response, "aggregations.slowest.value")),
        "estimated": True,
    }


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
            # The most recent check from EACH place the monitor runs from. A
            # terms aggregation alone would give counts, and a count cannot
            # say whether the thing is up NOW.
            #
            # Per place, not per monitor. The newest check of all was the
            # row, and with Dublin down and Frankfurt up reporting in turn it
            # went down, up, down, up — an alert with a threshold of three
            # counted one failure, then none, and never fired.
            #
            # `missing` keeps the checks that name no place: a self-managed
            # Heartbeat writes no `observer` at all, and grouped by a field
            # it does not have, its monitors would drop out of the list.
            "locations": {
                "terms": {"field": "observer.geo.name", "missing": "",
                          "size": MAX_LOCATIONS},
                "aggs": {"latest": {"top_hits": {
                    "size": 1,
                    "sort": [{"@timestamp": {"order": "desc"}}]}}},
            },
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
            latest = []
            for place in _dig(bucket, "locations.buckets") or ():
                hits = _dig(place, "latest.hits.hits") or []
                if hits:
                    latest.append(hits[0])
            if not latest:
                continue
            monitor = self._to_monitor(latest)
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

    def _to_monitor(self, latest):
        """One row from the newest check at each place the monitor runs from.

        Down if ANY place's newest check is down, and the row is that check:
        its time, its duration, its error, with the place named in front of
        the error when there is more than one place to tell apart. One row
        per monitor rather than one per place, so an alert keyed on the
        monitor sees every failure — the detail page's "By location" card is
        where the places are set side by side.
        """
        def moment(hit):
            return (_parse_time(_dig(hit, "_source.@timestamp"))
                    or datetime.min.replace(tzinfo=timezone.utc))

        newest_first = sorted(latest, key=moment, reverse=True)
        down = [hit for hit in newest_first
                if _status(hit.get("_source") or {}) == DOWN]
        hit = (down or newest_first)[0]
        source = hit.get("_source") or {}
        duration = _dig(source, "monitor.duration.us")
        error = _dig(source, "error.message") or ""
        if down and len(latest) > 1:
            places = ", ".join(dict.fromkeys(
                _location(h.get("_source") or {}) or "an unnamed location"
                for h in down))
            error = (f"down from {places}: {error}" if error
                     else f"down from {places}")
        return Monitor(
            id=_dig(source, "monitor.id") or "",
            name=_dig(source, "monitor.name") or _dig(source, "monitor.id") or "",
            type=(_dig(source, "monitor.type") or "").lower(),
            url=_dig(source, "url.full") or "",
            status=_status(source),
            checked_at=_parse_time(source.get("@timestamp")),
            duration_ms=(duration / 1000.0) if duration is not None else None,
            error=error,
            tags=tuple(source.get("tags") or ()),
            # The endpoint's certificate, from the newest check that saw one.
            # A place that could not connect saw none, and taking the row's
            # would drop the monitor off the TLS tab — and resolve a
            # certificate alert — because of where the failure happened.
            certificate=next((c for c in (
                _certificate(h.get("_source") or {}) for h in newest_first)
                if c is not None), None),
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
        # Raised, not answered with []: an empty series is what "not enough
        # checks in this window to draw a line" is drawn from.
        response = self._answer(body)
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
                        "monitor.type", "monitor.check_group",
                        # Where the agent was standing. Measured: a
                        # self-managed Heartbeat writes no `observer` at all
                        # until somebody configures one, and Fleet-managed
                        # synthetics stamp `observer.geo.name` on everything.
                        "observer"],
            # Exact rather than the 10,000 cap: this number is shown to
            # somebody as "of N", and "of 10,000+" on a page of 12,000 checks
            # is a number that is simply wrong.
            "track_total_hits": True,
        }
        if limit is None:
            # The whole window, counted by the cluster, for the figures at the
            # top of the detail page. This read stops at MAX_HISTORY, and the
            # header used to be computed from what it returned: a monitor
            # down for most of a day and up for its last 500 minutes read
            # 100.0% available with its slowest check at 1 ms. In the same
            # request, so the count and the rows cannot disagree.
            body["aggs"] = {
                "down": {"filter": {"term": {"summary.status": DOWN}}},
                "slowest": {"max": {"field": "monitor.duration.us"}},
                # Estimates — a t-digest, not a rank — and said to be on the
                # page. Only used when the rows returned are not the window.
                "spread": {"percentiles": {"field": "monitor.duration.us",
                                           "percents": [50, 95]}},
            }
        # Raised, not answered with []: an empty history is what "no check in
        # this window" is drawn from.
        response = self._answer(body)

        hits = _dig(response, "hits.hits") or []
        steps, unread = self._steps_for(hits)
        checks = []
        for hit in hits:
            source = hit.get("_source") or {}
            duration = _dig(source, "monitor.duration.us")
            checks.append(MonitorCheck(
                timestamp=_parse_time(source.get("@timestamp")),
                status=_status(source),
                duration_ms=(duration / 1000.0) if duration is not None else None,
                error=_dig(source, "error.message") or "",
                location=_location(source),
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
        if limit is None:
            checks.whole_window = _whole_window(response, checks.total)
        if unread:
            checks.warnings = (unread,)
        return checks

    def _answer(self, body):
        """One search, or an error that says which source could not answer.

        For the reads whose empty answer means something: no checks, no
        line to draw. The listing has its own partial page for this, and the
        step lookup a warning on a history that is otherwise right.
        """
        try:
            return self._search(body)
        except Exception as exc:
            raise MonitorSourceError(f"{self.name}: {exc}") from exc

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

        Returns (steps by group, why they could not be read or "").
        """
        groups = [_dig(hit.get("_source") or {}, "monitor.check_group")
                  for hit in hits
                  if (_dig(hit.get("_source") or {}, "monitor.type") or
                      "").lower() == "browser"]
        groups = [group for group in groups if group]
        if not groups:
            return {}, ""

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
        except Exception as exc:
            # No steps rather than no history. The check itself is real and
            # already read; losing the detail should not lose the page. Said,
            # though: journeys with nothing to expand read as journeys that
            # had no steps.
            return {}, (f"{self.name}: the steps of these runs could not be "
                        f"read: {exc}")

        found = {}
        for hit in _dig(response, "hits.hits") or []:
            source = hit.get("_source") or {}
            group = _dig(source, "monitor.check_group")
            if not group:
                continue
            status = (_dig(source, "synthetics.step.status") or "").lower()
            duration = _dig(source, "synthetics.step.duration.us")
            index = _dig(source, "synthetics.step.index") or 0
            # Passed through when it is not one of the three measured values:
            # an agent that reports something new should show what it said,
            # rather than have it translated into one of ours.
            outcome = STEP_STATUS.get(status, status or STEP_SKIPPED)
            found.setdefault(group, []).append(StepResult(
                # Where the picture of this step lives, derived rather than
                # looked up: the screenshot documents are keyed by exactly
                # these two values, so asking the cluster whether one exists
                # would be a second query per page to decide whether to draw
                # a button.
                #
                # Except for a SKIPPED step, which is measured: it writes a
                # `step/end` document like any other and no screenshot at
                # all, because the step never ran and there was nothing on
                # screen to photograph. A token for it would be a button
                # that always fails.
                screenshot_id=(None if outcome == STEP_SKIPPED
                               else f"{group}:{index}"),
                index=index,
                kind="browser",
                # What the journey's author called the step. Not
                # `synthetics.payload.source`, which is the step's code and
                # carries whatever literal was typed into it.
                description=_dig(source, "synthetics.step.name") or "",
                status=outcome,
                # None for a skipped step, whatever the document says. It
                # carries one — 11 µs and 4 µs in the fixture, a few µs on
                # the lab — which is the time Heartbeat took to write down
                # that the step never ran. Passed through, a journey that
                # broke at sign-in reported its basket step as the fastest
                # step on the page and getting quicker by 100%.
                duration_us=None if outcome == STEP_SKIPPED else duration,
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
                for group, steps in found.items()}, ""

    def step_screenshot(self, token, scope):
        """The page as it was at the end of one step, in pieces.

        Measured against a running Heartbeat 8.19 rather than transcribed.
        What it writes is not an image:

          * one `step/screenshot_ref` document per step, carrying the size of
            the picture and a list of BLOCKS — 64 of them for a 1280x720
            screen, each 160x90, each with a `hash` and its `top`/`left`;
          * one `screenshot/block` document per distinct hash, whose `_id` IS
            the hash and whose `synthetics.blob` is a base64 JPEG of that
            tile.

        The blocks are content-addressed and written once. In the lab, a
        screenshot taken today was assembled almost entirely out of blocks
        stored two days earlier by different runs of a different monitor —
        125 references pointing at 30 stored blocks. Three consequences, and
        all three are why this is not a `get` by check group:

          * blocks are looked up by hash, across the whole data stream;
          * a screenshot with 64 blocks may hold only 14 distinct ones, so
            one lookup covers many tiles;
          * whatever deletes old documents punches holes in NEWER
            screenshots. `missing` counts them, so the page can say a piece
            is gone rather than drawing the gap and letting somebody read it
            as a blank region of the page.

        Returns the pieces, not an image. Assembling them server-side would
        mean decoding and re-encoding JPEG, which means an imaging library in
        the dependency list for one screen; the browser already has a canvas.
        """
        group, _, index = str(token or "").rpartition(":")
        if not group or not index.isdigit():
            return None

        try:
            response = self._search({
                "size": 1,
                "query": {"bool": {"filter": [
                    {"term": {"synthetics.type": "step/screenshot_ref"}},
                    {"term": {"monitor.check_group": group}},
                    {"term": {"synthetics.step.index": int(index)}},
                ]}},
                "_source": ["screenshot_ref", "synthetics.step",
                            "monitor.id", "@timestamp"],
            })
        except Exception:
            return None

        hits = _dig(response, "hits.hits") or []
        if not hits:
            return None
        source = hits[0].get("_source") or {}
        reference = _dig(source, "screenshot_ref") or {}
        blocks = reference.get("blocks") or []
        if not blocks:
            return None

        hashes = sorted({block.get("hash") for block in blocks
                         if block.get("hash")})
        blobs = {}
        for start in range(0, len(hashes), MAX_BLOCK_LOOKUP):
            batch = hashes[start:start + MAX_BLOCK_LOOKUP]
            try:
                found = self._search({
                    "size": len(batch),
                    "query": {"ids": {"values": batch}},
                    "_source": ["synthetics.blob", "synthetics.blob_mime"],
                })
            except Exception:
                found = None
            for hit in (_dig(found, "hits.hits") or []):
                blob = _dig(hit.get("_source") or {}, "synthetics.blob")
                if blob:
                    blobs[hit.get("_id")] = (
                        blob,
                        _dig(hit.get("_source") or {},
                             "synthetics.blob_mime") or "image/jpeg")

        tiles, missing = [], 0
        for block in blocks:
            blob = blobs.get(block.get("hash"))
            if blob is None:
                missing += 1
                continue
            tiles.append({
                "left": block.get("left") or 0, "top": block.get("top") or 0,
                "width": block.get("width") or 0,
                "height": block.get("height") or 0,
                "blob": blob[0], "mime": blob[1],
            })
        return {
            "width": reference.get("width") or 0,
            "height": reference.get("height") or 0,
            "step": _dig(source, "synthetics.step.name") or "",
            "monitor": _dig(source, "monitor.id") or "",
            "taken_at": source.get("@timestamp"),
            "blocks": tiles,
            "missing": missing,
            "source": self.name,
        }

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
