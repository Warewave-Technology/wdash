"""
Elasticsearch adapters.

Everything Elasticsearch-specific stops here. Outside this file, `hits`,
`_source` and `aggregations` do not appear.
"""

import logging
import math
import re
import time

from ...utils import timerange
from ..models import (
    FieldStat, FieldValue, LogContext, LogPage, LogRecord, PartialCounts,
    PartialList, Service, SourceRef, Span, Trace, TraceSummary,
    UNKNOWN_SEVERITY, normalise_severity,
)
from ..aggregation import AggregationResult, Bucket, DateHistogram, Terms
from ..query import DEFAULT_LOG_FIELDS, SORT_SLOWEST
from .. import query_language as ql
from ..source import Capability, LogSource, TraceSource
from .es_log_schema import (
    field_candidates, match_candidates, schema_for_document, source_fields,
)
from .es_trace_schema import detect_schema, dig, parse_time

logger = logging.getLogger(__name__)

#: Where a trace source looks when nobody said: the indices named for traces.
DEFAULT_TRACE_PATTERNS = ("*traces*", "*apm*")

# Log fields mapped onto the neutral model. Everything else lands in attributes.
_MAPPED_LOG_FIELDS = {"@timestamp", "message", "level", "service",
                      "trace_id", "span_id"}
_RESOURCE_FIELDS = ("host", "environment", "container", "pod", "namespace")


from ..patterns import matches as _pattern_matches  # noqa: F401

#: A discovered mapping path -> the neutral name it IS, for the editor.
#:
#: `field_candidates` runs the other way, neutral -> the paths a cluster might
#: keep it under, and that table is the one place the two spellings are
#: related; inverting it here keeps them from drifting. `severity` leads so
#: that both `level` and `severity_text` come back as `severity` — the name
#: `_panel_aggregations` and `_bucket_key` treat specially, and the one a
#: panel keeps when its board is re-pointed at another backend.
_NEUTRAL_FOR_PATH = {
    candidate: neutral
    for neutral in ("severity", "service", "host", "environment",
                    "trace_id", "span_id", "body", "timestamp")
    for candidate in field_candidates(neutral)
}

#: Neutral names that are the log line or its clock. Discovery excludes
#: `@timestamp` and `message` by path, so this is about the OTHER spellings:
#: an OpenTelemetry index maps `body_text` as a keyword, which discovery does
#: find and the table above resolves to `body` — a name the panel model
#: refuses, so offering it would be a select whose value the save rejects,
#: and a refused save re-renders from the stored panel list.
_NOT_GROUPABLE = frozenset({"body", "message", "timestamp"})

#: Mapped types that can hold the string a terms aggregation counts absent
#: documents under.
#:
#: `missing` is a VALUE, and Elasticsearch parses it as the field's own type:
#: measured on the lab, `{"terms": {"field": "http_status", "missing":
#: "unknown"}}` on a `short` answers HTTP 400 `For input string: "unknown"`,
#: and a 400 fails the whole `_search` — so ONE panel grouped by a number
#: took the other panels of its board down with it, which is the fault the
#: field offer exists to avoid. A number cannot be counted under "unknown"
#: anywhere, so the option is to invent a sentinel (a bucket labelled -1 that
#: no document holds) or to leave documents without the field out of a
#: question about the values of that field. The second is the true one.
_MISSING_CAN_BE_A_STRING = frozenset({"keyword"})


class MalformedResponse(ValueError):
    """The cluster answered with something Elasticsearch does not send."""


def _count(value, what="a count"):
    """An integer Elasticsearch computed: a total, a `took`, a doc_count.

    Only a number passes. These went to the page as they came, and the page
    put them into its HTML: a string where a number belonged was markup that
    whoever answered as Elasticsearch — its operator, anything on a plain-http
    link to it — had every reader's browser run. A total is `{"value": n}` or
    a bare number, depending on the version.
    """
    if isinstance(value, dict):
        value = value.get("value")
    # NaN and Infinity too: the client's JSON parser accepts both, and int()
    # of either raised something other than this.
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or (isinstance(value, float) and not math.isfinite(value))):
        raise MalformedResponse(f"{what} in the answer is not a number")
    return int(value)


def _shard_failure(response):
    """What an answer says about the shards that did not answer, or None.

    Elasticsearch fails a search outright only when every shard fails. When
    some do, it answers 200 with what the others found and says so in
    `_shards`, which nothing here read: measured on the lab, `attr_0:abc OR
    level:ERROR` over two indices, one of which maps `attr_0` as a number,
    failed on five shards of six and came back as a complete answer.
    """
    shards = response.get("_shards") or {}
    failed = _count(shards.get("failed", 0), "a shard count")
    if failed <= 0:
        return None
    total = _count(shards.get("total", failed), "a shard count")
    details = [failure.get("reason") for failure in shards.get("failures") or ()]
    reasons = [str(d.get("reason") or d.get("type")) for d in details
               if isinstance(d, dict) and (d.get("reason") or d.get("type"))]
    reason = reasons[0] if reasons else "no reason was given"
    return f"{failed} of {total} shards failed: {reason[:200]}"


def _wildcard_literal(text):
    """Text an Elasticsearch `wildcard` query reads as itself.

    It treats `*`, `?` and `\\` as syntax anywhere; the pattern language only
    a leading and a trailing star. Unescaped, `*pay?*` beside `*` hid
    `payments` in the query while the check allowed it.
    """
    return "".join("\\" + c if c in "\\*?" else c for c in text)


#: Request-body fields whose name differs from the client's keyword argument.
#:
#: Only one so far, and it is the one that matters: `_source` is what
#: Elasticsearch calls the field in the JSON body, and `source` is what
#: elasticsearch-py calls the parameter. A `**body` that does not translate it
#: raises `TypeError: search() got an unexpected keyword argument '_source'` —
#: which, at the only call site that uses it, is the log-to-trace jump.
_BODY_TO_KEYWORD = {"_source": "source"}


def _as_keywords(body):
    """Turn a request body into keyword arguments for the client.

    The `body=` parameter is deprecated and elasticsearch-py warns on every
    call; a future major removes it. Passing the fields as keywords is the
    supported form.

    It is also stricter, which is the point of doing it in ONE place: the
    client validates every name, so a typo in a body key becomes a TypeError
    here instead of a field Elasticsearch quietly ignores. `_search` and
    `_multi_search` below are the only two places that talk to the client, so
    this is the only translation table there needs to be.
    """
    return {_BODY_TO_KEYWORD.get(key, key): value for key, value in body.items()}


def _search(es, indices, body, **options):
    """One search. `indices` is a list; the client wants a string."""
    index = ",".join(indices) if not isinstance(indices, str) else indices
    return es.search(index=index, **_as_keywords(body), **options)


def _multi_search(es, requests, timeout="15s", reasons=None):
    """Run several searches in ONE round trip.

    Both sources need this: trace lookups fan out per schema, and comparing a
    window with the previous one is two queries. Issuing them separately would
    double the round trips for what Elasticsearch answers in a single batch.

    A per-query failure comes back as None so one bad request does not lose the
    results of the others. `reasons`, when given, is a dict that receives why
    each failed request failed, by position: a failure said without its
    reason is half a warning.
    """
    if reasons is None:
        reasons = {}
    if not requests:
        return []
    if len(requests) == 1:
        indices, body = requests[0]
        try:
            return [_search(es, indices, body, timeout=timeout)]
        except Exception as exc:
            reasons[0] = str(exc)[:200]
            return [None]

    payload = []
    for indices, body in requests:
        payload.append({"index": ",".join(indices)})
        payload.append(body)
    try:
        response = es.msearch(searches=payload)
    except Exception as exc:
        reasons.update(dict.fromkeys(range(len(requests)), str(exc)[:200]))
        return [None] * len(requests)

    out = []
    for position, item in enumerate(response.get("responses", [])):
        error = item.get("error")
        if error:
            reasons[position] = str(error.get("reason") if isinstance(error, dict)
                                    else error)[:200]
        out.append(None if error else item)
    while len(out) < len(requests):
        reasons[len(out)] = "no answer for this request in the batch"
        out.append(None)
    return out


class CatalogueUnavailable(RuntimeError):
    """The cluster's index list could not be read, and there is none to reuse.

    Raised rather than answered with an empty list. An empty list is what a
    cluster with no indices looks like, and every route turned it into "No
    log indices found" or "your role has access to nothing" — told to an
    administrator with `*` while the cluster was down.
    """


#: How Elasticsearch 7.11 onwards names a data stream's backing indices. Only
#: used for an index the catalogue has not listed yet: one a rollover created
#: since, whose records a search already returns.
_BACKING_INDEX = re.compile(r"^\.ds-(?P<stream>.+)-\d{4}\.\d{2}\.\d{2}-\d+$")


class _IndexCatalogue:
    """Short-lived cache of the cluster's index list.

    `cat.indices` is a cluster-level call and the index list barely changes,
    yet it was being issued on every single API request. The cache is keyed by
    nothing because the RAW list is user-independent — scope filtering happens
    afterwards, so no user ever sees another user's indices through it.

    Data streams are in the list by their own names. `cat.indices` lists a
    stream's backing indices (`.ds-<stream>-<date>-<generation>`, which the
    sources drop as system indices) and never the stream, so no data stream
    could become a container: Filebeat 8, Elastic Agent, APM 8 and a collector
    left on its default routing all write to them. Measured on the lab, its
    four streams were in no source's list. They are read from
    `_data_stream`, which leaves out hidden streams unless asked, and each is
    listed with the creation date of its newest backing index.
    """

    def __init__(self, client, ttl=30.0):
        self._es = client
        self._ttl = ttl
        self._entries = None
        self._fetched_at = 0.0
        self._streams = {}
        self._backing = {}
        #: Why the data streams could not be listed, while their backing
        #: indices could; None when they were.
        self.stream_error = None

    def entries(self):
        now = time.monotonic()
        if self._entries is not None and (now - self._fetched_at) < self._ttl:
            return self._entries
        try:
            self._fetch(now)
        except Exception as exc:
            # Serve a stale list rather than pretending the cluster is empty:
            # an empty list would look like "you have access to nothing".
            if self._entries is not None:
                return self._entries
            raise CatalogueUnavailable(
                f"the index list could not be read: {exc}") from exc
        return self._entries

    def invalidate(self):
        self._entries = None

    def refresh(self, min_age=2.0):
        """Fetch the list again now, unless it is younger than `min_age`.

        For a name that is not in the list yet. An index created a few
        seconds ago is in another worker's list and not this one's, and a
        record read from it through this worker was "not found". Bounded by
        `min_age` so that asking for names that do not exist cannot turn
        every request into a cluster-level call. A failed fetch keeps the
        list there was.
        """
        now = time.monotonic()
        if self._entries is not None and now - self._fetched_at < min_age:
            return
        try:
            self._fetch(now)
        except Exception:
            return

    def _fetch(self, now):
        entries = [dict(e) for e in
                   self._es.cat.indices(format="json", h="index,creation.date")]
        streams = self._streams
        try:
            answer = self._es.indices.get_data_stream(name="*")
            streams = {stream["name"]: tuple(index["index_name"]
                                             for index in stream.get("indices") or ())
                       for stream in answer.get("data_streams") or ()}
            self.stream_error = None
        except Exception as exc:
            # The indices are listed and the streams are not: what is known
            # of them is kept, and the sources say which records they cannot
            # reach rather than leaving them out without a word.
            self.stream_error = f"data streams could not be listed: {exc}"

        created = {entry["index"]: int(entry.get("creation.date") or 0)
                   for entry in entries}
        entries.extend({"index": name, "data_stream": True,
                        "creation.date": str(max((created.get(index, 0)
                                                  for index in backing), default=0))}
                       for name, backing in streams.items())
        self._streams = streams
        self._backing = {index: name for name, backing in streams.items()
                         for index in backing}
        self._entries = entries
        self._fetched_at = now

    def is_stream(self, name):
        return name in self._streams

    def stream_of(self, index):
        """The data stream `index` is a backing index of, or None."""
        stream = self._backing.get(index)
        if stream is None:
            match = _BACKING_INDEX.match(index or "")
            if match and match.group("stream") in self._streams:
                stream = match.group("stream")
        return stream

    def unlisted_backing(self):
        """Backing indices in the list whose stream could not be named."""
        if not self.stream_error:
            return []
        return [entry["index"] for entry in self._entries or ()
                if _BACKING_INDEX.match(entry["index"])
                and self.stream_of(entry["index"]) is None]


class ElasticsearchLogSource(LogSource):
    """Exposes Elasticsearch indices as a neutral log source."""

    backend = "elasticsearch"

    def __init__(self, client, name="elasticsearch", patterns=("*",),
                 exclude=(), catalogue=None):
        self._es = client
        self.name = name
        self._patterns = tuple(patterns)
        # Indices that hold a different signal. Without this the log source
        # happily searches the trace store: spans have a timestamp and match
        # `*`, so they come back as records with no body and no severity. A
        # deployment has to say which indices are logs and which are not.
        self._exclude = tuple(exclude)
        self._catalogue = catalogue or _IndexCatalogue(client)

    @property
    def capabilities(self):
        return frozenset({Capability.SEARCH, Capability.FIELD_STATS,
                          Capability.HISTOGRAM, Capability.CONTEXT,
                          Capability.AGGREGATION, Capability.RAW_DOCUMENT,
                          Capability.LOG_TRACE_CORRELATION})

    def health(self):
        # `ping()` returns False rather than raising, so the detail has to
        # branch too. Returning a constant "ok" made the failure log line —
        # `health: elasticsearch-traces: ok` — read as a success.
        try:
            if self._es.ping():
                return True, "ok"
            return False, "ping failed: no response from the cluster"
        except Exception as exc:
            return False, str(exc)

    def containers(self, scope):
        if scope.is_empty:
            return []
        # Raises when the cluster's list cannot be read and none was cached:
        # the routes have an answer for "cannot connect", and [] reached none
        # of them.
        entries = list(self._catalogue.entries())
        # Newest first: with time-based indices the user almost always cares
        # about the freshest one. System indices and a data stream's backing
        # indices start with a dot; the stream itself is listed by its name.
        entries = [e for e in entries
                   if not e["index"].startswith(".") and not e["index"].startswith("_")]
        entries.sort(key=lambda e: int(e.get("creation.date") or 0), reverse=True)
        # The source's own patterns first, then the scope
        return scope.resolve(self._own([e["index"] for e in entries]),
                             source=self.name)

    def _own(self, names):
        """The names this source's patterns take and its exclusions leave."""
        if "*" not in self._patterns:
            names = [n for n in names
                     if any(_pattern_matches(p, n) for p in self._patterns)]
        if self._exclude:
            names = [n for n in names
                     if not any(_pattern_matches(p, n) for p in self._exclude)]
        return names

    def _unlisted_streams(self, scope):
        """Data streams this search would have reached, had they been listed.

        Named from their backing indices, which the index list still has
        when `_data_stream` did not answer; the scope decides as it does for
        everything else.
        """
        names = sorted({_BACKING_INDEX.match(index).group("stream")
                        for index in self._catalogue.unlisted_backing()})
        unreached = scope.resolve(self._own(names), source=self.name)
        if not unreached:
            return None
        return (f"{self._catalogue.stream_error}; not searched: "
                f"{', '.join(unreached[:5])}"
                f"{' and more' if len(unreached) > 5 else ''}")

    # ---------- search ----------

    def _targets(self, query, scope):
        """Containers this query targets: scope ∩ query.containers.

        query.containers is a narrowing of scope, not a grant (a dashboard's
        index patterns, for example). The scope always wins.
        """
        allowed = self.containers(scope)
        if not getattr(query, "containers", None):
            return allowed
        wanted = set(query.containers)
        return [name for name in allowed if name in wanted]

    def search(self, query, scope):
        try:
            targets = self._targets(query, scope)
        except CatalogueUnavailable as exc:
            return LogPage(partial=True, warnings=(str(exc),))
        # Sending an empty target list to Elasticsearch means '*' — the exact opposite.
        if not targets:
            unreached = self._unlisted_streams(scope)
            if unreached:
                return LogPage(partial=True, warnings=(unreached,))
            return LogPage(warnings=("the scope permits no containers",))

        body = {
            "query": self._build_query(query),
            "sort": [{"@timestamp": {"order": "asc" if query.ascending else "desc"}},
                     {"_doc": {"order": "asc" if query.ascending else "desc"}}],
            "size": min(query.limit, 500),
            "track_total_hits": True,
        }
        # Keep the list view narrow. The full record is only fetched when the
        # detail view asks for it — but a row must still carry what the schema
        # reads, or it reads differently from the record it lists.
        if query.fields:
            body["_source"] = source_fields(query.fields)
        if query.cursor:
            body["search_after"] = query.cursor

        severity_field = None
        if query.histogram:
            # Rides on the same request. Split by severity because a flat count
            # tells you volume changed; split by severity tells you what changed.
            severity_field = self._resolve_agg_field(targets, "severity")
            timeline = {"date_histogram": {
                "field": "@timestamp",
                "fixed_interval": query.window.suggest_interval(),
                "min_doc_count": 0,
            }}
            if severity_field:
                timeline["aggs"] = {
                    "severity": {"terms": {"field": severity_field, "size": 10}}}
            body["aggs"] = {"timeline": timeline}

        try:
            response = _search(self._es, targets, body, timeout="30s")
        except Exception as exc:
            return LogPage(partial=True, containers=tuple(targets),
                           warnings=(f"search failed: {exc}",))

        hits = response["hits"]["hits"]
        warnings = []
        try:
            total = _count(response["hits"]["total"], "the total")
            took_ms = _count(response.get("took", 0), "took")
            shards = _shard_failure(response)
            histogram = []
            timeline = (response.get("aggregations") or {}).get("timeline")
            if timeline:
                for bucket in timeline.get("buckets", []):
                    count = _count(bucket.get("doc_count", 0))
                    by_severity = {}
                    # Added, not assigned: INFO and info, WARN and WARNING are
                    # one level each, and the last spelling used to overwrite
                    # the others — a bucket of 1100 stacked to 140.
                    for sub in (bucket.get("severity") or {}).get("buckets", []):
                        level = normalise_severity(sub["key"])
                        by_severity[level] = (by_severity.get(level, 0)
                                              + _count(sub["doc_count"]))
                    # The page stacks these rather than drawing the count, so
                    # what no level bucket holds — records without the field,
                    # levels beyond the ten asked for — is drawn too.
                    rest = count - sum(by_severity.values())
                    if severity_field and rest > 0:
                        by_severity[UNKNOWN_SEVERITY] = (
                            by_severity.get(UNKNOWN_SEVERITY, 0) + rest)
                    histogram.append({
                        "timestamp": bucket.get("key_as_string"),
                        "key": bucket.get("key"),
                        "count": count,
                        "by_severity": by_severity,
                    })
        except MalformedResponse as exc:
            # A failure, said as one — not an empty page.
            return LogPage(partial=True, containers=tuple(targets),
                           warnings=(f"the cluster's answer could not be read: "
                                     f"{exc}",))
        if shards:
            warnings.append(shards)
        unreached = self._unlisted_streams(scope)
        if unreached:
            warnings.append(unreached)

        return LogPage(
            records=[self._to_record(h) for h in hits],
            total=total,
            took_ms=took_ms,
            cursor=hits[-1].get("sort") if hits else None,
            containers=tuple(targets),
            partial=bool(response.get("timed_out")) or bool(shards or unreached),
            warnings=tuple(warnings),
            histogram=histogram,
        )

    def _readable(self, container, scope):
        """The concrete containers this scope may read in THIS source, if
        `container` is one of them; otherwise None.

        A name rather than a pattern match. The container arrives from a URL,
        and Elasticsearch reads it as an index EXPRESSION: `app-*` matches the
        pattern `app-*` as a string and, handed to a search, reaches every
        `app-*` index — the excluded `app-pii-*` ones included — and an alias
        that matches a grant can resolve to an index no grant names. Only a
        name the scope resolved for this source is read, and passing the
        source is what makes source-qualified rules count here at all.
        """
        allowed = set(self.containers(scope))
        if container not in allowed:
            self._catalogue.refresh()
            allowed = set(self.containers(scope))
        return allowed if container in allowed else None

    def _get(self, ref, scope):
        """GET one document from a container this scope may read, or None.

        The index Elasticsearch answers from is checked as well as the one
        asked for: a GET through a name that is not the index it lives in
        must not hand back a document from somewhere the scope never listed.
        A data stream's backing index counts as the stream.
        """
        allowed = self._readable(ref.container, scope)
        if allowed is None:
            return None
        try:
            if self._catalogue.is_stream(ref.container):
                # Elasticsearch refuses a GET through a stream's name —
                # `index_not_found_exception`, measured on 8.19 — so the id is
                # looked for in the stream, which reaches every backing index.
                hits = _search(self._es, ref.container,
                               {"query": {"ids": {"values": [ref.id]}}, "size": 1},
                               timeout="10s")["hits"]["hits"]
                if not hits:
                    return None
                response = hits[0]
            else:
                response = self._es.get(index=ref.container, id=ref.id)
        except Exception:
            return None
        if self._container_of(response.get("_index")) not in allowed:
            return None
        return response

    def _container_of(self, index):
        """The container an index is read as: its data stream, or itself."""
        return self._catalogue.stream_of(index) or index

    def fetch(self, ref, scope):
        response = self._get(ref, scope)
        if response is None:
            return None
        return self._to_record({"_index": response["_index"], "_id": response["_id"],
                                "_source": response["_source"]})

    def raw(self, ref, scope):
        """The Elasticsearch document, untranslated.

        Returns the hit envelope (`_index`/`_id`/`_source`) rather than
        `_source` alone: which index a record actually landed in is often the
        thing being diagnosed, and it is not visible from the source body.
        """
        response = self._get(ref, scope)
        if response is None:
            return None
        return {"_index": response.get("_index"), "_id": response.get("_id"),
                "_source": response.get("_source") or {}}

    #: How many names the editor's group-by select is offered.
    #:
    #: The discovery walk itself is uncapped here (`max_fields=1000`, the same
    #: number `_resolve_agg_field` already asks for) because the cap applies
    #: AFTER `_PRIORITY_FIELDS`, so a small one is what kept the list at four
    #: useful names. A mapping with a thousand dynamic fields is a select
    #: nobody can read, though, so the offer is cut — priority names first,
    #: then alphabetical, which is the order discovery returns.
    GROUP_BY_LIMIT = 50

    def group_by_fields(self, scope, window=None):
        """Every mapped field these indices can aggregate on, neutrally named.

        Measured on the lab's `app-logs-000001`: ten fields — `correlation_id`,
        `duration_ms`, `environment`, `host`, `http_status`, `level`,
        `request_id`, `service`, `trace_id`, `user_id` — of which the editor
        used to offer four. A text field is not among them: `_discover_...`
        keeps a `text` field only when it carries a `keyword` sub-field, which
        is the difference between a bar chart and tokenised nonsense.

        Named neutrally where a neutral name exists, so `level` is offered as
        `severity` and a panel built here still means the same thing if the
        board is re-pointed at Loki: `severity` is answerable on all three
        backends, `level` is one cluster's spelling of it.
        """
        targets = self.containers(scope)
        if not targets:
            return []
        discovered = self._aggregatable_fields(list(targets), max_fields=1000)

        seen, out = set(), []
        for path in discovered:
            name = _NEUTRAL_FOR_PATH.get(path, path)
            if name in _NOT_GROUPABLE or name in seen:
                continue
            seen.add(name)
            out.append(name)
        if len(out) <= self.GROUP_BY_LIMIT:
            return out
        # Cutting silently is the default case, not an edge: a log source
        # says `patterns=("*",)` unless somebody narrowed it, and the lab's
        # eleven-index cluster then discovers 1465 aggregatable fields, of
        # which the first fifty by name are `agent.*`, `as.*` and `attr_0`
        # to `attr_148` — `http_status` is not among them. An author who was
        # not told reads the select as the whole answer.
        return PartialList(
            out[:self.GROUP_BY_LIMIT], partial=True,
            warnings=(f"More fields can be grouped by here than one select "
                      f"can hold: these are the first {self.GROUP_BY_LIMIT} "
                      f"by name. Narrow this source's index patterns to "
                      f"reach the rest.",))

    def field_stats(self, query, scope, fields=None, top=10):
        targets = self._targets(query, scope)
        if not targets:
            return PartialCounts()

        discovered = fields or self._aggregatable_fields(targets)
        if not discovered:
            return PartialCounts()

        aggs = {name: {"terms": {"field": path, "size": top}}
                for name, path in discovered.items()}
        body = {"size": 0, "query": self._build_query(query), "aggs": aggs}

        # A search that fails, a mapping that cannot be read, an answer that
        # cannot be: each raises, and the route says so. They returned [],
        # which the sidebar showed as "No field data available" beside a page
        # full of results.
        response = _search(self._es, targets, body,
                           timeout="10s", request_cache=True)
        # An answer can be short without being a failure, and this read the
        # short one as the whole: measured on the lab with five of six shards
        # failing, the sidebar showed level, service and host at 2789 each —
        # one shard's worth — beside a result list that reported the failure.
        shards = _shard_failure(response)
        stats = []
        for name in discovered:
            buckets = ((response.get("aggregations") or {}).get(name, {})
                       .get("buckets", []))
            if buckets:
                stats.append(FieldStat(
                    field=name,
                    values=[FieldValue(value=b["key"],
                                       count=_count(b["doc_count"]))
                            for b in buckets],
                ))
        return PartialCounts(stats, warnings=(shards,) if shards else ())

    def aggregate(self, query, aggregations, scope):
        """Run the given aggregations in a SINGLE Elasticsearch request.

        The dashboard's four panels ask for different aggregations over the
        same query; issuing one request each keeps Elasticsearch's search
        thread pool busy for no reason.
        """
        try:
            targets = self._targets(query, scope)
        except CatalogueUnavailable as exc:
            return AggregationResult(warnings=(str(exc),), failed=True)
        if not targets:
            return AggregationResult(warnings=("the scope permits no containers",))

        warnings, notes = [], {}
        body = {"size": 0, "query": self._build_query(query),
                "aggs": {}, "track_total_hits": True}
        for agg in aggregations:
            translated = self._translate_agg(agg, targets, query, warnings, notes)
            if translated is not None:
                body["aggs"][agg.name] = translated

        if not body["aggs"]:
            return AggregationResult(warnings=tuple(warnings), notes=notes)

        try:
            response = _search(self._es, targets, body,
                               timeout="30s", request_cache=True)
        except Exception as exc:
            # An empty panel and "the query could not run" are different things.
            # Carrying the reason and returning empty beats a 500.
            return AggregationResult(warnings=tuple(warnings) + (str(exc)[:200],),
                                     notes=notes, failed=True)

        raw = response.get("aggregations") or {}
        try:
            shards = _shard_failure(response)
            return AggregationResult(
                total=_count(response["hits"]["total"], "the total"),
                buckets={agg.name: self._read_buckets(raw.get(agg.name), agg)
                         for agg in aggregations if agg.name in raw},
                warnings=tuple(warnings) + ((shards,) if shards else ()),
                notes=notes,
            )
        except MalformedResponse as exc:
            return AggregationResult(warnings=tuple(warnings) + (str(exc),),
                                     notes=notes, failed=True)

    def multi_aggregate(self, requests, scope):
        targets = None
        bodies, metadata = [], []

        for query, aggregations in requests:
            if targets is None:
                try:
                    targets = self._targets(query, scope)
                except CatalogueUnavailable as exc:
                    return [AggregationResult(warnings=(str(exc),), failed=True)
                            for _ in requests]
            if not targets:
                metadata.append((aggregations,
                                 ["the scope permits no containers"], {}))
                continue

            warnings, notes = [], {}
            aggs = {}
            for agg in aggregations:
                translated = self._translate_agg(agg, targets, query, warnings,
                                                 notes)
                if translated is not None:
                    aggs[agg.name] = translated
            metadata.append((aggregations, warnings, notes))
            bodies.append((targets, {"size": 0, "query": self._build_query(query),
                                     "aggs": aggs, "track_total_hits": True}))

        if not bodies:
            return [AggregationResult(warnings=tuple(w), notes=n)
                    for _, w, n in metadata]

        responses = _multi_search(self._es, bodies, timeout="30s")
        out = []
        for (aggregations, warnings, notes), response in zip(metadata, responses):
            if response is None:
                out.append(AggregationResult(
                    warnings=tuple(warnings) + ("query failed",),
                    notes=notes, failed=True))
                continue
            raw = response.get("aggregations") or {}
            try:
                shards = _shard_failure(response)
                out.append(AggregationResult(
                    total=_count(response["hits"]["total"], "the total"),
                    buckets={agg.name: self._read_buckets(raw.get(agg.name), agg)
                             for agg in aggregations if agg.name in raw},
                    warnings=tuple(warnings) + ((shards,) if shards else ()),
                    notes=notes))
            except MalformedResponse as exc:
                out.append(AggregationResult(
                    warnings=tuple(warnings) + (str(exc),),
                    notes=notes, failed=True))
        return out

    def _translate_agg(self, agg, targets, query, warnings, notes=None,
                       owner=None):
        """Neutral aggregation -> Elasticsearch aggregation node, or None.

        A refusal goes into `warnings` for the page AND, when `notes` is given,
        under the name of the aggregation it belongs to so the panel that asked
        can draw it. The text names the field, never the aggregation — two
        panels grouping by the same unmapped field produce the same sentence
        twice — which is why the attribution is a key and not a prefix.

        `owner` carries that key down the sub-aggregation recursion: a split
        that cannot be translated is the reason the PANEL's series is not
        split, and the panel is what is on screen.
        """
        owner = agg.name if owner is None else owner

        def refuse(reason):
            warnings.append(reason)
            if notes is not None:
                notes.setdefault(owner, []).append(reason)

        if isinstance(agg, DateHistogram):
            histogram = {
                "field": "@timestamp",
                "fixed_interval": agg.interval or query.window.suggest_interval(),
                "min_doc_count": agg.min_count,
            }
            if agg.min_count == 0:
                # min_doc_count alone only fills gaps BETWEEN buckets that
                # exist, so a window with no data at all comes back empty and
                # the panel renders blank — indistinguishable from a failure.
                # Extending to the requested bounds draws the axis the user
                # asked for, and "nothing happened" reads as a flat zero line.
                histogram["extended_bounds"] = {
                    "min": timerange.to_es(query.window.start),
                    "max": timerange.to_es(query.window.end),
                }
            node = {"date_histogram": histogram}
        elif isinstance(agg, Terms):
            # RESOLVE the field path from the mapping rather than guessing. The
            # old code tried "service.keyword" first and retried with "service"
            # on failure — two round trips and a guess.
            path, mapped = self._resolve_agg(targets, agg.field)
            if path is None:
                refuse(f"'{agg.field}' cannot be aggregated on these indices "
                       "(it may not be mapped as keyword)")
                return None
            terms = {"field": path, "size": agg.size, "order": {"_count": "desc"}}
            # Only where the mapping says the value will parse. The editor now
            # offers every field the mapping can count by, numbers included,
            # and a word sent as a number's `missing` is a 400 that takes the
            # whole batch — every other panel on the board — down with it.
            if agg.missing is not None and mapped in _MISSING_CAN_BE_A_STRING:
                terms["missing"] = agg.missing
            node = {"terms": terms}
        else:
            refuse(f"unknown aggregation type: {type(agg).__name__}")
            return None

        if agg.sub:
            node["aggs"] = {}
            for child in agg.sub:
                translated = self._translate_agg(child, targets, query, warnings,
                                                 notes, owner)
                if translated is not None:
                    node["aggs"][child.name] = translated
            if not node["aggs"]:
                node.pop("aggs")
        return node

    def _read_buckets(self, node, agg):
        if not node:
            return []
        out = []
        for raw in node.get("buckets") or []:
            bucket = Bucket(key=raw.get("key"),
                            count=_count(raw.get("doc_count", 0)),
                            key_text=raw.get("key_as_string"))
            for child in agg.sub or ():
                if child.name in raw:
                    bucket.sub[child.name] = self._read_buckets(raw[child.name], child)
            out.append(bucket)
        return out

    def _resolve_agg_field(self, targets, neutral_name):
        """The real aggregatable field path, or None. See `_resolve_agg`."""
        return self._resolve_agg(targets, neutral_name)[0]

    def _resolve_agg(self, targets, neutral_name):
        """Find the real aggregatable field path and its mapped type.

        The type is None when the mapping did not say — an unreadable mapping,
        or the dotted-path guess below — and a caller that needs to know what
        a value will be parsed as must treat that as "not known to be a
        string" rather than as a keyword.

        A neutral name can live under more than one backend field: `severity`
        is `level` in a flat index and `severity_text` in one written by the
        OpenTelemetry Collector. The candidates are tried against the actual
        mapping, so the answer comes from the indices being queried rather than
        from an assumption about who wrote them.

        A mapping that cannot be read leaves the guess below, as it always
        did; it is only no longer remembered as an empty one.
        """
        try:
            discovered, types = self._discovered(targets, max_fields=1000)
        except Exception:
            discovered, types = {}, {}
        for candidate in field_candidates(neutral_name):
            if candidate in discovered:
                return discovered[candidate], types.get(candidate)
        # Not discovered — a dotted path may still be valid; a bare name is not.
        for candidate in field_candidates(neutral_name):
            if "." in candidate:
                return candidate, None
        return None, None

    def histogram(self, query, scope):
        targets = self._targets(query, scope)
        if not targets:
            return PartialCounts()
        body = {
            "size": 0,
            "query": self._build_query(query),
            "aggs": {"timeline": {"date_histogram": {
                "field": "@timestamp",
                "fixed_interval": query.window.suggest_interval(),
                "min_doc_count": 0,
            }}},
        }
        try:
            response = _search(self._es, targets, body,
                               timeout="15s", request_cache=True)
        except Exception as exc:
            return PartialCounts(
                warnings=(f"the histogram could not be read: {exc}",))
        try:
            # The same partial answer `search` reports: counts from the shards
            # that answered, drawn as a whole series by everything that reads
            # a bare list of buckets.
            shards = _shard_failure(response)
            buckets = [{"timestamp": b["key_as_string"],
                        "count": _count(b["doc_count"])}
                       for b in response["aggregations"]["timeline"]["buckets"]]
        except MalformedResponse as exc:
            return PartialCounts(
                warnings=(f"the cluster's answer could not be read: {exc}",))
        return PartialCounts(buckets, warnings=(shards,) if shards else ())

    # ---------- internals ----------

    def _build_query(self, query):
        """Translate the neutral query tree into Elasticsearch query DSL.

        Raw text is never handed to Elasticsearch: what we emit is a structured
        query. That lets us catch syntax errors early and decide ourselves which
        clauses belong in filter context.
        """
        must = [self._render(query.filter)]
        must.append({"range": {"@timestamp": query.window.as_es_range()}})

        # Exact filters go into filter context: not scored, and cacheable
        filters = [{"term": {self._field_for(k): v}}
                   for k, v in (query.filters or {}).items()]
        must_not = [{"term": {self._field_for(k): v}}
                    for k, v in (query.exclude or {}).items()]

        clause = {"bool": {"must": must}}
        if filters:
            clause["bool"]["filter"] = filters
        if must_not:
            clause["bool"]["must_not"] = must_not
        return clause

    def _any_field(self, neutral_name, build):
        """Build a clause that matches the field wherever it lives.

        `severity` is `level` in a flat index and `severity_text` in one the
        OpenTelemetry Collector wrote, and a single search can span both. A
        clause naming one of them matches nothing in the other half of the
        result set — silently, because "no results" and "wrong field name"
        look identical.

        Every candidate is tried with `should`. A field that does not exist in
        an index simply does not match there, which is exactly right. A name
        the table does not know is tried where the collector keeps it as
        well — see `match_candidates`.
        """
        candidates = match_candidates(neutral_name)
        if len(candidates) == 1:
            return build(candidates[0])
        return {"bool": {"should": [build(name) for name in candidates],
                         "minimum_should_match": 1}}

    def _render(self, node):
        """Neutral node -> Elasticsearch query DSL."""
        f = self._field_for

        if isinstance(node, ql.MatchAll):
            return {"match_all": {}}

        if isinstance(node, ql.Term):
            # `match` is deliberate: exact on a keyword field, analysed on a
            # text field. `term` would silently match nothing on analysed fields.
            return self._any_field(
                node.field,
                lambda name: {"match": {name: {"query": node.value}}})

        if isinstance(node, ql.Phrase):
            return self._any_field(
                node.field, lambda name: {"match_phrase": {name: node.text}})

        if isinstance(node, ql.Prefix):
            return self._any_field(
                node.field, lambda name: {"prefix": {name: node.value}})

        if isinstance(node, ql.Wildcard):
            return self._any_field(
                node.field,
                lambda name: {"wildcard": {name: {"value": node.pattern}}})

        if isinstance(node, ql.Exists):
            return self._any_field(
                node.field, lambda name: {"exists": {"field": name}})

        if isinstance(node, ql.Range):
            bounds = {k: v for k, v in (("gte", node.gte), ("lte", node.lte),
                                        ("gt", node.gt), ("lt", node.lt))
                      if v is not None}
            return self._any_field(
                node.field, lambda name: {"range": {name: bounds}})

        if isinstance(node, ql.FullText):
            return self._any_field(
                ql.DEFAULT_FIELD,
                lambda name: {"match": {name: {"query": node.text}}})

        if isinstance(node, ql.And):
            return {"bool": {"must": [self._render(c) for c in node.clauses]}}

        if isinstance(node, ql.Or):
            return {"bool": {"should": [self._render(c) for c in node.clauses],
                             "minimum_should_match": 1}}

        if isinstance(node, ql.Not):
            return {"bool": {"must_not": [self._render(node.clause)]}}

        raise ValueError(f"untranslatable query node: {type(node).__name__}")

    @staticmethod
    def _field_for(neutral_name):
        """Map a neutral field name onto its Elasticsearch field."""
        return {"severity": "level", "severity_text": "level",
                "body": "message", "timestamp": "@timestamp"}.get(
                    neutral_name, neutral_name)

    def context(self, ref, scope, before=10, after=10, correlate_by=None):
        """The chronological neighbours of a record.

        With `correlate_by` (host or correlation_id, say) only records sharing
        that field value are returned — the way to follow a single stream inside
        a noisy index.
        """
        record = self.fetch(ref, scope)
        if record is None or record.timestamp is None:
            return LogContext(record=record)

        # To the millisecond. The anchor was cut to the second, so `lt` and
        # `gt` both missed the rest of its second — the closest neighbours.
        # Measured on the lab: of a second holding three records, the two
        # beside the one opened were in neither list. The record's own
        # millisecond goes before it, less the record itself, so a record
        # sharing it is shown once rather than on both sides.
        anchor = timerange.to_es_millis(record.timestamp)
        correlation = None
        if correlate_by:
            correlation = self._value_of(record, correlate_by)

        def neighbours(order, operator, size):
            must = [{"range": {"@timestamp": {operator: anchor}}}]
            if correlation is not None:
                must.append({"term": {self._field_for(correlate_by): correlation}})
            body = {
                "query": {"bool": {"must": must,
                                   "must_not": [{"ids": {"values": [ref.id]}}]}},
                "sort": [{"@timestamp": {"order": order}}, {"_doc": {"order": order}}],
                "size": min(size, 50),
                "_source": source_fields(DEFAULT_LOG_FIELDS),
            }
            try:
                response = _search(self._es, ref.container, body, timeout="10s")
            except Exception:
                return []
            return [self._to_record(h) for h in response["hits"]["hits"]]

        earlier = neighbours("desc", "lte", before)
        earlier.reverse()          # put back into chronological order
        return LogContext(
            record=record,
            before=earlier,
            after=neighbours("asc", "gt", after),
            correlated_by=correlate_by if correlation is not None else None,
        )

    @staticmethod
    def _value_of(record, neutral_name):
        """Find the value of a neutral field within a record."""
        direct = {"service": record.service, "body": record.body,
                  "severity": record.severity_text or record.severity}
        if neutral_name in direct:
            return direct[neutral_name] or None
        if neutral_name in record.resource:
            return record.resource[neutral_name]
        return record.attributes.get(neutral_name)

    #: Fields shown first in the sidebar — the ones users filter on most
    _PRIORITY_FIELDS = ("level", "service", "host", "environment")

    _FIELD_CACHE_TTL = 60.0

    def _aggregatable_fields(self, targets, max_fields=10):
        """The discovered field name -> the path to aggregate it on.

        The types the same walk found are beside it in `_discovered`, cached
        together: what a field IS decides whether `missing` can be a string,
        and asking separately would be a second get_mapping for a fact the
        first one already carried.
        """
        return self._discovered(targets, max_fields)[0]

    def _discovered(self, targets, max_fields=10):
        """Cached in front of the real discovery: mappings change rarely, but
        this was issuing a get_mapping on every field-stats request."""
        key = (",".join(targets), max_fields)
        cached = getattr(self, "_field_cache", None)
        if cached is None:
            cached = self._field_cache = {}
        hit = cached.get(key)
        if hit and (time.monotonic() - hit[0]) < self._FIELD_CACHE_TTL:
            return hit[1]
        discovered = self._discover_aggregatable_fields(targets, max_fields)
        cached[key] = (time.monotonic(), discovered)
        return discovered

    def _discover_aggregatable_fields(self, targets, max_fields=10):
        """Discover aggregatable fields across the target indices.

        Answers a PAIR: the name -> path map everything reads, and the name ->
        mapped type map beside it. The type is not decoration: `missing` is
        parsed as the field's own type, so sending a word for a `short` is a
        400 for the whole search.

        EVERY target's mapping is scanned, not just the first. Looking at one
        index causes a silent failure: because indices are ordered newest first,
        an index whose top-level fields are all objects (an APM trace store, for
        instance) landing at the head of the list means nothing is discovered
        and the sidebar goes blank without an error.

        A mapping that cannot be read raises, and so is not cached: it was
        answered with {} and the {} remembered for a minute, so an account
        without `view_index_metadata` had "No field data available" on every
        request.
        """
        if not targets:
            return {}, {}
        mapping = self._es.indices.get_mapping(index=",".join(targets))

        skip = {"@timestamp", "message"}
        aggregatable = {"keyword", "boolean", "integer", "short", "byte", "long", "ip"}
        found, types = {}, {}

        def walk(properties, prefix=""):
            """Descend into object fields.

            Only top-level properties used to be examined, which was enough
            while every log document was flat. The OpenTelemetry Collector
            nests the service name under `resource.attributes.service.name`, so
            a flat scan finds nothing there and the caller falls back to the
            raw path — which is a text field, and aggregating on it fails with
            a fielddata error rather than an empty panel.
            """
            for name, definition in properties.items():
                if name.startswith("_") or not isinstance(definition, dict):
                    continue
                path = f"{prefix}{name}"
                if path in skip or path in found:
                    continue

                field_type = definition.get("type")
                if field_type in aggregatable:
                    found[path] = path
                    types[path] = field_type
                elif field_type == "text" and "keyword" in (definition.get("fields") or {}):
                    found[path] = f"{path}.keyword"
                    # The type of what is AGGREGATED, which is the sub-field:
                    # `service` is text, `service.keyword` is the keyword the
                    # bucket keys come from and the one `missing` is read as.
                    types[path] = "keyword"
                elif definition.get("properties"):
                    # An object. Bounded depth: telemetry nests two or three
                    # levels, and an unbounded walk over a mapping with
                    # thousands of dynamic fields is its own problem.
                    if prefix.count(".") < 3:
                        walk(definition["properties"], f"{path}.")

        for index_mapping in mapping.values():
            walk((index_mapping.get("mappings") or {}).get("properties") or {})

        ordered = {}
        for name in self._PRIORITY_FIELDS:
            if name in found:
                ordered[name] = found.pop(name)
        for name in sorted(found):
            if len(ordered) >= max_fields:
                break
            ordered[name] = found[name]
        return ordered, {name: types[name] for name in ordered if name in types}

    def _to_record(self, hit):
        """Turn a hit into a record using whatever schema wrote it.

        Chosen per document rather than per index: a search can span indices
        written by different pipelines, and picking one schema for the whole
        response would silently mangle half of it.

        A hit from a data stream names its backing index; the record names
        the stream, which is what a role is granted, what a person
        recognises, and what a rollover does not replace.
        """
        stream = self._catalogue.stream_of(hit.get("_index"))
        if stream:
            hit = dict(hit, _index=stream)
        schema = schema_for_document(hit.get("_source"))
        return schema.to_record(hit, self.backend, self.name)


class TraceSearchFailed(RuntimeError):
    """Nothing this trace source was asked could be read."""


class ElasticsearchTraceSource(TraceSource):
    """Exposes Elasticsearch indices as a neutral trace source.

    More than one schema (OTel, Elastic APM) is supported at once: each index's
    schema is detected from its mapping, one query is issued per schema group,
    and the results are merged into a single neutral Trace. The caller never
    learns which span came from which schema.

    A group that cannot answer is not an empty group. When some answered, the
    answer is marked partial and names what is missing; when none did, the
    failure is raised, and the route turns it into a 503 the page shows.
    """

    backend = "elasticsearch"

    #: Seconds before an index whose mapping named no span schema is asked
    #: again: it may be a trace index before its first span. A mapping that
    #: could not be READ is not remembered at all.
    _UNRECOGNISED_TTL = 60.0

    def __init__(self, client, name="elasticsearch-traces",
                 patterns=DEFAULT_TRACE_PATTERNS, catalogue=None):
        self._es = client
        self.name = name
        self._patterns = tuple(patterns)
        self._schema_cache = {}
        self._catalogue = catalogue or _IndexCatalogue(client)

    @property
    def capabilities(self):
        return frozenset({Capability.TRACE_LOOKUP, Capability.TRACE_SEARCH,
                          Capability.SERVICE_LIST})

    def health(self):
        # `ping()` returns False rather than raising, so the detail has to
        # branch too. Returning a constant "ok" made the failure log line —
        # `health: elasticsearch-traces: ok` — read as a success.
        try:
            if self._es.ping():
                return True, "ok"
            return False, "ping failed: no response from the cluster"
        except Exception as exc:
            return False, str(exc)

    def containers(self, scope):
        # Trace stores have their own boundary: log patterns do not match trace
        # indices, and a role may see logs without seeing traces.
        if scope.trace_is_empty:
            return []
        names = [e["index"] for e in self._catalogue.entries()
                 if not e["index"].startswith(".")]
        matched = [n for n in names
                   if any(_pattern_matches(p, n) for p in self._patterns)]
        return sorted(scope.resolve_traces(matched, source=self.name))

    def _schema_for(self, index):
        """The schema of an index, or None when its mapping names none.

        Raises when the mapping could not be read. That used to be taken for
        "no schema", and the None was cached for good: one timed-out mapping
        request, or an index listed before its first span, and the index was
        out of every search until the process restarted, with nothing said.
        """
        cached = self._schema_cache.get(index)
        if cached is not None:
            schema, seen = cached
            if schema is not None or time.monotonic() - seen < self._UNRECOGNISED_TTL:
                return schema
        mapping = self._es.indices.get_mapping(index=index)
        entry = next(iter(mapping.values()), None) or {}
        schema = detect_schema((entry.get("mappings") or {}).get("properties") or {})
        if schema is None and cached is None:
            logger.warning(f"{self.name}: {index} matches the trace patterns but "
                           f"its mapping is no span schema WDash reads; left out")
        self._schema_cache[index] = (schema, time.monotonic())
        return schema

    def _grouped(self, scope):
        """({schema: [index, ...]}, [what could not be read, ...]).

        An index whose mapping names no span schema is skipped: it is not a
        trace store. One whose mapping could not be read is a store this
        answer is missing, and says so.
        """
        groups, failures = {}, []
        for index in self.containers(scope):
            try:
                schema = self._schema_for(index)
            except Exception as exc:
                logger.warning(f"{self.name}: the mapping of {index} could not be "
                               f"read, so it was not searched: {exc}")
                failures.append(f"{index}: its mapping could not be read ({exc})")
                continue
            if schema:
                # Keyed by what makes two indices searchable in one request,
                # which is not the class alone: two spellings of one schema
                # sort by different fields, and a single request can only
                # name one of them.
                groups.setdefault(schema.group_key, (schema, []))[1].append(index)
        return ({schema: indices for schema, indices in groups.values()}, failures)

    def _search_groups(self, groups, requests, failures):
        """Each group's answer, None for one that failed — which `failures`
        is told about, with the reason."""
        reasons = {}
        responses = _multi_search(self._es, requests, reasons=reasons)
        for position, (_, indices) in enumerate(groups):
            if responses[position] is None:
                failures.append(f"{', '.join(indices)}: the search failed "
                                f"({reasons.get(position, 'no reason given')})")
        return responses

    def _nothing_answered(self, failures):
        return TraceSearchFailed(f"{self.name} could not be searched: "
                                 + "; ".join(failures))

    def trace(self, trace_id, window, scope):
        spans = []
        groups, failures = self._grouped(scope)
        groups = list(groups.items())

        requests = [
            (indices, {
                "query": {"bool": {"must": [
                    {"term": {schema.trace_id_field: trace_id}},
                    {"range": {schema.timestamp_field: window.as_es_range()}},
                ]}},
                "sort": [{schema.timestamp_field: {"order": "asc"}}],
                "size": 1000,
            })
            for schema, indices in groups
        ]

        # De-duplicate by span id. The same logical span can arrive from more
        # than one schema when a cluster holds both an OTel and an APM copy of
        # the same trace. Left unmerged it would double the waterfall and, worse,
        # break self-time: children would be counted twice and every parent
        # would report zero time of its own.
        seen_spans, hidden = set(), set()

        responses = self._search_groups(groups, requests, failures)
        for (schema, _), response in zip(groups, responses):
            if response is None:
                continue
            for hit in response["hits"]["hits"]:
                span = schema.to_span(hit)
                if span is not None:
                    span.source = self.name
                if not span or span.span_id in seen_spans:
                    continue
                if not scope.allows_service(span.service, source=self.name):
                    hidden.add(span.span_id)
                    continue
                seen_spans.add(span.span_id)
                spans.append(span)

        if not spans:
            # Not "not found" while a store that may hold it did not answer.
            if failures:
                raise self._nothing_answered(failures)
            return None

        spans.sort(key=lambda s: (s.start is None, s.start))
        return Trace(trace_id=trace_id, spans=spans, partial=bool(failures),
                     hidden=len(hidden), warnings=tuple(failures))

    def search(self, query, scope):
        """Find traces matching the query.

        Implemented by querying SPANS rather than aggregating over trace ids.
        A terms aggregation on trace_id would be both expensive and only
        approximately correct at high cardinality; one span per trace, with
        `collapse` doing the de-duplication, is exact and cheap.

        Which span represents a trace depends on the question being asked:

          - filtered by service -> that service's own entry span, because the
            user asked about that service's work
          - unfiltered          -> the trace ROOT, because a plain trace list
            should show where each request came in

        Without the root restriction, `collapse` would pick whichever span
        happened to sort first, which is usually some downstream service — a
        confusing thing to show as "the trace".

        `TraceSummary` names its fields literally for this reason: `service` is
        the span that matched, not necessarily the root.
        """
        summaries, seen = [], set()
        groups, requests = [], []
        grouped, failures = self._grouped(scope)

        for schema, indices in grouped.items():
            must = [{"range": {schema.timestamp_field: query.window.as_es_range()}}]

            if query.service:
                if not scope.allows_service(query.service, source=self.name):
                    continue
                must.append({"term": {schema.service_field: query.service}})

            # Entry spans only: a service may emit many spans per trace and we
            # want one row per trace, describing work the service handled.
            must.append(schema.entry_filter())

            # Push the scope's service restriction INTO the query. Filtering
            # after the fact is wrong here: `collapse` returns the top N by
            # sort order, so a restricted role would get a page full of spans
            # it cannot see and end up with an empty list even when matching
            # traces exist.
            scope_filter = self._scope_service_filter(schema, scope, self.name)
            if scope_filter is not None:
                must.append(scope_filter)

            collapse = {"field": schema.trace_id_field}
            if not query.service and scope_filter is None:
                # No service asked for, so show where each request entered.
                must.append({"bool": {"must_not": [
                    {"exists": {"field": schema.parent_field}}]}})
            elif not query.service:
                # The root may be a span this role cannot see. Requiring it
                # beside the service rule kept only the traces whose ROOT was
                # visible: a role allowed `postgres` saw no trace at all,
                # because no request enters through the database. So every
                # visible entry span competes, and each trace is described
                # by its root when the root is among them, otherwise by the
                # earliest of them.
                collapse["inner_hits"] = {
                    "name": "entry", "size": 1,
                    "sort": [
                        {schema.parent_field: {
                            "order": "asc", "missing": "_first",
                            "unmapped_type": "keyword"}},
                        {schema.timestamp_field: {"order": "asc"}}]}

            if query.only_errors:
                must.append(schema.error_filter())
            if query.min_duration_us:
                must.append(schema.duration_filter(query.min_duration_us))

            groups.append((schema, indices))
            requests.append((indices, {
                "query": {"bool": {"must": must}},
                "size": min(query.limit, 200),
                # One row per trace without a terms aggregation.
                "collapse": collapse,
                "sort": (schema.slowest_first() if query.sort == SORT_SLOWEST
                         else [{schema.timestamp_field: {"order": "desc"}}]),
            }))

        responses = self._search_groups(groups, requests, failures)
        if failures and not any(response is not None for response in responses):
            raise self._nothing_answered(failures)

        for (schema, _), response in zip(groups, responses):
            if response is None:
                continue
            for hit in response["hits"]["hits"]:
                chosen = (((hit.get("inner_hits") or {}).get("entry") or {})
                          .get("hits") or {}).get("hits") or ()
                span = schema.to_span(chosen[0] if chosen else hit)
                if span is not None:
                    span.source = self.name
                if not span or span.trace_id in seen:
                    continue
                if not scope.allows_service(span.service, source=self.name):
                    continue
                seen.add(span.trace_id)
                summaries.append(TraceSummary(
                    trace_id=span.trace_id,
                    service=span.service,
                    name=span.name,
                    start=span.start,
                    duration_us=span.duration_us,
                    has_error=span.failed,
                ))

        reverse = query.sort == SORT_SLOWEST
        summaries.sort(
            key=lambda t: t.duration_us if reverse else (t.start.timestamp() if t.start else 0),
            reverse=True)
        return PartialList(summaries[:query.limit], partial=bool(failures),
                           warnings=failures)

    @staticmethod
    def _scope_service_filter(schema, scope, source_name):
        """Turn the scope's service allowlist into a query clause.

        Returns None when the scope imposes no restriction. Built from the
        patterns that apply to THIS source (bare ones, and ones qualified with
        its name), so `other-source:api-*` does not widen it and
        `-this-source:payments` does narrow it. A `*` alone is no restriction;
        a `*` beside an exclusion still has an exclusion to push down — it
        used to return early here and leave `-payments` to a post-filter,
        which is a short page rather than a boundary in the query.
        """
        from ...hub.patterns import for_source, narrows
        if not narrows(scope.services, source_name, scope.sources):
            return None
        applicable = for_source(scope.services, source_name, scope.sources)
        if not applicable:
            # An empty allowlist means nothing is visible.
            return {"match_none": {}}

        # The filter pushed into the query has to mean the same thing as
        # Scope.allows_service, or the boundary and the query disagree. This
        # rendered a trailing star and nothing else: `*-service` became a term
        # lookup for the literal string, and an exclusion would have become a
        # term lookup for `-payment-*`. Both fail closed, so nobody would have
        # noticed — the restricted role would just have seen less than it was
        # granted, with no error.
        from ...hub import patterns as patterns_module
        from ...hub.patterns import partition, shape

        allow, deny = partition(applicable)
        if not allow:
            return {"match_none": {}}

        def clause(pattern):
            field = schema.service_field
            kind = shape(pattern)
            if kind == patterns_module.ANY:
                # Everything, a span with no service field included: the
                # check calls its service "" and `*` matches that. `exists`
                # dropped such spans from the query alone.
                return {"match_all": {}}
            if kind == patterns_module.EXACT:
                return {"term": {field: pattern}}
            # `wildcard` covers prefix, suffix and contains alike. Special-
            # casing prefix bought nothing and was the reason the other two
            # were missing.
            return {"wildcard": {field: {
                "value": patterns_module.glob(pattern, _wildcard_literal)}}}

        query = {"bool": {}}
        if "*" not in allow:
            query["bool"]["should"] = [clause(p) for p in allow]
            query["bool"]["minimum_should_match"] = 1
        if deny:
            query["bool"]["must_not"] = [clause(p) for p in deny]
        return query

    def services(self, window, scope):
        totals, errors = {}, {}
        groups, requests = [], []
        grouped, failures = self._grouped(scope)

        for schema, indices in grouped.items():
            groups.append((schema, indices))
            requests.append((indices, {
                "size": 0,
                "query": {"range": {schema.timestamp_field: window.as_es_range()}},
                "aggs": {"services": {
                    "terms": {"field": schema.service_field, "size": 100},
                    "aggs": {"failed": {"filter": schema.error_filter()}},
                }},
            }))

        responses = self._search_groups(groups, requests, failures)
        if failures and not any(response is not None for response in responses):
            raise self._nothing_answered(failures)

        for response in responses:
            if response is None:
                continue
            for bucket in response["aggregations"]["services"]["buckets"]:
                name = bucket["key"]
                if not scope.allows_service(name, source=self.name):
                    continue
                totals[name] = totals.get(name, 0) + _count(bucket["doc_count"])
                errors[name] = (errors.get(name, 0)
                                + _count(bucket["failed"]["doc_count"]))

        return PartialList(sorted(
            (Service(name=n, span_count=c, error_count=errors.get(n, 0))
             for n, c in totals.items()),
            key=lambda s: s.span_count, reverse=True,
        ), partial=bool(failures), warnings=failures)
