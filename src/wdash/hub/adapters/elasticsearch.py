"""
Elasticsearch adapters.

Everything Elasticsearch-specific stops here. Outside this file, `hits`,
`_source` and `aggregations` do not appear.
"""

import time

from ...utils import timerange
from ..models import (
    FieldStat, FieldValue, LogContext, LogPage, LogRecord, Service, SourceRef,
    Span, Trace, TraceSummary, normalise_severity,
)
from ..aggregation import AggregationResult, Bucket, DateHistogram, Terms
from ..query import DEFAULT_LOG_FIELDS, SORT_SLOWEST
from .. import query_language as ql
from ..source import Capability, LogSource, TraceSource
from .es_log_schema import field_candidates, schema_for_document
from .es_trace_schema import detect_schema, dig, parse_time

# Log fields mapped onto the neutral model. Everything else lands in attributes.
_MAPPED_LOG_FIELDS = {"@timestamp", "message", "level", "service",
                      "trace_id", "span_id"}
_RESOURCE_FIELDS = ("host", "environment", "container", "pod", "namespace")


from ..patterns import matches as _pattern_matches  # noqa: F401


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


def _multi_search(es, requests, timeout="15s"):
    """Run several searches in ONE round trip.

    Both sources need this: trace lookups fan out per schema, and comparing a
    window with the previous one is two queries. Issuing them separately would
    double the round trips for what Elasticsearch answers in a single batch.

    A per-query failure comes back as None so one bad request does not lose the
    results of the others.
    """
    if not requests:
        return []
    if len(requests) == 1:
        indices, body = requests[0]
        try:
            return [_search(es, indices, body, timeout=timeout)]
        except Exception:
            return [None]

    payload = []
    for indices, body in requests:
        payload.append({"index": ",".join(indices)})
        payload.append(body)
    try:
        response = es.msearch(searches=payload)
    except Exception:
        return [None] * len(requests)

    out = []
    for item in response.get("responses", []):
        out.append(None if item.get("error") else item)
    while len(out) < len(requests):
        out.append(None)
    return out


class _IndexCatalogue:
    """Short-lived cache of the cluster's index list.

    `cat.indices` is a cluster-level call and the index list barely changes,
    yet it was being issued on every single API request. The cache is keyed by
    nothing because the RAW list is user-independent — scope filtering happens
    afterwards, so no user ever sees another user's indices through it.
    """

    def __init__(self, client, ttl=30.0):
        self._es = client
        self._ttl = ttl
        self._entries = None
        self._fetched_at = 0.0

    def entries(self):
        now = time.monotonic()
        if self._entries is not None and (now - self._fetched_at) < self._ttl:
            return self._entries
        try:
            fetched = self._es.cat.indices(format="json", h="index,creation.date")
        except Exception:
            # Serve a stale list rather than pretending the cluster is empty:
            # an empty list would look like "you have access to nothing".
            return self._entries if self._entries is not None else []
        self._entries = [dict(e) for e in fetched]
        self._fetched_at = now
        return self._entries

    def invalidate(self):
        self._entries = None


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
        entries = list(self._catalogue.entries())
        # Newest first: with time-based indices the user almost always cares
        # about the freshest one.
        entries = [e for e in entries
                   if not e["index"].startswith(".") and not e["index"].startswith("_")]
        entries.sort(key=lambda e: int(e.get("creation.date") or 0), reverse=True)
        names = [e["index"] for e in entries]

        # The source's own patterns first, then the scope
        if "*" not in self._patterns:
            names = [n for n in names
                     if any(_pattern_matches(p, n) for p in self._patterns)]
        if self._exclude:
            names = [n for n in names
                     if not any(_pattern_matches(p, n) for p in self._exclude)]
        return scope.resolve(names, source=self.name)

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
        targets = self._targets(query, scope)
        # Sending an empty target list to Elasticsearch means '*' — the exact opposite.
        if not targets:
            return LogPage(warnings=("the scope permits no containers",))

        body = {
            "query": self._build_query(query),
            "sort": [{"@timestamp": {"order": "asc" if query.ascending else "desc"}},
                     {"_doc": {"order": "asc" if query.ascending else "desc"}}],
            "size": min(query.limit, 500),
            "track_total_hits": True,
        }
        # Keep the list view narrow. The full record is only fetched when the
        # detail view asks for it.
        if query.fields:
            body["_source"] = sorted({name for field in query.fields
                                      for name in field_candidates(field)})
        if query.cursor:
            body["search_after"] = query.cursor

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
        total = response["hits"]["total"]
        total = total["value"] if isinstance(total, dict) else total

        histogram = []
        timeline = (response.get("aggregations") or {}).get("timeline")
        if timeline:
            for bucket in timeline.get("buckets", []):
                by_severity = {}
                for sub in (bucket.get("severity") or {}).get("buckets", []):
                    by_severity[normalise_severity(sub["key"])] = sub["doc_count"]
                histogram.append({
                    "timestamp": bucket.get("key_as_string"),
                    "key": bucket.get("key"),
                    "count": bucket.get("doc_count", 0),
                    "by_severity": by_severity,
                })

        return LogPage(
            records=[self._to_record(h) for h in hits],
            total=total,
            took_ms=response.get("took", 0),
            cursor=hits[-1].get("sort") if hits else None,
            containers=tuple(targets),
            partial=bool(response.get("timed_out")),
            histogram=histogram,
        )

    def fetch(self, ref, scope):
        if not scope.allows_container(ref.container):
            return None
        try:
            response = self._es.get(index=ref.container, id=ref.id)
        except Exception:
            return None
        return self._to_record({"_index": response["_index"], "_id": response["_id"],
                                "_source": response["_source"]})

    def raw(self, ref, scope):
        """The Elasticsearch document, untranslated.

        Returns the hit envelope (`_index`/`_id`/`_source`) rather than
        `_source` alone: which index a record actually landed in is often the
        thing being diagnosed, and it is not visible from the source body.
        """
        if not scope.allows_container(ref.container):
            return None
        try:
            response = self._es.get(index=ref.container, id=ref.id)
        except Exception:
            return None
        return {"_index": response.get("_index"), "_id": response.get("_id"),
                "_source": response.get("_source") or {}}

    def field_stats(self, query, scope, fields=None, top=10):
        targets = self._targets(query, scope)
        if not targets:
            return []

        discovered = fields or self._aggregatable_fields(targets)
        if not discovered:
            return []

        aggs = {name: {"terms": {"field": path, "size": top}}
                for name, path in discovered.items()}
        body = {"size": 0, "query": self._build_query(query), "aggs": aggs}

        try:
            response = _search(self._es, targets, body,
                               timeout="10s", request_cache=True)
        except Exception:
            return []

        stats = []
        for name in discovered:
            buckets = (response.get("aggregations") or {}).get(name, {}).get("buckets", [])
            if buckets:
                stats.append(FieldStat(
                    field=name,
                    values=[FieldValue(value=b["key"], count=b["doc_count"]) for b in buckets],
                ))
        return stats

    def aggregate(self, query, aggregations, scope):
        """Run the given aggregations in a SINGLE Elasticsearch request.

        The dashboard's four panels ask for different aggregations over the
        same query; issuing one request each keeps Elasticsearch's search
        thread pool busy for no reason.
        """
        targets = self._targets(query, scope)
        if not targets:
            return AggregationResult(warnings=("the scope permits no containers",))

        warnings = []
        body = {"size": 0, "query": self._build_query(query),
                "aggs": {}, "track_total_hits": True}
        for agg in aggregations:
            translated = self._translate_agg(agg, targets, query, warnings)
            if translated is not None:
                body["aggs"][agg.name] = translated

        if not body["aggs"]:
            return AggregationResult(warnings=tuple(warnings))

        try:
            response = _search(self._es, targets, body,
                               timeout="30s", request_cache=True)
        except Exception as exc:
            # An empty panel and "the query could not run" are different things.
            # Carrying the reason and returning empty beats a 500.
            return AggregationResult(warnings=tuple(warnings) + (str(exc)[:200],),
                                     failed=True)

        total = response["hits"]["total"]
        total = total["value"] if isinstance(total, dict) else total
        raw = response.get("aggregations") or {}

        return AggregationResult(
            total=total,
            buckets={agg.name: self._read_buckets(raw.get(agg.name), agg)
                     for agg in aggregations if agg.name in raw},
            warnings=tuple(warnings),
        )

    def multi_aggregate(self, requests, scope):
        targets = None
        bodies, metadata = [], []

        for query, aggregations in requests:
            if targets is None:
                targets = self._targets(query, scope)
            if not targets:
                metadata.append((aggregations, ["the scope permits no containers"]))
                continue

            warnings = []
            aggs = {}
            for agg in aggregations:
                translated = self._translate_agg(agg, targets, query, warnings)
                if translated is not None:
                    aggs[agg.name] = translated
            metadata.append((aggregations, warnings))
            bodies.append((targets, {"size": 0, "query": self._build_query(query),
                                     "aggs": aggs, "track_total_hits": True}))

        if not bodies:
            return [AggregationResult(warnings=tuple(w)) for _, w in metadata]

        responses = _multi_search(self._es, bodies, timeout="30s")
        out = []
        for (aggregations, warnings), response in zip(metadata, responses):
            if response is None:
                out.append(AggregationResult(
                    warnings=tuple(warnings) + ("query failed",), failed=True))
                continue
            total = response["hits"]["total"]
            total = total["value"] if isinstance(total, dict) else total
            raw = response.get("aggregations") or {}
            out.append(AggregationResult(
                total=total,
                buckets={agg.name: self._read_buckets(raw.get(agg.name), agg)
                         for agg in aggregations if agg.name in raw},
                warnings=tuple(warnings)))
        return out

    def _translate_agg(self, agg, targets, query, warnings):
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
            path = self._resolve_agg_field(targets, agg.field)
            if path is None:
                warnings.append(
                    f"'{agg.field}' cannot be aggregated on these indices "
                    "(it may not be mapped as keyword)")
                return None
            terms = {"field": path, "size": agg.size, "order": {"_count": "desc"}}
            if agg.missing is not None:
                terms["missing"] = agg.missing
            node = {"terms": terms}
        else:
            warnings.append(f"unknown aggregation type: {type(agg).__name__}")
            return None

        if agg.sub:
            node["aggs"] = {}
            for child in agg.sub:
                translated = self._translate_agg(child, targets, query, warnings)
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
            bucket = Bucket(key=raw.get("key"), count=raw.get("doc_count", 0),
                            key_text=raw.get("key_as_string"))
            for child in agg.sub or ():
                if child.name in raw:
                    bucket.sub[child.name] = self._read_buckets(raw[child.name], child)
            out.append(bucket)
        return out

    def _resolve_agg_field(self, targets, neutral_name):
        """Find the real aggregatable field path, or None.

        A neutral name can live under more than one backend field: `severity`
        is `level` in a flat index and `severity_text` in one written by the
        OpenTelemetry Collector. The candidates are tried against the actual
        mapping, so the answer comes from the indices being queried rather than
        from an assumption about who wrote them.
        """
        discovered = self._aggregatable_fields(targets, max_fields=1000)
        for candidate in field_candidates(neutral_name):
            if candidate in discovered:
                return discovered[candidate]
        # Not discovered — a dotted path may still be valid; a bare name is not.
        for candidate in field_candidates(neutral_name):
            if "." in candidate:
                return candidate
        return None

    def histogram(self, query, scope):
        targets = self._targets(query, scope)
        if not targets:
            return []
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
        except Exception:
            return []
        return [{"timestamp": b["key_as_string"], "count": b["doc_count"]}
                for b in response["aggregations"]["timeline"]["buckets"]]

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
        an index simply does not match there, which is exactly right.
        """
        candidates = field_candidates(neutral_name)
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

        anchor = timerange.to_es(record.timestamp)
        correlation = None
        if correlate_by:
            correlation = self._value_of(record, correlate_by)

        def neighbours(order, operator, size):
            must = [{"range": {"@timestamp": {operator: anchor}}}]
            if correlation is not None:
                must.append({"term": {self._field_for(correlate_by): correlation}})
            body = {
                "query": {"bool": {"must": must}},
                "sort": [{"@timestamp": {"order": order}}],
                "size": min(size, 50),
                "_source": sorted({name for field in DEFAULT_LOG_FIELDS
                                   for name in field_candidates(field)}),
            }
            try:
                response = _search(self._es, ref.container, body, timeout="10s")
            except Exception:
                return []
            return [self._to_record(h) for h in response["hits"]["hits"]]

        earlier = neighbours("desc", "lt", before)
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

        EVERY target's mapping is scanned, not just the first. Looking at one
        index causes a silent failure: because indices are ordered newest first,
        an index whose top-level fields are all objects (an APM trace store, for
        instance) landing at the head of the list means nothing is discovered
        and the sidebar goes blank without an error.
        """
        if not targets:
            return {}
        try:
            mapping = self._es.indices.get_mapping(index=",".join(targets))
        except Exception:
            return {}

        skip = {"@timestamp", "message"}
        aggregatable = {"keyword", "boolean", "integer", "short", "byte", "long", "ip"}
        found = {}

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
                elif field_type == "text" and "keyword" in (definition.get("fields") or {}):
                    found[path] = f"{path}.keyword"
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
        return ordered

    def _to_record(self, hit):
        """Turn a hit into a record using whatever schema wrote it.

        Chosen per document rather than per index: a search can span indices
        written by different pipelines, and picking one schema for the whole
        response would silently mangle half of it.
        """
        schema = schema_for_document(hit.get("_source"))
        return schema.to_record(hit, self.backend, self.name)


class ElasticsearchTraceSource(TraceSource):
    """Exposes Elasticsearch indices as a neutral trace source.

    More than one schema (OTel, Elastic APM) is supported at once: each index's
    schema is detected from its mapping, one query is issued per schema group,
    and the results are merged into a single neutral Trace. The caller never
    learns which span came from which schema.
    """

    backend = "elasticsearch"

    def __init__(self, client, name="elasticsearch-traces",
                 patterns=("*traces*", "*apm*"), catalogue=None):
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
        """Detect and cache the schema of an index."""
        if index in self._schema_cache:
            return self._schema_cache[index]
        try:
            mapping = self._es.indices.get_mapping(index=index)
            properties = list(mapping.values())[0]["mappings"].get("properties", {})
        except Exception:
            properties = {}
        schema = detect_schema(properties)
        self._schema_cache[index] = schema
        return schema

    def _grouped(self, scope):
        """{schema: [index, ...]} — indices with an unrecognised schema are skipped."""
        groups = {}
        for index in self.containers(scope):
            schema = self._schema_for(index)
            if schema:
                groups.setdefault(type(schema), []).append(index)
        return {schema_cls(): indices for schema_cls, indices in groups.items()}

    def trace(self, trace_id, window, scope):
        spans, partial = [], False
        groups = list(self._grouped(scope).items())

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
        seen_spans = set()

        for (schema, _), response in zip(groups, _multi_search(self._es, requests)):
            if response is None:
                partial = True
                continue
            for hit in response["hits"]["hits"]:
                span = schema.to_span(hit)
                if span is not None:
                    span.source = self.name
                if not span or span.span_id in seen_spans:
                    continue
                if not scope.allows_service(span.service):
                    continue
                seen_spans.add(span.span_id)
                spans.append(span)

        if not spans:
            return None

        spans.sort(key=lambda s: (s.start is None, s.start))
        return Trace(trace_id=trace_id, spans=spans, partial=partial)

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

        for schema, indices in self._grouped(scope).items():
            must = [{"range": {schema.timestamp_field: query.window.as_es_range()}}]

            if query.service:
                if not scope.allows_service(query.service):
                    continue
                must.append({"term": {schema.service_field: query.service}})

            # Entry spans only: a service may emit many spans per trace and we
            # want one row per trace, describing work the service handled.
            must.append(self._server_span_filter(schema))

            if not query.service:
                # No service asked for, so show where each request entered.
                must.append({"bool": {"must_not": [
                    {"exists": {"field": self._parent_field(schema)}}]}})

            # Push the scope's service restriction INTO the query. Filtering
            # after the fact is wrong here: `collapse` returns the top N by
            # sort order, so a restricted role would get a page full of spans
            # it cannot see and end up with an empty list even when matching
            # traces exist.
            scope_filter = self._scope_service_filter(schema, scope)
            if scope_filter is not None:
                must.append(scope_filter)

            if query.only_errors:
                must.append(self._error_filter(schema))
            if query.min_duration_us:
                must.append(self._duration_filter(schema, query.min_duration_us))

            groups.append(schema)
            requests.append((indices, {
                "query": {"bool": {"must": must}},
                "size": min(query.limit, 200),
                # One row per trace without a terms aggregation.
                "collapse": {"field": schema.trace_id_field},
                "sort": self._trace_sort(schema, query.sort),
            }))

        for schema, response in zip(groups, _multi_search(self._es, requests)):
            if response is None:
                continue
            for hit in response["hits"]["hits"]:
                span = schema.to_span(hit)
                if span is not None:
                    span.source = self.name
                if not span or span.trace_id in seen:
                    continue
                if not scope.allows_service(span.service):
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
        return summaries[:query.limit]

    @staticmethod
    def _parent_field(schema):
        return "parent_span_id" if schema.name == "otel" else "parent.id"

    @staticmethod
    def _scope_service_filter(schema, scope):
        """Turn the scope's service allowlist into a query clause.

        Returns None when the scope imposes no restriction.
        """
        if scope.services is None or "*" in scope.services:
            return None
        if not scope.services:
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

        allow, deny = partition(scope.services)
        if not allow:
            return {"match_none": {}}

        def clause(pattern):
            field = schema.service_field
            kind = shape(pattern)
            if kind == patterns_module.ANY:
                return {"exists": {"field": field}}
            if kind == patterns_module.EXACT:
                return {"term": {field: pattern}}
            # `wildcard` covers prefix, suffix and contains alike. Special-
            # casing prefix bought nothing and was the reason the other two
            # were missing.
            return {"wildcard": {field: {"value": pattern}}}

        query = {"bool": {"should": [clause(p) for p in allow],
                          "minimum_should_match": 1}}
        if deny:
            query["bool"]["must_not"] = [clause(p) for p in deny]
        return query

    @staticmethod
    def _server_span_filter(schema):
        """Restrict to spans representing work a service handled."""
        if schema.name == "otel":
            return {"term": {"kind": "SPAN_KIND_SERVER"}}
        return {"term": {"processor.event": "transaction"}}

    @staticmethod
    def _duration_filter(schema, minimum_us):
        if schema.name == "otel":
            return {"range": {"duration_ns": {"gte": minimum_us * 1000}}}
        return {"range": {"transaction.duration.us": {"gte": minimum_us}}}

    @staticmethod
    def _trace_sort(schema, sort):
        if sort == SORT_SLOWEST:
            field = "duration_ns" if schema.name == "otel" else "transaction.duration.us"
            return [{field: {"order": "desc"}}]
        return [{schema.timestamp_field: {"order": "desc"}}]

    def services(self, window, scope):
        totals, errors = {}, {}
        groups, requests = [], []

        for schema, indices in self._grouped(scope).items():
            groups.append(schema)
            requests.append((indices, {
                "size": 0,
                "query": {"range": {schema.timestamp_field: window.as_es_range()}},
                "aggs": {"services": {
                    "terms": {"field": schema.service_field, "size": 100},
                    "aggs": {"failed": {"filter": self._error_filter(schema)}},
                }},
            }))

        for response in _multi_search(self._es, requests):
            if response is None:
                continue
            for bucket in response["aggregations"]["services"]["buckets"]:
                name = bucket["key"]
                if not scope.allows_service(name):
                    continue
                totals[name] = totals.get(name, 0) + bucket["doc_count"]
                errors[name] = errors.get(name, 0) + bucket["failed"]["doc_count"]

        return sorted(
            (Service(name=n, span_count=c, error_count=errors.get(n, 0))
             for n, c in totals.items()),
            key=lambda s: s.span_count, reverse=True,
        )

    @staticmethod
    def _error_filter(schema):
        if schema.name == "otel":
            return {"term": {"status_code": "ERROR"}}
        return {"term": {"event.outcome": "failure"}}
