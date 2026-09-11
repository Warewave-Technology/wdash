"""
VictoriaLogs as a log source.

Closer to Elasticsearch than Loki is, in the ways that matter to this
application, and the differences are worth stating because they change which
capabilities are declared.

**It can count.** `/select/logsql/stats_query` answers `stats count()` over a
window, so a page total is a real match count rather than "how many we got
back". Loki cannot do this, and the whole `counted` flag exists because of it.

**It can list field values.** `/select/logsql/field_values` gives the top
values of any field with their hit counts — the field-statistics sidebar,
served by the backend rather than approximated from a page of results. This is
the capability Loki lacks, and it is why a merged view over Loki and
VictoriaLogs still loses the sidebar: capabilities intersect.

**There is no document id.** `_stream_id` identifies a stream, not a line, and
two lines in one stream can share a timestamp. So there is no RAW_DOCUMENT and
no CONTEXT, for the same reason as Loki: returning the wrong record is worse
than returning none.

**Containers are a field, not an index.** Same shape as Loki's stream label:
one configured field whose values a role can be granted or denied. The default
is `service`, and it must be one of the stream fields the data was written
with or the selector is a full scan.

**LogsQL is not LogQL.** Same first four letters, different language. A word on
its own is a phrase filter over `_msg`; `field:value` filters a field;
`field:*` is an existence check. Quoting matters — an unquoted value ends at a
space and the rest becomes a separate filter, which silently widens the query.
"""

import datetime as dt
import json
import logging
import re
import time
from datetime import datetime, timezone

import requests

from .. import query_language as ql
from ..aggregation import AggregationResult, Bucket, DateHistogram, Terms
from ..models import LogPage, LogRecord, SourceRef, normalise_severity
from ..source import Capability, LogSource

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

#: Fields conventionally carrying severity, in the order they are believed.
_SEVERITY_FIELDS = ("level", "severity", "log.level", "severity_text")
#: Fields VictoriaLogs owns. They describe the record rather than being part
#: of it, so they do not belong in `attributes`.
_RESERVED = frozenset({"_time", "_msg", "_stream", "_stream_id"})


class VictoriaLogsError(RuntimeError):
    """VictoriaLogs could not answer."""


def _quote(value):
    """Quote a value for a LogsQL filter.

    Always quoted, never conditionally. An unquoted value ends at the first
    space and everything after it becomes a separate filter — so
    `service:payment service` silently means "service is payment AND the line
    mentions service", which returns a plausible number of wrong rows.
    """
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _rfc3339(moment):
    """VictoriaLogs takes RFC3339, and is strict about the timezone."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_time(raw):
    if not raw:
        return None
    text = str(raw).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class VictoriaLogsSource(LogSource):
    """Exposes VictoriaLogs as a neutral log source."""

    backend = "victorialogs"

    def __init__(self, url, name="victorialogs", stream_field="service",
                 username=None, password=None, tenant=None, verify_certs=True,
                 timeout=DEFAULT_TIMEOUT, session=None):
        self.name = name
        self._url = (url or "").rstrip("/")
        #: Which field names a container. Must be one of the stream fields the
        #: data was written with, or every query becomes a full scan.
        self._stream_field = stream_field
        self._auth = (username, password) if username else None
        self._tenant = tenant
        self._verify = verify_certs
        self._timeout = timeout
        self._session = session or requests.Session()
        #: {(start, end): (values, fetched_at)} — see _container_values.
        self._container_cache = {}

    @property
    def capabilities(self):
        # FIELD_STATS is here and absent from Loki: `field_values` answers it
        # from the backend rather than from a page of results. CONTEXT and
        # RAW_DOCUMENT are absent because there is no per-line id to anchor
        # them to.
        return frozenset({Capability.SEARCH, Capability.HISTOGRAM,
                          Capability.AGGREGATION, Capability.FIELD_STATS,
                          Capability.LOG_TRACE_CORRELATION})

    # ---------- transport ----------

    def _post(self, path, params):
        """Every endpoint here is a POST with form-encoded parameters.

        GET works too, but a LogsQL query with several filters outgrows what
        proxies will carry in a URL, and the failure is a 414 that reads like
        the server being down.
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self._tenant:
            # AccountID:ProjectID. Absent means the default tenant.
            account, _, project = str(self._tenant).partition(":")
            headers["AccountID"] = account
            headers["ProjectID"] = project or "0"

        response = self._session.post(
            f"{self._url}{path}", data=params, headers=headers,
            auth=self._auth, timeout=self._timeout, verify=self._verify)
        if response.status_code >= 400:
            raise VictoriaLogsError(
                f"VictoriaLogs answered HTTP {response.status_code}: "
                f"{response.text[:200]}")
        return response

    def _json(self, path, params):
        response = self._post(path, params)
        try:
            return response.json()
        except ValueError as exc:
            raise VictoriaLogsError(
                f"VictoriaLogs returned something that is not JSON: {exc}")

    def _lines(self, path, params):
        """`/query` answers with JSON lines, not a JSON document."""
        response = self._post(path, params)
        out = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                # One malformed line must not lose the rest of the page.
                logger.warning("VictoriaLogs returned an unparseable line")
        return out

    def health(self):
        try:
            response = self._session.get(
                f"{self._url}/health", auth=self._auth, timeout=5,
                verify=self._verify)
            healthy = response.status_code < 400 and "OK" in response.text
            return healthy, "ok" if healthy else f"HTTP {response.status_code}"
        except Exception as exc:
            return False, str(exc)

    # ---------- containers ----------

    #: How far back to look when nobody named a window. See the Loki adapter
    #: for the same reasoning: a picker that lists what can be granted must
    #: not empty itself because nothing shipped since lunch.
    CATALOGUE_WINDOW = dt.timedelta(days=7)

    def containers(self, scope, window=None):
        """Values of the stream field, treated as containers."""
        if scope.is_empty:
            return []
        try:
            values = self._container_values(window)
        except Exception as exc:
            logger.error(f"VictoriaLogs field values could not be read: {exc}")
            return []
        return scope.resolve(values, source=self.name)

    def _container_values(self, window=None, ttl=30.0):
        """Distinct values of the stream field within a window.

        Keyed by window, because the answer depends on it — the same lesson
        the Loki adapter learned the hard way.
        """
        if window is None:
            end = datetime.now(timezone.utc)
            start = end - self.CATALOGUE_WINDOW
        else:
            start, end = window.start, window.end

        key = (_rfc3339(start), _rfc3339(end))
        now = time.monotonic()
        cached = self._container_cache.get(key)
        if cached is not None and (now - cached[1]) < ttl:
            return cached[0]

        body = self._json("/select/logsql/field_values", {
            "query": "*", "field": self._stream_field,
            "start": key[0], "end": key[1], "limit": 1000})
        values = sorted(entry.get("value") for entry in body.get("values") or ()
                        if entry.get("value"))

        if len(self._container_cache) > 32:
            self._container_cache.clear()
        self._container_cache[key] = (values, now)
        return values

    # ---------- query building ----------

    def _selector(self, targets):
        """The container filter. Never empty.

        An empty filter in LogsQL means `*`, which is every stream — the exact
        opposite of "the scope permits nothing". The Elasticsearch adapter had
        this bug with an empty index list, and it is the same shape here.
        """
        if not targets:
            raise VictoriaLogsError("no containers are in scope")
        # EXACT values, never phrases. `service:"pay"` is LogsQL's phrase
        # filter: it matches `pay` wherever it sits on word boundaries inside
        # a longer value, so a grant of `pay` also returned `pay-api` and
        # `pay worker`, and a role holding `app-*` with `-*-pii-*` read
        # `app-billing-pii-eu` through its allowed `app-billing`. The scope
        # decides which values may be read; the filter has to say exactly
        # those. `in(...)` is the multi-exact filter, and one form for one
        # value or many is one form to get right.
        values = ", ".join(_quote(name) for name in targets)
        return f"{self._stream_field}:in({values})"

    def _targets(self, query, scope):
        """Containers to search, resolved over the query's own window.

        Returns (targets, existed) — the same two-empties distinction as Loki:
        "you may not see this" and "nothing was logged then" send people to
        different places, and only one of them is anybody's fault.
        """
        available = self._container_values(getattr(query, "window", None))
        existed = bool(available)

        allowed = ([] if scope.is_empty
                   else scope.resolve(available, source=self.name))
        if not getattr(query, "containers", None):
            return allowed, existed
        wanted = set(query.containers)
        return [name for name in allowed if name in wanted], existed

    def _filter(self, node):
        """Render the neutral query tree into LogsQL.

        Anything LogsQL cannot express raises. A query that silently drops a
        clause returns MORE than the caller asked for — the one direction an
        access-controlled system must never round in.
        """
        if isinstance(node, ql.MatchAll) or node is None:
            return ""

        if isinstance(node, ql.FullText):
            return _quote(node.text)

        if isinstance(node, (ql.Term, ql.Phrase)):
            field = getattr(node, "field", None)
            value = getattr(node, "value", None) or getattr(node, "text", "")
            if field in ("body", "message", None):
                return _quote(value)
            return f"{self._field_for(field)}:{_quote(value)}"

        if isinstance(node, ql.And):
            parts = [self._filter(clause) for clause in node.clauses]
            return " AND ".join(part for part in parts if part)

        if isinstance(node, ql.Or):
            parts = [self._filter(clause) for clause in node.clauses]
            rendered = " OR ".join(part for part in parts if part)
            return f"({rendered})" if rendered else ""

        if isinstance(node, ql.Not):
            inner = self._filter(node.clause)
            if not inner:
                raise VictoriaLogsError(
                    "VictoriaLogs cannot express 'not everything'")
            return f"NOT ({inner})"

        if isinstance(node, ql.Exists):
            return f"{self._field_for(node.field)}:*"

        if isinstance(node, ql.Prefix):
            # LogsQL's own prefix syntax. The value is quoted and the star
            # sits outside the quotes, which is the opposite of what looks
            # right and the reason this is not inlined at the call site.
            return f"{self._field_for(node.field)}:{_quote(node.value)}*"

        raise VictoriaLogsError(
            f"{type(node).__name__} has no LogsQL equivalent; "
            f"VictoriaLogs cannot express this query")

    @staticmethod
    def _field_for(neutral_name):
        return {"severity": "level", "severity_text": "level",
                "body": "_msg", "message": "_msg",
                "timestamp": "_time"}.get(neutral_name, neutral_name)

    def _expression(self, query, targets):
        parts = [self._selector(targets)]
        rendered = self._filter(query.filter)
        if rendered:
            parts.append(rendered)
        return " AND ".join(parts)

    def _window(self, query):
        return {"start": _rfc3339(query.window.start),
                "end": _rfc3339(query.window.end)}

    # ---------- search ----------

    def search(self, query, scope):
        try:
            targets, existed = self._targets(query, scope)
        except Exception as exc:
            return LogPage(partial=True,
                           warnings=(f"containers could not be read: {exc}",))

        if not targets:
            return LogPage(
                warnings=(("the scope permits no containers",) if existed
                          else ("no containers reported any data in this "
                                "time range",)),
                informational=not existed)

        try:
            expression = self._expression(query, targets)
        except VictoriaLogsError as exc:
            return LogPage(containers=tuple(targets), partial=True,
                           warnings=(str(exc),))

        started = time.monotonic()
        try:
            rows = self._lines("/select/logsql/query", {
                "query": expression,
                "limit": min(query.limit, 1000),
                **self._window(query),
            })
        except Exception as exc:
            return LogPage(containers=tuple(targets), partial=True,
                           warnings=(f"search failed: {exc}",))

        records = [self._to_record(row) for row in rows]
        # `/query` returns rows in no guaranteed order, so the sort is ours.
        records.sort(key=lambda record: record.timestamp or datetime.min.replace(
            tzinfo=timezone.utc), reverse=not query.ascending)
        records = records[:query.limit]

        # A real count, in a second request. Loki has no equivalent and its
        # totals are floors; here the number on screen is the number of
        # matches, which is what people assume it is anyway.
        total, counted = len(records), False
        try:
            total = self._count(expression, query)
            counted = True
        except Exception as exc:
            logger.warning(f"VictoriaLogs count failed: {exc}")

        return LogPage(
            records=records,
            total=total,
            counted=counted,
            took_ms=int((time.monotonic() - started) * 1000),
            containers=tuple(targets),
            warnings=() if counted else (
                "the match count could not be read; the total shown is the "
                "number returned",),
        )

    def _count(self, expression, query):
        body = self._json("/select/logsql/stats_query", {
            "query": f"{expression} | stats count() as hits",
            **self._window(query),
        })
        result = (body.get("data") or {}).get("result") or []
        if not result:
            return 0
        return int(float(result[0]["value"][1]))

    def _to_record(self, row):
        severity = next((row[field] for field in _SEVERITY_FIELDS
                         if row.get(field)), None)
        resource, attributes = {}, {}
        for key, value in row.items():
            if key in _RESERVED or key in _SEVERITY_FIELDS:
                continue
            if key in ("host", "hostname", "namespace", "pod", "container",
                       self._stream_field):
                resource[key] = value
            else:
                attributes[key] = value

        container = row.get(self._stream_field) or ""
        return LogRecord(
            timestamp=_parse_time(row.get("_time")),
            body=row.get("_msg") or "",
            severity=normalise_severity(severity),
            severity_text=severity or "",
            service=container,
            resource=resource,
            attributes=attributes,
            trace_id=row.get("trace_id") or None,
            span_id=row.get("span_id") or None,
            # The handle names the container so the UI can show where a row
            # came from. It cannot name the LINE — `_stream_id` identifies a
            # stream, and two lines in one stream can share a timestamp — so
            # `fetch` refuses rather than returning a different record.
            ref=SourceRef(self.backend, container,
                          str(row.get("_time") or "")),
            source=self.name,
        )

    def fetch(self, ref, scope):
        """No per-line id exists, so there is nothing to fetch by."""
        return None

    # ---------- field statistics ----------

    #: Fields the sidebar asks about when nobody names any. VictoriaLogs has
    #: no mapping to consult the way Elasticsearch does, so `field_names`
    #: supplies the candidates and these lead because they are the ones people
    #: filter on.
    PREFERRED_FIELDS = ("level", "service", "host", "env", "namespace", "pod")

    def field_stats(self, query, scope, fields=None, top=10):
        """Top values per field, counted by the backend.

        Signature matches the hub contract — `(query, scope)` with the rest
        optional — and returns `FieldStat` objects, not dictionaries. The
        first version of this took `(query, fields, scope)` and returned
        dictionaries, which type-checked nowhere and failed at the one call
        site with a TypeError the moment a real request arrived.

        The capability Loki does not have. Asking the backend beats
        approximating from a page of results, which describes the page rather
        than the data.
        """
        from ..models import FieldStat, FieldValue

        try:
            targets, _ = self._targets(query, scope)
        except Exception as exc:
            logger.error(f"VictoriaLogs field statistics failed: {exc}")
            return []
        if not targets:
            return []

        try:
            expression = self._expression(query, targets)
        except VictoriaLogsError as exc:
            logger.warning(f"VictoriaLogs field statistics skipped: {exc}")
            return []

        candidates = list(fields) if fields else self._preferred(scope, query)
        out = []
        for field in candidates:
            name = self._field_for(field)
            try:
                body = self._json("/select/logsql/field_values", {
                    "query": expression, "field": name, "limit": top,
                    **self._window(query)})
            except Exception as exc:
                # One field failing must not empty the sidebar.
                logger.warning(f"VictoriaLogs field '{name}' failed: {exc}")
                continue
            # Merged by the NORMALISED key. VictoriaLogs stores what was
            # written, so `warn` and `warning` come back as two rows — and
            # both are WARN, which put the same label on the sidebar twice
            # with the counts split between them.
            merged = {}
            for entry in body.get("values") or ():
                key = self._bucket_key(field, entry.get("value"))
                merged[key] = merged.get(key, 0) + int(entry.get("hits") or 0)

            # A field where every value comes back with zero hits is one this
            # backend cannot count — high-cardinality fields answer that way.
            # A list of values with no numbers beside them is not a statistic,
            # and showing it invites somebody to read the zeros as real.
            if not any(merged.values()):
                continue

            values = [FieldValue(value=key, count=count)
                      for key, count in sorted(merged.items(),
                                               key=lambda item: -item[1])]
            out.append(FieldStat(field=field, values=values[:top]))
        return out

    def _preferred(self, scope, query):
        """Which fields to describe, when the caller did not say.

        Intersected with what is actually present, so the sidebar never lists
        a field that exists only in this tuple.
        """
        present = set(self.fields(scope, getattr(query, "window", None)))
        chosen = [name for name in self.PREFERRED_FIELDS if name in present]
        # Then whatever else there is, so a deployment with its own field
        # names is not left with an empty sidebar.
        chosen += sorted(present - set(chosen) - {self._stream_field})[:4]
        return chosen[:8]

    def fields(self, scope, window=None):
        """Field names present in the data, for the query builder."""
        try:
            body = self._json("/select/logsql/field_names", {"query": "*"})
        except Exception as exc:
            logger.error(f"VictoriaLogs field names could not be read: {exc}")
            return []
        return sorted(entry.get("value") for entry in body.get("values") or ()
                      if entry.get("value") and entry["value"] not in _RESERVED)

    # ---------- aggregation ----------

    def aggregate(self, query, aggregations, scope):
        try:
            targets, existed = self._targets(query, scope)
        except Exception as exc:
            return AggregationResult(
                failed=True, warnings=(f"containers could not be read: {exc}",))

        if not targets:
            return AggregationResult(warnings=(
                ("the scope permits no containers",) if existed
                else ("no containers reported any data in this time range",)))

        expression = self._expression(query, targets)
        buckets, warnings, total = {}, [], 0
        failed = False

        for aggregation in aggregations or ():
            try:
                if isinstance(aggregation, DateHistogram):
                    buckets[aggregation.name] = self._histogram(
                        expression, query, aggregation)
                elif isinstance(aggregation, Terms):
                    rows = self._terms(expression, query, aggregation)
                    buckets[aggregation.name] = rows
                    total = max(total, sum(row.count for row in rows))
                else:
                    warnings.append(
                        f"{type(aggregation).__name__} is not supported by "
                        f"VictoriaLogs")
            except Exception as exc:
                failed = True
                warnings.append(f"{aggregation.name}: {exc}")

        return AggregationResult(buckets=buckets, total=total, failed=failed,
                                 warnings=tuple(warnings))

    def histogram(self, query, scope):
        """Volume over time, as the hub asks for it.

        Declared HISTOGRAM without defining this, which the conformance suite
        did not notice until it grew a test for "a declared capability is
        callable the way the hub calls it". Every caller went through
        `aggregate`, so nothing failed until something used the short form.
        """
        result = self.aggregate(
            query, [DateHistogram(name="timeline", min_count=0)], scope)
        return result.get("timeline")

    def _terms(self, expression, query, aggregation):
        field = self._field_for(aggregation.field)
        body = self._json("/select/logsql/field_values", {
            "query": expression, "field": field,
            "limit": getattr(aggregation, "size", 10) or 10,
            **self._window(query)})
        return _merge_buckets(
            (self._bucket_key(aggregation.field, entry.get("value")),
             int(entry.get("hits") or 0))
            for entry in body.get("values") or ())

    def _bucket_key(self, neutral_field, value):
        """The key as the neutral model promises it.

        VictoriaLogs stores whatever was written, which for severity is
        usually lower case. Two sources answering one panel with "ERROR" and
        "error" draw two bars for the same thing.
        """
        if neutral_field in ("severity", "severity_text", "level"):
            return normalise_severity(value)
        return value

    def _histogram(self, expression, query, aggregation):
        """Volume over time, optionally split by a field.

        `/hits` returns one series per group with parallel `timestamps` and
        `values` arrays. The neutral model wants one bucket per instant with
        the groups nested inside it, so the series are transposed here rather
        than in every caller.
        """
        params = {"query": expression,
                  "step": _step(aggregation.interval),
                  **self._window(query)}
        # `sub` is a tuple of aggregations, not a mapping. VictoriaLogs splits
        # by one field, so the first Terms child is the split and any others
        # are reported as unsupported rather than silently dropped.
        children = tuple(getattr(aggregation, "sub", None) or ())
        terms = [child for child in children if isinstance(child, Terms)]
        split_field = sub_name = None
        if terms:
            split_field = self._field_for(terms[0].field)
            sub_name = terms[0].name
            params["field"] = split_field
            params["fields_limit"] = getattr(terms[0], "size", 10) or 10

        body = self._json("/select/logsql/hits", params)

        accumulated = {}
        neutral = terms[0].field if terms else None
        for series in body.get("hits") or ():
            label = (series.get("fields") or {}).get(split_field) if split_field else None
            if label is not None:
                label = self._bucket_key(neutral, label)
            for moment, count in zip(series.get("timestamps") or (),
                                     series.get("values") or ()):
                entry = accumulated.setdefault(moment, {"count": 0, "sub": {}})
                entry["count"] += int(count or 0)
                if label is not None:
                    entry["sub"][label] = entry["sub"].get(label, 0) + int(count or 0)

        out = []
        for moment in sorted(accumulated):
            entry = accumulated[moment]
            parsed = _parse_time(moment)
            out.append(Bucket(
                key=int(parsed.timestamp() * 1000) if parsed else moment,
                count=entry["count"],
                key_text=moment,
                sub=({sub_name: _merge_buckets(sorted(entry["sub"].items()))}
                     if sub_name and entry["sub"] else {}),
            ))
        return out


def _merge_buckets(pairs):
    """Buckets from (key, count) pairs, adding up collisions.

    Normalising keys can map two of them onto one — "warn" and "warning" both
    become WARN — and two buckets with the same key render as two bars that
    each show half the number.
    """
    totals = {}
    for key, count in pairs:
        totals[key] = totals.get(key, 0) + count
    return [Bucket(key=key, count=count, key_text=str(key))
            for key, count in sorted(totals.items(),
                                     key=lambda item: -item[1])]


def _step(interval):
    """The neutral interval, as a LogsQL duration.

    Elasticsearch calendar intervals (`1d`, `1w`) and fixed ones (`30s`) both
    arrive here; VictoriaLogs takes durations only, so a calendar interval is
    approximated and anything unrecognised falls back to a minute rather than
    producing a query that fails.
    """
    if not interval:
        return "1m"
    text = str(interval).strip()
    # A suffix check is not enough: "month" ends in "h", so a calendar
    # interval sailed through as a duration and VictoriaLogs rejected the
    # whole query. The shape has to be a number followed by a unit.
    if re.fullmatch(r"\d+(ms|s|m|h|d|w|y)", text):
        return text
    return "1m"
