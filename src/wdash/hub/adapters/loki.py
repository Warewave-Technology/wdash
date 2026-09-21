"""
Grafana Loki as a log source.

Loki is not Elasticsearch with different field names, and the places it differs
are the places this adapter has to be careful.

**A stream selector is mandatory.** LogQL cannot express "everything": `{}` is
a syntax error. So the neutral `*` has no direct translation, and the honest
answer is that a Loki source must be told which label identifies a stream. That
is `stream_label` below — usually `service_name` or `app`. Without it, this
adapter refuses rather than inventing a selector that quietly reads more or
less than the caller asked for.

**Filtering is two-stage, and the stages cost differently.** Label matchers in
the selector are indexed and cheap; line filters scan. Pushing what we can into
the selector is not an optimisation — it is the difference between a query that
returns and one that times out on a week of data.

**The scope is enforced in the selector**, for the same reason it is pushed
into the Elasticsearch query rather than applied afterwards: a limit applied by
the backend has already chosen its rows before any post-filter runs, so
filtering later leaves a restricted role with an empty page and no error.

**Labels are not fields.** Loki indexes a small set of labels and treats the
rest of the line as text. A record's severity is a label if the pipeline set
one and a guess otherwise; this adapter says which, rather than pretending
every log has structured severity.
"""

import json
import logging
import re
import time
import datetime as dt
from datetime import datetime, timezone

import requests

from ..aggregation import AggregationResult, Bucket, DateHistogram, Terms
from ..models import (
    KNOWN_SEVERITY_SPELLINGS, LogPage, LogRecord, SourceRef,
    normalise_severity, severity_from, severity_spellings,
)
from ..source import Capability, LogSource
from .. import query_language as ql

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

#: Labels Loki pipelines conventionally set, mapped onto the neutral model.
#: Anything else stays a label and shows up as a resource entry.
_SEVERITY_LABELS = ("level", "severity", "detected_level")
_SERVICE_LABELS = ("service_name", "service", "app", "job", "container")

#: What LogQL accepts as a label name inside `sum by (...)`.
#:
#: A panel may now name any field its source offers, and on Elasticsearch and
#: VictoriaLogs that includes dotted names like `log.level`. `sum by
#: (log.level)` is not a narrower answer here, it is a parse error — Loki
#: replies HTTP 400 and the panel would carry a stack trace where its reason
#: belongs. Checked before the query is built, so the refusal is this
#: adapter's sentence rather than Loki's.
_LABEL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class LokiError(RuntimeError):
    """Loki could not answer."""


def _escape(value):
    """Escape a label value for a LogQL selector.

    Values are interpolated into `{label="value"}`; a quote or backslash would
    end the string early and change which streams are selected. Same class of
    problem as an LDAP filter or a SQL string, and the same answer.
    """
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


#: What RE2 reads as syntax rather than as the character itself.
_REGEX_SYNTAX = re.compile(r"([\\.+*?()|\[\]{}^$])")


def _literal(value):
    """A label value as a regular expression that matches only itself.

    Several streams are selected with `label=~"a|b"`, and the names in that
    alternation are the values the scope allowed — so a name is data, and a
    `.` or a `|` inside it must not become syntax. Unescaped, `pay.svc`
    also selected `payXsvc`, and a service somebody named `team-a-x|.+`
    turned a grant of `team-a-*` into every stream Loki holds.
    """
    return _REGEX_SYNTAX.sub(r"\\\1", str(value))


def _severity_stage(value):
    """A label filter stage keeping the lines the page calls `value`.

    Every spelling that normalises the way `value` does, without regard to
    case: `level:ERROR` has to find the `error` and `ERR` lines, because
    those are the lines the record calls ERROR and the level panel counts as
    ERROR. Loki anchors a label regex at both ends — measured, `(?i)err`
    kept only `ERR` — so the alternation is whole values.

    Over EVERY label a record's level is read from, in the same order
    `_to_records` reads them. Matching `level` alone was right only for a
    pipeline that writes `level`: on a stream carrying `severity` — what an
    OTel collector writes — or only Loki's own `detected_level`, `level:ERROR`
    found none of the lines the page draws as ERROR, and said nothing.
    Measured on the lab's Loki 3.1.1 over one stream per shape:
    `| level=~"(?i)(error|err)"` kept 6 of the 18 ERROR lines, and
    `| severity=~"(?i)(error|err)"` kept 0 of them, because an absent label
    matches nothing under `=~`.

    The order is the point, not a detail. A stream carrying both `level=info`
    and `severity=error` is INFO — `level` is what the record read — so a
    plain or-chain over the three would answer `level:ERROR` with a line the
    page draws as INFO. Each clause therefore requires the labels ahead of it
    to be absent, which Loki spells `label=""`: measured, `level=""` kept
    exactly the 18 lines of the streams carrying no `level`, and `and` binds
    tighter than `or`, so the clauses need no parentheses.

    UNSPECIFIED is the level that is none of the known spellings, absent
    included — and it is the direction that quietly returns MORE, because an
    absent label matches EVERYTHING under `!~`. Rendered as `!~` over the
    first label alone it kept every line of a level-less stream, ERROR lines
    included.
    """
    spellings = severity_spellings(value)
    pattern = _escape("(?i)({})".format("|".join(
        _literal(spelling) for spelling
        in spellings or KNOWN_SEVERITY_SPELLINGS)))

    clauses = []
    for index, label in enumerate(_SEVERITY_LABELS):
        last = index == len(_SEVERITY_LABELS) - 1
        # Loki drops a label with an empty value, so `absent` and `empty` are
        # one state here — the same state `_to_records` skips over.
        terms = [f'{earlier}=""' for earlier in _SEVERITY_LABELS[:index]]
        if spellings:
            terms.append(f'{label}=~"{pattern}"')
        else:
            # "this label decided, and what it says is no known spelling".
            # The last needs no presence test: absent satisfies `!~` too, and
            # a line with none of the three labels IS UNSPECIFIED.
            if not last:
                terms.append(f'{label}!=""')
            terms.append(f'{label}!~"{pattern}"')
        clauses.append(" and ".join(terms))
    return " | " + " or ".join(clauses)


def _nanoseconds(moment):
    return str(int(moment.timestamp() * 1_000_000_000))


class LokiLogSource(LogSource):
    """Exposes Loki streams as a neutral log source."""

    backend = "loki"

    def __init__(self, url, name="loki", stream_label="service_name",
                 username=None, password=None, tenant=None, verify_certs=True,
                 timeout=DEFAULT_TIMEOUT, session=None):
        self.name = name
        self._url = (url or "").rstrip("/")
        #: Which label names a container. Loki has no indices; the closest
        #: thing is "all the streams sharing this label value".
        self._stream_label = stream_label
        self._auth = (username, password) if username else None
        self._tenant = tenant
        self._verify = verify_certs
        self._timeout = timeout
        self._session = session or requests.Session()
        #: {(start_ns, end_ns): (values, fetched_at)} — see _label_values.
        self._label_cache = {}

    @property
    def capabilities(self):
        # Deliberately short. Loki has no field mappings, so the field-stats
        # sidebar cannot be built the way it is for Elasticsearch, and saying
        # so is better than returning something thin and calling it the same
        # feature. CONTEXT and RAW_DOCUMENT are absent for the same reason:
        # there is no document to fetch by id.
        return frozenset({Capability.SEARCH, Capability.HISTOGRAM,
                          Capability.AGGREGATION,
                          Capability.LOG_TRACE_CORRELATION})

    # ---------- transport ----------

    def _get(self, path, params):
        headers = {}
        if self._tenant:
            headers["X-Scope-OrgID"] = self._tenant
        response = self._session.get(
            f"{self._url}{path}", params=params, headers=headers,
            auth=self._auth, timeout=self._timeout, verify=self._verify)
        if response.status_code >= 400:
            raise LokiError(
                f"Loki answered HTTP {response.status_code}: "
                f"{response.text[:200]}")
        return response.json()

    def health(self):
        try:
            response = self._session.get(
                f"{self._url}/ready", auth=self._auth, timeout=5,
                verify=self._verify)
            ready = response.status_code < 400 and "ready" in response.text.lower()
            return ready, "ok" if ready else f"HTTP {response.status_code}"
        except Exception as exc:
            return False, str(exc)

    # ---------- containers ----------

    def containers(self, scope, window=None):
        """Values of the stream label, treated as containers.

        Loki has no indices. The nearest equivalent that a person can be
        granted or denied is a label value, which is why the label has to be
        configured rather than guessed.

        A label value only exists for a time range. Asked without one, Loki
        answers for its own default — the last six hours — so this reports
        what exists over `CATALOGUE_WINDOW` instead: a picker that lists what
        you can grant should not empty itself because nothing shipped since
        lunch.
        """
        if scope.is_empty:
            return []
        try:
            values = self._label_values(window)
        except Exception as exc:
            # Raised, not answered with []. Every caller reads an empty list
            # as "nothing is here" — the logs page said "No log indices
            # found" and "your role has no access", the role editor said a
            # correct pattern matched nothing — while Loki was down. The
            # routes had the connection error written; it could not fire.
            raise LokiError(f"stream labels could not be read: {exc}") from exc
        return scope.resolve(values, source=self.name)

    #: How far back to look when nobody named a window. Loki's own default is
    #: six hours, which is short enough that a quiet morning reads as an empty
    #: installation.
    CATALOGUE_WINDOW = dt.timedelta(days=7)

    def _label_values(self, window=None, ttl=30.0):
        """Stream label values that exist within a window.

        Keyed by window, because the answer depends on it. A single cache slot
        used to serve whatever the first caller asked for to everyone after —
        so a search over the last hour could poison the catalogue, or a
        catalogue lookup could tell a one-hour search about streams that
        stopped days ago.
        """
        if window is None:
            end = dt.datetime.now(dt.timezone.utc)
            start = end - self.CATALOGUE_WINDOW
            # One slot for the catalogue. Keyed by its own `now`, it missed
            # on every call: a page view asked Loki twice and a search three
            # times, and a Loki that answered the first and not the second
            # failed half way through one request.
            key = "catalogue"
        else:
            start, end = window.start, window.end
            key = (_nanoseconds(start), _nanoseconds(end))

        now = time.monotonic()
        cached = self._label_cache.get(key)
        if cached is not None and (now - cached[1]) < ttl:
            return cached[0]

        body = self._get(f"/loki/api/v1/label/{self._stream_label}/values",
                         {"start": _nanoseconds(start), "end": _nanoseconds(end)})
        values = sorted(body.get("data") or [])
        # Bounded: one entry per distinct window, and the windows come from a
        # time picker with a handful of choices. Cleared wholesale rather than
        # evicted, because there is nothing here worth an LRU.
        if len(self._label_cache) > 32:
            self._label_cache.clear()
        self._label_cache[key] = (values, now)
        return values

    def group_by_fields(self, scope, window=None):
        """Loki's LABEL NAMES, as neutral field names.

        The whole list, and it is short. Loki indexes labels and treats the
        rest of the line as text, so a panel can group by a label and by
        nothing else — measured on the lab, `/loki/api/v1/labels` over 24h
        answers exactly `detected_level, level, service_name, severity`, and a
        terms panel over `host` or `environment` (two of the four names the
        editor used to offer every source) came back with no rows and the
        reason that they are not labels here.

        Scoped, and Loki honours it: `/labels` takes the same stream selector
        a search does, and the lab answers `[level, service_name]` for the
        `billing` stream against `[detected_level, level, service_name,
        severity]` unrestricted. A label only one forbidden stream carries is
        not put in the editor's select.
        """
        targets = self.containers(scope, window)
        if not targets:
            return []
        end = window.end if window else dt.datetime.now(dt.timezone.utc)
        start = (window.start if window
                 else end - self.CATALOGUE_WINDOW)
        body = self._get("/loki/api/v1/labels", {
            "start": _nanoseconds(start), "end": _nanoseconds(end),
            "query": self._selector(targets)})

        neutral = set()
        for label in body.get("data") or []:
            if label in _SEVERITY_LABELS:
                neutral.add("severity")
            elif label == self._stream_label:
                neutral.add("service")
            elif _LABEL_NAME.match(label):
                neutral.add(label)
        return sorted(neutral)

    # ---------- query building ----------

    def _selector(self, targets):
        """The stream selector. Never empty: `{}` is not valid LogQL.

        This is where the scope is enforced. Rendering an unrestricted scope as
        an empty selector would be a syntax error at best and "every stream" at
        worst, which is precisely the failure the Elasticsearch adapter had
        with an empty index list.
        """
        if not targets:
            raise LokiError("no streams are in scope")
        if len(targets) == 1:
            return f'{{{self._stream_label}="{_escape(targets[0])}"}}'
        # Regex-escaped first, because each name is a literal inside an
        # alternation; string-escaped second, because the whole regex then
        # sits inside a LogQL string, where a backslash is itself an escape.
        alternation = "|".join(_escape(_literal(name)) for name in targets)
        return f'{{{self._stream_label}=~"{alternation}"}}'

    def _targets(self, query, scope):
        """Streams to search, resolved over the query's own window.

        Returns (targets, existed) — `existed` says whether Loki reported ANY
        stream in the window before the scope was applied. The two empties mean
        different things and used to be reported the same way: "you may not see
        this" and "nothing was logged then" send people to different places,
        and only one of them is anybody's fault.
        """
        try:
            available = self._label_values(getattr(query, "window", None))
        except Exception as exc:
            logger.error(f"Loki label values could not be read: {exc}")
            raise
        existed = bool(available)

        allowed = ([] if scope.is_empty
                   else scope.resolve(available, source=self.name))
        if not getattr(query, "containers", None):
            return allowed, existed
        wanted = set(query.containers)
        return [name for name in allowed if name in wanted], existed

    def _pipeline(self, node):
        """Render the neutral query tree into LogQL pipeline stages.

        Only the parts Loki can express are rendered. Anything else raises,
        because a query that silently drops a clause returns MORE than the
        caller asked for — the one direction an access-controlled system must
        never round in.
        """
        if isinstance(node, ql.MatchAll) or node is None:
            return ""

        if isinstance(node, ql.FullText):
            return f' |= "{_escape(node.text)}"'

        if (isinstance(node, (ql.Term, ql.Phrase))
                and node.field in ("severity", "severity_text")):
            return _severity_stage(
                node.value if isinstance(node, ql.Term) else node.text)

        if isinstance(node, (ql.Term, ql.Phrase)):
            field = getattr(node, "field", None)
            value = getattr(node, "value", None) or getattr(node, "text", "")
            if field in ("body", "message", None):
                return f' |= "{_escape(value)}"'
            # A structured field: works if the pipeline parsed it into a label,
            # and matches nothing otherwise. Loki cannot tell us which, so the
            # caller is told through a warning rather than by silence.
            return f' | {self._label_for(field)}="{_escape(value)}"'

        if isinstance(node, ql.And):
            return "".join(self._pipeline(clause) for clause in node.clauses)

        if isinstance(node, ql.Not):
            # Decided by WHAT is negated, never by how it rendered. A group
            # of words renders as a chain of line filters, which starts with
            # one too, and turning only that first stage round made
            # NOT (a b) — NOT a OR NOT b — into NOT a AND b: fewer lines than
            # asked for, and nothing said. A chain cannot say OR.
            clause = node.clause
            if isinstance(clause, ql.FullText) or (
                    isinstance(clause, (ql.Term, ql.Phrase))
                    and clause.field in ("body", "message", None)):
                return ' !=' + self._pipeline(clause)[3:]
            raise LokiError("Loki cannot express this negation")

        raise LokiError(
            f"{type(node).__name__} has no LogQL equivalent; "
            f"Loki cannot express this query")

    def _label_for(self, neutral_name):
        # `service` is whatever label this source was told names a stream.
        # It was `service_name` whatever the configuration said, so a source
        # set up with `app` grouped its services panel by a label its streams
        # did not have, and drew nothing.
        return {"severity": "level", "severity_text": "level",
                "service": self._stream_label}.get(neutral_name, neutral_name)

    # ---------- search ----------

    def search(self, query, scope):
        try:
            targets, existed = self._targets(query, scope)
        except Exception as exc:
            return LogPage(partial=True,
                           warnings=(f"stream labels could not be read: {exc}",))
        if not targets:
            # Fail closed, and say WHICH kind of empty this is. Reporting a
            # quiet time range as an authorization boundary sends somebody to
            # their administrator over a search that was simply too narrow.
            return LogPage(warnings=(
                ("the scope permits no streams",) if existed
                else ("no streams reported any data in this time range",)),
                informational=not existed)

        try:
            expression = self._selector(targets) + self._pipeline(query.filter)
        except LokiError as exc:
            return LogPage(containers=tuple(targets), partial=True,
                           warnings=(str(exc),))

        started = time.monotonic()
        try:
            body = self._get("/loki/api/v1/query_range", {
                "query": expression,
                "start": _nanoseconds(query.window.start),
                "end": _nanoseconds(query.window.end),
                "limit": min(query.limit, 500),
                "direction": "forward" if query.ascending else "backward",
            })
        except Exception as exc:
            return LogPage(containers=tuple(targets), partial=True,
                           warnings=(f"search failed: {exc}",))

        records = self._to_records(body)
        # One timeline. Loki answers stream by stream — each in the direction
        # asked for, the streams one after another — and the page was drawn
        # in that order. Which lines come back is right (the limit is applied
        # across streams); only their order has to be made here.
        records.sort(key=lambda record: record.timestamp,
                     reverse=not query.ascending)
        return LogPage(
            records=records,
            # Loki reports no total for a range query: it returns up to `limit`
            # and stops. Reporting the number returned is honest; inventing a
            # total would be a number people would then reason about.
            total=len(records),
            took_ms=int((time.monotonic() - started) * 1000),
            containers=tuple(targets),
            # Under the limit Loki did return everything there was, so the
            # count is exact; at the limit it stopped, and the total is a floor.
            counted=len(records) < min(query.limit, 500),
            warnings=(("Loki reports no match count; "
                       "the total shown is the number returned",)
                      if len(records) >= min(query.limit, 500) else ()),
        )

    def _to_records(self, body):
        """Turn Loki's stream/values shape into neutral records."""
        records = []
        for stream in (body.get("data") or {}).get("result") or []:
            labels = stream.get("stream") or {}
            level, severity_label = severity_from(labels, _SEVERITY_LABELS)
            service = next(
                (labels[name] for name in _SERVICE_LABELS if name in labels), "")

            for entry in stream.get("values") or []:
                timestamp_ns, line = entry[0], entry[1]
                structured = _maybe_json(line)

                records.append(LogRecord(
                    timestamp=datetime.fromtimestamp(
                        int(timestamp_ns) / 1_000_000_000, tz=timezone.utc),
                    body=line,
                    # A level inside a JSON line is not a label, so no
                    # filter here can match it; the fallback stays because a
                    # record with a level is better than one without.
                    severity=(level if severity_label else normalise_severity(
                        (structured or {}).get("level"))),
                    severity_text=str(severity_label or ""),
                    service=service,
                    # Labels ARE the resource: they are what Loki indexes and
                    # what identifies where a line came from.
                    resource={k: v for k, v in labels.items()
                              if k not in _SEVERITY_LABELS
                              and k not in _SERVICE_LABELS},
                    attributes=structured or {},
                    trace_id=(structured or {}).get("trace_id"),
                    span_id=(structured or {}).get("span_id"),
                    ref=SourceRef(backend=self.backend,
                                  container=service or self.name,
                                  id=str(timestamp_ns)),
                    source=self.name,
                ))
        return records

    def fetch(self, ref, scope):
        """Loki has no document ids.

        A line is identified by its stream and its nanosecond timestamp, which
        is not a durable handle: two lines in one stream can share a
        nanosecond, and nothing guarantees a line is still there. Returning a
        wrong record would be worse than returning none.
        """
        return None

    # ---------- aggregation ----------

    def aggregate(self, query, aggregations, scope):
        try:
            targets, existed = self._targets(query, scope)
        except Exception as exc:
            return AggregationResult(
                failed=True,
                warnings=(f"stream labels could not be read: {exc}",))
        if not targets:
            # Same distinction as `search`: a panel over a quiet window is
            # empty, not forbidden.
            return AggregationResult(warnings=(
                ("the scope permits no streams",) if existed
                else ("no streams reported any data in this time range",)))

        buckets, warnings, total = {}, [], 0
        notes = {}
        failed = False

        def attribute(aggregation, reason):
            """File a reason under the aggregation — the panel — it is about.

            The page keeps its own copy in `warnings`, spelled as it always
            was; this one is what the panel draws where its chart would be, so
            it carries no name prefix. Both, because a reader looking at the
            alert above the grid and a reader looking at one card need the
            same fact in two places.
            """
            notes.setdefault(aggregation.name, []).append(reason)

        for aggregation in aggregations:
            try:
                if isinstance(aggregation, DateHistogram):
                    rows, reasons = self._histogram_buckets(
                        query, targets, aggregation)
                    buckets[aggregation.name] = rows
                    for reason in reasons:
                        warnings.append(f"{aggregation.name}: {reason}")
                        attribute(aggregation, reason)
                elif isinstance(aggregation, Terms):
                    rows, note = self._terms_buckets(query, targets, aggregation)
                    buckets[aggregation.name] = rows
                    if note:
                        warnings.append(f"{aggregation.name}: {note}")
                        attribute(aggregation, note)
                    total = max(total, sum(row.count for row in rows))
                else:
                    reason = (f"{type(aggregation).__name__} is not supported "
                              f"by Loki")
                    warnings.append(reason)
                    attribute(aggregation, reason)
            except Exception as exc:
                failed = True
                warnings.append(f"{aggregation.name} failed: {exc}")
                attribute(aggregation, f"this panel could not be counted: {exc}")

        return AggregationResult(total=total, buckets=buckets,
                                 warnings=tuple(warnings), notes=notes,
                                 failed=failed)

    def _instant(self, expression, query):
        body = self._get("/loki/api/v1/query", {
            "query": expression,
            "time": _nanoseconds(query.window.end),
        })
        return (body.get("data") or {}).get("result") or []

    def _log_query(self, query, targets):
        """The log query a metric counts over: the streams AND the filter.

        The filter used to be left out, so every panel on a Loki dashboard
        counted every line in its streams whatever the dashboard's query or
        the filter box said — more than was asked for, and drawn as the
        answer. A filter Loki cannot express raises here, as it does for a
        search, rather than being dropped.
        """
        return self._selector(targets) + self._pipeline(query.filter)

    def _by_labels(self, field):
        """(labels, normalised, reason) for a `sum by (...)` over `field`.

        One place, because a terms panel and a split timeseries ask the same
        question and used to answer it in one function only. `reason` is
        non-None when no `by` clause can be built at all, and then `labels` is
        None: the caller counts the whole and says why.
        """
        # Severity buckets are normalised, because the neutral model promises
        # normalised severity everywhere and Loki labels are lower case. Two
        # sources answering the same panel with "ERROR" and "error" would draw
        # two bars for one thing — and colour only one of them red.
        #
        # And a level is counted over every label it may have been written
        # in, grouped together so the FIRST one a stream carries decides —
        # the same rule the record reader and the filter use. Grouped by
        # `level` alone, a panel over the 18 ERROR lines a search now returns
        # reported ERROR 6 and said nothing about the rest.
        if field in ("severity", "severity_text"):
            return list(_SEVERITY_LABELS), True, None

        label = self._label_for(field) or ""
        if not _LABEL_NAME.match(label):
            return None, False, (
                f"'{field}' cannot be a Loki label name, so these streams "
                f"cannot be grouped by it")
        return [label], False, None

    def _terms_buckets(self, query, targets, aggregation):
        """`sum by (label) (count_over_time(...))`, and a note or None.

        Only works for values Loki has as LABELS. A field that lives inside the
        line is not aggregatable without a parser stage, and pretending
        otherwise would return an empty chart that looks like no data — which
        is what it did, until the note: Loki answers `sum by (host)` over
        streams with no `host` label with one series whose labels are empty.
        """
        labels, normalise, refusal = self._by_labels(aggregation.field)
        if refusal:
            return [], refusal
        window = int(query.window.duration_seconds) or 1
        expression = (f"sum by ({', '.join(labels)}) (count_over_time("
                      f"{self._log_query(query, targets)}[{window}s]))")

        counts, unlabelled = {}, False
        for series in self._instant(expression, query):
            metric = series.get("metric") or {}
            if normalise:
                # A series carrying none of them is not an unlabelled series
                # to skip: those lines have no level, which IS a level.
                key = severity_from(metric, _SEVERITY_LABELS)[0]
            else:
                key = metric.get(labels[0])
                if key is None:
                    unlabelled = True
                    continue
            value = series.get("value") or [0, "0"]
            counts[key] = counts.get(key, 0) + int(float(value[1]))

        if unlabelled and not counts:
            # Unprefixed: the caller puts the aggregation's name in front of
            # it for the page's warning list and files the bare sentence under
            # that name for the panel, which does not need to be told which
            # panel it is.
            return [], (f"'{aggregation.field}' is not a Loki label on these "
                        f"streams and cannot be counted by value")

        rows = [Bucket(key=key, count=count) for key, count in counts.items()]
        rows.sort(key=lambda bucket: bucket.count, reverse=True)
        return rows[:aggregation.size], None

    def _histogram_buckets(self, query, targets, aggregation):
        """Counts over time, split by a label, and the reasons it is not.

        The split is the SAME `by` clause `_terms_buckets` has always built —
        no parser stage, no `| json`, no `__error__=""`. That matters because
        the parser is what makes this expensive and fragile: measured against
        the lab's Loki 3.1.1, `{service_name=~".+"} | json | __error__=""`
        answers HTTP 400 ("pipeline error: JSONParserErr") on a stream holding
        one non-JSON line, while `sum by (level) (count_over_time(...))` over
        the same streams answers 200 and splits. A label split is what the
        default panel — Volume by Severity, on every board — actually needs.

        Non-label fields stay unanswerable and say so. Loki reports them as
        one series carrying no labels and the full count, so the totals are
        right and only the breakdown is missing: the panel draws the total and
        carries the reason, which is what it did before there was any split at
        all.
        """
        step = _step_seconds(aggregation.interval,
                             query.window.duration_seconds)

        # One Terms child is a split. Anything else is reported rather than
        # dropped: a legend promising a breakdown nobody ran is the fault
        # this whole function exists to fix.
        children = tuple(getattr(aggregation, "sub", None) or ())
        split = next((child for child in children
                      if isinstance(child, Terms)), None)
        notes = []
        ignored = sorted({str(getattr(child, "field", None)
                              or type(child).__name__)
                          for child in children if child is not split})
        if ignored:
            notes.append(f"Loki splits a series one way: "
                         f"{', '.join(ignored)} was not applied")

        labels = normalise = None
        if split is not None:
            labels, normalise, refusal = self._by_labels(split.field)
            if refusal:
                notes.append(f"{refusal}; this is the total")

        rows, note = self._counts_over_time(query, targets, step, labels,
                                            normalise, split)
        if note:
            notes.append(note)
        return rows, notes

    def _counts_over_time(self, query, targets, step, labels, normalise, split):
        """Issue the range query, with a `by` clause or without one.

        A split that Loki refuses falls back to the unsplit total rather than
        to a 400: the label set may be wider than the server's series limit
        ("maximum of series (500) reached"), which is a property of the data
        and not of the panel. The fallback is a second query, so an outage
        still fails — it is only the SPLIT that degrades.
        """
        def ask(by):
            expression = (f"sum{by} (count_over_time("
                          f"{self._log_query(query, targets)}[{step}s]))")
            body = self._get("/loki/api/v1/query_range", {
                "query": expression,
                "start": _nanoseconds(query.window.start),
                "end": _nanoseconds(query.window.end),
                "step": f"{step}s",
            })
            return (body.get("data") or {}).get("result") or []

        note = None
        if labels:
            try:
                series = ask(f" by ({', '.join(labels)})")
            except Exception as exc:
                note = (f"Loki could not split this series ({exc}); "
                        f"this is the total")
                labels, series = None, ask("")
        else:
            series = ask("")

        totals, split_counts, unlabelled = {}, {}, False
        for one in series:
            key = None
            if labels:
                metric = one.get("metric") or {}
                if normalise:
                    # A series carrying none of them is not an unlabelled
                    # series to skip: those lines have no level, which IS a
                    # level. The same rule `_terms_buckets` counts by.
                    key = severity_from(metric, _SEVERITY_LABELS)[0]
                else:
                    key = metric.get(labels[0])
                    if key is None:
                        unlabelled = True
            for at, value in one.get("values") or []:
                at = float(at)
                count = int(float(value))
                totals[at] = totals.get(at, 0) + count
                if key is not None:
                    counts = split_counts.setdefault(at, {})
                    counts[key] = counts.get(key, 0) + count

        # The series kept are chosen over the WINDOW, not per bucket: picking
        # the top few inside each bucket makes a legend whose entries appear
        # and vanish as the eye moves along the axis.
        ranked = {}
        for counts in split_counts.values():
            for key, count in counts.items():
                ranked[key] = ranked.get(key, 0) + count
        biggest = sorted(ranked.items(), key=lambda item: -item[1])
        keep = {key for key, _ in biggest[:(getattr(split, "size", 10) or 10)]}

        # AFTER the ranking, because how many values were dropped is one of
        # the things the note has to say.
        if labels and note is None:
            note = self._split_note(split, split_counts, unlabelled, totals,
                                    len(ranked) - len(keep))

        # A bucket is labelled with the START of the interval it counts,
        # because that is what every reader of a time chart assumes and what
        # every other adapter here produces.
        #
        # Loki does not answer that way. `count_over_time(...[step])`
        # evaluated at t counts the lines in (t-step, t], so the sample
        # Loki returns AT t is the bucket ENDING at t, and this used the
        # instant verbatim. Every Loki chart was therefore drawn one whole
        # interval late, and its first bar counted records from before the
        # window entirely. Measured against the lab at a 1h interval over a
        # 9-hour window: the bucket keyed 12:00 reported 79 lines and there
        # are exactly 79 lines in [11:00, 12:00) — outside the window — while
        # the true count for [12:00, 13:00) is 85. All nine buckets matched
        # the end-labelled reading and none matched the start-labelled one.
        #
        # So the key moves back one step, and the sample that then lands
        # before the window is dropped: it counts nothing the window asked
        # for, and drawing it would make the chart wider than the range
        # above it.
        start = query.window.start.timestamp()
        rows = []
        for at in sorted(totals):
            began = at - step
            if began < start - 1:
                continue
            bucket = Bucket(
                key=int(began * 1000),
                key_text=datetime.fromtimestamp(
                    began, tz=timezone.utc).isoformat(),
                count=totals[at])
            kept = [Bucket(key=key, count=count)
                    for key, count in sorted(split_counts.get(at, {}).items(),
                                             key=lambda item: -item[1])
                    if key in keep]
            if kept:
                bucket.sub[split.name] = kept
            rows.append(bucket)
        return rows, note

    @staticmethod
    def _split_note(split, split_counts, unlabelled, totals, dropped=0):
        """Why a split is missing or short, or None when it is whole.

        Every sentence here needs EVIDENCE, which is what `totals` and
        `unlabelled` are for. Loki does not report "that is not a label"; the
        adapter infers it from an answer of one unlabelled series carrying
        every line, and an empty answer is not that — it is a window in which
        nothing matched. Said anyway, it told an author that `severity` is
        not a Loki label on streams where it is, about a total that does not
        exist, and sent them to fix a panel that was right. `_terms_buckets`
        has always required the same evidence (`if unlabelled and not
        counts`); this is that rule, on the path that draws the picture.
        """
        if not split_counts:
            if not (unlabelled and totals):
                # Nothing was counted at all: no series, or series with no
                # points. There is nothing to explain and no total to claim.
                return None
            # Measured: `sum by (host)` over streams with no `host` label
            # answers with ONE series, no labels, carrying every line — so the
            # totals above are right and only the breakdown is missing.
            return (f"'{split.field}' is not a Loki label on these streams; "
                    f"this is the total")
        parts = []
        if unlabelled:
            # Half a breakdown is the worse state, because the stack is
            # shorter than the line above it and nothing says why.
            parts.append(f"some streams carry no '{split.field}' label; those "
                         f"lines are counted in the total and not in the split")
        if dropped > 0:
            # The same visible gap from the other cause: measured on the lab,
            # a 24h split by `service` at size 10 drew 473 of the 488 lines
            # on the line above it, the rest belonging to services that fell
            # off the end of the ranking.
            parts.append(f"{dropped} smaller '{split.field}' value"
                         f"{'' if dropped == 1 else 's'} did not fit the "
                         f"legend; those lines are counted in the total and "
                         f"not in the split")
        return "; ".join(parts) or None

    def histogram(self, query, scope):
        result = self.aggregate(
            query, [DateHistogram(name="timeline", min_count=0)], scope)
        return result.get("timeline")


def _maybe_json(line):
    """Parse a structured line, or return None.

    Loki stores lines as text. A JSON line carries fields worth surfacing; a
    plain one does not, and guessing at its structure would invent data.
    """
    line = (line or "").strip()
    if not line.startswith("{"):
        return None
    try:
        parsed = json.loads(line)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _step_seconds(interval, window_seconds):
    """Turn a neutral interval like '5m' into seconds."""
    if not interval:
        return max(int(window_seconds // 60) or 1, 1)
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    try:
        return max(int(interval[:-1]) * units[interval[-1]], 1)
    except (ValueError, KeyError):
        return max(int(window_seconds // 60) or 1, 1)
