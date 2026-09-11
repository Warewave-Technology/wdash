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
from ..models import LogPage, LogRecord, SourceRef, normalise_severity
from ..source import Capability, LogSource
from .. import query_language as ql

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

#: Labels Loki pipelines conventionally set, mapped onto the neutral model.
#: Anything else stays a label and shows up as a resource entry.
_SEVERITY_LABELS = ("level", "severity", "detected_level")
_SERVICE_LABELS = ("service_name", "service", "app", "job", "container")


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
            logger.error(f"Loki label values could not be read: {exc}")
            return []
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
        else:
            start, end = window.start, window.end

        key = (_nanoseconds(start), _nanoseconds(end))
        now = time.monotonic()
        cached = self._label_cache.get(key)
        if cached is not None and (now - cached[1]) < ttl:
            return cached[0]

        body = self._get(f"/loki/api/v1/label/{self._stream_label}/values",
                         {"start": key[0], "end": key[1]})
        values = sorted(body.get("data") or [])
        # Bounded: one entry per distinct window, and the windows come from a
        # time picker with a handful of choices. Cleared wholesale rather than
        # evicted, because there is nothing here worth an LRU.
        if len(self._label_cache) > 32:
            self._label_cache.clear()
        self._label_cache[key] = (values, now)
        return values

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
            inner = self._pipeline(node.clause)
            if inner.startswith(' |= "'):
                return ' !=' + inner[3:]
            raise LokiError("Loki cannot express this negation")

        raise LokiError(
            f"{type(node).__name__} has no LogQL equivalent; "
            f"Loki cannot express this query")

    @staticmethod
    def _label_for(neutral_name):
        return {"severity": "level", "severity_text": "level",
                "service": "service_name"}.get(neutral_name, neutral_name)

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
            severity_label = next(
                (labels[name] for name in _SEVERITY_LABELS if name in labels),
                None)
            service = next(
                (labels[name] for name in _SERVICE_LABELS if name in labels), "")

            for entry in stream.get("values") or []:
                timestamp_ns, line = entry[0], entry[1]
                structured = _maybe_json(line)

                records.append(LogRecord(
                    timestamp=datetime.fromtimestamp(
                        int(timestamp_ns) / 1_000_000_000, tz=timezone.utc),
                    body=line,
                    severity=normalise_severity(
                        severity_label or (structured or {}).get("level")),
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
        failed = False
        for aggregation in aggregations:
            try:
                if isinstance(aggregation, DateHistogram):
                    buckets[aggregation.name] = self._histogram_buckets(
                        query, targets, aggregation)
                elif isinstance(aggregation, Terms):
                    rows = self._terms_buckets(query, targets, aggregation)
                    buckets[aggregation.name] = rows
                    total = max(total, sum(row.count for row in rows))
                else:
                    warnings.append(
                        f"{type(aggregation).__name__} is not supported by Loki")
            except Exception as exc:
                failed = True
                warnings.append(f"{aggregation.name} failed: {exc}")

        return AggregationResult(total=total, buckets=buckets,
                                 warnings=tuple(warnings), failed=failed)

    def _instant(self, expression, query):
        body = self._get("/loki/api/v1/query", {
            "query": expression,
            "time": _nanoseconds(query.window.end),
        })
        return (body.get("data") or {}).get("result") or []

    def _terms_buckets(self, query, targets, aggregation):
        """`sum by (label) (count_over_time(...))`.

        Only works for values Loki has as LABELS. A field that lives inside the
        line is not aggregatable without a parser stage, and pretending
        otherwise would return an empty chart that looks like no data.
        """
        label = self._label_for(aggregation.field)
        window = int(query.window.duration_seconds) or 1
        expression = (f"sum by ({label}) (count_over_time("
                      f"{self._selector(targets)}[{window}s]))")

        # Severity buckets are normalised, because the neutral model promises
        # normalised severity everywhere and Loki labels are lower case. Two
        # sources answering the same panel with "ERROR" and "error" would draw
        # two bars for one thing — and colour only one of them red.
        normalise = aggregation.field in ("severity", "severity_text")

        counts = {}
        for series in self._instant(expression, query):
            key = (series.get("metric") or {}).get(label)
            if key is None:
                continue
            value = series.get("value") or [0, "0"]
            if normalise:
                key = normalise_severity(key)
            counts[key] = counts.get(key, 0) + int(float(value[1]))

        rows = [Bucket(key=key, count=count) for key, count in counts.items()]
        rows.sort(key=lambda bucket: bucket.count, reverse=True)
        return rows[:aggregation.size]

    def _histogram_buckets(self, query, targets, aggregation):
        step = _step_seconds(aggregation.interval,
                             query.window.duration_seconds)
        expression = (f"sum(count_over_time("
                      f"{self._selector(targets)}[{step}s]))")

        body = self._get("/loki/api/v1/query_range", {
            "query": expression,
            "start": _nanoseconds(query.window.start),
            "end": _nanoseconds(query.window.end),
            "step": f"{step}s",
        })

        rows = []
        for series in (body.get("data") or {}).get("result") or []:
            for at, value in series.get("values") or []:
                rows.append(Bucket(
                    key=int(float(at) * 1000),
                    key_text=datetime.fromtimestamp(
                        float(at), tz=timezone.utc).isoformat(),
                    count=int(float(value))))
        rows.sort(key=lambda bucket: bucket.key)
        return rows

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
