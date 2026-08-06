"""
Searching every source at once.

A LogSource that is really several. Presenting the fan-out as a source means
every route, every dashboard panel and the whole conformance suite work
unchanged — the merged view is not a special case threaded through the
application, it is another implementation of an interface that already exists.

Three things are hard here, and none of them is the merge:

**Partial failure must be visible.** One backend down and the page still
renders — with fewer results and no indication that anything is missing. That
is the failure mode this codebase keeps having to defend against: fewer rows
looks exactly like less data. Every source that fails is named in the warnings
and `partial` is set.

**A merged total is a lie unless it says so.** Elasticsearch reports a real
match count; Loki returns up to `limit` and stops. Adding them produces a
number that is neither, and people reason about numbers. The sum is reported
as a lower bound whenever any contributor could not count.

**Capabilities are the intersection, not the union.** If only one source can do
field statistics, serving its answer for a merged view labels one source's data
as everything's. Narrowing is the honest choice: the feature is offered when it
can be answered properly, and refused otherwise.

Fan-out is parallel. Serial would multiply latency by the number of backends
for no reason — they are independent systems and nothing about the merge needs
one before the next.
"""

import datetime as dt
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from .aggregation import AggregationResult, Bucket
from .models import (
    DOWN, FieldStat, FieldValue, LogPage, MonitorPage, Service, Trace,
)
from .source import Capability, LogSource, MonitorSource, TraceSource

logger = logging.getLogger(__name__)

#: Bounded because a fan-out with a thread per source, per request, per worker
#: multiplies quickly. Nobody has this many log backends; the cap exists so a
#: misconfiguration cannot exhaust the pool.
MAX_PARALLEL = 8

#: Sort key for a record with no timestamp: it goes last rather than crashing
#: the merge, because one malformed record must not lose the whole page.
_EPOCH = dt.datetime.fromtimestamp(0, tz=dt.timezone.utc)


class FanOutLogSource(LogSource):
    """Every configured log source, behind one."""

    backend = "fanout"

    def __init__(self, sources, name="all-sources"):
        if not sources:
            raise ValueError("a fan-out needs at least one source")
        self.name = name
        self._sources = list(sources)

    @property
    def sources(self):
        return list(self._sources)

    #: Capabilities the fan-out IMPLEMENTS rather than delegates.
    #:
    #: The intersection is right for everything it passes through: offering a
    #: feature that quietly answers from a subset labels one source's data as
    #: everything's. Field statistics are different because the fan-out merges
    #: them itself and names the sources that could not contribute — so the
    #: answer is attributed rather than pretended.
    #:
    #: The intersection was applied here too at first, and the effect was
    #: absurd: one Loki source holding a single log line out of a hundred
    #: thousand removed the sidebar from the merged view entirely. Hiding a
    #: feature is not more honest than answering it with a note attached.
    MERGED_CAPABILITIES = frozenset({Capability.FIELD_STATS})

    @property
    def capabilities(self):
        """What EVERY member can do, plus what the fan-out does itself."""
        shared = set(self._sources[0].capabilities)
        for source in self._sources[1:]:
            shared &= set(source.capabilities)

        for capability in self.MERGED_CAPABILITIES:
            if any(capability in source.capabilities
                   for source in self._sources):
                shared.add(capability)
        return frozenset(shared)

    def contributors(self, capability):
        """(can, cannot) member names for a capability. For attribution."""
        can = [s.name for s in self._sources if capability in s.capabilities]
        cannot = [s.name for s in self._sources
                  if capability not in s.capabilities]
        return can, cannot

    def health(self):
        results = [(source.name, source.health()) for source in self._sources]
        unhealthy = [name for name, (ok, _) in results if not ok]
        if not unhealthy:
            return True, f"{len(results)} sources ok"
        # Degraded rather than down: the healthy sources still answer, and
        # reporting the whole thing as down would hide that.
        return False, f"unhealthy: {', '.join(unhealthy)}"

    # ---------- fan-out ----------

    def _parallel(self, work):
        """Run one callable per source and keep failures attached to a name.

        Returns [(source, result_or_None, error_or_None)] in source order, so a
        caller can report which backend failed rather than that something did.
        """
        if len(self._sources) == 1:
            source = self._sources[0]
            try:
                return [(source, work(source), None)]
            except Exception as exc:
                return [(source, None, exc)]

        with ThreadPoolExecutor(max_workers=min(len(self._sources),
                                                MAX_PARALLEL)) as pool:
            futures = [(source, pool.submit(work, source))
                       for source in self._sources]
            out = []
            for source, future in futures:
                try:
                    out.append((source, future.result(), None))
                except Exception as exc:
                    logger.error(f"source '{source.name}' failed: {exc}")
                    out.append((source, None, exc))
            return out

    # ---------- containers ----------

    def containers(self, scope):
        """Every container the scope permits, across every source.

        Names are NOT qualified with the source. That keeps existing
        authorization working unchanged — a role granted `app-*` still means
        `app-*` — and it has a consequence worth stating plainly: a pattern
        applies to every source, so adding a source widens what existing roles
        can reach. See docs/hub.md.
        """
        if scope.is_empty:
            return []
        seen, ordered = set(), []
        for source, containers, _ in self._parallel(
                lambda source: source.containers(scope)):
            for name in containers or []:
                if name not in seen:
                    seen.add(name)
                    ordered.append(name)
        return ordered

    # ---------- search ----------

    def search(self, query, scope):
        if scope.is_empty:
            return LogPage(warnings=("the scope permits no containers",))

        # Each source is asked for a full page. Asking for limit/N would make
        # the merged page wrong whenever the results are not evenly spread —
        # which is the normal case, since one backend usually holds most of it.
        results = self._parallel(lambda source: source.search(query, scope))

        records, warnings, containers = [], [], []
        total, partial, countable = 0, False, True
        contributions = []
        # A merged page is only a note if every note in it is one. One real
        # fault among five sources is still a fault.
        informational = True

        for source, page, error in results:
            if error is not None:
                partial = True
                informational = False
                warnings.append(f"{source.name} failed: {error}")
                # A source that failed still belongs in the breakdown: "0 from
                # loki" and "loki did not answer" are different facts, and
                # leaving the row out reads as the first one.
                contributions.append({"name": source.name, "count": 0,
                                      "total": 0, "failed": True})
                continue

            contributions.append({
                "name": source.name, "count": len(page.records),
                "total": page.total, "failed": False,
                "exact": not _cannot_count(page),
            })
            records.extend(page.records)
            containers.extend(page.containers or ())
            total += page.total
            partial = partial or page.partial
            warnings.extend(f"{source.name}: {warning}"
                            for warning in page.warnings or ())
            if page.warnings and not page.informational:
                informational = False

            # A source that returned exactly what it was asked for has more,
            # and if it cannot count then the sum is not a count either.
            if len(page.records) >= query.limit or _cannot_count(page):
                countable = False

        records.sort(key=lambda record: record.timestamp or _EPOCH,
                     reverse=not query.ascending)
        trimmed = records[:query.limit]

        if not countable:
            warnings.append(
                f"at least {total:,} matches; an exact count is not available "
                f"across these sources")

        # Counted from what SURVIVED the merge, not from what each source
        # returned: a page capped at 50 shows 29 from one and 21 from the
        # other, and the number people read is the one on screen.
        surviving = Counter(record.source for record in trimmed)
        for entry in contributions:
            entry["count"] = surviving.get(entry["name"], 0)

        return LogPage(
            records=trimmed,
            total=total,
            # One member that cannot count makes the merged total a floor too.
            counted=countable,
            informational=informational,
            sources=contributions,
            took_ms=max((page.took_ms for _, page, error in results
                         if error is None and page), default=0),
            containers=tuple(containers),
            partial=partial,
            warnings=tuple(warnings),
            # Paging a merged, time-ordered result needs each source's own
            # cursor advanced together, and each backend's cursor means
            # something different. Not attempted rather than done wrongly:
            # a cursor that skips records silently is worse than no paging.
            cursor=None,
        )

    def fetch(self, ref, scope):
        """Route by the handle's own backend.

        The ref already says where it came from, which is what made it worth
        carrying an opaque handle rather than a bare id.
        """
        for source in self._sources:
            if getattr(source, "backend", None) == ref.backend:
                record = source.fetch(ref, scope)
                if record is not None:
                    return record
        return None

    def raw(self, ref, scope):
        if Capability.RAW_DOCUMENT not in self.capabilities:
            raise NotImplementedError(
                f"{self.name} does not expose raw documents: not every source can")
        for source in self._sources:
            if getattr(source, "backend", None) == ref.backend:
                return source.raw(ref, scope)
        return None

    # ---------- aggregation ----------

    def field_stats(self, query, scope, fields=None, top=10):
        """Field statistics from every member that has them.

        Counts are SUMMED across sources rather than one source's answer being
        shown as everything's. Severity is already normalised by each adapter,
        so "INFO" from Elasticsearch and "INFO" from VictoriaLogs are one
        bucket rather than two bars for the same thing.

        Which sources could not contribute is not returned here — the contract
        is a list of FieldStat — but `contributors` answers it, and the route
        puts the names on screen. An answer from a subset without saying which
        subset is the thing this was avoiding in the first place.
        """
        # No member can, so neither can the fan-out. Returning an empty list
        # would make a missing feature look like missing data — the rule that
        # applies to every undeclared capability, and the one the merging
        # below does not change.
        if Capability.FIELD_STATS not in self.capabilities:
            raise NotImplementedError(
                f"{self.name} cannot serve field statistics: no configured "
                f"source provides them")

        totals = {}
        for source, stats, error in self._parallel(
                lambda source: (source.field_stats(query, scope)
                                if Capability.FIELD_STATS in source.capabilities
                                else [])):
            if error is not None:
                logger.warning(f"{source.name} field statistics failed: {error}")
                continue
            for stat in stats or ():
                bucket = totals.setdefault(stat.field, {})
                for value in stat.values:
                    bucket[value.value] = bucket.get(value.value, 0) + value.count

        out = []
        for name, counts in totals.items():
            ordered = sorted(counts.items(), key=lambda item: -item[1])[:top]
            out.append(FieldStat(
                field=name,
                values=[FieldValue(value=value, count=count)
                        for value, count in ordered]))
        # Same order the single-source adapters produce: most talked-about
        # field first, so the sidebar does not reshuffle when a source is
        # added.
        out.sort(key=lambda stat: -sum(v.count for v in stat.values))
        return out

    def aggregate(self, query, aggregations, scope):
        if Capability.AGGREGATION not in self.capabilities:
            raise NotImplementedError(
                f"{self.name} cannot aggregate: not every source can")
        if scope.is_empty:
            return AggregationResult(
                warnings=("the scope permits no containers",))

        results = self._parallel(
            lambda source: source.aggregate(query, aggregations, scope))

        merged, warnings = {}, []
        total, failed = 0, False

        for source, result, error in results:
            if error is not None or result is None:
                failed = True
                warnings.append(f"{source.name} failed: {error}")
                continue
            if result.failed:
                failed = True
            warnings.extend(f"{source.name}: {warning}"
                            for warning in result.warnings or ())
            total += result.total

            for name, buckets in (result.buckets or {}).items():
                merged.setdefault(name, {})
                for bucket in buckets:
                    _merge_bucket(merged[name], bucket)

        return AggregationResult(
            total=total,
            buckets={name: _ordered(buckets)
                     for name, buckets in merged.items()},
            warnings=tuple(warnings),
            failed=failed)

    def histogram(self, query, scope):
        if Capability.HISTOGRAM not in self.capabilities:
            raise NotImplementedError(
                f"{self.name} cannot serve histograms: not every source can")
        from .aggregation import DateHistogram
        return self.aggregate(
            query, [DateHistogram(name="timeline", min_count=0)],
            scope).get("timeline")

    def context(self, ref, scope, before=10, after=10, correlate_by=None):
        """Surrounding records come from the record's own source.

        Mixing neighbours from other backends would answer a different question
        — "what else happened then" rather than "what surrounded this".
        """
        if Capability.CONTEXT not in self.capabilities:
            raise NotImplementedError(
                f"{self.name} cannot serve context: not every source can")
        for source in self._sources:
            if getattr(source, "backend", None) == ref.backend:
                return source.context(ref, scope, before, after, correlate_by)
        raise NotImplementedError(f"no source handles '{ref.backend}' handles")


def _cannot_count(page):
    """Is this page's total a floor rather than a match count?"""
    return not page.counted


def _merge_bucket(target, bucket):
    """Add one bucket into the accumulator, recursing into sub-buckets."""
    existing = target.get(bucket.key)
    if existing is None:
        target[bucket.key] = {"count": bucket.count,
                              "key_text": bucket.key_text,
                              "sub": {}}
        existing = target[bucket.key]
    else:
        existing["count"] += bucket.count

    for name, children in (bucket.sub or {}).items():
        existing["sub"].setdefault(name, {})
        for child in children:
            _merge_bucket(existing["sub"][name], child)


def _ordered(accumulated):
    """Rebuild Buckets, date buckets by time and everything else by size."""
    buckets = [
        Bucket(key=key, count=data["count"], key_text=data["key_text"],
               sub={name: _ordered(children)
                    for name, children in data["sub"].items()})
        for key, data in accumulated.items()
    ]
    if buckets and all(isinstance(bucket.key, (int, float))
                       for bucket in buckets):
        buckets.sort(key=lambda bucket: bucket.key)
    else:
        buckets.sort(key=lambda bucket: bucket.count, reverse=True)
    return buckets


class FanOutTraceSource(TraceSource):
    """Several trace backends behind one, on the same terms as the log side.

    A trace is more sensitive to merging than a page of logs, and the reason is
    worth stating: a distributed trace can genuinely be SPLIT across backends.
    A request that crosses from a service exporting to Jaeger into one
    exporting to Tempo produces spans of one trace in two stores, and neither
    store knows the other half exists. Showing the halves separately is a
    waterfall with holes in it that look like missing instrumentation.

    So spans are merged by trace id rather than the first answer winning —
    with two consequences that have to be handled rather than hoped away:

    **The same span can arrive twice.** Collectors fan out; a span exported to
    two backends appears in both. Deduplicated by span id, because a waterfall
    that draws one span twice reads as a retry that never happened.

    **A partial trace must say so.** If one backend fails, the trace is missing
    spans, and `partial` is what stops "the payment service never ran" being
    read off an incomplete picture.

    Service lists are summed rather than deduplicated: two backends reporting
    the same service name legitimately hold different spans of it, and one
    reporting nothing is not evidence the other is wrong.
    """

    backend = "fanout"

    def __init__(self, sources, name="all-sources"):
        if not sources:
            raise ValueError("a fan-out needs at least one source")
        self.name = name
        self._sources = list(sources)

    # The parallel helper, the capability intersection and health are the same
    # problem with the same answer as the log side; inheriting them from a
    # shared mixin would be one more indirection than two short methods are
    # worth, so they are reused directly.
    #: Nothing extra. Field statistics are a log concept; a trace fan-out
    #: delegates every capability it has, so the intersection is the whole
    #: rule here.
    MERGED_CAPABILITIES = frozenset()

    sources = FanOutLogSource.sources
    capabilities = FanOutLogSource.capabilities
    contributors = FanOutLogSource.contributors
    health = FanOutLogSource.health
    _parallel = FanOutLogSource._parallel

    def containers(self, scope):
        seen = []
        for _, containers, _ in self._parallel(
                lambda source: source.containers(scope)):
            for name in containers or []:
                if name not in seen:
                    seen.append(name)
        return sorted(seen)

    def trace(self, trace_id, window, scope):
        """One trace, assembled from every backend that has part of it."""
        spans, partial, found = [], False, False
        seen_spans = set()

        for source, trace, error in self._parallel(
                lambda source: source.trace(trace_id, window, scope)):
            if error is not None:
                partial = True
                logger.warning(f"{source.name} failed on trace {trace_id}: {error}")
                continue
            if trace is None:
                continue
            found = True
            partial = partial or trace.partial
            for span in trace.spans:
                # Dedup by span id: a span exported to two backends is one
                # span, and drawing it twice reads as a retry.
                if span.span_id in seen_spans:
                    continue
                seen_spans.add(span.span_id)
                spans.append(span)

        if not found and not spans:
            return None
        return Trace(trace_id=trace_id, spans=spans, partial=partial)

    def services(self, window, scope):
        totals, errors = {}, {}
        for source, services, error in self._parallel(
                lambda source: source.services(window, scope)):
            if error is not None:
                logger.warning(f"{source.name} failed listing services: {error}")
                continue
            for service in services or ():
                totals[service.name] = totals.get(service.name, 0) + service.span_count
                errors[service.name] = (errors.get(service.name, 0)
                                        + service.error_count)
        return sorted(
            (Service(name=name, span_count=count,
                     error_count=errors.get(name, 0))
             for name, count in totals.items()),
            key=lambda service: service.span_count, reverse=True)

    def search(self, query, scope):
        """Trace summaries from every backend, newest first.

        Summaries are NOT deduplicated across sources. Two backends returning
        the same trace id return different halves of it, and hiding one is how
        somebody concludes a service was not involved. The source is on each
        summary so the duplication is legible rather than confusing.
        """
        summaries = []
        for source, found, error in self._parallel(
                lambda source: source.search(query, scope)):
            if error is not None:
                logger.warning(f"{source.name} failed on trace search: {error}")
                continue
            for summary in found or ():
                if getattr(summary, "source", None) is None:
                    summary.source = source.name
                summaries.append(summary)

        summaries.sort(key=lambda summary: summary.start or _EPOCH, reverse=True)
        limit = getattr(query, "limit", None)
        return summaries[:limit] if limit else summaries


class FanOutMonitorSource(MonitorSource):
    """Several monitor backends behind one.

    Two agents watching the same endpoint from different places is not a
    mistake to be deduplicated away — it is the entire point of synthetic
    monitoring. "Up from Frankfurt, down from Singapore" is the answer, and
    collapsing it to one row throws away the only thing the second agent was
    installed to tell you.

    So monitors are keyed by (source, monitor id) rather than by monitor id.
    The list is longer and it is honest; the alternative silently picks a
    winner, and which one wins depends on dictionary order.
    """

    backend = "fanout"

    def __init__(self, sources, name="all-sources"):
        if not sources:
            raise ValueError("a fan-out needs at least one source")
        self.name = name
        self._sources = list(sources)

    #: Nothing extra: every capability here is delegated, so the intersection
    #: is the whole rule.
    MERGED_CAPABILITIES = frozenset()

    sources = FanOutLogSource.sources
    capabilities = FanOutLogSource.capabilities
    contributors = FanOutLogSource.contributors
    health = FanOutLogSource.health
    _parallel = FanOutLogSource._parallel

    def containers(self, scope):
        seen = []
        for _, containers, _ in self._parallel(
                lambda source: source.containers(scope)):
            for name in containers or []:
                if name not in seen:
                    seen.append(name)
        return seen

    def monitors(self, window, scope, series=False):
        """`series` is forwarded, and a member that cannot take it still works.

        Without the forward, the sparklines vanished the moment a second
        monitor source was configured — the route asks the fan-out, the
        fan-out asked each member without it, and every row came back with an
        empty series. A page that quietly loses a column when you add a source
        is worse than one that never had it.
        """
        def ask(source):
            if not series:
                return source.monitors(window, scope)
            try:
                return source.monitors(window, scope, series=True)
            except TypeError:
                # A source written against the two-argument interface. Its
                # rows simply have no sparkline; the others keep theirs.
                return source.monitors(window, scope)

        merged, warnings, answered, missing = [], [], [], []
        for source, page, error in self._parallel(ask):
            if error is not None or page is None:
                missing.append(source.name)
                warnings.append(f"{source.name}: {error}")
                continue
            answered.append(source.name)
            merged.extend(page.monitors)
            warnings.extend(page.warnings)
            if page.partial:
                missing.append(source.name)

        merged.sort(key=lambda m: (m.status != DOWN, m.name.lower(),
                                   m.source, m.id))
        return MonitorPage(
            monitors=merged, warnings=tuple(warnings),
            # Partial when ANY source failed. A page that is missing a whole
            # region's monitors and does not say so reads as "those checks
            # were deleted".
            partial=bool(missing), sources=tuple(answered),
            missing_sources=tuple(dict.fromkeys(missing)))

    def history(self, monitor_id, window, scope):
        """Whichever sources know this monitor, merged by time.

        A monitor id is unique within an agent, not across agents. Asking all
        of them and merging is what makes a history complete when the same
        check runs from two places.
        """
        merged = []
        for _, checks, error in self._parallel(
                lambda s: s.history(monitor_id, window, scope)):
            if error is None and checks:
                merged.extend(checks)
        merged.sort(key=lambda check: check.timestamp or 0)
        return merged

    def certificates(self, window, scope):
        merged = []
        for _, certificates, error in self._parallel(
                lambda s: s.certificates(window, scope)):
            if error is None and certificates:
                merged.extend(certificates)
        merged.sort(key=lambda m: (m.certificate.days_remaining is None,
                                   m.certificate.days_remaining or 0))
        return merged
