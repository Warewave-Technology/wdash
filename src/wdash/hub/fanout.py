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
    DOWN, FieldStat, FieldValue, LogPage, MonitorPage, MonitorPoint,
    PartialCounts, PartialList, Service, Trace,
)
from .source import Capability, LogSource, MonitorSource, TraceSource
from .source import MonitorSourceError

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
        seen, ordered, failed = set(), [], []
        for source, containers, error in self._parallel(
                lambda source: source.containers(scope)):
            if error is not None:
                failed.append((source.name, error))
                continue
            for name in containers or []:
                if name not in seen:
                    seen.add(name)
                    ordered.append(name)
        # Every member failing is a failure, and it left here as an empty
        # list: with two Elasticsearch sources both refusing connections the
        # page said "No log indices found in Elasticsearch" and the search API
        # answered 404 no_indices — the same fault the adapter's own catalogue
        # was fixed for, one level up. Some members failing is still an
        # answer, as it is for a search.
        if failed and len(failed) == len(self._sources):
            raise RuntimeError("; ".join(f"{name}: {error}"
                                         for name, error in failed))
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

        totals, failed, warnings = {}, [], []
        for source, stats, error in self._parallel(
                lambda source: (source.field_stats(query, scope)
                                if Capability.FIELD_STATS in source.capabilities
                                else [])):
            if error is not None:
                logger.warning(f"{source.name} field statistics failed: {error}")
                failed.append((source.name, error))
                continue
            # A member that answered from part of its data says so, and the
            # merge is where that would otherwise be dropped: a sum of one
            # source's real counts and another's sixth of one is a number
            # nobody can read.
            for warning in getattr(stats, "warnings", ()) or ():
                warnings.append(f"{source.name}: {warning}")
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
        # A member that failed was skipped with a log line, and its share of
        # every count went missing without a word on the page. Every member
        # failing is a failure; some is an answer that names who is missing.
        asked = [s for s in self._sources if Capability.FIELD_STATS in s.capabilities]
        if failed and len(failed) == len(asked):
            raise RuntimeError("; ".join(f"{name}: {error}" for name, error in failed))
        return _FieldStats(out, failed=[name for name, _ in failed],
                           warnings=warnings)

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
        result = self.aggregate(
            query, [DateHistogram(name="timeline", min_count=0)], scope)
        # The aggregation says what it could not reach; a bare list of buckets
        # does not, and that is what this used to hand back.
        return PartialCounts(result.get("timeline"), warnings=result.warnings)

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


class _FieldStats(PartialCounts):
    """Merged field statistics, and the members whose statistics failed.

    A list, so every caller of `field_stats` keeps the type it handles; the
    route reads `failed` to say whose counts are missing, and `warnings` for
    a member that answered from part of its own data.
    """

    def __init__(self, stats, failed=(), warnings=()):
        super().__init__(stats, warnings=warnings)
        self.failed = tuple(failed)

    @property
    def partial(self):
        return bool(self.warnings or self.failed)


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
        """One trace, assembled from every backend that has part of it.

        A member that failed makes the trace partial and is named. When
        nothing was found and a member failed, the failure is raised rather
        than answered None: the trace may be exactly what that member holds,
        and None is "not found in the selected time range" on the page.
        """
        spans, partial, found, hidden = [], False, False, 0
        seen_spans, warnings, failed = set(), [], []

        for source, trace, error in self._parallel(
                lambda source: source.trace(trace_id, window, scope)):
            if error is not None:
                partial = True
                failed.append(source.name)
                warnings.append(f"{source.name} failed: {error}")
                logger.warning(f"{source.name} failed on trace {trace_id}: {error}")
                continue
            if trace is None:
                continue
            found = True
            partial = partial or trace.partial
            hidden += getattr(trace, "hidden", 0)
            warnings.extend(f"{source.name}: {warning}"
                            for warning in getattr(trace, "warnings", ()) or ())
            for span in trace.spans:
                # Dedup by span id: a span exported to two backends is one
                # span, and drawing it twice reads as a retry.
                if span.span_id in seen_spans:
                    continue
                seen_spans.add(span.span_id)
                spans.append(span)

        if not found and not spans:
            if failed:
                raise RuntimeError(f"trace {trace_id} could not be looked up in "
                                   f"{', '.join(failed)}: " + "; ".join(warnings))
            return None
        return Trace(trace_id=trace_id, spans=spans, partial=partial,
                     hidden=hidden, warnings=tuple(warnings))

    def _gather(self, work, what):
        """Every member's answer to `work`, as (rows, partial, warnings).

        A member that failed is named in the warnings and its rows are
        missing; a member's own partial answer carries through. When every
        member failed there is no answer to give, and that is raised.
        """
        results = self._parallel(work)
        rows, warnings, failed, partial = [], [], 0, False
        for source, found, error in results:
            if error is not None:
                failed += 1
                warnings.append(f"{source.name} failed: {error}")
                logger.warning(f"{source.name} failed on {what}: {error}")
                continue
            partial = partial or bool(getattr(found, "partial", False))
            warnings.extend(f"{source.name}: {warning}"
                            for warning in getattr(found, "warnings", ()) or ())
            rows.append((source, found or ()))
        if failed and failed == len(results):
            raise RuntimeError(f"no trace source could answer the {what}: "
                               + "; ".join(warnings))
        return rows, partial or bool(failed), warnings

    def services(self, window, scope):
        totals, errors = {}, {}
        answered, partial, warnings = self._gather(
            lambda source: source.services(window, scope), "service list")
        for _, services in answered:
            for service in services:
                totals[service.name] = totals.get(service.name, 0) + service.span_count
                errors[service.name] = (errors.get(service.name, 0)
                                        + service.error_count)
        return PartialList(sorted(
            (Service(name=name, span_count=count,
                     error_count=errors.get(name, 0))
             for name, count in totals.items()),
            key=lambda service: service.span_count, reverse=True),
            partial=partial, warnings=warnings)

    def search(self, query, scope):
        """Trace summaries from every backend, in the order asked for.

        Summaries are NOT deduplicated across sources. Two backends returning
        the same trace id return different halves of it, and hiding one is how
        somebody concludes a service was not involved. The source is on each
        summary so the duplication is legible rather than confusing.

        Merged in the query's own order. Each member sorted its rows by
        duration for "slowest", and this sorted the lot by start time again
        before cutting it to the limit: over the lab's Tempo and Jaeger, the
        five slowest were Tempo's 34-minute traces and the merged five were
        Jaeger's 69 ms ones.
        """
        from .query import SORT_SLOWEST
        summaries = []
        answered, partial, warnings = self._gather(
            lambda source: source.search(query, scope), "trace search")
        for source, found in answered:
            for summary in found:
                if getattr(summary, "source", None) is None:
                    summary.source = source.name
                summaries.append(summary)

        if getattr(query, "sort", None) == SORT_SLOWEST:
            summaries.sort(key=lambda summary: summary.duration_us or 0, reverse=True)
        else:
            summaries.sort(key=lambda summary: summary.start or _EPOCH, reverse=True)
        limit = getattr(query, "limit", None)
        return PartialList(summaries[:limit] if limit else summaries,
                           partial=partial, warnings=warnings)


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

    def history(self, monitor_id, window, scope, offset=0, limit=None):
        """Whichever sources know this monitor, merged by time.

        A monitor id is unique within an agent, not across agents. Asking all
        of them and merging is what makes a history complete when the same
        check runs from two places.

        A page of the merge is not the merge of two pages, so each member is
        asked for its newest `offset + limit` and the slice is taken after
        the sort. The total is the members' totals added up, not the length
        of what came back: Elasticsearch stops a history at 500, and "of
        500" under a day of 1,440 checks was a pager that could not reach
        page 21. When only one member knows the monitor — the usual case —
        and its own ceiling stops short of the page, that member is asked
        for the page itself.

        A member that fails is named in `warnings` rather than dropped. When
        no member that answered had a check, this raises instead: the store
        knowing nothing of an Elasticsearch monitor while Elasticsearch is
        down is not "no check in this window", it is nobody able to say.
        """
        offset = max(0, int(offset or 0))
        wanted = None if limit is None else offset + int(limit)

        def ask(source, **paging):
            try:
                return source.history(monitor_id, window, scope, **paging)
            except TypeError:
                if not paging:
                    raise
                # Written against the three-argument interface: it answers
                # with the whole window, and the page is cut here.
                return source.history(monitor_id, window, scope)

        answered, warnings, failed = [], [], 0
        for source, checks, error in self._parallel(
                lambda s: ask(s) if wanted is None
                else ask(s, offset=0, limit=wanted)):
            if error is not None:
                failed += 1
                warnings.append(_named(source, error))
                continue
            warnings.extend(getattr(checks, "warnings", ()))
            if checks:
                answered.append((source, checks))
        if failed and not answered:
            raise MonitorSourceError("; ".join(warnings))

        def total_of(checks):
            return getattr(checks, "total", None) or len(checks)

        if len(answered) == 1 and wanted is not None:
            source, checks = answered[0]
            if len(checks) < min(wanted, total_of(checks)):
                page = source.history(monitor_id, window, scope,
                                      offset=offset, limit=limit)
                result = _CountedChecks(page)
                result.total = total_of(checks)
                result.warnings = tuple(dict.fromkeys(
                    warnings + list(getattr(page, "warnings", ()))))
                return result

        merged = []
        for source, checks in answered:
            merged.extend(checks)
            if len(answered) > 1 and len(checks) < min(
                    wanted or total_of(checks), total_of(checks)):
                warnings.append(
                    f"{source.name}: only its newest {len(checks):,} of "
                    f"{total_of(checks):,} checks could be merged")
        merged.sort(key=lambda check: check.timestamp or _EPOCH)

        if limit is not None:
            newest_first = list(reversed(merged))
            merged = list(reversed(newest_first[offset:offset + int(limit)]))
        result = _CountedChecks(merged)
        result.total = sum(total_of(checks) for _, checks in answered)
        result.warnings = tuple(warnings)
        if len(answered) == 1:
            # One member's own count of the whole window travels with it.
            # Several members' estimates cannot be added together, and the
            # page says so by falling back to the rows it holds.
            result.whole_window = getattr(answered[0][1], "whole_window",
                                          None)
        return result

    def series(self, monitor_id, window, scope, points=120):
        """The detail chart, merged across sources.

        Missing entirely until a second monitor source was configured, at
        which point the fan-out replaced the single source and took its
        `series` with it — the chart went to "not enough checks to draw a
        line" while the list beside it was full. The same shape as the
        `series=True` gap on `monitors`: one instance of the class was fixed
        and the class was not.

        A member whose buckets hold no check is left out. The store answers
        every monitor with a full set of empty buckets, and merging those by
        position with Elasticsearch's — which sit on multiples of the
        interval since the epoch, 33 of them for fifteen minutes — drew 120
        labels, the data in the first 33, and time running backwards where
        the two met. One member left is returned as it came.

        Several members that measured the monitor are merged BY TIME onto
        one grid of `points` equal spans across the window. Durations are
        averaged WEIGHTED by how many checks each bucket holds — a plain mean
        of means lets a source with one check outweigh one with fifty.
        """
        collected, warnings, failed = [], [], 0
        for source, series, error in self._parallel(
                lambda s: s.series(monitor_id, window, scope, points=points)
                if hasattr(s, "series") else []):
            if error is not None:
                failed += 1
                warnings.append(_named(source, error))
            elif series:
                collected.append(series)

        measured = [s for s in collected if any(p.checks for p in s)]
        if failed and not measured:
            # Empty buckets from the members that answered, and the one that
            # might have measured it did not: that is not an empty chart.
            raise MonitorSourceError("; ".join(warnings))
        if len(measured) > 1:
            merged = _CountedPoints(self._on_one_grid(measured, window, points))
        else:
            merged = _CountedPoints((measured or collected or [[]])[0])
        merged.warnings = tuple(warnings)
        return merged

    @staticmethod
    def _on_one_grid(collected, window, points):
        """Every member's buckets, put where their time says they go."""
        points = max(1, int(points))
        width = max(1.0, (window.end - window.start).total_seconds()) / points
        cells = [[] for _ in range(points)]
        for series in collected:
            for point in series:
                if not point.checks:
                    continue
                index = int((point.timestamp - window.start).total_seconds()
                            // width)
                # A bucket that starts before the window — Elasticsearch's
                # first one usually does — holds only checks inside it, and
                # those belong to the first span.
                cells[min(points - 1, max(0, index))].append(point)

        merged = []
        for index, buckets in enumerate(cells):
            checks = sum(b.checks for b in buckets)
            weighted = sum((b.duration_ms or 0) * b.checks
                           for b in buckets if b.duration_ms is not None)
            counted = sum(b.checks for b in buckets if b.duration_ms is not None)
            worsts = [getattr(b, "worst_ms", None) for b in buckets]
            worsts = [w for w in worsts if w is not None]

            point = MonitorPoint(
                timestamp=window.start + dt.timedelta(seconds=index * width),
                duration_ms=(weighted / counted) if counted else None,
                down=sum(b.down for b in buckets),
                checks=checks)
            point.worst_ms = max(worsts) if worsts else None
            merged.append(point)
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


class _CountedChecks(list):
    """A list of checks that also knows the total, matching the sources."""
    total = 0
    #: Members that could not answer, by name. The rows are what the others
    #: said, and the page says what is missing from them.
    warnings = ()
    whole_window = None


class _CountedPoints(list):
    """A merged chart, and the members that could not be asked for theirs."""
    warnings = ()


def _named(source, error):
    """A member's failure as a sentence that names it once."""
    text = str(error) or type(error).__name__
    return text if text.startswith(f"{source.name}:") else f"{source.name}: {text}"
