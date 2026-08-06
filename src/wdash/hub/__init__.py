"""
WDash Hub — a shared layer over multiple observability backends.

Design
------
1. **A neutral internal model.** Elasticsearch's `hits`/`_source` shape does
   not leak into the codebase; the internal model speaks OpenTelemetry
   semantic conventions. Adding a second backend means writing an adapter,
   not a rewrite.

2. **Scope is required.** Every source method takes a `scope`. Because the
   Basic licence has no document-level security, all authorization lives in
   the application and must be impossible to forget.

3. **Capabilities are explicit.** No backend does everything. A source
   declares what it supports through `capabilities` — the hub makes
   differences visible rather than hiding them.

Usage:
    hub = Hub()
    hub.add_logs(ElasticsearchLogSource(es))
    hub.add_traces(ElasticsearchTraceSource(es))

    page = hub.logs().search(LogQuery(window=TimeWindow.of("1h")), scope)
"""

from .models import (
    FieldStat, FieldValue, LogPage, LogRecord, Service, SourceRef, Span, Trace,
    iso_millis, normalise_severity, TraceSummary,
)
from .aggregation import AggregationResult, Bucket, DateHistogram, Terms
from .query import LogQuery, TimeWindow, TraceQuery, SORT_RECENT, SORT_SLOWEST
from .scope import Scope, ScopeViolation
from .fanout import FanOutLogSource, FanOutTraceSource
from .source import Capability, LogSource, Source, TraceSource

__all__ = [
    "Hub", "Scope", "ScopeViolation", "Capability", "FanOutLogSource",
    "FanOutTraceSource",
    "Source", "LogSource", "TraceSource",
    "LogQuery", "TraceQuery", "TimeWindow", "SORT_RECENT", "SORT_SLOWEST",
    "Terms", "DateHistogram", "Bucket", "AggregationResult",
    "LogRecord", "LogPage", "FieldStat", "FieldValue", "SourceRef",
    "Span", "Trace", "Service", "TraceSummary", "normalise_severity", "iso_millis",
]


class Hub:
    """Registry of configured sources.

    One log source and one trace source are enough today; the registry exists
    so callers depend on the interface rather than a concrete adapter. When
    multiple sources are needed (separate clusters, for example) the fan-out
    happens here and callers stay unchanged.
    """

    def __init__(self):
        self._logs = {}
        self._traces = {}
        self._monitors = {}

    def add_logs(self, source):
        self._logs[source.name] = source
        return source

    def add_traces(self, source):
        self._traces[source.name] = source
        return source

    def add_monitors(self, source):
        self._monitors[source.name] = source
        return source

    def replace_all(self, logs=(), traces=(), monitors=()):
        """Swap every registered source out.

        For tests that assert on what a scope reaches. The app factory always
        registers an environment-configured Elasticsearch source, so a test
        machine with a cluster running on the default port sees that cluster's
        real indices and one without sees none — the same assertion passes,
        fails or passes for the wrong reason depending on what happens to be
        listening.
        """
        self._logs = {source.name: source for source in logs}
        self._traces = {source.name: source for source in traces}
        self._monitors = {source.name: source for source in monitors}

    #: Reserved name for "search everything". Not a registered source, so it
    #: cannot collide with one an operator configures.
    ALL_SOURCES = "*"

    def logs(self, name=None):
        """One log source, or the fan-out over all of them.

        `name="*"` asks for every source at once. With a single source that is
        the source itself rather than a wrapper: a fan-out of one adds a thread
        pool, an intersection and a merge to answer a question one object
        already answers.
        """
        if name == self.ALL_SOURCES:
            sources = self.log_sources
            if not sources:
                return None
            if len(sources) == 1:
                return sources[0]
            from .fanout import FanOutLogSource, FanOutTraceSource
            return FanOutLogSource(sources)
        return self._pick(self._logs, name, "log")

    def traces(self, name=None):
        """One trace source, or the fan-out over all of them.

        Same shape as `logs`. Without this, a second trace source registered
        from the configuration page was reachable by nothing: it appeared in
        the source list, the health check probed it, and every query went to
        whichever one happened to be first. Registered and unreachable is
        worse than absent — the page says it is there.
        """
        if name == self.ALL_SOURCES:
            sources = self.trace_sources
            if not sources:
                return None
            if len(sources) == 1:
                return sources[0]
            from .fanout import FanOutTraceSource
            return FanOutTraceSource(sources)
        return self._pick(self._traces, name, "trace")

    def monitors(self, name=None):
        """One monitor source, or the fan-out over all of them.

        Same shape as `logs` and `traces`. A deployment can easily have two:
        Heartbeat writing to the production cluster and a second agent
        watching from another region, which is the whole point of running
        checks from outside.
        """
        if name == self.ALL_SOURCES:
            sources = self.monitor_sources
            if not sources:
                return None
            if len(sources) == 1:
                return sources[0]
            from .fanout import FanOutMonitorSource
            return FanOutMonitorSource(sources)
        return self._pick(self._monitors, name, "monitor")

    @staticmethod
    def _pick(registry, name, kind):
        if name:
            if name not in registry:
                raise KeyError(f"no {kind} source named {name}")
            return registry[name]
        if not registry:
            return None
        return next(iter(registry.values()))

    @property
    def log_sources(self):
        return list(self._logs.values())

    @property
    def trace_sources(self):
        return list(self._traces.values())

    @property
    def monitor_sources(self):
        return list(self._monitors.values())

    def _all(self):
        """Every registered source, once each.

        Deduplicated by identity: one configured Elasticsearch serving logs,
        traces and monitors is three adapters, but two adapters sharing a name
        would otherwise report health twice under the same key and the second
        would silently win.
        """
        seen, out = set(), []
        for registry in (self._logs, self._traces, self._monitors):
            for source in registry.values():
                if id(source) not in seen:
                    seen.add(id(source))
                    out.append(source)
        return out

    def capabilities(self):
        """Union of the capabilities of every registered source."""
        result = set()
        for source in self._all():
            result |= set(source.capabilities)
        return frozenset(result)

    def health(self):
        report = {}
        for source in self._all():
            healthy, detail = source.health()
            report[source.name] = {"healthy": healthy, "detail": detail}
        return report
