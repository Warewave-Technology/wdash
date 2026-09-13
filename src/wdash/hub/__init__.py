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

import logging
import threading
import time

from .models import (
    FieldStat, FieldValue, LogPage, LogRecord, Service, SourceRef, Span, Trace,
    iso_millis, normalise_severity, TraceSummary,
)
from .aggregation import AggregationResult, Bucket, DateHistogram, Terms
from .query import LogQuery, TimeWindow, TraceQuery, SORT_RECENT, SORT_SLOWEST
from .scope import Scope, ScopeViolation
from .fanout import FanOutLogSource, FanOutTraceSource
from .source import Capability, LogSource, Source, TraceSource

logger = logging.getLogger(__name__)

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

    Sources come from two places, and the difference is why this class has a
    reload at all:

      * the BASE set — what WDash registers itself: the store's own agents,
        as `wdash-agents`. It cannot change while the process runs, so it is
        registered once and never rebuilt. (An Elasticsearch declared in the
        environment used to be registered here too, ahead of everything
        stored; a cluster is a stored source now.)
      * the CONFIGURATION PAGE. These change whenever an administrator saves
        the form, in a worker that may not be this one, and until this existed
        the page said "restart WDash for it to be used for queries" — the
        configuration screen refusing to configure anything.

    So the second set is held apart and swapped as a unit. `reload_with` says
    how to rebuild it and how to tell whether it needs rebuilding; without one
    a Hub behaves exactly as it did before, which is what every test that
    builds sources by hand relies on.
    """

    #: How long a process may go on trusting the sources it holds without
    #: asking the store whether they changed. The question is one small query;
    #: this stops it being one per request.
    #:
    #: It is also the honest answer to "how long until my new source works on
    #: the other workers", and it is short enough to be the same answer as
    #: "immediately" to somebody who saved a form and reached for the tab.
    RELOAD_TTL = 5.0

    def __init__(self):
        self._logs = {}
        self._traces = {}
        self._monitors = {}
        # The configured layer, kept apart from the three above.
        self._configured = {"logs": {}, "traces": {}, "monitors": {}}
        # {name: why} for a stored source that is NOT live — it could not be
        # built, or its name is one of the base ones. Kept because the page
        # that saved it has to be able to say so; a source that silently does
        # not exist looks exactly like a source with no data.
        self._failures = {}
        self._shadowed = {}
        self._build = None
        self._stamp_of = None
        self._stamp = None
        self._checked_at = 0.0
        self._lock = threading.Lock()

    def add_logs(self, source):
        self._logs[source.name] = source
        return source

    def add_traces(self, source):
        self._traces[source.name] = source
        return source

    def add_monitors(self, source):
        self._monitors[source.name] = source
        return source

    # ---------- the configured layer ----------

    def reload_with(self, build, stamp):
        """Teach this hub to rebuild its configured sources.

        `build()` returns {"logs": [...], "traces": [...], "monitors": [...]}.
        `stamp()` returns any comparable value that changes when the stored
        sources do — it is called often and must be cheap.

        Loads once, now, so a hub that has been given a builder is never
        briefly missing the sources an operator configured.
        """
        self._build = build
        self._stamp_of = stamp
        self.reload()

    def reload(self):
        """Rebuild the configured sources now. Returns how many there are.

        Called directly by the configuration page, so the worker that handled
        the save is correct before it renders the next screen; every other
        worker notices within `RELOAD_TTL`.
        """
        if self._build is None:
            return 0
        try:
            stamp = self._stamp_of() if self._stamp_of else None
            built = self._build()
        except Exception:
            # The sources already loaded keep working. A store that cannot be
            # read right now is a reason to go on serving the last good
            # picture, not to take every configured source away — the same
            # rule the role resolver follows.
            logger.exception("Could not reload the configured sources")
            return sum(len(group) for group in self._configured.values())

        swapped = {}
        for signal in ("logs", "traces", "monitors"):
            registry = {}
            for source in built.get(signal, ()):
                # Two sources of one name in one signal: the second one wins
                # the key and the first is never asked again. The store
                # refuses this now, but a store that already had it — or one
                # edited directly — must not have it silently.
                shadowed = registry.get(source.name)
                if shadowed is not None:
                    logger.warning(
                        "Two %s sources are called %r (%s and %s). Only one "
                        "can be reached under that name: %s is being kept "
                        "and the other answers nothing, including in the "
                        "'*' fan-out. Rename one of them.",
                        signal, source.name, type(shadowed).__name__,
                        type(source).__name__, type(source).__name__)
                registry[source.name] = source
            swapped[signal] = registry
        failures = dict(built.get("failures") or {})
        with self._lock:
            # Swapped whole, never mutated in place: a search that is reading
            # `log_sources` while this runs gets the old set or the new one,
            # and not half of each.
            #
            # The replaced sources are NOT closed. Something may be mid-query
            # against one, and closing a client out from under a request in
            # flight turns somebody else's configuration edit into a failed
            # search. They are released when the last reference goes.
            self._configured = swapped
            self._failures = failures
            # Recomputed by the next read against the base names as they
            # stand then, so a stale entry cannot outlive the row it was
            # about.
            self._shadowed = {}
            self._stamp = stamp
            self._checked_at = time.monotonic()
        return sum(len(group) for group in swapped.values())

    @property
    def configured_count(self):
        """How many sources came from the configuration page."""
        with self._lock:
            return sum(len(group) for group in self._configured.values())

    @property
    def rebuilds_from_store(self):
        """Whether this hub knows how to rebuild its configured sources.

        False for a hub assembled by hand — every test that calls
        `replace_all`, and any caller that has not used `reload_with`. For
        one of those `reload()` is a no-op that returns 0, which is not the
        same statement as "the source you just saved could not be built", and
        anything reporting on a save has to tell the two apart.
        """
        return self._build is not None

    @property
    def source_failures(self):
        """{name: why} for every stored source that is not answering queries.

        Two ways to be on this list: the row could not be built at all (a
        credential that will not decrypt, a URL the adapter refuses), or its
        name is one WDash registers itself, so the base source keeps it and
        this one is unreachable. Both used to be a line in the log, under a
        screen that said the source was in use.
        """
        # Asked the store first, like every other liveness read on this class.
        # The configuration page touches the hub through this property and
        # nothing else, so without it the page never checked whether the
        # sources had changed: a worker that had served no query since the
        # save listed the row with no badge and no warning — a failure
        # looking exactly like ordinary data, on the one screen whose job is
        # to say otherwise.
        self._fresh()
        # Touched so a name that collides is noticed even when nothing has
        # read that signal's registry yet.
        for kind in ("logs", "traces", "monitors"):
            self._registry(kind)
        with self._lock:
            return {**self._failures, **self._shadowed}

    def _fresh(self):
        """Reload if the store says the configured sources have changed.

        Asked before every read, and almost always answered from the clock:
        the store is consulted once per `RELOAD_TTL`, and a rebuild only
        happens when the stamp has actually moved.
        """
        if self._build is None:
            return
        now = time.monotonic()
        with self._lock:
            if (now - self._checked_at) < self.RELOAD_TTL:
                return
            # Stamped before the query rather than after, so a store that is
            # slow or down is asked once per TTL and not once per request.
            self._checked_at = now
            known = self._stamp
        try:
            current = self._stamp_of() if self._stamp_of else None
        except Exception:
            logger.exception("Could not check whether the sources changed")
            return
        if current != known:
            self.reload()

    def _registry(self, kind):
        """One signal's sources: the base ones first, then the configured.

        Order is the interface. `logs()` with no name returns the first, so
        the configured sources keep the order they were created in, and an
        operator adding a source on the configuration page does not silently
        take over every query that names no source.

        A configured source whose NAME is a base one does not replace it.
        `{**base, **configured}` kept the key's position and swapped the
        value, so a stored source called by a base name took the base source
        out of the registry entirely and answered every query that named it
        — the guarantee this method's first paragraph makes, broken by the
        one thing it does not look at. The base source stays; the configured
        one is recorded as shadowed, which is how the configuration page
        comes to say so.
        """
        with self._lock:
            configured = self._configured[kind]
        base = {"logs": self._logs, "traces": self._traces,
                "monitors": self._monitors}[kind]
        collisions = [name for name in configured if name in base]
        if not collisions:
            return {**base, **configured}
        self._note_shadowed(kind, collisions)
        return {**base, **{name: source for name, source in configured.items()
                           if name not in base}}

    def _note_shadowed(self, kind, names):
        """Record — and say once — that a configured name is already taken."""
        fresh = []
        with self._lock:
            for name in names:
                if name not in self._shadowed:
                    self._shadowed[name] = (
                        f"'{name}' is the name of the {kind} source WDash "
                        f"registers itself. That one is still answering; "
                        f"this row is not. Rename it.")
                    fresh.append(name)
        for name in fresh:
            logger.warning(
                "Configured source '%s' is shadowed by the %s source of the "
                "same name WDash registers itself, and is not in use.",
                name, kind)

    def replace_all(self, logs=(), traces=(), monitors=()):
        """Swap every registered source out.

        For tests that assert on what a scope reaches. The app factory
        registers the store's own monitor source and whatever is stored, and
        a test that asks what a scope reaches must not inherit either: it
        declares the sources it depends on, and the assertion is about the
        scope again.
        """
        self._logs = {source.name: source for source in logs}
        self._traces = {source.name: source for source in traces}
        self._monitors = {source.name: source for source in monitors}
        # Including the configured layer, and the reloader that would put it
        # back. "Swap every registered source out" has to mean every one, or
        # a test that asks what a scope reaches gets its own sources plus
        # whatever the machine it runs on happens to have configured.
        with self._lock:
            self._configured = {"logs": {}, "traces": {}, "monitors": {}}
            self._failures = {}
            self._shadowed = {}
            self._build = None
            self._stamp_of = None

    #: Reserved name for "search everything". Not a registered source, so it
    #: cannot collide with one an operator configures.
    ALL_SOURCES = "*"

    def base_source_names(self):
        """Names WDash registers itself — the store's own agents, and
        nothing else now that no source comes from the environment.

        For the repository, which refuses them: a configured source called
        one of these is stored, shown on the page and reachable by nothing,
        because the base source keeps the name. Told at the form, that is a
        sentence about what to type; found later, it is a source that exists
        and answers nothing.
        """
        return frozenset(self._logs) | frozenset(self._traces) \
            | frozenset(self._monitors)

    def logs(self, name=None):
        """One log source, or the fan-out over all of them.

        `name="*"` asks for every source at once. With a single source that is
        the source itself rather than a wrapper: a fan-out of one adds a thread
        pool, an intersection and a merge to answer a question one object
        already answers.
        """
        self._fresh()
        if name == self.ALL_SOURCES:
            sources = self.log_sources
            if not sources:
                return None
            if len(sources) == 1:
                return sources[0]
            from .fanout import FanOutLogSource, FanOutTraceSource
            return FanOutLogSource(sources)
        return self._pick(self._registry("logs"), name, "log")

    def traces(self, name=None):
        """One trace source, or the fan-out over all of them.

        Same shape as `logs`. Without this, a second trace source registered
        from the configuration page was reachable by nothing: it appeared in
        the source list, the health check probed it, and every query went to
        whichever one happened to be first. Registered and unreachable is
        worse than absent — the page says it is there.
        """
        self._fresh()
        if name == self.ALL_SOURCES:
            sources = self.trace_sources
            if not sources:
                return None
            if len(sources) == 1:
                return sources[0]
            from .fanout import FanOutTraceSource
            return FanOutTraceSource(sources)
        return self._pick(self._registry("traces"), name, "trace")

    def monitors(self, name=None):
        """One monitor source, or the fan-out over all of them.

        Same shape as `logs` and `traces`. A deployment can easily have two:
        Heartbeat writing to the production cluster and a second agent
        watching from another region, which is the whole point of running
        checks from outside.
        """
        self._fresh()
        if name == self.ALL_SOURCES:
            sources = self.monitor_sources
            if not sources:
                return None
            if len(sources) == 1:
                return sources[0]
            from .fanout import FanOutMonitorSource
            return FanOutMonitorSource(sources)
        return self._pick(self._registry("monitors"), name, "monitor")

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
        self._fresh()
        return list(self._registry("logs").values())

    @property
    def trace_sources(self):
        self._fresh()
        return list(self._registry("traces").values())

    @property
    def monitor_sources(self):
        self._fresh()
        return list(self._registry("monitors").values())

    def _all(self):
        """Every registered source, once each.

        Deduplicated by identity: one configured Elasticsearch serving logs,
        traces and monitors is three adapters, but two adapters sharing a name
        would otherwise report health twice under the same key and the second
        would silently win.
        """
        seen, out = set(), []
        for kind in ("logs", "traces", "monitors"):
            for source in self._registry(kind).values():
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
