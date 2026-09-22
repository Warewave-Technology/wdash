"""
Source interfaces.

Every method REQUIRES a `scope`. That follows directly from Basic-licence
Elasticsearch having no document-level security: if authorization lives
entirely in the application, it must be impossible to forget. Making scope
optional would mean "one day somebody forgets"; making it required turns
forgetting into a call error.
"""

from abc import ABC, abstractmethod


class Capability:
    """What a source is able to do.

    No backend does everything. The UI consults this so it does not offer a
    feature the backend cannot serve — the point of the hub is to make
    differences visible, not to hide them.
    """
    SEARCH = "search"
    FIELD_STATS = "field_stats"
    CONTEXT = "context"          # records surrounding a given record
    HISTOGRAM = "histogram"
    RAW_DOCUMENT = "raw_document"   # the stored document, backend-shaped
    AGGREGATION = "aggregation"
    TRACE_LOOKUP = "trace_lookup"
    TRACE_SEARCH = "trace_search"
    SERVICE_LIST = "service_list"
    LOG_TRACE_CORRELATION = "log_trace_correlation"
    MONITOR_LIST = "monitor_list"          # current state of every monitor
    MONITOR_HISTORY = "monitor_history"    # past checks for one monitor
    TLS_CERTIFICATES = "tls_certificates"  # what the monitors saw on the wire


class Source(ABC):
    """Common base for every source."""

    #: Name shown to the user
    name = "unnamed"
    #: Backend type — must match SourceRef.backend
    backend = "unknown"

    @property
    def capabilities(self):
        return frozenset()

    def supports(self, capability):
        return capability in self.capabilities

    @abstractmethod
    def health(self):
        """Return (healthy, detail)."""

    @abstractmethod
    def containers(self, scope):
        """Containers (indices, streams) the scope can reach."""


class LogSource(Source):
    @abstractmethod
    def search(self, query, scope):
        """LogQuery -> LogPage"""

    @abstractmethod
    def fetch(self, ref, scope):
        """Fetch one record with all its fields, or None."""

    def raw(self, ref, scope):
        """The stored document exactly as the backend holds it, or None.

        This is the ONE place the neutral model is deliberately bypassed, and
        it is declared rather than leaked. The reason is diagnostic: `fetch`
        returns what WDash understood, and when a field is missing the question
        is always "is it absent, or did we fail to map it?". Only the raw
        document answers that, and without it the answer is a shell on the
        Elasticsearch host.

        Callers must treat the result as opaque and display-only: its shape is
        the backend's, it varies between backends, and nothing in WDash may
        branch on it. Optional.
        """
        raise NotImplementedError(f"{self.name} does not expose raw documents")

    def field_stats(self, query, scope, fields=None, top=10):
        """Field distributions in the current query context. Optional.

        `fields` is a {shown name: path to aggregate} map, from
        `stats_fields` narrowed to somebody's choice. None means the
        source picks, which is what it did before anybody could choose.
        """
        raise NotImplementedError(f"{self.name} does not support field statistics")

    def stats_fields(self, scope, matching=None):
        """Every field `field_stats` COULD report on here. Optional.

        `matching` narrows by substring, and narrows BEFORE any cut: the
        answer is a search of the whole mapping rather than of the first
        page of it.

        What the sidebar's picker offers, and a different question from
        `field_stats` itself: that one answers about ten fields in a query
        context, this one about the whole mapping with no query at all.
        A source that reports field statistics at all can answer it.

        A `PartialList`, because the honest answer on a cluster with a
        thousand dynamic fields is a cut one that says it was cut.
        """
        raise NotImplementedError(f"{self.name} does not list its fields")

    def resolve_stats_fields(self, scope, names):
        """{name: what to aggregate it on} for the names still mapped here.

        Separate from `stats_fields` for two reasons, and each of them was
        a fault before it was a method.

        The list is CUT and this is not: resolving against the first three
        hundred names reported every chosen field past the cut as one the
        cluster had lost — four of them, on a screen that then said so.

        And what a field is called is not always what an aggregation runs
        on: a `text` field with a `keyword` sub-field is counted on the
        sub-field, so passing the name through would have asked
        Elasticsearch to aggregate on analysed text, which it refuses.
        """
        raise NotImplementedError(f"{self.name} does not resolve its fields")

    def group_by_fields(self, scope, window=None):
        """Neutral field names a panel may GROUP BY here. Optional.

        Distinct from `field_stats`, which describes VALUES in a query
        context. This answers the editor's question — "what can I put on the
        x axis of a panel against this source" — and the answer is the
        backend's, not a constant: Elasticsearch groups by any mapped keyword
        or number, Loki only by a stream LABEL, VictoriaLogs by any field the
        records carry.

        ADVISORY, and that word is the contract. Nothing validates a stored
        panel against this list: `panels.normalise_all` runs on every READ of
        a dashboard, so a source that has changed, or one that is briefly
        down, would turn a stale field name into a 400 for the WHOLE board
        rather than one panel. A field this list does not hold is refused by
        the source that cannot answer it, as one panel carrying the reason —
        `AggregationResult.notes`.

        Scoped, like everything else here: the names come from the containers
        the scope reaches, so a label that exists only in a stream the caller
        may not read is not disclosed by the editor's select.
        """
        raise NotImplementedError(
            f"{self.name} does not list the fields it can group by")

    def context(self, ref, scope, before=10, after=10, correlate_by=None):
        """Records surrounding a given record. Optional."""
        raise NotImplementedError(f"{self.name} does not support context view")

    def histogram(self, query, scope):
        """Time series bucket counts. Optional."""
        raise NotImplementedError(f"{self.name} does not support histograms")

    def aggregate(self, query, aggregations, scope):
        """Run several aggregations in a SINGLE request.

        Dashboard panels ask for different aggregations over the same query;
        issuing one request per panel wastes backend capacity. Optional.
        """
        raise NotImplementedError(f"{self.name} does not support aggregation")

    def multi_aggregate(self, requests, scope):
        """Run several (query, aggregations) pairs in one round trip.

        Comparing a window with the one before it needs two different queries,
        which `aggregate` cannot express. Issuing them separately would double
        the round trips for what a backend can answer in a single batch.

        `requests` is a sequence of (LogQuery, aggregations). Returns one
        AggregationResult per request, in order.
        """
        return [self.aggregate(query, aggs, scope) for query, aggs in requests]


class TraceSource(Source):
    @abstractmethod
    def trace(self, trace_id, window, scope):
        """Fetch one trace with all its spans, or None."""

    @abstractmethod
    def services(self, window, scope):
        """Services observed within the window."""

    def search(self, query, scope):
        """TraceQuery -> trace summaries. Optional."""
        raise NotImplementedError(f"{self.name} does not support trace search")


class MonitorSource(Source):
    """Synthetic monitors: is this reachable from outside?

    A third signal alongside logs and traces, because it answers a question
    neither of them can. An application that has stopped serving requests
    writes no logs and emits no spans, so both of those go quiet — which looks
    exactly like a quiet night. Only something probing from outside can tell
    the difference between "nothing is happening" and "nothing can happen".

    TLS is part of this rather than its own signal: the certificate is
    something a monitor observes while checking, not a separate act of
    measurement. Splitting it would mean two sources probing the same endpoint
    and two answers to one question.
    """

    @abstractmethod
    def monitors(self, window, scope):
        """The latest state of every monitor -> MonitorPage."""

    def history(self, monitor_id, window, scope):
        """Past checks for one monitor -> [MonitorCheck], newest last.

        Optional: a backend that keeps only the current state can serve
        MONITOR_LIST without this. Declare MONITOR_HISTORY only if it works.

        Raises MonitorSourceError when the backend cannot answer. An empty
        list is "no check in this window", and a backend that is down has
        not said that.
        """
        raise NotImplementedError(
            f"{self.name} does not keep monitor history.")

    def certificates(self, window, scope):
        """TLS certificates seen -> [Monitor] carrying a certificate.

        Returns monitors rather than bare certificates so the page can say
        WHICH endpoint each one belongs to. A certificate with no endpoint
        attached is a fingerprint nobody can act on.
        """
        raise NotImplementedError(
            f"{self.name} does not report TLS certificates.")


class MonitorSourceError(RuntimeError):
    """A monitor backend could not answer a history or a chart.

    Raised rather than answered with an empty list, and worded for a person:
    the message is shown on the page, after the name of the source.
    """
