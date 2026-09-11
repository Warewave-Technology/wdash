"""
Trace schema adapters.

A single Elasticsearch cluster commonly holds more than one trace schema: the
semantic-convention documents written by an OpenTelemetry Collector, and the
ECS-shaped documents written by Elastic APM. Both carry spans, but their field
names are entirely different.

Schema knowledge stays HERE. The rest of the hub only ever sees `Span` and does
not know — and must not know — which schema it came from. Adding a third schema
means adding a class to this file; nothing else changes.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from ..models import STATUS_ERROR, STATUS_OK, STATUS_UNSET, Span, SourceRef


def dig(source, dotted, default=None):
    """Read a value from a nested dict using a dotted path.

    Elasticsearch documents may carry the same field nested
    ('service': {'name': x}) or flattened ('service.name': x); both are tried.
    """
    if dotted in source:
        return source[dotted]
    current = source
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def parse_time(value):
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


class SpanSchema(ABC):
    """Strategy that converts one trace schema into the neutral Span model.

    It also says how to ASK for spans in that schema — which are entry spans,
    which failed, how long one took. Those clauses lived in the search, a
    file away from the reader, and when the reader was corrected to what the
    collector writes they were not: the search went on asking for field
    names nothing writes. Beside the reader, the two are one change.
    """

    name = "unknown"

    #: Field to use for a term query on the trace id
    trace_id_field = "trace_id"
    #: Field to use for a terms aggregation on the service name
    service_field = "service.name"
    timestamp_field = "@timestamp"
    #: Field holding the parent's span id; absent on a root span.
    parent_field = "parent_span_id"

    @classmethod
    def for_mapping(cls, properties):
        """An instance suited to ONE index's mapping.

        A schema can read more than one spelling of the same field, and an
        index maps one of them. Which one it maps decides how that index can
        be sorted, so it is settled here, per index, rather than guessed once
        per query.
        """
        return cls()

    @property
    def group_key(self):
        """What makes two indices searchable in ONE request.

        The class alone was the key. Two indices of the same schema with
        different field spellings then shared a request — and a sort names a
        field: Elasticsearch puts every document that does not have it last,
        whatever its value. So one spelling outranked the other however slow
        it was, and the limit cut the rest out.
        """
        return type(self)

    @classmethod
    @abstractmethod
    def detect(cls, properties):
        """Decide from the index mapping whether this schema applies."""

    @abstractmethod
    def to_span(self, hit):
        """Elasticsearch hit -> Span, or None if it cannot be resolved."""

    @abstractmethod
    def entry_filter(self):
        """A clause for spans that are work a service handled."""

    @abstractmethod
    def error_filter(self):
        """A clause for spans that failed."""

    @abstractmethod
    def duration_filter(self, minimum_us):
        """A clause for spans that took at least `minimum_us`."""

    @abstractmethod
    def slowest_first(self):
        """A sort putting the longest spans first."""

    def _ref(self, hit):
        return SourceRef(backend="elasticsearch",
                         container=hit.get("_index", ""),
                         id=hit.get("_id", ""))


class OtelSpanSchema(SpanSchema):
    """OpenTelemetry semantic conventions.

    Two document shapes, because the ecosystem emits two. What the OpenTelemetry
    Collector's Elasticsearch exporter actually writes in `mapping.mode: otel`
    is:

        duration              nanoseconds
        kind                  "Client"
        status.code           "Ok" / "Error"
        resource.attributes.service.name

    An earlier version of this schema read `duration_ns`, `SPAN_KIND_CLIENT`,
    `status_code` and `resource.service.name` — none of which the collector
    produces. Every field that mattered came back empty: services blank,
    durations zero, statuses unset. It was written against a fixture that had
    itself been written against an assumption, so the two agreed with each
    other and with nothing else. Running a real collector in the lab is what
    surfaced it.

    Both are read, so a store written by an older pipeline keeps working.

    The search clauses below ask in the collector's spelling first. Measured
    by pushing OTLP through the lab's collector (0.109.0) and reading back
    what landed: `kind` is "Server", "Client", "Internal", "Producer",
    "Consumer" or "Unspecified"; `status.code` is "Ok", "Error" or "Unset";
    `duration` is nanoseconds; a root span has no `parent_span_id` at all.
    The older spelling is asked for beside it, because `to_span` reads it —
    except in the SORT, which can only name one field. Asking for both there
    ranks by which spelling an index uses rather than by duration, so
    `for_mapping` settles it per index and `group_key` keeps the two
    spellings out of a single request.
    """

    name = "otel"
    trace_id_field = "trace_id"
    service_field = "resource.attributes.service.name"

    def __init__(self, duration_field="duration"):
        #: The duration field THIS index maps: what the collector writes, or
        #: the older `duration_ns`.
        self.duration_field = duration_field

    @classmethod
    def for_mapping(cls, properties):
        properties = properties or {}
        if "duration" not in properties and "duration_ns" in properties:
            return cls(duration_field="duration_ns")
        return cls()

    @property
    def group_key(self):
        return (type(self), self.duration_field)

    #: Fields only a log record has. A collector writes `trace_id` and
    #: `span_id` onto a log record made inside a span, so the ids alone said
    #: "spans" of a log index — and the service list counted its records.
    LOG_FIELDS = ("body_text", "body_structured", "severity_number",
                  "severity_text")

    @classmethod
    def detect(cls, properties):
        """Ids, a kind and a duration, which no log record carries; and none
        of the fields only a log record carries, so an index holding both
        signals is not read as spans."""
        if any(name in properties for name in cls.LOG_FIELDS):
            return False
        return ("trace_id" in properties and "span_id" in properties
                and "kind" in properties
                and ("duration" in properties or "duration_ns" in properties))

    def entry_filter(self):
        return {"terms": {"kind": ["Server", "SPAN_KIND_SERVER"]}}

    def error_filter(self):
        return {"bool": {"should": [{"term": {"status.code": "Error"}},
                                    {"term": {"status_code": "ERROR"}}],
                         "minimum_should_match": 1}}

    def duration_filter(self, minimum_us):
        nanoseconds = int(minimum_us) * 1000
        return {"bool": {"should": [{"range": {"duration": {"gte": nanoseconds}}},
                                    {"range": {"duration_ns": {"gte": nanoseconds}}}],
                         "minimum_should_match": 1}}

    def slowest_first(self):
        # ONE field: the one this index maps. Sorting on both put every
        # document missing the first of them last whatever its duration —
        # Elasticsearch's `missing: _last` default — so a source holding an
        # index of each spelling ranked every collector-shaped span above
        # every older one, and the limit cut the genuinely slowest traces
        # out. `unmapped_type` still covers an index that maps neither.
        return [{self.duration_field: {"order": "desc", "unmapped_type": "long"}}]

    def to_span(self, hit):
        source = hit.get("_source") or {}
        trace_id = source.get("trace_id")
        span_id = source.get("span_id")
        if not trace_id or not span_id:
            return None

        resource = source.get("resource") or {}
        # The collector nests everything under resource.attributes; older
        # writers put the keys straight on resource.
        attributes = resource.get("attributes")
        resource_attributes = attributes if isinstance(attributes, dict) else resource

        # "SPAN_KIND_CLIENT" and "Client" mean the same thing.
        kind = str(source.get("kind") or "INTERNAL")
        kind = kind.replace("SPAN_KIND_", "").upper()

        status = source.get("status")
        status_raw = (status.get("code") if isinstance(status, dict)
                      else source.get("status_code"))
        status = {"OK": STATUS_OK, "ERROR": STATUS_ERROR}.get(
            str(status_raw or "").upper(), STATUS_UNSET)

        # `duration` is what the collector writes; `duration_ns` is the older
        # name. Both are nanoseconds.
        duration_ns = source.get("duration")
        if duration_ns is None:
            duration_ns = source.get("duration_ns") or 0

        return Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=source.get("parent_span_id") or None,
            name=source.get("name") or "",
            service=dig(resource_attributes, "service.name", "") or "",
            start=parse_time(source.get("@timestamp")),
            duration_us=int(int(duration_ns) // 1000),
            kind=kind,
            status=status,
            resource=dict(resource_attributes),
            attributes=dict(source.get("attributes") or {}),
            ref=self._ref(hit),
        )


class ApmSpanSchema(SpanSchema):
    """Elastic APM / ECS shape.

    In this schema a transaction and a span are distinct document types: a
    transaction is a request a service handled, a span is work done inside that
    request. Both become a Span in the neutral model — the distinction is kept
    in the `kind` field.
    """

    name = "apm"
    trace_id_field = "trace.id"
    service_field = "service.name"
    parent_field = "parent.id"

    @classmethod
    def detect(cls, properties):
        trace = properties.get("trace") or {}
        has_trace_id = "id" in (trace.get("properties") or {})
        return has_trace_id and ("transaction" in properties or "processor" in properties)

    def entry_filter(self):
        return {"term": {"processor.event": "transaction"}}

    def error_filter(self):
        return {"term": {"event.outcome": "failure"}}

    def duration_filter(self, minimum_us):
        return {"range": {"transaction.duration.us": {"gte": minimum_us}}}

    def slowest_first(self):
        return [{"transaction.duration.us": {"order": "desc"}}]

    def to_span(self, hit):
        source = hit.get("_source") or {}
        trace_id = dig(source, "trace.id")
        if not trace_id:
            return None

        is_transaction = dig(source, "processor.event") == "transaction"
        prefix = "transaction" if is_transaction else "span"

        span_id = dig(source, f"{prefix}.id")
        if not span_id:
            return None

        outcome = str(dig(source, "event.outcome") or "").lower()
        status = {"success": STATUS_OK, "failure": STATUS_ERROR}.get(outcome, STATUS_UNSET)

        service = dig(source, "service.name", "") or ""
        resource = {
            "service.name": service,
            "service.version": dig(source, "service.version"),
            "deployment.environment": dig(source, "service.environment"),
        }

        attributes = {}
        for key in ("type", "subtype"):
            value = dig(source, f"{prefix}.{key}")
            if value:
                attributes[f"{prefix}.{key}"] = value

        return Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=dig(source, "parent.id") or None,
            name=dig(source, f"{prefix}.name", "") or "",
            service=service,
            start=parse_time(source.get("@timestamp")),
            duration_us=int(dig(source, f"{prefix}.duration.us") or 0),
            # In APM a transaction is always an inbound request (SERVER) and a
            # span is an outbound call (CLIENT).
            kind="SERVER" if is_transaction else "CLIENT",
            status=status,
            resource={k: v for k, v in resource.items() if v},
            attributes=attributes,
            ref=self._ref(hit),
        )


#: Order matters: OTel has the more specific signature, so it is tried first
SCHEMAS = (OtelSpanSchema, ApmSpanSchema)


def detect_schema(properties):
    """Pick the matching schema strategy from an index mapping, or None."""
    for schema_cls in SCHEMAS:
        if schema_cls.detect(properties or {}):
            return schema_cls.for_mapping(properties or {})
    return None
