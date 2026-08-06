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
    """Strategy that converts one trace schema into the neutral Span model."""

    name = "unknown"

    #: Field to use for a term query on the trace id
    trace_id_field = "trace_id"
    #: Field to use for a terms aggregation on the service name
    service_field = "service.name"
    timestamp_field = "@timestamp"

    @classmethod
    @abstractmethod
    def detect(cls, properties):
        """Decide from the index mapping whether this schema applies."""

    @abstractmethod
    def to_span(self, hit):
        """Elasticsearch hit -> Span, or None if it cannot be resolved."""

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
    """

    name = "otel"
    trace_id_field = "trace_id"
    service_field = "resource.attributes.service.name"

    @classmethod
    def detect(cls, properties):
        return "trace_id" in properties and "span_id" in properties

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

    @classmethod
    def detect(cls, properties):
        trace = properties.get("trace") or {}
        has_trace_id = "id" in (trace.get("properties") or {})
        return has_trace_id and ("transaction" in properties or "processor" in properties)

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
            return schema_cls()
    return None
