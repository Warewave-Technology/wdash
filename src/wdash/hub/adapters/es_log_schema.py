"""
Reading a log document, whatever wrote it.

The trace side has had a schema layer since OpenTelemetry and Elastic APM
turned out to disagree about everything. The log side did not, and read one
hardcoded shape: `message`, `level`, `service`, with resource keys sitting at
the top level.

That shape is what WDash's own lab seeder wrote. It is not what the
OpenTelemetry Collector writes, which is:

    body_text                        the message
    severity_text / severity_number  the level
    resource.attributes.service.name the service

Reading collector output with the old mapping produced records with an empty
body, an unknown severity and no service — every field a person actually looks
at. The failure was invisible because the seeder and the reader had been
written from the same assumption and agreed with each other.

So: detect, then map. Same idea as the trace schemas, same reason.
"""

from ..models import LogRecord, SourceRef, normalise_severity
from .es_trace_schema import dig, parse_time

#: Fields the flat schema maps onto the model. Everything else is an attribute.
_FLAT_MAPPED = {"@timestamp", "message", "level", "service", "trace_id", "span_id"}
_FLAT_RESOURCE = ("host", "environment", "container", "pod", "namespace")

#: Fields the OTel schema consumes. `scope` and the dropped_* counters are
#: collector bookkeeping and would be noise in the attribute list.
_OTEL_CONSUMED = {
    "@timestamp", "observed_timestamp", "body_text", "body", "severity_text",
    "severity_number", "resource", "scope", "attributes", "trace_id",
    "span_id", "trace_flags", "dropped_attributes_count",
}

#: OTel SeverityNumber ranges. The number is authoritative; the text is
#: whatever the application chose to call it, and applications choose badly.
_SEVERITY_NUMBERS = (
    (1, 4, "TRACE"), (5, 8, "DEBUG"), (9, 12, "INFO"),
    (13, 16, "WARN"), (17, 20, "ERROR"), (21, 24, "FATAL"),
)


def severity_from_number(number):
    try:
        number = int(number)
    except (TypeError, ValueError):
        return None
    for low, high, name in _SEVERITY_NUMBERS:
        if low <= number <= high:
            return name
    return None


class LogSchema:
    """Turns one Elasticsearch hit into a LogRecord."""

    name = "unknown"

    @classmethod
    def detect(cls, properties):
        raise NotImplementedError

    def to_record(self, hit, backend, source_name=None):
        raise NotImplementedError

    @staticmethod
    def _ref(hit, backend):
        return SourceRef(backend=backend, container=hit.get("_index", ""),
                         id=hit.get("_id", ""))


class OtelLogSchema(LogSchema):
    """What the OpenTelemetry Collector's Elasticsearch exporter writes."""

    name = "otel"
    body_field = "body_text"
    severity_field = "severity_text"
    service_field = "resource.attributes.service.name"

    @classmethod
    def detect(cls, properties):
        return "body_text" in properties or "severity_number" in properties

    def to_record(self, hit, backend, source_name=None):
        source = hit.get("_source") or {}
        resource = source.get("resource") or {}
        attributes = resource.get("attributes")
        resource_attributes = attributes if isinstance(attributes, dict) else resource

        body = source.get("body_text")
        if body is None:
            # `body` is a map for structured bodies; render it rather than
            # showing nothing, because an empty row is indistinguishable from
            # a record that genuinely has no message.
            raw = source.get("body")
            body = raw if isinstance(raw, str) else ("" if raw is None else str(raw))

        # The number wins: severity_text is free-form and applications use it
        # for things like "notice" and "problem".
        severity = (severity_from_number(source.get("severity_number"))
                    or normalise_severity(source.get("severity_text")))

        return LogRecord(
            timestamp=parse_time(source.get("@timestamp")),
            body=body or "",
            severity=severity,
            severity_text=str(source.get("severity_text") or ""),
            service=dig(resource_attributes, "service.name", "") or "",
            resource={k: v for k, v in resource_attributes.items()
                      if k != "service.name"},
            attributes=dict(source.get("attributes") or {}),
            trace_id=source.get("trace_id"),
            span_id=source.get("span_id"),
            ref=self._ref(hit, backend),
            source=source_name,
        )


class FlatLogSchema(LogSchema):
    """One document, one level of keys: `message`, `level`, `service`.

    What most existing shippers produce, and the default when nothing more
    specific matches. Kept as the fallback rather than the assumption.
    """

    name = "flat"
    body_field = "message"
    severity_field = "level"
    service_field = "service"

    @classmethod
    def detect(cls, properties):
        return "message" in properties or "level" in properties

    def to_record(self, hit, backend, source_name=None):
        source = hit.get("_source") or {}
        resource = {key: source[key] for key in _FLAT_RESOURCE if key in source}
        attributes = {k: v for k, v in source.items()
                      if k not in _FLAT_MAPPED and k not in resource}

        return LogRecord(
            timestamp=parse_time(source.get("@timestamp")),
            body=source.get("message") or "",
            severity=normalise_severity(source.get("level")),
            severity_text=str(source.get("level") or ""),
            service=source.get("service") or "",
            resource=resource,
            attributes=attributes,
            trace_id=source.get("trace_id"),
            span_id=source.get("span_id"),
            ref=self._ref(hit, backend),
            source=source_name,
        )


#: Order matters: OTel is checked first because a collector-written index has
#: neither `message` nor `level`, while a flat index has neither `body_text`
#: nor `severity_number`. The two are cleanly distinguishable.
SCHEMAS = (OtelLogSchema, FlatLogSchema)


def detect_schema(properties):
    """Pick a schema from an index's mapping, or None if nothing matches."""
    if not properties:
        return None
    for schema in SCHEMAS:
        if schema.detect(properties):
            return schema()
    return None


def schema_for_document(source):
    """Pick a schema from a document, for the single-record fetch path.

    A `get` by id returns no mapping, and fetching one would cost a round trip
    to answer a question the document itself already answers.
    """
    if not isinstance(source, dict):
        return FlatLogSchema()
    if "body_text" in source or "severity_number" in source:
        return OtelLogSchema()
    return FlatLogSchema()


#: Where each neutral field lives, per schema, in preference order.
#:
#: Ordered so the flat shape is tried first — it is what most existing
#: deployments have — and the collector's names are the fallback. Resolution
#: checks the actual mapping, so the order only decides ties.
FIELD_CANDIDATES = {
    "timestamp": ("@timestamp",),
    "body": ("message", "body_text"),
    "severity": ("level", "severity_text"),
    "severity_text": ("level", "severity_text"),
    "service": ("service", "resource.attributes.service.name",
                "resource.service.name"),
    "host": ("host", "resource.attributes.host.name"),
    "environment": ("environment",
                    "resource.attributes.deployment.environment"),
    "trace_id": ("trace_id",),
    "span_id": ("span_id",),
}


def field_candidates(neutral_name):
    """Every backend field a neutral name might live in."""
    return FIELD_CANDIDATES.get(neutral_name, (neutral_name,))
