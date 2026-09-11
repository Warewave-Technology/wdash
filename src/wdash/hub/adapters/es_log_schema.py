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

import json

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

#: Either of these and a document is the collector's. It writes a string body
#: as `body_text` and a map as `body_structured`, never both, and leaves
#: `severity_text` out when the application sent none — but it always writes
#: `severity_number`, 0 when none was sent (measured on the lab's collector).
_OTEL_MARKERS = ("body_text", "severity_number")

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
        return any(name in properties for name in _OTEL_MARKERS)

    def to_record(self, hit, backend, source_name=None):
        source = hit.get("_source") or {}
        resource = source.get("resource") or {}
        attributes = resource.get("attributes")
        resource_attributes = attributes if isinstance(attributes, dict) else resource

        body = source.get("body_text")
        if body is None:
            # A structured body is a map — `body_structured` from the
            # collector, `body` from older writers — and is shown as the JSON
            # it is rather than as nothing, because an empty row is
            # indistinguishable from a record that genuinely has no message.
            # Measured on the lab's collector, a map body was read as "" in
            # the list and in the record alike.
            raw = source.get("body_structured")
            if raw is None:
                raw = source.get("body")
            body = _as_text(raw)

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


def _as_text(value):
    """A body as a line of text: a string as it is, a map or list as JSON."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


def schema_for_document(source):
    """Pick a schema from a document, for the single-record fetch path.

    A `get` by id returns no mapping, and fetching one would cost a round trip
    to answer a question the document itself already answers.
    """
    if not isinstance(source, dict):
        return FlatLogSchema()
    if any(name in source for name in _OTEL_MARKERS):
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


def match_candidates(name):
    """Every field a query clause naming `name` is tried against.

    The neutral names are the table's. Any other name is also looked for
    where the collector keeps it: the record view shows a collector record's
    resource and attributes by their own names — `deployment.environment`,
    `request_id` — and its filter icon searches for exactly that, while the
    document holds them under `resource.attributes.` and `attributes.`.
    Measured on the lab, both clauses matched none of the eleven records
    they were clicked on. A field that is not there does not match, so trying
    all three costs nothing where the flat shape is.

    Only for matching. What a list projects and what an aggregation runs on
    stay `field_candidates`: an aggregation that fell back to a path nothing
    has would be an empty panel where there is a warning now.
    """
    if name in FIELD_CANDIDATES:
        return FIELD_CANDIDATES[name]
    if name.startswith(("resource.", "attributes.")):
        return (name,)
    return (name, f"resource.attributes.{name}", f"attributes.{name}")


#: What the schemas read beyond the neutral fields: the markers that tell a
#: collector record from a flat one — one of them the number that decides its
#: level — and a structured body, however it was written.
SCHEMA_FIELDS = _OTEL_MARKERS + ("body_structured", "body")


def source_fields(neutral_fields):
    """The `_source` a list of neutral fields has to ask for.

    The list view asks for less than the whole record, and the schema is
    chosen from what arrives. Asking for the neutral fields alone left out
    `severity_number` and `body_structured`: of eleven records the lab's
    collector wrote, five read differently in the list than when opened — a
    level of UNSPECIFIED rather than INFO or ERROR, or no service — and a map
    body read as empty in both.
    """
    return sorted({name for field in neutral_fields
                   for name in field_candidates(field)} | set(SCHEMA_FIELDS))
