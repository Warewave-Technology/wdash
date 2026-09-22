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



#: Serilog's Compact Log Event Format, which a shipper with JSON merging on
#: leaves at the top level of the document beside the shipper's own fields.
#:
#: `@t` is the only required key. `@m` is the rendered message,
#: `@mt` the template it came from, `@l` the level, `@i` an event type hash,
#: `@x` an exception, `@r` renderings, and `@tr`/`@sp` the trace and span a
#: line belongs to.
#:
#: Reported from a real cluster: rows reading UNSPECIFIED with a body of
#: `{"@t":"…","@m":"Sayfa bulunamadı (NotFound): KZIAQV","@l":"Warning"}`,
#: while the field sidebar beside them counted `@l` — Warning 3,204, Error 15.
#: The level was in the cluster, mapped and aggregatable, and WDash was
#: showing the JSON envelope and no level at all.
_CLEF_TIME = "@t"
_CLEF_BODY = ("@m", "@mt")
_CLEF_SEVERITY = ("@l",)
#: `@t` beside any one of these. `@t` alone is too weak to claim a shape.
_CLEF_MARKERS = ("@m", "@mt", "@l", "@i", "@x", "@r")

#: What CLEF means by leaving `@l` out, and it is not "no level": the format
#: omits the key FOR Information and only for Information. That is why the
#: reported cluster's `@l` counted Warning and Error and nothing else — its
#: informational lines, which are most of them, carry no `@l` at all. Read as
#: absent they would every one of them say UNSPECIFIED.
_CLEF_DEFAULT_SEVERITY = "Information"


def _is_clef(source):
    """Is this document Serilog's compact format?

    Asked of a DOCUMENT rather than a mapping, because the rule it decides —
    an absent `@l` means Information — is a statement about one event.
    """
    return _CLEF_TIME in source and any(name in source
                                        for name in _CLEF_MARKERS)


#: What a container record maps onto the model. Everything else — `stream`,
#: `tag`, `docker.container_id` — stays an attribute, because each is a fact
#: about the capture that somebody chasing a missing line asks for, and a
#: shipper's field dropped here is a field with nowhere else to appear.
#:
#: The body and the severity are NOT in this set: which key held them is
#: decided per document below, and consuming a key that was not used would
#: drop a field the record still has.
#: The clock is NOT in here: which key held it is decided per document, like
#: the body and the level, and naming `@timestamp` here as well left the line
#: that consumes it covering only `@t` — half a rule, with nothing saying so.
_CONTAINER_CONSUMED = {"kubernetes", "trace_id", "span_id", "@tr", "@sp"}

#: Where the line is, in order.
#:
#: The parsed message comes FIRST and `log` last, which is the opposite of
#: what it looks like: where both exist, `log` is the JSON envelope and the
#: parsed field is the message inside it. A reader handed
#: `{"@t":"…","@m":"Sayfa bulunamadı (NotFound): KZIAQV","@l":"Warning"}`
#: instead of `Sayfa bulunamadı (NotFound): KZIAQV` has been shown the
#: packaging. `@mt` is the template, with its `{Placeholders}` unfilled, and
#: is still more readable than the envelope.
#:
#: `log` alone is what the Docker json-file driver and fluent-bit's tail
#: input write when nothing parsed the line, and it stays the fallback.
_CONTAINER_BODY = ("@m", "@mt", "message", "log")

#: A level only if the shipper or the application put one in the document.
#: Reading it is not guessing: it is there. Absent — and absent for a reason
#: other than CLEF's, which `_CLEF_DEFAULT_SEVERITY` covers — the record says
#: UNSPECIFIED, and see the class docstring for why nothing is inferred from
#: the text.
_CONTAINER_SEVERITY = ("@l", "level", "severity", "severity_text")

#: The trace a line belongs to, per shape. Reading these is what makes the
#: record's "open this trace" link appear at all.
_CONTAINER_TRACE = ("@tr", "trace_id")
_CONTAINER_SPAN = ("@sp", "span_id")

#: The clock, in order, and `@timestamp` FIRST on purpose. `@t` is when the
#: application logged and `@timestamp` when the shipper filed it, so `@t` is
#: the truer one — but `@timestamp` is the field this adapter sorts by and
#: ranges over, and a displayed time that disagrees with the sort reads as a
#: list in the wrong order. `@t` is the fallback for a document that has no
#: `@timestamp` at all.
_CONTAINER_TIME = ("@timestamp", "@t")

#: Where the name of the thing that logged lives, in order. The container
#: name is what a person recognises; the pod name carries a replica suffix
#: that changes on every deploy, so a chart grouped by it draws a new series
#: each time and no series survives a restart.
_CONTAINER_SERVICE = ("container_name", "labels.app_kubernetes_io/name",
                      "labels.app", "labels.k8s-app")

#: Lifted out of `kubernetes` onto the record's resource, under the neutral
#: names the rest of WDash groups, filters and displays by.
_CONTAINER_RESOURCE = {"host": "host", "namespace": "namespace_name",
                       "pod": "pod_name", "container": "container_name"}

#: Any one of these beside `log` makes a document the shippers' rather than
#: an application index that happens to have a field called `log`.
_CONTAINER_MARKERS = ("kubernetes", "stream", "tag", "docker")


class ContainerLogSchema(LogSchema):
    """A container's stdout, as the Kubernetes log shippers file it.

    Docker's json-file driver writes `log` and `stream`; fluentd's and
    fluent-bit's `kubernetes` filters add `tag` and a `kubernetes` object of
    pod, namespace, container and labels. It is one of the most common
    shapes an Elasticsearch holding container logs has — and WDash read none
    of it. A real cluster of 710 indices searched correctly, 177,511 hits,
    and every row of them came back with an empty line, no service and
    UNSPECIFIED, because neither of the two schemas matched and the flat one
    was used as a fallback: it looks for `message`, `level` and `service`,
    and this shape has none of the three.

    There is usually no severity here and this does not invent one. A level
    is read where the shipper parsed one into the document; otherwise the
    record says UNSPECIFIED and means it. `stream: stderr` is not a level —
    plenty of programs log INFO to stderr — and a level read out of the text
    would find one in the lines that happen to start `E0922` or contain the
    word, and leave the rest, which is worse than an honest UNSPECIFIED
    because it looks like data. A filter for errors would then quietly
    return a subset of them.
    """

    name = "container"
    body_field = "log"
    #: None, and the one schema here with no severity field at all.
    severity_field = None
    service_field = "kubernetes.container_name"

    @classmethod
    def detect(cls, properties):
        """The `kubernetes` object, or `log` beside one of the shippers'.

        `log` on its own is too weak — an application index can map a field
        called that and mean something else entirely — so it needs a second
        field only a shipper writes. `kubernetes` alone is enough on its own
        because nothing else writes an object by that name at the top level,
        and a shipper with JSON merging on writes no `log` field.
        """
        names = set(properties)
        return "kubernetes" in names or (
            "log" in names and bool(set(_CONTAINER_MARKERS) & names))

    def to_record(self, hit, backend, source_name=None):
        source = hit.get("_source") or {}
        kubernetes = source.get("kubernetes") or {}
        consumed = set(_CONTAINER_CONSUMED)

        body_key = _first_with_value(source, _CONTAINER_BODY)
        if body_key:
            consumed.add(body_key)

        severity_key = _first_with_value(source, _CONTAINER_SEVERITY)
        if severity_key:
            consumed.add(severity_key)
            severity_text = str(source.get(severity_key) or "")
        elif _is_clef(source):
            # Not a missing level: CLEF omits the key FOR Information. See
            # `_CLEF_DEFAULT_SEVERITY`.
            severity_text = _CLEF_DEFAULT_SEVERITY
        else:
            severity_text = ""

        time_key = _first_with_value(source, _CONTAINER_TIME)
        consumed.add(time_key or _CONTAINER_TIME[0])

        resource = {}
        for neutral, key in _CONTAINER_RESOURCE.items():
            value = dig(kubernetes, key)
            if value:
                resource[neutral] = _as_text(value)

        service = ""
        for candidate in _CONTAINER_SERVICE:
            value = dig(kubernetes, candidate)
            if value:
                service = _as_text(value)
                break

        return LogRecord(
            timestamp=parse_time(source.get(time_key)) if time_key else None,
            body=_as_text(source.get(body_key)) if body_key else "",
            severity=normalise_severity(severity_text or None),
            severity_text=severity_text,
            service=service,
            resource=resource,
            attributes={k: v for k, v in source.items() if k not in consumed},
            trace_id=_first_value(source, _CONTAINER_TRACE),
            span_id=_first_value(source, _CONTAINER_SPAN),
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


#: Order matters. OTel is checked first because a collector-written index has
#: neither `message` nor `level`, while a flat index has neither `body_text`
#: nor `severity_number`; the two are cleanly distinguishable.
#:
#: The container shape goes BEFORE flat and not after, because flat is the
#: fallback and answers yes to anything with a `message` — and a shipper that
#: writes both `log` and `message` has put the line in `log`. Flat stays last
#: for the same reason it always was: it is what nothing more specific
#: matched, rather than a claim about the index.
SCHEMAS = (OtelLogSchema, ContainerLogSchema, FlatLogSchema)


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


def _first_value(source, candidates):
    """The value under the first of `candidates` the document has one for."""
    name = _first_with_value(source, candidates)
    return source.get(name) if name else None


def _first_with_value(source, candidates):
    """The first of `candidates` the document actually has something under.

    Presence is not enough: fluent-bit writes `log: ""` for a blank line, and
    a key held with an empty value would otherwise win over the one holding
    the text.
    """
    for name in candidates:
        if source.get(name):
            return name
    return None


def schema_for_document(source):
    """Pick a schema from a document, for the single-record fetch path.

    A `get` by id returns no mapping, and fetching one would cost a round trip
    to answer a question the document itself already answers.

    A document's own keys ARE the properties a schema detects on, so this
    asks them in `SCHEMAS` order rather than repeating their conditions. It
    used to repeat one of them — the OTel markers, inline — and a container
    record went on reading as flat for as long as it took to notice that
    adding a schema to `SCHEMAS` had changed nothing on this path.

    Flat is still the fallback, as it is in `detect_schema`: it is what
    nothing more specific matched.
    """
    if not isinstance(source, dict):
        return FlatLogSchema()
    return detect_schema(source) or FlatLogSchema()


#: Where each neutral field lives, per schema, in preference order.
#:
#: Ordered so the flat shape is tried first — it is what most existing
#: deployments have — and the collector's names are the fallback. Resolution
#: checks the actual mapping, so the order only decides ties.
FIELD_CANDIDATES = {
    # `@t` is the other spelling of the clock and the reason it is here is
    # not the clock: it is the key `_is_clef` detects on, and a list asks
    # Elasticsearch for only these fields. Without it a row carried `@m` and
    # `@l` but no `@t`, so the format went unrecognised and the rule that an
    # absent `@l` means Information never ran — measured against a real
    # cluster, a record reading UNSPECIFIED in the list and INFO when opened.
    "timestamp": ("@timestamp", "@t"),
    "body": ("message", "body_text", "log", "@m", "@mt"),
    "severity": ("level", "severity_text", "severity", "@l"),
    "severity_text": ("level", "severity_text", "severity", "@l"),
    "service": ("service", "resource.attributes.service.name",
                "resource.service.name", "kubernetes.container_name"),
    "host": ("host", "resource.attributes.host.name", "kubernetes.host"),
    "environment": ("environment",
                    "resource.attributes.deployment.environment"),
    "trace_id": ("trace_id", "@tr"),
    "span_id": ("span_id", "@sp"),
    # Not in `DEFAULT_LOG_FIELDS`, and here so that a column or a filter
    # naming one is looked for where a shipper puts it rather than at a top
    # level that has nothing. `container` is the name, not the id: the id is
    # in `docker` and changes on every restart.
    "namespace": ("namespace", "kubernetes.namespace_name",
                  "resource.attributes.k8s.namespace.name"),
    "pod": ("pod", "kubernetes.pod_name",
            "resource.attributes.k8s.pod.name"),
    "container": ("container", "kubernetes.container_name",
                  "resource.attributes.k8s.container.name"),
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
#:
#: A container record needs no marker of its own here: `log` arrives as a
#: candidate for `body` and `kubernetes.container_name` as one for `service`,
#: and a list that asked for neither has no body and no service to read, so
#: which schema was chosen changes nothing about the row.
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
