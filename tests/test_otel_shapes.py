"""
Reading what the OpenTelemetry Collector actually writes.

The documents below were captured from a real
`otel/opentelemetry-collector-contrib` running the lab's config with
`mapping.mode: otel`, not written by hand. That matters: the previous versions
of these schemas were written against a fixture that had itself been written
from an assumption, so the reader and the fixture agreed with each other and
with nothing in the ecosystem.

What that cost, measured against a real collector before the fix:

    logs    body, severity and service ALL empty — every field a person reads
    traces  service empty, duration 0, status unset

Nothing raised. The records came back looking like data.

Both shapes are read, because a store written by an older pipeline must keep
working. The flat shape is the one most existing shippers produce.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub.adapters.es_log_schema import (  # noqa: E402
    FlatLogSchema, OtelLogSchema, detect_schema, field_candidates,
    schema_for_document, severity_from_number,
)
from wdash.hub.adapters.es_trace_schema import OtelSpanSchema  # noqa: E402
from wdash.hub.models import STATUS_ERROR, STATUS_OK  # noqa: E402

#: Captured from the collector. Do not "tidy" these — they are evidence.
COLLECTOR_LOG = {
    "_index": "otel-logs-000001", "_id": "log-1",
    "_source": {
        "@timestamp": "2026-08-05T09:12:45.346576594Z",
        "attributes": {"request_id": "81d0615e"},
        "body_text": "token refreshed",
        "dropped_attributes_count": 0,
        "observed_timestamp": "1970-01-01T00:00:00.000000000Z",
        "resource": {
            "attributes": {"deployment.environment": "lab",
                           "service.name": "auth-service"},
            "dropped_attributes_count": 0,
        },
        "scope": {"dropped_attributes_count": 0},
        "severity_number": 9,
        "severity_text": "INFO",
        "trace_id": "264507c913d84457977db807ceff491a",
    },
}

COLLECTOR_SPAN = {
    "_index": "otel-traces-000001", "_id": "span-1",
    "_source": {
        "@timestamp": "2026-08-05T08:45:24.934039656Z",
        "attributes": {"db.system": "postgresql"},
        "duration": 125000000,
        "kind": "Client",
        "name": "SELECT orders",
        "parent_span_id": "d005d27279074e35",
        "resource": {
            "attributes": {"deployment.environment": "lab",
                           "service.name": "api-gateway",
                           "service.version": "1.4.2"},
        },
        "span_id": "50461205ec0e437b",
        "status": {"code": "Ok"},
        "trace_id": "5efb8941dc0448b8bed77d1332d01ea0",
    },
}

#: The mapping of the lab's otel-traces-000001 once the collector (0.109.0,
#: `mapping.mode: otel`) had written to it: the seed's keyword fields and
#: what the collector added dynamically, cut to the fields a reader uses.
COLLECTOR_SPAN_MAPPING = {
    "@timestamp": {"type": "date"},
    "trace_id": {"type": "keyword"},
    "span_id": {"type": "keyword"},
    "parent_span_id": {"type": "keyword"},
    "name": {"type": "keyword"},
    "kind": {"type": "keyword"},
    "duration": {"type": "long"},
    "status": {"properties": {
        "code": {"type": "keyword"},
        "message": {"type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}}}},
    "resource": {"properties": {
        "attributes": {"properties": {"service": {"properties": {
            "name": {"type": "keyword"}, "version": {"type": "keyword"}}}}},
        "dropped_attributes_count": {"type": "long"}}},
    "dropped_attributes_count": {"type": "long"},
    "dropped_events_count": {"type": "long"},
    "dropped_links_count": {"type": "long"},
}

#: What dynamic mapping makes of a collector log index once a record carried
#: a span id (an application that logs inside a span).
COLLECTOR_LOG_MAPPING = {
    "@timestamp": {"type": "date"},
    "body_text": {"type": "text"},
    "severity_number": {"type": "long"},
    "severity_text": {"type": "text",
                      "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
    "trace_id": {"type": "text",
                 "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
    "span_id": {"type": "text",
                "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
    "observed_timestamp": {"type": "date"},
    "resource": {"properties": {"attributes": {"properties": {"service": {
        "properties": {"name": {"type": "text"}}}}}}},
}


def collector_span(trace_id, span_id, service, parent=None, kind="Server",
                   code="Ok", duration_ms=10, seconds_ago=60, name=None):
    """One span document as the collector writes it: `kind` "Server",
    `status.code` "Ok"/"Error"/"Unset", `duration` in nanoseconds, and no
    `parent_span_id` at all on a root. Measured by pushing OTLP through the
    lab collector with lab/otel/emit.py's own builder."""
    import datetime as dt
    stamp = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=seconds_ago)
             ).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")
    doc = {"_id": span_id, "@timestamp": stamp, "trace_id": trace_id,
           "span_id": span_id, "name": name or f"{service} op", "kind": kind,
           "duration": duration_ms * 1_000_000, "status": {"code": code},
           "resource": {"attributes": {"service.name": service,
                                       "deployment.environment": "lab"},
                        "dropped_attributes_count": 0},
           "scope": {"dropped_attributes_count": 0},
           "attributes": {}, "dropped_attributes_count": 0,
           "dropped_events_count": 0, "dropped_links_count": 0}
    if parent:
        doc["parent_span_id"] = parent
    if code == "Error":
        doc["status"]["message"] = "boom"
    return doc


#: The shape most existing shippers write, and what WDash read exclusively
#: before this. Still supported.
FLAT_LOG = {
    "_index": "app-logs-000001", "_id": "log-2",
    "_source": {
        "@timestamp": "2026-08-04T09:30:12.142Z",
        "level": "WARNING", "message": "disk usage above threshold",
        "service": "payment-service", "host": "node-3",
        "environment": "production", "request_id": "req-42",
    },
}


class LogSchemaDetectionTest(unittest.TestCase):
    def test_collector_output_is_recognised(self):
        self.assertIsInstance(detect_schema({"body_text": {}}), OtelLogSchema)
        self.assertIsInstance(detect_schema({"severity_number": {}}), OtelLogSchema)

    def test_the_flat_shape_is_recognised(self):
        self.assertIsInstance(detect_schema({"message": {}, "level": {}}),
                              FlatLogSchema)

    def test_the_two_are_cleanly_distinguishable(self):
        """A collector index has neither `message` nor `level`, and vice versa."""
        self.assertIsInstance(
            schema_for_document(COLLECTOR_LOG["_source"]), OtelLogSchema)
        self.assertIsInstance(
            schema_for_document(FLAT_LOG["_source"]), FlatLogSchema)

    def test_an_unrecognisable_mapping_returns_none(self):
        self.assertIsNone(detect_schema({"whatever": {}}))


class CollectorLogTest(unittest.TestCase):
    def record(self):
        return OtelLogSchema().to_record(COLLECTOR_LOG, "elasticsearch", "otel-lab")

    def test_the_body_is_read(self):
        """Was empty. `body_text`, not `message`."""
        self.assertEqual(self.record().body, "token refreshed")

    def test_the_service_is_read(self):
        """Was empty. Nested under resource.attributes, not top level."""
        self.assertEqual(self.record().service, "auth-service")

    def test_the_severity_is_read(self):
        """Was UNSPECIFIED."""
        self.assertEqual(self.record().severity, "INFO")
        self.assertEqual(self.record().severity_text, "INFO")

    def test_the_severity_number_wins_over_the_text(self):
        """severity_text is free-form; applications call things 'notice'."""
        hit = {"_index": "i", "_id": "1", "_source": dict(
            COLLECTOR_LOG["_source"], severity_number=17,
            severity_text="something-nobody-recognises")}
        self.assertEqual(OtelLogSchema().to_record(hit, "es").severity, "ERROR")

    def test_severity_numbers_map_to_their_bands(self):
        self.assertEqual(
            [severity_from_number(n) for n in (1, 5, 9, 13, 17, 21)],
            ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"])
        self.assertIsNone(severity_from_number(None))
        self.assertIsNone(severity_from_number("nine"))

    def test_the_trace_id_survives_so_correlation_works(self):
        self.assertEqual(self.record().trace_id,
                         "264507c913d84457977db807ceff491a")

    def test_collector_bookkeeping_is_not_shown_as_data(self):
        """dropped_attributes_count and scope are the collector talking to
        itself; putting them in the attribute list is noise on every record."""
        record = self.record()
        for noise in ("dropped_attributes_count", "scope", "observed_timestamp"):
            self.assertNotIn(noise, record.attributes)
            self.assertNotIn(noise, record.resource)

    def test_the_real_attributes_are_kept(self):
        self.assertEqual(self.record().attributes["request_id"], "81d0615e")

    def test_the_source_name_is_stamped(self):
        self.assertEqual(self.record().source, "otel-lab")


class FlatLogStillWorksTest(unittest.TestCase):
    def record(self):
        return FlatLogSchema().to_record(FLAT_LOG, "elasticsearch", "es-logs")

    def test_the_older_shape_is_unaffected(self):
        record = self.record()
        self.assertEqual(record.body, "disk usage above threshold")
        self.assertEqual(record.service, "payment-service")
        self.assertEqual(record.severity, "WARN")
        self.assertEqual(record.severity_text, "WARNING")
        self.assertEqual(record.resource["host"], "node-3")
        self.assertEqual(record.attributes["request_id"], "req-42")


class CollectorSpanTest(unittest.TestCase):
    def span(self):
        return OtelSpanSchema().to_span(COLLECTOR_SPAN)

    def test_the_service_is_read(self):
        """Was empty — which also broke the scope's service filter."""
        self.assertEqual(self.span().service, "api-gateway")

    def test_the_duration_is_read(self):
        """Was 0, which makes a waterfall meaningless. `duration`, not
        `duration_ns`."""
        self.assertEqual(self.span().duration_us, 125_000)

    def test_the_status_is_read(self):
        """Was UNSET. `status.code: "Ok"`, not `status_code: "OK"`."""
        self.assertEqual(self.span().status, STATUS_OK)

    def test_an_error_status_is_read(self):
        hit = {"_index": "i", "_id": "1",
               "_source": dict(COLLECTOR_SPAN["_source"],
                               status={"code": "Error"})}
        self.assertEqual(OtelSpanSchema().to_span(hit).status, STATUS_ERROR)

    def test_the_short_kind_form_is_understood(self):
        """"Client", not "SPAN_KIND_CLIENT"."""
        self.assertEqual(self.span().kind, "CLIENT")

    def test_the_long_kind_form_still_is(self):
        hit = {"_index": "i", "_id": "1",
               "_source": dict(COLLECTOR_SPAN["_source"],
                               kind="SPAN_KIND_SERVER")}
        self.assertEqual(OtelSpanSchema().to_span(hit).kind, "SERVER")

    def test_the_older_field_names_are_still_read(self):
        """A store written by an earlier pipeline must keep working."""
        source = {k: v for k, v in COLLECTOR_SPAN["_source"].items()
                  if k not in ("duration", "status", "resource")}
        source.update({"duration_ns": 7_000_000, "status_code": "ERROR",
                       "resource": {"service.name": "legacy-service"}})
        span = OtelSpanSchema().to_span({"_index": "i", "_id": "1",
                                         "_source": source})
        self.assertEqual(span.duration_us, 7_000)
        self.assertEqual(span.status, STATUS_ERROR)
        self.assertEqual(span.service, "legacy-service")


class SpanIndexDetectionTest(unittest.TestCase):
    """Which indices a trace source reads as spans.

    Two ids were the whole test. A collector writes both onto a log record
    made inside a span, so a trace source whose patterns reached an
    otel-logs index — the configured default was `*` — counted every such
    record in the service list as a span.
    """

    def detect(self, mapping):
        from wdash.hub.adapters.es_trace_schema import detect_schema as detect
        return detect(mapping)

    def test_the_collector_s_span_index_is_one(self):
        self.assertIsInstance(self.detect(COLLECTOR_SPAN_MAPPING), OtelSpanSchema)

    def test_an_older_pipeline_s_span_index_still_is(self):
        mapping = {k: v for k, v in COLLECTOR_SPAN_MAPPING.items()
                   if k not in ("duration", "status")}
        mapping.update({"duration_ns": {"type": "long"},
                        "status_code": {"type": "keyword"}})
        self.assertIsInstance(self.detect(mapping), OtelSpanSchema)

    def test_the_collector_s_log_index_is_not(self):
        self.assertIsNone(self.detect(COLLECTOR_LOG_MAPPING))

    def test_two_ids_alone_are_not(self):
        self.assertIsNone(self.detect({"trace_id": {"type": "keyword"},
                                       "span_id": {"type": "keyword"}}))

    def test_a_span_needs_its_kind_and_its_duration(self):
        for missing in ("kind", "duration"):
            mapping = {k: v for k, v in COLLECTOR_SPAN_MAPPING.items()
                       if k != missing}
            self.assertIsNone(self.detect(mapping), missing)

    def test_an_index_holding_log_records_too_is_not_read_as_spans(self):
        """Both signals pointed at one index. Read as spans, its log records
        would be counted as spans; left out, the trace source says so."""
        for field in ("body_text", "severity_number", "severity_text"):
            mapping = dict(COLLECTOR_SPAN_MAPPING, **{field: {"type": "text"}})
            self.assertIsNone(self.detect(mapping), field)


class CollectorSpanSearchTest(unittest.TestCase):
    """Searching what the collector writes, against a cluster model that
    answers the query it is sent.

    The reader had been fixed to the collector's field names; the search
    beside it had not. It asked for entry spans as `kind: SPAN_KIND_SERVER`,
    errors as `status_code: ERROR` and durations as `duration_ns`, none of
    which a collector writes. Measured on the lab's OTel index over 7 days:
    the trace list, errors-only, a minimum duration and "slowest" were all
    empty, and 13,537 spans had 0 errors — where the APM copy of the same
    traces gave 25 rows and 171 errors. Nothing failed.
    """

    def setUp(self):
        from tests.support import ModelledES
        from wdash.hub import Scope, TimeWindow
        from wdash.hub.adapters import ElasticsearchTraceSource
        # The fast trace is first in the index, so that only the cluster's
        # sort — not the order documents happen to sit in — puts the slow one
        # first when the limit cuts the list.
        docs = [
            # t2: newer, faster, clean.
            collector_span("t2", "t2-gw", "api-gateway", duration_ms=40,
                           seconds_ago=30),
            collector_span("t2", "t2-auth", "auth-service", parent="t2-gw",
                           duration_ms=20, seconds_ago=29),
            # t1: a failed request through the gateway, 1.2 s.
            collector_span("t1", "t1-gw", "api-gateway", code="Error",
                           duration_ms=1200, seconds_ago=120),
            collector_span("t1", "t1-pay", "payment-service", parent="t1-gw",
                           code="Error", duration_ms=900, seconds_ago=119),
            collector_span("t1", "t1-pg", "postgres", parent="t1-pay",
                           kind="Client", duration_ms=300, seconds_ago=118),
            # t3: a job with no request behind it: not an entry span.
            collector_span("t3", "t3-job", "cron", kind="Internal",
                           code="Unset", duration_ms=5000, seconds_ago=60),
        ]
        self.es = ModelledES({"otel-traces-000001": (COLLECTOR_SPAN_MAPPING, docs)})
        self.source = ElasticsearchTraceSource(self.es, name="otel")
        self.window = TimeWindow.of("1h")
        self.scope = Scope.unrestricted()

    def search(self, **arguments):
        from wdash.hub.query import TraceQuery
        arguments.setdefault("limit", 10)
        return [(row.trace_id, row.service) for row in self.source.search(
            TraceQuery(window=self.window, **arguments), self.scope)]

    def test_the_list_holds_the_traces_that_entered_through_a_server(self):
        self.assertEqual(self.search(), [("t2", "api-gateway"),
                                         ("t1", "api-gateway")])

    def test_a_service_s_own_entry_spans_are_found(self):
        self.assertEqual(self.search(service="payment-service"),
                         [("t1", "payment-service")])

    def test_errors_only_finds_the_failed_request(self):
        self.assertEqual(self.search(only_errors=True), [("t1", "api-gateway")])
        self.assertEqual(self.search(service="payment-service", only_errors=True),
                         [("t1", "payment-service")])
        self.assertEqual(self.search(service="auth-service", only_errors=True), [])

    def test_a_minimum_duration_is_read_in_nanoseconds(self):
        self.assertEqual(self.search(min_duration_us=1_000_000),
                         [("t1", "api-gateway")])
        self.assertEqual(self.search(min_duration_us=30_000),
                         [("t2", "api-gateway"), ("t1", "api-gateway")])

    def test_slowest_is_ordered_by_the_collector_s_duration(self):
        from wdash.hub.query import SORT_SLOWEST
        self.assertEqual(self.search(sort=SORT_SLOWEST),
                         [("t1", "api-gateway"), ("t2", "api-gateway")])
        # The rows are sorted again after they arrive; which rows arrive is
        # the cluster's sort.
        self.assertEqual(self.search(sort=SORT_SLOWEST, limit=1),
                         [("t1", "api-gateway")])

    def test_the_rows_carry_the_collector_s_values(self):
        from wdash.hub.query import TraceQuery
        rows = {row.trace_id: row for row in self.source.search(
            TraceQuery(window=self.window, limit=10), self.scope)}
        self.assertEqual(rows["t1"].duration_us, 1_200_000)
        self.assertTrue(rows["t1"].has_error)
        self.assertFalse(rows["t2"].has_error)

    def test_services_count_the_collector_s_errors(self):
        counted = {s.name: (s.span_count, s.error_count)
                   for s in self.source.services(self.window, self.scope)}
        self.assertEqual(counted, {"api-gateway": (2, 1), "payment-service": (1, 1),
                                   "postgres": (1, 0), "auth-service": (1, 0),
                                   "cron": (1, 0)})

    def test_both_spellings_in_one_source_sort_by_their_own_duration(self):
        """One index of each spelling, in one source, with the limit cutting.

        Both landed in ONE request, because the group was the schema CLASS,
        and Elasticsearch sorts a document that does not have the primary
        sort field LAST whatever its value. So every collector-shaped span
        outranked every older-pipeline one, and the limit cut the genuinely
        slowest traces out — invisible unless the limit bites, which at the
        page's 25 it normally does. Measured before: "slowest" with a limit
        of 1 gave the 40 ms row while a 9,000 ms trace sat in the other
        index. The test the older spelling already had builds a source
        holding that spelling ALONE, so nothing guarded the mixed store the
        `unmapped_type` comment was written for.
        """
        from tests.support import ModelledES
        from wdash.hub.adapters import ElasticsearchTraceSource
        from wdash.hub.query import SORT_SLOWEST

        older_mapping = {k: v for k, v in COLLECTOR_SPAN_MAPPING.items()
                         if k not in ("duration", "status")}
        older_mapping.update({"duration_ns": {"type": "long"},
                              "status_code": {"type": "keyword"}})
        older = collector_span("old", "old-root", "legacy", seconds_ago=120)
        for key in ("duration", "status", "kind"):
            older.pop(key)
        older.update({"kind": "SPAN_KIND_SERVER", "status_code": "OK",
                      "duration_ns": 9000 * 1_000_000})

        self.source = ElasticsearchTraceSource(ModelledES({
            "new-traces-1": (COLLECTOR_SPAN_MAPPING,
                             [collector_span("new", "new-root", "modern",
                                             duration_ms=40, seconds_ago=30)]),
            "old-traces-1": (older_mapping, [older]),
        }), name="otel")

        self.assertEqual(self.search(sort=SORT_SLOWEST),
                         [("old", "legacy"), ("new", "modern")])
        self.assertEqual(self.search(sort=SORT_SLOWEST, limit=1),
                         [("old", "legacy")])

    def test_an_older_pipeline_s_spellings_are_searched_too(self):
        """`to_span` reads `SPAN_KIND_SERVER`, `status_code` and
        `duration_ns`, so the search asks for them beside the collector's."""
        from tests.support import ModelledES
        from wdash.hub.adapters import ElasticsearchTraceSource
        from wdash.hub.query import SORT_SLOWEST

        def older(trace_id, seconds_ago, duration_ms, code):
            doc = collector_span(trace_id, f"{trace_id}-root", "legacy",
                                 seconds_ago=seconds_ago)
            for key in ("duration", "status", "kind"):
                doc.pop(key)
            doc.update({"kind": "SPAN_KIND_SERVER", "status_code": code,
                        "duration_ns": duration_ms * 1_000_000})
            return doc

        mapping = {k: v for k, v in COLLECTOR_SPAN_MAPPING.items()
                   if k not in ("duration", "status")}
        mapping.update({"duration_ns": {"type": "long"},
                        "status_code": {"type": "keyword"}})
        self.source = ElasticsearchTraceSource(ModelledES({"old-traces-1": (
            mapping, [older("o2", 50, 20, "OK"), older("o1", 100, 700, "ERROR")])}))
        self.assertEqual([t for t, _ in self.search()], ["o2", "o1"])
        self.assertEqual([t for t, _ in self.search(only_errors=True)], ["o1"])
        self.assertEqual([t for t, _ in self.search(min_duration_us=500_000)], ["o1"])
        self.assertEqual([t for t, _ in self.search(sort=SORT_SLOWEST)], ["o1", "o2"])
        self.assertEqual([t for t, _ in self.search(sort=SORT_SLOWEST, limit=1)],
                         ["o1"])


class FieldCandidateTest(unittest.TestCase):
    """One neutral name, every backend field it can live in.

    A search spans indices written by different pipelines; naming one field
    matches nothing in the other half, silently.
    """

    def test_severity_covers_both_shapes(self):
        self.assertIn("level", field_candidates("severity"))
        self.assertIn("severity_text", field_candidates("severity"))

    def test_body_covers_both_shapes(self):
        self.assertIn("message", field_candidates("body"))
        self.assertIn("body_text", field_candidates("body"))

    def test_service_covers_the_nested_path(self):
        self.assertIn("service", field_candidates("service"))
        self.assertIn("resource.attributes.service.name",
                      field_candidates("service"))

    def test_the_flat_name_is_tried_first(self):
        """Most deployments have it; the order only decides ties."""
        self.assertEqual(field_candidates("severity")[0], "level")

    def test_an_unknown_field_is_returned_as_itself(self):
        self.assertEqual(field_candidates("request_id"), ("request_id",))


if __name__ == "__main__":
    unittest.main(verbosity=2)
