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
