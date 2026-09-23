"""
Container logs, as the Kubernetes shippers file them.

Reported from a real cluster running WDash 3.1.0: 710 indices, a search that
answered 177,511 results, and every row of them reading

    UNSPECIFIED    unknown    (no body)

with the fields sidebar listing `log`, `stream`, `tag`, `docker`,
`kubernetes` — every one of them the shape fluent-bit writes, and not one of
them a name WDash looked for.

The search was right. The reading was not. `detect_schema` knew two shapes,
the OpenTelemetry Collector's and the flat one WDash's own lab seeds, and
the flat one is also the fallback — so a shipper's document matched nothing,
fell through to a schema that looks for `message`, `level` and `service`,
found none of the three, and produced a record with every field a person
reads left empty. A failure that looks like emptiness, on the one screen
where emptiness is a plausible answer.

Two things had to change and this file asserts both:

  * a third schema, `ContainerLogSchema`, for the shape Docker's json-file
    driver and the `kubernetes` filters write;
  * `schema_for_document`, which repeated the OTel condition inline instead
    of asking `SCHEMAS` — so adding a schema changed the mapping path and
    left the single-document path exactly as it was.

The severity is the interesting decision, and `WhatItDoesNotInventTest`
below is where it lives: there is usually no level in these documents, and
this reads UNSPECIFIED rather than guessing one from the text.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone  # noqa: E402

from tests.support import ModelledES  # noqa: E402
from wdash.hub import LogQuery, Scope, TimeWindow  # noqa: E402
from wdash.hub.adapters import ElasticsearchLogSource  # noqa: E402
from wdash.hub.adapters.es_log_schema import (  # noqa: E402
    ContainerLogSchema, FlatLogSchema, OtelLogSchema, detect_schema,
    field_candidates, match_candidates, schema_for_document, source_fields,
)
from wdash.hub.query import DEFAULT_LOG_FIELDS  # noqa: E402

WINDOW = TimeWindow.exact(datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
                          datetime(2026, 9, 22, 14, tzinfo=timezone.utc))
EVERY = Scope.unrestricted()

#: The line from the report, verbatim. A klog prefix, which is what makes the
#: severity decision below a real one rather than academic.
LINE = ("I0922 13:32:27.552676 1877779 container.go:578] "
        "TCP listen open pid=9565")


def shipped(**extra):
    """A document in the shape the report showed, field for field."""
    return dict({
        "@timestamp": "2026-09-22T13:32:27.552Z",
        "log": LINE,
        "stream": "stderr",
        "tag": "kubernetes.var.log.containers.coroot-node-agent-5s62c_"
               "coroot_node-agent.log",
        "docker": {"container_id": "e16068209923943b2fd88ccc93493bf728fed"},
        "kubernetes": {
            "container_name": "node-agent",
            "host": "10.0.40.99",
            "namespace_name": "coroot",
            "pod_name": "coroot-node-agent-5s62c",
            "labels": {"app_kubernetes_io/component": "coroot-node-agent"},
        },
    }, **extra)


#: The mapping fluent-bit's dynamic templates produce for the above, which is
#: what `detect_schema` is handed on the index path.
SHIPPED_MAPPING = {
    "@timestamp": {"type": "date"},
    "log": {"type": "text",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
    "stream": {"type": "keyword"},
    "tag": {"type": "keyword"},
    "docker": {"properties": {"container_id": {"type": "keyword"}}},
    "kubernetes": {"properties": {
        "container_name": {"type": "keyword"},
        "host": {"type": "keyword"},
        "namespace_name": {"type": "keyword"},
        "pod_name": {"type": "keyword"},
    }},
}


def record(source=None, index="kube-coroot-2026.09.22"):
    """The record WDash makes of one document, by the schema it picks."""
    source = shipped() if source is None else source
    hit = {"_index": index, "_id": "abc", "_source": source}
    return schema_for_document(source).to_record(hit, "elasticsearch", "k8s")


class WhatAShipperWritesTest(unittest.TestCase):
    """The report, reproduced, then read.

    Each assertion here is one of the columns the screenshot showed empty.
    """

    def setUp(self):
        self.record = record()

    def test_the_line_is_the_body(self):
        self.assertEqual(self.record.body, LINE)

    def test_the_container_is_the_service(self):
        """Not the pod: the pod name carries a replica suffix that changes on
        every deploy, so a chart grouped by it starts a new series each time
        and none of them survives a restart."""
        self.assertEqual(self.record.service, "node-agent")

    def test_the_pod_and_its_namespace_become_the_resource(self):
        self.assertEqual(self.record.resource, {
            "host": "10.0.40.99", "namespace": "coroot",
            "pod": "coroot-node-agent-5s62c", "container": "node-agent"})

    def test_the_timestamp_is_read(self):
        self.assertIsNotNone(self.record.timestamp)
        self.assertEqual(self.record.timestamp.hour, 13)

    def test_and_the_record_points_back_at_the_document(self):
        self.assertEqual(self.record.ref.container, "kube-coroot-2026.09.22")
        self.assertEqual(self.record.ref.id, "abc")

    def test_none_of_which_the_flat_schema_would_have_found(self):
        """The fault itself, held still. Without this the tests above pass
        against any schema at all, including the one that was already there,
        and there would be nothing saying what was wrong."""
        flat = FlatLogSchema().to_record(
            {"_index": "i", "_id": "abc", "_source": shipped()},
            "elasticsearch")
        self.assertEqual(flat.body, "")
        self.assertEqual(flat.service, "")
        self.assertEqual(str(flat.severity), "UNSPECIFIED")


class WhichSchemaTest(unittest.TestCase):
    """Detection, and the order the three are tried in.

    Two paths ask this question — a mapping, for an index, and a document,
    for one hit — and they have to answer the same. They did not: the
    document path repeated one schema's condition inline.
    """

    def test_a_shippers_document_is_the_container_shape(self):
        self.assertIsInstance(schema_for_document(shipped()),
                              ContainerLogSchema)

    def test_and_its_mapping_says_the_same(self):
        """The index path and the document path, on one shape. A schema
        added to `SCHEMAS` and not reached from here is a schema that works
        on a list and not on the record it lists."""
        self.assertIsInstance(detect_schema(SHIPPED_MAPPING),
                              ContainerLogSchema)

    def test_a_flat_document_is_still_flat(self):
        self.assertIsInstance(
            schema_for_document({"message": "hello", "level": "INFO"}),
            FlatLogSchema)

    def test_a_collector_document_is_still_the_collectors(self):
        self.assertIsInstance(
            schema_for_document({"body_text": "hello", "severity_number": 9}),
            OtelLogSchema)

    def test_log_on_its_own_is_not_the_container_shape(self):
        """An application index may map a field called `log` and mean
        something else entirely. One of the shippers' own fields beside it is
        what makes this a container record rather than a coincidence."""
        self.assertIsInstance(
            schema_for_document({"message": "hi", "log": "of what"}),
            FlatLogSchema)

    def test_but_the_kubernetes_object_is_enough_on_its_own(self):
        """A shipper with JSON merging on parses the line, puts its fields at
        the top level and writes no `log` at all. `kubernetes` is still
        there, and nothing else writes an object by that name."""
        merged = {"kubernetes": {"container_name": "api"},
                  "message": "served 200", "level": "info"}
        self.assertIsInstance(schema_for_document(merged), ContainerLogSchema)

    def test_and_that_document_reads_by_its_own_names(self):
        """The point of the line above: `message` and `level` are there, so
        flat would have produced a body and a level — and no service, because
        `service` is not a field a shipper writes."""
        read = record({"kubernetes": {"container_name": "api"},
                       "message": "served 200", "level": "error"})
        self.assertEqual(read.body, "served 200")
        self.assertEqual(read.service, "api")
        self.assertEqual(str(read.severity), "ERROR")

    def test_something_that_is_not_a_document_at_all_still_answers(self):
        """The single-record path is handed whatever `_source` was, and a
        missing one is None.

        The string is not hypothetical padding: every `detect` here asks
        `in properties`, and on a string that is substring containment. A
        line of text mentioning `body_text` would be detected as the
        collector's shape and then read with `.get`, which a string has
        not — an AttributeError out of a log viewer, for a log line.
        """
        self.assertIsInstance(schema_for_document(None), FlatLogSchema)
        self.assertIsInstance(schema_for_document("body_text was in it"),
                              FlatLogSchema)

    def test_an_empty_mapping_names_no_schema(self):
        """The index path says None and the caller decides; only the document
        path falls back to flat, because a hit has to be read as something."""
        self.assertIsNone(detect_schema({}))


class WhatItDoesNotInventTest(unittest.TestCase):
    """There is no level in these documents, and this does not make one up.

    A level read out of the text would find one in the lines that happen to
    start `E0922` or contain the word ERROR, and leave the rest — so a filter
    for errors would return a subset of them, silently, and look like an
    answer. UNSPECIFIED is the true statement: the shipper recorded the line
    and not a level.

    Where a shipper DID parse one, reading it is not guessing. That is the
    other half of this class.
    """

    def test_no_level_in_the_document_is_no_level_on_the_record(self):
        self.assertEqual(str(record().severity), "UNSPECIFIED")
        self.assertEqual(record().severity_text, "")

    def test_stderr_is_not_a_level(self):
        """The tempting one. Plenty of programs log INFO to stderr, and every
        line in the report's index was on it."""
        self.assertEqual(record(shipped(stream="stderr")).severity,
                         record(shipped(stream="stdout")).severity)

    def test_nor_is_a_klog_prefix(self):
        """`I0922` and `E0922` are Kubernetes components' own format. Reading
        them would put a level on the cluster's components and none on
        anything else that writes to the same index."""
        error = record(shipped(log="E0922 13:32:28.101 store.go:91] disk full"))
        self.assertEqual(str(error.severity), "UNSPECIFIED")

    def test_but_a_level_the_shipper_parsed_is_read(self):
        read = record(shipped(level="error"))
        self.assertEqual(str(read.severity), "ERROR")
        self.assertEqual(read.severity_text, "error")

    def test_under_any_of_the_three_spellings(self):
        for field in ("level", "severity", "severity_text"):
            with self.subTest(field=field):
                self.assertEqual(
                    str(record(shipped(**{field: "warn"})).severity), "WARN")

    def test_and_a_level_that_is_empty_is_not_a_level(self):
        """`level: ""` is a parser that ran and found nothing, not a level of
        no name. Testing presence rather than value would make it one."""
        self.assertEqual(str(record(shipped(level="")).severity),
                         "UNSPECIFIED")


class WhatSurvivesIntoTheAttributesTest(unittest.TestCase):
    """What the record carries beyond the fields it maps.

    Nothing the shipper wrote is dropped. `stream` and `tag` are facts about
    the capture, and the person asking why a line is missing is asking about
    exactly those.
    """

    def test_the_shippers_own_fields_are_kept(self):
        attributes = record().attributes
        self.assertEqual(attributes["stream"], "stderr")
        self.assertIn("tag", attributes)
        self.assertIn("docker", attributes)

    def test_and_what_the_record_already_holds_is_not_repeated(self):
        attributes = record().attributes
        for mapped in ("@timestamp", "log", "kubernetes"):
            self.assertNotIn(mapped, attributes)

    def test_a_field_no_schema_knows_is_still_there(self):
        """The report's sidebar listed one called `nothing`. A reader who can
        see it in the fields list must be able to see it on the record."""
        self.assertEqual(record(shipped(nothing="F")).attributes["nothing"],
                         "F")

    def test_a_level_that_was_used_is_not_also_an_attribute(self):
        self.assertNotIn("level", record(shipped(level="error")).attributes)

    def test_a_parsed_message_beside_a_log_wins(self):
        """Both present means the line was PARSED, and `log` is the envelope
        it was parsed out of.

        This assertion used to run the other way, on the reasoning that a
        shipper writing both had put the line in `log`. A real cluster
        settled it against that: with JSON merging and `Keep_Log` both on,
        `log` holds `{"@t":"…","@m":"Sayfa bulunamadı (NotFound): KZIAQV"}`
        and the parsed field holds the sentence. Showing `log` shows the
        packaging.

        Neither is dropped — the envelope stays an attribute, so a reader
        chasing what the shipper actually received can still see it.
        """
        read = record(shipped(message="the parsed line"))
        self.assertEqual(read.body, "the parsed line")
        self.assertEqual(read.attributes["log"], LINE)

    def test_and_an_empty_log_falls_through_to_it(self):
        """fluent-bit writes `log: ""` for a blank line. Choosing the body by
        presence rather than by value would make that empty string win."""
        self.assertEqual(record(shipped(log="", message="the line")).body,
                         "the line")

    def test_a_structured_line_is_rendered_rather_than_dropped(self):
        """With JSON merging off and a parser on, `log` arrives as a map. An
        empty row is the one thing it must not become."""
        self.assertIn("served", record(shipped(log={"msg": "served 200"})).body)


#: The other half of the report, from the same cluster a day later: the
#: container shape was being read, and the rows still said UNSPECIFIED with a
#: body of raw JSON. Serilog's compact format, merged to the top level by the
#: shipper while `log` kept the line it was parsed out of.
CLEF_MESSAGE = "Sayfa bulunamadı (NotFound): KZIAQV"
CLEF_ENVELOPE = ('{"@t":"2026-09-22T18:39:52.2909439Z","@m":"' + CLEF_MESSAGE +
                 '","@i":"9fb525ae","@l":"Warning"}')


def serilog(**extra):
    """A container record whose line was parsed as CLEF."""
    document = {
        # The shipper's clock, and deliberately a second behind the
        # application's below: a fixture where the two agree cannot tell
        # which one was read.
        "@timestamp": "2026-09-22T18:39:53.104Z",
        "log": CLEF_ENVELOPE,
        "stream": "stdout",
        "kubernetes": {"container_name": "content-service",
                       "host": "10.0.40.110",
                       "namespace_name": "superapp",
                       "pod_name": "content-service-7c9fb5"},
        "@t": "2026-09-22T18:39:52.2909439Z",
        "@m": CLEF_MESSAGE,
        "@i": "9fb525ae",
        "@l": "Warning",
    }
    document.update(extra)
    # None removes a key rather than setting it: the interesting cases here
    # are about a field the format LEAVES OUT, and `@l=None` reads better at
    # the call site than rebuilding the dict without it.
    return {key: value for key, value in document.items() if value is not None}


class WhatSerilogWritesTest(unittest.TestCase):
    """CLEF fields inside a container record.

    The screenshot that reported this showed rows of raw JSON at
    UNSPECIFIED, beside a field sidebar counting `@l` — Warning 3,204,
    Error 15. The level was in the cluster, mapped and aggregatable, and
    the page was showing neither it nor the sentence inside the envelope.
    """

    def test_the_rendered_message_is_the_body(self):
        self.assertEqual(record(serilog()).body, CLEF_MESSAGE)

    def test_not_the_envelope_it_came_out_of(self):
        """The fault itself. `log` holds the JSON and a reader handed that
        has been shown the packaging."""
        self.assertNotIn("@t", record(serilog()).body)

    def test_which_is_kept_all_the_same(self):
        """Somebody chasing what the shipper actually received needs the
        line as it arrived."""
        self.assertEqual(record(serilog()).attributes["log"], CLEF_ENVELOPE)

    def test_the_level_is_read(self):
        self.assertEqual(str(record(serilog()).severity), "WARN")

    def test_an_absent_level_means_information_and_not_nothing(self):
        """CLEF omits `@l` FOR Information and only for Information, which
        is why the reported cluster's `@l` counted Warning and Error and
        nothing else: its informational lines — most of them — carry no
        `@l` at all. Read as missing, every one of them says UNSPECIFIED.
        """
        self.assertEqual(str(record(serilog(**{"@l": None})).severity), "INFO")

    def test_and_that_rule_does_not_leak_to_anything_else(self):
        """A container record with no level and no CLEF marker is still
        UNSPECIFIED. The rule is CLEF's, not a default for logs."""
        self.assertEqual(str(record(shipped()).severity), "UNSPECIFIED")

    def test_the_template_is_used_when_there_is_no_rendered_message(self):
        """`CompactJsonFormatter` writes `@mt` and leaves `@m` out. A
        template with its `{Placeholders}` unfilled is still a sentence,
        and still beats the envelope."""
        read = record(serilog(**{"@m": None,
                                 "@mt": "Sayfa bulunamadı (NotFound): {Code}"}))
        self.assertEqual(read.body, "Sayfa bulunamadı (NotFound): {Code}")

    def test_the_trace_and_span_are_read(self):
        """Serilog's tracing writes `@tr` and `@sp`. Reading them is what
        makes a record's link to its trace appear at all."""
        read = record(serilog(**{"@tr": "e64d43507a07f838454ed6b354d53be6",
                                 "@sp": "2e3765e5b46662d1"}))
        self.assertEqual(read.trace_id, "e64d43507a07f838454ed6b354d53be6")
        self.assertEqual(read.span_id, "2e3765e5b46662d1")

    def test_and_the_ordinary_spellings_still_are(self):
        read = record(shipped(trace_id="abc", span_id="def"))
        self.assertEqual((read.trace_id, read.span_id), ("abc", "def"))

    def test_the_event_id_stays_an_attribute(self):
        """`@i` is a hash of the message template — the thing that groups
        every occurrence of one log statement. Data, not bookkeeping."""
        self.assertEqual(record(serilog()).attributes["@i"], "9fb525ae")

    def test_the_shippers_clock_is_the_one_shown(self):
        """`@t` is when the application logged and `@timestamp` when the
        shipper filed it, so `@t` is the truer one — and `@timestamp` is
        the field this adapter sorts by and ranges over. A displayed time
        that disagrees with the sort reads as a list in the wrong order."""
        read = record(serilog())
        self.assertEqual((read.timestamp.second,
                          read.timestamp.microsecond // 1000), (53, 104))

    def test_but_the_applications_clock_when_there_is_no_other(self):
        read = record(serilog(**{"@timestamp": None}))
        self.assertIsNotNone(read.timestamp)
        self.assertEqual((read.timestamp.second,
                          read.timestamp.microsecond // 1000), (52, 290))

    def test_the_clock_that_was_read_is_not_also_an_attribute(self):
        self.assertNotIn("@timestamp", record(serilog()).attributes)

    def test_whichever_of_the_two_it_was(self):
        """The half that was not covered: with no `@timestamp` the clock is
        `@t`, and a record showing its own timestamp again in the attribute
        list is showing the same fact twice."""
        read = record(serilog(**{"@timestamp": None}))
        self.assertNotIn("@t", read.attributes)

    def test_and_the_other_one_still_is(self):
        """They are two different facts — when the application logged, and
        when the shipper filed it — and the gap between them is what
        somebody investigating a delayed pipeline is looking for."""
        self.assertEqual(record(serilog()).attributes["@t"],
                         "2026-09-22T18:39:52.2909439Z")

    def test_the_trace_and_span_are_not_repeated_into_the_attributes(self):
        """Read onto the record, so a second copy under their raw names is
        the same value twice on the detail page."""
        attributes = record(serilog(**{"@tr": "abc", "@sp": "def"})).attributes
        self.assertNotIn("@tr", attributes)
        self.assertNotIn("@sp", attributes)

    def test_a_lone_key_is_not_the_compact_format(self):
        """One key is a coincidence somebody else's index can have. The
        rule it would switch on — an absent `@l` means Information — is a
        strong claim to make about a document carrying one field that
        happens to start with a symbol."""
        for key, value in (("@t", "2026-09-22T18:39:52.290Z"),
                           ("@m", "a line"), ("@i", "9fb525ae")):
            with self.subTest(key=key):
                read = record({"kubernetes": {"container_name": "x"},
                               "log": "a line", key: value})
                self.assertEqual(str(read.severity), "UNSPECIFIED")

    def test_but_two_of_them_are_a_naming_scheme(self):
        read = record({"kubernetes": {"container_name": "x"},
                       "@m": "a line", "@i": "9fb525ae"})
        self.assertEqual(str(read.severity), "INFO")

    def test_the_clock_is_not_one_of_the_two_it_has_to_be(self):
        """Reported from a real cluster on 3.1.2, which had this fix and
        still read UNSPECIFIED: fluent-bit's JSON parser CONSUMES its time
        key into the record's timestamp and drops it from the document
        unless `Time_Keep On` is set, and `Off` is the default. So the
        commonest way to ship these logs is the one that leaves no `@t`,
        and requiring it meant the rule never ran where it was needed."""
        read = record({"@timestamp": "2026-09-23T05:46:56.368Z",
                       "@m": "rpc.system: signalr", "@i": "d106fcee",
                       "kubernetes": {"container_name": "robot-master-service",
                                      "host": "10.0.40.99"}})
        self.assertEqual(str(read.severity), "INFO")
        self.assertEqual(read.body, "rpc.system: signalr")
        self.assertEqual(read.service, "robot-master-service")

    def test_a_trace_context_alone_is_not_an_event(self):
        """`@tr` and `@sp` are attached to an event rather than being one.
        Two of them would otherwise make an Information line out of a
        document whose only claim is a trace id."""
        read = record({"kubernetes": {"container_name": "x"},
                       "log": "a line", "@tr": "abc", "@sp": "def"})
        self.assertEqual(str(read.severity), "UNSPECIFIED")

    def test_a_document_with_neither_has_no_timestamp_rather_than_a_crash(self):
        self.assertIsNone(record({"kubernetes": {"container_name": "x"},
                                  "log": "a line"}).timestamp)

    def test_it_is_still_the_container_shape(self):
        """Not a schema of its own: these documents carry the `kubernetes`
        object too, and a CLEF schema taking them would read the message
        and lose the pod, the namespace and the service."""
        read = record(serilog())
        self.assertEqual(read.service, "content-service")
        self.assertEqual(read.resource["namespace"], "superapp")

    def test_a_filter_naming_severity_looks_where_serilog_put_it(self):
        self.assertIn("@l", match_candidates("severity"))

    def test_and_a_narrowed_list_asks_for_it(self):
        """The list view fetches a slice of each document. Leaving `@l` or
        `@m` out of it is a row that reads differently from the record it
        lists — which is the fault this whole file is about, one level
        down."""
        asked = source_fields(DEFAULT_LOG_FIELDS)
        for field in ("@m", "@mt", "@l", "@tr"):
            self.assertIn(field, asked)

    def test_and_for_the_key_that_says_it_is_the_compact_format(self):
        """`@t`, which is not about the clock at all here.

        It is what `_is_clef` detects on, and a list asks for only the
        fields in this table — so a row arrived carrying `@m` and `@l` and
        no `@t`, the format went unrecognised, and the rule that an absent
        `@l` means Information never ran. Measured against a real cluster
        after the rest of this was written: UNSPECIFIED in the list, INFO
        when the same record was opened.
        """
        self.assertIn("@t", source_fields(DEFAULT_LOG_FIELDS))

    def test_a_row_and_the_record_it_lists_agree_about_the_level(self):
        """The fault above, stated as what it costs rather than as which
        field was missing. This is the invariant the whole projection list
        exists for."""
        whole = serilog(**{"@l": None})
        asked = source_fields(DEFAULT_LOG_FIELDS)
        # As Elasticsearch projects it: `kubernetes.container_name` in the
        # list keeps the `kubernetes` object, with that key inside it.
        narrowed = {key: value for key, value in whole.items()
                    if key in asked or any(f.startswith(key + ".")
                                           for f in asked)}
        self.assertEqual(str(record(narrowed).severity),
                         str(record(whole).severity))


class WhereTheNeutralNamesLiveTest(unittest.TestCase):
    """The other half of reading a cluster: a column, a filter and an
    aggregation each have to be told where a neutral name lives in it.

    A record that reads correctly and a `service` filter that matches nothing
    is half a fix.
    """

    def test_the_body_is_looked_for_under_log(self):
        self.assertIn("log", field_candidates("body"))

    def test_the_service_under_the_container_name(self):
        self.assertIn("kubernetes.container_name", field_candidates("service"))

    def test_a_filter_on_a_service_reaches_it_too(self):
        """`match_candidates` is what the filter icon on a record uses, and it
        is a separate table lookup from the one above."""
        self.assertIn("kubernetes.container_name", match_candidates("service"))

    def test_the_pod_and_namespace_are_askable_by_their_neutral_names(self):
        for neutral, path in (("pod", "kubernetes.pod_name"),
                              ("namespace", "kubernetes.namespace_name"),
                              ("container", "kubernetes.container_name")):
            with self.subTest(neutral=neutral):
                self.assertIn(path, field_candidates(neutral))

    def test_the_flat_spellings_still_come_first(self):
        """Order decides ties where a mapping could not be read, and most
        deployments are still flat. A container path promoted to the front
        would change what an unreadable mapping guesses."""
        self.assertEqual(field_candidates("body")[0], "message")
        self.assertEqual(field_candidates("service")[0], "service")

    def test_a_narrowed_list_still_asks_for_all_of_it(self):
        """The list view asks Elasticsearch for less than the whole record.
        Leaving these out is how a row reads differently from the record it
        lists — measured before, on the collector's shape."""
        asked = source_fields(DEFAULT_LOG_FIELDS)
        for field in ("log", "kubernetes.container_name", "kubernetes.host",
                      "severity"):
            self.assertIn(field, asked)


class ThroughTheWholeSourceTest(unittest.TestCase):
    """End to end, against a cluster that evaluates what it is sent.

    The tests above call the schema. This one goes through the source, so a
    row is read from a `_source` Elasticsearch actually projected rather than
    from the document as written — which is where the collector's shape broke
    once already.
    """

    def setUp(self):
        docs = [dict(shipped(), _id="a"),
                dict(shipped(log="second line",
                             kubernetes={"container_name": "coroot",
                                         "namespace_name": "coroot",
                                         "pod_name": "coroot-0",
                                         "host": "10.0.40.99"}), _id="b")]
        self.es = ModelledES({"kube-coroot-2026.09.22":
                              (SHIPPED_MAPPING, docs)})
        self.source = ElasticsearchLogSource(self.es, name="k8s",
                                             patterns=("kube-*",))

    def rows(self, fields=DEFAULT_LOG_FIELDS):
        page = self.source.search(
            LogQuery(window=WINDOW, limit=10, fields=fields), EVERY)
        return page.records

    def test_a_row_carries_its_line(self):
        self.assertEqual([r.body for r in self.rows()],
                         [LINE, "second line"])

    def test_and_the_service_the_record_would_show(self):
        self.assertEqual({r.service for r in self.rows()},
                         {"node-agent", "coroot"})

    def test_and_its_host(self):
        self.assertEqual({r.resource.get("host") for r in self.rows()},
                         {"10.0.40.99"})

    def test_a_row_reads_the_same_as_the_record_it_lists(self):
        """The whole point of the projection list. The detail view reads the
        entire document; the list reads a slice of it, and the two must say
        the same thing about the fields the list shows."""
        row = self.rows()[0]
        whole = record()
        self.assertEqual((row.body, row.service, str(row.severity)),
                         (whole.body, whole.service, str(whole.severity)))

    def test_including_a_level_the_shipper_parsed(self):
        """`severity` is a third spelling of the level, and the projection
        did not ask for it: the row said UNSPECIFIED while the record said
        ERROR, which is the collector's old fault in a new shape."""
        self.es = ModelledES({"kube-coroot-2026.09.22": (
            dict(SHIPPED_MAPPING, severity={"type": "keyword"}),
            [dict(shipped(severity="error"), _id="a")])})
        self.source = ElasticsearchLogSource(self.es, name="k8s",
                                             patterns=("kube-*",))
        self.assertEqual(str(self.rows()[0].severity), "ERROR")

    def test_the_editor_offers_these_fields_by_their_neutral_names(self):
        """A board built against this cluster and re-pointed at another
        backend still means something. `kubernetes.container_name` is one
        cluster's spelling of `service`."""
        offered = self.source.group_by_fields(EVERY)
        self.assertIn("service", offered)
        self.assertIn("host", offered)

    def test_and_does_not_offer_the_log_line_to_group_by(self):
        """`log` resolves to the neutral `body`, which a chart cannot group
        by: a bar per distinct line is a bar per line."""
        self.assertNotIn("log", self.source.group_by_fields(EVERY))
        self.assertNotIn("body", self.source.group_by_fields(EVERY))


class AgainstARealClusterTest(unittest.TestCase):
    """The lab, with an index fluent-bit's own mapping would have made.

    `ModelledES` is a model of Elasticsearch and this file's claims are about
    Elasticsearch: that a `_source` naming `kubernetes.container_name` comes
    back as a nested object, and that a `text` field with a `keyword`
    sub-field is what a shipper leaves the line under.
    """

    #: Named so it matches no pattern another module's lab source uses, and
    #: containing neither `log` nor `trace`: the log source defaults to
    #: `patterns=("*",)`, so an index added here is an index every other
    #: lab-backed test can see while this class runs.
    INDEX = "wdash-shape-check-container"

    #: And dated years back, for the same reason. The lab tests that search
    #: everything search a recent window; a document outside it cannot turn
    #: up as somebody else's first row.
    PAST = TimeWindow.exact(datetime(2020, 1, 1, tzinfo=timezone.utc),
                            datetime(2020, 1, 2, tzinfo=timezone.utc))

    @classmethod
    def setUpClass(cls):
        from tests import lab
        if lab.volume("es-logs") is None:
            raise unittest.SkipTest(
                f"es-logs at {lab.BACKENDS['es-logs'][0]} is not running")
        from elasticsearch import Elasticsearch
        cls.es = Elasticsearch(hosts=[lab.ES], request_timeout=20)
        cls.es.options(ignore_status=[404]).indices.delete(index=cls.INDEX)
        cls.es.indices.create(index=cls.INDEX,
                              mappings={"properties": SHIPPED_MAPPING})
        for number, line in enumerate((LINE, "listening on :8080")):
            document = shipped(log=line)
            document["@timestamp"] = f"2020-01-01T13:3{number}:00.000Z"
            cls.es.index(index=cls.INDEX, id=f"d{number}",
                         document=document, refresh=True)
        cls.source = ElasticsearchLogSource(cls.es, name="k8s",
                                            patterns=(cls.INDEX,))

    @classmethod
    def tearDownClass(cls):
        cls.es.options(ignore_status=[404]).indices.delete(index=cls.INDEX)

    def test_a_real_search_reads_every_row(self):
        page = self.source.search(
            LogQuery(window=self.PAST, limit=10, fields=DEFAULT_LOG_FIELDS),
            EVERY)
        self.assertEqual(len(page.records), 2)
        for row in page.records:
            self.assertTrue(row.body)
            self.assertEqual(row.service, "node-agent")
            self.assertEqual(row.resource.get("host"), "10.0.40.99")

    def test_and_the_fields_sidebar_answers(self):
        """The other half of the report: the statistics panel beside the
        results. It reads the mapping, and a shipper's mapping is nested
        three deep."""
        stats = self.source.field_stats(LogQuery(window=self.PAST), EVERY)
        names = {getattr(f, "field", None) for f in
                 (stats.fields if hasattr(stats, "fields") else stats)}
        self.assertIn("kubernetes.container_name", names)
        self.assertIn("kubernetes.namespace_name", names)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
