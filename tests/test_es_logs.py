"""
The Elasticsearch log source, asked what a real cluster holds.

Each class below is a fault that was measured against the lab before it was
fixed, and each one looked like data rather than like a fault:

  * a cluster that could not be reached when a worker started was an empty
    one: "No log indices found", and a role with `*` was told it could read
    nothing;
  * a data stream was not a container at all. `_cat/indices` lists a stream's
    backing indices (`.ds-*`, dropped as system indices) and never its name,
    so the lab's four streams were invisible to both the log and the trace
    source, and so is every Filebeat 8, Elastic Agent and APM 8 install;
  * a list row asked Elasticsearch for too little to tell what wrote it: 4 of
    10 records the lab's collector wrote read UNSPECIFIED in the list and
    INFO or ERROR when opened, and a structured body read empty in both;
  * two spellings of one level overwrote each other in the histogram;
  * the records around one were looked for a whole second away from it;
  * shards that failed were not mentioned; field statistics that failed were
    "No field data available"; a filter on a collector record's resource or
    attribute matched nothing;
  * the logs page asked only the default source whether a role could read
    anything.

The cluster here is `ModelledES`, which evaluates the query it is sent,
extended with what Elasticsearch 8 does with data streams: the catalogue lists
backing indices, a search through the stream's name reaches all of them, and a
GET through the name is refused.
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from datetime import datetime, timezone  # noqa: E402

from tests.support import ModelledES, grant  # noqa: E402
from tests.test_log_contract import TestConfig, _session  # noqa: E402
from wdash.app import create_app  # noqa: E402
from wdash.hub import Hub, LogQuery, Scope, TimeWindow  # noqa: E402
from wdash.hub.adapters import (  # noqa: E402
    ElasticsearchLogSource, ElasticsearchTraceSource,
)
from wdash.hub.adapters.elasticsearch import _IndexCatalogue  # noqa: E402
from wdash.hub.aggregation import Terms  # noqa: E402
from wdash.hub.models import SourceRef  # noqa: E402
from wdash.hub.query import DEFAULT_LOG_FIELDS  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
START = "2026-08-04T09:00:00Z"
END = "2026-08-04T10:00:00Z"
WINDOW = TimeWindow.exact(datetime(2026, 8, 4, 9, tzinfo=timezone.utc),
                          datetime(2026, 8, 4, 10, tzinfo=timezone.utc))
EVERY = Scope.unrestricted()

FLAT = {"@timestamp": {"type": "date"}, "message": {"type": "text"},
        "level": {"type": "keyword"}, "service": {"type": "keyword"},
        "host": {"type": "keyword"}, "request_id": {"type": "keyword"}}


def flat(doc_id, at, message, level="INFO", **extra):
    return dict({"_id": doc_id, "@timestamp": f"2026-08-04T{at}Z",
                 "message": message, "level": level, "service": "svc"}, **extra)


class Cluster(ModelledES):
    """ModelledES with data streams, creation dates and shard failures.

    `streams` maps a data stream's name to {"indices": [backing, ...]} and
    optionally "hidden": True. As in Elasticsearch 8.19, measured on the lab:

      * `_cat/indices` lists the backing indices and never the stream;
      * `GET _data_stream/*` lists the streams, hidden ones only when asked
        with `expand_wildcards` that includes them;
      * a search or a mapping request through the stream's name reaches every
        backing index;
      * a GET by id through the stream's name is `index_not_found_exception`.
    """

    def __init__(self, indices, streams=None, created=None, shards=None):
        super().__init__(indices)
        self.streams = streams or {}
        self.created = created or {}
        self.shards = shards
        self.cat_fails = None
        self.listing_fails = None
        self.gets = []

    def _resolve(self, index):
        names = []
        for name in str(index or "").split(","):
            names.extend(self.streams[name]["indices"] if name in self.streams
                         else [name])
        return names

    def _docs(self, index):
        return super()._docs(",".join(self._resolve(index)))

    @property
    def cat(self):
        outer = self

        class Cat:
            def indices(self, **kw):
                if outer.cat_fails:
                    raise outer.cat_fails
                return [{"index": name,
                         "creation.date": str(outer.created.get(name, 0))}
                        for name in outer._indices]
        return Cat()

    @property
    def indices(self):
        outer = self

        class Indices:
            def get_mapping(self, index=None, **kw):
                return {name: {"mappings": {"properties": outer._indices[name][0]}}
                        for name in outer._resolve(index) if name in outer._indices}

            def get_data_stream(self, name=None, expand_wildcards=None, **kw):
                if outer.listing_fails:
                    raise outer.listing_fails
                wanted = str(expand_wildcards or "open")
                hidden_too = "all" in wanted or "hidden" in wanted
                return {"data_streams": [
                    {"name": stream, "hidden": bool(spec.get("hidden")),
                     "system": False,
                     "indices": [{"index_name": i} for i in spec["indices"]]}
                    for stream, spec in outer.streams.items()
                    if hidden_too or not spec.get("hidden")]}
        return Indices()

    def get(self, index=None, id=None, **kw):
        self.gets.append(index)
        if index in self.streams:
            raise Exception(f"NotFoundError(404, 'index_not_found_exception', "
                            f"'no such index [{index}]', excluded_ds)")
        for hit in self._indices.get(index, ({}, []))[1]:
            if hit["_id"] == id:
                return {"_index": index, "_id": id, "found": True,
                        "_source": copy.deepcopy(hit["_source"])}
        raise Exception("NotFoundError(404, \"{'found': False}\")")

    def search(self, index=None, **kwargs):
        response = super().search(index=index, **kwargs)
        response["timed_out"] = False
        if self.shards:
            response["_shards"] = copy.deepcopy(self.shards)
        return response

    def _aggregate(self, spec, hits):
        """`date_histogram` too, on fixed intervals, without empty buckets:
        the first page of every search from the page asks for one."""
        if "date_histogram" not in spec:
            return super()._aggregate(spec, hits)
        from tests.support import _comparable, _values
        histogram = spec["date_histogram"]
        text = str(histogram.get("fixed_interval") or "1m")
        interval = int(text[:-1]) * {"s": 1000, "m": 60_000, "h": 3_600_000,
                                     "d": 86_400_000}[text[-1]]
        groups = {}
        for hit in hits:
            values = _values(hit["_source"], histogram["field"])
            if values:
                at = int(_comparable(values[0]) * 1000)
                groups.setdefault(at - at % interval, []).append(hit)
        return {"buckets": [dict(
            {"key": key, "doc_count": len(members),
             "key_as_string": datetime.fromtimestamp(key / 1000, timezone.utc)
             .strftime("%Y-%m-%dT%H:%M:%S.000Z")},
            **{name: self._aggregate(sub, members)
               for name, sub in (spec.get("aggs") or {}).items()})
            for key, members in sorted(groups.items())]}


def _app(*sources, indices=("*",), permissions=("logs:read",), traces=()):
    app = create_app(TestConfig)
    hub = Hub()
    for source in sources:
        hub.add_logs(source)
    for source in traces:
        hub.add_traces(source)
    app.hub = hub
    client = app.test_client()
    grant(app, "u", list(permissions), list(indices))
    with client.session_transaction() as session:
        session["user_data"] = _session(list(permissions), list(indices))
        session["_user_id"] = "1"
    return app, client


# ---------------------------------------------------------------------------
# C163: a cluster that cannot be reached is not an empty one
# ---------------------------------------------------------------------------

def _plain_cluster():
    return Cluster({"app-logs-000001": (dict(FLAT), [
        flat("doc-1", "09:30:12.142", "disk usage above threshold")])},
        created={"app-logs-000001": 100})


class AnUnreachableClusterIsNotAnEmptyOneTest(unittest.TestCase):
    """The catalogue answered [] when its first read failed. Every route has
    a branch for "cannot connect", and none of them could be reached: the
    page said no indices existed, and told an administrator with `*` that
    their role could read nothing."""

    def setUp(self):
        self.es = _plain_cluster()
        self.es.cat_fails = ConnectionError("connection refused")
        self.source = ElasticsearchLogSource(self.es)
        self.query = LogQuery(window=WINDOW, text="*")

    def test_the_catalogue_raises_when_it_has_nothing_to_offer(self):
        with self.assertRaisesRegex(Exception, "connection refused"):
            _IndexCatalogue(self.es).entries()

    def test_so_does_the_list_of_containers(self):
        with self.assertRaisesRegex(Exception, "connection refused"):
            self.source.containers(EVERY)

    def test_a_list_it_already_had_is_served_while_it_cannot_read_one(self):
        """Stale beats "you have access to nothing"."""
        self.es.cat_fails = None
        catalogue = _IndexCatalogue(self.es, ttl=0)
        self.assertEqual([e["index"] for e in catalogue.entries()],
                         ["app-logs-000001"])
        self.es.cat_fails = ConnectionError("connection refused")
        self.assertEqual([e["index"] for e in catalogue.entries()],
                         ["app-logs-000001"])

    def test_a_search_says_it_failed(self):
        page = self.source.search(self.query, EVERY)
        self.assertTrue(page.partial)
        self.assertIn("connection refused", " ".join(page.warnings))
        self.assertNotIn("permits no containers", " ".join(page.warnings))

    def test_so_do_the_aggregations(self):
        result = self.source.aggregate(self.query, [Terms("lv", "severity")], EVERY)
        self.assertTrue(result.failed)
        self.assertIn("connection refused", " ".join(result.warnings))
        results = self.source.multi_aggregate(
            [(self.query, [Terms("lv", "severity")])] * 2, EVERY)
        self.assertEqual([r.failed for r in results], [True, True])


class TheRoutesSayTheClusterIsDownTest(unittest.TestCase):
    def setUp(self):
        self.es = _plain_cluster()
        self.es.cat_fails = ConnectionError("connection refused")
        self.app, self.client = _app(ElasticsearchLogSource(self.es))

    def test_the_page_says_it_cannot_connect(self):
        page = self.client.get("/logs").get_data(as_text=True)
        self.assertIn("Unable to connect", page)
        self.assertNotIn("No Access to Log Indices", page)
        self.assertNotIn("No log indices found", page)

    def test_the_search_answers_503(self):
        response = self.client.get(
            f"/api/search?q=*&start_time={START}&end_time={END}")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error_type"],
                         "elasticsearch_connection")

    def test_so_does_the_index_list(self):
        self.assertEqual(self.client.get("/api/indices").status_code, 503)

    def test_a_record_view_answers_503_rather_than_not_found(self):
        for view in ("", "/raw", "/context"):
            with self.subTest(view=view):
                response = self.client.get(f"/api/log/app-logs-000001/doc-1{view}")
                self.assertEqual(response.status_code, 503)
                self.assertIn("connection refused", response.get_json()["error"])


# ---------------------------------------------------------------------------
# C164 / C172: a data stream is a container
# ---------------------------------------------------------------------------

NGINX = "logs-nginx.access-default"
NGINX_1 = f".ds-{NGINX}-2026.08.04-000001"
NGINX_2 = f".ds-{NGINX}-2026.08.04-000002"
OTEL_TRACES = "traces-generic.otel-default"
OTEL_TRACES_1 = f".ds-{OTEL_TRACES}-2026.08.04-000001"
SPAN = {"@timestamp": {"type": "date"}, "trace_id": {"type": "keyword"},
        "span_id": {"type": "keyword"}, "parent_span_id": {"type": "keyword"},
        "kind": {"type": "keyword"}, "name": {"type": "keyword"},
        "duration": {"type": "long"},
        "resource": {"properties": {"attributes": {"properties": {
            "service": {"properties": {"name": {"type": "keyword"}}}}}}}}


def _span(doc_id, service, parent=None):
    return {"_id": doc_id, "@timestamp": "2026-08-04T09:15:00.000Z",
            "trace_id": "t-1", "span_id": doc_id, "parent_span_id": parent,
            "kind": "Server" if parent is None else "Client", "name": "GET /",
            "duration": 5_000_000, "status": {"code": "Ok"},
            "resource": {"attributes": {"service.name": service}}}


def _streaming_cluster():
    return Cluster({
        "app-logs-000001": (dict(FLAT), [flat("a1", "09:10:00.000", "plain one")]),
        NGINX_1: (dict(FLAT), [flat("n1", "09:05:00.000", "nginx one"),
                               flat("n2", "09:20:00.000", "nginx two")]),
        NGINX_2: (dict(FLAT), [flat("n3", "09:40:00.000", "nginx three")]),
        ".ds-ilm-history-7-2026.08.04-000001": (dict(FLAT), [
            flat("h1", "09:12:00.000", "ilm bookkeeping")]),
        OTEL_TRACES_1: (dict(SPAN), [_span("s1", "checkout"),
                                     _span("s2", "postgres", parent="s1")]),
    }, streams={
        NGINX: {"indices": [NGINX_1, NGINX_2]},
        "ilm-history-7": {"indices": [".ds-ilm-history-7-2026.08.04-000001"],
                          "hidden": True},
        OTEL_TRACES: {"indices": [OTEL_TRACES_1]},
    # The plain index is newer than the stream's first backing index and
    # older than its second: the stream is as new as the newest.
    }, created={"app-logs-000001": 250, NGINX_1: 200, NGINX_2: 300,
                ".ds-ilm-history-7-2026.08.04-000001": 400, OTEL_TRACES_1: 250})


class ADataStreamIsAContainerTest(unittest.TestCase):
    """Measured on the lab: its four data streams (heartbeat-8.19.9 and three
    synthetics-*) were in no source's containers, and a stream created for the
    measurement — 48 records in two backing indices — could not be searched,
    opened or granted."""

    def setUp(self):
        self.es = _streaming_cluster()
        self.source = ElasticsearchLogSource(self.es, exclude=("*traces*", "*apm*"))
        self.scope = Scope(principal="dev", containers=("logs-*",))

    def search(self, scope=None):
        return self.source.search(LogQuery(window=WINDOW, text="*",
                                           fields=DEFAULT_LOG_FIELDS),
                                  scope or self.scope)

    def test_the_stream_is_listed_by_its_name_newest_first(self):
        self.assertEqual(self.source.containers(EVERY), [NGINX, "app-logs-000001"])

    def test_a_hidden_stream_is_not(self):
        self.assertNotIn("ilm-history-7", self.source.containers(EVERY))

    def test_a_grant_on_the_stream_s_name_reaches_it(self):
        self.assertEqual(self.source.containers(self.scope), [NGINX])

    def test_a_search_reaches_every_backing_index(self):
        page = self.search()
        self.assertEqual([r.body for r in page.records],
                         ["nginx three", "nginx two", "nginx one"])
        self.assertEqual(page.containers, (NGINX,))

    def test_a_record_names_the_stream_it_was_found_in(self):
        """The name a role is granted and a person recognises, rather than
        the backing index a rollover will replace."""
        self.assertEqual({r.ref.container for r in self.search().records}, {NGINX})

    def test_a_record_in_an_older_backing_index_opens(self):
        oldest = self.search().records[-1]
        record = self.source.fetch(oldest.ref, self.scope)
        self.assertIsNotNone(record)
        self.assertEqual(record.body, "nginx one")
        self.assertEqual(record.ref.container, NGINX)

    def test_the_raw_view_says_which_backing_index_holds_it(self):
        oldest = self.search().records[-1]
        self.assertEqual(self.source.raw(oldest.ref, self.scope)["_index"], NGINX_1)

    def test_the_records_around_one_come_from_the_whole_stream(self):
        middle = self.search().records[1]
        context = self.source.context(middle.ref, self.scope, before=5, after=5)
        self.assertEqual([r.body for r in context.before], ["nginx one"])
        self.assertEqual([r.body for r in context.after], ["nginx three"])

    def test_a_record_in_a_stream_the_role_cannot_read_stays_closed(self):
        ref = SourceRef("elasticsearch", NGINX, "n1")
        self.assertIsNone(self.source.fetch(
            ref, Scope(principal="dev", containers=("app-*",))))

    def test_a_rollover_since_the_list_was_read_still_names_the_stream(self):
        self.search()                             # the catalogue is read now
        newest = f".ds-{NGINX}-2026.08.04-000003"
        document = flat("n4", "09:50:00.000", "nginx four")
        document.pop("_id")
        self.es._indices[newest] = (dict(FLAT), [
            {"_index": newest, "_id": "n4", "_source": document}])
        self.es.streams[NGINX]["indices"].append(newest)
        page = self.search()
        self.assertEqual(page.records[0].body, "nginx four")
        self.assertEqual(page.records[0].ref.container, NGINX)

    def test_a_stream_that_could_not_be_listed_is_said_to_be_missing(self):
        """Its backing indices are in the list and cannot be offered."""
        self.es.listing_fails = RuntimeError("security_exception")
        page = self.search(EVERY)
        self.assertTrue(page.partial)
        self.assertIn("data streams could not be listed", " ".join(page.warnings))
        self.assertIn(NGINX, " ".join(page.warnings))

    def test_and_so_when_it_was_all_a_role_could_reach(self):
        """Not "the scope permits no containers": the role is not the
        reason, and an administrator would be sent to edit it."""
        self.es.listing_fails = RuntimeError("security_exception")
        page = self.search()
        self.assertTrue(page.partial)
        self.assertIn("data streams could not be listed", " ".join(page.warnings))
        self.assertNotIn("permits no containers", " ".join(page.warnings))

    def test_a_stream_the_role_cannot_reach_is_not_named(self):
        self.es.listing_fails = RuntimeError("security_exception")
        page = self.search(Scope(principal="dev", containers=("app-*",)))
        self.assertNotIn(NGINX, " ".join(page.warnings))

    def test_the_trace_source_lists_a_trace_stream(self):
        traces = ElasticsearchTraceSource(self.es)
        self.assertEqual(traces.containers(EVERY), [OTEL_TRACES])
        self.assertEqual(sorted(s.name for s in traces.services(WINDOW, EVERY)),
                         ["checkout", "postgres"])

    def test_and_a_role_granted_the_stream_opens_its_records(self):
        app, client = _app(ElasticsearchLogSource(self.es, name="es"),
                           indices=["logs-*"])
        payload = client.get(f"/api/search?q=*&start_time={START}"
                             f"&end_time={END}").get_json()
        self.assertEqual(payload.get("accessible_containers"), [NGINX], payload)
        oldest = payload["records"][-1]["ref"].split(":", 2)
        for view in ("", "/raw", "/context"):
            with self.subTest(view=view):
                response = client.get(f"/api/log/{oldest[1]}/{oldest[2]}{view}"
                                      "?source=es")
                self.assertEqual(response.status_code, 200,
                                 response.get_data(as_text=True)[:200])


class HeartbeatStreamsAreNotLogsTest(unittest.TestCase):
    """What the fix above would otherwise have done to every deployment with
    Heartbeat: its streams, which WDash already reads as monitors, would have
    become log containers the moment streams were listed."""

    def test_a_stored_log_source_leaves_monitor_data_to_monitors(self):
        """A source added with the exclude box blank — which is how one is
        added — reads past Heartbeat's streams, as the source once declared
        in the environment did."""
        from wdash.hub.adapters.es_monitors import DEFAULT_PATTERNS
        app = create_app(TestConfig)
        app.store.sources.create(
            name="lab-es", signal=["logs"], kind="elasticsearch",
            config={"url": "http://elasticsearch.invalid:9200",
                    "verify_certs": False})
        app.hub.reload()
        log_source = app.hub.logs()
        for pattern in DEFAULT_PATTERNS:
            self.assertIn(pattern, log_source._exclude)


# ---------------------------------------------------------------------------
# C166: a list row reads the record it lists
# ---------------------------------------------------------------------------

#: As the lab's collector (otel/opentelemetry-collector-contrib 0.109.0,
#: `mapping.mode: otel`) wrote them on 2026-09-11, pushed with lab/otel/emit.py.
#: Only the date is moved into this module's window. Do not tidy: a string
#: body lands as `body_text`, a map as `body_structured`, and an empty
#: severity text is not written at all.
LANDED = {
    "information": {
        "@timestamp": "2026-08-04T09:02:28.782894080Z",
        "attributes": {"request_id": "wdash-a-information"},
        "body_text": "dotnet says hello", "dropped_attributes_count": 0,
        "observed_timestamp": "1970-01-01T00:00:00.000000000Z",
        "resource": {"attributes": {"deployment.environment": "lab",
                                    "service.name": "wdash-a-otel"},
                     "dropped_attributes_count": 0},
        "scope": {"dropped_attributes_count": 0},
        "severity_number": 9, "severity_text": "Information",
        "trace_id": "5ef8150a7f5744d1a6074a630d0bab84"},
    "empty-text": {
        "@timestamp": "2026-08-04T09:02:27.782894080Z",
        "attributes": {"request_id": "wdash-a-empty-text"},
        "body_text": "no severity text", "dropped_attributes_count": 0,
        "observed_timestamp": "1970-01-01T00:00:00.000000000Z",
        "resource": {"attributes": {"deployment.environment": "lab",
                                    "service.name": "wdash-a-otel"},
                     "dropped_attributes_count": 0},
        "scope": {"dropped_attributes_count": 0},
        "severity_number": 17, "trace_id": "c660b6620b394d8dbd11864e060a1efc"},
    "free-text": {
        "@timestamp": "2026-08-04T09:02:26.782894080Z",
        "attributes": {"request_id": "wdash-a-free-text"},
        "body_text": "a free-form severity", "dropped_attributes_count": 0,
        "observed_timestamp": "1970-01-01T00:00:00.000000000Z",
        "resource": {"attributes": {"deployment.environment": "lab",
                                    "service.name": "wdash-a-otel"},
                     "dropped_attributes_count": 0},
        "scope": {"dropped_attributes_count": 0},
        "severity_number": 17, "severity_text": "problem",
        "trace_id": "dbf378f4b3da4f6fae60985da3cdaf6d"},
    "map-body": {
        "@timestamp": "2026-08-04T09:02:25.782894080Z",
        "attributes": {"request_id": "wdash-a-map-body"},
        "body_structured": {"code": 17, "event": "structured body"},
        "dropped_attributes_count": 0,
        "observed_timestamp": "1970-01-01T00:00:00.000000000Z",
        "resource": {"attributes": {"deployment.environment": "lab",
                                    "service.name": "wdash-a-otel"},
                     "dropped_attributes_count": 0},
        "scope": {"dropped_attributes_count": 0},
        "severity_number": 17, "severity_text": "ERROR",
        "trace_id": "766a216681274703a0d8bd325118eb0a"},
    # Sent with neither a severity number nor a text: the number is written
    # anyway, as 0.
    "bare-map": {
        "@timestamp": "2026-08-04T09:26:59.640923904Z",
        "attributes": {"request_id": "wdash-a-bare-map"},
        "body_structured": {"event": "bare map body"},
        "dropped_attributes_count": 0,
        "observed_timestamp": "1970-01-01T00:00:00.000000000Z",
        "resource": {"attributes": {"deployment.environment": "lab",
                                    "service.name": "wdash-a-otel"},
                     "dropped_attributes_count": 0},
        "scope": {"dropped_attributes_count": 0},
        "severity_number": 0, "trace_id": "0a05a021b99144fc8da4c04248d4a18b"},
}

#: What an older writer left: a map body under `body`. Not from the lab.
OLDER = {"@timestamp": "2026-08-04T09:01:00.000Z", "body": {"a": 1},
         "severity_number": 17,
         "resource": {"attributes": {"service.name": "older-writer"}}}

OTEL_LOGS = {
    "@timestamp": {"type": "date"}, "severity_number": {"type": "long"},
    "body_text": {"type": "text"},
    "severity_text": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
    "attributes": {"properties": {"request_id": {
        "type": "text", "fields": {"keyword": {"type": "keyword"}}}}},
    "resource": {"properties": {"attributes": {"properties": {
        "deployment": {"properties": {"environment": {"type": "text"}}},
        "service": {"properties": {"name": {"type": "text"}}}}}}},
}


def _collector_cluster(older=False):
    docs = [dict(copy.deepcopy(doc), _id=name) for name, doc in LANDED.items()]
    if older:
        docs.append(dict(copy.deepcopy(OLDER), _id="older"))
    return Cluster({"otel-logs-000001": (dict(OTEL_LOGS), docs)})


class AListRowReadsTheRecordItListsTest(unittest.TestCase):
    """The list asked Elasticsearch for the neutral fields only, and the
    schema is chosen from what the document holds: without
    `severity_number` the number-wins rule could not run, and without
    either marker a collector record was read as a flat one."""

    def setUp(self):
        self.source = ElasticsearchLogSource(_collector_cluster(older=True),
                                             name="otel")
        self.rows = {r.ref.id: r for r in self.source.search(
            LogQuery(window=WINDOW, text="*", fields=DEFAULT_LOG_FIELDS),
            EVERY).records}

    def test_every_row_reads_as_its_record_does(self):
        self.assertEqual(sorted(self.rows), sorted(list(LANDED) + ["older"]))
        for name, row in self.rows.items():
            detail = self.source.fetch(row.ref, EVERY)
            with self.subTest(record=name):
                self.assertEqual((row.body, row.severity, row.service),
                                 (detail.body, detail.severity, detail.service))

    def test_the_number_decides_the_level_in_the_list(self):
        self.assertEqual({name: row.severity for name, row in self.rows.items()},
                         {"information": "INFO", "empty-text": "ERROR",
                          "free-text": "ERROR", "map-body": "ERROR",
                          "bare-map": "UNSPECIFIED", "older": "ERROR"})

    def test_a_structured_body_is_shown_rather_than_nothing(self):
        for name, words in (("map-body", "structured body"),
                            ("bare-map", "bare map body"), ("older", '"a": 1')):
            for body in (self.rows[name].body,
                         self.source.fetch(self.rows[name].ref, EVERY).body):
                with self.subTest(record=name):
                    self.assertIn(words, body)
        self.assertEqual(self.rows["map-body"].service, "wdash-a-otel")

    def test_the_records_around_one_read_the_same_way(self):
        context = self.source.context(self.rows["free-text"].ref, EVERY)
        levels = {r.ref.id: r.severity for r in context.before + context.after}
        self.assertEqual(levels, {"information": "INFO", "empty-text": "ERROR",
                                  "map-body": "ERROR", "bare-map": "UNSPECIFIED",
                                  "older": "ERROR"})


# ---------------------------------------------------------------------------
# C167: the histogram stacks to its count
# ---------------------------------------------------------------------------

class _Histogram:
    """An answer with a timeline, split or not by severity."""

    def __init__(self, mapping, buckets):
        self.mapping, self.buckets = mapping, buckets

    def ping(self):
        return True

    @property
    def cat(self):
        class Cat:
            def indices(self, **kw):
                return [{"index": "app-logs-000001", "creation.date": "1"}]
        return Cat()

    @property
    def indices(self):
        outer = self

        class Indices:
            def get_mapping(self, index=None, **kw):
                return {"app-logs-000001": {"mappings": {"properties": outer.mapping}}}
        return Indices()

    def search(self, index=None, **kw):
        return {"took": 1, "timed_out": False,
                "hits": {"total": {"value": 0}, "hits": []},
                "aggregations": {"timeline": {"buckets": self.buckets}}}


class TheHistogramStacksToItsCountTest(unittest.TestCase):
    """Raw levels that normalise to one level overwrote each other, and the
    page stacks by_severity rather than drawing the count: INFO 900 + info
    100 + WARNING 60 + WARN 40 in a bucket of 1100 drew as 140."""

    def histogram(self, mapping, buckets):
        page = ElasticsearchLogSource(_Histogram(mapping, buckets)).search(
            LogQuery(window=WINDOW, histogram=True), EVERY)
        return page.histogram

    def bucket(self, count, severities):
        return {"key": 0, "key_as_string": START, "doc_count": count,
                "severity": {"buckets": [{"key": k, "doc_count": n}
                                         for k, n in severities]}}

    def test_spellings_of_one_level_add_up(self):
        [bucket] = self.histogram({"level": {"type": "keyword"}}, [self.bucket(
            1100, [("INFO", 900), ("info", 100), ("WARNING", 60), ("WARN", 40)])])
        self.assertEqual(bucket["by_severity"], {"INFO": 1000, "WARN": 100})

    def test_records_with_no_level_are_drawn_as_unspecified(self):
        """Missing the field, or beyond the ten levels asked for: counted,
        not dropped, so the bar is as tall as the count says."""
        [bucket] = self.histogram({"level": {"type": "keyword"}},
                                  [self.bucket(10, [("INFO", 6)])])
        self.assertEqual(bucket["by_severity"], {"INFO": 6, "UNSPECIFIED": 4})
        self.assertEqual(sum(bucket["by_severity"].values()), bucket["count"])

    def test_an_unsplit_histogram_is_left_unsplit(self):
        """No level field to split by: the page draws the count itself."""
        [bucket] = self.histogram({"body": {"type": "text"}},
                                  [{"key": 0, "key_as_string": START,
                                    "doc_count": 10}])
        self.assertEqual(bucket["by_severity"], {})


# ---------------------------------------------------------------------------
# C170: the records around one, to the millisecond
# ---------------------------------------------------------------------------

class TheRecordsAroundOneTest(unittest.TestCase):
    """The anchor was cut to the second. Measured on the lab: of a second
    holding three records, the two beside the one opened were in neither
    list."""

    def setUp(self):
        self.source = ElasticsearchLogSource(Cluster({"app-logs-000001": (
            dict(FLAT), [flat("a", "09:30:11.900", "a, the second before"),
                         flat("b", "09:30:12.050", "b, same second, before"),
                         flat("c", "09:30:12.142", "c, the one opened"),
                         flat("x", "09:30:12.142", "x, same millisecond"),
                         flat("d", "09:30:12.500", "d, same second, after"),
                         flat("e", "09:30:13.000", "e, the second after")])}))
        self.context = self.source.context(
            SourceRef("elasticsearch", "app-logs-000001", "c"), EVERY)
        self.before = [r.ref.id for r in self.context.before]
        self.after = [r.ref.id for r in self.context.after]

    def test_the_same_second_is_on_the_right_side(self):
        self.assertEqual(self.before[:2], ["a", "b"])
        self.assertEqual(self.after, ["d", "e"])

    def test_the_record_itself_is_in_neither(self):
        self.assertNotIn("c", self.before + self.after)

    def test_one_in_the_same_millisecond_is_shown_once(self):
        self.assertEqual((self.before + self.after).count("x"), 1)


# ---------------------------------------------------------------------------
# C168: shards that failed are said
# ---------------------------------------------------------------------------

SHARDS_FAILED = {"total": 6, "successful": 1, "skipped": 0, "failed": 5,
                 "failures": [{"shard": 0, "index": "bad-logs-000001", "reason": {
                     "type": "query_shard_exception",
                     "reason": 'failed to create query: For input string: "abc"'}}]}


class FailedShardsAreSaidTest(unittest.TestCase):
    """Elasticsearch answers 200 when only some shards fail. Measured on the
    lab with `attr_0:abc OR level:ERROR` over app-logs and bad-logs: five of
    six shards failed and every path said nothing."""

    def source(self, shards):
        return ElasticsearchLogSource(Cluster({"app-logs-000001": (
            dict(FLAT), [flat("doc-1", "09:30:12.142", "one", level="ERROR")])},
            shards=shards))

    def query(self):
        return LogQuery(window=WINDOW, text="level:ERROR")

    def test_the_search_is_partial_and_says_why(self):
        page = self.source(SHARDS_FAILED).search(self.query(), EVERY)
        self.assertTrue(page.partial)
        said = " ".join(page.warnings)
        self.assertIn("5 of 6 shards failed", said)
        self.assertIn("failed to create query", said)

    def test_the_aggregations_say_it_too(self):
        source = self.source(SHARDS_FAILED)
        result = source.aggregate(self.query(), [Terms("lv", "severity")], EVERY)
        self.assertIn("5 of 6 shards failed", " ".join(result.warnings))
        for result in source.multi_aggregate(
                [(self.query(), [Terms("lv", "severity")])] * 2, EVERY):
            self.assertIn("5 of 6 shards failed", " ".join(result.warnings))

    def test_the_field_statistics_say_it_too(self):
        """The review found the other two read paths in this file still
        reading a partial answer as a whole one: on the lab, with 5 of 6
        shards failing, the sidebar drew level/service/host counts of 2789
        beside a result list that said the shards had failed."""
        stats = self.source(SHARDS_FAILED).field_stats(self.query(), EVERY)
        self.assertIn("level", [stat.field for stat in stats])
        self.assertTrue(stats.partial)
        self.assertIn("5 of 6 shards failed", " ".join(stats.warnings))

    def test_and_so_does_the_histogram(self):
        buckets = self.source(SHARDS_FAILED).histogram(self.query(), EVERY)
        self.assertTrue(buckets, "the histogram lost its buckets")
        self.assertTrue(buckets.partial)
        self.assertIn("5 of 6 shards failed", " ".join(buckets.warnings))

    def test_the_sidebar_is_told_the_counts_are_short(self):
        app, client = _app(self.source(SHARDS_FAILED))
        payload = client.get(f"/api/field-stats?q=*&start_time={START}"
                             f"&end_time={END}").get_json()
        self.assertIn("level", [f["field"] for f in payload["fields"]])
        self.assertTrue(payload.get("partial"), payload)
        self.assertIn("5 of 6 shards failed", " ".join(payload.get("warnings", ())))

    def test_a_merged_sidebar_names_whose_shards_failed(self):
        clean = dict(SHARDS_FAILED, successful=6, failed=0, failures=[])
        app, client = _app(
            ElasticsearchLogSource(Cluster({"app-logs-000001": (
                dict(FLAT), [flat("doc-1", "09:30:12.142", "one",
                                  level="ERROR")])}, shards=clean), name="es-a"),
            ElasticsearchLogSource(Cluster({"team-b-logs-000001": (
                dict(FLAT), [flat("doc-2", "09:30:12.142", "two",
                                  level="ERROR")])},
                shards=SHARDS_FAILED), name="es-b"))
        payload = client.get(f"/api/field-stats?q=*&source=*&start_time={START}"
                             f"&end_time={END}").get_json()
        said = " ".join(payload.get("warnings", ()))
        self.assertTrue(payload.get("partial"), payload)
        self.assertIn("es-b", said)
        self.assertIn("5 of 6 shards failed", said)

    def test_a_clean_answer_says_nothing(self):
        clean = dict(SHARDS_FAILED, successful=6, failed=0, failures=[])
        source = self.source(clean)
        page = source.search(self.query(), EVERY)
        self.assertEqual((page.partial, page.warnings), (False, ()))
        self.assertEqual(source.aggregate(self.query(), [Terms("lv", "severity")],
                                          EVERY).warnings, ())
        self.assertEqual(source.field_stats(self.query(), EVERY).warnings, ())
        self.assertEqual(source.histogram(self.query(), EVERY).warnings, ())
        app, client = _app(self.source(clean))
        payload = client.get(f"/api/field-stats?q=*&start_time={START}"
                             f"&end_time={END}").get_json()
        self.assertNotIn("partial", payload)
        self.assertNotIn("warnings", payload)


# ---------------------------------------------------------------------------
# C123: field statistics that failed are not "no field data"
# ---------------------------------------------------------------------------

class _FieldStatsFail(Cluster):
    """The size-0 search, or the mapping request, can be made to fail."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stats_fail = None
        self.mapping_fails = None

    @property
    def indices(self):
        outer, real = self, Cluster.indices.fget(self)

        class Indices:
            def get_mapping(self, index=None, **kw):
                if outer.mapping_fails:
                    raise outer.mapping_fails
                return real.get_mapping(index=index, **kw)

            def get_data_stream(self, **kw):
                return real.get_data_stream(**kw)
        return Indices()

    def search(self, index=None, **kwargs):
        if self.stats_fail and kwargs.get("size") == 0:
            raise self.stats_fail
        return super().search(index=index, **kwargs)


def _stats_cluster():
    return _FieldStatsFail({"app-logs-000001": (dict(FLAT), [
        flat("doc-1", "09:30:12.142", "one", level="ERROR", host="node-1")])})


class FieldStatisticsThatFailedAreSaidTest(unittest.TestCase):
    """Measured on the lab: with the statistics search timing out, the
    sidebar answered 200 {"fields": []} — "No field data available" beside
    the search's own failure."""

    def setUp(self):
        self.es = _stats_cluster()
        self.source = ElasticsearchLogSource(self.es)
        self.query = LogQuery(window=WINDOW, text="*")

    def test_a_failed_search_raises(self):
        self.es.stats_fail = ConnectionError("read timed out")
        with self.assertRaisesRegex(Exception, "read timed out"):
            self.source.field_stats(self.query, EVERY)

    def test_so_does_a_mapping_that_could_not_be_read(self):
        self.es.mapping_fails = PermissionError("security_exception")
        with self.assertRaisesRegex(Exception, "security_exception"):
            self.source.field_stats(self.query, EVERY)

    def test_a_search_beside_a_mapping_it_cannot_read_still_answers(self):
        """Its histogram is left unsplit, as it always was."""
        self.es.mapping_fails = PermissionError("security_exception")
        page = self.source.search(LogQuery(window=WINDOW, text="*", histogram=True),
                                  EVERY)
        self.assertEqual([r.body for r in page.records], ["one"])
        self.assertEqual(page.histogram[0]["by_severity"], {})

    def test_and_that_failure_is_not_remembered(self):
        self.es.mapping_fails = PermissionError("security_exception")
        with self.assertRaises(Exception):
            self.source.field_stats(self.query, EVERY)
        self.es.mapping_fails = None
        self.assertIn("level", [s.field for s in self.source.field_stats(
            self.query, EVERY)])

    def test_a_histogram_that_could_not_be_read_is_not_an_empty_series(self):
        """The same rule, in the method beside it: `[]` is what a quiet
        window looks like, and a search that never answered is not one."""
        self.es.stats_fail = ConnectionError("read timed out")
        buckets = self.source.histogram(self.query, EVERY)
        self.assertEqual(list(buckets), [])
        self.assertIn("read timed out", " ".join(buckets.warnings))

    def test_nor_is_an_answer_that_could_not_be_read(self):
        class Garbled(_FieldStatsFail):
            """A doc_count that is not a number — markup, as measured."""

            def search(self, index=None, **kwargs):
                response = super().search(index=index, **kwargs)
                timeline = (response.get("aggregations") or {}).get("timeline")
                if timeline:
                    timeline["buckets"] = [{"key_as_string": "x",
                                            "doc_count": "<img src=x>"}]
                return response

        source = ElasticsearchLogSource(Garbled({"app-logs-000001": (
            dict(FLAT), [flat("doc-1", "09:30:12.142", "one")])}))
        buckets = source.histogram(self.query, EVERY)
        self.assertEqual(list(buckets), [])
        self.assertIn("not a number", " ".join(buckets.warnings))

    def ask(self, *sources):
        app, client = _app(*sources)
        return client.get(f"/api/field-stats?q=*&start_time={START}"
                          f"&end_time={END}"
                          + ("&source=*" if len(sources) > 1 else ""))

    def test_the_route_answers_503_with_the_reason(self):
        self.es.stats_fail = ConnectionError("read timed out")
        response = self.ask(self.source)
        self.assertEqual(response.status_code, 503)
        self.assertIn("read timed out", response.get_json()["error"])

    def test_and_so_when_the_containers_cannot_be_listed(self):
        self.es.cat_fails = ConnectionError("connection refused")
        response = self.ask(self.source)
        self.assertEqual(response.status_code, 503)
        self.assertIn("connection refused", response.get_json()["error"])

    def test_a_merged_view_names_the_member_that_failed(self):
        broken = _stats_cluster()
        broken.stats_fail = ConnectionError("read timed out")
        response = self.ask(ElasticsearchLogSource(self.es, name="es-a"),
                            ElasticsearchLogSource(broken, name="es-b"))
        payload = response.get_json()
        self.assertEqual(response.status_code, 200, payload)
        self.assertTrue(payload.get("partial"), payload)
        self.assertEqual(payload.get("failed_sources"), ["es-b"])
        self.assertIn("level", [f["field"] for f in payload["fields"]])

    def test_and_answers_503_when_every_member_failed(self):
        self.es.stats_fail = ConnectionError("read timed out")
        broken = _stats_cluster()
        broken.stats_fail = ConnectionError("read timed out")
        response = self.ask(ElasticsearchLogSource(self.es, name="es-a"),
                            ElasticsearchLogSource(broken, name="es-b"))
        self.assertEqual(response.status_code, 503)


# ---------------------------------------------------------------------------
# C318: a filter clicked on a collector record's field matches it
# ---------------------------------------------------------------------------

class AFilterFromTheRecordMatchesItTest(unittest.TestCase):
    """The record view shows a collector record's resource and attributes by
    their own names — `deployment.environment`, `request_id` — and the
    filter icon searches for exactly that. In the document they live under
    `resource.attributes.` and `attributes.`, so the clause matched nothing:
    measured on the lab, 0 of 10 for each, and the exclusion kept all 10."""

    def setUp(self):
        es = _collector_cluster()
        es._indices["app-logs-000001"] = (dict(FLAT), [{
            "_index": "app-logs-000001", "_id": "flat-1", "_source": {
                "@timestamp": "2026-08-04T09:30:12.142Z", "message": "m",
                "level": "INFO", "service": "svc", "request_id": "req-42"}}])
        self.source = ElasticsearchLogSource(es)

    def total(self, text):
        return self.source.search(LogQuery(window=WINDOW, text=text), EVERY).total

    def test_a_resource_attribute_by_its_own_name(self):
        self.assertEqual(self.total('deployment.environment:"lab"'), len(LANDED))

    def test_a_record_attribute_by_its_own_name(self):
        self.assertEqual(self.total('request_id:"wdash-a-map-body"'), 1)

    def test_the_flat_shape_still_matches_where_it_was(self):
        self.assertEqual(self.total('request_id:"req-42"'), 1)

    def test_excluding_one_excludes_it(self):
        self.assertEqual(self.total('NOT request_id:"wdash-a-map-body"'), len(LANDED))

    def test_the_names_the_table_knows_are_not_widened(self):
        from wdash.hub.adapters.es_log_schema import field_candidates, match_candidates
        self.assertEqual(match_candidates("severity"), field_candidates("severity"))
        self.assertEqual(match_candidates("attributes.request_id"),
                         ("attributes.request_id",))


# ---------------------------------------------------------------------------
# C119: the logs page opens for a role that reads any source
# ---------------------------------------------------------------------------

class TheLogsPageAsksEverySourceTest(unittest.TestCase):
    """It asked only the default source. A role granted a second source's
    indices alone — `team-b-*`, or `es-b:*` — got "No Access to Log Indices"
    and no form, while /api/search?source=es-b answered it."""

    def sources(self):
        first = Cluster({"app-logs-000001": (dict(FLAT), [
            flat("a1", "09:10:00.000", "from the default")])})
        second = Cluster({"team-b-logs-000001": (dict(FLAT), [
            flat("b1", "09:10:00.000", "from b")])})
        return (ElasticsearchLogSource(first, name="elasticsearch"),
                ElasticsearchLogSource(second, name="es-b"))

    def test_a_grant_on_the_second_source_opens_the_page(self):
        for indices in (["team-b-*"], ["es-b:*"]):
            app, client = _app(*self.sources(), indices=indices)
            page = client.get("/logs").get_data(as_text=True)
            with self.subTest(indices=indices):
                self.assertIn('id="searchForm"', page)
                self.assertIn('id="sourceSelect"', page)
                self.assertNotIn("No Access to Log Indices", page)

    def test_a_grant_on_nothing_still_does_not(self):
        app, client = _app(*self.sources(), indices=["nothing-*"])
        self.assertIn("No Access to Log Indices",
                      client.get("/logs").get_data(as_text=True))

    def test_the_index_list_answers_for_the_source_it_is_asked_about(self):
        app, client = _app(*self.sources(), indices=["team-b-*"])
        self.assertEqual(client.get("/api/indices?source=es-b").get_json()
                         ["containers"], ["team-b-logs-000001"])
        response = client.get("/api/indices?source=nope")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error_type"], "source_missing")


# ---------------------------------------------------------------------------
# C305: only a flash message closes itself
# ---------------------------------------------------------------------------

class AFlashIsMarkedAsOneTest(unittest.TestCase):
    """The page closed every success and info box after five seconds,
    whatever it was: the traces page's scope notice, the advisor's "No
    findings", the setup and roles notes. Only a flash is meant to go, and
    the bundle now closes only what the layout marks as one."""

    def test_the_layout_marks_its_flash_messages(self):
        import re
        app, client = _app(ElasticsearchLogSource(_plain_cluster()),
                           indices=["nothing-*"])
        page = client.get("/logs").get_data(as_text=True)
        flashes = re.findall(r'<div class="alert [^"]*alert-dismissible[^"]*"[^>]*>',
                             page)
        self.assertTrue(flashes, "no flash was rendered to look at")
        for flash in flashes:
            self.assertIn("data-autodismiss", flash)


# ---------------------------------------------------------------------------
# C122 / C221: the documentation says what the client does
# ---------------------------------------------------------------------------

class TheDocumentationSaysWhatTheClientSendsTest(unittest.TestCase):
    """Three places said the client passes a record's `ref` back without
    interpreting it. The client splits it: the container and the id go in
    the path, and the record's own `source` goes in `?source=`."""

    PLACES = ("docs/hub.md", "README.md", "src/wdash/api/log_routes.py",
              "src/wdash/hub/models.py")

    def test_none_of_them_says_it_is_passed_back_uninterpreted(self):
        for place in self.PLACES:
            with open(os.path.join(ROOT, place)) as handle:
                text = " ".join(handle.read().split())
            with self.subTest(place=place):
                self.assertNotRegex(text, r"(?i)pass(es)? it back without "
                                          r"interpreting|clients pass back "
                                          r"without interpreting|only the "
                                          r"adapter that produced it interprets")

    def test_the_contract_names_what_is_sent(self):
        for place in ("docs/hub.md", "README.md", "src/wdash/api/log_routes.py"):
            with open(os.path.join(ROOT, place)) as handle:
                text = " ".join(handle.read().split())
            with self.subTest(place=place):
                self.assertRegex(text, r"container and (the )?id")
                self.assertIn("source=", text)


# ---------------------------------------------------------------------------
# The review of the commit above: what making the catalogue raise did to the
# routes that did not expect it, and what the model got wrong
# ---------------------------------------------------------------------------

class ATraceStoreThatCannotBeReadIsNotAMissingTraceTest(unittest.TestCase):
    """The correlated-log panel looks a trace up before it searches for its
    records, and it did so outside any try. While the catalogue answered []
    that was a 404; now that it raises, a cluster that was down when a worker
    started turned the panel into an unhandled 500 — an HTML error page to a
    client that reads JSON. Measured with `cat.indices` refusing the
    connection: /api/traces/<id>/logs 500 text/html."""

    TRACE_ID = "a" * 32

    def client(self, cat_fails=None):
        es = Cluster({OTEL_TRACES_1: (dict(SPAN), [_span("s1", "checkout")])},
                     streams={OTEL_TRACES: {"indices": [OTEL_TRACES_1]}})
        es.cat_fails = cat_fails
        app, client = _app(ElasticsearchLogSource(es, exclude=("*traces*",)),
                           permissions=("logs:read", "traces:read"),
                           traces=(ElasticsearchTraceSource(es),))
        # As a deployment answers: a route that raises is a 500 and an HTML
        # page, rather than the exception the test client re-raises.
        app.config["PROPAGATE_EXCEPTIONS"] = False
        return client

    def ask(self, client):
        return client.get(f"/api/traces/{self.TRACE_ID}/logs")

    def test_the_panel_is_told_the_store_could_not_be_read(self):
        response = self.ask(self.client(ConnectionError("connection refused")))
        self.assertEqual(response.status_code, 503,
                         response.get_data(as_text=True)[:200])
        payload = response.get_json()
        self.assertEqual(payload["error_type"], "trace_source_error")
        self.assertIn("connection refused", payload.get("details", ""))

    def test_a_trace_that_is_really_absent_is_still_not_found(self):
        """The failure branch must not swallow the honest answer."""
        response = self.ask(self.client())
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error_type"], "trace_not_found")


class EverySourceBeingDownIsNotAnEmptyDeploymentTest(unittest.TestCase):
    """"A cluster that was down looked empty" was only made true for a
    deployment with ONE source. The page asks every source now, and the
    fan-out swallowed each member's failure: with two Elasticsearch sources
    both refusing connections the page said "No log indices found in
    Elasticsearch" and /api/search?source=* answered 404 no_indices — a
    failure drawn as emptiness, which is the thing this was about."""

    def sources(self, down):
        out = []
        for at in ("a", "b"):
            es = Cluster({f"app-logs-{at}": (dict(FLAT), [
                flat(f"doc-{at}", "09:10:00.000", "one")])})
            out.append(ElasticsearchLogSource(es, name=f"es-{at}"))
            if len(out) <= down:
                es.cat_fails = ConnectionError("connection refused")
        return out

    def client(self, down):
        return _app(*self.sources(down))[1]

    def test_the_page_says_it_cannot_connect(self):
        page = self.client(down=2).get("/logs").get_data(as_text=True)
        self.assertIn("Unable to connect", page)
        self.assertNotIn("No log indices found", page)

    def test_the_search_says_so_rather_than_no_indices(self):
        response = self.client(down=2).get(
            f"/api/search?q=*&source=*&start_time={START}&end_time={END}")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error_type"],
                         "elasticsearch_connection")

    def test_and_so_does_the_index_list(self):
        response = self.client(down=2).get("/api/indices?source=*")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error_type"],
                         "elasticsearch_connection")

    def test_one_source_still_answering_is_still_answered_from(self):
        """Partial failure stays partial: the healthy member still lists."""
        payload = self.client(down=1).get("/api/indices?source=*").get_json()
        self.assertEqual(payload["containers"], ["app-logs-b"])


class TheCommentsSayWhatTheCatalogueDoesTest(unittest.TestCase):
    """The same fault as C122 and C221, left behind by their own commit:
    `_reaches_no_store` still said the Elasticsearch catalogue "answers []
    then rather than raising", which is what was changed. A comment that
    describes the opposite of the code is how the next reader decides the
    except branch below it is dead."""

    def test_the_trace_route_does_not_say_the_catalogue_answers_empty(self):
        with open(os.path.join(ROOT, "src/wdash/api/trace_routes.py")) as handle:
            text = " ".join(handle.read().split())
        self.assertNotIn("answers [] then rather than raising", text)
        self.assertRegex(text, r"(?i)catalogue raises")

    def test_and_an_outage_is_not_reported_as_the_role_s_doing(self):
        from wdash.api.trace_routes import _reaches_no_store
        es = Cluster({OTEL_TRACES_1: (dict(SPAN), [_span("s1", "checkout")])})
        es.cat_fails = ConnectionError("connection refused")
        self.assertFalse(_reaches_no_store(ElasticsearchTraceSource(es), EVERY))


class TheModelAnalysesWhatTheClusterAnalysesTest(unittest.TestCase):
    """`ModelledES` evaluates the query it is sent, which is why it is
    preferred to a fake that ignores it — so where it is more permissive than
    Elasticsearch, a test can pass over a product that answers nothing. It
    analysed every field, keyword fields included, and Elasticsearch does not
    analyse those. Measured on the lab's app-logs-000001, where `service` is
    a keyword holding 'search-service': {"match_phrase": {"service":
    "search"}} answers 0 hits and {"match_phrase": {"service":
    "search-service"}} 5140; the model said True to both."""

    def hits(self, text):
        source = ElasticsearchLogSource(Cluster({"app-logs-000001": (
            dict(FLAT), [flat("doc-1", "09:30:12.142",
                              "disk usage above threshold",
                              service="payment-service",
                              note="disk failure imminent")])}))
        return source.search(LogQuery(window=WINDOW, text=text), EVERY).total

    def test_a_word_of_a_keyword_value_is_not_a_match(self):
        for text in ('service:"payment"', "service:payment"):
            with self.subTest(text=text):
                self.assertEqual(self.hits(text), 0)

    def test_the_whole_value_is(self):
        self.assertEqual(self.hits('service:"payment-service"'), 1)

    def test_a_text_field_is_still_analysed(self):
        self.assertEqual(self.hits('message:"disk usage"'), 1)

    def test_and_so_is_one_the_mapping_does_not_know(self):
        """Elasticsearch maps a new string field as text with a keyword
        sub-field, so a word of it matches. Analysed is the right default."""
        self.assertEqual(self.hits('note:"disk failure"'), 1)

    def test_the_model_reads_the_mapping_it_is_given(self):
        from tests.support import es_query_matches
        doc = {"service": "payment-service", "severity_text": "ERROR"}
        keyword = {"service": {"type": "keyword"}}
        text = {"service": {"type": "text"}}
        multi = {"severity_text": {"type": "text", "fields": {
            "keyword": {"type": "keyword"}}}}
        for clause, mapping, expected in (
                ({"match_phrase": {"service": "payment"}}, keyword, False),
                ({"match": {"service": {"query": "payment"}}}, keyword, False),
                ({"match_phrase": {"service": "payment-service"}}, keyword, True),
                ({"match_phrase": {"service": "payment"}}, text, True),
                ({"match_phrase": {"service": "payment"}}, None, True),
                # A multi-field: the sub-field is the keyword, the field is not.
                ({"match": {"severity_text.keyword": "ERRO"}}, multi, False),
                ({"match": {"severity_text.keyword": "ERROR"}}, multi, True)):
            with self.subTest(clause=clause, mapping=mapping):
                self.assertEqual(
                    es_query_matches(clause, doc, mapping=mapping), expected)


if __name__ == "__main__":
    unittest.main()
