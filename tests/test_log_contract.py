"""
Wire contract for the log endpoints.

These tests lock the response shape `static/js/wdash.js` depends on. That shape
is now the neutral model: `records` / `body` / `severity` / `resource` /
`attributes`. Elasticsearch's `hits` and `_source` form never appears on the
wire.

The source is not mocked: a fake Elasticsearch is used so the real adapter and
the real Scope run.
"""

import json
import os
import sys
import unittest

from tests.support import search_body

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402

START = "2026-08-04T09:00:00Z"
END = "2026-08-04T10:00:00Z"

# A raw document in the shape Elasticsearch returns, milliseconds included
DOC = {
    "@timestamp": "2026-08-04T09:30:12.142Z",
    "level": "WARNING",          # deliberate: normalises to WARN
    "message": "disk usage above threshold",
    "service": "payment-service",
    "host": "node-3",
    "environment": "production",
    "request_id": "req-42",
    "duration_ms": 1234,
}


class FakeES:
    def __init__(self):
        self.searches = []

    def ping(self):
        return True

    @property
    def cat(self):
        outer = self

        class Cat:
            def indices(self, **kw):
                # Deliberately NOT alphabetical, with creation dates. The
                # previous behaviour put the newest first; the contract keeps it.
                return [
                    {"index": "app-logs-000001", "creation.date": "100"},
                    {"index": "zzz-logs-000001", "creation.date": "300"},
                    {"index": "infra-logs-000001", "creation.date": "200"},
                    {"index": ".hidden-system", "creation.date": "400"},
                ]
        return Cat()

    @property
    def indices(self):
        class Indices:
            def get_mapping(self, index=None, **kw):
                return {index or "app-logs-000001": {"mappings": {"properties": {
                    "level": {"type": "keyword"},
                    "service": {"type": "keyword"},
                    "message": {"type": "text"},
                }}}}
        return Indices()

    def get(self, index=None, id=None, **kw):
        if id != "doc-1":
            raise Exception("NotFoundError(404, \"{'found': False}\")")
        return {"_index": index, "_id": id, "_source": dict(DOC)}

    def search(self, index=None, **kwargs):
        body = search_body(kwargs)
        self.searches.append({"index": index, "body": body})
        if body.get("size") == 0:
            return {"hits": {"total": {"value": 0}, "hits": []},
                    "aggregations": {
                        "level": {"buckets": [{"key": "ERROR", "doc_count": 7},
                                              {"key": "INFO", "doc_count": 93}]},
                        "service": {"buckets": [{"key": "payment-service",
                                                 "doc_count": 100}]},
                        "message": {"buckets": []},
                    }}
        return {
            "took": 12,
            "timed_out": False,
            "hits": {
                "total": {"value": 57},
                "hits": [{"_index": "app-logs-000001", "_id": "doc-1",
                          "_score": None, "sort": [1754300000000, 5],
                          "_source": dict(DOC)}],
            },
        }


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "contract"
    # This module is about WIRING — that the log source is built excluding the
    # trace patterns. It needs a source to exist, not one that answers, so the
    # address is deliberately unresolvable: nothing here should be able to
    # reach a real cluster by accident, which is how these tests spent a year
    # quietly talking to the development lab on port 9200.
    ELASTICSEARCH_URL = "http://elasticsearch.invalid:9200"


def _session(permissions, indices=("*",)):
    return {"id": "1", "email": "u@x", "username": "u", "groups": [], "role": "admin",
            "permissions": list(permissions), "allowed_indices": list(indices),
            "allowed_trace_indices": ["*"], "allowed_services": ["*"]}


class LogContractTest(unittest.TestCase):
    def setUp(self):
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource

        self.es = FakeES()
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.es))
        hub.add_traces(ElasticsearchTraceSource(self.es))
        self.app.hub = hub
        self.client = self.app.test_client()
        self.login(["logs:read"])

    def login(self, permissions, indices=("*",)):
        from tests.support import grant
        grant(self.app, "u", permissions, indices)
        data = _session(permissions, indices)
        with self.client.session_transaction() as session:
            session["user_data"] = data
            session["_user_id"] = "1"

    def search(self, extra=""):
        return self.client.get(
            f"/api/search?q=*&size=5&start_time={START}&end_time={END}{extra}")

    # ---------- /api/search ----------

    def test_response_has_every_key_the_client_reads(self):
        payload = self.search().get_json()
        for key in ("records", "total", "took_ms", "partial", "cursor",
                    "containers", "accessible_containers", "user_role",
                    "total_accessible_containers"):
            self.assertIn(key, payload, f"the client reads the '{key}' key")

    def test_response_carries_no_elasticsearch_shape(self):
        """The real measure of the migration: no Elasticsearch shape on the wire."""
        payload = self.search().get_json()
        for leaked in ("hits", "_source", "took", "timed_out",
                       "next_search_after", "accessible_indices"):
            self.assertNotIn(leaked, payload, f"'{leaked}' is still leaking")
        self.assertNotIn("_source", payload["records"][0])

    def test_record_shape(self):
        record = self.search().get_json()["records"][0]
        self.assertEqual(
            sorted(record),
            ["attributes", "body", "ref", "resource", "service", "severity",
             "severity_text", "source", "span_id", "timestamp", "trace_id"])

    def test_the_record_says_which_source_answered(self):
        """The configured name, not the backend type.

        Two Elasticsearch sources both say "elasticsearch"; telling them apart
        is the entire reason this is on the record.
        """
        record = self.search().get_json()["records"][0]
        self.assertEqual(record["source"], "elasticsearch")
        self.assertTrue(record["ref"].startswith("elasticsearch:"))

    def test_ref_is_an_opaque_handle(self):
        """The client must pass ref back rather than interpreting it."""
        record = self.search().get_json()["records"][0]
        self.assertEqual(record["ref"], "elasticsearch:app-logs-000001:doc-1")

    def test_no_field_is_lost_in_translation(self):
        """Every field of the source document must land somewhere in the model."""
        record = self.search().get_json()["records"][0]
        self.assertEqual(record["body"], DOC["message"])
        self.assertEqual(record["service"], DOC["service"])
        self.assertEqual(record["resource"]["host"], DOC["host"])
        self.assertEqual(record["resource"]["environment"], DOC["environment"])
        self.assertEqual(record["attributes"]["request_id"], DOC["request_id"])
        self.assertEqual(record["attributes"]["duration_ms"], DOC["duration_ms"])

    def test_timestamp_keeps_millisecond_precision(self):
        """Truncating to the second makes same-second records indistinguishable."""
        record = self.search().get_json()["records"][0]
        self.assertEqual(record["timestamp"], "2026-08-04T09:30:12.142Z")

    def test_severity_carries_both_forms(self):
        """The normalised value drives styling; the raw value is what is displayed."""
        record = self.search().get_json()["records"][0]
        self.assertEqual(record["severity"], "WARN")        # normalised
        self.assertEqual(record["severity_text"], "WARNING")  # as reported

    def test_pagination_cursor_is_returned(self):
        self.assertEqual(self.search().get_json()["cursor"], [1754300000000, 5])

    def test_cursor_is_passed_back_to_the_backend(self):
        self.client.get(f"/api/search?q=*&start_time={START}&end_time={END}"
                        "&search_after=" + json.dumps([1754300000000, 5]))
        body = self.es.searches[-1]["body"]
        self.assertEqual(body["search_after"], [1754300000000, 5])

    def test_list_view_requests_only_the_fields_it_renders(self):
        """The list view must not fetch full records; response size matters."""
        self.search()
        body = self.es.searches[-1]["body"]
        self.assertIn("_source", body)
        self.assertIn("message", body["_source"])
        self.assertIn("level", body["_source"])

    def test_search_window_is_not_widened_by_alignment(self):
        """When returning raw records the window must be preserved exactly."""
        self.search()
        rng = self.es.searches[-1]["body"]["query"]["bool"]["must"][1]["range"]["@timestamp"]
        self.assertEqual(rng["gte"], "2026-08-04T09:00:00Z")
        self.assertEqual(rng["lte"], "2026-08-04T10:00:00Z")

    # ---------- siralama ----------

    def test_containers_are_ordered_newest_first(self):
        payload = self.search().get_json()
        self.assertEqual(payload["accessible_containers"],
                         ["zzz-logs-000001", "infra-logs-000001", "app-logs-000001"])

    def test_system_indices_are_hidden(self):
        self.assertNotIn(".hidden-system", self.search().get_json()["accessible_containers"])

    # ---------- hata sekilleri ----------

    def test_missing_time_range_returns_error_in_body_not_status(self):
        """The client checks data.error first, so the status stays 200."""
        response = self.client.get("/api/search?q=*&size=5")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["error_type"], "time_range_required")
        self.assertEqual(payload["records"], [])
        self.assertIn("accessible_containers", payload)

    def test_inverted_range_is_rejected(self):
        response = self.client.get(
            f"/api/search?q=*&start_time={END}&end_time={START}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error_type"], "validation_error")

    def test_permission_gate(self):
        """Searching is reading: one permission, not two.

        They used to be separate and neither role was usable — `logs:read`
        alone opened a page where every search failed, and `logs:search` alone
        worked in the API while the page refused to load.
        """
        self.login([])                            # no log permission at all
        response = self.search()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error_type"], "permission_denied")

    def test_no_accessible_indices(self):
        """The names of what a role cannot read are what the boundary holds
        back. They went to any role that reached nothing here; the
        dashboards had already stopped naming them."""
        self.login(["logs:read"], indices=["nothing-*"])
        response = self.search()
        self.assertEqual(response.status_code, 403)
        payload = response.get_json()
        self.assertEqual(payload["error_type"], "no_accessible_containers")
        self.assertNotIn("available_indices", payload)
        self.assertGreater(payload["total_containers"], 0)

    def test_the_logs_page_does_not_name_them_either(self):
        self.login(["logs:read"], indices=["nothing-*"])
        page = self.client.get("/logs", follow_redirects=True).data
        self.assertIn(b"exist that it cannot read", page)
        self.assertNotIn(b"app-logs-000001", page)

    def test_an_administrator_is_told_the_names(self):
        self.login(["logs:read", "system:admin"], indices=["nothing-*"])
        payload = self.search().get_json()
        self.assertTrue(payload["available_indices"])

    def test_scope_narrows_the_queried_indices(self):
        self.login(["logs:read"], indices=["app-*"])
        payload = self.search().get_json()
        self.assertEqual(payload["containers"], ["app-logs-000001"])
        self.assertEqual(self.es.searches[-1]["index"], "app-logs-000001")

    # ---------- dokuman detayi ----------

    def test_document_detail_shape(self):
        payload = self.client.get("/api/log/app-logs-000001/doc-1").get_json()
        self.assertTrue(payload["found"])
        self.assertEqual(payload["record"]["ref"],
                         "elasticsearch:app-logs-000001:doc-1")
        self.assertEqual(payload["record"]["body"], DOC["message"])
        self.assertNotIn("_source", payload)

    def test_missing_document_reports_not_found(self):
        response = self.client.get("/api/log/app-logs-000001/nope")
        self.assertEqual(response.status_code, 404)
        payload = response.get_json()
        self.assertFalse(payload["found"])
        self.assertEqual(payload["error_type"], "not_found")
        # Raw exception text must not leak out
        self.assertNotIn("NotFoundError", payload["error"])

    def test_document_outside_scope_is_refused(self):
        self.login(["logs:read"], indices=["other-*"])
        response = self.client.get("/api/log/app-logs-000001/doc-1")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error_type"], "index_access_denied")

    # ---------- raw document ----------
    #
    # The deliberate exception to the neutral wire format. It exists so an
    # operator can tell "this field never arrived" from "we failed to map it";
    # the neutral record alone cannot answer that.

    def test_raw_returns_the_stored_document_untranslated(self):
        payload = self.client.get("/api/log/app-logs-000001/doc-1/raw").get_json()
        self.assertTrue(payload["found"])
        self.assertEqual(payload["backend"], "elasticsearch")
        self.assertEqual(payload["document"]["_source"], DOC)
        self.assertEqual(payload["document"]["_index"], "app-logs-000001")

    def test_raw_keeps_the_original_field_names(self):
        """The point of the raw view: names the neutral model renames away.

        `message`/`level` become `body`/`severity` in the record, and WARNING
        is normalised to WARN. Someone debugging an ingest pipeline needs to
        see what was actually written.
        """
        raw = self.client.get("/api/log/app-logs-000001/doc-1/raw").get_json()
        source = raw["document"]["_source"]
        self.assertEqual(source["level"], "WARNING")
        self.assertIn("message", source)

        record = self.client.get("/api/log/app-logs-000001/doc-1").get_json()["record"]
        self.assertEqual(record["severity"], "WARN")
        self.assertNotIn("message", record)

    def test_raw_is_refused_outside_the_scope(self):
        """The escape hatch must not be a way around the index boundary."""
        self.login(["logs:read"], indices=["other-*"])
        response = self.client.get("/api/log/app-logs-000001/doc-1/raw")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error_type"], "index_access_denied")

    def test_raw_requires_the_read_permission(self):
        self.login([], indices=["*"])
        self.assertEqual(
            self.client.get("/api/log/app-logs-000001/doc-1/raw").status_code, 403)

    def test_raw_missing_document_reports_not_found(self):
        response = self.client.get("/api/log/app-logs-000001/nope/raw")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("NotFoundError", response.get_json()["error"])

    def test_raw_is_a_declared_capability(self):
        """A source that cannot serve it must say so, not fake an empty answer."""
        from wdash.hub import Capability
        from wdash.hub.source import LogSource

        self.assertIn(Capability.RAW_DOCUMENT, self.app.hub.logs().capabilities)

        class Minimal(LogSource):
            name = "minimal"
            backend = "minimal"
            capabilities = frozenset({Capability.SEARCH})

            def health(self):
                return True, "ok"

            def containers(self, scope):
                return []

            def search(self, query, scope):
                return None

            def fetch(self, ref, scope):
                return None

        with self.assertRaises(NotImplementedError):
            Minimal().raw(None, None)

    # ---------- context ----------

    def test_context_shape(self):
        payload = self.client.get(
            "/api/log/app-logs-000001/doc-1/context?count=3").get_json()
        self.assertEqual(sorted(payload),
                         ["after", "before", "correlated_by", "record"])
        self.assertEqual(payload["record"]["ref"],
                         "elasticsearch:app-logs-000001:doc-1")
        self.assertEqual(payload["record"]["timestamp"], "2026-08-04T09:30:12.142Z")

    def test_context_correlation_adds_a_term_filter(self):
        self.client.get("/api/log/app-logs-000001/doc-1/context?count=3&field=host")
        clauses = self.es.searches[-1]["body"]["query"]["bool"]["must"]
        self.assertTrue(any(c.get("term", {}).get("host") == "node-3" for c in clauses),
                        f"host correlation did not reach the query: {clauses}")

    def test_context_count_is_capped(self):
        self.client.get("/api/log/app-logs-000001/doc-1/context?count=9999")
        self.assertLessEqual(self.es.searches[-1]["body"]["size"], 50)

    # ---------- field stats ----------

    def test_field_stats_shape(self):
        payload = self.client.get(
            f"/api/field-stats?q=*&start_time={START}&end_time={END}").get_json()
        self.assertIn("fields", payload)
        level = next(f for f in payload["fields"] if f["field"] == "level")
        self.assertEqual(level["values"][0], {"value": "ERROR", "count": 7})

    def test_field_stats_are_aligned_for_caching(self):
        """Aggregations run with request_cache, so bounds must be aligned."""
        self.client.get("/api/field-stats?q=*"
                        "&start_time=2026-08-04T09:00:12.345Z"
                        "&end_time=2026-08-04T10:00:12.345Z")
        rng = self.es.searches[-1]["body"]["query"]["bool"]["must"][1]["range"]["@timestamp"]
        self.assertEqual(rng["gte"], "2026-08-04T09:00:00Z")
        self.assertNotIn(".", rng["gte"])

    # ---------- indices ----------

    def test_indices_shape(self):
        payload = self.client.get("/api/indices").get_json()
        self.assertEqual(sorted(payload),
                         ["accessible_containers", "containers",
                          "total_containers", "user_role"])
        self.assertEqual(payload["containers"][0], "zzz-logs-000001")

    # ---------- sayfa ----------

    def test_logs_page_renders(self):
        response = self.client.get("/logs")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log Viewer", response.data)

    def test_logs_page_without_permission_redirects(self):
        self.login(["dashboard:view"])
        self.assertEqual(self.client.get("/logs").status_code, 302)


class RecordingES(FakeES):
    """FakeES that remembers which indices it was asked to GET."""

    def __init__(self):
        super().__init__()
        self.gets = []

    def get(self, index=None, id=None, **kw):
        self.gets.append(index)
        return super().get(index=index, id=id, **kw)


class TheRecordIsReadFromItsOwnSourceTest(unittest.TestCase):
    """The record, raw and context views, and the source a record lives in.

    They asked the DEFAULT source whatever the record's origin, with a
    hard-coded `elasticsearch` handle, and checked the container without
    saying which source it came from. So a role's source-qualified rules were
    not consulted at all — `*` with `-primary:app-*` was refused `app-*` by
    the search and handed it here — and a record from a second source was
    looked up in the first.
    """

    def setUp(self):
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource

        self.primary, self.secondary = RecordingES(), RecordingES()
        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.primary, name="primary"))
        hub.add_logs(ElasticsearchLogSource(self.secondary, name="secondary"))
        self.app.hub = hub
        self.client = self.app.test_client()

    def login(self, indices):
        from tests.support import grant
        grant(self.app, "u", ["logs:read"], indices)
        with self.client.session_transaction() as session:
            session["user_data"] = _session(["logs:read"], indices)
            session["_user_id"] = "1"

    VIEWS = ("", "/raw", "/context")

    def views(self, container="app-logs-000001", source=None):
        query = f"?source={source}" if source else ""
        return {view or "/": self.client.get(
                    f"/api/log/{container}/doc-1{view}{query}")
                for view in self.VIEWS}

    def test_a_scoped_exclusion_holds_on_every_record_view(self):
        self.login(["*", "-primary:app-*"])
        for named in ("primary", None):          # None: the default source
            for view, response in self.views(source=named).items():
                with self.subTest(view=view, source=named):
                    self.assertEqual(response.status_code, 403)
        self.assertEqual(self.primary.gets, [], "the excluded record was read")

    def test_a_scoped_grant_opens_them_in_its_source_only(self):
        """The other half: a role granted only `primary:app-*` was refused
        every record, because the check never said which source it was."""
        self.login(["primary:app-*"])
        opened = self.views(source="primary")
        for view, response in opened.items():
            with self.subTest(view=view):
                self.assertEqual(response.status_code, 200,
                                 response.get_data(as_text=True)[:200])
        for view, response in self.views(source="secondary").items():
            with self.subTest(view=view, source="secondary"):
                self.assertEqual(response.status_code, 403)

    def test_the_record_is_read_from_the_source_it_came_from(self):
        self.login(["*"])
        response = self.client.get(
            "/api/log/app-logs-000001/doc-1?source=secondary")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.secondary.gets, ["app-logs-000001"])
        self.assertEqual(self.primary.gets, [])

    def test_one_record_is_not_asked_of_every_source(self):
        self.login(["*"])
        response = self.client.get("/api/log/app-logs-000001/doc-1?source=*")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error_type"], "source_missing")

    def test_a_container_expression_is_not_a_container(self):
        """The container arrives from a URL and Elasticsearch reads it as an
        index EXPRESSION. `*-logs-*` matched the grant `*` as a string, so
        the views sent it to a GET and a search — reaching `zzz-logs-*`,
        which the role excludes."""
        self.login(["*", "-zzz-*"])
        for container in ("*-logs-*", "app-logs-000001,zzz-logs-000001"):
            for view, response in self.views(container=container,
                                             source="primary").items():
                with self.subTest(container=container, view=view):
                    self.assertIn(response.status_code, (403, 404))
        self.assertEqual(self.primary.gets, [])
        self.assertFalse(any("*" in str(s["index"]) or "," in str(s["index"])
                             for s in self.primary.searches),
                         f"an expression reached a search: "
                         f"{[s['index'] for s in self.primary.searches]}")

    def test_a_document_answered_from_another_index_is_not_handed_back(self):
        """A GET through a name that is not the index the document lives in —
        an alias, say — answers from the index behind it. That index is
        checked against the scope too, not only the name that was asked."""
        class AliasingES(RecordingES):
            def get(self, index=None, id=None, **kw):
                answer = super().get(index=index, id=id, **kw)
                return dict(answer, _index="zzz-logs-000001")

        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(AliasingES(), name="primary"))
        self.app.hub = hub
        self.login(["*", "-zzz-*"])
        for view in ("", "/raw"):
            with self.subTest(view=view):
                response = self.client.get(
                    f"/api/log/app-logs-000001/doc-1{view}?source=primary")
                self.assertEqual(response.status_code, 404)

    def test_the_handle_names_the_source_backend(self):
        """It was built as `elasticsearch:` whatever the source was."""
        from tests.support import StubLogSource
        from wdash.hub import Hub

        asked = []

        class Recording(StubLogSource):
            def fetch(self, ref, scope):
                asked.append(ref)
                return None

        hub = Hub()
        hub.add_logs(Recording(name="stub", containers=("app-logs-000001",)))
        self.app.hub = hub
        self.login(["*"])
        self.client.get("/api/log/app-logs-000001/doc-1?source=stub")
        self.assertEqual([ref.backend for ref in asked], ["stub"])

    def test_context_is_refused_by_a_source_that_cannot_do_it(self):
        """It had no capability check: a source without CONTEXT raised
        NotImplementedError out of the base class, a 500."""
        from tests.support import StubLogSource
        from wdash.hub import Hub

        hub = Hub()
        hub.add_logs(StubLogSource(name="stub", containers=("app-logs-000001",)))
        self.app.hub = hub
        self.login(["*"])
        response = self.client.get(
            "/api/log/app-logs-000001/doc-1/context?source=stub")
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.get_json()["error_type"], "unsupported")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class FieldStatsCapabilityTest(LogContractTest):
    """A source that cannot provide field statistics is not a broken source.

    The base class raises `NotImplementedError` for an undeclared capability —
    that is the contract, and it is right. The route did not ask first, so
    selecting Loki turned a working page into an HTTP 500 and an empty
    sidebar: a backend behaving exactly as designed, presented as a fault in
    WDash.
    """

    class _NoStats:
        name = "loki-like"
        capabilities = frozenset()

        def supports(self, capability):
            return capability in self.capabilities

        def containers(self, scope):
            return ["stream-a"]

        def field_stats(self, query, scope, **kwargs):
            raise NotImplementedError("no field statistics here")

    def _ask(self, source):
        self.app.hub._logs = {source.name: source}
        return self.client.get(f"/api/field-stats?q=*&source={source.name}"
                               f"&start_time={START}&end_time={END}")

    def test_a_source_without_the_capability_is_not_an_error(self):
        response = self._ask(self._NoStats())
        self.assertEqual(response.status_code, 200)

    def test_the_answer_says_which_source_and_why(self):
        """"No field data available" beside a page full of logs reads as a bug
        in WDash; the reason reads as a property of the backend."""
        payload = self._ask(self._NoStats()).get_json()
        self.assertTrue(payload["unsupported"])
        self.assertIn("loki-like", payload["reason"])
        self.assertEqual(payload["fields"], [])

    def test_the_backend_is_never_asked(self):
        """Asking and catching would work, and would also run a query the
        source cannot answer — on every page load."""
        source = self._NoStats()
        asked = []
        source.field_stats = lambda *a, **k: asked.append(1)
        self._ask(source)
        self.assertEqual(asked, [])

    def test_a_source_with_the_capability_still_answers(self):
        payload = self.client.get(
            f"/api/field-stats?q=*&start_time={START}&end_time={END}").get_json()
        self.assertNotIn("unsupported", payload)


class EmptyResultTest(LogContractTest):
    """An empty result is not a failure, and the client must be able to tell.

    Every empty page with a warning used to come back as an error. Loki's
    "no streams in this window" then arrived on screen in red, worded as an
    authorization boundary — so a time picker set too narrow read as a
    permissions problem, which is a support ticket rather than a scroll.
    """

    class _Quiet:
        name = "quiet"
        capabilities = frozenset()

        def __init__(self, informational):
            self._informational = informational

        def containers(self, scope):
            return ["app-logs"]

        def search(self, query, scope):
            from wdash.hub.models import LogPage
            return LogPage(warnings=("nothing in this time range",),
                           informational=self._informational)

    def _search_with(self, informational):
        self.app.hub._logs = {"quiet": self._Quiet(informational)}
        return self.client.get(
            f"/api/search?q=*&size=5&start_time={START}&end_time={END}"
            "&source=quiet")

    def test_a_note_comes_back_as_an_empty_result(self):
        response = self._search_with(informational=True)
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(payload.get("error_type"),
                          "a quiet window was reported as a failure")
        self.assertEqual(payload["records"], [])
        self.assertIn("nothing in this time range", payload["warnings"],
                      "the reason was dropped along with the error")

    def test_a_fault_still_comes_back_as_an_error(self):
        """The softening must not swallow the case it was built around."""
        payload = self._search_with(informational=False).get_json()
        self.assertEqual(payload.get("error_type"), "search_error")


class FieldDiscoveryTest(unittest.TestCase):
    """Field discovery must scan every target, not just the first.

    Indices are ordered newest first. When an index whose top-level fields are
    all objects (an APM trace store, say) lands at the head of the list, a
    discovery that looks at one index finds nothing and the sidebar silently
    goes blank.
    """

    class MixedES(FakeES):
        @property
        def indices(self):
            class Indices:
                def get_mapping(self, index=None, **kw):
                    return {
                        # Newest index: all objects — empty if examined alone
                        "apm-traces-000001": {"mappings": {"properties": {
                            "@timestamp": {"type": "date"},
                            "service": {"properties": {"name": {"type": "keyword"}}},
                            "transaction": {"properties": {}},
                        }}},
                        "app-logs-000001": {"mappings": {"properties": {
                            "level": {"type": "keyword"},
                            "host": {"type": "keyword"},
                            "message": {"type": "text"},
                            "tag": {"type": "text",
                                    "fields": {"keyword": {"type": "keyword"}}},
                        }}},
                    }
            return Indices()

    def setUp(self):
        from wdash.hub.adapters import ElasticsearchLogSource
        self.source = ElasticsearchLogSource(self.MixedES())

    def test_fields_are_discovered_across_all_targets(self):
        found = self.source._aggregatable_fields(
            ["apm-traces-000001", "app-logs-000001"])
        self.assertIn("level", found)
        self.assertIn("host", found)

    def test_priority_fields_come_first(self):
        found = self.source._aggregatable_fields(
            ["apm-traces-000001", "app-logs-000001"])
        self.assertEqual(list(found)[0], "level")

    def test_text_fields_use_keyword_subfield(self):
        found = self.source._aggregatable_fields(["app-logs-000001"])
        self.assertEqual(found["tag"], "tag.keyword")

    def test_message_is_never_aggregated(self):
        found = self.source._aggregatable_fields(["app-logs-000001"])
        self.assertNotIn("message", found)

    def test_no_targets_is_safe(self):
        self.assertEqual(self.source._aggregatable_fields([]), {})


class HistogramTest(LogContractTest):
    """Volume over time rides on the search response."""

    def test_first_page_asks_for_a_histogram(self):
        self.search()
        self.assertIn("aggs", self.es.searches[-1]["body"])
        self.assertIn("timeline", self.es.searches[-1]["body"]["aggs"])

    def test_histogram_costs_no_extra_request(self):
        """A separate call would double the round trips for data the search
        already had to scan."""
        self.es.searches.clear()
        self.search()
        self.assertEqual(len(self.es.searches), 1)

    def test_paging_does_not_re_request_it(self):
        """The histogram covers the whole window and does not change per page."""
        import json
        self.client.get(f"/api/search?q=*&start_time={START}&end_time={END}"
                        "&search_after=" + json.dumps([1, 2]))
        self.assertNotIn("aggs", self.es.searches[-1]["body"])

    def test_histogram_is_split_by_severity(self):
        self.search()
        timeline = self.es.searches[-1]["body"]["aggs"]["timeline"]
        self.assertIn("severity", timeline.get("aggs", {}))

    def test_response_carries_the_histogram_key(self):
        self.assertIn("histogram", self.search().get_json())


class SignalSeparationTest(unittest.TestCase):
    """Logs and traces share a cluster; a log search must not return spans.

    This was a real defect: with the log source matching `*`, trace documents
    came back as records with no body and no severity. On a page of 200 there
    were 93 of them.
    """

    class MixedES(FakeES):
        @property
        def cat(self):
            class Cat:
                def indices(self, **kw):
                    return [{"index": "app-logs-000001", "creation.date": "100"},
                            {"index": "otel-traces-000001", "creation.date": "200"},
                            {"index": "apm-traces-000001", "creation.date": "300"}]
            return Cat()

    def _source(self, **kwargs):
        from wdash.hub.adapters import ElasticsearchLogSource
        return ElasticsearchLogSource(self.MixedES(), **kwargs)

    def test_trace_indices_are_excluded_when_configured(self):
        from wdash.hub import Scope
        source = self._source(exclude=("*traces*", "*apm*"))
        self.assertEqual(source.containers(Scope.unrestricted()), ["app-logs-000001"])

    def test_without_exclusion_they_leak_in(self):
        """Documents the behaviour the exclusion exists to prevent."""
        from wdash.hub import Scope
        source = self._source()
        self.assertIn("otel-traces-000001", source.containers(Scope.unrestricted()))

    def test_application_wires_the_exclusion(self):
        """The default deployment must have signal separation switched on."""
        app = create_app(TestConfig)
        log_source = app.hub.logs()
        self.assertTrue(log_source._exclude,
                        "the log source must exclude the trace patterns")
