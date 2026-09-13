"""Which sources a dashboard reads, and what it says about them.

Two rules, and the numbers that show the difference.

**An unnamed source is every source.** A board pinned to nothing reads every
log source and adds them up; its trace and monitor panels read every source
of their signal. It used to read ONE source — whichever was registered first,
which was the environment's cluster while there was one and the oldest
stored row after that. Measured on the demo's five stored sources over a
rolling 24h: an unpinned board answered 1,115 records from the Loki alone,
and its trace list for api-gateway was empty because the oldest trace source
was a Tempo holding no such service; the same board reads 15,431 records
twenty minutes later — 13,245 from the cluster, 1,066 from the Loki, 1,120
from VictoriaLogs — and lists ten api-gateway traces from the cluster.

**A pin is the source, for every signal it serves.** Pinned to a cluster
serving logs, traces and monitors, a board reads all three from it; pinned
to a Loki, its logs from the Loki and its traces and monitors from every
source, because the Loki serves neither. The pin used to apply to the log
side only: the demo's board pinned to its cluster still drew its trace list
from the Tempo.

And every panel says which sources answered, so two stored rows over one
cluster are two names under one number rather than one number that is
quietly double.

The clusters are `ModelledES`, which evaluates what it is asked; the trace
and monitor stores are the smallest objects the fillers accept, and they
record what they were asked.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from tests.support import ModelledES, change_dashboard, grant, install_dashboard

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.api import dashboard_routes  # noqa: E402
from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.dashboard.panels import normalise_all  # noqa: E402
from wdash.hub import Hub  # noqa: E402
from wdash.hub.adapters import ElasticsearchLogSource  # noqa: E402
from wdash.hub.models import (  # noqa: E402
    Monitor, MonitorPage, Service, TraceSummary,
)
from wdash.hub.source import Capability  # noqa: E402
from wdash.models import Dashboard, pinned_source  # noqa: E402

MAPPING = {"@timestamp": {"type": "date"}, "level": {"type": "keyword"},
           "service": {"type": "keyword"}, "message": {"type": "text"}}

PERMISSIONS = ["dashboard:view", "dashboard:create", "dashboard:edit",
               "traces:read", "monitors:read"]

PANELS = [
    {"id": "levels", "type": "terms", "field": "severity", "title": "Levels",
     "width": 6},
    {"id": "services", "type": "trace_services", "sort": "spans", "size": 5,
     "title": "Services", "width": 6},
    {"id": "list", "type": "trace_list", "service": "api", "view": "recent",
     "size": 5, "title": "api", "width": 6},
    {"id": "checks", "type": "monitors", "view": "status", "title": "Checks",
     "width": 6},
]


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "dashboard-sources"
    DASHBOARD_STORAGE = "database"


def _records(prefix, count):
    """Records inside the hour the route asks about by default."""
    stamp = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    return [{"_id": f"{prefix}-{n}", "@timestamp": stamp, "level": "ERROR",
             "service": "api", "message": "boom"} for n in range(count)]


class _TraceStore:
    """The smallest trace source both trace fillers accept, remembering
    what it was asked."""

    backend = "test"

    def __init__(self, name, services=(), traces=(), failing=False):
        self.name = name
        self.capabilities = frozenset({Capability.SERVICE_LIST,
                                       Capability.TRACE_SEARCH})
        self._services = list(services)
        self._traces = list(traces)
        self._failing = failing
        self.asked = []

    def supports(self, capability):
        return capability in self.capabilities

    def health(self):
        return True, "ok"

    def containers(self, scope):
        return [self.name]

    def services(self, window, scope):
        self.asked.append("services")
        if self._failing:
            raise RuntimeError("store unreachable")
        return list(self._services)

    def search(self, query, scope):
        self.asked.append("search")
        if self._failing:
            raise RuntimeError("store unreachable")
        return [t for t in self._traces if t.service == query.service]


class _MonitorStore:
    """The smallest monitor source the monitor filler accepts."""

    backend = "test"

    def __init__(self, name):
        self.name = name
        self.capabilities = frozenset({Capability.MONITOR_LIST})
        self.asked = []

    def supports(self, capability):
        return capability in self.capabilities

    def health(self):
        return True, "ok"

    def containers(self, scope):
        return []

    def monitors(self, window, scope, series=False):
        self.asked.append("monitors")
        return MonitorPage(
            monitors=[Monitor(id=f"{self.name}-check", name=f"{self.name} check",
                              status="up", url="https://x/", duration_ms=1.0,
                              checked_at=datetime.now(timezone.utc),
                              source=self.name)],
            sources=(self.name,))


def _summary(trace_id, service="api"):
    return TraceSummary(trace_id=trace_id, service=service, name="GET /",
                        start=datetime.now(timezone.utc), duration_us=1000)


class _Board(unittest.TestCase):
    """Two log clusters, two trace stores and two monitor stores — one of
    each called `cluster`, the way one stored Elasticsearch row serving
    three signals is registered — and a board over all of it."""

    def setUp(self):
        self.app = create_app(TestConfig)
        self.west = ModelledES({"app-logs-west": (MAPPING, _records("w", 3))})
        self.east = ModelledES({"app-logs-east": (MAPPING, _records("e", 2))})
        self.cluster_traces = _TraceStore(
            "cluster",
            services=[Service(name="api", span_count=30, error_count=1)],
            traces=[_summary("c-1"), _summary("c-2")])
        self.tempo = _TraceStore(
            "tempo", services=[Service(name="web", span_count=7)],
            traces=[_summary("t-1")])
        self.cluster_monitors = _MonitorStore("cluster")
        self.agents = _MonitorStore("wdash-agents")

        self.hub = Hub()
        self.hub.add_logs(ElasticsearchLogSource(self.west, name="cluster"))
        self.hub.add_logs(ElasticsearchLogSource(self.east, name="archive"))
        self.hub.add_traces(self.cluster_traces)
        self.hub.add_traces(self.tempo)
        self.hub.add_monitors(self.cluster_monitors)
        self.hub.add_monitors(self.agents)
        self.app.hub = self.hub

        self.board = install_dashboard(self.app, Dashboard(
            "b1", "Board", "", "*", "u", index_patterns=["*"],
            panels=normalise_all(PANELS)))
        self.client = self.app.test_client()
        grant(self.app, "u", permissions=PERMISSIONS, indices=["*"],
              trace_indices=["*"], services=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": list(PERMISSIONS),
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def pin(self, name):
        change_dashboard(self.app, self.board, source=name)

    def data(self):
        response = self.client.get("/api/dashboard/b1/data")
        return response.status_code, response.get_json()

    def panels(self, payload):
        return {panel["id"]: panel for panel in payload["panels"]}


class AnUnpinnedBoardReadsEverySourceTest(_Board):

    def test_the_counts_are_every_log_source_added_up(self):
        """Five records over two clusters, not the three of whichever cluster
        was registered first."""
        status, payload = self.data()
        self.assertEqual(status, 200)
        self.assertEqual(payload["total_hits"], 5)
        self.assertEqual(payload["error_count"], 5)

    def test_and_the_board_says_how_much_each_gave(self):
        _, payload = self.data()
        self.assertEqual(
            {row["name"]: row["total"] for row in payload["sources"]},
            {"cluster": 3, "archive": 2})
        self.assertFalse(any(row["failed"] for row in payload["sources"]))

    def test_each_cluster_answers_the_whole_batch_in_one_request(self):
        """The current window and its baseline are one msearch per member,
        as they are through a single source: the fan-out hands each member
        the batch whole rather than asking once per request."""
        calls = {"west": 0, "east": 0}
        for name, cluster in (("west", self.west), ("east", self.east)):
            real = cluster.msearch

            def counting(real=real, name=name, **kw):
                calls[name] += 1
                return real(**kw)
            cluster.msearch = counting
        self.data()
        self.assertEqual(calls, {"west": 1, "east": 1})

    def test_the_trace_panels_read_every_trace_source(self):
        _, payload = self.data()
        panels = self.panels(payload)
        self.assertEqual(sorted(panels["services"]["sources"]),
                         ["cluster", "tempo"])
        self.assertEqual({row["name"] for row in panels["services"]["rows"]},
                         {"api", "web"})
        self.assertEqual(sorted(panels["list"]["sources"]), ["cluster", "tempo"])
        # Both stores hold traces of `api`, and the list holds both stores'
        # rows, each saying which store it came from.
        self.assertEqual(
            sorted((row["trace_id"], row["source"])
                   for row in panels["list"]["rows"]),
            [("c-1", "cluster"), ("c-2", "cluster"), ("t-1", "tempo")])
        self.assertEqual(self.tempo.asked, ["services", "search"])

    def test_the_monitor_panel_reads_every_monitor_source(self):
        _, payload = self.data()
        checks = self.panels(payload)["checks"]
        self.assertEqual(sorted(checks["sources"]), ["cluster", "wdash-agents"])
        self.assertEqual(len(checks["rows"]), 2)

    def test_a_log_source_that_did_not_answer_is_in_the_breakdown_as_such(self):
        """"0 from archive" and "archive did not answer" are different facts,
        and a row missing from the breakdown reads as the first one. The
        counts that did arrive still ship, marked short."""
        def refuse(**kw):
            raise ConnectionError("refused")
        self.east.msearch = refuse
        status, payload = self.data()
        self.assertEqual(status, 200)
        self.assertEqual(payload["total_hits"], 3)
        self.assertEqual(
            {row["name"]: (row["total"], row["failed"])
             for row in payload["sources"]},
            {"cluster": (3, False), "archive": (0, True)})
        self.assertTrue(any(note.startswith("archive") for note in payload["warnings"]),
                        payload["warnings"])

    def test_a_log_source_that_raised_is_in_the_breakdown_as_failed(self):
        """The other way a member fails: not an answer marked failed, but
        no answer at all. The adapter above catches its client's errors and
        answers `failed`; a member that raises out of `multi_aggregate` is
        the path the merge itself has to keep in the breakdown."""
        archive = next(s for s in self.hub.log_sources if s.name == "archive")

        def raising(requests, scope):
            raise ConnectionError("refused outright")
        archive.multi_aggregate = raising
        status, payload = self.data()
        self.assertEqual(status, 200)
        self.assertEqual(payload["total_hits"], 3)
        self.assertEqual(
            {row["name"]: (row["total"], row["failed"])
             for row in payload["sources"]},
            {"cluster": (3, False), "archive": (0, True)})
        self.assertTrue(any("archive failed" in note for note in payload["warnings"]),
                        payload["warnings"])

    def test_a_trace_store_that_did_not_answer_is_named_apart(self):
        """Not in `sources` — those answered — and not silently absent: a
        panel over one store's rows that does not say the other was asked
        reads as the other having nothing."""
        self.tempo._failing = True
        _, payload = self.data()
        services = self.panels(payload)["services"]
        self.assertEqual(services["sources"], ["cluster"])
        self.assertEqual(services["missing_sources"], ["tempo"])
        self.assertTrue(services["partial"])

    def test_the_page_names_the_pin_as_every_source(self):
        """In the header's own line — the cost sentence further down says
        "all sources" too, and a test matching anywhere on the page was
        satisfied by it with the header saying nothing."""
        page = self.client.get("/dashboard/b1").get_data(as_text=True)
        self.assertIn('id="sourceNote">all sources — every log, trace and '
                      'monitor source', page)

    def test_an_outage_names_every_source_it_could_not_reach(self):
        """The fan-out raises only when no member answered, so the sentence
        names them all — not "all-sources", which nobody configured."""
        for cluster in (self.west, self.east):
            def refuse(**kw):
                raise ConnectionError("refused")
            cluster.search = refuse
            cluster.msearch = refuse
        for source in self.hub.log_sources:
            source.containers = lambda scope, *a, **k: (_ for _ in ()).throw(
                ConnectionError("refused"))
        status, payload = self.data()
        self.assertEqual(status, 200, "the trace panels still answer")
        self.assertIn("cluster", payload["error"])
        self.assertIn("archive", payload["error"])
        self.assertNotIn("all-sources", payload["error"])


class APinnedBoardReadsItsSourceForEverySignalTest(_Board):

    def test_pinned_to_the_cluster_the_logs_come_from_it_alone(self):
        self.pin("cluster")
        _, payload = self.data()
        self.assertEqual(payload["total_hits"], 3)
        self.assertEqual(payload["sources"],
                         [{"name": "cluster", "total": 3, "failed": False}])
        self.assertEqual(self.east.requests, [], "the other cluster was asked")

    def test_and_so_do_the_traces(self):
        """The rule this module exists for: the pin applied to the log side
        only, so the trace panels read whichever trace store was first."""
        self.pin("cluster")
        _, payload = self.data()
        panels = self.panels(payload)
        self.assertEqual(panels["services"]["sources"], ["cluster"])
        self.assertEqual([row["name"] for row in panels["services"]["rows"]],
                         ["api"])
        self.assertEqual(panels["list"]["sources"], ["cluster"])
        self.assertEqual(self.tempo.asked, [], "the Tempo was asked anyway")

    def test_and_so_do_the_monitors(self):
        self.pin("cluster")
        _, payload = self.data()
        checks = self.panels(payload)["checks"]
        self.assertEqual(checks["sources"], ["cluster"])
        self.assertEqual([row["source"] for row in checks["rows"]], ["cluster"])
        self.assertEqual(self.agents.asked, [], "the store's agents were asked")

    def test_pinned_to_a_log_only_source_the_other_signals_read_everything(self):
        """There is nowhere else they could come from, and the panel says
        whose they are."""
        self.pin("archive")
        _, payload = self.data()
        self.assertEqual(payload["total_hits"], 2)
        panels = self.panels(payload)
        self.assertEqual(sorted(panels["services"]["sources"]),
                         ["cluster", "tempo"])
        self.assertEqual(sorted(panels["list"]["sources"]), ["cluster", "tempo"])
        self.assertEqual(sorted(panels["checks"]["sources"]),
                         ["cluster", "wdash-agents"])

    def test_pinned_to_a_source_nothing_serves_every_panel_says_so(self):
        """Not the rest of the sources, quietly: a board pinned to a store
        that is gone is a board whose question cannot be asked."""
        self.pin("gone")
        status, payload = self.data()
        self.assertEqual(status, 200, "the reason is per panel")
        for panel in self.panels(payload).values():
            with self.subTest(panel=panel["id"]):
                self.assertIn("'gone'", panel.get("error", ""))
                self.assertIn("not configured", panel.get("error", ""))
        self.assertEqual(self.tempo.asked, [])
        self.assertEqual(self.agents.asked, [])

    def test_the_page_says_what_the_pin_means(self):
        self.pin("cluster")
        page = self.client.get("/dashboard/b1").get_data(as_text=True)
        self.assertIn("cluster for logs, traces and monitors", page)

        self.pin("archive")
        page = self.client.get("/dashboard/b1").get_data(as_text=True)
        self.assertIn("archive for logs; traces and monitors from every "
                      "source, because archive serves neither", page)


class TheFormOffersAllSourcesFirstTest(_Board):

    def test_all_sources_is_the_first_choice_and_the_empty_value(self):
        page = self.client.get("/dashboard/create").get_data(as_text=True)
        first = page.index('<option value="" selected>All sources</option>')
        self.assertGreater(first, 0)
        self.assertLess(first, page.index('<option value="cluster"'))
        self.assertNotIn("Default (", page)

    def test_a_new_board_reads_every_source(self):
        self.client.post("/dashboard/create",
                         data={"name": "New", "query": "*", "description": "",
                               "index_patterns": ["*"]},
                         follow_redirects=True)
        self.assertIsNone(self.stored("New").source)

    def test_the_star_is_the_same_choice_stored_the_same_way(self):
        """The search API's spelling of "every source", accepted and stored
        as nothing — one value, not two."""
        for spelling in ("", "*"):
            with self.subTest(spelling=spelling):
                self.client.post("/dashboard/create",
                                 data={"name": f"S{spelling}", "query": "*",
                                       "description": "",
                                       "index_patterns": ["*"],
                                       "source": spelling},
                                 follow_redirects=True)
                self.assertIsNone(self.stored(f"S{spelling}").source)

    def test_a_named_source_is_stored_as_named(self):
        self.client.post("/dashboard/create",
                         data={"name": "Pinned", "query": "*", "description": "",
                               "index_patterns": ["*"], "source": "archive"},
                         follow_redirects=True)
        self.assertEqual(self.stored("Pinned").source, "archive")

    def test_no_store_ever_holds_the_star(self):
        """Down to the row: the model reads `*` as nothing, and the store
        writes nothing for it, so a row read by anything else says the same
        thing the model does."""
        from sqlalchemy import text

        change_dashboard(self.app, self.board, source="*")
        self.assertIsNone(self.stored("Board").source)
        with self.app.dashboard_manager._engine.connect() as connection:
            self.assertIsNone(connection.execute(text(
                "select source from wdash_dashboards where id = 'b1'")).scalar())
        self.assertIsNone(Dashboard("x", "x", "", "*", "u", source="*").source)
        self.assertNotIn("source",
                         Dashboard("x", "x", "", "*", "u", source="*").to_dict())

    def test_the_one_spelling_in_one_place(self):
        self.assertIsNone(pinned_source(None))
        self.assertIsNone(pinned_source(""))
        self.assertIsNone(pinned_source("  "))
        self.assertIsNone(pinned_source("*"))
        self.assertEqual(pinned_source(" archive "), "archive")

    def stored(self, name):
        manager = self.app.dashboard_manager
        manager.refresh_cache()
        return next(d for d in manager.get_all_dashboards() if d.name == name)


class TheChoiceIsOfferedWhereItChangesSomethingTest(unittest.TestCase):
    """The select is drawn when pinning would read differently from "All
    sources" for at least one signal, and hidden otherwise — so an edit
    through the form on an installation with one source cannot repoint
    anything, which is what the present-and-empty rule was written for."""

    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        grant(self.app, "u", permissions=PERMISSIONS, indices=["*"],
              trace_indices=["*"], services=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": list(PERMISSIONS),
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def offered(self, logs=(), traces=(), monitors=()):
        hub = Hub()
        for name in logs:
            hub.add_logs(ElasticsearchLogSource(
                ModelledES({f"{name}-logs": (MAPPING, [])}), name=name))
        for name in traces:
            hub.add_traces(_TraceStore(name))
        for name in monitors:
            hub.add_monitors(_MonitorStore(name))
        self.app.hub = hub
        with self.app.test_request_context("/dashboard/create"):
            offered = dashboard_routes._pins_on_offer()
        page = self.client.get("/dashboard/create").get_data(as_text=True)
        self.assertEqual('name="source"' in page, bool(offered),
                         "the page and the rule disagree")
        return offered

    def test_two_log_sources_are_a_choice(self):
        self.assertEqual(self.offered(logs=["a", "b"]), ["a", "b"])

    def test_one_log_source_alone_is_not(self):
        self.assertEqual(self.offered(logs=["a"]), [])

    def test_one_cluster_beside_another_trace_store_is(self):
        """One log source, and a real choice for the trace panels: that
        cluster's traces, or every trace store's."""
        self.assertEqual(self.offered(logs=["cluster"],
                                      traces=["cluster", "tempo"]),
                         ["cluster"])

    def test_one_cluster_whose_traces_have_no_company_is_not(self):
        self.assertEqual(self.offered(logs=["cluster"], traces=["cluster"]),
                         [])

    def test_the_stores_own_agents_beside_a_cluster_are_company(self):
        self.assertEqual(self.offered(logs=["cluster"],
                                      monitors=["cluster", "wdash-agents"]),
                         ["cluster"])


class TheTracesPageReadsEveryStoreUnnamedTest(_Board):
    """The same rule on the Traces API: a service list or a search that
    names no source is every trace store's answer, not the first one's."""

    def test_the_service_list_is_every_stores(self):
        payload = self.client.get("/api/traces/services").get_json()
        self.assertEqual(sorted(s["name"] for s in payload["services"]),
                         ["api", "web"])
        self.assertEqual(self.tempo.asked, ["services"])

    def test_a_search_is_every_stores(self):
        payload = self.client.get("/api/traces?service=api").get_json()
        self.assertEqual(
            sorted((t["trace_id"], t["source"]) for t in payload["traces"]),
            [("c-1", "cluster"), ("c-2", "cluster"), ("t-1", "tempo")])


if __name__ == "__main__":
    unittest.main()
