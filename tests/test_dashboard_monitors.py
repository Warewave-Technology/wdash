"""Monitors on a dashboard.

The third signal, on the board. An application that has stopped serving
requests writes no logs and emits no spans, so a log-only dashboard draws
"No data in this window" everywhere and a reader cannot tell a quiet night
from a dead shipper. Measured on the lab while this was written: the newest
application log was 15.74 hours old and the newest Heartbeat check 25 seconds
old, with `lab-http-down` failing 3,775 of 3,775 checks over 24 hours.

Nothing here is a fake monitor source. `StoreMonitorSource` is the real
adapter over a real store, which is the whole point of the panel: it answers
with no Elasticsearch in the path at all.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from tests.support import change_dashboard, grant, install_dashboard
from tests.test_dashboard_contract import DASH_ID, FakeES, TestConfig

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.api import monitor_routes  # noqa: E402
from wdash.app import create_app  # noqa: E402
from wdash.hub import Hub  # noqa: E402
from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource  # noqa: E402
from wdash.hub.adapters.store_monitors import StoreMonitorSource  # noqa: E402
from wdash.hub.source import Capability, MonitorSource  # noqa: E402
from wdash.models import Dashboard  # noqa: E402


def _now():
    return datetime.now(timezone.utc)


def _iso(seconds_ago):
    return (_now() - timedelta(seconds=seconds_ago)).isoformat()


STATUS_PANEL = {"id": "mon-1", "type": "monitors", "title": "Checks",
                "view": "status", "width": 6}
AVAILABILITY_PANEL = {"id": "mon-2", "type": "monitors", "title": "Uptime",
                      "view": "availability", "width": 6}
CERTIFICATE_PANEL = {"id": "tls-1", "type": "monitor_certificates",
                     "title": "Certificates", "width": 6}
LOG_PANEL = {"id": "log-1", "type": "terms", "title": "Top services",
             "field": "service", "size": 10, "width": 6}
TRACE_PANEL = {"id": "tr-1", "type": "trace_services", "title": "Services",
               "sort": "spans", "size": 5, "width": 6}


class MonitorPanelTest(unittest.TestCase):
    """A board carrying monitor panels, over the real store adapter."""

    PANELS = [LOG_PANEL, STATUS_PANEL]
    #: Which permissions the viewer holds.
    PERMISSIONS = ("dashboard:view", "monitors:read")

    def make_es(self):
        return FakeES()

    def setUp(self):
        self.es = self.make_es()
        self.app = create_app(TestConfig)
        self.hub = Hub()
        self.hub.add_logs(ElasticsearchLogSource(self.es))
        self.hub.add_traces(ElasticsearchTraceSource(self.es))
        self.monitors = self.add_monitor_source()
        self.app.hub = self.hub

        self.board = install_dashboard(self.app, Dashboard(
            dashboard_id=DASH_ID, name="Test", description="", query="*",
            created_by="u", index_patterns=["app-*"], panels=self.PANELS))

        self.client = self.app.test_client()
        self.login(self.PERMISSIONS)

    def add_monitor_source(self):
        source = StoreMonitorSource(self.app.store)
        self.hub.add_monitors(source)
        return source

    def login(self, permissions, indices=("*",)):
        grant(self.app, "u", permissions, indices)
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": list(permissions),
                "allowed_indices": list(indices),
                "allowed_trace_indices": ["*"], "allowed_services": ["*"]}
            session["_user_id"] = "1"

    # ---------- the lab, in miniature ----------

    def agent(self, name="one"):
        row, _ = self.app.store.agents.create(name)
        self.app.store.agents.seen(row["id"], version="test")
        return row

    def monitor(self, name, target="https://example.com/", **kwargs):
        options = dict(kind="http", target=target, interval_seconds=30,
                       timeout_seconds=5)
        options.update(kwargs)
        return self.app.store.monitors.create(name=name, **options)

    def report(self, agent_id, monitor_id, status="up", ago=5,
               duration_us=12345, tls=None, handshake_verified=None):
        payload = {"monitor_id": monitor_id, "status": status,
                   "started_at": _iso(ago), "duration_us": duration_us}
        if tls is not None:
            payload["tls"] = tls
        if handshake_verified is not None:
            payload["handshake_verified"] = handshake_verified
        self.app.store.agents.seen(agent_id, version="test")
        self.app.store.results.record(agent_id, [payload])

    def data(self, **params):
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return self.client.get(f"/api/dashboard/{DASH_ID}/data"
                               + (f"?{query}" if query else ""))

    def panel(self, payload, panel_id):
        for panel in payload.get("panels") or ():
            if panel["id"] == panel_id:
                return panel
        self.fail(f"no panel '{panel_id}' in "
                  f"{[p['id'] for p in payload.get('panels') or ()]}")


class StatusGridTest(MonitorPanelTest):
    """D3: a grid of cells, one per check, down first."""

    def setUp(self):
        super().setUp()
        agent = self.agent()
        self.up = self.monitor("Zebra endpoint")
        self.down = self.monitor("Lab endpoint (down)")
        self.report(agent["id"], self.up["id"], "up", duration_us=1622)
        self.report(agent["id"], self.down["id"], "down", duration_us=1575)

    def test_the_panel_answers_from_the_monitor_source(self):
        """Without the panel type the board carried log buckets under this
        id — or nothing at all — and the reader learned nothing about
        whether anything was reachable."""
        panel = self.panel(self.data().get_json(), "mon-1")
        self.assertNotIn("error", panel, panel.get("error"))
        names = [row["name"] for row in panel["rows"]]
        self.assertEqual(sorted(names),
                         ["Lab endpoint (down)", "Zebra endpoint"])
        self.assertEqual(panel["counts"], {"up": 1, "down": 1, "unknown": 0})

    def test_down_comes_first_whatever_the_names_say(self):
        """Alphabetically 'Lab' precedes 'Zebra', so a list that is merely
        sorted by name would pass this by accident. The down monitor here is
        named so that only a status rule can put it first."""
        self.app.store.monitors.update(self.down["id"], name="Zzz endpoint")
        rows = self.panel(self.data().get_json(), "mon-1")["rows"]
        self.assertEqual(rows[0]["name"], "Zzz endpoint")
        self.assertEqual(rows[0]["status"], "down")

    def test_a_check_nobody_has_reported_sorts_above_the_healthy_ones(self):
        """Unknown is the state this whole signal exists to make visible: a
        check that has stopped running looks exactly like a quiet night from
        every other panel on the board. Filed with 'up' it would be at the
        bottom of a long grid, which is where nobody looks."""
        self.monitor("Aaa endpoint")          # never reported
        rows = self.panel(self.data().get_json(), "mon-1")["rows"]
        self.assertEqual([r["status"] for r in rows],
                         ["down", "unknown", "up"])

    def test_the_cell_carries_the_last_check_and_its_duration(self):
        rows = {r["name"]: r for r in
                self.panel(self.data().get_json(), "mon-1")["rows"]}
        cell = rows["Lab endpoint (down)"]
        self.assertEqual(cell["duration_ms"], 1.6)
        self.assertTrue(cell["checked_at"], "no time for the last check")
        self.assertEqual(cell["id"], self.down["id"])

    def test_the_monitor_panel_does_not_ride_the_log_batch(self):
        """Monitors are a different store with a different schema. A panel id
        that turned up in the Elasticsearch aggregations would mean the batch
        was asked a question it cannot answer — and would come back empty."""
        self.data()
        aggregations = sorted(self.es.searches[0]["body"]["aggs"])
        self.assertNotIn("mon-1", aggregations)
        self.assertIn("log-1", aggregations)
        self.assertEqual(self.es.round_trips, 1,
                         "the monitor panel cost an Elasticsearch round trip")

    def test_the_log_panels_on_the_same_board_are_untouched(self):
        panel = self.panel(self.data().get_json(), "log-1")
        self.assertTrue(panel["buckets"], "the log panel lost its data")

    def listings(self):
        """Every (window, scope) the monitor source was asked for."""
        asked = []
        original = StoreMonitorSource.monitors

        def recording(source, window, scope, series=False):
            asked.append(scope)
            return original(source, window, scope, series=series)

        StoreMonitorSource.monitors = recording
        self.addCleanup(setattr, StoreMonitorSource, "monitors", original)
        return asked

    def test_a_board_of_several_monitor_panels_costs_one_listing(self):
        """What makes a rich board affordable: the second monitor panel is
        free. One extra round trip for the signal, not one per panel — the
        same bargain the log batch makes and the reason panels are worth
        adding at all."""
        change_dashboard(self.app, self.board, panels=[
            LOG_PANEL, STATUS_PANEL, AVAILABILITY_PANEL])
        asked = self.listings()
        payload = self.data().get_json()
        self.assertEqual(len(asked), 1, f"{len(asked)} listings")
        self.assertTrue(self.panel(payload, "mon-1")["rows"])
        self.assertTrue(self.panel(payload, "mon-2")["rows"])

    def test_the_source_is_asked_under_the_monitors_own_scope(self):
        """Not under the viewer's log scope.

        `StoreMonitorSource` ignores the scope it is handed, so this cannot
        be measured by what comes back — a fixture that ignores what it is
        asked is exactly how a broken narrowing survives. The scope itself is
        recorded instead. A role reaching only `infra-*` must still reach
        every monitor: `es_monitors.containers` refuses that narrowing in as
        many words, and a dashboard applying it would show an empty grid to
        very nearly everybody.
        """
        self.login(("dashboard:view", "monitors:read"), indices=["app-*"])
        asked = self.listings()
        self.data()
        self.assertEqual(len(asked), 1)
        self.assertEqual(asked[0].containers, ("*",),
                         "the monitor source was narrowed by the log scope")


class NoMonitorBackendTest(MonitorPanelTest):
    """A deployment with no monitor source gets a reason, not an empty grid."""

    def add_monitor_source(self):
        return None

    def test_the_panel_says_there_is_no_monitor_backend(self):
        panel = self.panel(self.data().get_json(), "mon-1")
        self.assertEqual(panel["error"], "No monitor backend is configured.")
        self.assertNotIn("rows", panel)

    def test_the_rest_of_the_board_still_draws(self):
        self.assertTrue(self.panel(self.data().get_json(), "log-1")["buckets"])


class WithoutCertificates(MonitorSource):
    """A monitor source that lists but cannot report certificates.

    Real ones exist: the capability is declared per source, and the whole
    point of `Capability` is that the UI must not offer what a backend cannot
    serve.
    """
    name = "listing-only"
    backend = "test"

    @property
    def capabilities(self):
        return frozenset({Capability.MONITOR_LIST})

    def health(self):
        return True, "ok"

    def containers(self, scope):
        return []

    def monitors(self, window, scope, series=False):
        from wdash.hub.models import MonitorPage
        return MonitorPage(monitors=[], sources=(self.name,))


class CertificatePanelTest(MonitorPanelTest):
    """D18: the Monitors page's certificate tab, on a dashboard."""

    PANELS = [LOG_PANEL, CERTIFICATE_PANEL]

    def setUp(self):
        super().setUp()
        agent = self.agent()
        self.soon = self.monitor("Expiring soon", "https://soon.example/")
        self.gone = self.monitor("Already expired", "https://gone.example/")
        self.fine = self.monitor("Healthy", "https://fine.example/")
        for monitor, days in ((self.soon, 3), (self.gone, -25),
                              (self.fine, 328)):
            self.report(agent["id"], monitor["id"], "up", tls={
                "common_name": monitor["name"].lower().replace(" ", "-"),
                "issuer": "Lab CA",
                "not_after": (_now() + timedelta(days=days)).isoformat(),
                "key_algorithm": "RSA", "key_size": 2048})

    def rows(self):
        return self.panel(self.data().get_json(), "tls-1")["rows"]

    @staticmethod
    def named(row):
        """The checks on a row, as one name.

        A row is a CERTIFICATE now and a certificate has no name of its own
        — these fixtures give every check its own, so the one check on each
        row is how the tests below still say which is which.
        """
        return ", ".join(check["name"] for check in row["checks"])

    def test_one_certificate_on_two_checks_is_one_row(self):
        """A row per MONITOR, on a list whose subject is the certificate.

        Seen on the demo: the lab's TLS endpoint was watched by WDash's own
        agent and by Heartbeat, and the panel listed the same certificate
        twice — the same common name, the same issuer, the same expiry,
        once per check. On a card that answers "what renews next" that
        reads as two things to renew.
        """
        # Two probes, as the demo had: WDash's own agent, and a second one
        # standing in for the Heartbeat that watches the same endpoint.
        here = self.agent("here")
        there = self.agent("there")
        first = self.monitor("Gateway (agent)", "https://gateway.example/")
        second = self.monitor("Gateway (heartbeat)", "https://gateway.example/")
        shared = {"common_name": "gateway.example", "issuer": "Lab CA",
                  "not_after": (_now() + timedelta(days=40)).isoformat(),
                  "fingerprint": "ab" * 32,
                  "key_algorithm": "RSA", "key_size": 2048}
        for agent, monitor in ((here, first), (there, second)):
            self.report(agent["id"], monitor["id"], "up", tls=dict(shared))

        rows = [row for row in self.rows()
                if row["common_name"] == "gateway.example"]
        self.assertEqual(len(rows), 1, f"{len(rows)} rows for one certificate")
        self.assertEqual(
            sorted(check["name"] for check in rows[0]["checks"]),
            ["Gateway (agent)", "Gateway (heartbeat)"])

    def test_two_readings_that_differ_stay_two_rows(self):
        """The case worth keeping apart. A host mid-rotation, or one that
        answers a verified and an unverified connection differently, is two
        certificates on one endpoint — and merging them would hide the one
        that expires first behind the one that does not."""
        here, there = self.agent("a"), self.agent("b")
        first = self.monitor("Edge (old)", "https://edge.example/")
        second = self.monitor("Edge (new)", "https://edge.example/")
        # Everything a reader can see is identical — the name, the issuer,
        # the expiry to the second. Only the fingerprint differs, which is
        # the whole reason identity is the fingerprint: two hosts behind one
        # address answering with two certificates is not one certificate.
        expiry = (_now() + timedelta(days=45)).isoformat()
        for agent, monitor, fingerprint in ((here, first, "11" * 32),
                                            (there, second, "22" * 32)):
            self.report(agent["id"], monitor["id"], "up", tls={
                "common_name": "edge.example", "issuer": "Lab CA",
                "not_after": expiry, "fingerprint": fingerprint,
                "key_algorithm": "RSA", "key_size": 2048})

        rows = [row for row in self.rows()
                if row["common_name"] == "edge.example"]
        self.assertEqual(len(rows), 2, "two certificates became one row")
        self.assertEqual(sorted(row["fingerprint"] for row in rows),
                         ["11" * 32, "22" * 32])

    def test_a_certificate_with_no_fingerprint_is_still_one_row(self):
        """Heartbeat reports one; an agent behind an expiry-only check may
        not. Without a fingerprint the issuer and serial identify it, and
        without those the three fields every source reports."""
        here, there = self.agent("c"), self.agent("d")
        first = self.monitor("Shop (agent)", "https://shop.example/")
        second = self.monitor("Shop (heartbeat)", "https://shop.example/")
        shared = {"common_name": "shop.example", "issuer": "Lab CA",
                  "not_after": (_now() + timedelta(days=90)).isoformat(),
                  "key_algorithm": "RSA", "key_size": 2048}
        for agent, monitor in ((here, first), (there, second)):
            self.report(agent["id"], monitor["id"], "up", tls=dict(shared))

        rows = [row for row in self.rows()
                if row["common_name"] == "shop.example"]
        self.assertEqual(len(rows), 1, f"{len(rows)} rows for one certificate")

    def test_each_check_keeps_its_own_verdict(self):
        """Whether a handshake verified is an answer about the CONNECTION.
        One row for two checks must not hand one check's verdict to the
        other — the certificate is the same and the connections are not.
        """
        here, there = self.agent("e"), self.agent("f")
        first = self.monitor("Api (verifying)", "https://api.example/")
        second = self.monitor("Api (expiry only)", "https://api.example/")
        shared = {"common_name": "api.example", "issuer": "Lab CA",
                  "not_after": (_now() + timedelta(days=60)).isoformat(),
                  "fingerprint": "33" * 32,
                  "key_algorithm": "RSA", "key_size": 2048}
        self.report(here["id"], first["id"], "up", tls=dict(shared),
                    handshake_verified=True)
        self.report(there["id"], second["id"], "up", tls=dict(shared),
                    handshake_verified=False)

        row = [r for r in self.rows() if r["common_name"] == "api.example"][0]
        verdicts = {check["name"]: check["verified"] for check in row["checks"]}
        self.assertEqual(verdicts, {"Api (verifying)": True,
                                    "Api (expiry only)": False})

    def test_the_checks_on_a_row_are_in_a_settled_order(self):
        """Two checks arriving in whichever order the source listed them
        would make the row move under a reader between refreshes.

        Asked of the grouping directly, in the order a source might hand
        them over: the store adapter happens to return monitors by name, so
        a test through it would pass whether or not anything sorted.
        """
        from datetime import datetime, timezone

        from wdash.api.dashboard_routes import _certificate_rows
        from wdash.hub.models import Certificate, Monitor

        certificate = Certificate(
            common_name="cdn.example", issuer="Lab CA",
            not_after=datetime.now(timezone.utc) + timedelta(days=70),
            fingerprint="44" * 32)
        monitors = [Monitor(id="z", name="Zeta", url="https://cdn.example/",
                            certificate=certificate),
                    Monitor(id="a", name="Alpha", url="https://cdn.example/",
                            certificate=certificate)]
        rows = _certificate_rows(monitors)
        self.assertEqual(len(rows), 1)
        self.assertEqual([check["name"] for check in rows[0]["checks"]],
                         ["Alpha", "Zeta"])

    def test_a_check_that_saw_no_certificate_is_not_a_row(self):
        """A plain HTTP check reports none. A row for it would have no
        expiry and nothing to renew — an empty line on a list of things to
        renew.

        Both ways round. The two adapters that exist drop them before the
        panel is filled, so through the source this measures their
        behaviour; the grouping is asked directly as well, because it
        merges what several sources hand over and a source that kept one is
        a panel that raises rather than a panel with a blank line.
        """
        agent = self.agent("plain")
        monitor = self.monitor("Status page", "http://status.example/")
        self.report(agent["id"], monitor["id"], "up")
        names = [check["name"] for row in self.rows()
                 for check in row["checks"]]
        self.assertNotIn("Status page", names)

        from wdash.api.dashboard_routes import _certificate_rows
        from wdash.hub.models import Monitor
        self.assertEqual(
            _certificate_rows([Monitor(id="p", name="Status page",
                                       url="http://status.example/")]), [])

    def test_the_bands_are_the_monitors_pages_own(self):
        """Borrowed rather than re-derived. A dashboard that decided its own
        'expiring soon' would give the product two thresholds, and the one
        nobody remembers is the second one."""
        states = {self.named(row): row["state"] for row in self.rows()}
        self.assertEqual(states["Already expired"], "expired")
        self.assertEqual(states["Expiring soon"], "critical",
                         f"3 days is inside "
                         f"{monitor_routes.EXPIRY_CRITICAL_DAYS}")
        self.assertEqual(states["Healthy"], "ok")

    def test_the_thresholds_travel_with_the_panel(self):
        """So the footnote on the card cannot drift from the bands above
        it."""
        panel = self.panel(self.data().get_json(), "tls-1")
        self.assertEqual(panel["warning_days"],
                         monitor_routes.EXPIRY_WARNING_DAYS)
        self.assertEqual(panel["critical_days"],
                         monitor_routes.EXPIRY_CRITICAL_DAYS)

    def test_moving_the_monitors_pages_bands_moves_the_panel(self):
        """Borrowed means borrowed: the numbers are read from the Monitors
        page at the moment the panel is filled, not copied into this file
        once.

        The two tests above compare the panel to the constants and call a
        three-day certificate critical, both of which are true of a
        dashboard that wrote 30 and 7 down again — and a product with two
        thresholds renews on whichever one somebody remembers. So the bands
        are MOVED here, and the panel has to move with them.
        """
        from unittest.mock import patch

        with patch.object(monitor_routes, "EXPIRY_WARNING_DAYS", 400), \
                patch.object(monitor_routes, "EXPIRY_CRITICAL_DAYS", 100):
            panel = self.panel(self.data().get_json(), "tls-1")
        states = {self.named(row): row["state"] for row in panel["rows"]}
        self.assertEqual(panel["warning_days"], 400)
        self.assertEqual(panel["critical_days"], 100)
        # 328 days is comfortably "ok" under the shipped bands and a warning
        # under these, so a re-derived band cannot pass this by arithmetic.
        self.assertEqual(states["Healthy"], "warning")
        self.assertEqual(states["Expiring soon"], "critical")
        self.assertEqual(states["Already expired"], "expired")

    def test_the_state_is_the_monitors_pages_own_function(self):
        """Not a second chain that happens to agree today.

        A copy that reads the same two numbers still has to be found and
        edited when the wording or the bands change, and the one nobody
        remembers is the second one.
        """
        from unittest.mock import patch

        with patch.object(monitor_routes, "_certificate_state",
                          lambda certificate: "asked-the-monitors-page"):
            rows = self.rows()
        self.assertEqual({row["state"] for row in rows},
                         {"asked-the-monitors-page"})

    def test_what_expires_first_comes_first(self):
        self.assertEqual([self.named(row) for row in self.rows()],
                         ["Already expired", "Expiring soon", "Healthy"])

    def test_days_remaining_is_rounded_not_truncated(self):
        days = {self.named(row): row["days_remaining"] for row in self.rows()}
        self.assertEqual(days["Expiring soon"], 3)
        self.assertEqual(days["Already expired"], -25)

    def test_a_source_that_does_not_say_verified_is_not_a_finding(self):
        """`verified` is true, false or null, and Heartbeat never says. Null
        rendered as 'not verified' would be a finding invented on every row
        on day one."""
        for row in self.rows():
            for check in row["checks"]:
                self.assertIsNone(check["verified"], check["name"])

    def test_a_source_that_cannot_report_certificates_refuses_that_panel(self):
        """What the Monitors page already does rather than showing an empty
        tab, which reads as 'none found'."""
        self.app.hub = None
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.es))
        hub.add_monitors(WithoutCertificates())
        self.app.hub = hub

        panel = self.panel(self.data().get_json(), "tls-1")
        self.assertIn("does not report TLS certificates", panel["error"])
        self.assertIn("not evidence that the endpoints have none",
                      panel["error"])
        self.assertTrue(self.panel(self.data().get_json(), "log-1")["buckets"])


class RefusingSource(MonitorSource):
    """A second region that cannot be reached.

    Declares both capabilities — it is a perfectly ordinary source, it is
    simply down — because the fan-out offers a capability only when every
    member declares it, and a member that cannot be asked is exactly the case
    the panel has to survive.
    """
    name = "region-b"
    backend = "test"

    @property
    def capabilities(self):
        return frozenset({Capability.MONITOR_LIST, Capability.TLS_CERTIFICATES})

    def health(self):
        return True, "ok"

    def containers(self, scope):
        return []

    def monitors(self, window, scope, series=False):
        raise RuntimeError("connection refused")

    def certificates(self, window, scope):
        raise RuntimeError("connection refused")


class PartialCertificatesTest(MonitorPanelTest):
    """A certificate list is a list of what somebody could be asked.

    `FanOutMonitorSource.certificates` merged what answered and dropped the
    rest, so a region that could not be reached left no trace: the panel
    shipped a shorter list with no error and no `partial`, and a certificate
    about to expire in the region that did not answer was simply absent. With
    every source down the panel shipped no rows at all, and the client draws
    that as "None of the checks in this window used TLS" — a positive claim
    about the endpoints, made when nothing could be asked.
    """

    PANELS = [LOG_PANEL, CERTIFICATE_PANEL]

    def add_monitor_source(self):
        source = StoreMonitorSource(self.app.store)
        self.hub.add_monitors(source)
        self.hub.add_monitors(RefusingSource())
        return source

    def setUp(self):
        super().setUp()
        agent = self.agent()
        self.watched = self.monitor("Payments", "https://pay.example/")
        self.report(agent["id"], self.watched["id"], "up", tls={
            "common_name": "pay.example", "issuer": "Lab CA",
            "not_after": (_now() + timedelta(days=40)).isoformat()})

    def test_a_source_that_did_not_answer_is_named_on_the_panel(self):
        panel = self.panel(self.data().get_json(), "tls-1")
        self.assertTrue(panel.get("partial"),
                        "a region that could not be asked left no trace")
        self.assertEqual(len(panel["warnings"]), 1)
        self.assertIn("region-b", panel["warnings"][0])
        self.assertIn("connection refused", panel["warnings"][0])
        # And what the other source did say is still on the card: a shorter
        # list that says it is short beats no list at all.
        self.assertEqual([row["common_name"] for row in panel["rows"]],
                         ["pay.example"])

    def test_no_source_answering_is_not_no_certificate(self):
        """The forbidden failure, exactly: emptiness standing in for an
        answer. An empty certificate table reads as 'these endpoints have no
        TLS', which is a claim about the endpoints and not about us."""
        def refuse(window, scope):
            raise RuntimeError("the store is gone")

        self.monitors.certificates = refuse
        panel = self.panel(self.data().get_json(), "tls-1")
        self.assertEqual(panel["rows"], [])
        self.assertTrue(panel.get("partial"))
        self.assertEqual(len(panel["warnings"]), 2, panel["warnings"])

    def test_a_whole_list_carries_no_warning(self):
        """The flag has to mean something: marked partial on every load, it
        is furniture and the reader stops seeing it."""
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(self.es))
        hub.add_monitors(StoreMonitorSource(self.app.store))
        self.app.hub = hub
        panel = self.panel(self.data().get_json(), "tls-1")
        self.assertNotIn("partial", panel)
        self.assertEqual([row["common_name"] for row in panel["rows"]],
                         ["pay.example"])


class TwoArgumentSource(MonitorSource):
    """A source written against the interface as it is declared.

    `MonitorSource.monitors` takes (window, scope); `series=True` is an
    extension, which is the whole reason `monitor_routes._with_series` falls
    back. A source like this reports current state perfectly well and has no
    per-check history to count availability over.
    """
    name = "legacy-agent"
    backend = "test"

    @property
    def capabilities(self):
        return frozenset({Capability.MONITOR_LIST})

    def health(self):
        return True, "ok"

    def containers(self, scope):
        return []

    def monitors(self, window, scope):
        from wdash.hub.models import Monitor, MonitorPage
        return MonitorPage(
            monitors=[Monitor(id="checkout", name="Checkout", status="up",
                              url="https://pay.example/", duration_ms=12.0,
                              checked_at=_now(), source=self.name)],
            sources=(self.name,))


class LegacyMonitorSourceTest(MonitorPanelTest):
    """Availability over a source that cannot report per-check history.

    The fallback leaves every series empty, so the sums are zero and the
    panel said `availability: null` — which the grid draws as "no check ran",
    beside a timestamp from a second ago and a green "up" chip. The cell
    contradicts itself and it asserts the agent is silent when it is not. The
    honest answer is that this source cannot report availability.
    """

    PANELS = [LOG_PANEL, STATUS_PANEL, AVAILABILITY_PANEL]

    def add_monitor_source(self):
        source = TwoArgumentSource()
        self.hub.add_monitors(source)
        return source

    def test_the_availability_view_says_the_source_cannot_answer_it(self):
        panel = self.panel(self.data().get_json(), "mon-2")
        self.assertIn("legacy-agent", panel.get("error", ""))
        self.assertIn("history", panel["error"])
        self.assertNotIn("rows", panel)

    def test_it_does_not_report_a_check_that_ran_as_one_that_did_not(self):
        """The two are different answers and only one of them is about the
        endpoint."""
        panel = self.panel(self.data().get_json(), "mon-2")
        self.assertNotIn("rows", panel)
        self.assertNotIn("checks", str(panel.get("rows")))

    def test_the_status_view_of_the_same_source_still_answers(self):
        """Only the view that needs the history is refused. The source
        answers "is it up now" and that is most of what the grid is for."""
        panel = self.panel(self.data().get_json(), "mon-1")
        self.assertNotIn("error", panel, panel.get("error"))
        self.assertEqual([row["name"] for row in panel["rows"]], ["Checkout"])
        self.assertEqual(panel["rows"][0]["status"], "up")


class AvailabilityTest(MonitorPanelTest):
    """D8: was it up all window, out of the same listing."""

    PANELS = [LOG_PANEL, AVAILABILITY_PANEL]

    def setUp(self):
        super().setUp()
        self.agent_id = self.agent()["id"]
        self.flaky = self.monitor("Flaky endpoint")

    def rows(self):
        panel = self.panel(self.data(time_range="1h").get_json(), "mon-2")
        self.assertNotIn("error", panel, panel.get("error"))
        return {row["name"]: row for row in panel["rows"]}

    def test_availability_counts_runs_not_buckets(self):
        """The arithmetic `monitor_routes._availability` insists on.

        Six runs inside one two-and-a-half-minute bucket, one of which
        failed, is one failure out of six — 83.33%. Counted by BUCKET it is
        one bucket, and that bucket is down, so a sparkline-shaped answer
        would report 0.0% available for a monitor that answered five requests
        out of six.
        """
        for index in range(6):
            self.report(self.agent_id, self.flaky["id"],
                        "down" if index == 0 else "up", ago=10 + index)
        row = self.rows()["Flaky endpoint"]
        self.assertEqual(row["checks"], 6)
        self.assertEqual(row["down"], 1)
        self.assertEqual(row["availability"], 83.33)

    def test_the_check_count_ships_beside_the_percentage(self):
        """100% of 12 checks and 100% of 2,750 are not the same claim."""
        for index in range(3):
            self.report(self.agent_id, self.flaky["id"], "up", ago=10 + index)
        row = self.rows()["Flaky endpoint"]
        self.assertEqual(row["availability"], 100.0)
        self.assertEqual(row["checks"], 3)

    def test_a_check_that_never_ran_is_not_a_hundred_percent_available(self):
        """Zero of zero is not availability, and '100%' over an agent that
        has been silent all week is the loudest possible lie on the board."""
        row = self.rows()["Flaky endpoint"]
        self.assertEqual(row["checks"], 0)
        self.assertIsNone(row["availability"])

    def test_the_panel_says_which_of_the_two_it_is_showing(self):
        """A grid reading 100% and a grid reading 'up' look alike and are
        different claims."""
        payload = self.data(time_range="1h").get_json()
        self.assertEqual(self.panel(payload, "mon-2")["view"], "availability")

    def test_a_status_panel_carries_no_availability_numbers(self):
        """The view is what it says it is: a status grid that shipped an
        availability figure nobody asked for is a second number on the card
        with no caption."""
        change_dashboard(self.app, self.board,
                         panels=[LOG_PANEL, STATUS_PANEL])
        self.report(self.agent_id, self.flaky["id"], "up")
        row = self.panel(self.data().get_json(), "mon-1")["rows"][0]
        self.assertEqual(row["view"] if "view" in row else None, None)
        self.assertNotIn("availability", row)
        self.assertEqual(self.panel(self.data().get_json(), "mon-1")["view"],
                         "status")


class PermissionBoundaryTest(MonitorPanelTest):
    """The owner's boundary, both ways round.

    `monitors:read` is checked at panel-fill time and refuses THAT panel with
    a reason. The dashboard's own visibility rule is not widened, and a
    colleague who lacks the permission still reads the rest of the board.
    """

    PANELS = [LOG_PANEL, STATUS_PANEL, CERTIFICATE_PANEL]
    PERMISSIONS = ("dashboard:view",)          # no monitors:read

    def setUp(self):
        super().setUp()
        agent = self.agent()
        self.watched = self.monitor("Payments endpoint")
        self.report(agent["id"], self.watched["id"], "down", tls={
            "common_name": "payments.example",
            "not_after": (_now() + timedelta(days=2)).isoformat()})

    def test_the_monitor_panel_is_refused_with_a_reason(self):
        """dashboard_routes checks dashboard:* and system:admin and nothing
        else, so a shared dashboard would otherwise be a way to see monitors
        a role was never granted — which `es_monitors.containers` says
        deliberately is a route-level permission."""
        panel = self.panel(self.data().get_json(), "mon-1")
        self.assertIn("monitors:read", panel["error"])
        self.assertNotIn("rows", panel)

    def test_the_certificate_panel_is_refused_the_same_way(self):
        panel = self.panel(self.data().get_json(), "tls-1")
        self.assertIn("monitors:read", panel["error"])
        self.assertNotIn("rows", panel)

    def test_nothing_about_the_monitors_reaches_the_response(self):
        """Not just 'no rows key': a refusal that still shipped the names or
        the count would be the boundary in name only."""
        body = self.data().get_data(as_text=True)
        self.assertNotIn("Payments endpoint", body)
        self.assertNotIn("payments.example", body)

    def test_the_monitor_source_is_never_asked(self):
        """The permission decides before the query, not after it. Asking and
        discarding leaks nothing to the reader and everything to the backend
        log."""
        asked = []
        original = StoreMonitorSource.monitors

        def recording(source, window, scope, series=False):
            asked.append(scope.principal)
            return original(source, window, scope, series=series)

        StoreMonitorSource.monitors = recording
        try:
            self.data()
        finally:
            StoreMonitorSource.monitors = original
        self.assertEqual(asked, [])

    def test_the_rest_of_the_board_is_unaffected(self):
        payload = self.data().get_json()
        self.assertEqual(payload["total_hits"], 100)
        self.assertTrue(self.panel(payload, "log-1")["buckets"])
        self.assertIn("is unaffected", self.panel(payload, "mon-1")["error"])


class NotNarrowedByTheLogScopeTest(MonitorPanelTest):
    """A role's index patterns are about log data.

    `es_monitors.containers` refuses to filter monitors through them, on the
    grounds that applying them would hide the monitors from everybody whose
    scope happens not to mention `heartbeat-*` — which is everybody. The
    dashboard must not reintroduce that by the back door.
    """

    PANELS = [LOG_PANEL, STATUS_PANEL]

    def setUp(self):
        super().setUp()
        agent = self.agent()
        self.report(agent["id"], self.monitor("Checkout")["id"], "down")

    def test_a_viewer_whose_log_scope_reaches_nothing_still_sees_the_grid(self):
        """The dashboard's patterns are `app-*` and this role reaches only
        `infra-*`, so there is no log data to draw — which says nothing at
        all about which endpoints this person may watch."""
        self.login(("dashboard:view", "monitors:read"), indices=["infra-*"])
        payload = self.data().get_json()
        self.assertEqual(payload["error_type"], "no_accessible_containers")
        panel = self.panel(payload, "mon-1")
        self.assertEqual([row["name"] for row in panel["rows"]], ["Checkout"])
        self.assertEqual(panel["counts"]["down"], 1)

    def test_no_log_data_crosses_the_boundary_in_that_case(self):
        """The log boundary is intact; only the monitor panel crosses it.

        The log panel is still ON the board, carrying the reason it is empty
        rather than being dropped from the list — a panel that vanishes is a
        grid the reader cannot count, and "why is this card gone" is not a
        question the page answers. So the assertion is about its CONTENT: no
        buckets, and a sentence saying why.
        """
        self.login(("dashboard:view", "monitors:read"), indices=["infra-*"])
        payload = self.data().get_json()
        self.assertEqual([p["id"] for p in payload["panels"]],
                         ["log-1", "mon-1"])
        log = self.panel(payload, "log-1")
        self.assertEqual(log["buckets"], [], "log data crossed the boundary")
        self.assertIn("No accessible indices", log["error"])

    def test_the_permission_still_decides_in_that_case(self):
        """An empty log scope must not become a way around monitors:read
        either."""
        self.login(("dashboard:view",), indices=["infra-*"])
        panel = self.panel(self.data().get_json(), "mon-1")
        self.assertIn("monitors:read", panel["error"])


class DeadLogSourceTest(MonitorPanelTest):
    """The outage the monitor panel exists for.

    `_targets` resolves the LOG source before any panel is filled, so an
    unreachable Elasticsearch answered 503 and the client wiped the grid —
    including the monitor panel, whose own backend (WDash's own store) was
    perfectly healthy. That is the one reading this panel was added to
    support.
    """

    PANELS = [LOG_PANEL, STATUS_PANEL]

    def setUp(self):
        super().setUp()
        agent = self.agent()
        self.report(agent["id"], self.monitor("Checkout")["id"], "down")

    def log_source_is_down(self):
        source = self.hub.logs()
        original = source.containers

        def refuse(scope):
            raise ConnectionError("connection refused")

        source.containers = refuse
        self.addCleanup(setattr, source, "containers", original)

    def test_the_monitor_grid_survives_the_log_source(self):
        self.log_source_is_down()
        reply = self.data()
        self.assertEqual(reply.status_code, 200, reply.get_data(as_text=True))
        panel = self.panel(reply.get_json(), "mon-1")
        self.assertEqual([row["name"] for row in panel["rows"]], ["Checkout"])

    def test_the_reason_the_other_half_is_missing_is_still_said(self):
        """The client prints `error` above the grid. Filling the monitor
        panel must not quietly hide that the log half could not be read.

        Said twice over, in the two places a reader looks: once above the
        grid for the page, and once inside the log panel's own card. The log
        panel stays on the board carrying that reason — dropping it would
        leave a grid with a hole in it and nothing saying what used to be
        there.
        """
        self.log_source_is_down()
        payload = self.data().get_json()
        self.assertEqual(payload["error_type"], "elasticsearch_connection")
        self.assertIn("Unable to connect", payload["error"])
        self.assertEqual([p["id"] for p in payload["panels"]],
                         ["log-1", "mon-1"])
        self.assertIn("Unable to connect", self.panel(payload, "log-1")["error"])

    def test_the_summary_counts_are_not_reported_as_zero(self):
        """The four tiles at the top of the page are the log source's, and
        nobody counted them on this path.

        Turning the outage from 503 into 200 moved them from "unknown" to
        "zero": the body carried `total_hits: 0` and no error, warning or
        info count at all, and the client coerces an absent count to 0 — so
        the top of the page read "0 records, 0 errors, 0.00%" above a healthy
        green monitor grid. That is a quiet night, which is the one reading
        this whole package exists to prevent, and it is emptiness standing in
        for an answer.

        The absence IS the signal, and there is no flag beside it: a count
        that is not in the body is one that did not run, and `updateStats`
        prints an em dash for it (tests/dashboard_smoke.js, 'a count that did
        not run is an em dash, not zero', and the monitor board's own copy of
        that check). A flag would be a second way to say the same thing, and
        the one nobody sets is the one that ships a zero.
        """
        self.log_source_is_down()
        payload = self.data().get_json()
        self.assertNotIn("total_hits", payload,
                         "a count the log source could not make was asserted")
        for key in ("error_count", "warn_count", "info_count", "error_rate"):
            self.assertNotIn(key, payload)
        # And the reason is still in the body, so the absence is not the only
        # thing the reader gets.
        self.assertIn("Unable to connect", payload["error"])

    def test_a_board_of_log_panels_alone_still_fails_loudly(self):
        """Nothing on that board can be drawn, and 200 with an empty list is
        the project's forbidden failure — emptiness standing in for an
        answer."""
        change_dashboard(self.app, self.board, panels=[LOG_PANEL])
        self.log_source_is_down()
        reply = self.data()
        self.assertEqual(reply.status_code, 503)
        self.assertEqual(reply.get_json()["error_type"],
                         "elasticsearch_connection")


class MonitorSourceFailureTest(MonitorPanelTest):
    """A monitor backend that cannot answer costs its panel, not the page."""

    PANELS = [LOG_PANEL, STATUS_PANEL]

    def test_a_failing_listing_is_a_reason_rather_than_an_empty_grid(self):
        def explode(window, scope, series=False):
            raise RuntimeError("the store is gone")

        self.monitors.monitors = explode
        payload = self.data().get_json()
        self.assertEqual(self.panel(payload, "mon-1")["error"],
                         "Monitor data could not be loaded.")
        self.assertTrue(self.panel(payload, "log-1")["buckets"])

    def test_a_partial_listing_says_which_source_did_not_answer(self):
        """One source of several not answering is not 'those checks are all
        passing': it is a shorter list nobody can read as one."""
        from wdash.hub.models import MonitorPage

        def short(window, scope, series=False):
            return MonitorPage(monitors=[], partial=True,
                               sources=("a",), missing_sources=("b",),
                               warnings=("b: connection refused",))

        self.monitors.monitors = short
        panel = self.panel(self.data().get_json(), "mon-1")
        self.assertTrue(panel["partial"])
        self.assertEqual(panel["warnings"], ["b: connection refused"])


class TracingES(FakeES):
    """FakeES with a trace store standing beside the log indices.

    The real `ElasticsearchTraceSource` matches the index against its
    patterns, reads its mapping to pick a span schema and evaluates the
    aggregation it asked for, so the trace panel here is filled by the
    adapter rather than by a stub standing in for it — including the `failed`
    sub-aggregation the query actually asks for.
    """

    TRACE_INDEX = "traces-apm-000001"

    @property
    def cat(self):
        listed = super().cat

        class Cat:
            def indices(self, **kw):
                return list(listed.indices(**kw)) + [
                    {"index": TracingES.TRACE_INDEX, "creation.date": "300"}]
        return Cat()

    @property
    def indices(self):
        mapped = super().indices

        class Indices:
            def get_mapping(self, index=None, **kw):
                if index == TracingES.TRACE_INDEX:
                    return {index: {"mappings": {"properties": {
                        "trace": {"properties": {"id": {"type": "keyword"}}},
                        "transaction": {"properties": {
                            "id": {"type": "keyword"}}},
                        "service": {"properties": {
                            "name": {"type": "keyword"}}}}}}}
                return mapped.get_mapping(index=index, **kw)
        return Indices()

    def _run(self, index=None, body=None):
        reply = super()._run(index, body)
        if ((body or {}).get("aggs") or {}).get("services"):
            reply["aggregations"]["services"] = {"buckets": [
                {"key": "checkout", "doc_count": 12,
                 "failed": {"doc_count": 3}}]}
        return reply


class TracePanelsOnTheFailurePathsTest(MonitorPanelTest):
    """`_without_log_containers` routes every non-log panel, not only monitors.

    Both paths it covers now reach the trace panel as well, and nothing
    pinned that: a later edit narrowing `needs_logs` to the monitor signal
    would take the trace panel back down with the log source and every test
    would still pass. The reach is real either way — a role holding
    dashboard:view alone has always been able to fill a trace panel on the
    ordinary path, because no dashboard route has ever checked traces:read —
    so this measures what that filter now covers rather than changing it.
    """

    PANELS = [LOG_PANEL, TRACE_PANEL]

    def make_es(self):
        return TracingES()

    def test_a_trace_panel_survives_a_dead_log_source(self):
        source = self.hub.logs()
        original = source.containers
        source.containers = lambda scope: (_ for _ in ()).throw(
            ConnectionError("connection refused"))
        self.addCleanup(setattr, source, "containers", original)

        reply = self.data()
        self.assertEqual(reply.status_code, 200)
        panel = self.panel(reply.get_json(), "tr-1")
        self.assertNotIn("error", panel, panel.get("error"))
        self.assertEqual([row["name"] for row in panel["rows"]], ["checkout"])

    def test_a_trace_panel_survives_an_empty_log_scope(self):
        """The log scope is a boundary on log data; the trace panel has its
        own — `allowed_trace_indices` and `allowed_services`, which this role
        still holds."""
        self.login(("dashboard:view", "monitors:read"), indices=["infra-*"])
        payload = self.data().get_json()
        self.assertEqual(payload["error_type"], "no_accessible_containers")
        panel = self.panel(payload, "tr-1")
        self.assertEqual([row["name"] for row in panel["rows"]], ["checkout"])


class MonitorLinkTest(unittest.TestCase):
    """The cell's link and the route's converter, over one list of ids.

    `monitorUrl` in async-dashboard.js is a second copy of
    `MonitorIdConverter.to_url`, kept because the client builds the link and
    the ids come out of documents. A copy that drifts on the characters that
    matter — `.`, `..`, `/`, `~` — links a cell to the page next door, so the
    two are held to the same table: this half asserts what Python produces,
    and the jsdom check of the same name asserts the JavaScript produces
    exactly these strings.
    """

    #: id -> what one segment of the URL must be.
    LINKS = {
        ".": "~.",
        "..": "~..",
        "~": "~7E",
        "a~b": "a~7Eb",
        "a/b": "a%2Fb",
        "o'brien": "o%27brien",
        "a(b)c": "a%28b%29c",
        "a*b": "a%2Ab",
        "!x": "%21x",
        "héllo": "h%C3%A9llo",
        "plain-id_1.2": "plain-id_1.2",
    }

    def test_the_converter_writes_every_id_as_one_segment(self):
        from wdash.api.monitor_routes import MonitorIdConverter
        converter = MonitorIdConverter.__new__(MonitorIdConverter)
        self.assertEqual(
            {monitor_id: converter.to_url(monitor_id)
             for monitor_id in self.LINKS}, self.LINKS)


class PanelDefinitionTest(unittest.TestCase):
    """What the panel list will accept."""

    def test_a_monitor_panel_declares_the_monitor_signal(self):
        from wdash.dashboard.panels import normalise, signals
        panels = [normalise(dict(STATUS_PANEL)),
                  normalise(dict(CERTIFICATE_PANEL))]
        self.assertEqual(signals(panels), {"monitors"})

    def test_a_mixed_board_names_every_source_it_needs(self):
        from wdash.dashboard.panels import normalise, signals
        panels = [normalise(dict(LOG_PANEL)), normalise(dict(STATUS_PANEL))]
        self.assertEqual(signals(panels), {"logs", "monitors"})

    def test_status_is_the_view_a_panel_gets_when_it_names_none(self):
        from wdash.dashboard.panels import normalise
        self.assertEqual(normalise({"type": "monitors"})["view"], "status")

    def test_a_view_nobody_can_answer_is_refused_on_the_way_in(self):
        from wdash.dashboard.panels import PanelError, normalise
        with self.assertRaises(PanelError) as caught:
            normalise({"type": "monitors", "view": "p99"})
        self.assertIn("p99", str(caught.exception))
        self.assertIn("availability", str(caught.exception))

    def test_the_board_refuses_a_panel_it_cannot_draw(self):
        """A dashboard whose stored panels name a view that no longer exists
        is an error with the name in it, not a blank card."""
        from wdash.dashboard.panels import PanelError, normalise_all
        with self.assertRaises(PanelError):
            normalise_all([{"type": "monitors", "view": "sometimes"}])


if __name__ == "__main__":          # pragma: no cover
    unittest.main()
