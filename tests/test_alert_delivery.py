"""
Channels, the store behind them, and the loop that drives both.

The state machine is tested in `test_alert_evaluation.py` without any I/O.
What is here is everything around it: that a webhook URL is treated as the
credential it is, that a failed delivery is recorded and retried rather than
lost, and that one broken rule does not take the others down.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.alerts.channels import DeliveryError, payload, send  # noqa: E402
from wdash.alerts.runner import AlertRunner, observe  # noqa: E402
from wdash.hub import Hub  # noqa: E402
from wdash.hub.models import DOWN, UNKNOWN, UP, Certificate, Monitor, \
    MonitorPage  # noqa: E402
from wdash.store import Store  # noqa: E402
from wdash.store.alerting import AlertingError  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402


class Receiver:
    """A real HTTP server, so the client is exercised rather than mocked."""

    def __init__(self, status=200, body=b"ok"):
        self.received = []
        self.status = status
        self.body = body
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                outer.received.append({
                    "body": json.loads(raw or b"{}"),
                    "headers": dict(self.headers)})
                self.send_response(outer.status)
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *arguments):
                pass

        from tests.support import serve_in_background
        self._server = serve_in_background(HTTPServer(("127.0.0.1", 0), Handler))

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_port}/services/T/B/xxTOKENxx"

    def stop(self):
        self._server.shutdown()


class AlertingTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.store = Store.open(f"sqlite:///{self.database}",
                                secret_box=SecretBox(SecretBox.generate_key()))
        self.receiver = Receiver()

    def tearDown(self):
        self.receiver.stop()
        self.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _channel(self, url=None):
        return self.store.channels.create("hook", url=url or self.receiver.url)

    def _hub(self, *monitors):
        class Source:
            name = "fake"
            capabilities = frozenset({"monitor_list"})

            def monitors(self, window, scope, series=False):
                return MonitorPage(monitors=list(monitors), sources=("fake",))

            def health(self):
                return True, "ok"

            def containers(self, scope):
                return []

        hub = Hub()
        hub.add_monitors(Source())
        return hub


class ChannelSecrecyTest(AlertingTestCase):
    """A webhook URL is a credential.

    For Slack and Teams the PATH is the secret: anybody holding the URL can
    post into the channel. Storing it beside the name would put it on a
    screen, in a template, and in every backup of the metadata database.
    """

    def test_the_url_is_not_in_the_public_shape(self):
        channel = self._channel()
        self.assertNotIn("xxTOKENxx", json.dumps(channel))

    def test_the_host_is_shown_so_a_screen_can_say_where_alerts_go(self):
        channel = self._channel()
        self.assertTrue(channel["host"].startswith("127.0.0.1:"))

    def test_it_is_nowhere_on_disk_in_clear(self):
        """The WHOLE row, not just the secrets column.

        Checking `secrets` alone passes even when the URL is also written into
        the plain `config` JSON beside it — which is on every screen that
        renders a channel and in every backup of the metadata database.
        """
        self._channel()
        # The row as the database holds it, through a connection of its own
        # rather than the repository — on either dialect.
        with self.store.engine.connect() as connection:
            row = connection.exec_driver_sql(
                "SELECT * FROM wdash_alert_channels").fetchone()
        self.assertNotIn("xxTOKENxx", " ".join(str(v) for v in row))

    def test_the_runner_can_still_read_it(self):
        channel = self._channel()
        self.assertIn("xxTOKENxx",
                      self.store.channels.credentials(channel["id"])["url"])

    def test_a_url_that_is_not_a_url_is_refused(self):
        with self.assertRaises(AlertingError):
            self.store.channels.create("bad", url="hooks.slack.com/x")


class DeliveryTest(AlertingTestCase):
    def _send(self, status=200, body=b"ok"):
        self.receiver.status = status
        self.receiver.body = body
        channel = self._channel()
        return send(channel,
                    self.store.channels.credentials(channel["id"]),
                    {"hello": "world"})

    def test_a_webhook_is_posted_as_json(self):
        self._send()
        self.assertEqual(self.receiver.received[0]["body"], {"hello": "world"})
        self.assertEqual(
            self.receiver.received[0]["headers"]["Content-Type"],
            "application/json")

    def test_a_refusal_carries_the_reason(self):
        """A webhook that refuses usually says why — "no such channel",
        "token revoked" — and that sentence is the whole answer to why alerts
        stopped arriving."""
        with self.assertRaises(DeliveryError) as caught:
            self._send(status=404, body=b"channel_not_found")
        self.assertIn("404", str(caught.exception))
        self.assertIn("channel_not_found", str(caught.exception))

    def test_the_reason_does_not_contain_the_url(self):
        """The failure is written to the alert history and shown on a screen.

        Against an UNREACHABLE receiver, because that is the error that
        actually carries the URL — requests renders the target into a
        connection error. A refusal with a short body does not, so testing
        that one passes with the redaction deleted.
        """
        channel = self.store.channels.create(
            "dead", url="http://127.0.0.1:59997/services/T/B/xxTOKENxx")
        with self.assertRaises(DeliveryError) as caught:
            send(channel, self.store.channels.credentials(channel["id"]), {})
        message = str(caught.exception)
        self.assertTrue(message, "the reason was lost entirely")
        self.assertNotIn("xxTOKENxx", message)

    def test_a_receiver_that_echoes_the_url_back_is_redacted_too(self):
        """Some webhooks quote the request in their refusal.

        A separate case from the unreachable one: `requests` renders the host
        and the path separately, so the token there is caught by the
        path-tail rule. A body containing the WHOLE url is what the full-url
        rule is for, and without this test that line could be deleted with
        everything still green.
        """
        channel = self._channel()
        url = self.store.channels.credentials(channel["id"])["url"]
        self.receiver.status = 400
        self.receiver.body = f"rejected request to {url}".encode()
        with self.assertRaises(DeliveryError) as caught:
            send(channel, self.store.channels.credentials(channel["id"]), {})
        message = str(caught.exception)
        self.assertNotIn(url, message)
        self.assertNotIn("xxTOKENxx", message)
        # The reason survives; only the credential goes.
        self.assertIn("400", message)

    def _refusal(self, url):
        channel = self.store.channels.create("dead", url=url)
        with self.assertRaises(DeliveryError) as caught:
            send(channel, self.store.channels.credentials(channel["id"]), {})
        return str(caught.exception)

    def test_a_url_ending_in_a_slash_keeps_its_credential(self):
        """Zapier's catch hooks end in '/'. The last segment was then empty,
        and the token before it went into the history as sent — measured,
        the whole path was in the message."""
        message = self._refusal(
            "http://127.0.0.1:59997/hooks/catch/1234567/XXSECRETXX1/")
        self.assertNotIn("XXSECRETXX1", message)
        self.assertIn("127.0.0.1", message, "the reason lost its host")

    def test_every_long_segment_is_a_credential(self):
        """Slack's is three segments, not one."""
        message = self._refusal(
            "http://127.0.0.1:59997/services/T0SECRET01/B0SECRET02/last-part-x")
        for secret in ("T0SECRET01", "B0SECRET02", "last-part-x"):
            self.assertNotIn(secret, message)

    def test_a_token_in_the_query_or_the_user_part_is_redacted(self):
        """Quoted back by a receiver, the way the whole-URL case is."""
        port = self.receiver._server.server_port
        url = f"http://hook:PASSWORD9876@127.0.0.1:{port}/h?token=QUERYSECRET1&x=1"
        channel = self.store.channels.create("quoting", url=url)
        self.receiver.status = 400
        self.receiver.body = f"rejected {url}".encode()
        with self.assertRaises(DeliveryError) as caught:
            send(channel, self.store.channels.credentials(channel["id"]), {})
        message = str(caught.exception)
        self.assertNotIn("QUERYSECRET1", message)
        self.assertNotIn("PASSWORD9876", message)
        self.assertIn("400", message)

    def test_a_credential_is_redacted_as_requests_writes_it(self):
        """`requests` puts the path into a connection error percent-encoded,
        and a token with a character it encodes was left in that form."""
        message = self._refusal("http://127.0.0.1:59997/hooks/s\u00e9cret-tok\u00e9n-1")
        self.assertNotIn("s%C3%A9cret-tok%C3%A9n-1", message)
        self.assertNotIn("s\u00e9cret-tok\u00e9n-1", message)

    def test_a_short_path_is_not_taken_for_a_credential(self):
        """`/hook` is a word; blanking it would take the reason with it."""
        port = self.receiver._server.server_port
        channel = self.store.channels.create(
            "short", url=f"http://127.0.0.1:{port}/hook")
        self.receiver.status = 410
        self.receiver.body = b"this webhook is disabled"
        with self.assertRaises(DeliveryError) as caught:
            send(channel, self.store.channels.credentials(channel["id"]), {})
        self.assertIn("this webhook is disabled", str(caught.exception))

    def test_a_sealed_header_of_any_name_is_redacted(self):
        """Any header can be sealed; only three names were redacted.
        A receiver that quoted a custom token put it in the history."""
        channel = self.store.channels.create(
            "hook", url=self.receiver.url,
            secret_headers={"X-Auth-Token": "SEALED-TOKEN-VALUE"})
        self.receiver.status = 401
        self.receiver.body = b"bad X-Auth-Token: SEALED-TOKEN-VALUE"
        with self.assertRaises(DeliveryError) as caught:
            send(channel, self.store.channels.credentials(channel["id"]), {})
        message = str(caught.exception)
        self.assertNotIn("SEALED-TOKEN-VALUE", message)
        self.assertIn("401", message)
        self.assertEqual(self.receiver.received[0]["headers"]["X-Auth-Token"],
                         "SEALED-TOKEN-VALUE", "the header was not sent")

    def test_an_unreachable_receiver_is_a_delivery_error(self):
        channel = self.store.channels.create(
            "dead", url="http://127.0.0.1:59997/hook")
        with self.assertRaises(DeliveryError):
            send(channel, self.store.channels.credentials(channel["id"]), {})

    def test_the_payload_says_when_it_started(self):
        """"down since 03:12" is what somebody woken at 04:00 needs; "as of
        04:00" is what they already know."""
        from wdash.alerts.evaluate import Decision, State
        started = datetime(2026, 8, 6, 3, 12, tzinfo=timezone.utc)
        body = payload({"id": "r", "name": "n", "kind": "monitor_down"},
                       Decision("m1", "API", State(), detail="500",
                                since=started), "firing")
        self.assertEqual(body["since"], started.isoformat())
        self.assertEqual(body["transition"], "firing")


class RunnerTest(AlertingTestCase):
    def _rule(self, channel=None, **kwargs):
        options = dict(name="API down", kind="monitor_down", threshold=1)
        options.update(kwargs)
        return self.store.rules.create(
            channel_id=(channel or self._channel())["id"], **options)

    def _runner(self, *monitors):
        return AlertRunner(self.store, self._hub(*monitors))

    def test_a_down_monitor_fires(self):
        self._rule()
        runner = self._runner(Monitor(id="m1", name="API", status=DOWN,
                                      error="500"))
        self.assertEqual(runner.evaluate_once(), 1)
        self.assertEqual(self.receiver.received[0]["body"]["name"], "API")

    def test_an_unknown_monitor_does_not(self):
        """An agent that stopped reporting says nothing about the target.
        Paging somebody because a probe restarted is how a channel gets
        muted, and that case has its own rule kind."""
        self._rule()
        runner = self._runner(Monitor(id="m1", name="API", status=UNKNOWN))
        self.assertEqual(runner.evaluate_once(), 0)

    def test_a_failed_delivery_is_recorded_and_retried(self):
        """A webhook that was down when the alert fired would otherwise be an
        outage nobody was ever told about: the state says firing, and with no
        repeat interval it would never try again."""
        self.receiver.status = 500
        self._rule()
        runner = self._runner(Monitor(id="m1", name="API", status=DOWN))

        self.assertEqual(runner.evaluate_once(), 0)
        entry = self.store.alert_history.recent()[0]
        self.assertFalse(entry["delivered"])
        self.assertTrue(entry["delivery_error"])

        self.receiver.status = 200
        self.assertEqual(runner.evaluate_once(), 1)
        # And then it stops, rather than repeating for ever.
        self.assertEqual(runner.evaluate_once(), 0)

    def test_one_broken_rule_does_not_silence_the_others(self):
        """A rule that RAISES must not stop every other alert.

        A rule pointing at a deleted channel is handled and returns a delivery
        failure — it never reaches the handler, so testing with one passes
        with the handler removed. A selector of the wrong shape does raise,
        which is the case worth protecting: one malformed row should not make
        the whole installation go quiet.
        """
        working = self._channel()
        broken = self.store.rules.create(
            name="broken", kind="monitor_down", channel_id=working["id"],
            selector={"team": "payments"})
        # A list where a mapping is expected — the shape a hand-edited row or
        # a future import could produce.
        with self.store.engine.begin() as connection:
            from sqlalchemy import update as _update

            from wdash.store.schema import alert_rules
            connection.execute(
                _update(alert_rules).where(alert_rules.c.id == broken["id"])
                .values(selector=["not", "a", "mapping"]))

        self._rule(channel=working, name="working")
        runner = self._runner(Monitor(id="m1", name="API", status=DOWN))
        self.assertEqual(runner.evaluate_once(), 1)

    def test_a_silenced_subject_sends_nothing(self):
        self._rule()
        self.store.silences.create(
            "m1", datetime.now(timezone.utc) + timedelta(hours=1), "maintenance")
        runner = self._runner(Monitor(id="m1", name="API", status=DOWN))
        self.assertEqual(runner.evaluate_once(), 0)

    def test_history_records_both_transitions(self):
        self._rule()
        monitor = Monitor(id="m1", name="API", status=DOWN, error="500")
        self._runner(monitor).evaluate_once()
        monitor.status = UP
        self._runner(monitor).evaluate_once()
        transitions = [h["transition"]
                       for h in self.store.alert_history.recent()]
        self.assertEqual(sorted(transitions), ["firing", "resolved"])


class ObservationTest(AlertingTestCase):
    """What each rule kind counts as bad."""

    def _observe(self, rule, *monitors):
        from wdash.hub.query import TimeWindow
        hub = self._hub(*monitors)
        return observe(rule, hub.monitors(hub.ALL_SOURCES), self.store,
                       TimeWindow.of("1h"),
                       datetime.now(timezone.utc)).observations

    def test_monitor_down_ignores_unknown(self):
        observations = self._observe(
            {"kind": "monitor_down"},
            Monitor(id="a", status=DOWN), Monitor(id="b", status=UNKNOWN),
            Monitor(id="c", status=UP))
        self.assertEqual({o.subject: o.bad for o in observations},
                         {"a": True, "b": False, "c": False})

    def test_a_certificate_rule_only_sees_checks_that_have_one(self):
        now = datetime.now(timezone.utc)
        soon = Certificate(not_after=now + timedelta(days=5))
        later = Certificate(not_after=now + timedelta(days=200))
        observations = self._observe(
            {"kind": "certificate_expiring", "days_before": 30},
            Monitor(id="soon", status=UP, certificate=soon),
            Monitor(id="later", status=UP, certificate=later),
            Monitor(id="plain", status=UP))
        self.assertEqual({o.subject: o.bad for o in observations},
                         {"soon": True, "later": False})

    def test_an_expired_certificate_says_so_rather_than_counting_down(self):
        now = datetime.now(timezone.utc)
        observations = self._observe(
            {"kind": "certificate_expiring", "days_before": 30},
            Monitor(id="gone", status=UP,
                    certificate=Certificate(not_after=now - timedelta(days=3))))
        self.assertIn("expired", observations[0].detail)

    def test_an_empty_selector_watches_everything(self):
        """A monitor added later is covered without anybody remembering to add
        it — the omission nobody notices until the outage."""
        observations = self._observe(
            {"kind": "monitor_down", "selector": {}},
            Monitor(id="a", status=DOWN), Monitor(id="b", status=DOWN))
        self.assertEqual(len(observations), 2)

    def test_a_selector_narrows_by_label(self):
        observations = self._observe(
            {"kind": "monitor_down", "selector": {"team": "payments"}},
            Monitor(id="a", status=DOWN, tags=("team=payments",)),
            Monitor(id="b", status=DOWN, tags=("team=search",)))
        self.assertEqual([o.subject for o in observations], ["a"])

    def test_agent_silent_looks_at_agents_rather_than_monitors(self):
        """Different fact, different audience: "the payment API is
        unreachable" goes to whoever owns payments, "the Frankfurt probe is
        dead" to whoever runs the probes."""
        agent, _ = self.store.agents.create("frankfurt")
        observations = self._observe({"kind": "agent_silent"})
        self.assertEqual([o.subject for o in observations], [agent["id"]])
        self.assertTrue(observations[0].bad)     # never reported

    def test_a_reporting_agent_is_not_silent(self):
        agent, _ = self.store.agents.create("frankfurt")
        self.store.agents.seen(agent["id"])
        observations = self._observe({"kind": "agent_silent"})
        self.assertFalse(observations[0].bad)


if __name__ == "__main__":
    unittest.main()


class ManagementPageTest(unittest.TestCase):
    """Defining channels, rules and silences from the configuration page."""

    def setUp(self):
        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database
        self.receiver = Receiver()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "alerts"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        grant(self.app, "admin", ["system:admin", "monitors:read"],
              indices=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "u1", "username": "admin", "email": "a@b", "groups": [],
                "role": "admin",
                "permissions": ["system:admin", "monitors:read"],
                "allowed_indices": ["*"]}
            session["_user_id"] = "u1"

    def tearDown(self):
        self.receiver.stop()
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _channel(self):
        self.client.post("/admin/channels",
                         data={"name": "on-call", "url": self.receiver.url},
                         follow_redirects=True)
        return self.app.store.channels.all()[0]

    def test_the_webhook_url_never_reaches_the_page(self):
        """For Slack and Teams the path IS the credential — a screen showing
        it is a screen that leaks the ability to post."""
        self._channel()
        body = self.client.get("/admin/config").get_data(as_text=True)
        self.assertNotIn("xxTOKENxx", body)
        self.assertIn("127.0.0.1", body)      # the host, so it can be told apart

    def test_a_channel_in_use_cannot_be_deleted(self):
        """Deleting it would leave those rules evaluating and failing to
        deliver — alerts firing into nothing, which is the failure this whole
        feature exists to prevent."""
        channel = self._channel()
        self.client.post("/admin/rules",
                         data={"name": "r", "kind": "monitor_down",
                               "channel_id": channel["id"], "threshold": "1"},
                         follow_redirects=True)
        body = self.client.post(f"/admin/channels/{channel['id']}/delete",
                                follow_redirects=True).get_data(as_text=True)
        self.assertIn("still used by", body)
        self.assertEqual(len(self.app.store.channels.all()), 1)

    def test_a_rule_is_saved_with_its_selector(self):
        channel = self._channel()
        self.client.post("/admin/rules",
                         data={"name": "payments", "kind": "monitor_down",
                               "channel_id": channel["id"], "threshold": "5",
                               "repeat_minutes": "15",
                               "selector": "team: payments"},
                         follow_redirects=True)
        rule = self.app.store.rules.all()[0]
        self.assertEqual(rule["selector"], {"team": "payments"})
        self.assertEqual(rule["threshold"], 5)

    def test_a_silence_that_has_already_ended_is_refused(self):
        """A control that did nothing, and somebody walks away believing they
        set one."""
        body = self.client.post("/admin/silences",
                                data={"subject": "m1", "hours": "-1"},
                                follow_redirects=True).get_data(as_text=True)
        self.assertIn("in the future", body)
        self.assertEqual(self.app.store.silences.all(), [])

    def test_a_viewer_cannot_define_alerting(self):
        from tests.support import grant
        grant(self.app, "admin", ["monitors:read"], indices=["*"])
        response = self.client.post(
            "/admin/channels", data={"name": "x", "url": self.receiver.url})
        self.assertIn(response.status_code, (302, 403))
        self.assertEqual(self.app.store.channels.all(), [])

    def test_the_history_page_lists_what_fired(self):
        channel = self._channel()
        self.app.store.rules.create(name="r", kind="monitor_down",
                                    channel_id=channel["id"], threshold=1)

        class Source:
            name = "fake"
            capabilities = frozenset()

            def monitors(self, window, scope, series=False):
                return MonitorPage(
                    monitors=[Monitor(id="m2", name="API", status=DOWN,
                                      error="500")], sources=("fake",))

            def health(self):
                return True, "ok"

            def containers(self, scope):
                return []

        self.app.hub.add_monitors(Source())
        AlertRunner(self.app.store, self.app.hub).evaluate_once()

        body = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("API", body)
        self.assertIn("firing", body)

    def test_undelivered_alerts_have_their_own_view(self):
        """The absence of alerts reads as "nothing is wrong", so an alert that
        was never sent needs somewhere it cannot hide."""
        channel = self._channel()
        rule = self.app.store.rules.create(
            name="r", kind="monitor_down", channel_id=channel["id"])
        self.app.store.alert_history.record(
            rule["id"], "m1", "firing", "500", delivered=False,
            error="the receiver answered 500")

        body = self.client.get("/alerts?undelivered=1").get_data(as_text=True)
        self.assertIn("m1", body)
        self.assertIn("the receiver answered 500", body)

    def test_alerts_need_the_monitors_permission(self):
        from tests.support import grant
        grant(self.app, "admin", ["logs:read"], indices=["*"])
        self.assertEqual(self.client.get("/alerts").status_code, 302)

    def test_the_banner_does_not_promise_a_drain_that_cannot_come(self):
        """It said "an entry that stays is a channel that is still broken".

        `evaluate_once` walks enabled rules only, and deleting a rule leaves
        its history behind, so an entry belonging to a switched-off or
        deleted rule stays for ever with every channel working. Measured: one
        failed delivery, the rule disabled, ten passes — badge still 1; the
        rule deleted — badge still 1.
        """
        channel = self._channel()
        rule = self.app.store.rules.create(
            name="r", kind="monitor_down", channel_id=channel["id"])
        self.app.store.alert_history.record(
            rule["id"], "m1", "firing", "500", delivered=False, error="500")
        self.app.store.rules.update(rule["id"], enabled=False)
        self.assertEqual(
            self.app.store.alert_history.count(undelivered_only=True), 1,
            "a disabled rule's undelivered row would have to be hidden for "
            "the old sentence to be true")

        body = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("switched off or deleted", body)
        self.assertNotIn("an entry that stays is a channel that is still "
                         "broken", body)


class HistoryLabelTest(AlertingTestCase):
    """A history row has to name what it is about.

    Version 12 stored the subject id alone, so the screen showed a uuid.
    Looking the name up at render time does not work either: history is most
    often read about a monitor that has since been deleted, which is exactly
    when the name is gone.
    """

    def test_the_name_is_stored_with_the_row(self):
        channel = self._channel()
        self.store.rules.create(name="r", kind="monitor_down",
                                channel_id=channel["id"], threshold=1)
        runner = AlertRunner(self.store, self._hub(
            Monitor(id="4f2c-uuid", name="Payments API", status=DOWN,
                    error="500")))
        runner.evaluate_once()
        entry = self.store.alert_history.recent()[0]
        self.assertEqual(entry["subject_label"], "Payments API")
        self.assertEqual(entry["subject"], "4f2c-uuid")

    def test_it_survives_the_monitor_being_deleted(self):
        """The row still says what it was about when nothing else can."""
        self.store.alert_history.record("r", "gone-id", "firing",
                                        label="Payments API")
        self.assertEqual(self.store.alert_history.recent()[0]["subject_label"],
                         "Payments API")

    def test_a_row_with_no_label_falls_back_to_the_id(self):
        self.store.alert_history.record("r", "some-id", "firing")
        self.assertEqual(self.store.alert_history.recent()[0]["subject_label"],
                         "some-id")


class NoChannelYetTest(ManagementPageTest):
    """The first thing anybody sees, before anything is configured.

    A rule cannot be saved without somewhere to send, so the button used to be
    `disabled` with the reason in a `title`. Browsers do not show a title on a
    disabled control — pointer events are suppressed — so it was a dead end
    with no visible explanation: the button does nothing, hovering says
    nothing, and there is no hint that a channel is what is missing.
    """

    def _page(self):
        return self.client.get("/admin/config").get_data(as_text=True)

    def test_the_rule_button_is_not_a_dead_end(self):
        body = self._page()
        self.assertNotIn('id="addRuleAlertBtn"', body)
        self.assertIn("Add a channel first", body)

    def test_it_says_what_is_missing(self):
        self.assertIn("A rule needs somewhere to send", self._page())

    def test_the_way_out_opens_the_channel_form(self):
        """The replacement has to DO something, or it is the same dead end
        with different wording."""
        body = self._page()
        after = body.split("Add a channel first")[0][-300:]
        self.assertIn("#channelModal", after)

    def test_once_a_channel_exists_the_rule_button_returns(self):
        self._channel()
        body = self._page()
        self.assertIn('id="addRuleAlertBtn"', body)
        self.assertNotIn("Add a channel first", body)

    def test_and_a_rule_can_then_be_saved(self):
        channel = self._channel()
        self.client.post("/admin/rules",
                         data={"name": "API down", "kind": "monitor_down",
                               "channel_id": channel["id"], "threshold": "3"},
                         follow_redirects=True)
        self.assertEqual(len(self.app.store.rules.all()), 1)


class RuleReadabilityTest(unittest.TestCase):
    """A rule has to say what it does, in a sentence.

    The first version showed `kind`, `threshold` and `selector` in three
    columns — `monitor_down`, `3 failure(s) in a row`, `everything`. Each
    fragment is accurate and together they are not a statement anybody can
    check against what they meant. A rule nobody can read is a rule nobody
    can tell is wrong.
    """

    CHANNELS = [{"id": "c1", "name": "on-call"}]

    def _describe(self, **rule):
        from wdash.api.config_routes import _describe_rule
        base = {"kind": "monitor_down", "threshold": 3, "repeat_minutes": 0,
                "channel_id": "c1", "selector": {}}
        base.update(rule)
        return _describe_rule(base, self.CHANNELS)

    def test_it_names_the_channel(self):
        self.assertTrue(self._describe().startswith("Tells on-call when"))

    def test_it_says_the_threshold_in_words(self):
        self.assertIn("fails 3 checks in a row", self._describe())

    def test_one_is_singular(self):
        """"fails 1 checks in a row" is the tell of a sentence assembled by
        something that was not reading it."""
        self.assertIn("fails one check", self._describe(threshold=1))

    def test_the_subject_is_singular_too(self):
        """A rule watching fifty monitors fires fifty times, once per monitor.
        "monitors labelled x fails" is both ungrammatical and the wrong mental
        model — it reads as one alert for the whole group."""
        sentence = self._describe(selector={"team": "payments"})
        self.assertIn("any monitor labelled team=payments fails", sentence)

    def test_no_repeat_says_once(self):
        self.assertTrue(self._describe().endswith(", once."))

    def test_a_repeat_says_until_it_recovers(self):
        self.assertIn("every 15 minutes until it recovers",
                      self._describe(repeat_minutes=15))

    def test_a_certificate_rule_reads_as_a_diary_entry(self):
        sentence = self._describe(kind="certificate_expiring", days_before=14)
        self.assertIn("within 14 days of expiring", sentence)
        self.assertNotIn("fails", sentence)

    def test_an_agent_rule_is_about_the_probe(self):
        self.assertIn("an agent stops reporting",
                      self._describe(kind="agent_silent"))

    def test_a_missing_channel_is_stated_as_the_fault_it_is(self):
        """A rule with no channel fires into nothing, and that is the thing to
        notice — not a blank in a column."""
        sentence = self._describe(channel_id="deleted")
        self.assertIn("nobody is told", sentence)

    def test_every_kind_has_a_title_and_an_explanation(self):
        """The dropdown shows the title. `monitor_down` is what the database
        calls it; nobody should have to learn that to configure an alert."""
        from wdash.alerts.evaluate import RULE_KINDS
        from wdash.api.config_routes import RULE_DESCRIPTIONS
        for kind in RULE_KINDS:
            self.assertIn(kind, RULE_DESCRIPTIONS)
            title, explanation = RULE_DESCRIPTIONS[kind]
            self.assertTrue(title and explanation)
            # The title must not be the identifier with the underscore taken
            # out — that is the jargon with a coat of paint.
            self.assertNotEqual(title.lower(), kind.replace("_", " "))


class RuleFormTest(ManagementPageTest):
    """The dictionary being right is not the same as the page using it.

    A mutation putting `kind.replace('_', ' ')` back into the template
    survived every test above: they all read RULE_DESCRIPTIONS directly and
    none of them looked at what was rendered.
    """

    def _page(self):
        return self.client.get("/admin/config").get_data(as_text=True)

    def test_the_dropdown_shows_titles_not_identifiers(self):
        from wdash.api.config_routes import RULE_DESCRIPTIONS
        body = self._page()
        for kind, (title, explanation) in RULE_DESCRIPTIONS.items():
            self.assertIn(title, body)
            self.assertIn(explanation[:40], body)
            self.assertNotIn(f">{kind.replace('_', ' ')}<", body)


class SilenceFormTest(ManagementPageTest):
    """Silencing is an action, not a filter.

    Three inputs sitting in a card header read as a search bar; somebody types
    into them expecting the list below to narrow. Every other section here
    opens a modal, and the odd one out is the one that gets misread.
    """

    def _page(self):
        return self.client.get("/admin/config").get_data(as_text=True)

    def test_it_is_a_modal_like_everything_else(self):
        body = self._page()
        self.assertIn('id="silenceModal"', body)
        self.assertIn("Add silence", body)

    def test_the_inline_form_is_gone(self):
        self.assertNotIn('placeholder="monitor or agent id', self._page())

    def test_the_subject_is_chosen_rather_than_typed(self):
        """The subject is an id. Asking somebody to paste a uuid is asking
        them to silence the wrong thing."""
        self.app.store.monitors.create(
            name="Payments API", kind="http", target="https://x.example")
        body = self._page()
        self.assertIn('name="subject"', body)
        self.assertIn("Payments API", body)

    def test_the_duration_is_bounded(self):
        """A silence with no end is a channel muted by hand, and those stay
        muted."""
        body = self._page()
        self.assertIn("1 hour", body)
        self.assertNotIn('name="hours" type="number"', body)

    def test_it_still_saves(self):
        self.client.post("/admin/silences",
                         data={"subject": "*", "hours": "4",
                               "reason": "migration"},
                         follow_redirects=True)
        silences = self.app.store.silences.all()
        self.assertEqual(len(silences), 1)
        self.assertEqual(silences[0]["reason"], "migration")


class IncompleteListingTest(AlertingTestCase):
    """A listing that failed is not a monitor that recovered.

    The Elasticsearch monitor adapter answers any exception with
    `MonitorPage(partial=True)` and no monitors, and the fan-out does the same
    when one member fails. Read as a complete listing, every firing subject
    has "disappeared", which resolves it, tells somebody it recovered, and
    deletes the failure count it had been keeping during the outage.
    """

    def setUp(self):
        super().setUp()
        self.failing = {"now": False}

    def _runner(self, *monitors):
        failing = self.failing

        class Source:
            name = "es"
            capabilities = frozenset({"monitor_list"})

            def monitors(self, window, scope, series=False):
                if failing["now"]:
                    return MonitorPage(
                        partial=True, sources=(), missing_sources=("es",),
                        warnings=("es: read timed out",))
                return MonitorPage(monitors=list(monitors), sources=("es",))

            def health(self):
                return True, "ok"

            def containers(self, scope):
                return []

        hub = Hub()
        hub.add_monitors(Source())
        return AlertRunner(self.store, hub)

    def _state(self, rule):
        return {subject: (s.state, s.failures) for subject, s
                in self.store.alert_state.load(rule["id"]).items()}

    def _fired(self):
        rule = self.store.rules.create(
            channel_id=self._channel()["id"], name="API down",
            kind="monitor_down", threshold=3)
        runner = self._runner(Monitor(id="m1", name="API", status=DOWN,
                                      error="500"))
        for _ in range(3):
            runner.evaluate_once()
        self.assertEqual(self._state(rule), {"m1": ("firing", 3)})
        return rule, runner

    def test_a_partial_listing_does_not_resolve_what_is_still_firing(self):
        rule, runner = self._fired()
        self.failing["now"] = True
        runner.evaluate_once()
        self.assertEqual(
            [entry["transition"] for entry in self.store.alert_history.recent()
             if entry["transition"] == "resolved"], [],
            "a failed listing was reported as a recovery")
        self.assertNotIn(
            "no longer being checked",
            json.dumps([m["body"] for m in self.receiver.received]))

    def test_the_failure_count_is_not_thrown_away(self):
        """Forgetting it restarts the threshold, so the second page for the
        same outage arrives three evaluations after the source recovers."""
        rule, runner = self._fired()
        self.failing["now"] = True
        runner.evaluate_once()
        self.assertEqual(self._state(rule), {"m1": ("firing", 3)})
        self.failing["now"] = False
        runner.evaluate_once()
        self.assertEqual(self._state(rule), {"m1": ("firing", 4)})

    def test_the_pass_says_which_source_could_not_be_read(self):
        """Skipping the resolution silently would be a second silent failure:
        somebody reading the log has to be able to see why nothing moved.

        The source's OWN words, not just the letters 'es': asserting on the
        short name matched the runner's own sentence ("nothing was resolved
        this pass"), so the whole warnings path from `MonitorPage` through
        `Observed` could be deleted with this test still green.
        """
        rule, runner = self._fired()
        self.failing["now"] = True
        with self.assertLogs("wdash.alerts.runner", "WARNING") as caught:
            runner.evaluate_once()
        logged = " ".join(caught.output)
        self.assertIn("es: read timed out", logged)
        self.assertNotIn("no reason given", logged)

    def test_a_monitor_that_really_went_away_still_resolves(self):
        """The disappearance path is made conditional, not deleted: a monitor
        deleted while it was down must not stay firing for ever."""
        rule, runner = self._fired()
        self._runner().evaluate_once()     # a complete listing, nothing in it
        entry = self.store.alert_history.recent()[0]
        self.assertEqual(entry["transition"], "resolved")
        self.assertEqual(entry["detail"], "no longer being checked")
        self.assertEqual(self._state(rule), {})

    def test_a_rule_kind_this_version_cannot_evaluate_resolves_nothing(self):
        """A row written by a newer version, or edited by hand. It observes
        nothing, and nothing is not "everything this rule watched recovered"
        — which would announce a recovery and forget the outage."""
        rule, runner = self._fired()
        with self.store.engine.begin() as connection:
            from sqlalchemy import update as _update

            from wdash.store.schema import alert_rules
            connection.execute(
                _update(alert_rules).where(alert_rules.c.id == rule["id"])
                .values(kind="monitor_flapping"))
        runner.evaluate_once()
        self.assertEqual(self._state(rule), {"m1": ("firing", 3)})
        self.assertEqual(
            [e["transition"] for e in self.store.alert_history.recent()],
            ["firing"])

    def test_a_store_error_skips_an_agent_rule_rather_than_resolving_it(self):
        """`_agents` returned [] on a store error, which reads exactly like
        "every agent was deleted"."""
        agent, _ = self.store.agents.create("frankfurt")
        rule = self.store.rules.create(
            channel_id=self._channel()["id"], name="probe quiet",
            kind="agent_silent", threshold=1)
        runner = self._runner()
        runner.evaluate_once()
        self.assertEqual(self._state(rule), {agent["id"]: ("firing", 1)})

        def explode():
            raise RuntimeError("database is locked")

        original, self.store.agents.all = self.store.agents.all, explode
        try:
            runner.evaluate_once()
        finally:
            self.store.agents.all = original
        self.assertEqual(self._state(rule), {agent["id"]: ("firing", 1)})
        self.assertEqual(
            [e["transition"] for e in self.store.alert_history.recent()],
            ["firing"])


class UnreadableChannelCredentialsTest(AlertingTestCase):
    """A key that changed must say so, not "This channel has no URL."

    The sealed half of a channel is the URL. When `SecretBox.open` failed the
    repository logged a line with no reason and returned {}, `send` then found
    no URL, and every alert went into the history blaming a URL that is fine.
    """

    def setUp(self):
        super().setUp()
        self.second = None

    def tearDown(self):
        if self.second is not None:
            self.second.engine.dispose()
        super().tearDown()

    def _through(self, box):
        """The same database, opened with a different key."""
        self.second = Store.open(f"sqlite:///{self.database}", secret_box=box)
        return self.second

    def _delivery_error(self, box):
        channel = self._channel()
        store = self._through(box)
        rule = store.rules.create(channel_id=channel["id"], name="API down",
                                  kind="monitor_down", threshold=1)
        runner = AlertRunner(store, self._hub(
            Monitor(id="m1", name="API", status=DOWN, error="500")))
        self.assertEqual(runner.evaluate_once(), 0)
        entry = store.alert_history.recent()[0]
        self.assertFalse(entry["delivered"])
        self.assertEqual(entry["rule_id"], rule["id"])
        return entry["delivery_error"] or ""

    def test_a_rotated_key_says_the_key_changed(self):
        message = self._delivery_error(SecretBox(SecretBox.generate_key()))
        self.assertIn("WDASH_ENCRYPTION_KEY", message)
        self.assertNotIn("no URL", message)

    def test_no_key_at_all_says_that_instead(self):
        message = self._delivery_error(SecretBox(None))
        self.assertIn("WDASH_ENCRYPTION_KEY", message)
        self.assertNotIn("no URL", message)

    def test_the_reason_is_logged_with_the_exception(self):
        with self.assertLogs("wdash.store.alerting", "ERROR") as caught:
            self._delivery_error(SecretBox(None))
        self.assertIn("WDASH_ENCRYPTION_KEY", " ".join(caught.output))

    def test_a_readable_channel_is_unaffected(self):
        channel = self._channel()
        self.assertIn("xxTOKENxx",
                      self.store.channels.credentials(channel["id"])["url"])

    def test_starting_with_no_key_says_alerting_is_among_the_casualties(self):
        """The startup warning named OIDC and LDAP only, so an operator who
        has neither read it as "nothing I use" — and then every alert failed
        with a sentence about a URL."""
        from wdash.app import create_app
        from wdash.config import Config

        handle, database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(database)

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "alerts"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = ""
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        try:
            with self.assertLogs("wdash.app", "WARNING") as caught:
                app = create_app(TestConfig)
            app.store.engine.dispose()
            said = " ".join(caught.output)
            self.assertIn("WDASH_ENCRYPTION_KEY", said)
            self.assertIn("channel", said)
        finally:
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(database + suffix):
                    os.unlink(database + suffix)


class UndeliveredCountTest(AlertingTestCase):
    """The "never delivered" count has to mean something that can drain.

    It counted every failed row ever written — one row per evaluation while a
    channel is broken, about 2,880 a day per subject — and no later success
    ever took one away, while the banner on /alerts says it drains by itself.
    """

    def _firing(self, **rule):
        options = dict(name="API down", kind="monitor_down", threshold=1)
        options.update(rule)
        self.store.rules.create(channel_id=self._channel()["id"], **options)
        self.monitor = Monitor(id="m1", name="API", status=DOWN, error="500")
        return AlertRunner(self.store, self._hub(self.monitor))

    def _undelivered(self):
        return self.store.alert_history.count(undelivered_only=True)

    def test_a_delivered_alert_clears_the_failed_attempts_before_it(self):
        self.receiver.status = 500
        runner = self._firing()
        for _ in range(5):
            runner.evaluate_once()
        self.assertEqual(self._undelivered(), 1,
                         "one subject is outstanding, not one per attempt")
        self.assertEqual(self.store.alert_history.count(), 5,
                         "every attempt is still recorded")

        self.receiver.status = 200
        self.assertEqual(runner.evaluate_once(), 1)
        self.assertEqual(self._undelivered(), 0)
        self.assertEqual(
            self.store.alert_history.recent(undelivered_only=True), [],
            "the list and the count disagree")

    def test_another_subject_is_still_counted(self):
        """Cleared per subject, not wholesale: one channel working for one
        monitor says nothing about the others."""
        self.store.alert_history.record("r", "m2", "firing", "500",
                                        delivered=False, error="500")
        self.receiver.status = 500
        runner = self._firing()
        runner.evaluate_once()
        self.receiver.status = 200
        runner.evaluate_once()
        self.assertEqual(self._undelivered(), 1)
        self.assertEqual(
            [e["subject"] for e in
             self.store.alert_history.recent(undelivered_only=True)], ["m2"])

    def test_a_recovery_that_could_not_be_sent_is_sent_again(self):
        """The OK state was saved anyway, so the subject was healthy, the
        machine never transitioned again, and the last thing anybody was told
        was that it is broken."""
        runner = self._firing()
        self.assertEqual(runner.evaluate_once(), 1)

        self.receiver.status = 500
        self.monitor.status = UP
        self.assertEqual(runner.evaluate_once(), 0)
        self.assertEqual(
            [e["transition"] for e in
             self.store.alert_history.recent(undelivered_only=True)],
            ["resolved"])

        self.receiver.status = 200
        self.assertEqual(runner.evaluate_once(), 1,
                         "the recovery was never tried again")
        self.assertEqual(self.receiver.received[-1]["body"]["transition"],
                         "resolved")
        self.assertEqual(self._undelivered(), 0)
        # And then it stops, rather than announcing the recovery for ever.
        self.assertEqual(runner.evaluate_once(), 0)

    def test_a_recovery_that_was_sent_forgets_a_vanished_subject(self):
        """The row-per-deleted-monitor cleanup still happens on success."""
        rule = self.store.rules.create(
            channel_id=self._channel()["id"], name="API down",
            kind="monitor_down", threshold=1)
        AlertRunner(self.store, self._hub(
            Monitor(id="m1", name="API", status=DOWN))).evaluate_once()
        AlertRunner(self.store, self._hub()).evaluate_once()
        self.assertEqual(self.store.alert_state.load(rule["id"]), {})

    def test_a_firing_alert_that_could_not_be_sent_still_remembers_it_fired(self):
        """The other half of the skip above, and the half no test held.

        Widening it from "a failed RESOLVED delivery" to "any failed
        delivery" passes every alerting test, and breaks the firing path
        outright: the FIRING state is never written while the channel is
        down, so the machine never transitions, no recovery is ever produced,
        and the pass that finally reaches the receiver has nothing to say.
        """
        self.receiver.status = 500
        rule = self.store.rules.create(
            channel_id=self._channel()["id"], name="API down",
            kind="monitor_down", threshold=1)
        monitor = Monitor(id="m1", name="API", status=DOWN, error="500")
        runner = AlertRunner(self.store, self._hub(monitor))
        self.assertEqual(runner.evaluate_once(), 0)
        self.assertEqual(
            {subject: (s.state, s.failures) for subject, s
             in self.store.alert_state.load(rule["id"]).items()},
            {"m1": ("firing", 1)},
            "the alert was not remembered, so nothing can recover from it")

        # And the recovery it makes possible actually arrives.
        self.receiver.status = 200
        monitor.status = UP
        self.assertEqual(runner.evaluate_once(), 1)
        self.assertEqual(self.receiver.received[-1]["body"]["transition"],
                         "resolved")


class BadgeIndexTest(unittest.TestCase):
    """The badge query has to be an indexed read, on an existing database too.

    "Never delivered" now means the LAST row per (rule, subject), which is
    what let it drain — and a `max(id) GROUP BY rule_id, subject` over the one
    table that grows a row per evaluation while a channel is broken. It is
    read on every render of /alerts and once on the configuration page.
    Measured on SQLite with 200,000 rows over five subjects: 96 ms without
    the index, 12 ms with it.
    """

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.path)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.path + suffix):
                os.unlink(self.path + suffix)

    def _indexes(self, engine):
        from sqlalchemy import inspect
        with engine.connect() as connection:
            return {index["name"]: list(index["column_names"]) for index
                    in inspect(connection).get_indexes("wdash_alert_history")}

    def test_a_new_database_has_it(self):
        from wdash.store.database import build_engine
        from wdash.store.migrations import migrate
        engine = build_engine(f"sqlite:///{self.path}")
        migrate(engine)
        indexes = self._indexes(engine)
        engine.dispose()
        self.assertEqual(indexes.get("ix_wdash_alert_history_latest"),
                         ["rule_id", "subject", "id"])

    def test_a_database_that_predates_it_gets_it(self):
        """The table was created at version 12 and that step will never run
        again, so the index has to arrive as a migration of its own."""
        from sqlalchemy import text

        from wdash.store.database import build_engine
        from wdash.store.migrations import migrate
        engine = build_engine(f"sqlite:///{self.path}")
        migrate(engine)
        with engine.begin() as connection:
            connection.execute(
                text("DROP INDEX ix_wdash_alert_history_latest"))
            connection.execute(text(
                "DELETE FROM wdash_schema_version WHERE version >= 15"))
        self.assertNotIn("ix_wdash_alert_history_latest", self._indexes(engine))

        migrate(engine)
        indexes = self._indexes(engine)
        with engine.connect() as connection:
            applied = connection.execute(text(
                "SELECT max(version) FROM wdash_schema_version")).scalar()
        engine.dispose()
        self.assertIn("ix_wdash_alert_history_latest", indexes)
        self.assertGreaterEqual(applied, 15)

    def test_the_name_is_not_the_one_sqlalchemy_already_took(self):
        """`subject` is declared `index=True`, which SQLAlchemy auto-names
        `ix_wdash_alert_history_subject`. A migration that spelt the new index
        that way would be a `CREATE INDEX IF NOT EXISTS` that silently did
        nothing — measured: the plan stayed a full scan at 86 ms.
        """
        from wdash.store.database import build_engine
        from wdash.store.migrations import migrate
        engine = build_engine(f"sqlite:///{self.path}")
        migrate(engine)
        indexes = self._indexes(engine)
        engine.dispose()
        self.assertEqual(indexes.get("ix_wdash_alert_history_subject"),
                         ["subject"])


class RetryThatCannotSucceedTest(AlertingTestCase):
    """A recovery is held open for a channel that might come back, not for one
    that cannot.

    Holding the FIRING state until the recovery is delivered is right while
    the receiver is merely down. It is wrong when the channel has been
    deleted or switched off: that refusal is identical on every pass for
    ever, so the subject keeps its `alert_state` row — defeating the forget
    that exists "so the state table does not grow a row per deleted monitor
    for ever" — and earns a fresh 'resolved' history row every thirty
    seconds. Measured: six history rows after five passes, against two.
    """

    def _fired_then_vanished(self, passes=5, delete_channel=False):
        # A closed port rather than a stopped receiver: a real refused
        # connection, and one that is the same on every pass.
        channel = self._channel(url="http://127.0.0.1:9/never")
        rule = self.store.rules.create(
            channel_id=channel["id"], name="API down", kind="monitor_down",
            threshold=1)
        AlertRunner(self.store, self._hub(
            Monitor(id="m1", name="API", status=DOWN,
                    error="500"))).evaluate_once()
        if delete_channel:
            self.store.channels.delete(channel["id"])
        runner = AlertRunner(self.store, self._hub())      # the monitor is gone
        for _ in range(passes):
            runner.evaluate_once()
        return rule

    def test_a_deleted_channel_does_not_hold_a_vanished_subject_open(self):
        rule = self._fired_then_vanished(delete_channel=True)
        self.assertEqual(
            [e["transition"] for e in
             self.store.alert_history.recent(limit=100)],
            ["resolved", "firing"],
            "the resolution was written again on every pass")
        self.assertEqual(self.store.alert_state.load(rule["id"]), {},
                         "the deleted monitor kept its state row for ever")

    def test_the_failure_is_still_on_the_record_and_on_the_badge(self):
        """Bounding the retry must not be a way of forgetting it happened."""
        self._fired_then_vanished(delete_channel=True)
        resolved = [e for e in self.store.alert_history.recent(limit=100)
                    if e["transition"] == "resolved"][0]
        self.assertFalse(resolved["delivered"])
        self.assertIn("no longer exists", resolved["delivery_error"])
        self.assertEqual(self.store.alert_history.count(undelivered_only=True),
                         1)

    def test_a_receiver_that_is_merely_down_is_still_retried(self):
        """The case the skip was added for is untouched: this one can work
        again on the next pass, so the recovery stays owed."""
        rule = self._fired_then_vanished(passes=3)
        self.assertEqual(
            {subject: (s.state, s.failures) for subject, s
             in self.store.alert_state.load(rule["id"]).items()},
            {"m1": ("firing", 1)},
            "a transient outage threw the alert away")
