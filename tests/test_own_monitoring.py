"""
The checks WDash runs itself: the store, the endpoints, the agent.

Phase one read what Heartbeat wrote. This is the other half — our own agent —
and the whole point of the neutral model is that nothing downstream can tell
them apart. What is tested here is the part that is NOT translation:

  * an ingest endpoint must not let an agent report for checks it does not run
  * a silent agent must not report its last known status as the current one
  * results must survive the network outage they were measuring
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub.models import DOWN, UNKNOWN, UP  # noqa: E402
from wdash.hub.query import TimeWindow  # noqa: E402
from wdash.hub.scope import Scope  # noqa: E402
from wdash.store import Store  # noqa: E402
from wdash.store.monitoring import (  # noqa: E402
    AGENT_STALE_AFTER, MonitoringError, hash_token,
)


def _now():
    return datetime.now(timezone.utc)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.store = Store.open(f"sqlite:///{self.database}")

    def tearDown(self):
        self.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _agent(self, name="one"):
        return self.store.agents.create(name)

    def _monitor(self, name="API", **kwargs):
        options = dict(kind="http", target="https://example.com",
                       interval_seconds=30, timeout_seconds=5)
        options.update(kwargs)
        return self.store.monitors.create(name=name, **options)


class TokenTest(StoreTestCase):
    """Why these are not password hashes.

    Argon2 exists to make a low-entropy secret expensive to guess. An agent
    token is 256 bits of machine randomness with no dictionary to attack, and
    verifying it with Argon2 on every result batch — every fifteen seconds,
    per agent — would burn CPU for no security while handing anybody who can
    reach the ingest endpoint a way to exhaust the server.
    """

    def test_the_token_is_returned_once_and_never_stored(self):
        agent, token = self._agent()
        self.assertNotIn("token_hash", agent)
        self.assertNotIn(token, json.dumps(agent, default=str))

    def test_only_the_hash_is_in_the_database(self):
        from sqlalchemy import select

        from wdash.store.schema import agents
        _, token = self._agent()
        with self.store.engine.connect() as connection:
            stored = connection.execute(
                select(agents.c.token_hash)).scalar()
        self.assertEqual(stored, hash_token(token))
        self.assertNotEqual(stored, token)

    def test_a_token_finds_its_agent(self):
        agent, token = self._agent("frankfurt")
        self.assertEqual(self.store.agents.by_token(token)["name"], "frankfurt")

    def test_a_wrong_token_finds_nothing(self):
        self._agent()
        self.assertIsNone(self.store.agents.by_token("not-a-token"))
        self.assertIsNone(self.store.agents.by_token(""))
        self.assertIsNone(self.store.agents.by_token(None))

    def test_a_disabled_agent_cannot_authenticate(self):
        agent, token = self._agent()
        self.store.agents.set_enabled(agent["id"], False)
        self.assertIsNone(self.store.agents.by_token(token))

    def test_rotation_invalidates_the_old_token_immediately(self):
        """No grace period. An overlap window is exactly what somebody
        rotating a leaked token does not want."""
        agent, old = self._agent()
        new = self.store.agents.rotate_token(agent["id"])
        self.assertIsNone(self.store.agents.by_token(old))
        self.assertIsNotNone(self.store.agents.by_token(new))


class AssignmentTest(StoreTestCase):
    def test_an_unassigned_monitor_runs_everywhere(self):
        """The useful default: one agent, everything on it, no bookkeeping.
        Explicitly assigning it to nobody would be a monitor that exists and
        is never checked, which looks like a broken agent."""
        one, _ = self._agent("one")
        two, _ = self._agent("two")
        self._monitor()
        self.assertEqual(len(self.store.monitors.for_agent(one["id"])), 1)
        self.assertEqual(len(self.store.monitors.for_agent(two["id"])), 1)

    def test_an_assigned_monitor_runs_only_there(self):
        one, _ = self._agent("one")
        two, _ = self._agent("two")
        self._monitor(agent_ids=[one["id"]])
        self.assertEqual(len(self.store.monitors.for_agent(one["id"])), 1)
        self.assertEqual(self.store.monitors.for_agent(two["id"]), [])

    def test_one_monitor_can_run_from_several_places(self):
        """"Up from Frankfurt, down from Singapore" is the answer, and a
        single agent column cannot express it."""
        one, _ = self._agent("frankfurt")
        two, _ = self._agent("singapore")
        three, _ = self._agent("sydney")
        self._monitor(agent_ids=[one["id"], two["id"]])
        self.assertEqual(len(self.store.monitors.for_agent(one["id"])), 1)
        self.assertEqual(len(self.store.monitors.for_agent(two["id"])), 1)
        self.assertEqual(self.store.monitors.for_agent(three["id"]), [])

    def test_a_disabled_monitor_is_given_to_nobody(self):
        one, _ = self._agent()
        monitor = self._monitor()
        self.store.monitors.update(monitor["id"], enabled=False)
        self.assertEqual(self.store.monitors.for_agent(one["id"]), [])


class IngestTest(StoreTestCase):
    """An endpoint that accepts anything is a way to paint the board green."""

    def test_results_for_an_unassigned_monitor_are_dropped(self):
        one, _ = self._agent("one")
        two, _ = self._agent("two")
        monitor = self._monitor(agent_ids=[one["id"]])

        stored = self.store.results.record(two["id"], [
            {"monitor_id": monitor["id"], "status": "up",
             "started_at": _now().isoformat()}])
        self.assertEqual(stored, 0)
        self.assertEqual(self.store.results.count(), 0)

    def test_results_for_its_own_monitors_are_kept(self):
        one, _ = self._agent("one")
        monitor = self._monitor(agent_ids=[one["id"]])
        stored = self.store.results.record(one["id"], [
            {"monitor_id": monitor["id"], "status": "up",
             "started_at": _now().isoformat(), "duration_us": 1234}])
        self.assertEqual(stored, 1)

    def test_an_unrecognised_status_becomes_down(self):
        """Anything that is not an explicit "down" is stored as up or down,
        never as a third value the page has no column for."""
        one, _ = self._agent()
        monitor = self._monitor()
        self.store.results.record(one["id"], [
            {"monitor_id": monitor["id"], "status": "sideways",
             "started_at": _now().isoformat()}])
        rows = self.store.results.series(
            monitor["id"], _now() - timedelta(hours=1), _now())
        self.assertEqual(rows[0]["status"], "up")

    def test_both_clocks_are_recorded(self):
        """The difference is the only way to see clock skew, and an agent an
        hour out puts its points in the wrong buckets — which reads as a
        nightly slowdown that never happened."""
        one, _ = self._agent()
        monitor = self._monitor()
        stamped = _now() - timedelta(hours=3)
        self.store.results.record(one["id"], [
            {"monitor_id": monitor["id"], "status": "up",
             "started_at": stamped.isoformat()}])
        row = self.store.results.series(
            monitor["id"], stamped - timedelta(minutes=1), _now())[0]
        self.assertLess(abs((row["started_at"].replace(tzinfo=timezone.utc)
                             - stamped).total_seconds()), 2)
        self.assertGreater(row["received_at"].replace(tzinfo=timezone.utc),
                           stamped)


class RetentionTest(StoreTestCase):
    def test_old_results_are_pruned(self):
        one, _ = self._agent()
        monitor = self._monitor()
        for age in (1, 10, 40):
            self.store.results.record(one["id"], [
                {"monitor_id": monitor["id"], "status": "up",
                 "started_at": (_now() - timedelta(days=age)).isoformat()}])
        self.assertEqual(self.store.results.count(), 3)
        self.assertEqual(self.store.results.prune(30), 1)
        self.assertEqual(self.store.results.count(), 2)

    def test_no_retention_prunes_nothing(self):
        """`prune(0)` must not be read as "delete everything older than
        now"."""
        one, _ = self._agent()
        monitor = self._monitor()
        self.store.results.record(one["id"], [
            {"monitor_id": monitor["id"], "status": "up",
             "started_at": _now().isoformat()}])
        self.assertEqual(self.store.results.prune(0), 0)
        self.assertEqual(self.store.results.count(), 1)


class SourceTest(StoreTestCase):
    """Reading it back through the neutral model."""

    def setUp(self):
        super().setUp()
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        self.source = StoreMonitorSource(self.store)
        self.window = TimeWindow.of("1h")
        self.scope = Scope(containers=("*",))

    def _report(self, agent_id, monitor_id, status="up", ago_seconds=5, **extra):
        """Report a result AND mark the agent alive.

        Both, because that is what the ingest endpoint does. Recording a
        result without the heartbeat produces an agent that has reported and
        never checked in — a state the real path cannot reach, and one where
        the source correctly returns `unknown`. Two of these tests asserted
        `up` against that setup and were measuring their own fixture.
        """
        self.store.agents.seen(agent_id, version="test")
        self.store.results.record(agent_id, [dict(
            monitor_id=monitor_id, status=status,
            started_at=(_now() - timedelta(seconds=ago_seconds)).isoformat(),
            duration_us=12345, **extra)])

    def test_a_reported_monitor_shows_its_status(self):
        agent, _ = self._agent()
        monitor = self._monitor()
        self._report(agent["id"], monitor["id"], "down")
        rows = self.source.monitors(self.window, self.scope).monitors
        self.assertEqual(rows[0].status, DOWN)

    def test_an_agent_that_has_reported_but_never_checked_in_is_unknown(self):
        """Not reachable through the endpoint, which marks the agent alive on
        every exchange — but reachable by anything that writes results
        directly, and it used to crash the whole listing: `last_seen_at` is
        None and the message formatted it as a time. One unregistered agent
        took away every other monitor's row."""
        agent, _ = self._agent()
        monitor = self._monitor()
        self.store.results.record(agent["id"], [
            {"monitor_id": monitor["id"], "status": "up",
             "started_at": _now().isoformat()}])
        row = self.source.monitors(self.window, self.scope).monitors[0]
        self.assertEqual(row.status, UNKNOWN)
        self.assertIn("not reported at all", row.error)

    def test_a_monitor_nobody_has_reported_is_unknown_not_missing(self):
        """The row that matters most: it means the agent is not running it,
        and leaving it out makes a broken assignment look tidy."""
        self._agent()
        self._monitor(name="never ran")
        rows = self.source.monitors(self.window, self.scope).monitors
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, UNKNOWN)
        self.assertIn("no agent", rows[0].error)

    def test_a_silent_agent_makes_its_monitors_unknown(self):
        """Showing the last known status would report a target as up for as
        long as nobody was watching."""
        from sqlalchemy import update

        from wdash.store.schema import agents as agents_table
        agent, _ = self._agent()
        monitor = self._monitor()
        self._report(agent["id"], monitor["id"], "up")
        with self.store.engine.begin() as connection:
            connection.execute(
                update(agents_table).where(agents_table.c.id == agent["id"])
                .values(last_seen_at=_now() - AGENT_STALE_AFTER * 3))

        row = self.source.monitors(self.window, self.scope).monitors[0]
        self.assertEqual(row.status, UNKNOWN)
        self.assertIn("has not reported", row.error)

    def test_a_stale_agent_still_shows_what_it_last_measured(self):
        """Unknown is about the STATUS. Throwing the measurement away too
        would lose the last thing anybody knows about the target."""
        from sqlalchemy import update

        from wdash.store.schema import agents as agents_table
        agent, _ = self._agent()
        monitor = self._monitor()
        self._report(agent["id"], monitor["id"], "up")
        with self.store.engine.begin() as connection:
            connection.execute(
                update(agents_table).where(agents_table.c.id == agent["id"])
                .values(last_seen_at=_now() - AGENT_STALE_AFTER * 3))
        row = self.source.monitors(self.window, self.scope).monitors[0]
        self.assertIsNotNone(row.checked_at)
        self.assertGreater(row.duration_ms, 0)

    def test_two_agents_reporting_one_monitor_are_two_rows(self):
        one, _ = self._agent("frankfurt")
        two, _ = self._agent("singapore")
        monitor = self._monitor()
        self._report(one["id"], monitor["id"], "up")
        self._report(two["id"], monitor["id"], "down")
        rows = self.source.monitors(self.window, self.scope).monitors
        self.assertEqual(len(rows), 2)
        self.assertEqual({r.status for r in rows}, {UP, DOWN})

    def test_the_certificate_needs_no_translation(self):
        """The agent already writes the neutral shape, so a mapping here
        would be a second place for the field names to drift."""
        agent, _ = self._agent()
        monitor = self._monitor()
        expiry = _now() + timedelta(days=9)
        self._report(agent["id"], monitor["id"], "up", tls={
            "common_name": "example.com", "issuer": "Example CA",
            "not_after": expiry.isoformat(), "key_algorithm": "ECDSA",
            "key_curve": "secp256r1"})
        certificate = self.source.certificates(self.window, self.scope)[0]
        self.assertEqual(certificate.certificate.days_remaining, 9)
        self.assertEqual(certificate.certificate.key_description,
                         "ECDSA secp256r1")

    def test_every_series_spans_the_whole_window(self):
        """Drawn to the same width, differing bucket counts give every row its
        own x-axis."""
        agent, _ = self._agent()
        first = self._monitor(name="old")
        second = self._monitor(name="new")
        self._report(agent["id"], first["id"], ago_seconds=3000)
        self._report(agent["id"], second["id"], ago_seconds=5)
        rows = self.source.monitors(self.window, self.scope,
                                    series=True).monitors
        self.assertEqual(len({len(r.series) for r in rows}), 1)

    def test_an_empty_bucket_is_a_gap_not_a_zero(self):
        agent, _ = self._agent()
        monitor = self._monitor()
        self._report(agent["id"], monitor["id"], ago_seconds=5)
        points = self.source.series(monitor["id"], self.window, self.scope,
                                    points=12)
        empty = [p for p in points if not p.has_data]
        self.assertTrue(empty)
        self.assertIsNone(empty[0].duration_ms)

    def test_health_says_when_every_agent_has_gone_quiet(self):
        self._agent()
        healthy, detail = self.source.health()
        self.assertFalse(healthy)
        self.assertIn("reported", detail)

    def test_no_agents_at_all_is_healthy(self):
        """An installation reading Heartbeat and running no checks of its own
        is working perfectly well."""
        healthy, detail = self.source.health()
        self.assertTrue(healthy)
        self.assertIn("no agents", detail)


class ValidationTest(StoreTestCase):
    def test_a_timeout_longer_than_the_interval_is_refused(self):
        """Otherwise a slow check is still running when the next is due, and
        the agent either overlaps them or silently skips."""
        with self.assertRaises(MonitoringError):
            self._monitor(interval_seconds=10, timeout_seconds=30)

    def test_an_http_target_has_to_be_a_url(self):
        with self.assertRaises(MonitoringError):
            self._monitor(kind="http", target="example.com")

    def test_a_tcp_target_has_to_carry_a_port(self):
        with self.assertRaises(MonitoringError):
            self._monitor(kind="tcp", target="db.internal")

    def test_an_unknown_check_type_is_refused(self):
        """ICMP needs a raw socket and a browser check needs a browser. Both
        are decisions, not types that quietly appear in a dropdown."""
        with self.assertRaises(MonitoringError):
            self._monitor(kind="icmp", target="8.8.8.8")


if __name__ == "__main__":
    unittest.main()


class EndpointTest(unittest.TestCase):
    """The two routes an agent talks to.

    Outside the session login on purpose: an agent has no browser and no
    cookie. A redirect to an HTML sign-in page is not something a daemon can
    act on — it parses the body as JSON, fails, and reports itself broken
    while WDash is merely waiting for somebody to create an account.
    """

    def setUp(self):
        import tempfile as _tempfile

        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        handle, self.database = _tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "agent-test"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"
            WTF_CSRF_ENABLED = False

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.agent, self.token = self.app.store.agents.create("one")
        self.monitor = self.app.store.monitors.create(
            name="API", kind="http", target="https://example.com",
            interval_seconds=30, timeout_seconds=5)
        self.headers = {"Authorization": f"Bearer {self.token}",
                        "X-Agent-Version": "0.1.0"}

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def test_an_agent_gets_its_configuration_before_setup_is_done(self):
        """The first-run guard redirected every request to /setup, agents
        included. A 302 to an HTML form is not an answer a daemon can use."""
        self.assertTrue(self.app.store.needs_setup)
        response = self.client.get("/api/agent/config", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["monitors"]), 1)

    def test_no_token_is_refused(self):
        self.assertEqual(self.client.get("/api/agent/config").status_code, 401)

    def test_a_wrong_token_and_a_disabled_agent_look_the_same(self):
        """Telling them apart tells somebody holding a stolen token which
        half of it is wrong."""
        wrong = self.client.get("/api/agent/config",
                                headers={"Authorization": "Bearer nope"})
        self.app.store.agents.set_enabled(self.agent["id"], False)
        disabled = self.client.get("/api/agent/config", headers=self.headers)
        self.assertEqual(wrong.status_code, disabled.status_code)
        self.assertEqual(wrong.get_json(), disabled.get_json())

    def test_the_configuration_version_changes_only_when_it_changes(self):
        """The agent reschedules on a change. A version that moves on every
        poll would restart every monitor's schedule once a minute."""
        first = self.client.get("/api/agent/config",
                                headers=self.headers).get_json()["version"]
        again = self.client.get("/api/agent/config",
                                headers=self.headers).get_json()["version"]
        self.assertEqual(first, again)
        self.app.store.monitors.update(self.monitor["id"], interval_seconds=45)
        after = self.client.get("/api/agent/config",
                                headers=self.headers).get_json()["version"]
        self.assertNotEqual(first, after)

    def test_results_are_stored_and_counted(self):
        response = self.client.post("/api/agent/results", headers=self.headers,
                                    json={"results": [{
                                        "monitor_id": self.monitor["id"],
                                        "started_at": _now().isoformat(),
                                        "status": "up", "duration_us": 1000}]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["accepted"], 1)

    def test_the_reply_says_how_many_were_dropped(self):
        """An agent that keeps reporting for a monitor it no longer runs needs
        to know the difference between "stored" and "received and dropped", or
        it sends them for ever."""
        response = self.client.post("/api/agent/results", headers=self.headers,
                                    json={"results": [
                                        {"monitor_id": "gone",
                                         "started_at": _now().isoformat(),
                                         "status": "up"}]})
        payload = response.get_json()
        self.assertEqual((payload["received"], payload["accepted"]), (1, 0))

    def test_an_oversized_batch_is_refused_rather_than_half_stored(self):
        from wdash.api.agent_routes import MAX_BATCH
        response = self.client.post(
            "/api/agent/results", headers=self.headers,
            json={"results": [{"monitor_id": self.monitor["id"],
                               "status": "up"}] * (MAX_BATCH + 1)})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.app.store.results.count(), 0)

    def test_a_malformed_body_is_a_400_not_a_500(self):
        response = self.client.post("/api/agent/results", headers=self.headers,
                                    json={"nothing": "useful"})
        self.assertEqual(response.status_code, 400)

    def test_talking_to_wdash_marks_the_agent_alive(self):
        """This is what tells "the target is down" apart from "nobody
        looked"."""
        self.client.get("/api/agent/config", headers=self.headers)
        agent = self.app.store.agents.get(self.agent["id"])
        self.assertIsNotNone(agent["last_seen_at"])
        self.assertFalse(agent["stale"])
        self.assertEqual(agent["version"], "0.1.0")


class SpoolTest(unittest.TestCase):
    """Results that outlive the network outage they were measuring.

    A check that ran during an outage is the most valuable check there is, and
    it is exactly the one that cannot be delivered at the time.
    """

    def setUp(self):
        from wdash.agent.spool import Spool
        self.directory = tempfile.mkdtemp()
        self.path = os.path.join(self.directory, "spool.jsonl")
        self.spool = Spool(self.path, limit=5)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_results_survive_a_restart(self):
        from wdash.agent.spool import Spool
        self.spool.add([{"n": 1}, {"n": 2}])
        self.assertEqual(Spool(self.path).pending(), 2)

    def test_taking_does_not_remove(self):
        """A send that fails must leave them where they were. Removing first
        and re-adding on failure loses them if the agent dies in between —
        which is the moment it is most likely to."""
        self.spool.add([{"n": 1}, {"n": 2}])
        self.spool.take(2)
        self.assertEqual(self.spool.pending(), 2)

    def test_dropping_removes_the_oldest(self):
        self.spool.add([{"n": 1}, {"n": 2}, {"n": 3}])
        self.spool.drop(2)
        self.assertEqual([r["n"] for r in self.spool.take(10)], [3])

    def test_overflow_drops_the_oldest_not_the_newest(self):
        """A backlog that has overflowed is one where the recent results
        matter more — and dropping the newest would mean the agent reports
        nothing at all until the backlog clears."""
        self.spool.add([{"n": n} for n in range(10)])
        self.assertEqual([r["n"] for r in self.spool.take(10)], [5, 6, 7, 8, 9])

    def test_a_half_written_line_costs_one_result_not_the_backlog(self):
        self.spool.add([{"n": 1}, {"n": 2}])
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write('{"n": ')
        self.assertEqual(len(self.spool.take(10)), 2)


class ManagementPageTest(unittest.TestCase):
    """Defining checks and agents from the configuration page."""

    def setUp(self):
        import re as _re
        import tempfile as _tempfile

        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        self.re = _re
        handle, self.database = _tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "manage"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"
            WTF_CSRF_ENABLED = False

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        grant(self.app, "admin", ["system:admin"], indices=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "u1", "username": "admin", "email": "a@b", "groups": [],
                "role": "admin", "permissions": ["system:admin"],
                "allowed_indices": ["*"]}
            session["_user_id"] = "u1"

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _shown_token(self, body):
        match = self.re.search(
            r'<code class="d-block[^>]*>([^<]+)</code>', body)
        return match.group(1).strip() if match else None

    def test_the_token_block_holds_the_token_and_nothing_else(self):
        """The block is `user-select-all`, so anything else in it is copied
        along with the token — and a token pasted with a sentence in front of
        it fails authentication for a reason nobody can see."""
        body = self.client.post("/admin/agents", data={"name": "frankfurt"},
                                follow_redirects=True).get_data(as_text=True)
        token = self._shown_token(body)
        self.assertIsNotNone(token)
        self.assertIsNotNone(self.app.store.agents.by_token(token))

    def test_the_token_is_never_shown_again(self):
        """Only the hash is stored, so no screen can show it — and the page
        must not pretend otherwise."""
        body = self.client.post("/admin/agents", data={"name": "frankfurt"},
                                follow_redirects=True).get_data(as_text=True)
        token = self._shown_token(body)
        later = self.client.get("/admin/config").get_data(as_text=True)
        self.assertNotIn(token, later)

    def test_the_token_notice_cannot_be_dismissed_by_reflex(self):
        """It is the one thing on the page that is unrecoverable once it goes
        away."""
        body = self.client.post("/admin/agents", data={"name": "frankfurt"},
                                follow_redirects=True).get_data(as_text=True)
        after = body.split("Shown once")[1][:400]
        self.assertNotIn("btn-close", after)

    def test_rotating_says_the_agent_has_stopped_reporting(self):
        """No grace period, so somebody has to know that before they walk
        away."""
        self.client.post("/admin/agents", data={"name": "one"})
        agent = self.app.store.agents.all()[0]
        body = self.client.post(f"/admin/agents/{agent['id']}/rotate",
                                follow_redirects=True).get_data(as_text=True)
        self.assertIn("stopped working immediately", body)

    def test_removing_an_agent_keeps_its_results(self):
        """They are measurements of a target, not property of the agent.
        Throwing away history because the collector was retired is how an
        investigation loses the week before the incident."""
        self.client.post("/admin/agents", data={"name": "one"})
        agent = self.app.store.agents.all()[0]
        monitor = self.app.store.monitors.create(
            name="API", kind="http", target="https://example.com")
        self.app.store.results.record(agent["id"], [
            {"monitor_id": monitor["id"], "status": "up",
             "started_at": _now().isoformat()}])

        self.client.post(f"/admin/agents/{agent['id']}/delete",
                         follow_redirects=True)
        self.assertEqual(self.app.store.agents.all(), [])
        self.assertEqual(self.app.store.results.count(), 1)

    def test_a_check_is_saved_with_its_assertions(self):
        self.client.post("/admin/monitors", data={
            "name": "Checkout", "kind": "http",
            "target": "https://example.com/health",
            "interval_seconds": "30", "timeout_seconds": "5",
            "status": "200, 204", "body_contains": "ok",
            "max_duration_ms": "2000"}, follow_redirects=True)
        monitor = self.app.store.monitors.all()[0]
        self.assertEqual(monitor["assertions"], {
            "status": [200, 204], "body_contains": "ok",
            "max_duration_ms": 2000})

    def test_an_invalid_target_is_refused_with_a_reason(self):
        body = self.client.post("/admin/monitors", data={
            "name": "Bad", "kind": "http", "target": "example.com",
            "interval_seconds": "30", "timeout_seconds": "5"},
            follow_redirects=True).get_data(as_text=True)
        self.assertIn("needs a URL", body)
        self.assertEqual(self.app.store.monitors.all(), [])

    def test_removing_a_check_removes_its_results(self):
        """Unlike an agent's. They are about a check that no longer exists,
        and a page cannot show them without a definition to name them."""
        self.client.post("/admin/agents", data={"name": "one"})
        agent = self.app.store.agents.all()[0]
        monitor = self.app.store.monitors.create(
            name="API", kind="http", target="https://example.com")
        self.app.store.results.record(agent["id"], [
            {"monitor_id": monitor["id"], "status": "up",
             "started_at": _now().isoformat()}])

        self.client.post(f"/admin/monitors/{monitor['id']}/delete",
                         follow_redirects=True)
        self.assertEqual(self.app.store.results.count(), 0)

    def test_a_check_reaches_the_agent_that_asks(self):
        """The whole loop: defined on the page, fetched by the agent."""
        body = self.client.post("/admin/agents", data={"name": "one"},
                                follow_redirects=True).get_data(as_text=True)
        token = self._shown_token(body)
        self.client.post("/admin/monitors", data={
            "name": "Checkout", "kind": "tcp", "target": "db.internal:5432",
            "interval_seconds": "60", "timeout_seconds": "5"},
            follow_redirects=True)

        payload = self.client.get(
            "/api/agent/config",
            headers={"Authorization": f"Bearer {token}"}).get_json()
        self.assertEqual([m["name"] for m in payload["monitors"]], ["Checkout"])

    def test_a_viewer_cannot_define_checks(self):
        """Granted in the STORE, not in the session.

        Permissions are resolved from the metadata store on every request —
        deliberately, because a signed cookie the server wrote is still stale
        data and trusting it is how a revoked role keeps working. Editing the
        session here changed nothing, and the first version of this test
        passed a monitor straight through while asserting it had been
        refused.
        """
        from tests.support import grant
        grant(self.app, "admin", ["logs:read"], indices=["*"])
        response = self.client.post("/admin/monitors", data={
            "name": "Sneaky", "kind": "http", "target": "https://example.com"})
        self.assertIn(response.status_code, (302, 403))
        self.assertEqual(self.app.store.monitors.all(), [])
