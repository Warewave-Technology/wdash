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

from tests.postgres_store import sqlite_only  # noqa: E402
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
        # What was taken, rather than how many: the spool moves underneath a
        # send. See `Spool.drop`.
        self.spool.drop(self.spool.take(2))
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

    def _kept_on(self, *agents, name="internal-admin"):
        return self.app.store.monitors.create(
            name=name, kind="http", target="https://admin.internal/health",
            agent_ids=[a["id"] for a in agents],
            request={"auth": {"type": "bearer", "token": "s3cret-token"}})

    def _sent_to(self, token):
        return self.client.get(
            "/api/agent/config",
            headers={"Authorization": f"Bearer {token}"}).get_json()["monitors"]

    def test_removing_the_one_agent_a_check_was_kept_on_stops_it(self):
        """A check assigned to nobody runs on every agent. Removing the one
        it was kept on handed it, token and all, to every other agent —
        measured: `branch-office` was sent it, bearer token included, the
        moment `dmz-browser` was removed."""
        store = self.app.store
        dmz, _ = store.agents.create("dmz-browser")
        _, branch_token = store.agents.create("branch-office")
        monitor = self._kept_on(dmz)
        self.assertEqual(self._sent_to(branch_token), [])

        self.client.post(f"/admin/agents/{dmz['id']}/delete")
        # The flash itself: the page lists the check by name whatever the
        # message says.
        with self.client.session_transaction() as session:
            said = " ".join(text for _, text in session.get("_flashes", []))
        self.assertEqual(self._sent_to(branch_token), [],
                         "the check spread to another agent")
        self.assertFalse(store.monitors.get(monitor["id"])["enabled"])
        self.assertIn("switched off: internal-admin", said)
        row = [r for r in store.audit.recent() if r["action"] == "agent removed"][0]
        self.assertEqual(row["state"]["monitors_switched_off"], ["internal-admin"])

    def test_a_check_with_another_agent_left_keeps_running_there(self):
        store = self.app.store
        dmz, _ = store.agents.create("dmz-browser")
        spare, spare_token = store.agents.create("dmz-spare")
        _, branch_token = store.agents.create("branch-office")
        monitor = self._kept_on(dmz, spare)
        self.client.post(f"/admin/agents/{dmz['id']}/delete")
        self.assertTrue(store.monitors.get(monitor["id"])["enabled"])
        self.assertEqual([m["name"] for m in self._sent_to(spare_token)],
                         ["internal-admin"])
        self.assertEqual(self._sent_to(branch_token), [])

    def test_a_check_assigned_to_nobody_is_left_alone(self):
        """It already runs everywhere; removing an agent narrows that."""
        store = self.app.store
        dmz, _ = store.agents.create("dmz-browser")
        _, branch_token = store.agents.create("branch-office")
        monitor = self._kept_on()
        self.assertEqual(store.agents.delete(dmz["id"]), [])
        self.assertTrue(store.monitors.get(monitor["id"])["enabled"])
        self.assertEqual(len(self._sent_to(branch_token)), 1)

    def _billing(self):
        return self.app.store.monitors.create(
            name="billing-api", kind="http",
            target="https://billing.internal/health",
            request={"secret_headers": {"X-Api-Key": "SEALED-KEY"}})

    def _retarget(self, monitor, target, **extra):
        return self.client.post("/admin/monitors", data={
            "id": monitor["id"], "name": monitor["name"], "kind": "http",
            "target": target, "interval_seconds": "60",
            "timeout_seconds": "10", "enabled": "on", **extra},
            follow_redirects=True).get_data(as_text=True)

    def test_a_check_pointed_elsewhere_does_not_take_its_credentials(self):
        """Measured: retargeted at a listener with the boxes left blank,
        the sealed X-Api-Key went with it to the next agent poll."""
        monitor = self._billing()
        body = self._retarget(monitor, "https://listener.example/health")
        self.assertEqual(self.app.store.monitors.credentials(monitor["id"]), {})
        self.assertFalse(self.app.store.monitors.get(monitor["id"])["has_credentials"])
        self.assertIn("were not carried", body)
        self.assertIn("https://listener.example:443", body)

    def test_another_path_on_the_same_host_keeps_them(self):
        monitor = self._billing()
        body = self._retarget(monitor, "https://billing.internal/healthz")
        self.assertEqual(
            self.app.store.monitors.credentials(monitor["id"])["headers"],
            {"X-Api-Key": "SEALED-KEY"})
        self.assertNotIn("were not carried", body)

    def test_credentials_typed_again_go_to_the_new_target(self):
        monitor = self._billing()
        self._retarget(monitor, "https://billing2.internal/health",
                       request_headers="X-Api-Key: NEW-KEY")
        self.assertEqual(
            self.app.store.monitors.credentials(monitor["id"])["headers"],
            {"X-Api-Key": "NEW-KEY"})

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


class RetentionSchedulingTest(StoreTestCase):
    """Something has to CALL prune, and not on every request.

    The first version had working retention code and nothing that ran it, so
    the table grew without bound while the tests passed.
    """

    def setUp(self):
        super().setUp()
        self.agent, _ = self.store.agents.create("one")
        self.store.agents.seen(self.agent["id"])
        self.monitor = self.store.monitors.create(
            name="API", kind="http", target="https://example.com")

    def _old(self, days):
        self.store.results.record(self.agent["id"], [
            {"monitor_id": self.monitor["id"], "status": "up",
             "started_at": (_now() - timedelta(days=days)).isoformat()}])

    def test_it_prunes_past_the_retention_period(self):
        self._old(1)
        self._old(40)
        self.assertEqual(self.store.results.prune_if_due(self.store.settings), 1)
        self.assertEqual(self.store.results.count(), 1)

    def test_it_does_not_run_again_straight_away(self):
        """Otherwise every fifteen-second report from every agent puts a
        delete behind it."""
        self._old(40)
        self.store.results.prune_if_due(self.store.settings)
        self.assertIsNone(self.store.results.prune_if_due(self.store.settings))

    def test_the_marker_is_shared_rather_than_per_process(self):
        """Four gunicorn workers must not each keep their own clock and prune
        four times an hour between them."""
        from wdash.store.monitoring import PRUNE_MARKER
        self.store.results.prune_if_due(self.store.settings)
        self.assertIsNotNone(self.store.settings.get(PRUNE_MARKER))

    def test_retention_can_be_turned_off_on_purpose(self):
        from wdash.store.monitoring import PRUNE_MARKER, RETENTION_SETTING
        self._old(400)
        self.store.settings.set(RETENTION_SETTING, 0)
        self.store.settings.set(PRUNE_MARKER, (_now() - timedelta(days=1)).isoformat())
        self.assertIsNone(self.store.results.prune_if_due(self.store.settings))
        self.assertEqual(self.store.results.count(), 1)

    def test_a_broken_setting_falls_back_to_the_default(self):
        """A typo in a settings row must not switch retention off silently —
        that is how a table grows for a year."""
        from wdash.store.monitoring import (
            DEFAULT_RETENTION_DAYS, PRUNE_MARKER, RETENTION_SETTING,
        )
        self._old(DEFAULT_RETENTION_DAYS + 10)
        self.store.settings.set(RETENTION_SETTING, "thirty")
        self.store.settings.set(PRUNE_MARKER, (_now() - timedelta(days=1)).isoformat())
        self.assertEqual(self.store.results.prune_if_due(self.store.settings), 1)

    def test_a_large_batch_is_stored_rather_than_refused(self):
        """A single multi-VALUES insert binds nine parameters a row and SQLite
        refuses the statement past its variable ceiling — "too many SQL
        variables", which says nothing about the batch being too big. The
        endpoint caps at 500, so the live path never reached it; a caller
        flushing a day's backlog did."""
        # 50,000 because that is where it was MEASURED to break. 20,000 went
        # through on this build, so a test using it passed against the
        # unchunked insert too — it was measuring the threshold rather than
        # the fix.
        rows = [{"monitor_id": self.monitor["id"], "status": "up",
                 "started_at": _now().isoformat()} for _ in range(50000)]
        self.assertEqual(self.store.results.record(self.agent["id"], rows), 50000)


class StorageWarningTest(StoreTestCase):
    def test_a_small_table_says_nothing(self):
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        self.assertEqual(StoreMonitorSource(self.store).storage_warning(), "")

    @sqlite_only("the advice is to move to Postgres")
    def test_past_the_measured_threshold_it_says_so(self):
        """Measured, not guessed: 2.2 million rows is 508 ms for this page on
        SQLite and 8.6 million is 2.3 seconds. A page that is slow without
        saying why sends somebody to look at the network."""
        from wdash.hub.adapters import store_monitors
        source = store_monitors.StoreMonitorSource(self.store)
        original = self.store.results.count
        self.store.results.count = lambda monitor_id=None: 9_000_000
        try:
            warning = source.storage_warning()
        finally:
            self.store.results.count = original
        self.assertIn("Postgres", warning)
        self.assertIn("9,000,000", warning)


class RequestConfigurationTest(StoreTestCase):
    """Headers, cookies and authentication on an http check.

    Everything here is about one property: a credential goes into the
    database encrypted, comes out only for the agent, and appears on no
    screen and in no stored error. The rest is validation of things that turn
    a monitor definition into a way to send a request nobody configured.
    """

    def setUp(self):
        super().setUp()
        from wdash.store.secrets import SecretBox
        # A store WITH a key. The default fixture has none, and a check with
        # credentials must refuse to save rather than store them in clear.
        self.store.engine.dispose()
        self.store = Store.open(f"sqlite:///{self.database}",
                                secret_box=SecretBox(SecretBox.generate_key()))

    def _monitor(self, **kwargs):
        options = dict(name="API", kind="http", target="https://x.example",
                       interval_seconds=30, timeout_seconds=5)
        options.update(kwargs)
        return self.store.monitors.create(**options)

    # ---------- the split ----------

    def test_a_credential_header_is_sealed_wherever_it_is_typed(self):
        """Somebody pasting a bearer token into the plain header box should
        not have it stored in clear because of a checkbox they did not
        notice."""
        monitor = self._monitor(request={
            "headers": {"X-Api-Version": "2", "Authorization": "Bearer abc"}})
        self.assertEqual(monitor["request"]["headers"], {"X-Api-Version": "2"})
        self.assertEqual(
            self.store.monitors.credentials(monitor["id"])["headers"],
            {"Authorization": "Bearer abc"})

    def test_cookie_names_are_shown_and_values_are_not(self):
        """A cookie is a session token far more often than a preference. The
        names are enough for a screen to say what is being sent."""
        monitor = self._monitor(request={"cookies": {"session": "s3cr3t"}})
        self.assertEqual(monitor["request"]["cookie_names"], ["session"])
        self.assertNotIn("s3cr3t", json.dumps(monitor, default=str))

    def test_nothing_secret_survives_into_the_public_shape(self):
        monitor = self._monitor(request={
            "headers": {"Authorization": "Bearer abc"},
            "cookies": {"session": "s3cr3t"},
            "auth": {"type": "basic", "username": "svc", "password": "p@ss"}})
        rendered = json.dumps(monitor, default=str)
        for secret in ("Bearer abc", "s3cr3t", "p@ss"):
            self.assertNotIn(secret, rendered)
        self.assertTrue(monitor["has_credentials"])

    def test_it_is_encrypted_on_disk(self):
        monitor = self._monitor(request={
            "auth": {"type": "basic", "username": "svc", "password": "p@ss"}})
        with self.store.engine.connect() as connection:
            stored = connection.exec_driver_sql(
                "SELECT secrets FROM wdash_monitors").fetchone()[0]
        self.assertNotIn("p@ss", stored or "")

    def test_without_a_key_it_refuses_rather_than_storing_in_clear(self):
        plain = Store.open(f"sqlite:///{self.database}", secret_box=None)
        with self.assertRaises(MonitoringError) as caught:
            plain.monitors.create(
                name="API", kind="http", target="https://x.example",
                request={"auth": {"type": "bearer", "token": "abc"}})
        self.assertIn("WDASH_ENCRYPTION_KEY", str(caught.exception))
        plain.engine.dispose()

    def test_an_edit_that_supplies_no_credential_keeps_the_stored_one(self):
        """A form that submits an empty password box must not wipe the
        credential every time somebody changes the interval."""
        monitor = self._monitor(request={
            "auth": {"type": "basic", "username": "svc", "password": "p@ss"}})
        self.store.monitors.update(monitor["id"], interval_seconds=90, request={
            "auth": {"type": "basic", "username": "svc"}})
        self.assertEqual(
            self.store.monitors.credentials(monitor["id"])["auth_password"],
            "p@ss")

    # ---------- validation ----------

    def test_a_newline_in_a_header_value_is_refused(self):
        """A value containing CR or LF ends the header and starts another —
        turning a monitor definition into a way to add arbitrary headers."""
        with self.assertRaises(MonitoringError):
            self._monitor(request={"headers": {"X-A": "a\r\nX-Injected: b"}})

    def test_a_transport_header_cannot_be_overridden(self):
        """A wrong Host reaches a different vhost; a wrong Content-Length
        truncates the body."""
        for name in ("Host", "Content-Length", "Transfer-Encoding"):
            with self.assertRaises(MonitoringError):
                self._monitor(request={"headers": {name: "x"}})

    def test_a_header_name_with_a_space_is_refused(self):
        with self.assertRaises(MonitoringError):
            self._monitor(request={"headers": {"bad name": "x"}})

    def test_an_unknown_authentication_type_is_refused(self):
        with self.assertRaises(MonitoringError):
            self._monitor(request={"auth": {"type": "ntlm", "username": "x"}})

    def test_basic_auth_without_a_username_is_refused(self):
        with self.assertRaises(MonitoringError):
            self._monitor(request={"auth": {"type": "basic"}})

    def test_a_tcp_check_cannot_carry_headers(self):
        """A tcp check opens a socket. Boxes that will never be used teach
        that they work."""
        with self.assertRaises(MonitoringError):
            self._monitor(kind="tcp", target="db:5432",
                          request={"headers": {"X-A": "b"}})

    def test_matching_a_header_against_nothing_is_refused(self):
        """That is the presence check with extra steps, and two ways to say
        one thing is how they drift apart."""
        with self.assertRaises(MonitoringError):
            self._monitor(assertions={"headers_match": {"Content-Type": ""}})

    # ---------- what the agent receives ----------

    def test_the_agent_gets_the_credentials_filled_back_in(self):
        from wdash.api.agent_routes import _request_for
        monitor = self._monitor(request={
            "headers": {"X-Api-Version": "2", "Authorization": "Bearer abc"},
            "cookies": {"session": "s3cr3t"},
            "auth": {"type": "basic", "username": "svc", "password": "p@ss"}})
        request = _request_for(self.store, self.store.monitors.get(monitor["id"]))
        self.assertEqual(request["headers"],
                         {"X-Api-Version": "2", "Authorization": "Bearer abc"})
        self.assertEqual(request["cookies"], {"session": "s3cr3t"})
        self.assertEqual(request["auth"]["password"], "p@ss")
        # `cookie_names` is for a screen; the agent has the cookies.
        self.assertNotIn("cookie_names", request)

    def test_rotating_a_credential_changes_the_configuration_version(self):
        """`has_credentials` does not move when a password is REPLACED, so a
        rotated credential would never reach the agent. `updated_at` does."""
        from wdash.api.agent_routes import _configuration_version
        monitor = self._monitor(request={
            "auth": {"type": "basic", "username": "svc", "password": "old"}})
        before = _configuration_version([self.store.monitors.get(monitor["id"])])
        self.store.monitors.update(monitor["id"], request={
            "auth": {"type": "basic", "username": "svc", "password": "new"}})
        after = _configuration_version([self.store.monitors.get(monitor["id"])])
        self.assertNotEqual(before, after)


class CredentialRedactionTest(unittest.TestCase):
    """A failing check must not put its credentials on the page.

    urllib3 puts the failing request into some of its exceptions, and the
    error is both shown on the Monitors screen and stored in the results
    table — so a leak here is a credential in a table people read.
    """

    def test_a_secret_is_removed_from_a_message(self):
        from wdash.agent.checks import _redact
        request = {"headers": {"Authorization": "Bearer SUPERSECRET"},
                   "cookies": {"session": "C00KIE-VALUE"},
                   "auth": {"type": "basic", "password": "P4SSWORD"}}
        message = ("failed with Bearer SUPERSECRET and C00KIE-VALUE "
                   "and P4SSWORD")
        cleaned = _redact(message, request)
        for secret in ("SUPERSECRET", "C00KIE-VALUE", "P4SSWORD"):
            self.assertNotIn(secret, cleaned)

    def test_a_non_secret_header_is_left_alone(self):
        """Redacting everything would remove the reason along with the
        secret."""
        from wdash.agent.checks import _redact
        message = "X-Api-Version: 2 was rejected"
        self.assertEqual(
            _redact(message, {"headers": {"X-Api-Version": "2"}}), message)

    def test_the_redaction_is_applied_at_the_call_site(self):
        """Through `run_check`, with an exception that actually carries one.

        Testing `_redact` alone leaves the CALL SITE untested, and a redaction
        that is never applied does nothing — removing it from the failure path
        passed every test until this existed.

        The exception is injected rather than provoked. A refused connection
        does not carry the request, so a real failure against a dead port
        proves nothing; what has to be tested is that whatever the message
        says goes through the filter. This is defence in depth against
        libraries that render a request into an error, not a reproduction of
        one that does.
        """
        import requests

        from wdash.agent.checks import run_check

        class Leaky:
            def get(self, *args, **kwargs):
                raise requests.exceptions.ConnectionError(
                    "refused while sending Bearer SUPERSECRET "
                    "with cookie C00KIE-VALUE and password P4SSWORD")

        monitor = {
            "id": "x", "name": "t", "kind": "http",
            "target": "http://127.0.0.1:59998/",
            "timeout_seconds": 2, "assertions": {},
            "request": {"headers": {"Authorization": "Bearer SUPERSECRET"},
                        "cookies": {"session": "C00KIE-VALUE"},
                        "auth": {"type": "basic", "username": "u",
                                 "password": "P4SSWORD"}},
        }
        result = run_check(monitor, session=Leaky())
        self.assertEqual(result["status"], "down")
        self.assertTrue(result["error"], "the reason was lost entirely")
        for secret in ("SUPERSECRET", "C00KIE-VALUE", "P4SSWORD"):
            self.assertNotIn(secret, result["error"])

    def test_a_very_short_value_is_not_redacted(self):
        """Replacing every occurrence of a two-character secret would blank
        out most of the sentence."""
        from wdash.agent.checks import _redact
        message = "could not connect to db"
        self.assertEqual(_redact(message, {"cookies": {"s": "db"}}), message)


class RedirectTest(unittest.TestCase):
    """What a redirect target is sent.

    `requests` followed a redirect with the request's own headers and
    cookies, and on a change of host stripped only `Authorization`. Measured
    with two local servers: a 302 from the monitor's host to another handed
    the other host the sealed X-Api-Key, X-Auth-Token and cookie, whether the
    monitor used a bearer token or basic auth.
    """

    SECRETS = ("SEALED-KEY", "SEALED-TOK", "SEALED-COOKIE", "SEALED-BEARER",
               "c3ZjOnNlYWxlZC1wYXNz")  # base64 of svc:sealed-pass

    @classmethod
    def setUpClass(cls):
        cls.seen = []
        cls.other = cls._server(lambda handler: (200, []))
        cls.origin = cls._server(cls._answer)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.other, cls.origin):
            server.shutdown()
            server.server_close()

    @classmethod
    def _server(cls, answer):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = cls.seen

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.server.server_port, self.path, dict(self.headers)))
                status, headers = answer(self)
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        from tests.support import serve_in_background
        return serve_in_background(ThreadingHTTPServer(("127.0.0.1", 0), Handler))

    @classmethod
    def _answer(cls, handler):
        path = handler.path
        if path == "/away":
            return 302, [("Location", f"http://localhost:{cls.other.server_port}/x")]
        if path == "/port":
            return 302, [("Location", f"http://127.0.0.1:{cls.other.server_port}/x")]
        if path == "/old":
            return 301, [("Location", "/new")]
        if path == "/new":
            return (200 if handler.headers.get("X-Api-Key") == "SEALED-KEY"
                    else 401), []
        if path == "/set":
            return 302, [("Set-Cookie", "flow=abc; Path=/"), ("Location", "/need")]
        if path == "/need":
            return (200 if "flow=abc" in (handler.headers.get("Cookie") or "")
                    else 403), []
        if path == "/loop":
            return 302, [("Location", "/loop")]
        return 404, []

    def check(self, path, auth=None):
        from wdash.agent import checks
        self.seen.clear()
        monitor = {"id": "m", "name": "t", "kind": "http",
                   "target": f"http://127.0.0.1:{self.origin.server_port}{path}",
                   "timeout_seconds": 3, "assertions": {},
                   "request": {"headers": {"X-Api-Key": "SEALED-KEY",
                                           "X-Auth-Token": "SEALED-TOK"},
                               "cookies": {"session": "SEALED-COOKIE"},
                               "auth": auth or {}}}
        original = checks._certificate
        checks._certificate = lambda *args, **kwargs: None
        try:
            return checks.run_check(monitor)
        finally:
            checks._certificate = original

    def sent_to_the_other_host(self):
        return sorted({secret for port, _, headers in self.seen
                       if port == self.other.server_port
                       for secret in self.SECRETS
                       if secret in " ".join(headers.values())})

    def test_another_host_is_sent_nothing_the_monitor_was_given(self):
        for auth in ({"type": "bearer", "token": "SEALED-BEARER"},
                     {"type": "basic", "username": "svc", "password": "sealed-pass"}):
            with self.subTest(auth=auth["type"]):
                result = self.check("/away", auth)
                self.assertEqual(result["status"], "up", result["error"])
                self.assertTrue(any(port == self.other.server_port
                                    for port, _, _ in self.seen),
                                "the redirect was not followed")
                self.assertEqual(self.sent_to_the_other_host(), [])

    def test_another_port_on_the_same_host_is_another_origin(self):
        result = self.check("/port", {"type": "bearer", "token": "SEALED-BEARER"})
        self.assertEqual(result["status"], "up", result["error"])
        self.assertEqual(self.sent_to_the_other_host(), [])

    def test_a_redirect_on_its_own_origin_keeps_what_it_was_given(self):
        """/new answers 401 without the key: a check that dropped its
        headers on every hop would call a moved page down."""
        result = self.check("/old")
        self.assertEqual((result["status"], result["http_status"]), ("up", 200))

    def test_a_cookie_set_on_the_way_is_sent_on(self):
        """What `requests.get` did, and a check of its own must still do:
        sites set a cookie in the redirect and ask for it on the next page."""
        result = self.check("/set")
        self.assertEqual((result["status"], result["http_status"]), ("up", 200))

    def test_a_loop_ends_and_says_why(self):
        from wdash.agent.checks import MAX_REDIRECTS
        result = self.check("/loop")
        self.assertEqual(result["status"], "down")
        self.assertEqual(result["error"], "too many redirects")
        self.assertEqual(len(self.seen), MAX_REDIRECTS + 1)

    def test_what_counts_as_the_monitors_own_origin(self):
        """http:// to https:// on the same host is the one hop nearly every
        site makes, and the secrets go on encrypted; nothing else outside the
        origin qualifies. Decided here, because no local server speaks both
        on the default ports."""
        from wdash.agent.checks import _at_home, _origin
        home = _origin("http://site.example/health")
        self.assertTrue(_at_home(home, "http://site.example:80/login"))
        self.assertTrue(_at_home(home, "https://site.example/health"))
        self.assertTrue(_at_home(home, "https://SITE.example:443/"))
        self.assertFalse(_at_home(home, "https://site.example:8443/"))
        self.assertFalse(_at_home(home, "http://www.site.example/"))
        self.assertFalse(_at_home(_origin("http://site.example:8080/"),
                                  "https://site.example/"))
        self.assertFalse(_at_home(_origin("https://site.example/"),
                                  "http://site.example/"),
                         "a downgrade would send the secrets in the clear")


class WhereTheCheckRanTest(StoreTestCase):
    """A check knows which agent reported it, so a history can say so.

    Two probes watching one endpoint is the whole reason to have two probes,
    and until this existed the detail page averaged them: measured on one
    slow agent failing a quarter of its runs and one healthy one, the page
    reported 87.5% available and a response time that was true of neither.
    """

    def setUp(self):
        super().setUp()
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        self.source = StoreMonitorSource(self.store)
        self.window = TimeWindow.of("1h")
        self.scope = Scope.unrestricted()
        self.monitor = self._monitor()
        self.agents = {}
        for name in ("frankfurt", "dublin"):
            agent, _ = self._agent(name)
            self.agents[name] = agent
        self.store.monitors.update(
            self.monitor["id"],
            agent_ids=[a["id"] for a in self.agents.values()])

    def _report(self, agent_name, count=4, status=UP, duration_us=100_000):
        self.store.results.record(self.agents[agent_name]["id"], [{
            "monitor_id": self.monitor["id"],
            "started_at": (_now() - timedelta(minutes=i)).isoformat(),
            "status": status, "duration_us": duration_us,
            "error": "" if status == UP else "gateway timeout",
        } for i in range(count)])

    def _history(self):
        return self.source.history(self.monitor["id"], self.window, self.scope)

    def test_a_check_says_which_agent_reported_it(self):
        self._report("frankfurt")
        self._report("dublin")
        places = {c.location for c in self._history()}
        self.assertEqual(places, {"frankfurt", "dublin"})

    def test_it_is_the_name_somebody_typed_not_the_id(self):
        """An agent id is a uuid, and a page printing uuids where it means
        "Dublin" has not answered the question."""
        self._report("dublin", count=1)
        location = self._history()[0].location
        self.assertEqual(location, "dublin")
        self.assertNotIn(self.agents["dublin"]["id"], location)

    def test_a_result_from_a_deleted_agent_says_nothing_rather_than_lying(self):
        """The agent row is gone and the results it wrote are still real
        history. An empty location is the honest answer; the id would be a
        label nobody can read."""
        self._report("frankfurt", count=2)
        self.store.agents.delete(self.agents["frankfurt"]["id"])
        checks = self._history()
        self.assertEqual(len(checks), 2)
        self.assertEqual({c.location for c in checks}, {""})


class UnreadableCredentialsTest(unittest.TestCase):
    """A key that changed must not look like the target refusing a password.

    Sealed with one key and read with another, `credentials()` logged a line
    with no reason and returned {}. The agent then made the request with no
    Authorization header and the target answered 401, so every authenticated
    check reported the target down — while the page still said the check has
    credentials and the edit form said the secret does not exist. The one
    thing to fix, the server's key, was the one thing nothing said.
    """

    def setUp(self):
        from wdash.store.secrets import SecretBox

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.url = f"sqlite:///{self.database}"
        self.sealed = Store.open(
            self.url, secret_box=SecretBox(SecretBox.generate_key()))
        self.monitor = self.sealed.monitors.create(
            name="billing", kind="http", target="https://billing.example/health",
            request={"auth": {"type": "bearer", "token": "TOKEN-A"}})
        self.journey = self.sealed.monitors.create(
            name="Sign in", kind="browser", target=None, steps=[
                {"kind": "goto", "value": "https://shop.example/login"},
                {"kind": "fill", "selector": "#p",
                 "value": "{{ secret.password }}"},
                {"kind": "expect_url", "value": "/dashboard"}],
            journey_secrets={"password": "PW-A"})
        self.agent, self.token = self.sealed.agents.create("probe")
        self.opened = []

    def tearDown(self):
        self.sealed.engine.dispose()
        for store in self.opened:
            store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _reopened(self, box):
        store = Store.open(self.url, secret_box=box)
        self.opened.append(store)
        return store

    def _rotated(self):
        from wdash.store.secrets import SecretBox
        return self._reopened(SecretBox(SecretBox.generate_key()))

    def test_a_rotated_key_is_an_error_rather_than_no_credentials(self):
        store = self._rotated()
        with self.assertRaises(MonitoringError) as caught:
            store.monitors.credentials(self.monitor["id"])
        self.assertIn("WDASH_ENCRYPTION_KEY", str(caught.exception))

    def test_no_key_at_all_says_that_instead(self):
        from wdash.store.secrets import SecretBox
        store = self._reopened(SecretBox(None))
        with self.assertRaises(MonitoringError) as caught:
            store.monitors.credentials(self.journey["id"])
        self.assertIn("WDASH_ENCRYPTION_KEY", str(caught.exception))

    def test_a_check_with_no_credentials_is_untouched(self):
        store = self._rotated()
        plain = self.sealed.monitors.create(
            name="plain", kind="http", target="https://x.example")
        self.assertEqual(store.monitors.credentials(plain["id"]), {})

    def test_editing_the_journey_names_the_key_rather_than_the_secret(self):
        """`update()` feeds `credentials()` into the step merge, so the edit
        failed with "there is no such secret" — a sentence that sends somebody
        to re-type a password into a box that will seal it with a key the
        other process cannot read either."""
        store = self._rotated()
        with self.assertRaises(MonitoringError) as caught:
            store.monitors.update(
                self.journey["id"], steps=self.sealed.monitors.get(
                    self.journey["id"])["steps"])
        self.assertIn("WDASH_ENCRYPTION_KEY", str(caught.exception))


class UnreadableCredentialsAgentTest(unittest.TestCase):
    """What the agent is told, and what it does with it."""

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        # Sealed with one key, then read by a process holding another: what a
        # rotation, a lost key or a second deployment with its own key does.
        self.key = SecretBox.generate_key()
        self.sealed = Store.open(f"sqlite:///{database}",
                                 secret_box=SecretBox(self.key))
        self.monitor = self.sealed.monitors.create(
            name="billing", kind="http", target="https://billing.example/health",
            request={"auth": {"type": "bearer", "token": "TOKEN-A"}})
        self.journey = self.sealed.monitors.create(
            name="Sign in", kind="browser", target=None, steps=[
                {"kind": "goto", "value": "https://shop.example/login"},
                {"kind": "fill", "selector": "#p",
                 "value": "{{ secret.password }}"},
                {"kind": "expect_url", "value": "/dashboard"}],
            journey_secrets={"password": "PW-A"})
        self.plain = self.sealed.monitors.create(
            name="health", kind="http", target="https://shop.example/health")
        _, self.token = self.sealed.agents.create("probe")
        self.sealed.engine.dispose()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "monitors"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _configuration(self):
        reply = self.client.get(
            "/api/agent/config",
            headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(reply.status_code, 200)
        return {m["name"]: m for m in reply.get_json()["monitors"]}

    def test_the_check_carries_the_reason_instead_of_half_a_request(self):
        monitor = self._configuration()["billing"]
        self.assertIn("WDASH_ENCRYPTION_KEY", monitor.get("config_error", ""))
        self.assertNotIn("auth", monitor["request"],
                         "a bearer block with no token was sent")

    def test_a_journey_says_so_rather_than_sending_no_secrets(self):
        monitor = self._configuration()["Sign in"]
        self.assertIn("WDASH_ENCRYPTION_KEY", monitor.get("config_error", ""))
        self.assertFalse(monitor.get("secrets"))

    def test_the_checks_that_need_no_credentials_still_run(self):
        """One unreadable secret must not take the other checks with it —
        that was the shape of the 500 this endpoint had before."""
        monitor = self._configuration()["health"]
        self.assertNotIn("config_error", monitor)

    def test_the_agent_reports_it_down_without_making_the_request(self):
        """Making the request anyway measures the credential that is missing
        and reports a target that is fine as broken."""
        from http.server import BaseHTTPRequestHandler, HTTPServer

        from tests.support import serve_in_background
        from wdash.agent.checks import run_check

        asked = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                asked.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *arguments):
                pass

        server = serve_in_background(HTTPServer(("127.0.0.1", 0), Handler))
        try:
            monitor = dict(self._configuration()["billing"],
                           target=f"http://127.0.0.1:{server.server_port}/health")
            result = run_check(monitor)
        finally:
            server.shutdown()
        self.assertEqual(result["status"], "down")
        self.assertIn("WDASH_ENCRYPTION_KEY", result["error"])
        self.assertEqual(asked, [], "the request was made anyway")

    def _version(self, key):
        """The configuration version this database serves under `key`."""
        from wdash.app import create_app
        from wdash.config import Config

        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "monitors"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        app = create_app(TestConfig)
        try:
            reply = app.test_client().get(
                "/api/agent/config",
                headers={"Authorization": f"Bearer {self.token}"})
            return reply.get_json()
        finally:
            app.store.engine.dispose()

    def test_restoring_the_key_moves_the_version_the_agent_polls_on(self):
        """Otherwise the repair never reaches a running agent.

        `AgentRunner._poll_config` returns early when the version has not
        moved, and the version hashed only the stored monitor row — which is
        identical whether the check went out with its credential or with
        `config_error`. So an agent that adopted the broken configuration kept
        reporting the check down with "the key has probably changed" after the
        operator had put the key back, until something else edited a monitor
        or the agent was restarted.
        """
        from wdash.store.secrets import SecretBox

        broken = self._version(SecretBox.generate_key())
        fixed = self._version(self.key)
        self.assertTrue(
            any(m.get("config_error") for m in broken["monitors"]),
            "the broken configuration was not broken")
        self.assertFalse(any(m.get("config_error") for m in fixed["monitors"]))
        self.assertNotEqual(
            broken["version"], fixed["version"],
            "the agent would have seen an unchanged version and kept the "
            "configuration it could not run")

    def test_a_poll_that_changes_nothing_still_reads_as_nothing(self):
        """The version has to stay a comparison the agent can trust: two
        polls of the same database in the same state are the same version."""
        self.assertEqual(self._version(self.key)["version"],
                         self._version(self.key)["version"])

    def test_the_reason_is_not_what_is_hashed(self):
        """A reworded message is not a configuration change. Only the FACT
        that a check could not be configured belongs in the version."""
        import wdash.api.agent_routes as routes
        monitors = [{"id": "m1", "kind": "http", "target": "https://x/",
                     "interval_seconds": 60, "timeout_seconds": 10,
                     "assertions": {}, "request": {}, "updated_at": None}]
        self.assertEqual(
            routes._configuration_version(monitors, {"m1"}),
            routes._configuration_version(monitors, ["m1"]))
        self.assertNotEqual(
            routes._configuration_version(monitors, {"m1"}),
            routes._configuration_version(monitors, set()))


# ---------------------------------------------------------------------------
# A check's own TLS decision
# ---------------------------------------------------------------------------

def _certificates(scratch):
    """A private CA, a second one, and the leaves they signed.

    Both extensions OpenSSL 3 insists on are here — KeyUsage(key_cert_sign)
    on the authority and an Authority Key Identifier on the leaf. Measured
    without them: the chain is refused with "CA cert does not include key
    usage extension" and "Missing Authority Key Identifier", so every case
    below would fail for a reason that has nothing to do with what it is
    about.
    """
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)
    out = {}

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def authority(common):
        k = key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])
        certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                k.public_key()), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(k, hashes.SHA256()))
        return certificate, k

    def leaf(common, ca, ca_key, tag):
        k = key()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, common)]))
            .issuer_name(ca.subject).public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(common)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.AuthorityKeyIdentifier
                           .from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                k.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
        cert_path = os.path.join(scratch, f"{tag}.crt")
        key_path = os.path.join(scratch, f"{tag}.key")
        with open(cert_path, "wb") as handle:
            handle.write(certificate.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as handle:
            handle.write(k.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        return certificate, cert_path, key_path

    ours, ours_key = authority("Warewave Internal CA")
    theirs, theirs_key = authority("Somebody Else's CA")
    out["ca_pem"] = ours.public_bytes(serialization.Encoding.PEM).decode()
    out["other_ca_pem"] = theirs.public_bytes(
        serialization.Encoding.PEM).decode()
    out["leaf"], out["leaf_crt"], out["leaf_key"] = leaf(
        "payments.internal", ours, ours_key, "payments")
    out["second"], out["second_crt"], out["second_key"] = leaf(
        "billing.internal", theirs, theirs_key, "billing")
    return out


def _tls_listener(cert_path, key_path, redirect_to=None):
    """A real HTTPS server on 127.0.0.1. Returns it; shut it down after.

    Real rather than faked, because everything this file asserts about trust
    is a property of OpenSSL, urllib3 and requests together — a fake session
    would assert what the test author believed those three do.
    """
    import ssl as _ssl
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from tests.support import serve_in_background

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if redirect_to:
                self.send_response(302)
                self.send_header("Location", redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return serve_in_background(server)


class TlsSettingTest(StoreTestCase):
    """What a check may decide about the certificate, and what it may not.

    Most of these are one rule: a check that does not verify the certificate
    is talking to whatever answered, so it must send NOTHING. Asked about the
    REQUEST rather than about the secret box, which is the whole point — only
    six header names are sealed wherever they are typed, and `X-Tenant-Token`
    in the plain box is stored in the open, leaves `has_credentials` False and
    still goes out on the wire.
    """

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.mkdtemp()
        cls.certificates = _certificates(cls.scratch)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def setUp(self):
        super().setUp()
        from wdash.store.secrets import SecretBox
        # A store WITH a key: half of what is asserted here is about a check
        # that HOLDS a credential, and the default fixture cannot store one.
        self.store.engine.dispose()
        self.store = Store.open(f"sqlite:///{self.database}",
                                secret_box=SecretBox(SecretBox.generate_key()))

    def _pem(self, key="ca_pem"):
        return self.certificates[key]

    def test_a_pasted_certificate_is_stored_and_shown_back(self):
        """Shown back on purpose: a certificate is public, and "which one
        does this check trust" is the question the form has to answer."""
        monitor = self._monitor(
            tls={"mode": "verify", "certificate": self._pem(),
                 "expected_name": "payments.internal"})
        self.assertEqual(monitor["tls"]["mode"], "verify")
        self.assertIn("BEGIN CERTIFICATE", monitor["tls"]["certificate"])
        self.assertEqual(monitor["tls"]["expected_name"], "payments.internal")
        import sqlalchemy

        from wdash.store.schema import monitors as table
        with self.store.engine.connect() as connection:
            stored = connection.execute(sqlalchemy.select(table.c.tls).where(
                table.c.id == monitor["id"])).scalar()
        self.assertIn("BEGIN CERTIFICATE", json.dumps(stored))

    def test_no_setting_stores_nothing(self):
        """NULL and "verify against the public roots" are one fact. Two of
        them would make every check written before this differ from every one
        written after it, for no reason anybody could see."""
        self.assertEqual(self._monitor()["tls"], {})

    def test_a_check_that_sends_a_sealed_credential_cannot_stop_verifying(self):
        with self.assertRaises(MonitoringError) as caught:
            self._monitor(request={"auth": {"type": "basic", "username": "svc",
                                            "password": "P4SS"}},
                          tls={"mode": "expiry_only"})
        self.assertIn("does not verify", str(caught.exception))
        self.assertIn("svc", str(caught.exception))

    def test_a_plain_header_counts_as_something_it_would_send(self):
        """`X-Tenant-Token` is not one of the six names sealed wherever they
        are typed, so it is stored in the OPEN, leaves `has_credentials`
        False — and still goes out, to whatever answered."""
        with self.assertRaises(MonitoringError) as caught:
            self._monitor(request={"headers": {"X-Tenant-Token": "abc123"}},
                          tls={"mode": "expiry_only"})
        self.assertIn("X-Tenant-Token", str(caught.exception))
        self.assertNotIn("abc123", str(caught.exception))

    def test_a_username_with_no_stored_password_counts_too(self):
        """`requests` prepares ('svc', '') into a real Authorization header:
        measured, `Basic c3ZjOg==`. Nothing about it is in `secrets`."""
        with self.assertRaises(MonitoringError) as caught:
            self._monitor(request={"auth": {"type": "basic",
                                            "username": "svc"}},
                          tls={"mode": "expiry_only"})
        self.assertIn("svc", str(caught.exception))

    def test_a_check_that_sends_nothing_may_stop_verifying(self):
        """The refusal has to refuse a combination, not the setting."""
        monitor = self._monitor(tls={"mode": "expiry_only"})
        self.assertEqual(monitor["tls"]["mode"], "expiry_only")

    def test_the_stored_row_is_untouched_when_the_edit_is_refused(self):
        monitor = self._monitor(
            request={"auth": {"type": "basic", "username": "svc",
                              "password": "P4SS"}})
        with self.assertRaises(MonitoringError):
            self.store.monitors.update(monitor["id"],
                                       tls={"mode": "expiry_only"})
        again = self.store.monitors.get(monitor["id"])
        self.assertEqual(again["tls"], {})
        self.assertTrue(again["has_credentials"])
        self.assertEqual(self.store.monitors.credentials(monitor["id"]),
                         {"auth_password": "P4SS"})

    def test_forgetting_what_it_sends_empties_the_open_half_as_well(self):
        """The escape hatch, and the only one there is: measured, a stored
        credential cannot otherwise be removed at all. It has to clear the
        PUBLIC request too, or the check goes on sending the header the
        refusal was about."""
        monitor = self._monitor(
            request={"headers": {"X-Tenant-Token": "abc123"},
                     "auth": {"type": "basic", "username": "svc",
                              "password": "P4SS"}})
        saved = self.store.monitors.update(
            monitor["id"], forget_request=True, tls={"mode": "expiry_only"})
        self.assertEqual(saved["request"], {})
        self.assertFalse(saved["has_credentials"])
        self.assertEqual(self.store.monitors.credentials(monitor["id"]), {})
        self.assertEqual(saved["tls"]["mode"], "expiry_only")

    def test_retargeting_and_forgetting_and_waiving_in_one_save(self):
        """Three branches of `update` write the secrets, so the rule has to
        be evaluated against what the save LEAVES BEHIND. Read off the row as
        it stands, this legitimate save is refused for a credential it is in
        the act of removing."""
        monitor = self._monitor(
            target="https://payments.internal/health",
            request={"auth": {"type": "basic", "username": "svc",
                              "password": "P4SS"}})
        saved = self.store.monitors.update(
            monitor["id"], target="https://billing.internal/health",
            forget_request=True, tls={"mode": "expiry_only"})
        self.assertEqual(saved["target"], "https://billing.internal/health")
        self.assertEqual(saved["tls"]["mode"], "expiry_only")
        self.assertFalse(saved["has_credentials"])

    def test_a_certificate_does_not_follow_a_check_to_another_host(self):
        """It was pasted because THAT endpoint presents it. Same rule as a
        stored credential — and unlike one it is shown on the form, so
        pasting it again is one deliberate act rather than a lost secret."""
        monitor = self._monitor(target="https://payments.internal/health",
                                tls={"certificate": self._pem()})
        saved = self.store.monitors.update(
            monitor["id"], target="https://billing.internal/health")
        self.assertEqual(saved["tls"], {})

    def test_another_path_on_the_same_host_keeps_the_certificate(self):
        monitor = self._monitor(target="https://payments.internal/health",
                                tls={"certificate": self._pem()})
        saved = self.store.monitors.update(
            monitor["id"], target="https://payments.internal/ready")
        self.assertIn("BEGIN CERTIFICATE", saved["tls"]["certificate"])

    def test_a_setting_on_a_tcp_check_is_refused(self):
        with self.assertRaises(MonitoringError) as caught:
            self._monitor(kind="tcp", target="db.internal:5432",
                          tls={"mode": "expiry_only"})
        self.assertIn("never sees a certificate", str(caught.exception))

    def test_a_setting_on_an_http_target_is_refused(self):
        """A setting stored and ignored is the shape this package exists to
        remove."""
        with self.assertRaises(MonitoringError) as caught:
            self._monitor(target="http://plain.internal/health",
                          tls={"certificate": self._pem()})
        self.assertIn("plain http check", str(caught.exception))

    def test_a_private_key_is_refused_and_says_to_rotate_it(self):
        with self.assertRaises(MonitoringError) as caught:
            self._monitor(tls={"certificate":
                               "-----BEGIN PRIVATE KEY-----\nx\n"
                               "-----END PRIVATE KEY-----\n"})
        self.assertIn("rotate", str(caught.exception))

    def test_something_that_is_not_a_certificate_is_refused(self):
        with self.assertRaises(MonitoringError):
            self._monitor(tls={"certificate": "hello"})

    def test_a_bundle_is_refused_by_size(self):
        """It goes into a JSON column, into every /api/agent/config response
        for every agent on every poll, and into the version hash."""
        from wdash.store.monitoring import MAX_TLS_PEM_BYTES
        with self.assertRaises(MonitoringError) as caught:
            self._monitor(tls={"certificate":
                               self._pem() * (MAX_TLS_PEM_BYTES // 100)})
        self.assertIn("KB", str(caught.exception))

    def test_a_certificate_and_a_waiver_are_opposite_instructions(self):
        with self.assertRaises(MonitoringError):
            self._monitor(tls={"mode": "expiry_only",
                               "certificate": self._pem()})

    def test_an_expected_name_needs_a_certificate(self):
        with self.assertRaises(MonitoringError):
            self._monitor(tls={"expected_name": "payments.internal"})

    def test_an_unknown_mode_is_refused_rather_than_read_as_verify(self):
        with self.assertRaises(MonitoringError):
            self._monitor(tls={"mode": "trust-me"})


class JourneyTlsTest(StoreTestCase):
    """A journey behind a private certificate, which is the commonest one.

    A journey that signs in CANNOT exist without a stored secret, so "a
    journey may not name a certificate, and expiry-only carries no
    credentials" would leave every internal sign-in journey with no working
    configuration at all. Measured against Chromium 151, it has one: a pinned
    public key.
    """

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.mkdtemp()
        cls.certificates = _certificates(cls.scratch)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def setUp(self):
        super().setUp()
        from wdash.store.secrets import SecretBox
        # A journey that signs in cannot exist without a stored secret, which
        # is the whole reason this class is separate.
        self.store.engine.dispose()
        self.store = Store.open(f"sqlite:///{self.database}",
                                secret_box=SecretBox(SecretBox.generate_key()))

    STEPS = [{"kind": "goto", "value": "https://payments.internal/login"},
             {"kind": "fill", "selector": "#p",
              "value": "{{ secret.password }}"},
             {"kind": "expect_text", "value": "hello"}]

    def _journey(self, **kwargs):
        options = dict(name="Sign in", kind="browser", target=None,
                       interval_seconds=60, timeout_seconds=30,
                       steps=self.STEPS,
                       journey_secrets={"password": "P4SS"})
        options.update(kwargs)
        return self.store.monitors.create(**options)

    def test_a_sign_in_journey_may_name_the_certificate_it_trusts(self):
        monitor = self._journey(
            tls={"certificate": self.certificates["ca_pem"]})
        self.assertTrue(monitor["has_credentials"])
        self.assertIn("BEGIN CERTIFICATE", monitor["tls"]["certificate"])

    def test_a_sign_in_journey_may_not_waive_verification(self):
        with self.assertRaises(MonitoringError) as caught:
            self._journey(tls={"mode": "expiry_only"})
        self.assertIn("certificate this endpoint presents",
                      str(caught.exception))

    def test_a_journey_with_no_secret_may_waive_it(self):
        monitor = self._journey(
            steps=[{"kind": "goto", "value": "https://payments.internal/"},
                   {"kind": "expect_text", "value": "hello"}],
            journey_secrets={}, tls={"mode": "expiry_only"})
        self.assertEqual(monitor["tls"]["mode"], "expiry_only")

    def test_an_expected_name_on_a_journey_is_refused(self):
        """Measured: a pinned key is accepted whatever name the certificate
        carries, so a name typed here would be stored and never consulted."""
        with self.assertRaises(MonitoringError) as caught:
            self._journey(tls={"certificate": self.certificates["ca_pem"],
                               "expected_name": "payments.internal"})
        self.assertIn("public key", str(caught.exception))

    def test_forgetting_a_journey_secret_is_refused_rather_than_offered(self):
        """It would leave a step with nothing to type: the escape hatch would
        be a way to break a check."""
        monitor = self._journey()
        with self.assertRaises(MonitoringError) as caught:
            self.store.monitors.update(monitor["id"], forget_request=True)
        self.assertIn("nothing to type", str(caught.exception))


class TlsTrustTest(unittest.TestCase):
    """The agent against real TLS listeners with a real private chain.

    Behavioural rather than mocked, and that is deliberate: every claim here
    is a property of OpenSSL, urllib3 and requests together — which version
    re-arms verification from the `verify` argument, which layer re-checks
    the host name — and a fake session would assert what the author believed
    those three do. An upgrade that moves one of those hooks fails these
    loudly rather than quietly trusting less, or more.
    """

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.mkdtemp()
        cls.certificates = _certificates(cls.scratch)
        cls.ours = _tls_listener(cls.certificates["leaf_crt"],
                                 cls.certificates["leaf_key"])
        cls.theirs = _tls_listener(cls.certificates["second_crt"],
                                   cls.certificates["second_key"])
        cls.port = cls.ours.server_address[1]
        cls.other_port = cls.theirs.server_address[1]
        cls.elsewhere = _tls_listener(
            cls.certificates["leaf_crt"], cls.certificates["leaf_key"],
            redirect_to=f"https://127.0.0.1:{cls.other_port}/next")
        cls.redirect_port = cls.elsewhere.server_address[1]

    @classmethod
    def tearDownClass(cls):
        import shutil
        for server in (cls.ours, cls.theirs, cls.elsewhere):
            server.shutdown()
            server.server_close()
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def _check(self, tls=None, port=None):
        from wdash.agent.checks import run_check
        return run_check({
            "id": "m1", "name": "payments", "kind": "http",
            "target": f"https://127.0.0.1:{port or self.port}/",
            "timeout_seconds": 5, "assertions": {}, "request": {},
            "tls": tls or {}})

    def test_a_private_certificate_is_down_and_the_reason_names_the_setting(self):
        """The failure is where somebody needs to be told the setting exists
        — not on a form they were not looking at."""
        result = self._check()
        self.assertEqual(result["status"], "down")
        self.assertIn("unable to get local issuer certificate",
                      result["error"])
        self.assertIn("Name the certificate to trust", result["error"])
        self.assertIs(result["handshake_verified"], False)

    def test_the_certificate_and_the_name_it_carries_make_it_up(self):
        result = self._check({"mode": "verify",
                              "certificate": self.certificates["ca_pem"],
                              "expected_name": "payments.internal"})
        self.assertEqual(result["status"], "up", result["error"])
        self.assertIs(result["handshake_verified"], True)
        self.assertEqual(result["tls"]["common_name"], "payments.internal")

    def test_without_the_expected_name_the_address_has_to_be_named(self):
        """The setting does not paper over the name: an endpoint reached at
        an address its certificate does not carry is still down, and the
        reason says which box answers it."""
        result = self._check({"certificate": self.certificates["ca_pem"]})
        self.assertEqual(result["status"], "down")
        self.assertIn("mismatch", result["error"])
        self.assertIn("Expected certificate name", result["error"])

    def test_the_wrong_certificate_is_still_down(self):
        result = self._check({"certificate": self.certificates["other_ca_pem"],
                              "expected_name": "payments.internal"})
        self.assertEqual(result["status"], "down")
        self.assertIn("did not sign", result["error"])
        self.assertIs(result["handshake_verified"], False)

    def test_expiry_only_reports_the_clock_and_says_it_did_not_verify(self):
        result = self._check({"mode": "expiry_only"})
        self.assertEqual(result["status"], "up", result["error"])
        self.assertIs(result["handshake_verified"], False)
        self.assertEqual(result["tls"]["common_name"], "payments.internal")
        self.assertTrue(result["tls"]["not_after"])

    def test_the_waiver_does_not_travel_to_the_redirect(self):
        """Bounded to the monitor's own origin, exactly as its credentials
        are: a redirect to a sign-in page on another host is asked for with
        the public roots like anybody else's."""
        result = self._check({"mode": "expiry_only"}, port=self.redirect_port)
        self.assertEqual(result["status"], "down")
        self.assertIn("TLS handshake failed", result["error"])

    def test_expiry_only_does_not_fill_the_log_with_warnings(self):
        """urllib3 warns once per request, and this is a setting somebody
        chose on purpose — a line per check per interval is how a log becomes
        unreadable. Filtered around the call rather than disabled for the
        process, which would silence the agent's own unverified link to
        WDash for ever."""
        import warnings

        import urllib3
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            self._check({"mode": "expiry_only"})
        self.assertEqual(
            [w for w in seen
             if issubclass(w.category,
                           urllib3.exceptions.InsecureRequestWarning)], [])

    def test_a_plain_http_target_says_nothing_about_a_handshake(self):
        """None, not False. There was no handshake to make, and False is a
        finding."""
        from wdash.agent.checks import run_check
        result = run_check({"id": "m1", "name": "plain", "kind": "http",
                            "target": "http://127.0.0.1:9/", "request": {},
                            "timeout_seconds": 2, "assertions": {}})
        self.assertEqual(result["status"], "down")
        self.assertIsNone(result["handshake_verified"])

    def test_the_adapter_is_mounted_where_requests_will_look_for_it(self):
        """Both forms of the prefix, and this is the case the whole feature
        turned on: `PreparedRequest.prepare_url` does NOT add the port a
        scheme implies, so a prefix built from the port-filled origin —
        `https://payments.internal:443/` — never matches the ordinary
        `https://payments.internal/`. Measured with requests 2.32.5:
        `get_adapter` returns the DEFAULT adapter for that prefix, so both
        settings were silently ignored on every https check at the default
        port, which is most of them.

        Asserted at this level because binding port 443 needs root; every
        listener in this class has an explicit port, which is exactly why
        this would pass with the bug in place.
        """
        import requests

        from wdash.agent.checks import _trust
        session = requests.Session()
        default = session.get_adapter("https://payments.internal/")
        _trust(session, "https://payments.internal/",
               {"certificate": self.certificates["ca_pem"]})
        self.assertIsNot(session.get_adapter("https://payments.internal/"),
                         default)
        self.assertIsNot(
            session.get_adapter("https://payments.internal:443/health"),
            default)
        # And nowhere else: another host and another port keep the session's
        # own adapter and the public roots, and so does the other scheme —
        # which has an adapter of its own.
        for elsewhere in ("https://billing.internal/",
                          "https://payments.internal:8443/"):
            self.assertIs(session.get_adapter(elsewhere), default, elsewhere)
        self.assertIs(session.get_adapter("http://payments.internal/"),
                      session.adapters["http://"])

    def test_a_pasted_certificate_is_trusted_instead_of_the_public_roots(self):
        """Not in addition to them. A certificate is pasted because the
        service is not public, and the public roots beside it would let a
        wrong paste through a path nobody meant — the check would look like
        it was working.

        Counted AFTER a real request, which is the only moment it can be
        counted: `requests`'s own `cert_verify` resolves the `verify`
        argument to the system CA bundle and urllib3 loads it into this very
        context at connect time. Measured with the stock implementation left
        in place: 122 certificates in the context after one request, of which
        the pasted one was one. With it overridden: 1.
        """
        import requests

        from wdash.agent.checks import _trust
        url = f"https://127.0.0.1:{self.port}/"
        session = requests.Session()
        _trust(session, url, {"certificate": self.certificates["ca_pem"],
                              "expected_name": "payments.internal"})
        session.get(url, timeout=5).close()
        context = (session.get_adapter(url)
                   .poolmanager.connection_pool_kw["ssl_context"])
        self.assertEqual(len(context.get_ca_certs()), 1)

    def test_a_session_without_mount_is_left_alone(self):
        """`run_check` takes a caller's session, and a fake in a test has no
        `mount`. Reaching into one would turn a TLS setting into a crash on
        every check that used it."""
        from wdash.agent.checks import _trust
        self.assertFalse(_trust(object(), "https://x/", {"certificate": "x"}))


class TlsReasonTest(unittest.TestCase):
    """Which failures the discoverability sentence is appended to.

    Measured, the four common TLS failures are distinguishable from the
    message, and two of them are not answered by naming a certificate. The
    expired one is the important one: "set the check to expiry only" against
    `certificate has expired` is advice to switch verification off to stop
    seeing an expiry, which is the one thing the TLS screen exists to show.
    """

    def _reason(self, text, tls=None):
        import requests

        from wdash.agent.checks import _reason
        return _reason(requests.exceptions.SSLError(text), tls)

    def test_an_untrusted_chain_is_told_about_the_setting(self):
        sentence = self._reason(
            "certificate verify failed: unable to get local issuer certificate")
        self.assertIn("Name the certificate to trust", sentence)

    def test_a_self_signed_certificate_is_told_too(self):
        sentence = self._reason(
            "certificate verify failed: self-signed certificate in "
            "certificate chain")
        self.assertIn("Name the certificate to trust", sentence)

    def test_an_expired_certificate_is_told_nothing(self):
        """The expiry IS the finding."""
        sentence = self._reason(
            "certificate verify failed: certificate has expired")
        self.assertNotIn("expiry only", sentence)
        self.assertNotIn("Name the certificate", sentence)

    def test_a_wrong_name_is_not_answered_by_naming_an_authority(self):
        sentence = self._reason(
            "certificate verify failed: Hostname mismatch, certificate is "
            "not valid for 'localhost'")
        self.assertNotIn("expiry only", sentence)

    def test_a_wrong_name_under_a_pasted_certificate_names_the_right_box(self):
        sentence = self._reason(
            "certificate verify failed: IP address mismatch, certificate is "
            "not valid for '127.0.0.1'",
            {"mode": "verify", "certificate": "-----BEGIN CERTIFICATE-----"})
        self.assertIn("Expected certificate name", sentence)

    def test_a_check_that_already_names_one_is_told_it_did_not_sign(self):
        sentence = self._reason(
            "certificate verify failed: unable to get local issuer certificate",
            {"mode": "verify", "certificate": "-----BEGIN CERTIFICATE-----"})
        self.assertIn("did not sign", sentence)

    def test_a_check_that_is_not_verifying_is_told_nothing(self):
        """Whatever went wrong, the setting is not it."""
        sentence = self._reason(
            "certificate verify failed: self-signed certificate",
            {"mode": "expiry_only"})
        self.assertNotIn("expiry only", sentence)
        self.assertNotIn("Name the certificate", sentence)


class WithheldFromTheAgentTest(unittest.TestCase):
    """What /api/agent/config refuses to send, and why it is loud about it.

    The store refuses to SAVE a check that does not verify the certificate
    and still sends something, so a row holding both was hand-edited or
    written by an older build. Withheld here as well because this endpoint is
    the only place any of it leaves the database, and a silent 401 an hour
    later is not something anybody can act on.
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
            SECRET_KEY = "withheld"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.agent, self.token = self.app.store.agents.create("one")
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        self.app.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _hand_edit(self, monitor_id, tls):
        """What an older build or a hand-edited row leaves behind."""
        import sqlalchemy

        from wdash.store.schema import monitors as table
        with self.app.store.engine.begin() as connection:
            connection.execute(sqlalchemy.update(table)
                               .where(table.c.id == monitor_id)
                               .values(tls=tls))

    def test_nothing_it_would_send_reaches_the_agent(self):
        monitor = self.app.store.monitors.create(
            name="billing", kind="http", target="https://billing.internal/",
            interval_seconds=60, timeout_seconds=10,
            request={"headers": {"X-Tenant-Token": "PLAIN-TOKEN"},
                     "cookies": {"session": "C00KIE"},
                     "auth": {"type": "basic", "username": "svc",
                              "password": "P4SS"}})
        self._hand_edit(monitor["id"], {"mode": "expiry_only"})

        with self.assertLogs("wdash.api.agent_routes", "ERROR") as logged:
            response = self.client.get("/api/agent/config",
                                       headers=self.headers)
        body = response.get_data(as_text=True)
        check = response.get_json()["monitors"][0]
        self.assertEqual(check["request"], {})
        self.assertEqual(check["tls"], {"mode": "expiry_only"})
        for secret in ("PLAIN-TOKEN", "C00KIE", "P4SS", "X-Tenant-Token",
                       "svc"):
            self.assertNotIn(secret, body)
        self.assertIn("billing", "\n".join(logged.output))

    def test_a_journey_in_that_state_is_not_handed_its_secrets(self):
        monitor = self.app.store.monitors.create(
            name="Sign in", kind="browser", target=None, interval_seconds=60,
            timeout_seconds=30,
            steps=[{"kind": "goto", "value": "https://payments.internal/"},
                   {"kind": "fill", "selector": "#p",
                    "value": "{{ secret.password }}"},
                   {"kind": "expect_text", "value": "hello"}],
            journey_secrets={"password": "P4SS"})
        self._hand_edit(monitor["id"], {"mode": "expiry_only"})

        with self.assertLogs("wdash.api.agent_routes", "ERROR"):
            response = self.client.get("/api/agent/config",
                                       headers=self.headers)
        check = response.get_json()["monitors"][0]
        self.assertNotIn("secrets", check)
        self.assertNotIn("P4SS", response.get_data(as_text=True))

    def test_a_verifying_check_is_handed_what_it_needs(self):
        """The withholding must be about the setting, not about the endpoint:
        a rule that withheld from everything would be a rule that breaks
        every authenticated check."""
        self.app.store.monitors.create(
            name="billing", kind="http", target="https://billing.internal/",
            interval_seconds=60, timeout_seconds=10,
            request={"auth": {"type": "basic", "username": "svc",
                              "password": "P4SS"}})
        response = self.client.get("/api/agent/config", headers=self.headers)
        check = response.get_json()["monitors"][0]
        self.assertEqual(check["request"]["auth"]["password"], "P4SS")

    def test_the_certificate_reaches_the_agent(self):
        """It has to: the agent owns no files and reads nothing local, so a
        path here would be a configuration error on each agent host that
        WDash could not see and that would look like an outage."""
        scratch = tempfile.mkdtemp()
        try:
            pem = _certificates(scratch)["ca_pem"]
        finally:
            import shutil
            shutil.rmtree(scratch, ignore_errors=True)
        self.app.store.monitors.create(
            name="payments", kind="http", target="https://payments.internal/",
            interval_seconds=60, timeout_seconds=10,
            tls={"certificate": pem, "expected_name": "payments.internal"})
        check = self.client.get(
            "/api/agent/config", headers=self.headers).get_json()["monitors"][0]
        self.assertIn("BEGIN CERTIFICATE", check["tls"]["certificate"])
        self.assertEqual(check["tls"]["expected_name"], "payments.internal")

    def test_the_version_moves_when_only_the_tls_setting_changes(self):
        """Asserted against `_configuration_version` directly, with the SAME
        `updated_at`. Through `update()` this passes either way — every edit
        bumps the timestamp, and the timestamp is already hashed — so a test
        that went through the route would catch nothing, and the field could
        be left out of the payload with nobody noticing.
        """
        import wdash.api.agent_routes as routes
        base = {"id": "m1", "kind": "http", "target": "https://x/",
                "interval_seconds": 60, "timeout_seconds": 10,
                "assertions": {}, "request": {}, "updated_at": "fixed"}
        verifying = dict(base, tls={})
        waived = dict(base, tls={"mode": "expiry_only"})
        self.assertNotEqual(routes._configuration_version([verifying]),
                            routes._configuration_version([waived]))


class VerdictReachesThePageTest(StoreTestCase):
    """From the agent's result to the neutral model, without a page.

    The verdict is a column of its own rather than a key inside the
    certificate blob, and this is why: the blob is NULL exactly when no
    certificate could be read — an http target, an agent behind a proxy, an
    endpoint that closes the second connection — and those are the runs where
    the verdict still has to survive.
    """

    def _reported(self, result):
        from wdash.hub.adapters import store_monitors
        from wdash.hub.query import TimeWindow
        from wdash.hub.scope import Scope
        agent, _ = self._agent()
        monitor = self._monitor(**result.pop("monitor", {}))
        self.store.results.record(agent["id"], [dict(
            {"monitor_id": monitor["id"], "started_at": _now().isoformat(),
             "status": "up"}, **result)])
        source = store_monitors.StoreMonitorSource(self.store)
        page = source.monitors(TimeWindow.of("1h"), Scope(containers=("*",)))
        return page.monitors[0]

    CERTIFICATE = {"common_name": "payments.internal",
                   "not_after": "2027-01-01T00:00:00+00:00"}

    def test_an_unverified_run_says_so(self):
        monitor = self._reported({"tls": dict(self.CERTIFICATE),
                                  "handshake_verified": False})
        self.assertIs(monitor.certificate.verified, False)

    def test_a_verified_run_says_so(self):
        monitor = self._reported({"tls": dict(self.CERTIFICATE),
                                  "handshake_verified": True})
        self.assertIs(monitor.certificate.verified, True)

    def test_a_result_written_before_the_column_existed_says_nothing(self):
        """None, not False. Every row written before this change carries no
        verdict, and an unknown must never render as a finding."""
        monitor = self._reported({"tls": dict(self.CERTIFICATE)})
        self.assertIsNone(monitor.certificate.verified)

    def test_the_mode_comes_from_the_definition_not_the_result(self):
        """So a check whose certificate could not be read — the branch-office
        agent behind a proxy, where `_certificate` opens a raw socket while
        `requests` honours the proxy — still says on the page that it does
        not verify."""
        monitor = self._reported(
            {"monitor": {"tls": {"mode": "expiry_only"}}})
        self.assertIsNone(monitor.certificate)
        self.assertTrue(monitor.expiry_only)

    def test_a_check_that_has_never_run_still_has_a_mode(self):
        from wdash.hub.adapters import store_monitors
        from wdash.hub.query import TimeWindow
        from wdash.hub.scope import Scope
        self._monitor(tls={"mode": "expiry_only"})
        source = store_monitors.StoreMonitorSource(self.store)
        page = source.monitors(TimeWindow.of("1h"), Scope(containers=("*",)))
        self.assertEqual(page.monitors[0].status, UNKNOWN)
        self.assertTrue(page.monitors[0].expiry_only)

    def test_an_agent_that_claims_a_verdict_in_words_is_not_believed(self):
        """Everything on the ingest endpoint is a claim, so only a real
        boolean is kept."""
        monitor = self._reported({"tls": dict(self.CERTIFICATE),
                                  "handshake_verified": "yes"})
        self.assertIsNone(monitor.certificate.verified)

    def test_a_stored_verdict_that_is_not_a_boolean_reads_as_nothing(self):
        """The same guard one layer down, where a row written straight into
        the database arrives. `bool("yes")` is the reading that turns a
        claim nobody checked into a reassurance on the page."""
        from wdash.hub.adapters.store_monitors import _certificate
        self.assertIsNone(_certificate({"common_name": "x"}, "yes").verified)
        self.assertIs(_certificate({"common_name": "x"}, True).verified, True)


class TlsFormTest(unittest.TestCase):
    """The check form: two settings, one escape hatch, and an audited refusal.

    The escape hatch is not optional. Measured before it: a stored credential
    cannot be removed at all — `update` replaces `secrets` only when
    something new is supplied — so a refusal without it would leave the
    administrator deleting the check and building it again.
    """

    def setUp(self):
        import tempfile as _tempfile

        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        handle, self.database = _tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "tls-form"
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
        self.scratch = tempfile.mkdtemp()
        self.pem = _certificates(self.scratch)["ca_pem"]

    def tearDown(self):
        import shutil
        self.app.store.engine.dispose()
        shutil.rmtree(self.scratch, ignore_errors=True)
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def _save(self, **extra):
        data = {"name": "Payments", "kind": "http",
                "target": "https://payments.internal/health",
                "interval_seconds": "60", "timeout_seconds": "10",
                "enabled": "on"}
        data.update(extra)
        return self.client.post("/admin/monitors", data=data,
                                follow_redirects=True)

    def _monitor(self):
        return self.app.store.monitors.all()[0]

    def test_a_pasted_certificate_is_saved_and_shown_on_the_table(self):
        page = self._save(tls_mode="verify", tls_certificate=self.pem,
                          tls_expected_name="payments.internal")
        monitor = self._monitor()
        self.assertIn("BEGIN CERTIFICATE", monitor["tls"]["certificate"])
        self.assertEqual(monitor["tls"]["expected_name"], "payments.internal")
        self.assertIn(">own certificate</span>", page.get_data(as_text=True))

    def test_waiving_verification_is_shown_on_the_table(self):
        page = self._save(tls_mode="expiry_only")
        self.assertEqual(self._monitor()["tls"]["mode"], "expiry_only")
        # The markup, not the phrase: the modal's own radio says "expiry
        # only" on every render of this page, so a looser assertion passes
        # with the badge deleted.
        self.assertIn(">expiry only</span>", page.get_data(as_text=True))

    def test_a_check_that_sends_a_header_cannot_waive_it_and_is_audited(self):
        """The header is in the PLAIN box, so nothing about it is in
        `secrets` and `has_credentials` is False — and it would still go out,
        over the channel this setting stops verifying."""
        self._save()
        monitor_id = self._monitor()["id"]
        page = self._save(id=monitor_id, tls_mode="expiry_only",
                          request_headers="X-Tenant-Token: abc123")
        body = page.get_data(as_text=True)
        self.assertIn("X-Tenant-Token", body)
        self.assertIn("Forget what this check sends", body)
        self.assertEqual(self.app.store.monitors.get(monitor_id)["tls"], {})

        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertIn("monitor save refused", actions)

    def test_forgetting_and_waiving_in_one_submission_saves_both(self):
        self._save(request_headers="X-Tenant-Token: abc123",
                   auth_type="basic", auth_username="svc",
                   auth_password="P4SS")
        monitor_id = self._monitor()["id"]
        self.assertTrue(self.app.store.monitors.get(monitor_id)
                        ["has_credentials"])

        self._save(id=monitor_id, tls_mode="expiry_only",
                   forget_request="on",
                   request_headers="X-Tenant-Token: abc123",
                   auth_type="basic", auth_username="svc")
        saved = self.app.store.monitors.get(monitor_id)
        self.assertEqual(saved["tls"]["mode"], "expiry_only")
        self.assertEqual(saved["request"], {})
        self.assertFalse(saved["has_credentials"])
        self.assertEqual(self.app.store.monitors.credentials(monitor_id), {})

    def test_a_certificate_is_not_carried_to_a_new_host_and_the_page_says_so(self):
        self._save(tls_mode="verify", tls_certificate=self.pem,
                   tls_expected_name="payments.internal")
        monitor_id = self._monitor()["id"]
        page = self._save(id=monitor_id, target="https://billing.internal/x",
                          tls_mode="verify", tls_certificate=self.pem,
                          tls_expected_name="payments.internal")
        self.assertEqual(self.app.store.monitors.get(monitor_id)["tls"], {})
        self.assertIn("was not carried", page.get_data(as_text=True))

    def test_a_refusal_says_what_is_wrong_rather_than_500(self):
        page = self._save(tls_mode="verify", tls_certificate="not a pem")
        self.assertEqual(page.status_code, 200)
        self.assertIn("BEGIN CERTIFICATE", page.get_data(as_text=True))
        self.assertEqual(self.app.store.monitors.all(), [])
