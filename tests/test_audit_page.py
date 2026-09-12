"""
The audit trail, and the screen that shows it.

Logging already said that a change happened. What it could not answer is "what
could this role see last Tuesday" — the question that comes up exactly once,
after something has gone wrong, by which time the log has rotated and the
current state is the only state anybody can see.

The rule that runs through all of it: the trail is read-only from the
application. An administrator being audited must not be able to prune the
screen they are being audited on.
"""

import datetime as dt
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

PASSWORD = "correct-horse-battery"


class AuditTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "audit"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key
            OIDC_CLIENT_ID = None

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.secret = support.set_up(
            self.client, username="owner", password=PASSWORD)
    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def demote(self):
        self.app.store.roles.upsert("admin", permissions=["logs:read"],
                                    containers=["*"], trace_containers=["*"])
        self.app.store.rbac.invalidate()

    def save_role(self, name="auditor", **overrides):
        form = {"name": name, "permissions": "logs:read",
                "containers": "audit-*", "trace_containers": "",
                "services": "", "groups": ""}
        form.update(overrides)
        return self.client.post("/admin/roles", data=form, follow_redirects=True)


class AccessTest(AuditTestCase):
    def test_an_administrator_can_read_the_trail(self):
        self.assertEqual(self.client.get("/admin/audit").status_code, 200)

    def test_everybody_else_cannot(self):
        """The trail names who changed what and from where. It is not a
        report for the people it is about."""
        self.demote()
        response = self.client.get("/admin/audit", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("/admin/audit", response.headers["Location"])

    def test_the_export_is_gated_the_same_way(self):
        """A page that refuses and a download that does not is not a boundary."""
        self.demote()
        response = self.client.get("/admin/audit/export", follow_redirects=False)
        self.assertEqual(response.status_code, 302)


class ContentTest(AuditTestCase):
    def test_each_sign_in_outcome_is_shown_as_itself(self):
        """Everything but a success or a lockout showed as "failure": an
        outage read as a burst of guesses that never locked, and a provider
        refused under a local name as a mistyped password."""
        from wdash.store.signin import REFUSED, UNAVAILABLE
        self.app.store.signin.record("alice", "10.0.0.1", UNAVAILABLE)
        self.app.store.signin.record("owner", "10.0.0.2", REFUSED)
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn(">directory unavailable</span>", body)
        self.assertIn(">refused</span>", body)
        self.assertNotIn(">failure</span>", body)

    def test_a_configuration_change_reaches_the_trail(self):
        self.save_role()
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn("role saved", body)
        self.assertIn("role:auditor", body)

    def test_a_refused_change_reaches_it_too(self):
        """The more interesting row: an attempt to grant somebody
        administration that did not happen."""
        self.save_role(name="admin", permissions="logs:read")
        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertIn("role save refused", actions)

    def test_the_resulting_state_is_stored_not_a_diff(self):
        """One row answers "what was it then" without replaying history."""
        self.save_role()
        row = next(entry for entry in self.app.store.audit.recent()
                   if entry["action"] == "role saved")
        self.assertEqual(row["state"]["containers"], ["audit-*"])

    def test_the_actor_address_is_recorded(self):
        """"Everything from this address" is a question asked during an
        incident, and it should not need a JSON scan to answer."""
        self.client.post("/admin/roles",
                         data={"name": "auditor", "permissions": "logs:read",
                               "containers": "audit-*", "trace_containers": "",
                               "services": "", "groups": ""},
                         environ_base={"REMOTE_ADDR": "203.0.113.9"},
                         follow_redirects=True)
        row = next(entry for entry in self.app.store.audit.recent()
                   if entry["action"] == "role saved")
        self.assertEqual(row["address"], "203.0.113.9")

    def test_signing_out_is_recorded(self):
        """A trail with sign-ins and no sign-outs cannot answer whether a
        session was still open when something happened."""
        self.client.get("/auth/logout")
        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertIn("sign-out", actions)

    def test_sign_in_attempts_appear_on_the_same_screen(self):
        """Two tables, one question. An administrator chasing an incident
        should not have to know they are stored apart."""
        self.client.get("/auth/logout")
        self.client.post("/auth/login",
                         data={"username": "owner", "password": "wrong"})
        support.sign_in(self.client, "owner", PASSWORD, self.secret,
                        app=self.app)
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn("Sign-in attempts", body)
        self.assertIn("failure", body)


class ExportLinkTest(AuditTestCase):
    """The Export link passed the whole query string to url_for, and Flask
    reads `_method`, `_scheme`, `_external` and `_anchor` from it itself."""

    def test_url_for_s_own_arguments_in_the_address_are_not_its_arguments(self):
        response = self.client.get("/admin/audit?_method=POST")
        self.assertEqual(response.status_code, 200)
        page = self.client.get(
            "/admin/audit?_external=1&_scheme=https&_anchor=planted&action=x"
        ).get_data(as_text=True)
        self.assertNotIn("#planted", page)
        self.assertNotIn("https://localhost/admin/audit/export", page)
        self.assertIn("/admin/audit/export?", page)


class FilterTest(AuditTestCase):
    def setUp(self):
        super().setUp()
        self.save_role(name="one")
        self.save_role(name="two")

    def test_filtering_by_action_narrows_the_page(self):
        body = self.client.get(
            "/admin/audit?action=role+saved").get_data(as_text=True)
        self.assertIn("role:one", body)
        self.assertNotIn("sign-in</span>", body)

    def test_filtering_by_subject_narrows_it_further(self):
        body = self.client.get(
            "/admin/audit?subject=role:one").get_data(as_text=True)
        self.assertIn("role:one", body)
        self.assertNotIn("role:two", body)

    def test_an_empty_result_says_the_filters_may_be_the_reason(self):
        """Otherwise "nothing here" reads as "nothing happened"."""
        body = self.client.get(
            "/admin/audit?actor=nobody").get_data(as_text=True)
        self.assertIn("Nothing matches these filters", body)

    def test_a_time_range_is_honoured(self):
        tomorrow = (dt.datetime.now(dt.timezone.utc)
                    + dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
        body = self.client.get(
            f"/admin/audit?since={tomorrow}").get_data(as_text=True)
        self.assertNotIn("role:one", body)

    def test_unparseable_dates_filter_nothing_rather_than_everything(self):
        """A rejected date that silently became "now" would hide the whole
        trail and look like an empty period."""
        body = self.client.get(
            "/admin/audit?since=not-a-date").get_data(as_text=True)
        self.assertIn("role:one", body)

    def test_the_action_filter_offers_what_exists(self):
        """A free-text box here repeats the mistake the permission catalogue
        exists to prevent: a typo returns nothing and looks like quiet."""
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn('<option value="role saved"', body)


class PagingTest(AuditTestCase):
    def setUp(self):
        super().setUp()
        for index in range(150):
            self.app.store.audit.record("owner", "bulk", subject=f"n:{index}")

    def test_the_first_page_is_bounded(self):
        """An append-only table grows forever; rendering all of it is a way to
        take the process down from a URL."""
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertLessEqual(body.count("<td><code>"), 101)

    def test_a_second_page_shows_different_rows(self):
        first = self.client.get("/admin/audit").get_data(as_text=True)
        second = self.client.get("/admin/audit?page=1").get_data(as_text=True)
        self.assertNotEqual(first, second)
        self.assertIn("n:0", second)
        self.assertNotIn("n:0<", first)

    def test_a_negative_page_does_not_reach_the_query(self):
        self.assertEqual(self.client.get("/admin/audit?page=-5").status_code, 200)

    def test_a_nonsense_page_does_not_error(self):
        self.assertEqual(
            self.client.get("/admin/audit?page=banana").status_code, 200)


class ExportTest(AuditTestCase):
    def setUp(self):
        super().setUp()
        self.save_role()

    def test_the_export_is_json_lines(self):
        """What every log pipeline on the receiving end already reads, and a
        truncated download is still parseable up to the truncation."""
        response = self.client.get("/admin/audit/export")
        self.assertIn("ndjson", response.headers["Content-Type"])
        lines = [line for line
                 in response.get_data(as_text=True).splitlines() if line]
        self.assertTrue(lines)
        for line in lines:
            json.loads(line)

    def test_timestamps_survive_the_trip(self):
        line = json.loads(
            self.client.get("/admin/audit/export?limit=1")
            .get_data(as_text=True).splitlines()[0])
        self.assertRegex(line["at"], r"^\d{4}-\d{2}-\d{2}T")

    def test_the_filters_apply_to_the_export_too(self):
        """Otherwise "export what I am looking at" quietly exports everything."""
        body = self.client.get(
            "/admin/audit/export?action=role+saved").get_data(as_text=True)
        actions = {json.loads(line)["action"]
                   for line in body.splitlines() if line}
        self.assertEqual(actions, {"role saved"})

    def test_the_export_is_capped(self):
        for index in range(60):
            self.app.store.audit.record("owner", "bulk", subject=f"n:{index}")
        body = self.client.get(
            "/admin/audit/export?limit=999999").get_data(as_text=True)
        self.assertLessEqual(len([1 for line in body.splitlines() if line]),
                             50000)


class ATrailThatCannotBeReadIsNotAnEmptyTrailTest(AuditTestCase):
    """A lock, a statement timeout, a missing grant, a damaged table.

    Every read swallowed its error into `[]`, `0` and `[]`, so the page came
    back 200 with a "0 entries" badge and "Nothing recorded yet" twice, and
    the export streamed an empty file with a 200 on it. An administrator
    collecting evidence was handed the absence of a record nothing had looked
    for — from the one screen in this application whose entire job is to say
    what happened.
    """

    def setUp(self):
        super().setUp()
        self.save_role()
        self.app.store.signin.record("alice", "10.0.0.1", "failure")

    def hide(self, *tables):
        """Rename a table out from under the reader.

        The nearest thing to a damaged table, a revoked grant or a statement
        timeout that a test can arrange, and the failure arrives where a real
        one would: out of the driver, in the middle of a query. The store is
        a temporary database of this test's own, torn down with it, so
        nothing is put back.
        """
        from sqlalchemy import text
        for table in tables:
            with self.app.store.engine.begin() as connection:
                connection.execute(
                    text(f"ALTER TABLE {table} RENAME TO {table}_hidden"))

    def test_the_page_says_it_could_not_be_read(self):
        self.hide("wdash_audit")
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn("could not be read", body)
        self.assertNotIn("Nothing recorded yet", body)

    def test_the_badge_does_not_claim_the_trail_is_empty(self):
        self.hide("wdash_audit")
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertNotIn("0 entries", body)

    def test_the_page_still_renders_what_it_can_read(self):
        """Partial, not blank: the sign-in half is a different table and a
        different question, and losing one must not cost the other."""
        self.hide("wdash_audit")
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertEqual(self.client.get("/admin/audit").status_code, 200)
        self.assertIn("alice", body)

    def test_the_sign_in_half_reports_its_own_failure(self):
        self.hide("wdash_signin_attempts")
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn("could not be read", body)
        self.assertIn("role saved", body)

    def test_the_export_refuses_rather_than_downloading_nothing(self):
        """A zero-length wdash-audit.jsonl with a 200 on it is evidence of
        the wrong thing."""
        self.hide("wdash_audit")
        response = self.client.get("/admin/audit/export")
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"could not be read", response.data)

    def test_the_store_itself_raises_rather_than_answering_nothing(self):
        """Where the decision belongs. A read that answers `[]` has told its
        caller something that is not true, and every caller after this one
        inherits it."""
        self.hide("wdash_audit", "wdash_signin_attempts")
        with self.assertRaises(Exception):
            self.app.store.audit.recent()
        with self.assertRaises(Exception):
            self.app.store.audit.count()
        with self.assertRaises(Exception):
            self.app.store.audit.actions()
        with self.assertRaises(Exception):
            self.app.store.signin.recent()

    def test_writing_an_entry_still_never_raises(self):
        """The other half of the rule, and it did not change: losing an audit
        row is bad, refusing an administrator's repair because the audit
        table is unhappy is worse."""
        self.hide("wdash_audit", "wdash_signin_attempts")
        self.app.store.audit.record("owner", "role saved")
        self.app.store.signin.record("owner", "10.0.0.1", "failure")

    def test_the_page_shows_the_driver_s_first_line_and_not_the_statement(self):
        """SQLAlchemy's message carries the whole SELECT and its bind
        parameters — the actor, action and subject somebody filtered by —
        after the first line. It is escaped and the page is admin-only, so
        this is not a leak; it is a multi-line SQL dump inside an alert,
        where one sentence was wanted. The statement is already in the log.
        """
        self.hide("wdash_audit")
        body = self.client.get("/admin/audit?actor=alice").get_data(as_text=True)
        # What the driver says, not how it says it: SQLite answers "no such
        # table" and Postgres "relation ... does not exist", and both name
        # the table on the first line.
        self.assertIn("wdash_audit", body)
        self.assertNotIn("[SQL:", body)
        self.assertNotIn("[parameters:", body)

    def test_the_export_s_detail_is_one_line_too(self):
        self.hide("wdash_audit")
        response = self.client.get("/admin/audit/export?actor=alice")
        self.assertEqual(response.status_code, 503)
        detail = response.get_json()["detail"]
        self.assertIn("wdash_audit", detail)
        self.assertEqual(len(detail.splitlines()), 1, detail)


class AForwardingQueueThatCannotBeCountedIsNotAnEmptyQueueTest(AuditTestCase):
    """The third panel on the same screen, answering the same broken table.

    `AuditForwarder.pending` returned 0 for any exception and `sweep`
    returned 0 when the read of unforwarded rows failed, so the card said
    "0 entries waiting to be sent" and the Forward button flashed "Nothing
    was waiting." with a 200 — an administrator told the queue is drained
    when nothing could be counted or read. One card below the trail this
    commit's first half is about.
    """

    DESTINATION = {"enabled": True, "kind": "elasticsearch",
                   # A port nothing listens on, and never reached: the read
                   # of the queue fails first, which is the point.
                   "url": "http://127.0.0.1:9/", "index": "wdash-audit",
                   "verify_certs": False}

    def setUp(self):
        super().setUp()
        for number in range(3):
            self.app.store.audit.record("owner", "role saved",
                                        subject=f"role:{number}")
        self.app.store.settings.set("audit.forwarding", dict(self.DESTINATION))

    def hide(self):
        from sqlalchemy import text
        with self.app.store.engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE wdash_audit RENAME TO wdash_audit_hidden"))

    def forwarder(self):
        from wdash.store.forwarding import AuditForwarder, build_sink
        return AuditForwarder(
            self.app.store.engine,
            build_sink(dict(self.DESTINATION), "unused-token"))

    def test_a_queue_that_can_be_read_still_reports_its_depth(self):
        """The guard: the fix must not turn a countable queue into a
        warning."""
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn("waiting to be sent", body)
        self.assertNotIn("forwarding queue could not be read", body)

    def test_the_card_says_it_could_not_be_counted(self):
        self.hide()
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn("forwarding queue could not be read", body)
        self.assertNotIn("waiting to be sent", body)

    def test_the_button_does_not_report_an_empty_queue(self):
        self.hide()
        response = self.client.post("/admin/audit/forward",
                                    follow_redirects=True)
        body = response.get_data(as_text=True)
        self.assertNotIn("Nothing was waiting.", body)
        self.assertIn("could not be read", body)

    def test_counting_raises_rather_than_answering_zero(self):
        """Where the decision belongs, as with the trail itself: a count of
        0 has told its caller something that is not true."""
        self.hide()
        with self.assertRaises(Exception):
            self.forwarder().pending()

    def test_a_sweep_raises_rather_than_reporting_nothing_shipped(self):
        self.hide()
        with self.assertRaises(Exception):
            self.forwarder().sweep()
        with self.assertRaises(Exception):
            self.forwarder().drain()


class ImmutabilityTest(AuditTestCase):
    def test_the_screen_offers_no_way_to_change_the_trail(self):
        """Not a claim about the database — a claim about this application.
        A trail an administrator can prune from the screen they are audited on
        is not a trail.
        """
        body = self.client.get("/admin/audit").get_data(as_text=True)
        for word in ("audit/delete", "audit/clear", "audit/prune"):
            self.assertNotIn(word, body)

    def test_no_route_exists_to_delete_an_entry(self):
        routes = [str(rule) for rule in self.app.url_map.iter_rules()
                  if "audit" in str(rule)]
        for route in routes:
            self.assertNotIn("delete", route)
            self.assertNotIn("clear", route)


class UpgradeNoteTest(AuditTestCase):
    """The shape change has to be said where the operator is.

    `state` now reaches Elasticsearch as JSON text. An index created by an
    earlier release mapped it as an object and refuses every row that has one
    — measured against the lab cluster: document_parsing_exception, "object
    mapping for [state] tried to parse field [state] as object, but found a
    concrete value", on every sweep, with the queue never moving. Loud, but
    only to somebody who already ran it.
    """

    def test_the_forwarding_form_says_what_an_existing_index_needs(self):
        body = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn("state", body)
        self.assertIn("reindex", body)

    def test_the_readme_carries_the_upgrade_note(self):
        readme = os.path.join(os.path.dirname(__file__), "..", "README.md")
        with open(readme, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("Upgrading:", text)
        self.assertIn("mapped `state` as an object", text)


class ForwardNowTest(AuditTestCase):
    """What the button says after a batch the destination half took.

    A refused document no longer holds the whole batch — the rows the
    destination accepted are marked before the error is re-raised — but the
    page still said "nothing was marked as sent". That sends an administrator
    to look for entries that have already gone, and the number they would
    check against, the queue depth, has moved underneath them.
    """

    def setUp(self):
        super().setUp()
        from http.server import BaseHTTPRequestHandler, HTTPServer

        from tests.support import serve_in_background

        self.refuse = 1          # how many documents of each batch to refuse
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(
                    int(self.headers.get("Content-Length", 0)))
                actions = len(
                    [line for line in raw.decode().splitlines() if line]) // 2
                items, refused = [], outer.refuse
                for index in range(actions):
                    if index < refused:
                        items.append({"index": {
                            "status": 400,
                            "error": {"type": "document_parsing_exception"}}})
                    else:
                        items.append({"index": {"status": 201}})
                body = json.dumps(
                    {"errors": bool(refused), "items": items}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *arguments):
                pass

        self.server = serve_in_background(
            HTTPServer(("127.0.0.1", 0), Handler))
        self.client.post("/admin/audit/forwarding", data={
            "kind": "elasticsearch", "enabled": "on",
            "url": f"http://127.0.0.1:{self.server.server_port}",
            "index": "wdash-audit", "username": "", "credential": ""})
        for index in range(4):
            self.app.store.audit.record("owner", "role saved",
                                        subject=f"role:{index}")

    def tearDown(self):
        self.server.shutdown()
        super().tearDown()

    def _pending(self):
        from wdash.store.forwarding import AuditForwarder
        return AuditForwarder(self.app.store.engine, None).pending()

    def _forward(self):
        return self.client.post("/admin/audit/forward",
                                follow_redirects=True).get_data(as_text=True)

    def test_the_entries_it_did_take_are_reported_as_taken(self):
        before = self._pending()
        self.assertGreaterEqual(before, 3, "the setup wrote no audit rows")
        body = self._forward()
        self.assertIn("Forwarding stopped", body)
        self.assertIn(f"{before - 1:,} entries the destination did accept "
                      f"were marked as sent", body)
        self.assertNotIn("nothing was marked as sent", body)
        self.assertEqual(self._pending(), 1)

    def test_a_wholly_refused_batch_still_says_nothing_was_marked(self):
        """The other direction has to keep being true, or the sentence is
        just as useless the other way round."""
        self.refuse = 500
        before = self._pending()
        body = self._forward()
        self.assertIn("nothing was marked as sent", body)
        self.assertEqual(self._pending(), before)

    def test_one_entry_is_singular(self):
        from wdash.store.forwarding import AuditForwarder
        AuditForwarder(self.app.store.engine, None)
        with self.app.store.engine.begin() as connection:
            from sqlalchemy import update as _update

            from wdash.store.schema import audit
            connection.execute(_update(audit).values(
                forwarded_at=dt.datetime.now(dt.timezone.utc)))
        self.app.store.audit.record("owner", "kept", subject="a")
        self.app.store.audit.record("owner", "refused", subject="b")
        body = self._forward()
        self.assertIn("1 entry the destination did accept was marked as sent",
                      body)


if __name__ == "__main__":
    unittest.main()
