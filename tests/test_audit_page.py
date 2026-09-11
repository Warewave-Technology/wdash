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
        self.client.post("/setup", data={"username": "owner",
                                         "password": PASSWORD,
                                         "confirm": PASSWORD})

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
        self.client.post("/auth/login",
                         data={"username": "owner", "password": PASSWORD})
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


if __name__ == "__main__":
    unittest.main()
