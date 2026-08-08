"""
The authorization surface, end to end.

Written from an audit that probed every route with a permission-less user
rather than from reading the code. The findings it produced are the tests
below; each one names what was actually wrong.
"""

import datetime as dt
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.hub import Scope  # noqa: E402
from wdash.hub.patterns import (  # noqa: E402
    matches, matches_any, matches_for_source)

PASSWORD = "a-sufficiently-long-password"


class PatternTest(unittest.TestCase):
    """One pattern language.

    There used to be two, both called "index patterns": the scope understood a
    trailing star only, the adapter also understood leading and surrounding
    ones. `*logs*` in a role matched nothing while the same string in a source
    configuration worked. It failed closed, so it was not a hole — it was an
    administrator getting no access and no explanation.
    """

    def test_every_documented_form_works(self):
        self.assertTrue(matches("*", "anything"))
        self.assertTrue(matches("app-*", "app-logs-1"))
        self.assertTrue(matches("*-1", "app-logs-1"))
        self.assertTrue(matches("*logs*", "app-logs-1"))
        self.assertTrue(matches("app-logs-1", "app-logs-1"))

    def test_a_near_miss_does_not_match(self):
        self.assertFalse(matches("application-*", "app-logs-1"))
        self.assertFalse(matches("app-logs-2", "app-logs-1"))

    def test_an_empty_pattern_grants_nothing(self):
        self.assertFalse(matches("", "anything"))
        self.assertFalse(matches(None, "anything"))

    # --- exclusions ---

    def test_an_exclusion_beats_every_inclusion(self):
        """Order-independent, because a role is a set and not a program.

        The alternative — last match wins — makes the meaning of a grant
        depend on the order somebody happened to type it in, and the order is
        not visible in any list that displays it.
        """
        patterns = ["app-*", "-*-pii-*"]
        self.assertTrue(matches_any(patterns, "app-logs-1"))
        self.assertFalse(matches_any(patterns, "app-billing-pii-1"))
        self.assertFalse(matches_any(list(reversed(patterns)),
                                     "app-billing-pii-1"))

    def test_an_exclusion_cannot_grant_by_itself(self):
        """'-secret-*' alone is a role with no grants, not a role with all."""
        self.assertFalse(matches_any(["-secret-*"], "app-logs-1"))

    def test_a_bare_dash_is_a_name_and_not_a_denial(self):
        self.assertTrue(matches_any(["-"], "-"))

    def test_an_exclusion_applies_across_the_wildcard(self):
        patterns = ["*", "-bad-*"]
        self.assertTrue(matches_any(patterns, "app-logs-1"))
        self.assertFalse(matches_any(patterns, "bad-logs-1"))

    def test_an_exclusion_can_be_scoped_to_one_source(self):
        """The same container name in two stores is two different things."""
        patterns = ["*", "-primary:secret-*"]
        self.assertFalse(matches_for_source(patterns, "secret-1", "primary"))
        self.assertTrue(matches_for_source(patterns, "secret-1", "secondary"))

    def test_a_source_scoped_exclusion_does_not_leak_when_unqualified(self):
        """Asked without a source, a source-specific rule must not apply."""
        self.assertTrue(matches_for_source(["*", "-primary:secret-*"],
                                           "secret-1", None))

    def test_there_is_exactly_one_pattern_implementation(self):
        """A second one is not a duplicate, it is a second answer.

        `User` carried its own `_matches_any` — trailing wildcards only, no
        exclusions — left over from the authorization path that predated
        `Scope`. Nothing called it, which is worse rather than better: dead
        code shaped like an access check is what somebody reaches for next.
        """
        import os
        import re

        root = os.path.join(os.path.dirname(__file__), "..", "src", "wdash")
        offenders = []
        for directory, _, files in os.walk(root):
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                # patterns.py is the implementation. query_language.py detects
                # a trailing star to build a PREFIX QUERY — that is search
                # syntax, a different thing that happens to share a character.
                if filename in ("patterns.py", "query_language.py"):
                    continue
                path = os.path.join(directory, filename)
                with open(path, encoding="utf-8") as handle:
                    body = handle.read()
                # The tell-tale of a hand-rolled matcher.
                if re.search(r"endswith\(['\"]\*['\"]\)", body):
                    offenders.append(os.path.relpath(path, root))

        self.assertEqual(offenders, [],
                         f"pattern matching outside hub/patterns.py: {offenders}")

    def test_the_scope_and_the_adapter_now_agree(self):
        from wdash.hub.adapters.elasticsearch import _pattern_matches
        for pattern in ("*", "app-*", "*-1", "*logs*", "exact"):
            self.assertEqual(
                Scope(containers=(pattern,)).allows_container("app-logs-1"),
                _pattern_matches(pattern, "app-logs-1"),
                f"{pattern} still means two different things")


class SourceQualifiedGrantTest(unittest.TestCase):
    """A bare pattern applies to every source; qualifying is opt-in.

    Without qualification, adding a source silently widens what existing roles
    can reach — which is the behaviour, documented, and now avoidable.
    """

    SCOPE = Scope(containers=("app-*", "es-logs:secret-*"))

    def test_a_bare_pattern_applies_everywhere(self):
        self.assertTrue(self.SCOPE.allows_container("app-1", "es-logs"))
        self.assertTrue(self.SCOPE.allows_container("app-1", "loki"))

    def test_a_qualified_pattern_applies_to_its_source_only(self):
        self.assertTrue(self.SCOPE.allows_container("secret-1", "es-logs"))
        self.assertFalse(self.SCOPE.allows_container("secret-1", "loki"))

    def test_an_unknown_source_does_not_satisfy_a_qualified_pattern(self):
        """Fail closed: no source given means qualified grants do not apply."""
        self.assertFalse(self.SCOPE.allows_container("secret-1", None))

    def test_a_colon_in_a_pattern_without_a_body_is_literal(self):
        self.assertFalse(matches_for_source(("es-logs:",), "anything", "es-logs"))

    def test_resolve_passes_the_source_through(self):
        available = ["app-1", "secret-1"]
        self.assertEqual(self.SCOPE.resolve(available, source="es-logs"),
                         ["app-1", "secret-1"])
        self.assertEqual(self.SCOPE.resolve(available, source="loki"), ["app-1"])


class GateTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "authz"
            DATABASE_URL = f"sqlite:///{database}"
            OIDC_CLIENT_ID = None

        self.app = create_app(TestConfig)
        # Declared, not inherited. These tests are about AUTHORIZATION and use
        # `/api/search` as the probe; what it searches is beside the point.
        # Without this they answered from whatever was listening on port 9200,
        # which for a year was the development lab.
        from tests.support import with_stub_logs
        self.logs = with_stub_logs(self.app)
        self.client = self.app.test_client()
        self.client.post("/setup", data={
            "username": "owner", "password": PASSWORD, "confirm": PASSWORD})

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def strip_permissions(self):
        self.app.store.roles.upsert(
            "admin", permissions=["system:admin"], containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()


class EveryRouteIsGatedTest(GateTestCase):
    """The audit found two that were not."""

    def test_saved_searches_need_the_log_permission(self):
        """A saved search holds a query. Ownership was always enforced, so
        this was an inconsistency rather than a hole — but everything else
        that touches log queries is gated."""
        self.strip_permissions()
        self.assertEqual(self.client.get("/api/saved-searches").status_code, 403)
        self.assertEqual(
            self.client.post("/api/saved-searches",
                             json={"name": "x", "query": "*"}).status_code, 403)
        self.assertEqual(
            self.client.delete("/api/saved-searches/abc").status_code, 403)

    def test_the_index_list_needs_it_too(self):
        self.strip_permissions()
        self.assertEqual(self.client.get("/api/indices").status_code, 403)

    def test_they_work_again_with_the_permission(self):
        self.app.store.roles.upsert(
            "admin", permissions=["logs:read", "system:admin"],
            containers=["*"], trace_containers=["*"])
        self.app.store.rbac.invalidate()
        self.assertEqual(self.client.get("/api/saved-searches").status_code, 200)


class MergedLogPermissionTest(GateTestCase):
    """Searching is reading.

    They were separate permissions and neither resulting role was usable:
    `logs:read` alone opened a page where every search returned 403, and
    `logs:search` alone worked in the API while the page refused to load.
    """

    def grant(self, *permissions):
        self.app.store.roles.upsert(
            "admin", permissions=list(permissions), containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()

    def test_one_permission_opens_both_the_page_and_the_api(self):
        self.grant("logs:read")
        self.assertEqual(self.client.get("/logs").status_code, 200)
        self.assertEqual(self.client.get("/api/search?q=*").status_code, 200)

    def test_without_it_neither_works(self):
        self.grant("system:admin")
        self.assertEqual(self.client.get("/logs").status_code, 302)
        self.assertEqual(self.client.get("/api/search?q=*").status_code, 403)

    def test_a_role_stored_with_the_retired_name_still_searches(self):
        """An upgrade must not quietly narrow what a role could do."""
        self.grant("logs:search")
        self.assertEqual(self.client.get("/api/search?q=*").status_code, 200)


class AdminIsNotASuperuserTest(GateTestCase):
    """The single most surprising fact about this model, and the reason
    losing the last administrator role cannot be recovered from in the UI."""

    def test_administration_grants_no_data_access(self):
        self.strip_permissions()
        self.assertEqual(self.client.get("/api/search?q=*").status_code, 403)
        self.assertEqual(self.client.get("/api/traces").status_code, 403)

    def test_it_does_grant_the_configuration_page(self):
        self.strip_permissions()
        self.assertEqual(self.client.get("/admin/config").status_code, 200)


class PreviewTest(GateTestCase):
    """A role that reaches nothing is usually a typo, and it was invisible."""

    def preview(self, **body):
        return self.client.post("/admin/api/roles/preview", json=body).get_json()

    def test_a_working_pattern_lists_what_it_reaches(self):
        result = self.preview(containers=["*"], trace_containers=[])
        self.assertFalse(result["reaches_nothing"])

    def test_a_mistyped_pattern_is_called_out(self):
        result = self.preview(containers=["applicaiton-*"], trace_containers=[])
        self.assertTrue(result["reaches_nothing"])

    def test_a_blank_service_list_reads_as_unrestricted(self):
        """The form says blank means every service; the preview has to agree
        with the form or it teaches the wrong thing."""
        self.assertEqual(self.preview(containers=["*"], services=[])["services"],
                         "every service")

    def test_the_preview_needs_administration(self):
        self.app.store.roles.upsert(
            "admin", permissions=["logs:read"], containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()
        self.assertEqual(
            self.client.post("/admin/api/roles/preview", json={}).status_code,
            403)


class AuditTrailTest(GateTestCase):
    """Logging said a change happened; it could not say what a role could see
    on the day something went wrong."""

    def save_role(self, name, containers, mode="create"):
        return self.client.post("/admin/roles", data={
            "name": name, "mode": mode, "permissions": "logs:read",
            "containers": containers, "trace_containers": ""},
            follow_redirects=True)

    def test_a_saved_role_is_recorded_with_its_resulting_state(self):
        self.save_role("auditor", "audit-*")
        entries = self.app.store.audit.recent(10)
        saved = [e for e in entries if e["subject"] == "role:auditor"]
        self.assertTrue(saved)
        self.assertEqual(saved[0]["state"]["containers"], ["audit-*"])

    def test_a_refused_change_is_recorded_too(self):
        """An attempt to remove the last administrator is the more interesting
        row."""
        self.client.post("/admin/roles", data={
            "name": "admin", "mode": "edit", "permissions": "logs:read",
            "containers": "*", "trace_containers": "*"}, follow_redirects=True)
        actions = [e["action"] for e in self.app.store.audit.recent(10)]
        self.assertIn("role save refused", actions)

    def test_the_trail_answers_what_a_role_could_see_then(self):
        self.save_role("auditor", "audit-*")
        moment = dt.datetime.now(dt.timezone.utc)
        self.save_role("auditor", "*", mode="edit")

        past = self.app.store.audit.state_at("role:auditor", moment)
        self.assertEqual(past["state"]["containers"], ["audit-*"])
        self.assertEqual(self.app.store.roles.get("auditor")["containers"], ["*"])

    def test_a_datetime_in_the_state_does_not_lose_the_entry(self):
        """Role dictionaries carry `updated_at`, which no JSON encoder takes.
        Swallowing that produced a trail that recorded only refusals."""
        self.save_role("auditor", "audit-*")
        self.assertTrue(
            [e for e in self.app.store.audit.recent(10)
             if e["action"] == "role saved"],
            "a successful change produced no audit row")

    def test_recording_never_breaks_the_change_itself(self):
        original = self.app.store.audit.record

        def explode(*args, **kwargs):
            raise RuntimeError("audit table is unhappy")

        self.app.store.audit.record = explode
        try:
            self.save_role("auditor", "audit-*")
        finally:
            self.app.store.audit.record = original

        self.assertIsNotNone(self.app.store.roles.get("auditor"),
                             "a failing audit refused an administrator's change")


if __name__ == "__main__":
    unittest.main(verbosity=2)
