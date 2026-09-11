"""
The configuration screen.

Possible only because authorization moved out of the session cookie: a page
that edits roles while permissions are frozen at sign-in shows a revocation
that has not happened, which is worse than having no such page.

What these tests hold:

  * `system:admin` on every route, including the ones that only read
  * secrets are written and never rendered — a settings page that shows stored
    credentials is an exfiltration endpoint for anyone with an admin session
  * a blank credential field means "keep", not "delete"
  * a role change reaches an already-signed-in session
  * the URL a source points at is checked before the server will fetch it
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store import SecretBox  # noqa: E402
from wdash.store.sources import SourceError, validate_url  # noqa: E402

PASSWORD = "a-sufficiently-long-password"


class ConfigTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)

        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "config-page"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key
            OIDC_CLIENT_ID = None

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.client.post("/setup", data={
            "username": "owner", "password": PASSWORD, "confirm": PASSWORD})

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def demote(self):
        """Take system:admin away from the signed-in account."""
        self.app.store.roles.upsert(
            "admin", permissions=["logs:read"], containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()

    def add_source(self, **overrides):
        form = {"name": "lab", "signal": "logs", "kind": "elasticsearch",
                "url": "http://elasticsearch:9200", "verify_certs": "on",
                "enabled": "on"}
        form.update(overrides)
        return self.client.post("/admin/sources", data=form,
                                follow_redirects=True)


class AccessTest(ConfigTestCase):
    def test_the_page_needs_the_admin_permission(self):
        self.demote()
        response = self.client.get("/admin/config")
        self.assertEqual(response.status_code, 302)

    def test_every_write_route_needs_it_too(self):
        """A page guard is not a route guard."""
        self.demote()
        for path in ("/admin/sources", "/admin/auth", "/admin/roles",
                     "/admin/mappings"):
            response = self.client.post(path, data={})
            self.assertEqual(response.status_code, 302, path)

    def test_the_json_route_answers_403_rather_than_redirecting(self):
        self.demote()
        response = self.client.post("/admin/api/sources/test", json={})
        self.assertEqual(response.status_code, 403)

    def test_an_administrator_gets_the_page(self):
        response = self.client.get("/admin/config")
        self.assertEqual(response.status_code, 200)
        for section in (b"Sources", b"Authentication", b"Roles"):
            self.assertIn(section, response.data)


class SourceTest(ConfigTestCase):
    def rename(self, source, to):
        return self.client.post("/admin/sources", data={
            "id": source["id"], "name": to, "signal": "logs",
            "kind": "elasticsearch", "url": "http://elasticsearch:9200",
            "password": "", "verify_certs": "on", "enabled": "on"},
            follow_redirects=True)

    def test_a_rename_a_role_depends_on_is_refused(self):
        """Role patterns name sources, compared by exact name. Renaming
        `lab-es` made `-lab-es:secret-*` stop excluding — a role of `*` read
        `secret-*` the moment the page saved — with no preview and nothing
        in the audit row but the new name."""
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "readers", permissions=["logs:read"],
            containers=["*", "-lab-es:secret-*"], trace_containers=[])
        source = self.app.store.sources.all()[0]

        response = self.rename(source, "lab-es-2")
        # The roles table lists "readers" whatever happens; the refusal is
        # what has to say it, or the admin sees the old name and no reason.
        self.assertIn(b"would change what these roles reach: readers",
                      response.data)
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "source rename refused"]
        self.assertEqual(refused[0]["state"]["roles"], ["readers"])

    def test_a_trace_store_pattern_counts_too(self):
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=["lab-es:otel-*"])
        source = self.app.store.sources.all()[0]
        self.rename(source, "lab-es-2")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_rename_to_a_name_a_role_already_names_is_refused(self):
        """`staging:*`, left from a deleted source or written ahead of one,
        reaches nothing until a source is called `staging`. The guard asked
        only about the OLD name, so renaming a source to `staging` handed
        the role every index in it."""
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "contractor", permissions=["logs:read"],
            containers=["staging:*"], trace_containers=[])
        self.rename(self.app.store.sources.all()[0], "staging")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_blank_name_is_not_a_way_around_the_guard(self):
        """A name of spaces passes the input's `required`, stripped to "",
        skipped the guard, and was stored: a source called "" matches no
        rule, so `-lab-es:secret-*` stopped excluding."""
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "readers", permissions=["logs:read"],
            containers=["*", "-lab-es:secret-*"], trace_containers=[])
        self.rename(self.app.store.sources.all()[0], "   ")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_blank_name_is_refused_even_when_no_role_names_the_source(self):
        self.add_source(name="lab-es")
        response = self.rename(self.app.store.sources.all()[0], "   ")
        self.assertIn(b"A name is required", response.data)
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_rename_onto_another_source_s_name_is_refused_not_a_crash(self):
        """Create checked for a duplicate name; update did not, and the
        database's refusal came out as a server error."""
        self.add_source(name="lab-es")
        self.add_source(name="lab-es-2")
        first = next(s for s in self.app.store.sources.all()
                     if s["name"] == "lab-es")
        response = self.rename(first, "lab-es-2")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already exists", response.data)

    def test_a_source_name_cannot_hold_a_colon(self):
        """In a rule the colon separates a source's name from its pattern,
        so a source called `eu:prod` could not be named by one:
        `-eu:prod:secret-*` read as a rule for a source called `eu`."""
        response = self.add_source(name="eu:prod")
        self.assertIn(b"cannot contain", response.data)
        self.assertEqual(self.app.store.sources.all(), [])

    def test_nor_can_a_renamed_one(self):
        self.add_source(name="lab-es")
        response = self.rename(self.app.store.sources.all()[0], "eu:prod")
        self.assertIn(b"cannot contain", response.data)
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_source_cannot_be_created_under_a_name_rules_already_use(self):
        """A colon qualifies a rule only when a source has that name, so
        `staging:*` is a plain name today. Creating a source called
        `staging` would make it a grant of everything in it."""
        self.app.store.roles.upsert(
            "contractor", permissions=["logs:read"],
            containers=["staging:*"], trace_containers=[])
        response = self.add_source(name="staging")
        self.assertIn(b"would turn them from names into rules", response.data)
        self.assertEqual(self.app.store.sources.all(), [])
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "source creation refused"]
        self.assertEqual(refused[0]["state"]["roles"], ["contractor"])

    def test_a_service_rule_counts_for_that_too(self):
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=["*"], services=["*", "-staging:payments"])
        self.add_source(name="staging")
        self.assertEqual(self.app.store.sources.all(), [])

    def test_a_rename_nothing_depends_on_goes_through(self):
        self.add_source(name="lab-es")
        source = self.app.store.sources.all()[0]
        self.rename(source, "lab-es-2")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es-2"])

    def test_a_service_rule_naming_the_source_counts_too(self):
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=["*"], services=["*", "-lab-es:payments"])
        self.rename(self.app.store.sources.all()[0], "lab-es-2")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def _tempo(self, role_stores):
        self.add_source(name="lab-tempo", kind="tempo", signal="traces",
                        url="http://tempo:3200")
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=role_stores)
        source = self.app.store.sources.all()[0]
        self.client.post("/admin/sources", data={
            "id": source["id"], "name": "tempo-2", "signal": "traces",
            "kind": "tempo", "url": "http://tempo:3200", "password": "",
            "verify_certs": "on", "enabled": "on"}, follow_redirects=True)
        return [s["name"] for s in self.app.store.sources.all()]

    def test_a_tempo_store_excluded_by_name_cannot_be_renamed_open(self):
        """Tempo's one trace store is matched by the source's name, so
        `-lab-tempo` beside `*` stops excluding under any other name."""
        self.assertEqual(self._tempo(["*", "-lab-tempo"]), ["lab-tempo"])

    def test_a_tempo_store_granted_by_name_cannot_be_renamed_shut(self):
        self.assertEqual(self._tempo(["lab-tempo"]), ["lab-tempo"])

    def test_a_tempo_rename_the_patterns_do_not_notice_goes_through(self):
        self.assertEqual(self._tempo(["*", "-otel-*"]), ["tempo-2"])

    def test_an_elasticsearch_source_name_is_not_a_trace_store(self):
        """Its trace stores are indices; a pattern that happens to spell the
        source's name says nothing about it."""
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=["*", "-lab-es"])
        self.rename(self.app.store.sources.all()[0], "lab-es-2")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es-2"])

    def test_a_source_can_be_added(self):
        self.add_source(name="lab-es")
        names = [s["name"] for s in self.app.store.sources.all()]
        self.assertEqual(names, ["lab-es"])

    def test_the_password_is_stored_encrypted_and_never_rendered(self):
        self.add_source(name="lab-es", password="super-secret")
        page = self.client.get("/admin/config").data

        self.assertNotIn(b"super-secret", page,
                         "the stored credential was rendered into the page")
        source = self.app.store.sources.all()[0]
        self.assertTrue(source["has_secret"])
        self.assertNotIn("password", source)
        self.assertEqual(
            self.app.store.sources.credential(source["id"]), "super-secret")

    def test_a_blank_password_keeps_the_stored_one(self):
        """Blank means 'leave it alone'. Treating it as deletion means anyone
        who saves this form without retyping the password breaks the source."""
        self.add_source(name="lab-es", password="super-secret")
        source = self.app.store.sources.all()[0]

        self.client.post("/admin/sources", data={
            "id": source["id"], "name": "renamed", "signal": "logs",
            "kind": "elasticsearch", "url": "http://elasticsearch:9200",
            "password": "", "verify_certs": "on", "enabled": "on"},
            follow_redirects=True)

        self.assertEqual(
            self.app.store.sources.credential(source["id"]), "super-secret")
        self.assertEqual(self.app.store.sources.all()[0]["name"], "renamed")

    def test_the_metadata_address_is_refused(self):
        """169.254.169.254 hands out instance credentials to anything asking."""
        response = self.add_source(name="bad", url="http://169.254.169.254/")
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"link-local", response.data)

    def test_a_non_http_scheme_is_refused(self):
        response = self.add_source(name="bad", url="file:///etc/passwd")
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"http and https", response.data)

    def test_internal_addresses_stay_allowed(self):
        """Blocking them would make the feature useless: these backends are
        on internal networks essentially always."""
        for url in ("http://127.0.0.1:9200", "http://10.0.0.5:9200",
                    "http://elasticsearch:9200"):
            self.assertEqual(validate_url(url), url)

    def test_a_source_kind_cannot_serve_a_signal_it_does_not_have(self):
        response = self.add_source(name="bad", kind="loki", signal="traces",
                                   url="http://loki:3100")
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"cannot serve", response.data)

    def test_two_sources_cannot_share_a_name_and_signal(self):
        self.add_source(name="lab")
        response = self.add_source(name="lab")
        self.assertEqual(len(self.app.store.sources.all()), 1)
        self.assertIn(b"already exists", response.data)

    def test_a_source_can_be_deleted(self):
        self.add_source(name="lab")
        source = self.app.store.sources.all()[0]
        self.client.post(f"/admin/sources/{source['id']}/delete",
                         follow_redirects=True)
        self.assertEqual(self.app.store.sources.all(), [])

    def test_the_connection_test_reports_rather_than_raising(self):
        response = self.client.post("/admin/api/sources/test", json={
            "kind": "elasticsearch", "url": "http://127.0.0.1:1",
            "verify_certs": False})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["ok"])

    def test_the_connection_test_refuses_a_bad_url_before_fetching(self):
        response = self.client.post("/admin/api/sources/test", json={
            "kind": "elasticsearch", "url": "file:///etc/passwd"})
        self.assertFalse(response.get_json()["ok"])


class DeleteAsksFirstTest(ConfigTestCase):
    """The listener in config.js asks before a form with `data-confirm` is
    sent. The attribute has to be on the forms the page renders, or the
    listener binds to nothing and Delete deletes on the first click — what
    the inline onsubmit it replaced did, because the policy refuses those."""

    def test_every_delete_form_carries_its_question(self):
        import re
        self.add_source(name="lab-es")
        self.app.store.roles.upsert("auditor", permissions=["logs:read"],
                                    containers=["*"], trace_containers=[])
        page = self.client.get("/admin/config").get_data(as_text=True)
        forms = [tag for tag in re.findall(r"<form[^>]*>", page, re.S)
                 if re.search(r'action="[^"]*/delete"', tag)]
        self.assertGreaterEqual(len(forms), 2, "no delete forms rendered")
        for tag in forms:
            self.assertIn("data-confirm=", tag, tag)
        self.assertTrue(any("Delete lab-es?" in tag for tag in forms))
        self.assertTrue(any("Delete role auditor?" in tag for tag in forms))


class AuthSettingsTest(ConfigTestCase):
    def save_oidc(self, **overrides):
        form = {"provider": "oidc", "client_id": "wdash",
                "discovery_url": "https://idp/.well-known/openid-configuration",
                "redirect_uri": "https://wdash/auth/callback", "enabled": "on"}
        form.update(overrides)
        return self.client.post("/admin/auth", data=form, follow_redirects=True)

    def test_settings_are_stored(self):
        self.save_oidc()
        stored = self.app.store.settings.get("auth.oidc")
        self.assertEqual(stored["client_id"], "wdash")
        self.assertTrue(stored["enabled"])

    def test_the_client_secret_is_never_rendered(self):
        self.save_oidc(client_secret="oidc-client-secret")
        page = self.client.get("/admin/config").data
        self.assertNotIn(b"oidc-client-secret", page)
        self.assertEqual(self.app.store.settings.secret("auth.oidc"),
                         "oidc-client-secret")

    def test_a_blank_secret_keeps_the_stored_one(self):
        self.save_oidc(client_secret="oidc-client-secret")
        self.save_oidc(client_id="renamed", client_secret="")
        self.assertEqual(self.app.store.settings.secret("auth.oidc"),
                         "oidc-client-secret")
        self.assertEqual(self.app.store.settings.get("auth.oidc")["client_id"],
                         "renamed")

    def test_ldap_settings_are_separate_from_oidc(self):
        """One row per key, so saving one cannot clobber the other."""
        self.save_oidc()
        self.client.post("/admin/auth", data={
            "provider": "ldap", "server": "ldaps://ldap:636",
            "base_dn": "dc=example,dc=com"}, follow_redirects=True)

        self.assertEqual(self.app.store.settings.get("auth.oidc")["client_id"],
                         "wdash")
        self.assertEqual(self.app.store.settings.get("auth.ldap")["server"],
                         "ldaps://ldap:636")


class RoleEditingTest(ConfigTestCase):
    def setUp(self):
        super().setUp()
        # One test here probes `/api/search` to show an edit reaching a live
        # session. Declared rather than inherited from whatever is listening
        # on port 9200 — which is what it used to be.
        from tests.support import with_stub_logs
        with_stub_logs(self.app)

    def save_role(self, **overrides):
        form = {"name": "auditor", "permissions": "logs:read\ntraces:read",
                "containers": "audit-*", "trace_containers": "",
                "services": "", "groups": "auditors"}
        form.update(overrides)
        return self.client.post("/admin/roles", data=form, follow_redirects=True)

    def test_a_role_can_be_created(self):
        self.save_role()
        role = self.app.store.roles.get("auditor")
        self.assertEqual(role["permissions"], ["logs:read", "traces:read"])
        self.assertEqual(role["containers"], ["audit-*"])
        self.assertEqual(role["groups"], ["auditors"])

    def test_a_blank_services_box_means_unrestricted_not_nothing(self):
        """The one field where empty is permissive, and it says so on the form."""
        self.save_role(services="")
        self.assertIsNone(self.app.store.roles.get("auditor")["services"])

        self.save_role(services="payment-service")
        self.assertEqual(self.app.store.roles.get("auditor")["services"],
                         ["payment-service"])

    def test_a_blank_containers_box_grants_nothing(self):
        self.save_role(containers="")
        self.assertEqual(self.app.store.roles.get("auditor")["containers"], [])

    def test_an_edit_reaches_a_session_that_is_already_signed_in(self):
        """The whole reason this page can exist."""
        self.assertEqual(self.client.get("/api/search?q=*").status_code, 200)

        self.client.post("/admin/roles", data={
            "name": "admin", "permissions": "system:admin",
            "containers": "*", "trace_containers": "*",
            "services": "", "groups": ""}, follow_redirects=True)

        self.assertEqual(self.client.get("/api/search?q=*").status_code, 403)

    def test_you_cannot_delete_the_role_you_are_standing_on(self):
        """With another administrator role present, the guard that fires is
        the personal one rather than the system-wide one."""
        self.app.store.roles.upsert(
            "co-admin", permissions=["system:admin"], containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()

        response = self.client.post("/admin/roles/admin/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("admin"))
        self.assertIn(b"lock you out", response.data)

    def test_the_only_administrator_role_cannot_be_deleted(self):
        """system:admin is not a superuser, so nothing else can recover it."""
        response = self.client.post("/admin/roles/admin/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("admin"))
        self.assertIn(b"only role that can administer", response.data)

    def test_the_last_role_cannot_be_deleted(self):
        for name in ("developer", "viewer"):
            self.app.store.roles.delete(name)
        self.app.store.rbac.invalidate()
        response = self.client.post("/admin/roles/admin/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("admin"))
        self.assertIn(b"last role", response.data)


class ChangePreviewTest(ConfigTestCase):
    """The editor answers "what does this change", not just "what is this".

    An end state is easy to read and impossible to review: `app-*` and `ap-*`
    both look deliberate, produce a plausible count, and reach completely
    different sets. The delta is the sentence that catches it.
    """

    def setUp(self):
        super().setUp()
        from tests.test_fanout import StubSource
        # Replace, not add: the factory registers a source pointing at
        # ELASTICSEARCH_URL, and on a machine with a lab running it answers.
        self.app.hub.replace_all(logs=[StubSource(
            "lab", "elasticsearch",
            ["app-logs", "infra-logs", "bad-logs"], [])])
        self.client.post("/admin/roles", data={
            "name": "auditor", "permissions": "logs:read",
            "containers": "app-*", "trace_containers": "",
            "services": "", "groups": ""}, follow_redirects=True)

    def preview(self, **overrides):
        payload = {"name": "auditor", "permissions": ["logs:read"],
                   "containers": ["app-*"], "trace_containers": [],
                   "services": []}
        payload.update(overrides)
        return self.client.post("/admin/api/roles/preview",
                                json=payload).get_json()["change"]

    def test_a_colon_that_names_no_source_is_pointed_out(self):
        """It is right when that is the name and a typo when a source was
        meant; only the person writing it knows which."""
        result = self.client.post("/admin/api/roles/preview", json={
            "name": "auditor", "permissions": ["logs:read"],
            "containers": ["staging:*", "lab:app-*"],
            "trace_containers": [], "services": ["unknown_service:java"],
        }).get_json()
        said = " ".join(result["warnings"])
        self.assertIn("no source is called 'staging'", said)
        self.assertIn("no source is called 'unknown_service'", said)
        self.assertNotIn("'lab'", said)

    def test_a_new_role_has_nothing_to_compare_against(self):
        self.assertIsNone(self.preview(name="brand-new"))

    def test_an_unchanged_role_reports_no_change(self):
        change = self.preview()
        self.assertEqual(change["logs_added"], [])
        self.assertEqual(change["logs_removed"], [])
        self.assertFalse(change["widens"])

    def test_a_typo_shows_up_as_a_loss_rather_than_a_count(self):
        change = self.preview(containers=["ap-*"])
        self.assertEqual(change["logs_removed"], ["app-logs"])
        self.assertEqual(change["logs_added"], [])
        self.assertFalse(change["widens"])

    def test_widening_is_called_widening(self):
        change = self.preview(containers=["*"])
        self.assertEqual(change["logs_added"], ["bad-logs", "infra-logs"])
        self.assertTrue(change["widens"])

    def test_an_exclusion_is_reflected_in_what_is_granted(self):
        change = self.preview(containers=["*", "-bad-*"])
        self.assertNotIn("bad-logs", change["logs_added"])
        self.assertIn("infra-logs", change["logs_added"])

    def test_a_new_permission_widens_even_with_identical_containers(self):
        """Access is not only about where; system:admin reaches everything."""
        change = self.preview(permissions=["logs:read", "system:admin"])
        self.assertEqual(change["permissions_added"], ["system:admin"])
        self.assertEqual(change["logs_added"], [])
        self.assertTrue(change["widens"])

    def test_removing_a_permission_does_not_widen(self):
        change = self.preview(permissions=[])
        self.assertEqual(change["permissions_removed"], ["logs:read"])
        self.assertFalse(change["widens"])

    def test_clearing_the_services_box_widens(self):
        """Blank is every service — the widest value that box holds — and the
        diff left services out, so this edit showed no change at all."""
        self.client.post("/admin/roles", data={
            "name": "auditor", "permissions": "logs:read",
            "containers": "app-*", "trace_containers": "",
            "services": "payment-service", "groups": ""}, follow_redirects=True)
        change = self.preview(services=[])
        self.assertEqual(change["services_added"], ["every service"])
        self.assertTrue(change["widens"])

    def test_restricting_services_narrows(self):
        change = self.preview(services=["payment-service"])
        self.assertEqual(change["services_removed"], ["every service"])
        self.assertEqual(change["services_added"], [])
        self.assertFalse(change["widens"])

    def _with_services(self, services):
        self.client.post("/admin/roles", data={
            "name": "auditor", "permissions": "logs:read",
            "containers": "app-*", "trace_containers": "",
            "services": "\n".join(services), "groups": ""},
            follow_redirects=True)

    def test_taking_an_exclusion_off_widens(self):
        """As strings, `-payments` leaving a role of `*` was "removes
        services" and "narrows access" — on the edit that makes payments
        visible."""
        self._with_services(["*", "-payments"])
        change = self.preview(services=["*"])
        self.assertEqual(change["exclusions_removed"], ["-payments"])
        self.assertEqual(change["services_removed"], [])
        self.assertTrue(change["widens"])

    def test_putting_an_exclusion_on_narrows(self):
        """…and adding it was "grants services" and "widens"."""
        self._with_services(["*"])
        change = self.preview(services=["*", "-payments"])
        self.assertEqual(change["exclusions_added"], ["-payments"])
        self.assertEqual(change["services_added"], [])
        self.assertFalse(change["widens"])

    def test_an_exclusion_is_one_with_the_marker_after_the_qualifier_too(self):
        self._with_services(["*", "lab:-payments"])
        change = self.preview(services=["*"])
        self.assertEqual(change["exclusions_removed"], ["lab:-payments"])
        self.assertTrue(change["widens"])

    def test_a_marker_after_a_colon_that_names_no_source_is_a_name(self):
        """`x:-y` with no source called x is the name "x:-y": taking it off
        removes a grant, not an exclusion."""
        self._with_services(["*", "x:-y"])
        change = self.preview(services=["*"])
        self.assertEqual(change["services_removed"], ["x:-y"])
        self.assertEqual(change["exclusions_removed"], [])

    def test_adding_a_group_widens(self):
        """A group is who gets the role: adding one hands everything it
        reaches to a whole directory group."""
        change = self.preview(groups=["contractors"])
        self.assertEqual(change["groups_added"], ["contractors"])
        self.assertTrue(change["widens"])


class MappingTest(ConfigTestCase):
    def test_mappings_are_parsed_and_stored(self):
        self.client.post("/admin/mappings", data={
            "default_role": "viewer",
            "user_roles": "alice@example.com = admin\nbob = viewer"},
            follow_redirects=True)
        self.assertEqual(self.app.store.settings.get("rbac.user_roles"),
                         {"alice@example.com": "admin", "bob": "viewer"})

    def test_a_mapping_to_a_role_that_does_not_exist_is_reported(self):
        """Silently dropping one is silently changing somebody's access."""
        response = self.client.post("/admin/mappings", data={
            "default_role": "viewer",
            "user_roles": "alice@example.com = nonexistent"},
            follow_redirects=True)
        self.assertEqual(self.app.store.settings.get("rbac.user_roles"), {})
        self.assertIn(b"not understood", response.data)

    def test_an_unparseable_line_is_reported(self):
        response = self.client.post("/admin/mappings", data={
            "default_role": "viewer", "user_roles": "this is not a mapping"},
            follow_redirects=True)
        self.assertIn(b"not understood", response.data)

    def test_a_default_role_that_does_not_exist_is_refused(self):
        response = self.client.post("/admin/mappings", data={
            "default_role": "nonexistent", "user_roles": ""},
            follow_redirects=True)
        self.assertIn(b"no longer exists", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.default_role"),
                         "viewer")

    def test_a_blank_default_is_refused_rather_than_replaced(self):
        """It used to be saved as "viewer" — whether or not a role of that
        name existed. The default only ever changes to something chosen."""
        self.app.store.settings.set("rbac.default_role", "developer")
        response = self.client.post("/admin/mappings", data={
            "default_role": "", "user_roles": ""}, follow_redirects=True)
        self.assertIn(b"Choose a default role", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.default_role"),
                         "developer")

    def test_a_default_that_no_longer_exists_is_not_shown_as_the_first_role(
            self):
        """With no option selected the browser selects the FIRST one — `admin`
        — and the next "Save mappings" made everybody unmapped an
        administrator. Measured on the rendered page, where the browser
        decides."""
        self.app.store.settings.set("rbac.default_role", "auditor")
        page = self.client.get("/admin/config").get_data(as_text=True)
        select = page.split('id="defaultRole"', 1)[1].split("</select>", 1)[0]
        selected = [option for option in select.split("<option")[1:]
                    if " selected" in option.split(">", 1)[0]]
        self.assertEqual(len(selected), 1, select)
        self.assertIn('value="auditor"', selected[0])
        self.assertIn("no longer exists", selected[0])

        # And what the browser would therefore submit is refused, by name.
        # Asserted on what only a refusal produces: the page re-renders the
        # missing default with "no longer exists" either way, and the stored
        # value was already "auditor".
        response = self.client.post("/admin/mappings", data={
            "default_role": "auditor", "user_roles": ""}, follow_redirects=True)
        self.assertIn(b"The default role &#39;auditor&#39; no longer exists",
                      response.data)
        self.assertNotIn(b"Role mappings saved", response.data)
        self.assertNotIn("mappings updated", [
            row["action"] for row in self.app.store.audit.recent()])


class RoleDependentsTest(ConfigTestCase):
    """A role something still points at stays until it points elsewhere.

    Deleting a role never asked who depended on it. The page then offered
    its first role — `admin` — in every select that had pointed at the one
    deleted, so the next "Save mappings" handed out administration: to the
    people mapped to it, or, for the default role, to everybody unmapped.
    """

    def test_the_default_role_cannot_be_deleted(self):
        response = self.client.post("/admin/roles/viewer/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("viewer"))
        self.assertIn(b"is the default role", response.data)

    def test_a_role_a_mapping_names_cannot_be_deleted(self):
        self.app.store.settings.set("rbac.user_roles",
                                    {"alice@example.com": "developer"})
        response = self.client.post("/admin/roles/developer/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("developer"))
        # The page embeds the stored mappings whatever happened, so the
        # identifier is read from the refusal itself.
        self.assertIn(b"These mappings still give", response.data)
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "role delete refused"]
        self.assertIn("alice@example.com", refused[0]["state"]["reason"])

    def test_a_role_a_local_account_holds_cannot_be_deleted(self):
        """Its stored role is what makes a local account the way back in."""
        self.app.store.roles.upsert(
            "co-admin", permissions=["system:admin"], containers=["*"],
            trace_containers=["*"])
        self.app.store.users.create("breakglass", PASSWORD, role="co-admin")
        self.app.store.rbac.invalidate()
        response = self.client.post("/admin/roles/co-admin/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("co-admin"))
        self.assertIn(b"breakglass", response.data)

    def test_a_role_nothing_points_at_can_go(self):
        response = self.client.post("/admin/roles/developer/delete",
                                    follow_redirects=True)
        self.assertIsNone(self.app.store.roles.get("developer"))
        self.assertIn(b"deleted", response.data)

    def test_a_refused_deletion_is_recorded(self):
        """README and SECURITY both say refused attempts sit beside the
        successful ones; for deletions they did not."""
        self.client.post("/admin/roles/viewer/delete")
        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertIn("role delete refused", actions)


class DirectoryAdministratorTest(ConfigTestCase):
    """An administrator who is one because a directory group says so.

    Every other test here signs in as the local `owner`, whose stored role
    comes first in the resolver's order — so nothing these routes now pass
    the invariants (email, groups, mappings, the default) could change an
    answer. These sign in the way an OIDC or LDAP administrator does.
    """

    def setUp(self):
        super().setUp()
        admin = self.app.store.roles.get("admin")
        self.assertIn("wdash-admins", admin["groups"])  # seeded by rbac.yaml
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "directory-1", "email": "alice@example.com",
                "username": "alice", "groups": ["wdash-admins"],
                "local_role": None}
            session["_user_id"] = "directory-1"
        self.app.store.rbac.invalidate()
        self.assertEqual(self.client.get("/admin/config").status_code, 200,
                         "alice should reach the page through her group")

    def test_changing_the_default_role_is_allowed(self):
        """Refused before: the old rule never looked at groups, decided she
        would land on the new default, and blocked a harmless edit."""
        response = self.client.post("/admin/mappings", data={
            "default_role": "developer", "user_roles": ""},
            follow_redirects=True)
        self.assertIn(b"Role mappings saved", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.default_role"),
                         "developer")

    def test_mapping_her_email_below_her_username_is_refused(self):
        """The resolver reads the email first. The old rule read the username
        first, saw admin, and saved a change that demoted her on the next
        request."""
        response = self.client.post("/admin/mappings", data={
            "default_role": "viewer",
            "user_roles": "alice@example.com = viewer\nalice = admin"},
            follow_redirects=True)
        self.assertIn(b"lose access", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.user_roles") or {},
                         {})

        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "mappings save refused"]
        self.assertEqual(len(refused), 1, "the refusal was not recorded")
        self.assertIn("lose access", refused[0]["state"]["reason"])

    def test_taking_her_group_off_the_admin_role_is_refused(self):
        admin = self.app.store.roles.get("admin")
        response = self.client.post("/admin/roles", data={
            "name": "admin", "permissions": "\n".join(admin["permissions"]),
            "containers": "\n".join(admin["containers"] or []),
            "trace_containers": "\n".join(admin["trace_containers"] or []),
            "services": "", "groups": ""}, follow_redirects=True)
        self.assertIn(b"lock you out", response.data)
        self.assertIn("wdash-admins", self.app.store.roles.get("admin")["groups"])


class SecretsUnavailableTest(unittest.TestCase):
    """With no encryption key, the page works but refuses to store secrets."""

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "no-key"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = None
            OIDC_CLIENT_ID = None

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.client.post("/setup", data={
            "username": "owner", "password": PASSWORD, "confirm": PASSWORD})

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def test_the_page_says_so_rather_than_failing_quietly(self):
        page = self.client.get("/admin/config").data
        self.assertIn(b"WDASH_ENCRYPTION_KEY", page)

    def test_storing_a_secret_is_refused_not_written_as_plaintext(self):
        response = self.client.post("/admin/auth", data={
            "provider": "oidc", "client_id": "wdash",
            "client_secret": "would-be-plaintext"}, follow_redirects=True)
        self.assertIn(b"not set", response.data)
        self.assertIsNone(self.app.store.settings.get("auth.oidc"))

    def test_settings_without_secrets_still_save(self):
        self.client.post("/admin/roles", data={
            "name": "auditor", "permissions": "logs:read",
            "containers": "audit-*", "trace_containers": "",
            "services": "", "groups": ""}, follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("auditor"))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class DuplicateSourceTest(ConfigTestCase):
    """The environment Elasticsearch and a configured one, on one cluster.

    Both register. Every matching log line is then counted twice in a merged
    search, and nothing says so — the totals simply look bigger, which is the
    hardest kind of wrong to notice.
    """

    def setUp(self):
        super().setUp()
        self.app.config["ELASTICSEARCH_URL"] = "http://cluster:9200"

    def _detect(self):
        from wdash.app import _same_backend_twice
        return _same_backend_twice(self.app, self.app.store)

    def _add(self, url, kind="elasticsearch", name="mirror"):
        return self.app.store.sources.create(
            name=name, signal=["logs"], kind=kind,
            config={"url": url, "verify_certs": False})

    def test_the_same_cluster_twice_is_reported(self):
        self._add("http://cluster:9200")
        warnings = self._detect()
        self.assertEqual(len(warnings), 1)
        self.assertIn("mirror", warnings[0])
        self.assertIn("twice", warnings[0])

    def test_a_trailing_slash_on_the_source_is_still_the_same_cluster(self):
        """`http://cluster:9200/` and `http://cluster:9200` are one system,
        and a check that misses that reports nothing on the commonest way of
        typing it."""
        self._add("http://cluster:9200/")
        self.assertEqual(len(self._detect()), 1)

    def test_a_trailing_slash_on_the_environment_url_is_too(self):
        """The other side of the same comparison. Normalising only the stored
        url passes the test above and still misses this, which is the half an
        operator is more likely to type — it is copied out of a browser."""
        self.app.config["ELASTICSEARCH_URL"] = "http://cluster:9200/"
        self._add("http://cluster:9200")
        self.assertEqual(len(self._detect()), 1)

    def test_a_different_cluster_is_not_reported(self):
        self._add("http://other:9200")
        self.assertEqual(self._detect(), [])

    def test_another_backend_at_the_same_host_is_not_reported(self):
        """Loki on the same address is a different system, not a duplicate."""
        self._add("http://cluster:9200", kind="loki", name="loki")
        self.assertEqual(self._detect(), [])

    def test_no_environment_cluster_means_nothing_to_clash_with(self):
        self.app.config["ELASTICSEARCH_URL"] = ""
        self._add("http://cluster:9200")
        self.assertEqual(self._detect(), [])

    def test_a_stored_source_can_never_have_an_empty_url(self):
        """Why the empty-url guard above is a short circuit and not a check.

        If a source could be stored without one, an unset ELASTICSEARCH_URL
        would match it and every such source would be reported as a duplicate
        of nothing.
        """
        from wdash.store.sources import SourceError
        with self.assertRaises(SourceError):
            self._add("", name="empty")

    def test_a_disabled_source_is_not_a_duplicate(self):
        """It registers nowhere, so it cannot double-count anything."""
        row = self._add("http://cluster:9200")
        self.app.store.sources.update(row["id"], enabled=False)
        self.assertEqual(self._detect(), [])

    def test_the_warning_reaches_the_configuration_page(self):
        """A warning in a log file is a warning nobody reads, and the symptom
        never points at its cause."""
        self._add("http://cluster:9200")
        self.app.duplicate_sources = self._detect()
        body = self.client.get("/admin/config").get_data(as_text=True)
        self.assertIn("Two sources, one system", body)
        # Not the source name: it is already in the sources table below, so
        # asserting it here passes even when the warning body is dropped.
        # This sentence exists nowhere else on the page.
        self.assertIn("counts every matching record twice", body)


class SignalFormTest(ConfigTestCase):
    """The form has to offer every signal the catalogue declares.

    `signal_map` was derived from SOURCE_KINDS with a comment saying a copy in
    JavaScript would give the product two answers to one question. The
    checkboxes beside it were hand-written — two of them — so adding
    `monitors` to the catalogue produced a page that knew about a signal and
    could not offer it. The Monitors screen then said "no monitor source is
    configured", which was true and unfixable from the configuration page.
    """

    def _page(self):
        return self.client.get("/admin/config").get_data(as_text=True)

    def test_every_declared_signal_has_a_checkbox(self):
        from wdash.store.sources import SOURCE_KINDS
        body = self._page()
        declared = {signal for kind in SOURCE_KINDS.values()
                    for signal in kind["signals"]}
        missing = sorted(s for s in declared
                         if f'data-signal="{s}"' not in body)
        self.assertEqual(missing, [], f"no checkbox for: {missing}")

    def test_the_map_the_form_reads_matches_the_catalogue(self):
        from wdash.store.sources import SOURCE_KINDS
        import json
        import re
        body = self._page()
        match = re.search(r'id="sourceSignals"[^>]*>\s*(\{.*?\})\s*</script>',
                          body, re.S)
        self.assertIsNotNone(match, "the page ships no signal map")
        served = json.loads(match.group(1))
        self.assertEqual(
            served, {k: list(v["signals"]) for k, v in SOURCE_KINDS.items()})

    def test_a_signal_with_per_signal_fields_has_somewhere_to_put_them(self):
        """A signal that can be ticked but has no index-pattern box saves a
        source pointing at whatever the default is, with no way to say
        otherwise."""
        body = self._page()
        for signal in ("logs", "traces", "monitors"):
            self.assertIn(f'data-needs="{signal}"', body,
                          f"{signal} can be ticked with nowhere to configure it")

    def test_a_source_can_be_saved_serving_all_three(self):
        response = self.client.post("/admin/sources", data={
            "name": "cluster", "kind": "elasticsearch",
            "signals": ["logs", "traces", "monitors"],
            "url": "http://cluster:9200", "enabled": "on",
            "logs_index_patterns": "app-*",
            "traces_index_patterns": "*apm*",
            "monitors_index_patterns": "heartbeat-*",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        row = next(r for r in self.app.store.sources.all()
                   if r["name"] == "cluster")
        self.assertEqual(row["signals"], ["logs", "traces", "monitors"])
        self.assertEqual(row["config"]["monitors"]["index_patterns"],
                         ["heartbeat-*"])

    def test_saving_it_registers_a_monitor_adapter(self):
        """Stored and unreachable is worse than absent: the configuration page
        says it is there."""
        from wdash.hub import Hub
        from wdash.hub.factory import register_configured_sources

        self.client.post("/admin/sources", data={
            "name": "cluster", "kind": "elasticsearch",
            "signals": ["logs", "monitors"],
            "url": "http://cluster:9200", "enabled": "on",
            "logs_index_patterns": "app-*",
            "monitors_index_patterns": "",
        }, follow_redirects=True)

        hub = Hub()
        register_configured_sources(hub, self.app.store)
        self.assertEqual([s.name for s in hub.monitor_sources], ["cluster"])
        # Left empty, it must fall back to Heartbeat's own names rather than
        # to `*`, which would read every index in the cluster to find nothing.
        self.assertEqual(hub.monitor_sources[0]._patterns,
                         ("heartbeat-*", "synthetics-*"))
