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
        self.assertIn(b"is not a role", response.data)


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
