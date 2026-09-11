"""
Identity provider settings, and whether they are actually in force.

Storing a setting is not the same as applying one. These tests hold the rule
that decides which of two sources wins, and the two mistakes that rule exists
to prevent:

  * the environment overriding the config page, so an administrator saves a
    change and nothing happens
  * a provider switched off still being offered, because its settings are
    still filled in and something fell back to the environment

They also cover the LDAP bind, where the classic bug is treating a successful
*search* as a successful *authentication* — which is a complete bypass that
looks like working code.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.auth.ldap_auth import escape_filter  # noqa: E402
from wdash.auth.providers import ldap_settings, oidc_settings  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store import SecretBox  # noqa: E402

PASSWORD = "a-sufficiently-long-password"


def make_app(oidc_client_id=None, oidc_discovery=None):
    handle, database = tempfile.mkstemp(suffix=".db")
    os.close(handle)
    os.unlink(database)
    key = SecretBox.generate_key()

    class TestConfig(Config):
        TESTING = True
        SECRET_KEY = "providers"
        DATABASE_URL = f"sqlite:///{database}"
        ENCRYPTION_KEY = key
        OIDC_CLIENT_ID = oidc_client_id
        OIDC_DISCOVERY_URL = oidc_discovery
        OIDC_CLIENT_SECRET = "env-secret"
        OIDC_REDIRECT_URI = "http://env/callback"

    return create_app(TestConfig), database


class OidcResolutionTest(unittest.TestCase):
    def setUp(self):
        self.app, self.database = make_app(
            oidc_client_id="env-client",
            oidc_discovery="https://env-idp/.well-known/openid-configuration")

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def store_oidc(self, **overrides):
        value = {"client_id": "stored-client",
                 "discovery_url": "https://stored-idp/.well-known/openid-configuration",
                 "redirect_uri": "http://stored/callback", "enabled": True}
        value.update(overrides)
        self.app.store.settings.set("auth.oidc", value, secret="stored-secret")

    def test_the_environment_is_used_when_nothing_is_stored(self):
        settings = oidc_settings(self.app)
        self.assertEqual(settings["client_id"], "env-client")
        self.assertEqual(settings["source"], "environment")

    def test_a_stored_provider_wins_over_the_environment(self):
        """Otherwise the config page saves successfully and changes nothing."""
        self.store_oidc()
        settings = oidc_settings(self.app)
        self.assertEqual(settings["client_id"], "stored-client")
        self.assertEqual(settings["client_secret"], "stored-secret")
        self.assertEqual(settings["source"], "configuration")

    def test_switching_it_off_does_not_fall_back_to_the_environment(self):
        """The switch must do something on a deployment that has both."""
        self.store_oidc(enabled=False)
        self.assertIsNone(oidc_settings(self.app))

    def test_incomplete_stored_settings_disable_it_rather_than_half_work(self):
        self.store_oidc(discovery_url="")
        self.assertIsNone(oidc_settings(self.app))

    def test_an_unreadable_secret_disables_it_rather_than_falling_back(self):
        """A changed encryption key must not sign people in against the
        provider the administrator thought they had replaced."""
        self.store_oidc()
        self.app.store.secrets._fernet = SecretBox(
            SecretBox.generate_key())._fernet
        self.assertIsNone(oidc_settings(self.app))

    def test_the_stored_redirect_uri_is_used(self):
        self.store_oidc()
        self.assertEqual(oidc_settings(self.app)["redirect_uri"],
                         "http://stored/callback")

    def test_a_change_takes_effect_without_a_restart(self):
        """The client is built per request, so the same app object sees it."""
        self.assertEqual(oidc_settings(self.app)["client_id"], "env-client")
        self.store_oidc()
        self.assertEqual(oidc_settings(self.app)["client_id"], "stored-client")


class LoginPageTest(unittest.TestCase):
    def setUp(self):
        self.app, self.database = make_app()
        self.client = self.app.test_client()
        self.client.post("/setup", data={
            "username": "owner", "password": PASSWORD, "confirm": PASSWORD})
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def test_no_provider_means_no_single_sign_on_button(self):
        page = self.client.get("/auth/login").data
        self.assertNotIn(b"single sign-on", page)

    def test_configuring_one_makes_the_button_appear(self):
        self.app.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": "https://idp/.well-known/openid-configuration"},
            secret="s")
        self.assertIn(b"single sign-on", self.client.get("/auth/login").data)

    def test_the_oidc_route_refuses_when_no_provider_is_in_force(self):
        response = self.client.get("/auth/oidc")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_the_callback_refuses_too(self):
        """Reachable directly, so it cannot rely on the redirect for its guard."""
        response = self.client.get("/auth/callback")
        self.assertEqual(response.status_code, 302)


class LdapResolutionTest(unittest.TestCase):
    def setUp(self):
        self.app, self.database = make_app()

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def store_ldap(self, **overrides):
        value = {"server": "ldaps://ldap:636", "bind_dn": "cn=svc,dc=x",
                 "base_dn": "dc=x", "user_filter": "(uid={username})",
                 "group_attribute": "memberOf", "enabled": True}
        value.update(overrides)
        self.app.store.settings.set("auth.ldap", value, secret="bind-secret")

    def test_nothing_stored_means_no_directory(self):
        self.assertIsNone(ldap_settings(self.app))

    def test_stored_settings_are_returned_with_the_decrypted_password(self):
        self.store_ldap()
        settings = ldap_settings(self.app)
        self.assertEqual(settings["server"], "ldaps://ldap:636")
        self.assertEqual(settings["bind_password"], "bind-secret")

    def test_switching_it_off_disables_it(self):
        self.store_ldap(enabled=False)
        self.assertIsNone(ldap_settings(self.app))

    def test_incomplete_settings_disable_it(self):
        self.store_ldap(base_dn="")
        self.assertIsNone(ldap_settings(self.app))


class LdapAuthenticationTest(unittest.TestCase):
    """The bind, with the directory faked at the library boundary."""

    SETTINGS = {"server": "ldap://ldap:389", "bind_dn": "cn=svc,dc=x",
                "bind_password": "svc", "base_dn": "dc=x",
                "user_filter": "(uid={username})", "group_attribute": "memberOf"}

    def authenticate(self, *args, **kwargs):
        from wdash.auth.ldap_auth import authenticate
        return authenticate(*args, **kwargs)

    def patch(self, find_result, user_bind_succeeds):
        from wdash.auth import ldap_auth

        self.original_find = ldap_auth._find_user
        self.original_connection = ldap_auth._connection

        class FakeConnection:
            # What ldap3 leaves on a connection after a bind: a rejected
            # password is result 49, invalidCredentials. Without it a refusal
            # cannot be told from a directory that failed to answer.
            result = ({"result": 0, "description": "success"}
                      if user_bind_succeeds else
                      {"result": 49, "description": "invalidCredentials"})

            def bind(self):
                return user_bind_succeeds

            def unbind(self):
                pass

        ldap_auth._find_user = lambda settings, filt: find_result
        ldap_auth._connection = lambda *a, **k: FakeConnection()

    def tearDown(self):
        from wdash.auth import ldap_auth
        if hasattr(self, "original_find"):
            ldap_auth._find_user = self.original_find
            ldap_auth._connection = self.original_connection

    def test_a_successful_bind_authenticates(self):
        self.patch(("uid=alice,dc=x", {"mail": ["alice@x"],
                                       "memberOf": ["cn=admins,dc=x"]}), True)
        result = self.authenticate(self.SETTINGS, "alice", "secret")
        self.assertEqual(result["username"], "alice")
        self.assertEqual(result["email"], "alice@x")
        self.assertIn("admins", result["groups"])

    def test_finding_the_user_is_not_enough(self):
        """The bypass this whole flow exists to avoid: a successful search
        proves the account exists, not that the password is right."""
        self.patch(("uid=alice,dc=x", {}), False)
        self.assertIsNone(self.authenticate(self.SETTINGS, "alice", "wrong"))

    def test_an_unknown_user_is_rejected(self):
        self.patch((None, {}), True)
        self.assertIsNone(self.authenticate(self.SETTINGS, "nobody", "secret"))

    def test_an_empty_password_is_refused_before_binding(self):
        """Most directories treat an empty password as an anonymous bind and
        answer success, which would authenticate anyone."""
        self.patch(("uid=alice,dc=x", {}), True)
        self.assertIsNone(self.authenticate(self.SETTINGS, "alice", ""))

    def test_group_dns_are_offered_by_name_as_well(self):
        self.patch(("uid=alice,dc=x",
                    {"memberOf": ["cn=admins,ou=groups,dc=x"]}), True)
        groups = self.authenticate(self.SETTINGS, "alice", "secret")["groups"]
        self.assertIn("admins", groups)
        self.assertIn("cn=admins,ou=groups,dc=x", groups)


class FilterEscapingTest(unittest.TestCase):
    """A username goes into an LDAP filter; this is that injection."""

    def test_a_wildcard_is_escaped(self):
        """`*` alone turns the filter into 'any user'."""
        self.assertNotIn("*", escape_filter("admin*"))

    def test_filter_syntax_is_escaped(self):
        escaped = escape_filter("x)(uid=*")
        for character in ("(", ")", "*"):
            self.assertNotIn(character, escaped)

    def test_ordinary_names_survive_intact(self):
        self.assertEqual(escape_filter("alice.smith"), "alice.smith")


if __name__ == "__main__":
    unittest.main(verbosity=2)
