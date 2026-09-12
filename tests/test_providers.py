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

And the rule that at most ONE directory signs people in. Measured before it
existed: a stored LDAP and an OIDC provider in the environment were both
usable at once, both doors rendered on one sign-in page, and an OIDC principal
who chose `preferred_username` signed in as the directory user `alice`, got
her role mapping and opened her private dashboard (C147). The subtle half is
that "in force" and "configured" must be decided on the same footing: decide
"in force" from usability and an LDAP whose bind password can no longer be
decrypted stops shadowing the environment, and the installation changes
directory with nothing anywhere saying so.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.auth.ldap_auth import escape_filter  # noqa: E402
from wdash.auth.providers import (  # noqa: E402
    directory, ldap_settings, oidc_settings, refuses_second_directory,
    shadow_notice,
)
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


class OneDoorOnTheSignInPageTest(unittest.TestCase):
    """Two directories configured, one door offered, and the other said.

    Measured before the rule: a store with LDAP enabled beside an environment
    OIDC rendered "Continue with single sign-on" AND "directory accounts both
    use this form" on the same page, and /auth/oidc really started a flow.
    """

    MARKERS = (b"single sign-on", b"directory accounts both use this form")

    def setUp(self):
        self.app, self.database = make_app(**ENVIRONMENT)
        client = self.app.test_client()
        client.post("/setup", data={"username": "owner", "password": PASSWORD,
                                    "confirm": PASSWORD})
        self.app.store.settings.set("auth.ldap", LDAP_VALUE, secret="bind")
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def doors(self, page):
        return [marker for marker in self.MARKERS if marker in page]

    def test_exactly_one_directory_door_is_offered(self):
        page = self.client.get("/auth/login").data
        self.assertEqual(self.doors(page),
                         [b"directory accounts both use this form"])
        self.assertIn(b"Another sign-in method is configured here", page)

    def test_the_notice_survives_a_wrong_password(self):
        """The 401 page is where the person who used the other door lands,
        and "Invalid username or password" is a failure that looks like their
        own mistake."""
        # A local name, so the unreachable directory is never asked and the
        # 401 page is the one that renders.
        response = self.client.post("/auth/login",
                                    data={"username": "owner",
                                          "password": "wrong-password-here"})
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Another sign-in method is configured here",
                      response.data)
        self.assertEqual(self.doors(response.data),
                         [b"directory accounts both use this form"])

    def test_the_notice_survives_a_lockout(self):
        for _ in range(8):
            response = self.client.post("/auth/login",
                                        data={"username": "owner",
                                              "password": "wrong-password-here"})
        self.assertEqual(response.status_code, 429)
        self.assertIn(b"Another sign-in method is configured here",
                      response.data)

    def test_the_shadowed_route_says_so_rather_than_denying_it_exists(self):
        response = self.client.get("/auth/oidc", follow_redirects=True)
        page = response.get_data(as_text=True)
        self.assertNotIn("No identity provider is configured", page)
        self.assertIn("Another sign-in method is configured here", page)

    def test_the_callback_says_the_same(self):
        page = self.client.get("/auth/callback",
                               follow_redirects=True).get_data(as_text=True)
        self.assertNotIn("No identity provider is configured", page)
        self.assertIn("Another sign-in method is configured here", page)

    def test_with_nothing_shadowed_the_old_sentence_stands(self):
        self.app.store.settings.set("auth.ldap", {**LDAP_VALUE,
                                                  "enabled": False})
        self.app.store.settings.set("auth.oidc", {"enabled": False})
        page = self.client.get("/auth/oidc",
                               follow_redirects=True).get_data(as_text=True)
        self.assertIn("No identity provider is configured", page)


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


LDAP_VALUE = {"server": "ldaps://ldap:636", "bind_dn": "cn=svc,dc=x",
              "base_dn": "dc=x", "user_filter": "(uid={username})",
              "group_attribute": "memberOf", "enabled": True}
OIDC_VALUE = {"client_id": "stored-client", "enabled": True,
              "discovery_url": "https://stored-idp/.well-known/openid-configuration"}
ENVIRONMENT = dict(
    oidc_client_id="env-client",
    oidc_discovery="https://env-idp/.well-known/openid-configuration")


class OneDirectoryTest(unittest.TestCase):
    """At most one directory, LDAP or OIDC, signs people in.

    Every case here was measured to behave the other way before the rule
    existed: `scratchpad/design/H-one-directory/measure_H.py`.
    """

    def tearDown(self):
        database = getattr(self, "database", None)
        if database and os.path.exists(database):
            os.unlink(database)

    def app_with(self, ldap=None, oidc=None, environment=False, order=("ldap",
                                                                       "oidc")):
        app, self.database = make_app(**(ENVIRONMENT if environment else {}))
        rows = {"ldap": ldap, "oidc": oidc}
        for which in order:
            if rows[which] is not None:
                app.store.settings.set(f"auth.{which}", rows[which],
                                       secret="a-secret")
        return app

    def test_a_stored_directory_shadows_one_in_the_environment(self):
        """The demo's shape. Both were usable at once, and the sign-in page
        rendered two doors."""
        app = self.app_with(ldap=LDAP_VALUE, environment=True)
        self.assertIsNotNone(ldap_settings(app))
        self.assertIsNone(oidc_settings(app))
        state = directory(app)
        self.assertEqual((state["in_force"], state["shadowed"]),
                         ("ldap", "oidc"))
        self.assertIn("LDAP is in force", state["reason"])
        self.assertIn("OpenID Connect is configured in the environment",
                      state["reason"])
        self.assertIn("--use-directory", state["reason"])

    def test_both_stored_the_one_saved_most_recently_is_in_force(self):
        for order in (("ldap", "oidc"), ("oidc", "ldap")):
            with self.subTest(saved=order):
                app = self.app_with(ldap=LDAP_VALUE, oidc=OIDC_VALUE,
                                    order=order)
                self.assertEqual(directory(app)["in_force"], order[-1])
                self.assertEqual(directory(app)["shadowed"], order[0])
                in_force = {"ldap": ldap_settings, "oidc": oidc_settings}
                self.assertIsNotNone(in_force[order[-1]](app))
                self.assertIsNone(in_force[order[0]](app))
                self.tearDown()

    def test_a_directory_that_cannot_be_read_keeps_the_installation(self):
        """The hole a usability-based rule leaves: an LDAP whose bind password
        no longer decrypts stops shadowing the environment, the environment
        provider becomes the only door, and because ownership is the username
        an OIDC principal can then take a directory user's name. Configured
        and in-force are decided on the SAME footing, so the door closes
        instead of moving."""
        app = self.app_with(ldap=LDAP_VALUE, environment=True)
        app.store.secrets._fernet = SecretBox(SecretBox.generate_key())._fernet

        state = directory(app)
        self.assertEqual(state["in_force"], "ldap")
        self.assertIsNone(ldap_settings(app))
        self.assertIsNone(oidc_settings(app),
                          "the environment provider took over the installation")
        self.assertIn("bind password could not be decrypted", state["unusable"])
        self.assertIn("cannot be used", state["reason"])
        self.assertIn("Directory sign-in is unavailable", shadow_notice(app))

    def test_an_enabled_but_incomplete_directory_shadows_too(self):
        """Presence-and-enabled, not usability — the same rule the refusal
        uses, so a half-filled row cannot hand the installation over."""
        app = self.app_with(ldap={**LDAP_VALUE, "base_dn": ""},
                            environment=True)
        self.assertEqual(directory(app)["in_force"], "ldap")
        self.assertIsNone(oidc_settings(app))

    def test_one_directory_alone_is_untouched(self):
        for which, value in (("ldap", LDAP_VALUE), ("oidc", OIDC_VALUE)):
            with self.subTest(which=which):
                app = self.app_with(**{which: value})
                state = directory(app)
                self.assertEqual(state["in_force"], which)
                self.assertIsNone(state["shadowed"])
                self.assertIsNone(state["reason"])
                self.assertIsNone(shadow_notice(app))
                self.tearDown()

    def test_no_directory_at_all_says_nothing(self):
        app = self.app_with()
        self.assertEqual(directory(app)["in_force"], None)
        self.assertIsNone(shadow_notice(app))

    def test_the_answer_never_carries_a_secret(self):
        """It goes to a template, to the log and to an audit row."""
        app = self.app_with(ldap=LDAP_VALUE, oidc=OIDC_VALUE)
        self.assertNotIn("a-secret", repr(directory(app)))
        self.assertEqual(
            sorted(directory(app)),
            ["in_force", "reason", "shadowed", "sources", "unusable"])

    def test_enabling_the_second_directory_is_refused(self):
        for which, other in (("oidc", "ldap"), ("ldap", "oidc")):
            with self.subTest(enabling=which):
                app = self.app_with(**{other: LDAP_VALUE if other == "ldap"
                                       else OIDC_VALUE})
                message = refuses_second_directory(app, which, True)
                self.assertIsNotNone(message, "the second directory was allowed")
                self.assertIn("one directory at a time", message)
                self.assertIsNone(refuses_second_directory(app, which, False),
                                  "turning it off must never be refused")
                self.assertIsNone(refuses_second_directory(app, other, True),
                                  "re-saving the one in force is not a second")
                self.tearDown()

    def test_an_environment_provider_counts_as_the_other_directory(self):
        """The page CAN turn it off — saving the card with Enabled unchecked
        stores a disabled row, which suppresses the environment — so exempting
        it would leave the one shape that gets no refusal and no guidance."""
        app = self.app_with(environment=True)
        message = refuses_second_directory(app, "ldap", True)
        self.assertIsNotNone(message)
        self.assertIn("Enabled unchecked", message)
        self.assertNotIn("OIDC_CLIENT_ID", message)

    def test_nothing_configured_means_nothing_to_refuse(self):
        app = self.app_with()
        self.assertIsNone(refuses_second_directory(app, "ldap", True))


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
