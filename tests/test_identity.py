"""
First-run setup, local sign-in, and per-request authorization.

Replaces the development-only login, whose only guard was an environment
variable — the guard people forget. What stands in its place is a real account
in the metadata store, created once, protected by a uniqueness constraint.

The property that matters most here is the last one: authorization is resolved
on every request. Permissions used to be written into the session cookie at
sign-in, which meant revoking a role saved successfully and changed nothing
until the person happened to sign out. An administrator shown a revocation that
did not happen is worse than no revocation feature at all.
"""

import os
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402

PASSWORD = "a-sufficiently-long-password"


class IdentityTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)

        database = self.database

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "identity"
            DATABASE_URL = f"sqlite:///{database}"
            OIDC_CLIENT_ID = None
            # Stated, not inherited: one test here asserts the setup page warns
            # that secrets cannot be stored, which is only true without a key.
            ENCRYPTION_KEY = None

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def complete_setup(self, username="owner", password=PASSWORD):
        return self.client.post("/setup", data={
            "username": username, "password": password, "confirm": password})


class SetupGateTest(IdentityTestCase):
    def test_an_unclaimed_installation_sends_everything_to_setup(self):
        """Serving pages whose authorization has no owner is not useful."""
        for path in ("/", "/logs", "/dashboards", "/traces"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response.headers["Location"].endswith("/setup"), path)

    def test_health_stays_reachable_during_setup(self):
        """A container that fails its health check never gets to be set up."""
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_setup_itself_is_reachable(self):
        self.assertEqual(self.client.get("/setup").status_code, 200)

    def test_the_gate_closes_once_an_account_exists(self):
        self.complete_setup()
        self.assertNotEqual(self.client.get("/logs").headers.get("Location", ""),
                            "/setup")

    def test_setup_redirects_to_sign_in_once_complete(self):
        """A stale bookmark should land somewhere useful, not on an error."""
        self.complete_setup()
        response = self.app.test_client().get("/setup")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_a_second_client_cannot_run_setup_again(self):
        self.complete_setup()
        response = self.app.test_client().post("/setup", data={
            "username": "intruder", "password": PASSWORD, "confirm": PASSWORD})
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.app.store.users.by_username("intruder"))


class SetupFormTest(IdentityTestCase):
    def test_mismatched_passwords_are_refused(self):
        response = self.client.post("/setup", data={
            "username": "owner", "password": PASSWORD, "confirm": "something-else"})
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.app.store.needs_setup)

    def test_a_short_password_is_refused_with_the_reason(self):
        response = self.client.post("/setup", data={
            "username": "owner", "password": "short", "confirm": "short"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"12 characters", response.data)

    def test_a_blank_username_is_refused(self):
        response = self.client.post("/setup", data={
            "username": "   ", "password": PASSWORD, "confirm": PASSWORD})
        self.assertEqual(response.status_code, 400)

    def test_setup_signs_the_administrator_in(self):
        response = self.complete_setup()
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "owner")

    def test_the_page_warns_when_secrets_cannot_be_stored(self):
        """Otherwise the first OIDC save fails for a reason nobody expects."""
        self.assertIn(b"WDASH_ENCRYPTION_KEY", self.client.get("/setup").data)


class LocalSignInTest(IdentityTestCase):
    def setUp(self):
        super().setUp()
        self.complete_setup()
        self.client = self.app.test_client()      # a fresh, signed-out client

    def test_the_right_password_signs_in(self):
        response = self.client.post("/auth/login", data={
            "username": "owner", "password": PASSWORD})
        self.assertEqual(response.status_code, 302)

    def test_the_wrong_password_does_not(self):
        response = self.client.post("/auth/login", data={
            "username": "owner", "password": "wrong-but-long-enough"})
        self.assertEqual(response.status_code, 401)

    def test_the_failure_message_does_not_reveal_which_half_was_wrong(self):
        """Otherwise the form becomes a username oracle."""
        wrong_password = self.client.post("/auth/login", data={
            "username": "owner", "password": "wrong-but-long-enough"})
        unknown_user = self.client.post("/auth/login", data={
            "username": "nobody", "password": PASSWORD})
        self.assertEqual(wrong_password.status_code, unknown_user.status_code)
        self.assertIn(b"Invalid username or password", wrong_password.data)
        self.assertIn(b"Invalid username or password", unknown_user.data)

    def test_the_development_login_is_gone(self):
        """One door. The old one was guarded by an environment variable."""
        self.assertEqual(self.client.get("/auth/dev-login").status_code, 404)

    def test_the_session_carries_identity_only(self):
        """Anything else in there is authorization frozen at sign-in."""
        self.client.post("/auth/login", data={
            "username": "owner", "password": PASSWORD})
        with self.client.session_transaction() as session:
            stored = session["user_data"]
        self.assertEqual(sorted(stored),
                         ["email", "groups", "id", "local_role", "username"])
        for leaked in ("permissions", "allowed_indices", "role"):
            self.assertNotIn(leaked, stored, f"'{leaked}' is frozen in the cookie")


class PerRequestAuthorizationTest(IdentityTestCase):
    def setUp(self):
        super().setUp()
        self.complete_setup()
        # `/api/search` is the probe; what it searches is beside the point.
        # Said out loud, because without it these answered from whatever was
        # listening on port 9200 and a permission test failed the day the
        # development lab was switched off.
        from tests.support import with_stub_logs
        with_stub_logs(self.app)

    def search(self):
        """An endpoint that genuinely gates on a permission."""
        return self.client.get("/api/search?q=*")

    def test_a_revoked_permission_takes_effect_without_signing_out(self):
        """The whole reason authorization moved out of the cookie.

        The same session, still signed in, must lose access the moment the
        role loses it.
        """
        self.assertEqual(self.search().status_code, 200)

        self.app.store.roles.upsert(
            "admin", permissions=[], containers=[], trace_containers=[])
        self.app.store.rbac.invalidate()

        self.assertEqual(self.search().status_code, 403)

    def test_a_granted_permission_takes_effect_the_same_way(self):
        self.app.store.roles.upsert(
            "admin", permissions=[], containers=[], trace_containers=[])
        self.app.store.rbac.invalidate()
        self.assertEqual(self.search().status_code, 403)

        self.app.store.roles.upsert(
            "admin", permissions=["logs:read"], containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()
        self.assertEqual(self.search().status_code, 200)

    def test_boundaries_come_from_the_store_not_the_cookie(self):
        from wdash.auth.auth import load_user_from_session

        self.app.store.roles.upsert(
            "admin", permissions=["logs:read"], containers=["only-this-*"],
            trace_containers=[])
        self.app.store.rbac.invalidate()

        with self.client.session_transaction() as session:
            # Forge a wider boundary in the cookie. It must be ignored.
            session["user_data"]["allowed_indices"] = ["*"]

        with self.app.test_request_context():
            from flask import session as flask_session
            flask_session["user_data"] = {
                "id": "x", "email": "", "username": "owner", "groups": [],
                "local_role": "admin", "allowed_indices": ["*"]}
            user = load_user_from_session()
            self.assertEqual(user.allowed_indices, ["only-this-*"])

    def test_the_resolver_caches_but_can_be_invalidated(self):
        resolver = self.app.store.rbac
        first = resolver.resolve(username="owner", explicit="admin")["permissions"]

        self.app.store.roles.upsert(
            "admin", permissions=["logs:read"], containers=["*"],
            trace_containers=["*"])
        cached = resolver.resolve(username="owner", explicit="admin")["permissions"]
        self.assertEqual(cached, first, "the cache should still be serving")

        resolver.invalidate()
        self.assertEqual(
            resolver.resolve(username="owner", explicit="admin")["permissions"],
            ["logs:read"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class SignInThrottleTest(IdentityTestCase):
    """The limit has to be on the route, not only in the guard.

    A guard nothing calls is a rate limit in the same sense that an unplugged
    alarm is a security system.
    """

    def setUp(self):
        super().setUp()
        self.complete_setup()
        self.client.get("/auth/logout")

    def attempt(self, password="wrong-password-here", address="10.0.0.1"):
        return self.client.post("/auth/login",
                                data={"username": "owner", "password": password},
                                environ_base={"REMOTE_ADDR": address})

    def test_guessing_is_refused_after_repeated_failures(self):
        for _ in range(6):
            self.attempt()
        response = self.attempt()
        self.assertEqual(response.status_code, 429,
                         "the seventh guess was answered like the first")

    def test_the_refusal_says_when_to_come_back(self):
        """'Try again later' is not something anybody can act on."""
        for _ in range(6):
            self.attempt()
        body = self.attempt().get_data(as_text=True)
        self.assertIn("Too many sign-in attempts", body)
        self.assertRegex(body, r"(seconds|minute)")

    def test_a_locked_out_attempt_never_reaches_the_password_check(self):
        """Otherwise the lockout still pays the Argon2 cost on every request,
        and the limiter becomes the amplifier."""
        for _ in range(6):
            self.attempt()
        with unittest.mock.patch.object(
                self.app.store.users, "verify") as verify:
            self.attempt()
        verify.assert_not_called()

    def test_the_correct_password_still_works_below_the_threshold(self):
        self.attempt()
        self.attempt()
        response = self.client.post(
            "/auth/login", data={"username": "owner", "password": PASSWORD},
            environ_base={"REMOTE_ADDR": "10.0.0.1"})
        self.assertEqual(response.status_code, 302)

    def test_a_lockout_here_does_not_lock_the_account_there(self):
        for _ in range(6):
            self.attempt(address="10.0.0.1")
        response = self.client.post(
            "/auth/login", data={"username": "owner", "password": PASSWORD},
            environ_base={"REMOTE_ADDR": "192.168.5.5"})
        self.assertEqual(response.status_code, 302,
                         "an attacker locked the owner out of their own machine")

    def test_every_attempt_is_recorded(self):
        self.attempt()
        outcomes = [row["outcome"] for row in self.app.store.signin.recent()]
        self.assertIn("failure", outcomes)

    def test_a_refusal_is_recorded_as_a_refusal(self):
        """'Still trying' is a different fact from 'guessed wrong'."""
        for _ in range(7):
            self.attempt()
        outcomes = [row["outcome"] for row in self.app.store.signin.recent()]
        self.assertIn("locked", outcomes)

    def test_signing_in_reaches_the_audit_trail(self):
        self.client.post("/auth/login",
                         data={"username": "owner", "password": PASSWORD},
                         environ_base={"REMOTE_ADDR": "10.0.0.1"})
        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertIn("sign-in", actions)

    def test_a_lockout_reaches_the_audit_trail(self):
        """The trail is where somebody looks after the fact; a lockout that
        only appears in a log file has rotated away by then."""
        for _ in range(7):
            self.attempt()
        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertIn("sign-in blocked", actions)


class BreakGlassTest(IdentityTestCase):
    """The account that exists for when the identity provider does not.

    It was an administrator until the first time they signed out. The account
    row said `role: admin`; the sign-in path could not tell a local account
    from a directory one, so it treated the stored role as inapplicable and
    started the session with none. The break-glass account came back as a
    viewer, on the day it was needed, with no way to fix it from the UI —
    because fixing it needs the configuration page.
    """

    def test_the_local_administrator_survives_signing_out(self):
        self.complete_setup()
        self.client.get("/auth/logout")
        self.client.post("/auth/login",
                         data={"username": "owner", "password": PASSWORD})
        self.assertEqual(self.client.get("/admin/config").status_code, 200)

    def test_a_local_account_is_marked_as_local(self):
        """What the sign-in path branches on. A directory principal has no
        stored role; a local one does, and the flag is the difference."""
        self.complete_setup()
        account = self.app.store.users.verify("owner", PASSWORD)
        self.assertTrue(account.get("local"))

    def test_the_sign_in_is_recorded_as_local_rather_than_directory(self):
        self.complete_setup()
        self.client.get("/auth/logout")
        self.client.post("/auth/login",
                         data={"username": "owner", "password": PASSWORD})
        row = next(entry for entry in self.app.store.audit.recent()
                   if entry["action"] == "sign-in")
        self.assertEqual(row["state"]["method"], "local account")


class OidcScopeTest(unittest.TestCase):
    """What WDash asks the identity provider for.

    It asked for `openid email profile`, and this product maps GROUPS to
    roles — `rbac.yaml` names a `groups_claim` and the callback reads it. A
    provider that gates that claim behind a scope therefore sent nothing, and
    every OIDC identity signed in perfectly and landed on the default role.
    No error, no log line; the symptom was an administrator who could not see
    the configuration page.

    Found against a real Dex in `lab/identity`, which is the only way it
    could have been: a stubbed provider returns whatever the stub was written
    to return, including groups nobody asked for.
    """

    def _registered_scope(self, config=None):
        from wdash.auth.auth import init_oauth

        settings = {"client_id": "wdash", "client_secret": "secret",
                    "discovery_url": "https://idp.invalid/.well-known/"
                                     "openid-configuration",
                    "redirect_uri": "http://127.0.0.1:5001/auth/callback"}

        class OidcConfig(Config):
            TESTING = True
            SECRET_KEY = "scope"
            DATABASE_URL = "sqlite:///:memory:"
            ELASTICSEARCH_URL = ""

        if config:
            for name, value in config.items():
                setattr(OidcConfig, name, value)

        app = create_app(OidcConfig)
        with app.app_context():
            _, oidc = init_oauth(app, settings)
            return oidc.client_kwargs["scope"]

    def test_groups_are_asked_for(self):
        self.assertIn("groups", self._registered_scope().split())

    def test_the_usual_three_are_still_asked_for(self):
        scope = self._registered_scope().split()
        for name in ("openid", "email", "profile"):
            self.assertIn(name, scope)

    def test_a_deployment_can_override_it(self):
        """An authorization server MAY refuse a scope it does not recognise.
        A deployment that meets one needs a way out that is not a fork."""
        scope = self._registered_scope({"OIDC_SCOPES": "openid email"})
        self.assertEqual(scope, "openid email")


class KnockingTest(IdentityTestCase):
    """The account-wide limit counted refused attempts. Measured before the
    fix: fifty POSTs from one address answered 5x401 and 45x429, and the
    owner, from another address with the right password, got 429."""

    def test_fifty_requests_from_one_address_do_not_lock_the_owner_out(self):
        self.complete_setup()
        self.client.get("/auth/logout")
        for _ in range(50):
            self.client.post("/auth/login",
                             data={"username": "owner", "password": "wrong-one-here"},
                             environ_base={"REMOTE_ADDR": "6.6.6.6"})
        response = self.client.post(
            "/auth/login", data={"username": "owner", "password": PASSWORD},
            environ_base={"REMOTE_ADDR": "10.0.0.5"})
        self.assertEqual(response.status_code, 302)


class DirectoryTest(IdentityTestCase):
    """What the sign-in page does with what the directory says."""

    SETTINGS = {"server": "ldaps://directory.invalid", "base_dn": "dc=corp"}

    def setUp(self):
        super().setUp()
        self.complete_setup()
        self.client.get("/auth/logout")

    def attempt(self, answer, username="alice", address="10.0.0.9"):
        from wdash.auth import ldap_auth

        def authenticate(settings, name, password):
            if isinstance(answer, Exception):
                raise answer
            return answer

        with unittest.mock.patch("wdash.auth.auth.ldap_settings",
                                 return_value=self.SETTINGS), \
             unittest.mock.patch.object(ldap_auth, "authenticate", authenticate):
            return self.client.post(
                "/auth/login", data={"username": username, "password": "typed-pw"},
                environ_base={"REMOTE_ADDR": address})

    def test_an_outage_is_said_as_one_and_counted_as_no_guess(self):
        """It was "Invalid username or password" and a failure on the
        record: five of them during an outage locked alice out."""
        from wdash.auth.ldap_auth import DirectoryUnavailable
        for _ in range(8):
            response = self.attempt(DirectoryUnavailable("unreachable"))
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"could not be reached", response.data)
        self.assertIsNone(self.app.store.signin.check("alice", "10.0.0.9"))
        signed_in = self.attempt({"username": "alice", "email": "alice@corp",
                                  "groups": []})
        self.assertEqual(signed_in.status_code, 302)

    def test_any_failure_of_the_directory_code_is_an_outage_too(self):
        response = self.attempt(RuntimeError("socket closed"))
        self.assertEqual(response.status_code, 503)

    def test_a_directory_may_not_sign_in_as_a_local_account(self):
        """Ownership and name mappings follow the username, so a directory
        entry called `owner` was the break-glass administrator's
        dashboards."""
        response = self.attempt({"username": "owner", "email": None, "groups": []},
                                username="owner")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"name of a local account", response.data)
        self.assertEqual(self.client.get("/admin/config").status_code, 302)
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "sign-in refused"]
        self.assertEqual(refused[0]["state"]["method"], "directory")


class ProviderIdentityTest(IdentityTestCase):
    """What the OIDC callback takes from the provider's claims."""

    def setUp(self):
        super().setUp()
        self.complete_setup()
        self.client.get("/auth/logout")
        self.app.store.settings.set("rbac.user_roles",
                                    {"boss@corp.example": "admin",
                                     "mallory": "viewer"})
        self.app.store.rbac.invalidate()

    def sign_in(self, claims, **settings):
        class Provider:
            def authorize_access_token(self):
                return {"userinfo": claims}

        effective = {"client_id": "wdash", "redirect_uri": "http://x/cb",
                     "username_claim": "preferred_username", "email_claim": "email",
                     "groups_claim": "groups", "trust_unverified_email": False,
                     **settings}
        with self.client.session_transaction() as session:
            session["oidc_nonce"] = "n"
        with unittest.mock.patch("wdash.auth.auth.oidc_settings",
                                 return_value=effective), \
             unittest.mock.patch("wdash.auth.auth.init_oauth",
                                 return_value=(None, Provider())):
            return self.client.get("/auth/callback")

    def administers(self):
        return self.client.get("/admin/config").status_code == 200

    def test_an_unverified_email_is_not_the_person_it_names(self):
        """Measured before the fix: a userinfo of boss@corp.example with
        email_verified false, beside a mapping of that address to admin,
        resolved to admin."""
        self.sign_in({"sub": "1", "preferred_username": "mallory",
                      "email": "boss@corp.example", "email_verified": False})
        self.assertFalse(self.administers())

    def test_a_verified_email_is(self):
        self.sign_in({"sub": "1", "preferred_username": "boss",
                      "email": "boss@corp.example", "email_verified": True})
        self.assertTrue(self.administers())

    def test_a_verified_flag_sent_as_text_counts(self):
        self.sign_in({"sub": "1", "preferred_username": "boss",
                      "email": "boss@corp.example", "email_verified": "true"})
        self.assertTrue(self.administers())

    def test_a_provider_that_never_says_can_be_trusted_on_purpose(self):
        self.sign_in({"sub": "1", "preferred_username": "boss",
                      "email": "boss@corp.example"}, trust_unverified_email=True)
        self.assertTrue(self.administers())

    def test_a_provider_may_not_sign_in_as_a_local_account(self):
        """preferred_username is whatever the provider lets people edit."""
        self.sign_in({"sub": "1", "preferred_username": "Owner",
                      "email": "o@x", "email_verified": True})
        self.assertFalse(self.administers())
        with self.client.session_transaction() as session:
            self.assertNotIn("user_data", session)
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "sign-in refused"]
        self.assertEqual(refused[0]["state"]["method"], "oidc")

    def test_with_no_username_the_fallback_is_not_an_unverified_email(self):
        """It fell back to the email as sent, which was the same hole."""
        self.sign_in({"sub": "subject-42", "email": "boss@corp.example",
                      "email_verified": False})
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "subject-42")
            self.assertEqual(session["user_data"]["email"], "")

    def test_the_claims_are_the_ones_configured(self):
        """Keycloak puts realm roles at realm_access.roles."""
        self.app.store.roles.upsert("ops", permissions=["system:admin"],
                                    containers=["*"], trace_containers=["*"],
                                    groups=["platform-ops"])
        self.app.store.rbac.invalidate()
        self.sign_in({"sub": "1", "login": "dora",
                      "realm_access": {"roles": ["platform-ops"]}},
                     username_claim="login", groups_claim="realm_access.roles")
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "dora")
        self.assertTrue(self.administers())


class ClaimSettingsTest(IdentityTestCase):
    def test_the_configuration_page_s_claims_reach_the_callback(self):
        from wdash.auth.providers import oidc_settings
        self.app.store.settings.set("auth.oidc", {
            "enabled": True, "client_id": "c", "discovery_url": "https://i/.w",
            "username_claim": "login", "email_claim": "", "groups_claim": "",
            "trust_unverified_email": True})
        settings = oidc_settings(self.app)
        self.assertEqual(settings["username_claim"], "login")
        self.assertEqual(settings["email_claim"], "email")
        self.assertTrue(settings["trust_unverified_email"])

    def test_rbac_yaml_s_claim_mappings_are_the_default(self):
        """Shipped, documented and never read."""
        from wdash.auth.providers import oidc_settings
        self.app.store.settings.set("rbac.claim_mappings",
                                    {"groups_claim": "roles"})
        self.app.store.settings.set("auth.oidc", {
            "enabled": True, "client_id": "c", "discovery_url": "https://i/.w"})
        self.assertEqual(oidc_settings(self.app)["groups_claim"], "roles")

    def test_the_import_carries_them(self):
        from wdash.store import Store
        path = os.path.join(tempfile.mkdtemp(), "rbac.yaml")
        with open(path, "w") as handle:
            handle.write("roles:\n  admin:\n    permissions: [system:admin]\n"
                         "claim_mappings:\n  groups_claim: roles\n")
        store = Store.open(f"sqlite:///{tempfile.mkdtemp()}/c.db", rbac_file=path)
        self.assertEqual(store.settings.get("rbac.claim_mappings"),
                         {"groups_claim": "roles"})

    def test_the_environment_can_name_them(self):
        from wdash.auth.providers import oidc_settings
        self.app.config.update(OIDC_CLIENT_ID="c", OIDC_DISCOVERY_URL="https://i/.w",
                               OIDC_GROUPS_CLAIM="cognito:groups")
        self.assertEqual(oidc_settings(self.app)["groups_claim"], "cognito:groups")


class SetupRoleTest(unittest.TestCase):
    """The account setup creates always got the role called `admin`. An
    rbac.yaml that calls its administrator role something else — or has
    none — left the break-glass account on the default role: it could sign
    in and could not open the page that fixes anything."""

    def app_with(self, rbac):
        path = os.path.join(tempfile.mkdtemp(), "rbac.yaml")
        with open(path, "w") as handle:
            handle.write(rbac)
        database = os.path.join(tempfile.mkdtemp(), "setup.db")

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "setup-role"
            DATABASE_URL = f"sqlite:///{database}"
            RBAC_CONFIG_FILE = path
            OIDC_CLIENT_ID = None

        app = create_app(TestConfig)
        client = app.test_client()
        client.post("/setup", data={"username": "owner", "password": PASSWORD,
                                    "confirm": PASSWORD})
        return app, client

    def test_an_administering_role_by_another_name_is_used(self):
        app, client = self.app_with(
            "roles:\n  superusers:\n    permissions: [system:admin]\n"
            "    indices: ['*']\n  readers:\n    permissions: [logs:read]\n"
            "default_role: readers\n")
        self.assertEqual(app.store.users.by_username("owner")["role"], "superusers")
        self.assertEqual(client.get("/admin/config").status_code, 200)

    def test_with_no_administering_role_one_is_made(self):
        app, client = self.app_with(
            "roles:\n  readers:\n    permissions: [logs:read]\n"
            "default_role: readers\n")
        role = app.store.users.by_username("owner")["role"]
        self.assertIn("system:admin", app.store.roles.get(role)["permissions"])
        self.assertEqual(client.get("/admin/config").status_code, 200)
