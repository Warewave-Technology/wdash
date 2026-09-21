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

from tests import support  # noqa: E402

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store import SecretBox  # noqa: E402

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
            # Stated, not inherited. A local account cannot finish signing in
            # without a key: its authenticator's secret is sealed with this
            # one, and WDash refuses to write a secret as plain text. The
            # test about a keyless installation builds its own app.
            ENCRYPTION_KEY = SecretBox.generate_key()

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def submit_setup(self, username="owner", password=PASSWORD):
        """The form alone. A correct submission no longer starts a session:
        it leaves the browser holding a half-finished sign-in."""
        return self.client.post("/setup", data={
            "username": username, "password": password, "confirm": password})

    def complete_setup(self, username="owner", password=PASSWORD):
        """The form AND the authenticator enrolment it now requires, which
        together are what one POST used to do. The secret is kept on `self`
        so a later sign-in can produce a code for it."""
        response = self.submit_setup(username, password)
        self.secret = support.enrol(self.client)
        return response

    def sign_in(self, username="owner", password=PASSWORD):
        return support.sign_in(self.client, username, password, self.secret,
                               app=self.app)


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

    def test_setup_does_not_sign_the_administrator_in(self):
        """It used to, which with a mandatory second factor would have made
        the account that matters most the one account that never enrolled."""
        response = self.submit_setup()
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/totp/enrol", response.headers["Location"])
        with self.client.session_transaction() as session:
            self.assertNotIn("user_data", session)
        self.assertEqual(self.client.get("/admin/config").status_code, 302)

    def test_enrolling_is_what_signs_them_in(self):
        self.complete_setup()
        self.assertEqual(self.client.get("/admin/config").status_code, 200)

    def test_the_page_warns_when_secrets_cannot_be_stored(self):
        """Otherwise the first OIDC save fails for a reason nobody expects —
        and now so does the first sign-in, which is worse."""
        database = os.path.join(tempfile.mkdtemp(), "keyless.db")

        class Keyless(Config):
            TESTING = True
            SECRET_KEY = "keyless"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = None

        client = create_app(Keyless).test_client()
        self.assertIn(b"WDASH_ENCRYPTION_KEY", client.get("/setup").data)

    def test_without_a_key_the_administrator_cannot_finish_signing_in(self):
        """No key, no secret — and an authenticator IS a secret. Refused with
        the sentence that says what to set, rather than enrolled into
        plaintext."""
        database = os.path.join(tempfile.mkdtemp(), "keyless.db")

        class Keyless(Config):
            TESTING = True
            SECRET_KEY = "keyless"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = None

        app = create_app(Keyless)
        client = app.test_client()
        client.post("/setup", data={"username": "owner", "password": PASSWORD,
                                    "confirm": PASSWORD})
        page = client.get("/auth/totp/enrol")
        self.assertEqual(page.status_code, 503)
        self.assertIn(b"WDASH_ENCRYPTION_KEY", page.data)
        self.assertEqual(client.get("/admin/config").status_code, 302)
        self.assertIsNone(app.store.users.by_username("owner")["totp_enrolled"]
                          or None)


class LocalSignInTest(IdentityTestCase):
    def setUp(self):
        super().setUp()
        self.complete_setup()
        self.client = self.app.test_client()      # a fresh, signed-out client

    def test_the_right_password_asks_for_a_code_rather_than_signing_in(self):
        """Half a sign-in. The hold grants nothing until the code."""
        response = self.client.post("/auth/login", data={
            "username": "owner", "password": PASSWORD})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/totp", response.headers["Location"])
        with self.client.session_transaction() as session:
            self.assertNotIn("user_data", session)

    def test_the_code_is_what_signs_them_in(self):
        support.sign_in(self.client, "owner", PASSWORD, self.secret,
                        app=self.app)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "owner")

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
        """Anything else in there is authorization frozen at sign-in.

        `provider` is identity — which door this person came through — and it
        is read by the rule about turning a directory off, which otherwise
        has to guess and tells an administrator something untrue.
        """
        support.sign_in(self.client, "owner", PASSWORD, self.secret,
                        app=self.app)
        with self.client.session_transaction() as session:
            stored = session["user_data"]
        self.assertEqual(sorted(stored),
                         ["email", "groups", "id", "local_role", "provider",
                          "username"])
        self.assertEqual(stored["provider"], "local account")
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
        self.sign_in()
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
        self.sign_in()
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
        self.sign_in()
        row = next(entry for entry in self.app.store.audit.recent()
                   if entry["action"] == "sign-in")
        self.assertEqual(row["state"]["method"], "local account")


class OidcScopeTest(unittest.TestCase):
    """What WDash asks the identity provider for.

    It asked for `openid email profile`, and this product maps GROUPS to
    roles — a `groups_claim` names the claim and the callback reads it. A
    provider that gates that claim behind a scope therefore sent nothing, and
    every OIDC identity signed in perfectly and landed on the default role.
    No error, no log line; the symptom was an administrator who could not see
    the configuration page.

    Found against a real Dex in `lab/identity`, which is the only way it
    could have been: a stubbed provider returns whatever the stub was written
    to return, including groups nobody asked for.
    """

    def _registered_scope(self, scopes=None):
        """The scope the client is registered with, for a card whose Scopes
        field holds `scopes` — None for a card without the field, as one
        saved before it existed."""
        from wdash.auth.auth import init_oauth

        settings = {"client_id": "wdash", "client_secret": "secret",
                    "discovery_url": "https://idp.invalid/.well-known/"
                                     "openid-configuration",
                    "redirect_uri": "http://127.0.0.1:5001/auth/callback"}
        if scopes is not None:
            settings["scopes"] = scopes

        class OidcConfig(Config):
            TESTING = True
            SECRET_KEY = "scope"
            DATABASE_URL = "sqlite:///:memory:"

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
        A deployment that meets one needs a way out that is not a fork: the
        Scopes field on the OpenID Connect card."""
        self.assertEqual(self._registered_scope("openid email"), "openid email")

    def test_a_blank_field_asks_for_the_default(self):
        """Blank is what a card saved with the field untouched holds, and a
        sign-in that asked for no scope at all would not even get `openid`."""
        self.assertIn("groups", self._registered_scope("").split())
        self.assertIn("openid", self._registered_scope("").split())


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

    def test_a_directory_name_that_resolves_to_a_local_account_is_refused(self):
        """The break-glass administrator's identity, through the directory.

        The local-name guard checks what was TYPED, and that was the same
        string as the session's username until the username started coming
        from the directory's own attribute. With a filter matching more than
        one attribute — `(|(uid={username})(mail={username}))`, which is an
        ordinary thing to write — they are not the same string.

        Measured against the lab's OpenLDAP before this refusal existed:
        typing `alice` was refused 401 as a local name, and typing
        `alice@lab.local` was accepted and started a session as `alice`,
        reached /admin/config with the local alice's admin role, and
        survived that local account being disabled — because
        `load_user_from_session` re-reads the stored account only for a
        session that says it is local.
        """
        self.app.store.users.create("alice", "local-password-12chars",
                                    role="admin")

        response = self.attempt({"username": "alice", "email": "alice@corp",
                                 "groups": []}, username="alice@corp")
        self.assertEqual(response.status_code, 401)
        with self.client.session_transaction() as session:
            self.assertIsNone(session.get("user_data"))

        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "directory sign-in refused"]
        self.assertEqual(len(refused), 1, "the refusal was not recorded")
        self.assertEqual(refused[0]["state"]["typed"], "alice@corp")

    def test_a_directory_name_of_its_own_still_signs_in(self):
        """The refusal is about a collision, not about a name that differs
        from what was typed — which is now the ordinary case."""
        response = self.attempt({"username": "bob", "email": "bob@corp",
                                 "groups": []}, username="bob@corp")
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "bob")

    def test_the_session_holds_the_name_the_directory_gave(self):
        """What the directory answered, not what was typed — and it is the
        name everything downstream is keyed by: the role a mapping names,
        the `created_by` on a dashboard, the actor on an audit row.

        `ldap_auth.authenticate` is where the two are reconciled, against a
        real directory in tests/test_ldap_auth.py and
        tests/test_identity_lab.py. This is the other half: that the answer
        reaches the session rather than being replaced by the form field on
        the way.
        """
        self.app.store.settings.set("rbac.user_roles", {"alice": "admin"})
        self.app.store.rbac.invalidate()

        response = self.attempt({"username": "alice", "email": "alice@corp",
                                 "groups": []}, username="Alice")
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "alice")

        # And the mapping written for that name applies, which is the
        # symptom the whole change is about: typed as Alice, it did not.
        page = self.client.get("/admin/config")
        self.assertEqual(page.status_code, 200,
                         "the mapping for the directory's name did not apply")

    def test_any_failure_of_the_directory_code_is_an_outage_too(self):
        response = self.attempt(RuntimeError("socket closed"))
        self.assertEqual(response.status_code, 503)

    def test_a_local_name_is_not_asked_of_the_directory(self):
        """Ownership and name mappings follow the username, so a directory
        entry called `owner` was the break-glass administrator's
        dashboards; and asking about it let a directory that could not
        answer turn every guess at owner's password into an outage no limit
        counts. So the directory is not asked, and a wrong password for a
        local name is a wrong password."""
        from wdash.auth.ldap_auth import DirectoryUnavailable
        for answer in ({"username": "owner", "email": None, "groups": []},
                       DirectoryUnavailable("unreachable")):
            with self.subTest(answer=answer):
                response = self.attempt(answer, username="owner")
                self.assertEqual(response.status_code, 401)
                self.assertIn(b"Invalid username or password", response.data)
        self.assertEqual(self.client.get("/admin/config").status_code, 302)
        # The two attempts made here, newest first. The success under them is
        # the enrolment that finished setUp's sign-in; what matters is that
        # neither of these was recorded as an outage, which no limit counts.
        self.assertEqual(
            [row["outcome"] for row in self.app.store.signin.recent()
             if row["username"] == "owner"][:2], ["failure", "failure"])

    def test_guesses_at_a_local_account_lock_it_while_the_directory_is_down(self):
        """The measurement, as a test: 60 wrong guesses at `owner` with the
        directory unreachable were 60 x 503 and the right password was let
        in straight after."""
        from wdash.auth.ldap_auth import DirectoryUnavailable
        codes = [self.attempt(DirectoryUnavailable("unreachable"),
                              username="owner", address="6.6.6.6").status_code
                 for _ in range(8)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(set(codes[5:]), {429})
        self.assertIsNotNone(self.app.store.signin.check("owner", "6.6.6.6"))


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

    def test_a_provider_refused_under_a_local_name_does_not_lock_it(self):
        """Refusals are recorded as refused, which no limit counts. Recorded
        as failures, anybody whose provider let them call themselves `owner`
        could lock the break-glass account out by signing in again and
        again."""
        for _ in range(12):
            self.sign_in({"sub": "1", "preferred_username": "owner",
                          "email": "o@x", "email_verified": True})
        # Everything the twelve attempts wrote. The success below them is
        # setUp's own sign-in finishing; none of these is a failure, which is
        # what would have counted towards a lockout.
        outcomes = {row["outcome"] for row in self.app.store.signin.recent()
                    if row["username"] == "owner"} - {"success"}
        self.assertEqual(outcomes, {"refused"})
        response = self.client.post("/auth/login", data={
            "username": "owner", "password": PASSWORD})
        self.assertEqual(response.status_code, 302)

    def test_with_no_username_an_unverified_email_is_not_the_fallback(self):
        """It fell back to the email as sent, which was the same hole. Nor
        is it `sub`: a token shaped like ADFS or Entra v1 — no
        preferred_username, no email_verified — would have signed its
        person in as an opaque id, their dashboards and mappings gone
        without a word. Refused, with what fixes it."""
        for claims in ({"sub": "subject-42", "email": "boss@corp.example",
                        "email_verified": False},
                       {"sub": "subject-42", "email": "boss@corp.example",
                        "upn": "boss@corp.example", "unique_name": "CORP\\boss"}):
            with self.subTest(claims=claims):
                self.sign_in(claims)
                with self.client.session_transaction() as session:
                    self.assertNotIn("user_data", session)
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "sign-in refused"]
        self.assertEqual(len(refused), 2)
        self.assertEqual(refused[0]["subject"], "user:boss@corp.example")
        self.assertEqual(
            [row["outcome"] for row in self.app.store.signin.recent()
             if row["username"] == "boss@corp.example"], ["refused", "refused"])

    def test_naming_the_claim_that_holds_the_name_lets_them_in(self):
        self.sign_in({"sub": "subject-42", "email": "boss@corp.example",
                      "upn": "boss@corp.example"}, username_claim="upn")
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "boss@corp.example")
            self.assertEqual(session["user_data"]["email"], "")

    def test_with_no_name_and_no_address_sub_is_the_name(self):
        """Nothing was dropped, so nothing changes who they are."""
        self.sign_in({"sub": "subject-42"})
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "subject-42")

    def test_email_verified_speaks_for_the_email_claim_only(self):
        """Measured: with email_claim `work_email`, a verified `email` of
        the attacker's own vouched for a `work_email` of boss@corp.example,
        mapped to admin — and they administered."""
        self.client.get("/auth/logout")
        self.sign_in({"sub": "2", "preferred_username": "m",
                      "email": "m@attacker.example", "email_verified": True,
                      "work_email": "boss@corp.example"},
                     email_claim="work_email")
        self.assertFalse(self.administers())
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_data"]["email"], "")

    def test_an_address_that_is_not_used_is_said_in_the_log(self):
        """Every mapping written against an address stops matching when the
        provider never sends email_verified, and nothing on a page says so."""
        with self.assertLogs(self.app.logger, level="WARNING") as said:
            self.sign_in({"sub": "1", "preferred_username": "alice",
                          "email": "alice@corp.example"})
        self.assertTrue(any("not mark it verified" in line for line in said.output))

    def test_the_audit_says_what_the_provider_said(self):
        """`email_verified` was recorded as whether an address was used: with
        unverified addresses trusted, one the provider called unverified
        went into the trail as verified."""
        self.sign_in({"sub": "1", "preferred_username": "boss",
                      "email": "boss@corp.example", "email_verified": False},
                     trust_unverified_email=True)
        row = [r for r in self.app.store.audit.recent()
               if r["action"] == "sign-in"][0]
        self.assertIs(row["state"]["email_verified"], False)
        self.assertIs(row["state"]["unverified_email_trusted"], True)

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

    def test_stored_claim_mappings_are_the_default(self):
        """What an installation imported from an rbac.yaml at an earlier
        version, and still has. The block was once shipped, documented and
        never read: an operator whose provider sends groups as `roles` edited
        it and every OIDC user still landed on the default role."""
        from wdash.auth.providers import oidc_settings
        self.app.store.settings.set("rbac.claim_mappings",
                                    {"groups_claim": "roles"})
        self.app.store.settings.set("auth.oidc", {
            "enabled": True, "client_id": "c", "discovery_url": "https://i/.w"})
        self.assertEqual(oidc_settings(self.app)["groups_claim"], "roles")

    def test_with_none_stored_the_claims_are_the_ones_a_new_installation_stores(self):
        """An installation that never stored a mapping — seeded before WDash
        read the block, or from a file without one — reads the fallback. A
        new installation stores its claims instead. Two answers to one
        question have to be one answer, or which claim names a person's
        groups depends on the age of the installation."""
        from wdash.auth.providers import oidc_settings
        stored = dict(self.app.store.settings.get("rbac.claim_mappings"))
        self.app.store.settings.delete("rbac.claim_mappings")
        self.app.store.settings.set("auth.oidc", {
            "enabled": True, "client_id": "c", "discovery_url": "https://i/.w"})
        settings = oidc_settings(self.app)
        self.assertEqual({key: settings[key] for key in stored}, stored)

    def test_the_card_can_name_them_and_trust_an_unverified_address(self):
        """Every claim, and the trust switch, from the one place a provider
        is configured."""
        from wdash.auth.providers import oidc_settings
        self.app.store.settings.set("auth.oidc", {
            "enabled": True, "client_id": "c", "discovery_url": "https://i/.w",
            "groups_claim": "cognito:groups", "username_claim": "sub",
            "email_claim": "mail", "trust_unverified_email": True})
        settings = oidc_settings(self.app)
        self.assertEqual(settings["groups_claim"], "cognito:groups")
        self.assertEqual(settings["username_claim"], "sub")
        self.assertEqual(settings["email_claim"], "mail")
        self.assertIs(settings["trust_unverified_email"], True)

    def test_what_is_stored_is_not_overwritten_by_a_restart(self):
        """An installation whose provider sends `memberOf` has that stored.
        A start that wrote the defaults over it would send every group
        mapping back to reading `groups`, where each resolves nothing and
        everybody lands on the default role — silently."""
        from wdash.store import Store
        url = f"sqlite:///{tempfile.mkdtemp()}/kept.db"
        store = Store.open(url)
        store.settings.set("rbac.claim_mappings", {"groups_claim": "memberOf"})
        store.engine.dispose()
        self.assertEqual(Store.open(url).settings.get("rbac.claim_mappings"),
                         {"groups_claim": "memberOf"})


class SetupRoleTest(unittest.TestCase):
    """The account setup creates always got the role called `admin`. An
    installation whose roles call the administrator something else —
    imported from an rbac.yaml by an earlier version, or edited since — or
    have none, left the break-glass account on the default role: it could
    sign in and could not open the page that fixes anything.

    Made here the way such an installation is found: a store holding those
    roles and mappings, which nobody has claimed yet.
    """

    def unclaimed(self, roles, default_role, user_roles=None):
        """`roles` maps a name to (permissions, log containers)."""
        database = os.path.join(tempfile.mkdtemp(), "setup.db")

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "setup-role"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()

        app = create_app(TestConfig)
        store = app.store
        for existing in store.roles.all():
            store.roles.delete(existing["name"])
        for name, (permissions, containers) in roles.items():
            store.roles.upsert(name, permissions=permissions,
                               containers=containers, trace_containers=[])
        store.settings.set("rbac.default_role", default_role)
        store.settings.set("rbac.user_roles", user_roles or {})
        store.rbac.invalidate()
        return app

    def app_with(self, roles, default_role, user_roles=None):
        app = self.unclaimed(roles, default_role, user_roles)
        client = app.test_client()
        support.set_up(client, username="owner", password=PASSWORD)
        return app, client

    READERS = {"readers": (["logs:read"], [])}

    def test_an_administering_role_by_another_name_is_used(self):
        app, client = self.app_with(
            {"superusers": (["system:admin"], ["*"]), **self.READERS},
            default_role="readers")
        self.assertEqual(app.store.users.by_username("owner")["role"], "superusers")
        self.assertEqual(client.get("/admin/config").status_code, 200)

    def test_the_role_it_makes_is_not_one_a_mapping_already_names(self):
        """`bob: admin`, left from a rename, granted nothing while no role
        was called that. Setup made `admin` with every permission, and bob
        was an administrator of every container."""
        app, client = self.app_with(
            self.READERS, default_role="readers",
            user_roles={"bob": "admin", "carol": "setup-admin"})
        role = app.store.users.by_username("owner")["role"]
        self.assertNotIn(role, ("admin", "setup-admin"))
        self.assertIsNone(app.store.roles.get("admin"))
        self.assertEqual(client.get("/admin/config").status_code, 200)

    def test_nor_one_the_default_role_names(self):
        """A default role that names no role gives nothing; made at setup,
        it would give everybody everything."""
        app, _ = self.app_with(self.READERS, default_role="setup-admin")
        role = app.store.users.by_username("owner")["role"]
        self.assertNotEqual(role, "setup-admin")
        self.assertIsNone(app.store.roles.get("setup-admin"))

    def test_a_refused_password_makes_no_role(self):
        app = self.unclaimed(self.READERS, default_role="readers")
        response = app.test_client().post("/setup", data={
            "username": "owner", "password": "short", "confirm": "short"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(sorted(r["name"] for r in app.store.roles.all()),
                         ["readers"])

    def test_with_no_administering_role_one_is_made(self):
        app, client = self.app_with(self.READERS, default_role="readers")
        role = app.store.users.by_username("owner")["role"]
        self.assertIn("system:admin", app.store.roles.get(role)["permissions"])
        self.assertEqual(client.get("/admin/config").status_code, 200)
