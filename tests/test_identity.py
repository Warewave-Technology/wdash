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
