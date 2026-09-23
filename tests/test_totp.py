"""
The second factor for local accounts.

Three separable things, tested separately:

  * the ALGORITHM, RFC 6238, against the RFC's own published vectors. An
    implementation with no vectors behind it is a guess, and this one is
    written out rather than taken from a library precisely because it can be
    checked.
  * the HOLD between the password and the code, which must grant nothing.
    Proved by asking every route in the url map for it, not by reading the
    code — "no route accepts it" is a claim about a hundred routes.
  * the FLOW: enrol at the first sign-in, a code at every one after, a
    replayed code refused, a wrong code counted by the lockout that already
    exists, and an administrator able to reset it when somebody loses a phone.

Directory accounts are untouched throughout. WDash never sees an LDAP or OIDC
password and has nowhere to keep a secret for one; a second factor for them
belongs at the provider that authenticates them.
"""

import contextlib
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

from wdash.app import create_app  # noqa: E402
from wdash.auth import totp  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store import SecretBox  # noqa: E402

PASSWORD = "a-sufficiently-long-password"

#: RFC 4226 appendix D and RFC 6238 appendix B share this key: the ASCII
#: "12345678901234567890", which is what `GEZD…` is in base32.
RFC_KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class VectorTest(unittest.TestCase):
    """The published answers. Nothing else here proves the maths is right."""

    def test_the_key_is_the_rfcs_own(self):
        self.assertEqual(totp._key(RFC_KEY), b"12345678901234567890")

    def test_rfc_6238_appendix_b(self):
        """Its table is eight digits so that the truncation is visible; the
        product uses six of the same number."""
        for moment, expected in ((59, "94287082"),
                                 (1111111109, "07081804"),
                                 (1111111111, "14050471"),
                                 (1234567890, "89005924"),
                                 (2000000000, "69279037"),
                                 (20000000000, "65353130")):
            with self.subTest(at=moment):
                self.assertEqual(totp.code(RFC_KEY, at=moment, digits=8),
                                 expected)

    def test_rfc_4226_appendix_d(self):
        """TOTP is HOTP over a counter made of time, so the HOTP vectors check
        the half that does the work."""
        self.assertEqual([totp.code_at(RFC_KEY, counter)
                          for counter in range(10)],
                         ["755224", "287082", "359152", "969429", "338314",
                          "254676", "287922", "162583", "399871", "520489"])

    def test_the_step_is_thirty_seconds(self):
        self.assertEqual(totp.step_at(at=59), 1)
        self.assertEqual(totp.step_at(at=60), 2)
        self.assertEqual(totp.STEP, 30)

    def test_the_product_asks_for_six_digits(self):
        self.assertEqual(totp.DIGITS, 6)
        self.assertEqual(len(totp.code(RFC_KEY, at=59)), 6)


class VerifyTest(unittest.TestCase):
    NOW = 1234567890

    def test_the_current_code_is_accepted(self):
        self.assertIsNotNone(totp.verify(
            RFC_KEY, totp.code(RFC_KEY, at=self.NOW), at=self.NOW))

    def test_a_step_either_side_is_accepted_for_clock_drift(self):
        """Thirty seconds of skew is ordinary on a phone. Refusing it makes a
        second factor that works for most people most of the time."""
        for offset in (-totp.STEP, 0, totp.STEP):
            with self.subTest(offset=offset):
                self.assertIsNotNone(totp.verify(
                    RFC_KEY, totp.code(RFC_KEY, at=self.NOW + offset),
                    at=self.NOW))

    def test_two_steps_away_is_not(self):
        for offset in (-2 * totp.STEP, 2 * totp.STEP):
            with self.subTest(offset=offset):
                self.assertIsNone(totp.verify(
                    RFC_KEY, totp.code(RFC_KEY, at=self.NOW + offset),
                    at=self.NOW))

    def test_it_answers_the_step_so_the_caller_can_refuse_it_again(self):
        step = totp.verify(RFC_KEY, totp.code(RFC_KEY, at=self.NOW),
                           at=self.NOW)
        self.assertEqual(step, totp.step_at(at=self.NOW))

    def test_a_step_already_used_is_refused(self):
        """A replayed code is one somebody read over a shoulder, off a screen
        share, or out of a phishing page thirty seconds ago."""
        code = totp.code(RFC_KEY, at=self.NOW)
        used = totp.verify(RFC_KEY, code, at=self.NOW)
        self.assertIsNone(totp.verify(RFC_KEY, code, at=self.NOW, after=used))

    def test_nor_is_an_earlier_one_that_would_otherwise_drift_in(self):
        earlier = totp.code(RFC_KEY, at=self.NOW - totp.STEP)
        used = totp.step_at(at=self.NOW)
        self.assertIsNone(totp.verify(RFC_KEY, earlier, at=self.NOW,
                                      after=used))

    def test_the_next_step_still_works_after_one_is_used(self):
        used = totp.verify(RFC_KEY, totp.code(RFC_KEY, at=self.NOW),
                           at=self.NOW)
        self.assertIsNotNone(totp.verify(
            RFC_KEY, totp.code(RFC_KEY, at=self.NOW + totp.STEP),
            at=self.NOW, after=used))

    def test_the_wrong_shape_never_reaches_the_hmac(self):
        for wrong in ("", "12345", "1234567", "abcdef", "12 34 56", None,
                      "12345a"):
            with self.subTest(submitted=wrong):
                self.assertIsNone(totp.verify(RFC_KEY, wrong, at=self.NOW))

    def test_a_secret_typed_with_spaces_or_in_lower_case_still_works(self):
        """The page shows it in groups of four so it can be typed, and some
        applications hand it back lower-cased."""
        typed = totp.readable(RFC_KEY).lower()
        self.assertEqual(totp.code(typed, at=59, digits=8), "94287082")


class UriTest(unittest.TestCase):
    def test_every_parameter_is_written_out(self):
        """An application that assumes a different default enrols happily and
        then produces codes that never match."""
        uri = totp.provisioning_uri("ABCDEFGH", "bob")
        self.assertTrue(uri.startswith("otpauth://totp/"))
        for part in ("secret=ABCDEFGH", "issuer=WDash", "algorithm=SHA1",
                     "digits=6", "period=30"):
            self.assertIn(part, uri)

    def test_the_label_carries_the_issuer_and_the_name(self):
        self.assertIn("WDash%3Abob", totp.provisioning_uri("AB", "bob"))

    def test_a_name_with_a_slash_in_it_does_not_break_the_path(self):
        self.assertNotIn("a/b", totp.provisioning_uri("AB", "a/b"))

    def test_a_secret_is_shown_in_groups_somebody_can_type(self):
        self.assertEqual(totp.readable("ABCDEFGHIJKL"), "ABCD EFGH IJKL")

    def test_a_new_secret_is_160_bits(self):
        secret = totp.generate_secret()
        self.assertEqual(len(totp._key(secret)), 20)
        self.assertNotEqual(secret, totp.generate_secret())

    def test_the_qr_is_an_inline_svg_with_nothing_to_fetch(self):
        """The page's Content-Security-Policy admits no external image and no
        CDN, so a QR that is a URL is a QR nobody sees."""
        svg = totp.qr_svg(totp.provisioning_uri(RFC_KEY, "bob"))
        self.assertTrue(svg.startswith("<svg"))
        # Paths and nothing else. The only URL in it is the SVG namespace,
        # which is a name rather than something a browser fetches.
        for fetches in ("<image", "href", "url(", "<script"):
            self.assertNotIn(fetches, svg)


class FlowTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "totp"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def claim(self):
        """First-run setup, leaving the browser holding a sign-in."""
        return self.client.post("/setup", data={
            "username": "owner", "password": PASSWORD, "confirm": PASSWORD})

    def secret_on_the_page(self):
        page = self.client.get("/auth/totp/enrol").data.decode()
        return support._secret_on(page), page

    def account(self):
        return self.app.store.users.by_username("owner")

    def stored_secret_column(self):
        from sqlalchemy import select

        from wdash.store.schema import users
        with self.app.store.engine.connect() as connection:
            return connection.execute(
                select(users.c.totp_secret)
                .where(users.c.username == "owner")).scalar()

    def outcomes(self):
        return [row["outcome"] for row in self.app.store.signin.recent()]

    def actions(self):
        return [row["action"] for row in self.app.store.audit.recent(limit=50)]


class TheHoldGrantsNothingTest(FlowTestCase):
    """A correct password does not start a session.

    Measured against the url map rather than read: "no route accepts it" is a
    claim about every route there is, and the one that quietly did would be
    the one nobody thought to check.
    """

    #: Reachable without being signed in at all — before this change and
    #: after it. The agent API is guarded by a bearer token and answers 401.
    PUBLIC = {"static", "health", "livez", "readyz", "index",
              "setup.first_run", "auth.login", "auth.oidc_login",
              "auth.callback", "agent.config", "agent.results",
              "auth.totp_enrol", "auth.totp_code"}

    def test_a_correct_password_does_not_sign_anybody_in(self):
        support.set_up(self.client, username="owner", password=PASSWORD)
        self.client.get("/auth/logout")
        response = self.client.post("/auth/login", data={
            "username": "owner", "password": PASSWORD})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/totp", response.headers["Location"])
        with self.client.session_transaction() as session:
            self.assertNotIn("user_data", session)
            self.assertIn("pending_totp", session)

    def test_no_route_in_the_whole_map_accepts_it(self):
        self.claim()          # the hold, from first-run setup
        with self.client.session_transaction() as session:
            self.assertIn("pending_totp", session)

        reached = []
        for rule in self.app.url_map.iter_rules():
            if rule.endpoint in self.PUBLIC:
                continue
            method = sorted(rule.methods - {"HEAD", "OPTIONS"})[0]
            url = str(rule)
            for argument in rule.arguments:
                url = url.replace(f"<{argument}>", "x")
                url = url.replace(f"<path:{argument}>", "x")
                url = url.replace(f"<monitor:{argument}>", "x")
            if "<" in url:
                continue
            response = self.client.open(url, method=method)
            signed_in = (response.status_code < 400
                         and not (response.status_code == 302
                                  and "/auth/login"
                                  in response.headers.get("Location", "")))
            if signed_in:
                reached.append(f"{method} {url} -> {response.status_code} "
                               f"{response.headers.get('Location', '')}")
        self.assertEqual(reached, [], "\n".join(
            ["a held sign-in reached these:"] + reached))

    def test_the_hold_carries_no_session_of_its_own(self):
        self.claim()
        with self.client.session_transaction() as session:
            self.assertEqual(sorted(session["pending_totp"]),
                             ["expires_at", "issued_at", "secret", "username"])
            self.assertNotIn("user_data", session)

    def test_an_expired_hold_is_dropped_and_says_so(self):
        from datetime import datetime, timedelta, timezone
        self.claim()
        with self.client.session_transaction() as session:
            held = dict(session["pending_totp"])
            held["expires_at"] = (datetime.now(timezone.utc)
                                  - timedelta(seconds=1)).isoformat()
            session["pending_totp"] = held

        response = self.client.get("/auth/totp/enrol", follow_redirects=True)
        self.assertIn(b"timed out", response.data)
        with self.client.session_transaction() as session:
            self.assertNotIn("pending_totp", session)

    def test_the_pages_are_unreachable_without_one(self):
        support.set_up(self.client, username="owner", password=PASSWORD)
        self.client.get("/auth/logout")
        for path in ("/auth/totp", "/auth/totp/enrol"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertIn("/auth/login", response.headers["Location"])


class EnrolmentTest(FlowTestCase):
    def test_setup_leads_to_the_enrolment_page(self):
        response = self.claim()
        self.assertIn("/auth/totp/enrol", response.headers["Location"])

    def test_the_page_offers_all_three_ways_to_carry_the_secret(self):
        """An authenticator on the same device cannot scan the screen it is
        on, so the QR alone is not enough."""
        self.claim()
        secret, page = self.secret_on_the_page()
        self.assertIn("<svg", page)
        self.assertIn(totp.readable(secret), page)
        self.assertIn("otpauth://totp/", page)

    def test_nothing_is_stored_before_a_code_proves_it(self):
        """An unconfirmed secret sitting on an account is a half-enrolled
        account somebody else may be able to sign in as."""
        self.claim()
        self.secret_on_the_page()
        self.assertIsNone(self.stored_secret_column())
        self.assertFalse(self.account()["totp_enrolled"])

    def test_a_wrong_code_stores_nothing_and_counts_as_a_failure(self):
        self.claim()
        self.secret_on_the_page()
        response = self.client.post("/auth/totp/enrol", data={"code": "000000"})
        self.assertEqual(response.status_code, 401)
        self.assertIsNone(self.stored_secret_column())
        self.assertEqual(self.outcomes(), ["failure"])
        with self.client.session_transaction() as session:
            self.assertNotIn("user_data", session)

    def test_the_right_code_seals_it_records_it_and_signs_them_in(self):
        self.claim()
        secret, _ = self.secret_on_the_page()
        response = self.client.post("/auth/totp/enrol",
                                    data={"code": totp.code(secret)})
        self.assertEqual(response.status_code, 302)

        account = self.account()
        self.assertTrue(account["totp_enrolled"])
        self.assertIsNotNone(account["totp_confirmed_at"])
        self.assertEqual(account["totp_last_step"], totp.step_at())
        self.assertEqual(self.app.store.users.totp_secret("owner"), secret)
        self.assertEqual(self.client.get("/admin/config").status_code, 200)

    def test_the_secret_is_sealed_at_rest_like_every_other_credential(self):
        self.claim()
        secret, _ = self.secret_on_the_page()
        self.client.post("/auth/totp/enrol", data={"code": totp.code(secret)})

        stored = self.stored_secret_column()
        self.assertNotIn(secret, stored)
        self.assertTrue(stored.startswith("wdash:v1:"),
                        "not sealed with the store's own SecretBox")

    def test_the_enrolment_is_audited_and_the_secret_is_not_in_the_row(self):
        self.claim()
        secret, _ = self.secret_on_the_page()
        self.client.post("/auth/totp/enrol", data={"code": totp.code(secret)})
        rows = self.app.store.audit.recent(limit=10)
        enrolled = next(row for row in rows if row["action"] == "totp enrolled")
        self.assertEqual(enrolled["subject"], "user:owner")
        self.assertNotIn(secret, str(enrolled))
        self.assertIn("sign-in", [row["action"] for row in rows])

    def test_the_secret_survives_a_reload_of_the_page(self):
        """It is held in the browser's own cookie, so re-reading the page must
        not hand out a second one — the person may already have scanned the
        first."""
        self.claim()
        first, _ = self.secret_on_the_page()
        second, _ = self.secret_on_the_page()
        self.assertEqual(first, second)

    def test_the_last_sign_in_column_waits_for_the_code(self):
        """Otherwise somebody with the password and no phone writes to it."""
        self.claim()
        self.secret_on_the_page()
        self.assertIsNone(self.account()["last_login_at"])
        secret, _ = self.secret_on_the_page()
        self.client.post("/auth/totp/enrol", data={"code": totp.code(secret)})
        self.assertIsNotNone(self.account()["last_login_at"])

    def test_with_no_encryption_key_it_refuses_rather_than_storing_text(self):
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
        self.assertFalse(app.store.users.by_username("owner")["totp_enrolled"])


class CodeTest(FlowTestCase):
    def setUp(self):
        super().setUp()
        self.secret = support.set_up(self.client, username="owner",
                                     password=PASSWORD)
        self.client.get("/auth/logout")
        self.MOMENT = time.time()

    #: The moment every exchange in this class happens at, taken from the
    #: real clock once the enrolment is done.
    #:
    #: Taken, not chosen: the replay guard remembers the step the enrolment
    #: used, and a fixed constant would sit thousands of steps before it —
    #: every code refused as a replay, which is a test measuring the wrong
    #: rule. It only has to be ONE moment, not a particular one.
    #:
    #: A code is computed against `time.time()` HERE and checked against
    #: `time.time()` in the process, and the two are separated by a sign-in
    #: and a form post. A 30-second step boundary falling between them
    #: shifts the distance by a whole step: a code two steps ahead becomes
    #: one and is accepted, a code one step ahead becomes two and is
    #: refused. Both are this class's assertions, inverted, and under load
    #: it happens — once, in a full run, with the module passing twice on
    #: its own afterwards.
    #:
    #: So the checking side is pinned to the same moment the code was made
    #: for. `totp`'s own `time` is replaced rather than the process's: the
    #: sign-in throttle and the audit trail read the real clock in the same
    #: request, and freezing that would be a different test.
    @contextlib.contextmanager
    def _at(self, moment):
        class _Clock:
            @staticmethod
            def time():
                return moment

        original = totp.time
        totp.time = _Clock
        try:
            yield
        finally:
            totp.time = original

    def submit(self, code, address="10.0.0.1", at=None):
        self.client.post("/auth/login",
                         data={"username": "owner", "password": PASSWORD},
                         environ_base={"REMOTE_ADDR": address})
        with self._at(self.MOMENT if at is None else at):
            return self.client.post("/auth/totp", data={"code": code},
                                    environ_base={"REMOTE_ADDR": address})

    def current(self, ahead=totp.STEP):
        """A code the enrolment has not already used."""
        return totp.code(self.secret, at=self.MOMENT + ahead)

    def test_an_enrolled_account_is_asked_for_a_code(self):
        response = self.client.post("/auth/login", data={
            "username": "owner", "password": PASSWORD})
        self.assertIn("/auth/totp", response.headers["Location"])
        self.assertNotIn("enrol", response.headers["Location"])

    def test_the_right_code_signs_them_in(self):
        self.assertEqual(self.submit(self.current()).status_code, 302)
        self.assertEqual(self.client.get("/admin/config").status_code, 200)

    def test_the_success_is_recorded_only_once_both_halves_are_done(self):
        """The pair limit counts from the last success, so recording one when
        the password was accepted would reset the counter before the code was
        ever checked — an unlimited number of guesses at the second factor for
        anybody holding the password."""
        # Counted, because setUp's own enrolment signed in once already.
        before = self.outcomes().count("success")
        self.client.post("/auth/login",
                         data={"username": "owner", "password": PASSWORD})
        self.assertEqual(self.outcomes().count("success"), before,
                         "a correct password recorded a sign-in")
        self.client.post("/auth/totp", data={"code": self.current()})
        self.assertEqual(self.outcomes().count("success"), before + 1)

    def test_a_code_copied_with_the_space_in_it_is_accepted(self):
        """Authenticators show `123 456`, and that is what gets pasted."""
        code = self.current()
        spaced = f"{code[:3]} {code[3:]}"
        self.assertEqual(self.submit(spaced).status_code, 302)

    def test_a_code_cannot_be_used_twice(self):
        code = self.current()
        self.assertEqual(self.submit(code).status_code, 302)
        self.client.get("/auth/logout")
        again = self.submit(code)
        self.assertEqual(again.status_code, 401)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_data", session)

    def test_the_step_before_this_one_is_accepted_for_clock_drift(self):
        """A phone thirty seconds behind is ordinary. The step used by the
        enrolment is forgotten first, because a code before it is refused as
        a replay whatever the drift allowance says — which is the rule this
        test must not be measuring."""
        self.app.store.users.record_totp_step("owner", None)
        behind = totp.code(self.secret, at=self.MOMENT - totp.STEP)
        self.assertEqual(self.submit(behind).status_code, 302)

    def test_two_steps_away_is_not(self):
        self.app.store.users.record_totp_step("owner", None)
        far = totp.code(self.secret, at=self.MOMENT + 2 * totp.STEP)
        self.assertEqual(self.submit(far).status_code, 401)

    def test_a_wrong_code_is_a_failure_the_existing_guard_counts(self):
        self.assertEqual(self.submit("000000").status_code, 401)
        self.assertEqual(self.outcomes()[0], "failure")

    def test_guessing_codes_locks_out_like_guessing_passwords(self):
        """No counter of its own: the lockout, the backoff and the trail that
        cover password guessing cover code guessing for free."""
        statuses = [self.submit("000000").status_code for _ in range(7)]
        self.assertIn(429, statuses)
        self.assertIn("locked", self.outcomes())
        self.assertIn("sign-in blocked", self.actions())

    def test_the_lockout_row_says_which_half_it_was(self):
        for _ in range(7):
            self.submit("000000")
        row = next(entry for entry in self.app.store.audit.recent()
                   if entry["action"] == "sign-in blocked")
        self.assertEqual(row["state"]["stage"], "second factor")

    def test_a_wrong_code_reveals_nothing_about_the_account(self):
        """Reaching this page already needed the right password, so it names
        the account — but the message is about the code and nothing else."""
        response = self.submit("000000")
        self.assertIn(b"code was not accepted", response.data)
        self.assertNotIn(b"Invalid username or password", response.data)

    def test_the_sign_in_page_still_says_one_thing_for_both_halves(self):
        """A username that does not exist and a wrong password have to look
        the same, and adding a second factor must not change that."""
        wrong_password = self.client.post("/auth/login", data={
            "username": "owner", "password": "wrong-but-long-enough"})
        unknown = self.client.post("/auth/login", data={
            "username": "nobody-here", "password": PASSWORD})
        self.assertEqual(wrong_password.status_code, unknown.status_code)
        self.assertIn(b"Invalid username or password", wrong_password.data)
        self.assertIn(b"Invalid username or password", unknown.data)

    def test_an_account_disabled_between_the_halves_cannot_finish(self):
        self.client.post("/auth/login",
                         data={"username": "owner", "password": PASSWORD})
        self.app.store.users.set_disabled("owner", True)
        response = self.client.post("/auth/totp",
                                    data={"code": self.current()})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])
        with self.client.session_transaction() as session:
            self.assertNotIn("user_data", session)

    def test_a_secret_that_cannot_be_opened_is_said_rather_than_denied(self):
        """A changed key is not a wrong code, and telling somebody their code
        is wrong sends them to reinstall an application that was fine."""
        self.client.post("/auth/login",
                         data={"username": "owner", "password": PASSWORD})
        self.app.store.secrets._fernet = None
        response = self.client.post("/auth/totp",
                                    data={"code": self.current()})
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"--reset-totp", response.data)


class DirectoryAccountsAreUntouchedTest(FlowTestCase):
    """Their provider is where a second factor belongs. WDash never sees
    their password and keeps no row for them to hang a secret on."""

    def directory(self, username="alice"):
        from unittest import mock
        self.app.store.settings.set("auth.ldap", {
            "server": "ldaps://ldap:636", "base_dn": "dc=x", "enabled": True})
        answer = {"username": username, "email": None, "groups": ["viewers"]}
        return mock.patch("wdash.auth.ldap_auth.authenticate",
                          return_value=answer)

    def test_a_directory_sign_in_needs_no_code(self):
        support.set_up(self.client, username="owner", password=PASSWORD)
        client = self.app.test_client()
        with self.directory():
            response = client.post("/auth/login", data={
                "username": "alice", "password": "whatever-the-directory-says"})
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("/auth/totp", response.headers["Location"])
        with client.session_transaction() as session:
            self.assertEqual(session["user_data"]["username"], "alice")
            self.assertEqual(session["user_data"]["provider"], "directory")

    def test_the_sign_in_page_says_which_is_which(self):
        support.set_up(self.client, username="owner", password=PASSWORD)
        page = self.app.test_client().get("/auth/login").data
        self.assertIn(b"asks for a code", page)
        self.assertIn(b"Directory accounts do not", page)


class ResetTest(FlowTestCase):
    """Recovery, because a mandatory second factor locks people out."""

    def setUp(self):
        super().setUp()
        self.secret = support.set_up(self.client, username="owner",
                                     password=PASSWORD)
        self.app.store.users.create("bob", "another-long-password", "viewer")
        bob = self.app.test_client()
        self.bob_secret = support.sign_in(bob, "bob", "another-long-password")

    def test_an_administrator_can_reset_it_from_the_accounts_page(self):
        self.assertTrue(self.app.store.users.by_username("bob")["totp_enrolled"])
        response = self.client.post("/admin/accounts/bob/totp/reset",
                                    follow_redirects=True)
        self.assertIn(b"reset", response.data)
        account = self.app.store.users.by_username("bob")
        self.assertFalse(account["totp_enrolled"])
        self.assertIsNone(account["totp_confirmed_at"])
        self.assertIsNone(account["totp_last_step"])
        self.assertIsNone(self.app.store.users.totp_secret("bob"))

    def test_the_reset_is_audited_with_what_it_costs(self):
        self.client.post("/admin/accounts/bob/totp/reset")
        row = self.app.store.audit.recent(limit=1)[0]
        self.assertEqual(row["action"], "account totp reset")
        self.assertEqual(row["subject"], "user:bob")
        self.assertIn("password alone", row["state"]["consequence"])

    def test_the_button_asks_first(self):
        page = self.client.get("/admin/config").data.decode()
        action = 'action="/admin/accounts/bob/totp/reset"'
        self.assertIn(action, page)
        self.assertIn("data-confirm", page.split(action)[1].split(">")[0])

    def test_after_a_reset_the_next_sign_in_enrols_again(self):
        self.client.post("/admin/accounts/bob/totp/reset")
        bob = self.app.test_client()
        fresh = support.sign_in(bob, "bob", "another-long-password")
        self.assertNotEqual(fresh, self.bob_secret)
        self.assertEqual(bob.get("/logs").status_code, 200)

    def test_the_page_says_who_has_one_and_who_does_not(self):
        self.app.store.users.create("carol", "yet-another-long-password",
                                    "viewer")
        page = self.client.get("/admin/config").data.decode()
        self.assertIn("set up", page)
        self.assertIn("not yet", page)

    def test_resetting_an_account_that_has_none_says_so_and_changes_nothing(self):
        self.app.store.users.create("carol", "yet-another-long-password",
                                    "viewer")
        response = self.client.post("/admin/accounts/carol/totp/reset",
                                    follow_redirects=True)
        self.assertIn(b"no authenticator", response.data)
        self.assertNotIn("account totp reset", self.actions())

    def test_it_needs_the_admin_permission_like_every_other_route(self):
        self.app.store.roles.upsert("admin", permissions=["logs:read"],
                                    containers=["*"], trace_containers=["*"])
        self.app.store.rbac.invalidate()
        response = self.client.post("/admin/accounts/bob/totp/reset")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.app.store.users.by_username("bob")["totp_enrolled"])


class RecoveryToolTest(FlowTestCase):
    """The operator who is the only administrator and has lost their phone.

    The accounts page can do this too, and it is behind the sign-in that
    needs the code.
    """

    def setUp(self):
        super().setUp()
        self.secret = support.set_up(self.client, username="owner",
                                     password=PASSWORD)

    def run_tool(self, *arguments):
        import contextlib
        import io

        from wdash.store import recover
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = recover.main(["--database-url",
                                 f"sqlite:///{self.database}", *arguments])
        return code, out.getvalue() + err.getvalue()

    def test_reset_totp_clears_it_and_says_what_it_costs(self):
        code, output = self.run_tool("--reset-totp", "owner")
        self.assertEqual(code, 0, output)
        self.assertIn("password alone", output)
        self.assertFalse(
            self.app.store.users.by_username("owner")["totp_enrolled"])

    def test_an_account_that_does_not_exist_is_refused_with_the_list(self):
        code, output = self.run_tool("--reset-totp", "nobody")
        self.assertEqual(code, 1)
        self.assertIn("owner", output)

    def test_an_account_with_none_is_said_rather_than_reported_as_reset(self):
        self.app.store.users.create("bob", "another-long-password", "viewer")
        code, output = self.run_tool("--reset-totp", "bob")
        self.assertEqual(code, 0)
        self.assertIn("no authenticator", output)

    def test_status_says_who_has_one(self):
        self.app.store.users.create("bob", "another-long-password", "viewer")
        _, output = self.run_tool("--status")
        self.assertIn("bob -> viewer [no authenticator]", output)
        self.assertNotIn("owner -> admin [no authenticator]", output)


def _playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(_playwright(), "playwright is not installed")
class InARealBrowserTest(unittest.TestCase):
    """The two new pages, driven in Chromium.

    This is an authentication change, so the flow is measured where a person
    meets it rather than only through a test client. Three things a client
    cannot see: whether the QR is actually painted (it is an inline SVG under
    a Content-Security-Policy that admits no external image), whether either
    page throws or is refused anything on the console, and whether they are
    legible in both themes — which is what `tests/test_rendered_pages.py`
    measures for every other screen and could not measure for these, because
    reaching them needs a sign-in that is deliberately half finished.
    """

    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server

        from tests.support import serve_in_background

        database = os.path.join(tempfile.mkdtemp(), "totp-browser.db")

        class BrowserConfig(Config):
            SECRET_KEY = "totp-browser"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            DASHBOARD_STORAGE = "database"

        cls.app = create_app(BrowserConfig)
        cls.server = serve_in_background(
            make_server("127.0.0.1", 0, cls.app, threaded=True))
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def audit(self, page, theme):
        """The same colour and contrast audit every other screen gets."""
        from tests.test_rendered_pages import AUDIT, BOOTSTRAP
        page.evaluate(f"window.wdashTheme.set('{theme}')")
        page.wait_for_timeout(200)
        report = page.evaluate(AUDIT, BOOTSTRAP)
        return report["defaults"] + report["unreadable"]

    def test_a_person_can_enrol_and_then_sign_in_with_a_code(self):
        from playwright.sync_api import sync_playwright

        faults = []
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context(
                viewport={"width": 1200, "height": 1000}).new_page()
            page.on("pageerror", lambda error: faults.append(f"threw: {error}"))
            page.on("console", lambda message: faults.append(message.text)
                    if "Content Security Policy" in message.text else None)

            # First run: setup, and then the enrolment it does not skip.
            page.goto(f"{self.base}/setup", wait_until="networkidle")
            page.fill("input[name=username]", "owner")
            page.fill("input[name=password]", PASSWORD)
            page.fill("input[name=confirm]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")
            self.assertIn("/auth/totp/enrol", page.url)

            # The QR is painted, not merely present: an inline SVG that the
            # policy refused, or that rendered at nothing, is a QR nobody can
            # scan and the page would look the same.
            box = page.locator(".qr-quiet-zone svg").bounding_box()
            self.assertIsNotNone(box, "no QR was drawn")
            self.assertGreater(box["width"], 100)
            self.assertAlmostEqual(box["width"], box["height"], delta=2)

            # All three ways to carry it are on the page a person is reading.
            secret = "".join(page.inner_text("#totpSecret").split())
            self.assertIn("otpauth://totp/", page.inner_text("#totpUri"))
            for theme in ("dark", "light"):
                faults += [f"{theme} · enrolment: {line}"
                           for line in self.audit(page, theme)]

            page.fill("input[name=code]", totp.code(secret))
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")
            self.assertNotIn("/auth/", page.url, "the code did not sign in")

            # And again, which is the code page rather than the enrolment one.
            page.goto(f"{self.base}/auth/logout", wait_until="networkidle")
            page.goto(f"{self.base}/auth/login", wait_until="networkidle")
            page.fill("input[name=username]", "owner")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")
            self.assertTrue(page.url.endswith("/auth/totp"), page.url)
            for theme in ("dark", "light"):
                faults += [f"{theme} · code: {line}"
                           for line in self.audit(page, theme)]

            # A wrong code first, so the refusal is measured where it is read.
            page.fill("input[name=code]", "000000")
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")
            self.assertIn("code was not accepted", page.inner_text("body"))

            page.fill("input[name=code]",
                      totp.code(secret, at=time.time() + totp.STEP))
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")
            self.assertNotIn("/auth/", page.url, "the code did not sign in")
            browser.close()

        self.assertEqual(faults, [], "\n".join([""] + faults))


if __name__ == "__main__":
    unittest.main(verbosity=2)
