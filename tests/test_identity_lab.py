"""
Sign-in against a real directory and a real identity provider.

Both of WDash's non-local sign-in paths end in the same question — which
groups is this person in, and therefore which role do they get — and both had
only ever been tested against objects this repository wrote itself. That is
enough to check the parsing and nothing else: a directory has opinions about
what it returns, and so does an OIDC provider.

Running them against `./lab.sh up identity` found two things a stub could not
have:

  * WDash asked for `openid email profile` and never for `groups`. Dex gates
    that claim behind the scope, so every OIDC identity signed in perfectly
    and landed on the DEFAULT role — no error, no log line, and the only
    symptom an administrator who could not see the configuration page;
  * the lab's own directory used `groupOfNames`, and the memberOf overlay in
    the image is configured for `groupOfUniqueNames`. The groups listed their
    members correctly and no user had a `memberOf` at all.

Skipped when the lab is not up, and REQUIRED when `WDASH_REQUIRE_IDENTITY=1`
says a job promised one — a test that exists to check this and passes by
skipping is the same fault it is looking for.
"""

import html
import os
import re
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.auth.ldap_auth import authenticate  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

LDAP_URL = os.environ.get("WDASH_LAB_LDAP") or "ldap://localhost:1389"
DEX_URL = os.environ.get("WDASH_LAB_DEX") or "http://localhost:5556/dex"
REQUIRED = os.environ.get("WDASH_REQUIRE_IDENTITY") == "1"

#: What the lab's directory holds. Written out rather than read from the LDIF
#: so that a change to one and not the other is a failure rather than a pair
#: of files agreeing with each other about nothing.
PEOPLE = {
    "alice": ("alice@lab.local", ["wdash-admins"]),
    "bob": ("bob@lab.local", ["wdash-developers"]),
    "carol": ("carol@lab.local", ["wdash-viewers"]),
    "dave": ("dave@lab.local", []),
}
PASSWORD = "hunter2"

SETTINGS = {
    "server": LDAP_URL,
    "base_dn": "dc=lab,dc=local",
    "bind_dn": "cn=admin,dc=lab,dc=local",
    "bind_password": PASSWORD,
}


def _directory_is_up():
    try:
        return authenticate(SETTINGS, "alice", PASSWORD) is not None
    except Exception:
        return False


def _provider_is_up():
    try:
        import requests
        response = requests.get(
            f"{DEX_URL}/.well-known/openid-configuration", timeout=3)
        return response.status_code == 200
    except Exception:
        return False


DIRECTORY = _directory_is_up()
PROVIDER = _provider_is_up()

_MISSING = ("no identity lab — `cd lab && ./lab.sh up identity`, or set "
            "WDASH_LAB_LDAP / WDASH_LAB_DEX")


class TheLabIsThereWhenPromisedTest(unittest.TestCase):
    """The guard on both skips below."""

    @unittest.skipUnless(REQUIRED, "only asserted where a lab is promised")
    def test_both_halves_answered(self):
        self.assertTrue(DIRECTORY, f"nothing answered at {LDAP_URL}")
        self.assertTrue(PROVIDER, f"nothing answered at {DEX_URL}")


@unittest.skipUnless(DIRECTORY, _MISSING)
class DirectorySignInTest(unittest.TestCase):
    """WDash's own LDAP path, against OpenLDAP."""

    def test_everybody_authenticates(self):
        for username, (email, _) in PEOPLE.items():
            with self.subTest(username=username):
                result = authenticate(SETTINGS, username, PASSWORD)
                self.assertIsNotNone(result)
                self.assertEqual(result["username"], username)
                self.assertEqual(result["email"], email)

    def test_however_it_is_typed_it_is_one_person(self):
        """OpenLDAP matches `uid` with caseIgnoreMatch, so all three of
        these sign in. Each used to become a different person: WDash kept
        the string that was typed, and a mapping written `alice`, the
        dashboards `alice` owns and the audit rows under that name all
        belonged to one of the three.

        Measured here rather than against a fake, because whether the
        directory matches loosely at all is the directory's business — and
        this one does.
        """
        for typed in ("alice", "Alice", "ALICE", "aLiCe"):
            with self.subTest(typed=typed):
                result = authenticate(SETTINGS, typed, PASSWORD)
                self.assertIsNotNone(result, "the directory refused it")
                self.assertEqual(result["username"], "alice")
                self.assertEqual(result["email"], "alice@lab.local")

    def test_the_groups_come_back_as_names(self):
        """`memberOf` yields full DNs. Both forms are returned on purpose, so
        a role mapping written either way matches — this checks the names are
        among them, since that is what the roles are written in."""
        for username, (_, groups) in PEOPLE.items():
            with self.subTest(username=username):
                result = authenticate(SETTINGS, username, PASSWORD)
                names = [g for g in result["groups"] if "=" not in g]
                self.assertEqual(names, groups)

    def test_belonging_to_nothing_is_not_a_failure(self):
        """Dave authenticates and is entitled to nothing. That is a different
        path from a refused password and lands on the default role."""
        result = authenticate(SETTINGS, "dave", PASSWORD)
        self.assertIsNotNone(result)
        self.assertEqual(result["groups"], [])

    def test_a_wrong_password_is_refused(self):
        self.assertIsNone(authenticate(SETTINGS, "alice", "not-the-password"))

    def test_an_unknown_person_is_refused(self):
        self.assertIsNone(authenticate(SETTINGS, "eve", PASSWORD))

    def test_an_empty_password_is_refused(self):
        """Most directories treat a bind with an empty password as an
        ANONYMOUS bind and return success, which would authenticate anybody
        who submits a blank field. Worth checking against a real one."""
        self.assertIsNone(authenticate(SETTINGS, "alice", ""))

    # --- a directory that cannot answer is not a wrong password ---
    #
    # Each of these returned None — "no such user" — and was recorded as a
    # failed guess against whoever tried. Measured against this directory.

    def test_a_directory_nobody_is_listening_for_cannot_answer(self):
        from wdash.auth.ldap_auth import DirectoryUnavailable
        with self.assertRaises(DirectoryUnavailable):
            authenticate({**SETTINGS, "server": "ldap://localhost:1"},
                         "alice", PASSWORD)

    def test_a_service_account_it_refuses_cannot_answer(self):
        from wdash.auth.ldap_auth import DirectoryUnavailable
        with self.assertRaises(DirectoryUnavailable):
            authenticate({**SETTINGS, "bind_password": "not-it"}, "alice", PASSWORD)

    def test_a_base_dn_it_does_not_hold_cannot_answer(self):
        from wdash.auth.ldap_auth import DirectoryUnavailable
        with self.assertRaises(DirectoryUnavailable):
            authenticate({**SETTINGS, "base_dn": "dc=nowhere"}, "alice", PASSWORD)

    def test_its_ldaps_certificate_is_checked(self):
        """The lab's certificate is self-signed, for a container id, and
        expired: nothing should accept it. It was never looked at."""
        from wdash.auth.ldap_auth import DirectoryUnavailable
        ldaps = LDAP_URL.replace("ldap://", "ldaps://").replace(":1389", ":1636")
        with self.assertRaises(DirectoryUnavailable):
            authenticate({**SETTINGS, "server": ldaps}, "alice", PASSWORD)


@unittest.skipUnless(DIRECTORY and PROVIDER, _MISSING)
class ProviderSignInTest(unittest.TestCase):
    """A full authorization code flow: WDash -> Dex -> the same directory.

    No listening server. The redirect URI never has to be reachable — the
    code arrives in a `Location` header and is handed to the app through the
    test client, which is carrying the session cookie the callback checks.
    """

    def setUp(self):
        database = os.path.join(tempfile.mkdtemp(), "identity.db")

        class OidcConfig(Config):
            TESTING = True
            SECRET_KEY = "identity-lab"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()

        self.app = create_app(OidcConfig)
        # The provider as the configuration page stores it, which is the
        # only way one reaches WDash.
        self.app.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": f"{DEX_URL}/.well-known/openid-configuration",
            "redirect_uri": "http://127.0.0.1:5001/auth/callback"},
            secret="wdash-lab-secret")
        # Until an administrator exists every route leads to /setup, including
        # the one that starts the flow.
        password = "correct-horse-battery"
        self.app.test_client().post("/setup", data={"username": "owner",
                                                    "password": password,
                                                    "confirm": password})

    def _sign_in(self, username, password):
        """Returns the client once the callback has been handled, or None if
        the provider refused."""
        import requests

        client = self.app.test_client()
        start = client.get("/auth/oidc")
        self.assertEqual(start.status_code, 302)

        session = requests.Session()
        url, method, data = start.headers["Location"], "GET", None
        # Walked rather than followed: something else may be listening on the
        # redirect URI's port, and `allow_redirects` would hand it the code.
        for _ in range(12):
            response = session.request(method, url, data=data,
                                       allow_redirects=False, timeout=10)
            if response.is_redirect:
                url = urllib.parse.urljoin(url, response.headers["Location"])
                method, data = "GET", None
                if url.startswith("http://127.0.0.1:5001"):
                    break
                continue
            form = re.search(r'action="([^"]*)"', response.text)
            self.assertIsNotNone(form, f"no form and no redirect at {url}")
            # Unescaped: the action is HTML, so `&` arrives as `&amp;`, and
            # posted as written the provider reads a parameter named
            # `amp;state`, finds no state, and refuses — which looks exactly
            # like a wrong password.
            action = urllib.parse.urljoin(url, html.unescape(form.group(1)))
            if "approval" in action:
                url, method, data = action, "POST", {"approval": "approve"}
            else:
                url, method = action, "POST"
                data = {"login": username, "password": password}
        else:
            # A refused password leaves the provider re-rendering its login
            # form, which is a refusal rather than a broken flow. Anything
            # else that runs out of steps is the lab being wrong, and should
            # say so rather than read as "wrong password".
            if "password" in response.text.lower():
                return None
            self.fail(f"the flow never reached the redirect URI: {url}")

        query = urllib.parse.urlparse(url).query
        if "code=" not in query:
            return None
        client.get(f"/auth/callback?{query}")
        return client

    def _role(self, client):
        page = client.get("/logs").get_data(as_text=True)
        found = re.search(r"Role:\s*([a-z-]+)", page)
        return found.group(1) if found else None

    def test_a_directory_group_decides_the_role(self):
        """The whole point. Without the `groups` scope every one of these was
        `viewer`, and nothing said so."""
        for username, role in (("alice", "admin"), ("bob", "developer"),
                               ("carol", "viewer")):
            with self.subTest(username=username):
                client = self._sign_in(username, PASSWORD)
                self.assertIsNotNone(client, "the provider refused")
                self.assertEqual(self._role(client), role)

    def test_belonging_to_nothing_lands_on_the_default_role(self):
        client = self._sign_in("dave", PASSWORD)
        self.assertIsNotNone(client)
        self.assertEqual(self._role(client), "viewer")

    def test_a_wrong_password_never_reaches_the_callback(self):
        self.assertIsNone(self._sign_in("alice", "not-the-password"))

    def test_the_same_person_reaches_the_same_role_by_either_path(self):
        """One source of identity truth, two paths to it. If these disagree,
        one of the two is wrong — and each is written by a different half of
        this project."""
        for username, _ in PEOPLE.items():
            with self.subTest(username=username):
                directory = authenticate(SETTINGS, username, PASSWORD)
                names = [g for g in directory["groups"] if "=" not in g]

                client = self._sign_in(username, PASSWORD)
                self.assertIsNotNone(client)
                through_the_provider = self._role(client)

                with self.app.app_context():
                    # By keyword. `resolve`'s first parameter is `email`, so
                    # passing the groups positionally resolves an identity
                    # with no groups at all — which returns the default role
                    # and makes this test look like a product bug.
                    expected = self.app.store.rbac.resolve(groups=tuple(names))
                self.assertEqual(through_the_provider, expected["role"])


if __name__ == "__main__":
    unittest.main()
