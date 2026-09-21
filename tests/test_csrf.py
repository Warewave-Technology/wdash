"""
Cross-site request forgery, and the token that stops it.

There was none. `SameSite=Lax` cookies were the whole defence, and the
README said so rather than claiming otherwise — which is how this came to be
the next thing to fix instead of a surprise. Lax is a real defence and a
single one: it is a browser default a deployment can lose behind a proxy
that rewrites the cookie, it does nothing about a same-site subdomain, and
it is the wrong shape for the one place it matters most — the sign-in form,
where an attacker does not need your cookie because they are trying to give
you theirs.

Flask-WTF had been installed and never initialised while five test
configurations set `WTF_CSRF_ENABLED = False`, so the suite read as
"protection is on in production, off for tests" about a protection that was
never on anywhere. Both were removed. What replaces them is here, and the
suite does NOT switch it off: every test client carries the token the way a
browser does (see `tests/__init__.py`), and the tests below are the ones
that deliberately do not.

Three properties, and the third is the one that lasts:

  * a state-changing request without the token is refused;
  * the exemption list is short, written down, and about requests that carry
    no ambient authority to borrow;
  * every POST route and every POST form is held to it by enumeration, so a
    new one is protected before anybody remembers it exists.
"""

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.security import (  # noqa: E402
    EXEMPT_BLUEPRINTS, EXEMPT_ENDPOINTS, FIELD, GUARDED_METHODS, HEADER,
)
from wdash.store.secrets import SecretBox  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
PASSWORD = "correct-horse-battery"


class CsrfTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "csrf"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.secret = support.set_up(self.client, username="owner",
                                     password=PASSWORD)

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def token(self):
        """This client's token, issued if the session has none.

        Signing in clears the session, token included, so a client that has
        not rendered a page since has nothing to send — which is exactly
        what a browser would be in, and it gets one from the next page it
        loads. This is that page.
        """
        import secrets
        with self.client.session_transaction() as session:
            value = session.get(FIELD)
            if not value:
                value = secrets.token_urlsafe(32)
                session[FIELD] = value
            return value

    def mappings(self):
        return self.app.store.settings.get("rbac.user_roles") or {}


class ARequestWithoutTheTokenIsRefusedTest(CsrfTestCase):
    def test_a_form_post_with_no_token_changes_nothing(self):
        response = self.client.post(
            "/admin/mappings/entry",
            data={"identifier": "mallory", "role": "admin", "original": ""},
            csrf=False)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.mappings(), {},
                         "the request went through anyway")

    def test_the_refusal_says_what_happened_and_what_to_do(self):
        """A bare 400 sends somebody to an administrator for a page they
        left open too long."""
        page = self.client.post("/admin/mappings",
                                data={FIELD: "not-the-real-token"},
                                csrf=False).get_data(as_text=True)
        self.assertIn("security token", page)
        self.assertIn("Nothing was changed", page)
        # It does carry the session's own token, in the meta tag every page
        # has, and that is not a leak: a cross-origin caller cannot read
        # this response at all, and the browser that CAN read it is the one
        # whose token it is. What must not appear is the token that was
        # submitted, which would be reflecting an attacker's own input.
        self.assertNotIn("not-the-real-token", page)

    def test_a_token_from_somebody_elses_session_is_refused(self):
        other = self.app.test_client()
        other.get("/auth/login")            # issues a token of its own
        with other.session_transaction() as session:
            stolen = session.get(FIELD)
        self.assertTrue(stolen)
        self.assertNotEqual(stolen, self.token())

        response = self.client.post(
            "/admin/mappings/entry",
            data={"identifier": "mallory", "role": "admin",
                  FIELD: stolen}, csrf=False)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.mappings(), {})

    def test_a_prefix_of_the_token_is_not_the_token(self):
        """Compared whole and in constant time. A comparison that stopped at
        the first difference would leak it a character at a time."""
        response = self.client.post(
            "/admin/mappings/entry",
            data={"identifier": "mallory", "role": "admin",
                  FIELD: self.token()[:-1]}, csrf=False)
        self.assertEqual(response.status_code, 400)

    def test_an_api_call_is_refused_as_json(self):
        """A fetch that gets an HTML page back reports "unexpected token <"
        in a console nobody has open."""
        response = self.client.post("/api/dashboards/x/data", json={},
                                    csrf=False)
        self.assertEqual(response.status_code, 400)
        self.assertIn("security token", response.get_json()["error"])


class ARequestWithTheTokenGoesThroughTest(CsrfTestCase):
    def test_in_the_form_field(self):
        response = self.client.post(
            "/admin/mappings/entry",
            data={"identifier": "carol", "role": "viewer", "original": "",
                  FIELD: self.token()},
            csrf=False, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.mappings(), {"carol": "viewer"})

    def test_in_the_header(self):
        """Where `fetch` puts it. The shim in base.html adds it to every
        same-origin state-changing call."""
        response = self.client.post(
            "/admin/mappings/entry",
            data={"identifier": "carol", "role": "viewer", "original": ""},
            headers={HEADER: self.token()}, csrf=False, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.mappings(), {"carol": "viewer"})

    def test_a_get_is_never_refused(self):
        """The guard is over the verbs that change something. A GET that
        changes something is a different bug and this is not its fix."""
        self.assertEqual(self.client.get("/admin/config").status_code, 200)

    def test_the_page_carries_one_to_carry_back(self):
        page = self.client.get("/admin/config").get_data(as_text=True)
        self.assertIn(f'name="{FIELD}"', page)
        self.assertIn('name="csrf-token"', page, "no meta tag for fetch")
        self.assertIn(self.token(), page)


class TheTokenBelongsToTheSessionTest(CsrfTestCase):
    def test_signing_in_replaces_it(self):
        """Session fixation. An attacker who plants a token in somebody's
        pre-sign-in session — one they chose, and therefore know — must not
        still hold a valid one for the session that person signs in to.

        `_start_session` clears the whole session, which is what does it;
        this pins that, because a later edit that kept "just the useful
        keys" would keep this one.
        """
        self.client.get("/auth/logout")
        before = self.token() or ""
        self.client.get("/auth/login")
        before = self.token()
        support.sign_in(self.client, "owner", PASSWORD, self.secret,
                        app=self.app)
        self.assertNotEqual(self.token(), before,
                            "the pre-sign-in token survived sign-in")

    def test_a_token_from_before_sign_out_is_refused_after(self):
        stale = self.token()
        self.client.get("/auth/logout")
        support.sign_in(self.client, "owner", PASSWORD, self.secret,
                        app=self.app)
        response = self.client.post(
            "/admin/mappings/entry",
            data={"identifier": "mallory", "role": "admin", FIELD: stale},
            csrf=False)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.mappings(), {})

    def test_one_session_keeps_one_token_across_requests(self):
        """Re-issued per request, a form rendered on one page would be
        refused by the next — which is how a protection gets switched off
        for being unusable."""
        first = self.client.get("/admin/config") and self.token()
        self.client.get("/logs")
        self.assertEqual(self.token(), first)


class TheAgentIsExemptAndSaysWhyTest(CsrfTestCase):
    """The one exemption, and it is about ambient authority rather than
    about convenience: an agent sends a bearer token and no cookie, so
    there is nothing for another site to borrow — and no session to keep a
    CSRF token in, and no browser to read one out of a page."""

    def test_an_agent_can_still_report(self):
        agent, token = self.app.store.agents.create("frankfurt")
        response = self.client.post(
            "/api/agent/results", json={"results": []},
            headers={"Authorization": f"Bearer {token}"}, csrf=False)
        self.assertNotEqual(response.status_code, 400,
                            "the agent was refused for having no CSRF token")

    def test_and_without_its_bearer_token_it_is_still_refused(self):
        """Exempt from THIS check, not from authentication."""
        response = self.client.post("/api/agent/results", json={"results": []},
                                    csrf=False)
        self.assertEqual(response.status_code, 401)

    def test_the_exemptions_are_a_written_list(self):
        self.assertEqual(EXEMPT_BLUEPRINTS, ("agent",))
        self.assertEqual(EXEMPT_ENDPOINTS, ())


class EveryRouteAndEveryFormIsHeldToItTest(CsrfTestCase):
    """The part that outlives everybody who remembers writing it.

    Forty-one POST routes and thirty-six POST forms: a list of them is a
    list somebody forgets to add to, so neither is a list. The guard is over
    the METHOD, and these two tests are the enumeration that proves nothing
    slipped out from under it.
    """

    def guarded_rules(self):
        for rule in self.app.url_map.iter_rules():
            if set(rule.methods or ()) & set(GUARDED_METHODS):
                yield rule

    def test_there_are_enough_of_them_to_be_worth_checking(self):
        self.assertGreater(len(list(self.guarded_rules())), 30)

    def test_more_than_one_verb_is_in_use(self):
        """`GUARDED_METHODS` is four words and the test above would pass with
        one of them if every route were a POST. One is not — the saved
        searches are deleted with DELETE — so the list has something to be
        wrong about."""
        verbs = {method for rule in self.guarded_rules()
                 for method in (rule.methods or ())
                 if method in GUARDED_METHODS}
        self.assertGreater(len(verbs), 1, verbs)

    def test_every_state_changing_route_is_protected_or_named_exempt(self):
        for rule in self.guarded_rules():
            blueprint = (rule.endpoint.rsplit(".", 1)[0]
                         if "." in rule.endpoint else "")
            with self.subTest(endpoint=rule.endpoint):
                if (blueprint in EXEMPT_BLUEPRINTS
                        or rule.endpoint in EXEMPT_ENDPOINTS):
                    continue
                # The verb this rule actually takes. Probing everything
                # with POST hid the whole point of guarding by method: a
                # DELETE-only route answers a POST with 405 — after this
                # check has already refused it — so the guard could have
                # covered POST alone and nothing here would have noticed.
                method = next(m for m in GUARDED_METHODS
                              if m in (rule.methods or ()))
                response = self.client.open(rule.rule.replace("<", "1")
                                            .replace(">", ""),
                                            method=method, csrf=False)
                self.assertEqual(
                    response.status_code, 400,
                    f"{rule.endpoint} accepted a {method} with no token "
                    f"({response.status_code})")

    def test_every_post_form_in_every_template_carries_the_field(self):
        """The browser's half. A form without it is a button that always
        fails, which is worse than one that is not protected: it reads as a
        broken page rather than as a missing line."""
        forms = re.compile(r"<form\b[^>]*?method=[\"']post[\"'][^>]*?>",
                           re.I | re.S)
        found = 0
        for name in sorted(os.listdir(os.path.join(ROOT, "templates"))):
            if not name.endswith(".html"):
                continue
            with open(os.path.join(ROOT, "templates", name),
                      encoding="utf-8") as handle:
                text = handle.read()
            for match in forms.finditer(text):
                found += 1
                after = text[match.end():match.end() + 300]
                with self.subTest(template=name,
                                  form=text.count("\n", 0, match.start()) + 1):
                    self.assertIn(f'name="{FIELD}"', after,
                                  f"a POST form in {name} carries no token")
        self.assertGreater(found, 30, "the forms were not found at all")


if __name__ == "__main__":
    unittest.main()
