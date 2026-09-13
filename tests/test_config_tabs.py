"""
Authentication is three tabs, and a link to one of them arrives.

It was one pane holding an OIDC card, an LDAP card and — since local
accounts got a screen — the Local accounts card, stacked. Three unrelated
things under one heading, the third of them below the fold, and no way to
send anybody to any of them: the page's hash mechanism knew two tabs by
name, `#tab-monitors` and `#tab-alerts`, each written out in its own copy
of the same four lines, and Authentication had neither copy. Every save on
it therefore returned somebody to Sources.

What these hold:

  * three panes inside `#tab-auth`, exactly one of them open;
  * the hash opens the one it names, and the tab it sits inside — showing
    a sub-pane while its parent is hidden opens nothing anybody can see;
  * the deep links that already existed still land where they meant to,
    `#tab-monitors` and `#tab-alerts` included;
  * the "one directory at a time" notice is readable from all three,
    because it says which directory is in force and which is shadowed and
    somebody on the LDAP tab is exactly who needs to know;
  * every save and every refusal comes back to its own card.

The last of those is a test client reading `Location`; the rest need a
browser, because "which pane is open" is a question about what is painted
and Bootstrap decides it.
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
from wdash.store import SecretBox  # noqa: E402

PASSWORD = "a-sufficiently-long-password"

#: The three, in the order the strip shows them.
SUB_TABS = ("#tab-auth-oidc", "#tab-auth-ldap", "#tab-auth-local")


def _playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False


class TabTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)

        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "config-tabs"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key
            OIDC_CLIENT_ID = None

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        support.set_up(self.client, username="owner", password=PASSWORD)

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def page(self):
        answer = self.client.get("/admin/config")
        self.assertEqual(answer.status_code, 200)
        return answer.get_data(as_text=True)


class ThePaneIsThreePanesTest(TabTestCase):
    """What the server renders, before any script has run."""

    def test_the_strip_offers_all_three(self):
        html = self.page()
        for target in SUB_TABS:
            self.assertIn(f'data-bs-target="{target}"', html,
                          f"nothing opens {target}")

    def test_there_are_three_panes_and_one_is_open(self):
        html = self.page()
        open_ = [target for target in SUB_TABS
                 if re.search(r'<div class="tab-pane fade show active" '
                              r'id="%s"' % target[1:], html)]
        present = [target for target in SUB_TABS
                   if f'id="{target[1:]}"' in html]
        self.assertEqual(present, list(SUB_TABS), html[:0])
        self.assertEqual(open_, ["#tab-auth-oidc"],
                         f"{len(open_)} sub-panes start open: {open_}")

    def test_the_cards_moved_rather_than_being_copied(self):
        """One of each. A split that duplicates a form gives the page two
        Save buttons writing the same setting."""
        html = self.page()
        for name, times in (("Save OIDC settings", 1),
                            ("Save LDAP settings", 1),
                            ('id="localAccounts"', 1)):
            self.assertEqual(html.count(name), times, name)

    def test_the_directory_rule_is_outside_all_three(self):
        """It says which directory is in force and which is shadowed.
        Inside a pane it would be three copies or two people who never see
        it."""
        html = self.page()
        self.assertEqual(html.count("At most one directory signs people in"),
                         1)
        # After the last sub-pane closes: inside `#tab-auth`, outside the
        # nested content.
        notice = html.index('id="directoryRule"')
        for target in SUB_TABS:
            self.assertLess(html.index(f'id="{target[1:]}"'), notice, target)


class EverySaveComesBackToItsOwnCardTest(TabTestCase):
    """A save that lands on another tab is a flash nobody reads."""

    def _where(self, answer):
        self.assertEqual(answer.status_code, 302)
        return answer.headers["Location"]

    def test_an_oidc_save_returns_to_the_oidc_card(self):
        answer = self.client.post("/admin/auth", data={"provider": "oidc"})
        self.assertTrue(self._where(answer).endswith("#tab-auth-oidc"),
                        self._where(answer))

    def test_an_ldap_save_returns_to_the_ldap_card(self):
        answer = self.client.post("/admin/auth", data={"provider": "ldap"})
        self.assertTrue(self._where(answer).endswith("#tab-auth-ldap"),
                        self._where(answer))

    def test_a_refused_save_returns_there_too(self):
        """The refusal is the sentence somebody most needs to read, and it
        is rendered at the top of whatever page they land on."""
        answer = self.client.post("/admin/auth", data={
            "provider": "ldap", "enabled": "on", "verify_certs": "on",
            "server": "ldaps://ldap.example.com", "base_dn": "dc=example",
            "ca_certs": "/no/such/ca.pem"})
        self.assertTrue(self._where(answer).endswith("#tab-auth-ldap"),
                        self._where(answer))

    def test_an_unknown_provider_returns_to_the_tab(self):
        answer = self.client.post("/admin/auth", data={"provider": "nonsense"})
        self.assertTrue(self._where(answer).endswith("#tab-auth"),
                        self._where(answer))

    def test_every_account_route_returns_to_local_accounts(self):
        self.app.store.users.create("reader", "a-long-enough-password",
                                    "viewer", email="reader@example.com")
        routes = (
            ("/admin/accounts", {"username": "", "role": "viewer"}),
            ("/admin/accounts/reader", {"role": "admin"}),
            ("/admin/accounts/reader/disable", {}),
            ("/admin/accounts/reader/enable", {}),
            ("/admin/accounts/reader/password", {"password": "x" * 14,
                                                 "confirm": "x" * 14}),
            ("/admin/accounts/reader/totp/reset", {}),
            ("/admin/accounts/reader/delete", {}),
        )
        for route, form in routes:
            with self.subTest(route=route):
                answer = self.client.post(route, data=form)
                self.assertTrue(
                    self._where(answer).endswith("#tab-auth-local"),
                    f"{route} -> {self._where(answer)}")

    def test_the_links_that_already_existed_are_untouched(self):
        """`#tab-monitors` and `#tab-alerts` were the only two the page
        knew, and the mechanism that opens them is the one being
        rewritten."""
        source = self.client.post("/admin/agents", data={"name": "berlin"})
        self.assertTrue(self._where(source).endswith("#tab-monitors"),
                        self._where(source))
        channel = self.client.post("/admin/channels", data={
            "name": "ops", "kind": "webhook", "url": "https://example.com/x"})
        self.assertTrue(self._where(channel).endswith("#tab-alerts"),
                        self._where(channel))


#: Which panes are painted, and which strip item is marked.
MEASURE_PANES = r"""() => {
  const shown = (id) => {
    const pane = document.getElementById(id);
    return !!(pane && pane.getClientRects().length);
  };
  const marked = [...document.querySelectorAll('[data-bs-target]')]
      .filter(b => b.classList.contains('active'))
      .map(b => b.getAttribute('data-bs-target'));
  return {
    outer: ['tab-sources', 'tab-auth', 'tab-monitors', 'tab-alerts',
            'tab-roles'].filter(shown),
    inner: ['tab-auth-oidc', 'tab-auth-ldap', 'tab-auth-local'].filter(shown),
    marked: marked,
    notice: shown('directoryRule'),
  };
}"""


@unittest.skipUnless(_playwright(), "playwright is not installed")
class TheHashOpensTheTabItNamesTest(unittest.TestCase):
    """Which pane is open is a question about what is painted."""

    @classmethod
    def setUpClass(cls):
        from tests.support import grant, serve_in_background
        from werkzeug.serving import make_server

        database = os.path.join(tempfile.mkdtemp(), "config-tabs.db")

        class TabConfig(Config):
            SECRET_KEY = "config-tabs-browser"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            DASHBOARD_STORAGE = "database"

        cls.app = create_app(TabConfig)
        cls.secret = support.set_up(cls.app.test_client(), username="admin",
                                    password=PASSWORD)
        grant(cls.app, "admin", ["system:admin", "monitors:read"])
        cls.app.store.settings.set("rbac.user_roles", {"admin": "test-role"})
        cls.app.store.rbac.invalidate()

        cls.server = serve_in_background(
            make_server("127.0.0.1", 0, cls.app, threaded=True))
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _land(self, hashes):
        from playwright.sync_api import sync_playwright

        seen = {}
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context(
                viewport={"width": 1500, "height": 1000}).new_page()
            support.sign_in_in_browser(page, self.base, "admin", PASSWORD,
                                       self.secret, app=self.app)
            for fragment in hashes:
                page.goto(f"{self.base}/admin/config{fragment}",
                          wait_until="networkidle")
                # Loaded with the fragment already in the URL, which is the
                # case a link somebody was SENT produces. A `goto` that
                # only changes the fragment loads nothing — the page is
                # already open — so without this every fragment after the
                # first would be measuring the first one's page.
                page.reload(wait_until="networkidle")
                # The pane fades in; Bootstrap paints it over 150ms.
                page.wait_for_timeout(400)
                seen[fragment] = page.evaluate(MEASURE_PANES)
            browser.close()
        return seen

    def test_a_link_to_a_sub_tab_lands_on_it(self):
        seen = self._land(SUB_TABS)
        for fragment, state in seen.items():
            with self.subTest(hash=fragment):
                # Its parent too: a sub-pane shown inside a hidden pane is
                # nothing anybody can see.
                self.assertEqual(state["outer"], ["tab-auth"], state)
                self.assertEqual(state["inner"], [fragment[1:]], state)
                self.assertIn("#tab-auth", state["marked"], state)
                self.assertIn(fragment, state["marked"], state)

    def test_the_tab_itself_still_opens_on_its_first_card(self):
        state = self._land(["#tab-auth"])["#tab-auth"]
        self.assertEqual(state["outer"], ["tab-auth"], state)
        self.assertEqual(state["inner"], ["tab-auth-oidc"], state)

    def test_the_directory_rule_is_readable_from_all_three(self):
        for fragment, state in self._land(SUB_TABS).items():
            with self.subTest(hash=fragment):
                self.assertTrue(state["notice"],
                                f"{fragment}: the directory rule is hidden")

    def test_the_links_that_already_existed_still_arrive(self):
        seen = self._land(["#tab-monitors", "#tab-alerts", "#tab-sources"])
        for fragment, state in seen.items():
            with self.subTest(hash=fragment):
                self.assertEqual(state["outer"], [fragment[1:]], state)
                self.assertIn(fragment, state["marked"], state)

    def test_the_strip_is_three_things_somebody_can_click(self):
        """A tab reachable only by its URL is not a tab.

        Everything else here drives the panes through the hash, which a
        trigger nobody can see answers just as well — so this clicks.
        """
        from playwright.sync_api import sync_playwright

        seen = {}
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context(
                viewport={"width": 1500, "height": 1000}).new_page()
            support.sign_in_in_browser(page, self.base, "admin", PASSWORD,
                                       self.secret, app=self.app)
            page.goto(f"{self.base}/admin/config#tab-auth",
                      wait_until="networkidle")
            page.wait_for_timeout(400)
            for target in SUB_TABS:
                trigger = page.locator(f'[data-bs-target="{target}"]')
                seen[target] = {"visible": trigger.is_visible(),
                                "label": trigger.inner_text().strip()}
                if seen[target]["visible"]:
                    trigger.click()
                    page.wait_for_timeout(400)
                    seen[target]["after"] = page.evaluate(MEASURE_PANES)
            browser.close()

        for target, state in seen.items():
            with self.subTest(tab=target):
                self.assertTrue(state["visible"],
                                f"{target} has no control anybody can see")
                self.assertTrue(state["label"],
                                f"{target}'s control has no words on it")
                self.assertEqual(state["after"]["inner"], [target[1:]], state)

    def test_a_link_followed_from_inside_the_page_moves_the_tab(self):
        """Changing the fragment loads nothing. The call on load would
        never run again, so the URL would change and the screen would
        not."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context(
                viewport={"width": 1500, "height": 1000}).new_page()
            support.sign_in_in_browser(page, self.base, "admin", PASSWORD,
                                       self.secret, app=self.app)
            page.goto(f"{self.base}/admin/config", wait_until="networkidle")
            page.wait_for_timeout(300)
            before = page.evaluate(MEASURE_PANES)
            page.evaluate("() => { window.location.hash = 'tab-auth-local'; }")
            page.wait_for_timeout(500)
            after = page.evaluate(MEASURE_PANES)
            browser.close()

        self.assertEqual(before["outer"], ["tab-sources"], before)
        self.assertEqual(after["outer"], ["tab-auth"], after)
        self.assertEqual(after["inner"], ["tab-auth-local"], after)

    def test_a_hash_that_names_nothing_leaves_the_page_as_it_was(self):
        """`openTab` is handed whatever is in the URL. A fragment naming a
        card, an anchor or nothing at all must not throw and must not close
        the tab the page opens on."""
        seen = self._land(["", "#localAccounts", "#nothing-here"])
        for fragment, state in seen.items():
            with self.subTest(hash=fragment):
                self.assertEqual(state["outer"], ["tab-sources"], state)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(
        "Run this through the runner: ./venv/bin/python -m unittest "
        "tests.test_config_tabs")
