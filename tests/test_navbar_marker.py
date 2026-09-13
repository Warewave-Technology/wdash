"""
Which page you are on, in the one landmark this product has.

Measured across every screen the day this was written: not one
`.navbar .nav-link` carried `active`, and not one carried `aria-current`.
Logs, Dashboards, Traces, Monitors and Alerts were five identical links
whichever of them was open — and somebody navigating by landmarks was
told nothing at all, which is worse than the sighted case: at least a
sighted reader has the heading under the bar to go on.

What these hold:

  * exactly one entry is marked, on every page, and it is the right one;
  * it is marked BOTH ways — the class the stylesheet paints, and
    `aria-current="page"`, which is the half a screen reader reads;
  * a detail page counts as its section. `/monitors/42` is Monitors and
    `/dashboard/create` is Dashboards, or the marker disappears exactly
    when somebody has gone somewhere and most wants to know where;
  * it is decided from the REQUEST. A flag passed by each template is a
    flag a later page forgets, and a page with no marker is what this
    commit is about;
  * the three administration pages are marked too. They are in the
    account menu rather than the strip, so the item carries
    `aria-current="page"` and the control that opens the menu is marked
    as holding the page — a menu that says nothing while the page inside
    it is open is the same fault one level down.

`tests/test_rendered_pages.py` measures what the marker is painted in,
in both themes, along with everything else on the screen. This measures
where it is.
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

#: Every page that renders the navbar, and the entry each one belongs to.
#: The label is what the link says, which is what a reader is looking for.
PAGES = (
    ("/logs", "Logs"),
    ("/dashboards", "Dashboards"),
    ("/dashboard/create", "Dashboards"),
    ("/traces", "Traces"),
    ("/monitors", "Monitors"),
    ("/alerts", "Alerts"),
    ("/admin/config", "Configuration"),
    ("/admin/audit", "Audit trail"),
    ("/advisor", "Cluster Advisor"),
)

#: The entries that live in the account menu rather than in the strip.
IN_THE_MENU = {"Configuration", "Audit trail", "Cluster Advisor"}


class NavbarTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)

        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "navbar-marker"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key
            DASHBOARD_STORAGE = "database"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        support.set_up(self.client, username="owner", password=PASSWORD)
        support.grant(self.app, "owner",
                      ["system:admin", "logs:read", "traces:read",
                       "monitors:read", "dashboard:view", "dashboard:create"],
                      indices=["*"])

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def navbar(self, url):
        answer = self.client.get(url)
        self.assertEqual(answer.status_code, 200, f"{url}: {answer.status}")
        html = answer.get_data(as_text=True)
        start = html.index("<nav")
        return html[start:html.index("</nav>", start)]

    def _marked(self, url):
        """Every navbar entry carrying the class, and every one carrying
        the attribute, as the words a reader sees."""
        bar = self.navbar(url)
        anchors = re.findall(r"<a\b[^>]*>(.*?)</a>", bar, re.S)
        opens = re.findall(r"<a\b[^>]*>", bar)
        by_class, by_aria = [], []
        for tag, body in zip(opens, anchors):
            words = " ".join(re.sub(r"<[^>]+>", " ", body).split())
            if re.search(r'class="[^"]*\bactive\b', tag):
                by_class.append(words)
            if 'aria-current="page"' in tag:
                by_aria.append(words)
        return by_class, by_aria


class ExactlyOnePageIsMarkedTest(NavbarTestCase):
    def test_every_page_says_which_one_it_is(self):
        for url, label in PAGES:
            with self.subTest(page=url):
                by_class, by_aria = self._marked(url)
                self.assertEqual(
                    len(by_aria), 1,
                    f"{url}: {len(by_aria)} entries announce themselves as "
                    f"the page: {by_aria}")
                self.assertIn(label, by_aria[0],
                              f"{url}: announced as {by_aria[0]!r}")

    def test_the_marker_is_visible_as_well_as_announced(self):
        """`aria-current` alone paints nothing, and the class alone says
        nothing. The bar is the one landmark this product has and both
        halves of it have to work."""
        for url, label in PAGES:
            with self.subTest(page=url):
                by_class, by_aria = self._marked(url)
                self.assertTrue(any(label in words for words in by_class),
                                f"{url}: nothing visible is marked: {by_class}")

    def test_a_detail_page_is_still_its_section(self):
        """A marker that disappears the moment somebody has gone
        somewhere is a marker that is missing where it is most wanted."""
        self.app.store.monitors.create("checkout", "http",
                                       "https://example.com/health")
        monitor = self.app.store.monitors.all()[0]
        _, by_aria = self._marked(f"/monitors/{monitor['id']}")
        self.assertEqual(len(by_aria), 1, by_aria)
        self.assertIn("Monitors", by_aria[0])

    def test_the_menu_says_it_holds_the_page(self):
        """Configuration, the audit trail and the advisor are in the
        account menu rather than the strip. The item announces itself;
        the control that opens the menu is marked as holding it, so a
        closed navbar still says where you are."""
        for url, label in PAGES:
            with self.subTest(page=url):
                by_class, _ = self._marked(url)
                bar = self.navbar(url)
                toggle = re.search(
                    r'<a\b[^>]*dropdown-toggle[^>]*>', bar).group(0)
                held = bool(re.search(r'class="[^"]*\bactive\b', toggle))
                wanted = label in IN_THE_MENU
                self.assertEqual(
                    held, wanted,
                    f"{url}: the menu says it holds this page: {held}; "
                    f"it should: {wanted}")

    def test_the_toggle_does_not_claim_to_be_the_page(self):
        """It opens a menu. `aria-current="page"` on it would be a lie,
        and the item inside is where the truth goes."""
        for url, _ in PAGES:
            with self.subTest(page=url):
                toggle = re.search(r'<a\b[^>]*dropdown-toggle[^>]*>',
                                   self.navbar(url)).group(0)
                self.assertNotIn("aria-current", toggle, url)

    def test_the_sign_in_page_marks_nothing(self):
        """Nobody is anywhere yet, and the bar carries a Login link and a
        theme menu. A marker here would name a page that is not open."""
        client = self.app.test_client()
        bar = self.navbar_of(client, "/auth/login")
        self.assertNotIn('aria-current="page"', bar)

    def navbar_of(self, client, url):
        answer = client.get(url)
        html = answer.get_data(as_text=True)
        start = html.index("<nav")
        return html[start:html.index("</nav>", start)]


class ItIsDecidedFromTheRequestTest(NavbarTestCase):
    """A flag each template passes is a flag a later page forgets."""

    def test_no_template_hands_the_navbar_its_answer(self):
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        offenders = []
        for name in sorted(os.listdir(os.path.join(root, "templates"))):
            if not name.endswith(".html") or name == "base.html":
                continue
            with open(os.path.join(root, "templates", name)) as handle:
                text = handle.read()
            for number, line in enumerate(text.splitlines(), start=1):
                if re.search(r"{%\s*set\s+(nav_\w+|active_\w+|\w*_active)\s*=",
                             line):
                    offenders.append(f"{name}:{number}: {line.strip()}")
        self.assertEqual(offenders, [], "\n".join(
            ["a template tells the navbar which page it is:"] + offenders))

    def test_a_page_nobody_wrote_a_rule_for_marks_nothing_and_does_not_break(
            self):
        """`/` redirects and `/setup` is closed, but a page outside every
        section still has to render a navbar rather than a stack trace."""
        answer = self.client.get("/health")
        self.assertEqual(answer.status_code, 200)

    def test_the_navbar_only_ever_marks_what_the_person_can_reach(self):
        """The strip is drawn from permissions. A marker on a link that
        is not rendered is not a risk; a crash deciding one is."""
        self.app.store.roles.upsert(
            support.TEST_ROLE, permissions=["system:admin", "logs:read"],
            containers=["*"], trace_containers=["*"])
        self.app.store.rbac.invalidate()
        _, by_aria = self._marked("/logs")
        self.assertEqual(len(by_aria), 1, by_aria)
        self.assertIn("Logs", by_aria[0])


#: What the marked link is actually painted as, against its neighbours.
MEASURE_NAVBAR = r"""() => {
  const links = [...document.querySelectorAll('.navbar-nav > .nav-link')];
  const read = (el) => {
    const s = getComputedStyle(el);
    return {
      words: (el.textContent || '').trim(),
      marked: el.classList.contains('active'),
      colour: s.color,
      weight: s.fontWeight,
      shadow: s.boxShadow,
    };
  };
  return links.map(read);
}"""

#: The account menu, opened, and what its marked item is painted as. It has
#: to be opened: a closed menu paints nothing, and the audit in
#: tests/test_rendered_pages.py walks past every element with no box —
#: which is how `.dropdown-item.active` sat in Bootstrap's own blue with
#: nothing in the product able to see it.
MEASURE_MENU = r"""() => {
  // The menu that is OPEN. The navbar carries a second one for the theme,
  // whose items are shut and whose chosen option is marked the same way —
  // reading every `.dropdown-item` in the bar measures three invisible
  // rows and a second marker.
  return [...document.querySelectorAll('.dropdown-menu.show .dropdown-item')]
      .map(el => {
        const s = getComputedStyle(el);
        return {
          words: (el.textContent || '').trim(),
          marked: el.classList.contains('active'),
          colour: s.color,
          ground: s.backgroundColor,
          shadow: s.boxShadow,
          painted: !!el.getClientRects().length,
        };
      });
}"""


def _playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(_playwright(), "playwright is not installed")
class TheMarkerIsPaintedTest(unittest.TestCase):
    """A class the stylesheet never reaches marks nothing.

    `.navbar-nav .nav-link` sets its colour with `!important`, which an
    `.active` rule without one loses to: the markup would say the page and
    the screen would not. Measured in both themes, because the marker is
    a colour and this product has two palettes.
    """

    @classmethod
    def setUpClass(cls):
        from tests.support import grant, serve_in_background
        from werkzeug.serving import make_server

        database = os.path.join(tempfile.mkdtemp(), "navbar.db")

        class BarConfig(Config):
            SECRET_KEY = "navbar-painted"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            DASHBOARD_STORAGE = "database"

        cls.app = create_app(BarConfig)
        cls.secret = support.set_up(cls.app.test_client(), username="admin",
                                    password=PASSWORD)
        grant(cls.app, "admin", ["system:admin", "logs:read", "traces:read",
                                 "monitors:read", "dashboard:view"],
              indices=["*"])
        cls.app.store.settings.set("rbac.user_roles", {"admin": "test-role"})
        cls.app.store.rbac.invalidate()

        cls.server = serve_in_background(
            make_server("127.0.0.1", 0, cls.app, threaded=True))
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_the_marked_link_does_not_look_like_the_others(self):
        from playwright.sync_api import sync_playwright

        seen = {}
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context(
                viewport={"width": 1500, "height": 1000}).new_page()
            support.sign_in_in_browser(page, self.base, "admin", PASSWORD,
                                       self.secret, app=self.app)
            for url in ("/logs", "/monitors", "/alerts"):
                page.goto(self.base + url, wait_until="networkidle")
                for theme in ("dark", "light"):
                    page.evaluate(f"window.wdashTheme.set('{theme}')")
                    page.wait_for_timeout(250)
                    seen[f"{theme} {url}"] = page.evaluate(MEASURE_NAVBAR)
            browser.close()

        for where, links in seen.items():
            with self.subTest(page=where):
                marked = [link for link in links if link["marked"]]
                plain = [link for link in links if not link["marked"]]
                self.assertEqual(len(marked), 1, links)
                self.assertTrue(plain, links)
                here = marked[0]
                for other in plain:
                    self.assertNotEqual(here["colour"], other["colour"],
                                        f"{where}: same ink as {other['words']}")
                # Not colour alone. Somebody who cannot tell the two hues
                # apart still has to be able to see which one it is.
                self.assertNotIn(here["shadow"], ("none", ""),
                                 f"{where}: the marker is colour and nothing "
                                 f"else: {here}")
                self.assertGreater(int(here["weight"]),
                                   int(plain[0]["weight"]), here)

    def test_the_menu_item_is_this_palette_rather_than_bootstraps(self):
        """`.dropdown-item.active` is a blue fill with white text in
        Bootstrap, and the menu is shut, so the audit that walks every
        screen never sees it: it skips anything with no box."""
        from playwright.sync_api import sync_playwright

        seen = {}
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context(
                viewport={"width": 1500, "height": 1000}).new_page()
            support.sign_in_in_browser(page, self.base, "admin", PASSWORD,
                                       self.secret, app=self.app)
            for url in ("/admin/config", "/admin/audit"):
                page.goto(self.base + url, wait_until="networkidle")
                page.click(".navbar-nav .dropdown-toggle")
                page.wait_for_timeout(300)
                for theme in ("dark", "light"):
                    page.evaluate(f"window.wdashTheme.set('{theme}')")
                    page.wait_for_timeout(250)
                    seen[f"{theme} {url}"] = page.evaluate(MEASURE_MENU)
            browser.close()

        for where, items in seen.items():
            with self.subTest(page=where):
                self.assertTrue(items, where)
                self.assertTrue(all(item["painted"] for item in items),
                                f"{where}: the menu did not open: {items}")
                marked = [item for item in items if item["marked"]]
                plain = [item for item in items if not item["marked"]]
                self.assertEqual(len(marked), 1, items)
                here = marked[0]
                for other in plain:
                    self.assertNotEqual(here["colour"], other["colour"],
                                        f"{where}: same ink as {other['words']}")
                # Not a filled row. Bootstrap paints this one as a solid
                # block of its primary, which is a colour this palette
                # never uses.
                self.assertIn(here["ground"],
                              ("rgba(0, 0, 0, 0)", "transparent"),
                              f"{where}: the item is filled: {here}")
                self.assertNotIn(here["shadow"], ("none", ""), here)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(
        "Run this through the runner: ./venv/bin/python -m unittest "
        "tests.test_navbar_marker")
