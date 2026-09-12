"""A records panel and a trace list, authored in a real browser.

tests/dashboard_form_smoke.js runs the editor's script under jsdom with its
Jinja values filled in by hand, which is where the control tables are
measured. It cannot say that the include is rendered by the real form, that
what the browser posts is what the server stores, or that a stored panel comes
back into its controls unharmed — three joins, three files, and the seam this
package closes ran right through them.

So this drives Chromium against the real create form and the real edit form:
add one of each new type, save, reload, read the controls back. The harness is
the one tests/test_rendered_pages.py already uses — an app on a port of its
own, a local account, a role from the store.

Needs playwright and skips without it.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

PASSWORD = "panel-editor-browser-password"

#: A service name nobody would type, chosen because every character in it is
#: one the editor has to carry through a quoted HTML attribute and back: the
#: quotes and the tag go into `value="..."`, and `escapeAttr` leaving `&`
#: alone is exactly how a title holding `&quot;` came back as a quote.
SERVICE = 'checkout "eu" & <b>west</b>'

#: How much room the Show select has for its selected option, and how much
#: that option needs — measured in the select's own computed font, because a
#: select clips silently: the text is in the DOM whatever the box is wide.
SELECT_ROOM = """
() => {
  const row = [...document.querySelectorAll('#panelList .list-group-item')]
      .find(r => r.querySelector('[data-key="service"]'));
  const select = row.querySelector('[data-key="view"]');
  const style = getComputedStyle(select);
  const ruler = document.createElement('span');
  ruler.style.cssText = 'position:absolute;visibility:hidden;white-space:pre';
  ruler.style.font = style.font;
  ruler.textContent = select.options[select.selectedIndex].textContent;
  document.body.appendChild(ruler);
  const text = ruler.getBoundingClientRect().width;
  ruler.remove();
  return {label: select.options[select.selectedIndex].textContent,
          text: Math.round(text),
          room: Math.round(select.getBoundingClientRect().width
                           - parseFloat(style.paddingLeft)
                           - parseFloat(style.paddingRight))};
}
"""

#: The trace list's row against a row with no trace list in it.
ROW_HEIGHTS = """
() => {
  const rows = [...document.querySelectorAll('#panelList .list-group-item')];
  const trace = rows.find(r => r.querySelector('[data-key="service"]'));
  const plain = rows.find(r => !r.querySelector('[data-key="service"]'));
  return {trace: Math.round(trace.getBoundingClientRect().height),
          plain: Math.round(plain.getBoundingClientRect().height)};
}
"""


def _playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(_playwright(), "playwright is not installed")
class PanelsAuthoredInABrowserTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        database = os.path.join(tempfile.mkdtemp(), "panel-editor.db")

        class EditorConfig(Config):
            SECRET_KEY = "panel-editor-browser"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        cls.app = create_app(EditorConfig)
        # Enrolled once here, through a test client: a local account needs an
        # authenticator, and every browser sign-in below uses the secret this
        # returns rather than enrolling again.
        cls.secret = support.set_up(cls.app.test_client(), username="admin",
                                    password=PASSWORD)
        grant(cls.app, "admin", ["system:admin", "logs:read", "traces:read",
                                 "dashboard:view", "dashboard:create",
                                 "dashboard:edit"], indices=["*"])
        cls.app.store.settings.set("rbac.user_roles", {"admin": "test-role"})
        cls.app.store.rbac.invalidate()

        # A port of its own: the parallel runner splits this file's class from
        # its neighbours' and two servers on one fixed port take each other's.
        from werkzeug.serving import make_server
        from tests.support import serve_in_background
        cls.server = serve_in_background(
            make_server("127.0.0.1", 0, cls.app, threaded=True))
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _sign_in(self, page):
        support.sign_in_in_browser(page, self.base, "admin", PASSWORD,
                                   self.secret, app=self.app)

    def test_both_new_panel_types_survive_the_create_form_and_the_edit_form(self):
        from playwright.sync_api import sync_playwright

        said, threw = [], []
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context(
                viewport={"width": 1500, "height": 1000}).new_page()
            page.on("pageerror", lambda e: threw.append(str(e)))
            page.on("dialog", lambda d: (said.append(d.message), d.dismiss()))
            self._sign_in(page)

            # ---- the create form -------------------------------------
            page.goto(f"{self.base}/dashboard/create", wait_until="networkidle")
            page.fill("input[name=name]", "E1 editor round trip")
            page.fill("input[name=query]", "*")

            page.click('[data-add-panel="records"]')
            page.click('[data-add-panel="trace_list"]')
            rows = page.locator("#panelList .list-group-item")
            self.assertEqual(rows.count(), 5, "three defaults and two added")

            records, traces = rows.nth(3), rows.nth(4)
            self.assertEqual(
                records.locator('[data-key="split_by"]').count(), 0,
                "the records panel was handed the timeseries controls")
            self.assertEqual(records.locator('[data-key="size"]').count(), 1)
            self.assertEqual(traces.locator('[data-key="service"]').count(), 1)

            # A trace list with no service is a save the server refuses, and a
            # refusal re-renders the form from the stored list — taking the
            # other four panels with it.
            page.click("button[type=submit]")
            page.wait_for_timeout(200)
            self.assertTrue(any("needs a service" in message
                                for message in said), said)
            self.assertIn("/dashboard/create", page.url,
                          "the form submitted a panel the save would refuse")

            records.locator('[data-key="size"]').fill("25")
            records.locator('[data-key="size"]').dispatch_event("change")
            traces.locator('[data-key="service"]').fill(SERVICE)
            traces.locator('[data-key="service"]').dispatch_event("change")
            # The row is redrawn when a service is named, so re-find them.
            rows = page.locator("#panelList .list-group-item")
            traces = rows.nth(4)
            self.assertEqual(traces.locator("[data-needs-service]").count(), 0,
                             "the warning stayed after a service was named")
            traces.locator('[data-key="view"]').select_option("errors")
            traces.locator('[data-key="size"]').fill("7")
            traces.locator('[data-key="size"]').dispatch_event("change")

            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")
            self.assertNotIn("/dashboard/create", page.url,
                             f"the create form refused the board: {said}")
            dashboard_id = page.url.rstrip("/").rsplit("/", 1)[-1]

            # ---- what was stored -------------------------------------
            stored = self.app.dashboard_manager.get_dashboard(dashboard_id)
            kinds = {panel["type"]: panel for panel in stored.get_panels()}
            self.assertIn("records", kinds, stored.panels)
            self.assertIn("trace_list", kinds, stored.panels)
            self.assertEqual(kinds["records"]["size"], 25)
            self.assertNotIn("split_by", kinds["records"],
                             "a records panel stored a timeseries field")
            self.assertEqual(kinds["trace_list"]["service"], SERVICE)
            self.assertEqual(kinds["trace_list"]["view"], "errors")
            self.assertEqual(kinds["trace_list"]["size"], 7)

            # ---- and what the edit form makes of it ------------------
            page.goto(f"{self.base}/dashboard/{dashboard_id}/edit",
                      wait_until="networkidle")
            rows = page.locator("#panelList .list-group-item")
            records, traces = rows.nth(3), rows.nth(4)
            self.assertEqual(
                records.locator('[data-key="size"]').input_value(), "25")
            self.assertEqual(
                records.locator('[data-key="split_by"]').count(), 0,
                "a stored records panel was offered a split-by select")
            self.assertEqual(
                traces.locator('[data-key="service"]').input_value(), SERVICE,
                "the service did not survive the round trip")
            self.assertEqual(
                traces.locator('[data-key="view"]').input_value(), "errors")
            self.assertEqual(
                traces.locator('[data-key="size"]').input_value(), "7")
            self.assertEqual(page.locator("#panelList b").count(), 0,
                             "a service name arrived as markup")

            # The rows say what they are, and neither says the other's thing.
            self.assertIn("one more request", records.inner_text())
            self.assertIn("traces:read", traces.inner_text())

            # ---- an edit of both, through the edit form --------------
            records.locator('[data-key="size"]').fill("5")
            records.locator('[data-key="size"]').dispatch_event("change")
            traces.locator('[data-key="view"]').select_option("recent")
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")

            again = self.app.dashboard_manager.get_dashboard(dashboard_id)
            kinds = {panel["type"]: panel for panel in again.get_panels()}
            self.assertEqual(kinds["records"]["size"], 5, again.panels)
            self.assertEqual(kinds["trace_list"]["view"], "recent",
                             json.dumps(again.panels))
            self.assertEqual(kinds["trace_list"]["service"], SERVICE)
            browser.close()

        self.assertEqual(threw, [], "the editor threw in the browser")

    def test_the_editor_is_legible_at_the_width_it_is_drawn_at(self):
        """Three things a DOM alone cannot answer, because none of them is in
        it: how wide a control ends up, how tall a sentence makes its row, and
        where the keyboard goes next.

        Measured in Chromium at 1500x1100 on the real create form before this
        was fixed. The trace list's three controls shared the four grid
        columns the other types use for two, so the Show select came out 91px
        wide with 56 of that its own padding and caret — 35px of room for a
        label needing 92 — and all three of the panel's questions rendered as
        "the". Which of "the slowest", "the newest" and "errors only" a panel
        was on could not be read off the page at all.

        The row also carried the whole ~180-character reason for the service
        box stacked into one quarter-width column: 312px tall against 98 for
        every other row, and the row being `align-items-end`, the Title
        control sat at the bottom of a ten-line warning.

        And `change` on the service box redrew the whole panel list, which
        fires exactly as focus leaves — so a person typing a service name and
        pressing Tab landed on the document body rather than on the Show
        select beside it.
        """
        from playwright.sync_api import sync_playwright

        threw = []
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context(
                viewport={"width": 1500, "height": 1100}).new_page()
            page.on("pageerror", lambda e: threw.append(str(e)))
            page.on("dialog", lambda d: d.dismiss())
            self._sign_in(page)
            page.goto(f"{self.base}/dashboard/create", wait_until="networkidle")
            page.click('[data-add-panel="trace_list"]')

            # What the select can actually show, against what its selected
            # option needs, in the select's own font.
            room = page.evaluate(SELECT_ROOM)
            self.assertGreaterEqual(
                room["room"], room["text"],
                f"the Show select clips {room['label']!r}: {room['room']}px of "
                f"room for {room['text']}px of label")

            # What the row costs while the service box is empty. The reason it
            # is empty is worth a sentence; the sentence belongs where there is
            # room for it, which is the refusal, not a quarter-width column.
            empty = page.evaluate(ROW_HEIGHTS)
            row = page.locator("#panelList .list-group-item").nth(3)
            service = row.locator('[data-key="service"]')
            service.click()
            page.keyboard.type("payment-service")
            page.keyboard.press("Tab")
            page.wait_for_timeout(120)

            landed = page.evaluate(
                "() => ({key: (document.activeElement.dataset || {}).key,"
                "        tag: document.activeElement.tagName})")
            self.assertEqual(
                landed, {"key": "view", "tag": "SELECT"},
                "Tab out of the service box did not land on the Show select")

            named = page.evaluate(ROW_HEIGHTS)
            self.assertEqual(page.locator("[data-needs-service]").count(), 0,
                             "the warning stayed after a service was named")
            self.assertLessEqual(
                empty["trace"] - named["trace"], 40,
                f"the missing-service warning adds "
                f"{empty['trace'] - named['trace']}px to the row")

            # The menu is the only way to add five of the seven types without
            # writing a dashboard's JSON by hand, so it has to be reachable on
            # a phone rather than off the side of it.
            page.set_viewport_size({"width": 390, "height": 900})
            page.goto(f"{self.base}/dashboard/create", wait_until="networkidle")
            fits = page.evaluate(
                "() => ({menu: Math.round(document"
                "          .querySelector('[data-add-panel]').parentElement"
                "          .getBoundingClientRect().width),"
                "        scroll: document.documentElement.scrollWidth,"
                "        viewport: window.innerWidth})")
            self.assertLessEqual(fits["menu"], fits["viewport"],
                                 f"the add menu is wider than the phone: {fits}")
            self.assertLessEqual(fits["scroll"], fits["viewport"],
                                 f"the create form scrolls sideways: {fits}")
            browser.close()

        self.assertEqual(threw, [], "the editor threw in the browser")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
