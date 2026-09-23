"""
The field picker's list, measured where it is painted.

Reported with a screenshot: the dialog opened, the names were all there,
and it read as mostly empty — "modal içinde çok boş duruyorlar, yani çok
geniş boş alan kalmış". The list was a two-column Bootstrap grid, which
splits a dialog into two equal halves whatever is in them. Field names are
`@l`, `@i`, `tag`, `stream`: a 380px half holding a 20px name is 360px of
nothing, twice per row, and a list of thirty fields scrolled while most of
the dialog was blank.

It is now `columns` in the stylesheet, so the count follows the width. That
cannot be checked by reading CSS — `columns` on a container says nothing
about how many columns a browser then draws, which depends on the width it
is drawn at — and it cannot be checked in jsdom, which has no layout at
all. So this opens the real dialog in a real browser at three widths and
counts how many names share a line.

Needs playwright and skips without it.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

PASSWORD = "field-picker-layout-password"

#: Names of the shape a cluster actually offers: short ones from Serilog,
#: one dotted path from a shipper. Enough of them that a column count is a
#: measurement rather than a rounding.
FIELDS = ["@i", "@l", "@m", "@mt", "@sp", "@tr", "tag", "stream", "level",
          "service", "host", "environment", "pod", "namespace", "container",
          "kubernetes.container_name", "kubernetes.namespace_name",
          "kubernetes.pod_name", "trace_id", "span_id"]

#: Fill the dialog through the page's own renderer rather than through the
#: API: the layout is the subject, and a source that can answer
#: `/api/field-stats/fields` is a backend this test would then be about.
FILL = """
(names) => {
    const search = window.logSearch;
    search._ticked = new Set();
    search._renderStatsFieldOffer({fields: names, chosen: []});
    bootstrap.Modal.getOrCreateInstance(
        document.getElementById('fieldStatsPicker')).show();
}
"""

#: One row per distinct top edge. Two names on one line share a top; a
#: browser drawing one column per name gives every one its own.
ROWS = """
() => {
    const tops = {};
    document.querySelectorAll('#fieldStatsOptions .form-check').forEach(el => {
        if (!el.getClientRects().length) { return; }
        const top = Math.round(el.getBoundingClientRect().top);
        tops[top] = (tops[top] || 0) + 1;
    });
    return Object.values(tops);
}
"""

#: What the list occupies, against what the dialog gives it.
WIDTHS = """
() => {
    const list = document.getElementById('fieldStatsOptions');
    let right = 0;
    list.querySelectorAll('.form-check').forEach(el => {
        if (el.getClientRects().length) {
            right = Math.max(right, el.getBoundingClientRect().right);
        }
    });
    return {used: right - list.getBoundingClientRect().left,
            available: list.getBoundingClientRect().width};
}
"""


def _chromium_available():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as play:
            play.chromium.launch().close()
    except Exception:
        return False
    return True


HAVE_BROWSER = _chromium_available()


@unittest.skipUnless(HAVE_BROWSER,
                     "no Chromium — run `playwright install chromium`")
class TheFieldPickerFillsItsDialogTest(unittest.TestCase):
    """How many names share a line, at three widths."""

    @classmethod
    def setUpClass(cls):
        from tests.support import grant, serve_in_background
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox
        from werkzeug.serving import make_server

        database = os.path.join(tempfile.mkdtemp(), "picker-layout.db")

        class PickerConfig(Config):
            SECRET_KEY = "field-picker-layout"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            DASHBOARD_STORAGE = "database"

        cls.app = create_app(PickerConfig)
        cls.secret = support.set_up(cls.app.test_client(), username="admin",
                                    password=PASSWORD)
        # `system:admin` because the button and the dialog are rendered only
        # for somebody who may save what they choose.
        grant(cls.app, "admin", ["system:admin", "logs:read"], indices=["*"])
        cls.app.store.settings.set("rbac.user_roles", {"admin": "test-role"})
        cls.app.store.rbac.invalidate()

        cls.server = serve_in_background(
            make_server("127.0.0.1", 0, cls.app, threaded=True))
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _measure(self, width, script=ROWS):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as play:
            browser = play.chromium.launch()
            try:
                page = browser.new_context(
                    viewport={"width": width, "height": 900}).new_page()
                support.sign_in_in_browser(page, self.base, "admin", PASSWORD,
                                           self.secret, app=self.app)
                page.goto(self.base + "/logs", wait_until="networkidle")
                page.evaluate(FILL, FIELDS)
                # The dialog fades in, and a measurement taken during the
                # fade is of an element still being placed.
                page.wait_for_timeout(500)
                return page.evaluate(script)
            finally:
                browser.close()

    def test_a_desktop_dialog_puts_several_names_on_a_line(self):
        """Two was the old grid's answer at every width above md. The fault
        reported was that two is too few for names this short."""
        rows = self._measure(1500)
        self.assertTrue(rows, "no name was painted, so nothing was measured")
        self.assertGreaterEqual(
            max(rows), 3,
            f"the widest line holds {max(rows)} of {len(FIELDS)} names, so "
            f"the dialog is mostly empty: lines were {rows}")

    def test_and_uses_the_width_it_was_given(self):
        """A count of three means nothing if the three sit in the left half.
        Measured against the space the dialog actually offers."""
        room = self._measure(1500, WIDTHS)
        self.assertGreater(
            room["used"], room["available"] * 0.6,
            f"the names reach {room['used']:.0f}px of the "
            f"{room['available']:.0f}px the dialog gives them")

    def test_a_phone_puts_one_name_on_a_line(self):
        """The other end of the same rule: a column count that follows the
        width has to come down as well as up, or a phone scrolls sideways."""
        rows = self._measure(375)
        self.assertTrue(rows, "no name was painted, so nothing was measured")
        self.assertEqual(
            max(rows), 1,
            f"a phone's dialog puts {max(rows)} names on one line")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
