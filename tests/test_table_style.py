"""
One table, measured where it is painted.

There was no table style in this product; there were thirty table
declarations. Measured in Chromium at 1500x1000 the day this was written,
signed in, with a row in every table:

    configuration, Configured sources   16px     4px 4px    middle
    configuration, Local accounts       16px     4px 4px    middle
    configuration, Roles                16px     4px 4px    middle
    configuration, agents and checks    13.6px   8px 8px    top
    configuration, channels and rules   13.6px   8px 8px    top
    monitors                            14.4px   8px 8px    top
    audit                               13.12px  4px 4px    top

Four type sizes, two densities and an alignment that changed table to
table — none of it in the stylesheet. Every size was an inline
`style="font-size:…"` typed into a template, and every density was
Bootstrap's `.table-sm`, which only ever meant "denser". Inside one row of
Local accounts that produced three type sizes at once: the username at
16px, the email and both dates at 12.8px, the role's select back at 16px.

So this measures. It is not a reading of the stylesheet — a class nobody
restyled keeps Bootstrap's, and the whole fault above was invisible to a
test that reads CSS because none of it was written in CSS. It walks the
real pages in a real browser, in both themes, and asks of every visible
table that its type size, its cell padding, its vertical alignment and its
header treatment come from one small set:

  * one type size, `.table` in the stylesheet;
  * two paddings — the ordinary one, and `.table-dense` for a table that
    genuinely is denser (the audit trail), which is a NAME rather than a
    number typed into a template;
  * one vertical alignment, middle, so a row whose tallest thing is a
    control reads as one line rather than as text floating above it;
  * one header treatment, the one `.field-table thead th` already had and
    nothing else used.

`SOURCES` below covers what the walk cannot reach: the tables built by
JavaScript out of a trace or a panel's records, which need a live backend
to render. Those carried inline sizes too.

Needs playwright and skips without it.
"""

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PASSWORD = "table-style-only-password"

#: The one size, in the stylesheet. 0.85rem, which is what most of the
#: product already painted.
TYPE_SIZES = {"13.6px"}

#: Two, and the second one has a name. `4px 4px` is Bootstrap's `.table-sm`
#: and is not among them: a table that is denser says `table-dense`.
PADDINGS = {"8px 12px", "4px 8px"}

#: A row reads as one line. `baseline` is what a cell holding a select and
#: four buttons gets wrong.
ALIGNMENTS = {"middle"}


def _playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False


#: Every visible table, and what it is actually painted as.
MEASURE = r"""() => {
  const out = [];
  const where = (el) => {
    const bits = [];
    for (let n = el; n && n.tagName && bits.length < 3; n = n.parentElement) {
      bits.unshift(n.tagName.toLowerCase() + (n.id ? '#' + n.id : '') +
        (n.className && typeof n.className === 'string'
         ? '.' + n.className.trim().split(/\s+/).slice(0, 2).join('.') : ''));
    }
    return bits.join(' > ');
  };
  for (const table of document.querySelectorAll('table')) {
    if (!table.getClientRects().length) { continue; }
    const th = table.querySelector('thead th');
    const cells = [...table.querySelectorAll('tbody td')];
    if (!cells.length) { continue; }
    const box = (el) => {
      const s = getComputedStyle(el);
      return {font: s.fontSize,
              pad: s.paddingTop + ' ' + s.paddingLeft,
              align: s.verticalAlign,
              colour: s.color};
    };
    out.push({
      where: where(table),
      // Every cell, not the first one: four cells of Local accounts carried
      // an inline size of their own and the first one did not.
      cells: cells.map(box),
      head: th ? {
        font: getComputedStyle(th).fontSize,
        colour: getComputedStyle(th).color,
        transform: getComputedStyle(th).textTransform,
        spacing: getComputedStyle(th).letterSpacing,
        border: getComputedStyle(th).borderBottomWidth,
      } : null,
    });
  }
  return out;
}"""

#: Where the buttons of ONE cell sit. Per cell rather than per row: a row of
#: Local accounts also holds a "Save role" button in the role cell, which is
#: a different control in a different column and is meant to sit above the
#: sentence underneath it.
MEASURE_ACTION_CELLS = r"""() => {
  const out = [];
  for (const table of document.querySelectorAll('table')) {
    if (!table.getClientRects().length) { continue; }
    for (const td of table.querySelectorAll('tbody td')) {
      const buttons = [...td.querySelectorAll(
          ':scope > .btn, :scope > form > .btn')];
      if (buttons.length < 2) { continue; }
      const boxes = buttons.map(b => b.getBoundingClientRect());
      const tops = boxes.map(b => Math.round(b.top));
      out.push({
        where: (table.id || table.className).slice(0, 40) +
               ' cell ' + [...td.parentElement.children].indexOf(td),
        buttons: buttons.length,
        // The room the buttons themselves take, not the cell's: a `td`
        // stretches to its ROW, and the row is as tall as its tallest
        // column whatever this cell does.
        extent: Math.round(Math.max(...boxes.map(b => b.bottom)) -
                           Math.min(...boxes.map(b => b.top))),
        buttonHeight: Math.round(boxes[0].height),
        spread: Math.max(...tops) - Math.min(...tops),
      });
    }
  }
  return out;
}"""


@unittest.skipUnless(_playwright(), "playwright is not installed")
class EveryTableIsTheSameTableTest(unittest.TestCase):
    """One app, one browser, every page with a table in it, both themes."""

    PAGES = (("monitors", "/monitors"), ("alerts", "/alerts"),
             ("audit", "/admin/audit"))

    #: The configuration page is five pages wearing one URL, and a hidden
    #: pane measures nothing: `getClientRects()` is empty for all of it.
    PANES = ("#tab-sources", "#tab-auth", "#tab-monitors", "#tab-alerts",
             "#tab-roles")

    @classmethod
    def setUpClass(cls):
        from tests.support import grant, serve_in_background
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox
        from werkzeug.serving import make_server

        database = os.path.join(tempfile.mkdtemp(), "table-style.db")

        class TableConfig(Config):
            SECRET_KEY = "table-style"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        cls.app = create_app(TableConfig)
        cls.secret = support.set_up(cls.app.test_client(), username="admin",
                                    password=PASSWORD)
        grant(cls.app, "admin", ["system:admin", "logs:read", "traces:read",
                                 "monitors:read", "dashboard:view"],
              indices=["*"])
        cls.app.store.settings.set("rbac.user_roles", {"admin": "test-role"})
        cls.app.store.rbac.invalidate()

        # A row in every table. An empty table paints no cell, and a test
        # that measures nothing passes.
        store = cls.app.store
        store.sources.create("warehouse-logs", "logs", "loki",
                             {"url": "http://127.0.0.1:9/loki"})
        store.agents.create("frankfurt-office")
        store.monitors.create("checkout", "http", "https://example.com/health")
        channel = store.channels.create("ops-webhook", "webhook",
                                        url="https://example.com/hook")
        rule = store.rules.create("checkout down", "monitor_down",
                                  channel["id"])
        store.alert_history.record(rule["id"], "monitor:checkout", "firing",
                                   detail="two checks in a row failed",
                                   delivered=True)
        store.users.create("reader", "a-long-enough-password", "viewer",
                           email="reader@example.com")
        store.audit.record("admin", "source created",
                           subject="source:warehouse-logs")
        store.rbac.invalidate()

        cls.server = serve_in_background(
            make_server("127.0.0.1", 0, cls.app, threaded=True))
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    #: Narrow as well as wide. A cell of buttons has room at 1500px whatever
    #: it says; the wrap this is about happened where a browser window
    #: usually is, and that is where `TheAgentRowIsOneRowHighTest` found it.
    WIDTHS = (1024, 1500)

    def _walk(self):
        """Every table on every screen, in both themes, measured."""
        from playwright.sync_api import sync_playwright

        seen, cells = [], []
        with sync_playwright() as play:
            browser = play.chromium.launch()
            for width in self.WIDTHS:
                page = browser.new_context(
                    viewport={"width": width, "height": 1000}).new_page()
                support.sign_in_in_browser(page, self.base, "admin", PASSWORD,
                                           self.secret, app=self.app)
                for name, url in (self.PAGES
                                  + (("configuration", "/admin/config"),)):
                    page.goto(self.base + url, wait_until="networkidle")
                    panes = self.PANES if url == "/admin/config" else (None,)
                    for pane in panes:
                        if pane:
                            page.evaluate(SHOW_PANE, pane)
                        # Both themes, because the face a theme picks
                        # decides how much room the words take, and because
                        # the header's colour is a token resolved per theme.
                        for theme in ("dark", "light"):
                            page.evaluate(f"window.wdashTheme.set('{theme}')")
                            page.wait_for_timeout(200)
                            label = (f"{width}px {theme} · {name}"
                                     f"{' ' + pane if pane else ''}")
                            # Type, density and alignment do not move with the
                            # window; measured once, at the width the product
                            # was measured at when this was written.
                            if width == 1500:
                                for table in page.evaluate(MEASURE):
                                    seen.append((label, table))
                            for cell in page.evaluate(MEASURE_ACTION_CELLS):
                                cells.append((label, cell))
                page.close()
            browser.close()
        self.assertTrue(seen, "no table was measured at all")
        return seen, cells

    def test_every_table_is_one_size_one_density_and_one_alignment(self):
        seen, _ = self._walk()
        faults = []
        for label, table in seen:
            for cell in table["cells"]:
                if cell["font"] not in TYPE_SIZES:
                    faults.append(f"{label}: {table['where']} type {cell['font']}")
                if cell["pad"] not in PADDINGS:
                    faults.append(f"{label}: {table['where']} padding {cell['pad']}")
                if cell["align"] not in ALIGNMENTS:
                    faults.append(f"{label}: {table['where']} aligned {cell['align']}")
        self.assertEqual(sorted(set(faults)), [],
                         "\n".join([""] + sorted(set(faults))))

    def test_every_table_header_wears_the_same_treatment(self):
        """The house style existed and exactly one table used it."""
        seen, _ = self._walk()
        by_theme, body_ink = {}, {}
        for label, table in seen:
            theme = label.split(" · ")[0].split(" ")[-1]
            for cell in table["cells"]:
                body_ink.setdefault(theme, set()).add(cell["colour"])
            if not table["head"]:
                continue
            by_theme.setdefault(theme, {}).setdefault(
                tuple(sorted(table["head"].items())), []).append(
                    f"{label}: {table['where']}")
        self.assertTrue(by_theme, "no table header was measured")
        for theme, treatments in by_theme.items():
            self.assertEqual(
                len(treatments), 1,
                f"{theme}: {len(treatments)} header treatments, not one:\n" +
                "\n".join(f"  {dict(k)} — {v}" for k, v in treatments.items()))
            head = dict(next(iter(treatments)))
            self.assertEqual(head["transform"], "uppercase", head)
            self.assertEqual(head["border"], "2px", head)
            # The accent, not body ink. A header painted in the body's own
            # colour is a row of data with more weight on it, which is what
            # every table but one had.
            self.assertNotIn(
                head["colour"], body_ink.get(theme, set()),
                f"{theme}: the header is painted in the body's own ink "
                f"({head['colour']})")

    def test_a_cell_of_buttons_keeps_them_on_one_line(self):
        """The wrap `config.html` papered over four times with
        `text-nowrap`, asked of every action cell in the product."""
        _, cells = self._walk()
        self.assertTrue(cells, "no cell of controls was measured")
        for label, cell in cells:
            with self.subTest(where=f"{label} {cell['where']}"):
                self.assertEqual(cell["spread"], 0,
                                 f"the buttons start on different lines: {cell}")
                self.assertLess(cell["extent"], cell["buttonHeight"] * 2,
                                f"the cell is two buttons high: {cell}")


#: Shows one pane of the configuration page's tab strip.
SHOW_PANE = """(pane) => {
  const trigger = document.querySelector('[data-bs-target="' + pane + '"]');
  if (trigger && window.bootstrap) {
    window.bootstrap.Tab.getOrCreateInstance(trigger).show();
  }
}"""


class NoSizeIsTypedIntoASourceFileTest(unittest.TestCase):
    """The measurement above cannot reach a table built out of a trace.

    `trace_detail.html`, `traces.html` and `async-dashboard.js` write their
    tables from JavaScript when a backend answers, and five of them carried
    an inline `font-size` of their own — 0.75rem and 0.8rem, two more sizes
    nobody could see from the stylesheet. A browser walk cannot render them
    without a live store, so this reads the files instead. It is the
    cheaper half of the same claim and it fails first.
    """

    #: Everything that writes a `<table>`.
    SOURCES = ("templates", os.path.join("static", "js"))

    def _sources(self):
        for folder in self.SOURCES:
            path = os.path.join(ROOT, folder)
            for name in sorted(os.listdir(path)):
                if name.endswith(".min.js"):
                    continue
                if not (name.endswith(".html") or name.endswith(".js")):
                    continue
                with open(os.path.join(path, name)) as handle:
                    yield f"{folder}/{name}", handle.read()

    def _tables(self):
        """The whole opening tag, not the line it starts on.

        A version of this that read one line at a time missed the agents
        table, whose `style` sits on the second line of the tag — which a
        mutation put straight back and nothing noticed.
        """
        found = []
        for where, text in self._sources():
            for match in re.finditer(r"<table\b[^>]*>", text):
                line = text.count("\n", 0, match.start()) + 1
                found.append((f"{where}:{line}",
                              " ".join(match.group(0).split())))
        return found

    def test_there_are_tables_to_check(self):
        self.assertGreater(len(self._tables()), 15, self._tables())

    def test_no_table_carries_a_size_of_its_own(self):
        """A size typed into a template is a size the stylesheet cannot
        reach, and five of them disagreed."""
        offenders = [f"{at}: {line.strip()}" for at, line in self._tables()
                     if re.search(r"font-size\s*:", line)]
        self.assertEqual(offenders, [], "\n".join(
            ["a table declares its own type size:"] + offenders))

    def test_no_table_is_denser_by_accident(self):
        """`table-sm` says "smaller" and means "4px padding". A table that
        is genuinely denser says `table-dense`, which is a name in the
        stylesheet and can be changed in one place."""
        offenders = [f"{at}: {line.strip()}" for at, line in self._tables()
                     if "table-sm" in line]
        self.assertEqual(offenders, [], "\n".join(
            ["a table still uses Bootstrap's density:"] + offenders))

    def test_no_table_cell_declares_a_size_either(self):
        """Three type sizes inside one row of Local accounts, none of them
        in the stylesheet."""
        offenders = []
        for where, text in self._sources():
            # The cell's own tag, and the tag of whatever it opens with: a
            # `<code>` inside a `<td>` carried three of these.
            for match in re.finditer(r"<t[dh]\b[^>]*>(?:\s*<[a-z]+\b[^>]*>)?",
                                     text):
                if not re.search(r"font-size\s*:", match.group(0)):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{where}:{line}: "
                                 f"{' '.join(match.group(0).split())}")
        self.assertEqual(offenders, [], "\n".join(
            ["a table cell declares its own type size:"] + offenders))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(
        "Run this through the runner: ./venv/bin/python -m unittest "
        "tests.test_table_style")
