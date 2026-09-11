"""
Every screen, rendered, in both themes.

`tests/test_contrast.py` reads the stylesheet. That catches a colour written
wrongly and cannot catch a colour never written at all: a class nobody
restyled keeps Bootstrap's, and Bootstrap's palette is close enough to this
one that nothing looks broken. Measured across the product the day this was
written, that was 44 elements painting themselves #212529 on the light theme,
blue links on four pages, a blue tick in every checkbox, and — on the sign-in
page — the only action on screen at 3.84:1.

So this walks the real pages in a real browser and asks three things of every
visible element:

  * did anything fail to load, or throw;
  * is it painted in one of Bootstrap's own colours, which this palette never
    uses;
  * does its text reach the contrast it needs against the ground ACTUALLY
    behind it — including when that ground is a gradient, which is how half
    the filled things in this product are painted.

Needs playwright and skips without it. It is the slowest test in the suite by
some way; it is also the only one that has ever seen the product.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

PASSWORD = "rendered-pages-only-password"

#: Bootstrap 5.3's own palette. None of it is in `wdash.css`, so an element
#: wearing one of these is wearing a class nobody restyled.
BOOTSTRAP = {
    "rgb(13, 110, 253)": "primary", "rgb(10, 88, 202)": "primary-hover",
    "rgb(108, 117, 125)": "secondary", "rgb(25, 135, 84)": "success",
    "rgb(220, 53, 69)": "danger", "rgb(255, 193, 7)": "warning",
    "rgb(13, 202, 240)": "info", "rgb(248, 249, 250)": "light",
    "rgb(33, 37, 41)": "dark", "rgb(102, 16, 242)": "indigo",
    "rgb(214, 51, 132)": "pink", "rgb(253, 126, 20)": "orange",
}

AUDIT = r"""(bootstrap) => {
  const parse = (value) => {
    const m = value.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/);
    return m ? [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]] : null;
  };
  const lum = (c) => {
    const f = (v) => { v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
  };
  const ratio = (a, b) => {
    const [x, y] = [lum(a), lum(b)];
    return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
  };
  // The ground actually behind the text. A gradient counts: buttons, status
  // chips and cards are painted with `linear-gradient`, whose
  // `background-color` is transparent — walking past them reports dark ink
  // on the dark PAGE at 1:1 and produces a page of lies about controls that
  // are perfectly readable.
  const behind = (el) => {
    for (let n = el; n && n !== document.documentElement; n = n.parentElement) {
      const style = getComputedStyle(n);
      const solid = parse(style.backgroundColor);
      if (solid && solid[3] > 0.6) { return solid; }
      if (style.backgroundImage && style.backgroundImage !== 'none') {
        const stops = (style.backgroundImage.match(/rgba?\([^)]+\)/g) || [])
            .map(parse).filter(c => c && c[3] > 0.6);
        // Judged at its darkest stop rather than at whichever end came first.
        if (stops.length) { return stops.reduce((a, c) =>
            lum(c) < lum(a) ? c : a); }
      }
    }
    return parse(getComputedStyle(document.body).backgroundColor) ||
           [255, 255, 255, 1];
  };
  const path = (el) => {
    const bits = [];
    for (let n = el; n && n.tagName && bits.length < 3; n = n.parentElement) {
      bits.unshift(n.tagName.toLowerCase() +
        (n.className && typeof n.className === 'string'
         ? '.' + n.className.trim().split(/\s+/).slice(0, 2).join('.') : ''));
    }
    return bits.join(' > ');
  };

  const defaults = [], unreadable = [], seen = new Set();
  for (const el of document.querySelectorAll('body *')) {
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' ||
        !el.getClientRects().length) { continue; }

    for (const prop of ['color', 'background-color', 'border-top-color']) {
      const value = style.getPropertyValue(prop);
      if (bootstrap[value] &&
          !(prop === 'border-top-color' && style.borderTopWidth === '0px')) {
        const key = `${path(el)}|${prop}|${value}`;
        if (seen.has(key)) { continue; }
        seen.add(key);
        defaults.push(`${bootstrap[value]} ${prop} on ${path(el)} ` +
                      `${JSON.stringify((el.textContent || '').trim().slice(0, 30))}`);
      }
    }

    // Elements holding their own text, and not text painted with a gradient
    // clipped to the glyphs — there `color` is not what anybody sees, and
    // tests/test_contrast.py reads the gradient's stops instead.
    const own = [...el.childNodes]
        .filter(n => n.nodeType === 3 && n.textContent.trim())
        .map(n => n.textContent.trim()).join(' ');
    if (!own || style.webkitTextFillColor === 'rgba(0, 0, 0, 0)') { continue; }
    const ink = parse(style.color);
    if (!ink || ink[3] < 0.5) { continue; }
    const ground = behind(el);
    const size = parseFloat(style.fontSize);
    const weight = parseInt(style.fontWeight, 10) || 400;
    const needed = (size >= 24 || (size >= 18.66 && weight >= 700)) ? 3.0 : 4.5;
    const got = ratio(ink, ground);
    if (got >= needed) { continue; }
    const key = `${path(el)}|${style.color}|${own.slice(0, 20)}`;
    if (seen.has(key)) { continue; }
    seen.add(key);
    unreadable.push(`${got.toFixed(2)}:1 (needs ${needed}) ${path(el)} ` +
                    `${style.color} on rgb(${ground.slice(0, 3)}) ` +
                    `${JSON.stringify(own.slice(0, 40))}`);
  }
  return {defaults, unreadable};
}"""


def _playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False


@unittest.skipUnless(_playwright(), "playwright is not installed")
class EveryScreenTest(unittest.TestCase):
    """One app, one browser, every page twice."""

    #: Reached with no data source configured, which is how a fresh
    #: installation looks. What is being measured is the CHROME — navbar,
    #: cards, tables, tabs, buttons, form controls — and that is on every one
    #: of these whether or not there are records to put in it.
    PAGES = (("logs", "/logs"), ("dashboards", "/dashboards"),
             ("monitors", "/monitors"), ("alerts", "/alerts"),
             ("configuration", "/admin/config"), ("audit", "/admin/audit"),
             ("new dashboard", "/dashboard/create"))

    @classmethod
    def setUpClass(cls):
        from tests.support import grant
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        database = os.path.join(tempfile.mkdtemp(), "rendered.db")

        class RenderConfig(Config):
            SECRET_KEY = "rendered-pages"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            ELASTICSEARCH_URL = ""
            DASHBOARD_STORAGE = "database"

        cls.app = create_app(RenderConfig)
        cls.app.test_client().post("/setup", data={"username": "admin",
                                                   "password": PASSWORD,
                                                   "confirm": PASSWORD})
        # Through the store, like everything else here: the local account's
        # role decides what the navbar shows, and a page nobody may open
        # renders nothing to measure.
        grant(cls.app, "admin", ["system:admin", "logs:read", "traces:read",
                                 "monitors:read", "dashboard:view",
                                 "dashboard:create"], indices=["*"])
        cls.app.store.settings.set("rbac.user_roles", {"admin": "test-role"})
        cls.app.store.rbac.invalidate()

        # A port of its own. It was a fixed one, and two of these running at
        # once — the parallel runner splits this class — took each other's.
        from werkzeug.serving import make_server
        from tests.support import serve_in_background
        cls.server = serve_in_background(
            make_server("127.0.0.1", 0, cls.app, threaded=True))
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    # One theme a test, so a parallel run can take them one each.
    def test_no_screen_wears_bootstraps_colours_or_fails_to_be_read_dark(self):
        self._every_screen("dark")

    def test_no_screen_wears_bootstraps_colours_or_fails_to_be_read_light(self):
        self._every_screen("light")

    def _every_screen(self, theme):
        from playwright.sync_api import sync_playwright

        base = self.base
        faults = []
        with sync_playwright() as play:
            browser = play.chromium.launch()
            context = browser.new_context(viewport={"width": 1500,
                                                    "height": 1000})
            page = context.new_page()
            page.goto(f"{base}/auth/login", wait_until="networkidle")
            page.fill("input[name=username]", "admin")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")

            # Registered once. Inside the loop they accumulate, and the
            # fourth page reports the first page's failures four times.
            trouble = []
            page.on("pageerror", lambda e: trouble.append(f"threw: {e}"))
            page.on("response", lambda r: trouble.append(
                f"{r.status} {r.url.split('?')[0]}") if r.status >= 400
                else None)

            for name, url in self.PAGES:
                trouble.clear()
                page.goto(base + url, wait_until="networkidle")
                page.evaluate(f"window.wdashTheme.set('{theme}')")
                page.wait_for_timeout(400)
                report = page.evaluate(AUDIT, BOOTSTRAP)
                for line in (list(dict.fromkeys(trouble))
                             + report["defaults"] + report["unreadable"]):
                    faults.append(f"{theme} · {name}: {line}")
            browser.close()

        self.assertEqual(faults, [], "\n".join([""] + faults))

    def test_the_cdn_scripts_still_load_under_the_policy(self):
        """script-src names no host now: the nonce admits the tags WDash
        writes, and their integrity hashes admit only their bytes. Measured
        rather than assumed — a script the policy refuses leaves its global
        undefined and says so only on the console, and the log page's
        histogram quietly skips itself when Chart is missing."""
        from playwright.sync_api import sync_playwright

        base = self.base
        refused, loaded = [], {}
        with sync_playwright() as play:
            browser = play.chromium.launch()
            page = browser.new_context().new_page()
            page.on("console", lambda m: refused.append(m.text)
                    if "Content Security Policy" in m.text else None)
            page.goto(f"{base}/auth/login", wait_until="networkidle")
            page.fill("input[name=username]", "admin")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")
            for url in ("/logs", "/dashboards"):
                page.goto(base + url, wait_until="networkidle")
                loaded[url] = page.evaluate(
                    "({chart: typeof Chart, bootstrap: typeof bootstrap,"
                    "  flatpickr: typeof flatpickr})")
            browser.close()

        self.assertEqual(refused, [])
        for url, globals_ in loaded.items():
            self.assertNotIn("undefined", globals_.values(), f"{url}: {globals_}")
