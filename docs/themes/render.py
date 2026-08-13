"""Three palettes, on the real screens, through a real browser.

What produced the images beside this file. Kept so the numbers in README.md
can be re-measured rather than believed, and so the palettes live somewhere
they can be edited and looked at again.

Nothing here is wired into the product. A theme is a setting WDash does not
have yet; this is what it would look like if it did.

The stylesheet is rewritten on the way to the page rather than injected as a
tag: WDash sends a Content-Security-Policy, and a theme demo that has to be
allowed through it would be demonstrating something other than the theme.

Before running it:

  1. Copy a database that has some monitor results in it, and give yourself a
     password on the COPY — never on the original:

       cp data/wdash.db /tmp/themes.db
       PYTHONPATH=src python -c "
       from wdash.store import Store
       from wdash.store.secrets import SecretBox
       s = Store.open('sqlite:////tmp/themes.db',
                      secret_box=SecretBox(SecretBox.generate_key()))
       s.users.set_password('admin', 'theme-preview-only')"

     If the results are older than the window below, shift the copy's clock
     forward — an empty screen says nothing about a palette.

  2. Run the app against the copy, on a port nothing else holds:

       DATABASE_URL=sqlite:////tmp/themes.db ELASTICSEARCH_URL= \
           WDASH_DEV_PORT=5055 python main.py

  3. python docs/themes/render.py
"""
import tempfile
import pathlib
import sys

from playwright.sync_api import sync_playwright

BASE = "http://localhost:5055"
OUT = pathlib.Path("docs/themes")
#: The per-page tiles, which only exist to be assembled into the sheets.
SHOTS = pathlib.Path(tempfile.mkdtemp(prefix="wdash-themes-"))

PAGES = [
    ("Monitors", "/monitors?window=24h"),
    # Whichever monitor id the copy happens to have; this one is the lab's
    # deliberately-failing endpoint, which is the row worth showing.
    ("Monitor detail",
     "/monitors/d721b8c8-2c86-4029-9b1d-f7a5a4e61aa0?window=24h"),
    ("Configuration", "/admin/config"),
]

# --- the palettes ----------------------------------------------------------

LIGHT = {
    "--dark-bg": "#ffffff",
    "--dark-bg-secondary": "#f6f8fa",
    "--dark-bg-tertiary": "#eaeef2",
    "--dark-card": "#ffffff",
    "--dark-navbar": "#ffffff",
    "--dark-input": "#ffffff",
    "--dark-hover": "#eaeef2",
    "--dark-text": "#1f2328",
    "--dark-text-muted": "#5a636c",
    "--dark-text-secondary": "#636c76",
    "--dark-border": "#d0d7de",
    "--dark-accent": "#1a7f37",
    "--dark-accent-teal": "#0e7490",
    "--dark-accent-orange": "#cf222e",
    "--syntax-blue": "#0969da",
    "--syntax-green": "#116329",
    "--syntax-yellow": "#7d4e00",
    "--syntax-red": "#cf222e",
    "--syntax-purple": "#8250df",
    "--syntax-cyan": "#0e7490",
    "--primary-color": "#0969da",
    "--success-color": "#116329",
    "--warning-color": "#7d4e00",
    "--danger-color": "#cf222e",
    "--info-color": "#0969da",
}

HIGH_CONTRAST = {
    "--dark-bg": "#000000",
    "--dark-bg-secondary": "#000000",
    "--dark-bg-tertiary": "#0d0d0d",
    "--dark-card": "#000000",
    "--dark-navbar": "#000000",
    "--dark-input": "#000000",
    "--dark-hover": "#1f1f1f",
    "--dark-text": "#ffffff",
    "--dark-text-muted": "#d6d6d6",
    "--dark-text-secondary": "#e6e6e6",
    "--dark-border": "#9aa0a6",
    "--dark-accent": "#4ade80",
    "--dark-accent-teal": "#67e8f9",
    "--dark-accent-orange": "#ff8a80",
    "--syntax-blue": "#8ab4ff",
    "--syntax-green": "#4ade80",
    "--syntax-yellow": "#ffd54f",
    "--syntax-red": "#ff8a80",
    "--syntax-purple": "#e0b0ff",
    "--syntax-cyan": "#67e8f9",
    "--primary-color": "#67e8f9",
    "--success-color": "#4ade80",
    "--warning-color": "#ffd54f",
    "--danger-color": "#ff8a80",
    "--info-color": "#8ab4ff",
}

# Colours written as literals rather than as tokens, patched so the demo shows
# a finished theme instead of a half-tokenised one. The COUNT of these is the
# estimate: this is the work a theme needs before it is a setting.
LIGHT_LEFTOVERS = """
.navbar { background: var(--dark-navbar) !important;
          border-bottom: 1px solid var(--dark-border); }
.card, .table { --bs-table-bg: transparent; }
.journey-step.passed { color: #116329;
    border-color: rgba(17,99,41,.4); background: rgba(17,99,41,.08); }
.journey-step.failed { color: #cf222e;
    border-color: rgba(207,34,46,.45); background: rgba(207,34,46,.10); }
.journey-step.skipped { color: #5a636c;
    border-color: rgba(90,99,108,.35); background: transparent; }
.monitor-status.up { color: #116329; background: rgba(17,99,41,.10); }
.monitor-status.down { color: #cf222e; background: rgba(207,34,46,.12); }
.monitor-row-down { background: rgba(207,34,46,.06) !important; }

/* `.table table-dark` is in six templates and three scripts: another fixed
   dark, and this one hides its own text — white on white — rather than
   merely being the wrong shade. */
.table-dark { --bs-table-color: var(--dark-text);
              --bs-table-bg: transparent;
              --bs-table-border-color: var(--dark-border);
              --bs-table-striped-color: var(--dark-text);
              --bs-table-hover-color: var(--dark-text);
              --bs-table-hover-bg: var(--dark-hover);
              color: var(--dark-text); }
.table-dark > :not(caption) > * > * { color: var(--dark-text); }
"""

HIGH_CONTRAST_LEFTOVERS = """
.navbar { background: var(--dark-navbar) !important;
          border-bottom: 1px solid var(--dark-border); }
.journey-step.passed { color: #4ade80; border-color: #4ade80; }
.journey-step.failed { color: #ff8a80; border-color: #ff8a80; }
.journey-step.skipped { color: #d6d6d6; border-color: #9aa0a6; }
.monitor-status.up { color: #4ade80; background: transparent;
    border: 1px solid #4ade80; }
.monitor-status.down { color: #ff8a80; background: transparent;
    border: 1px solid #ff8a80; }
.table-dark { --bs-table-color: var(--dark-text);
              --bs-table-bg: transparent;
              --bs-table-border-color: var(--dark-border);
              --bs-table-hover-bg: var(--dark-hover); }
.table-dark > :not(caption) > * > * { color: var(--dark-text); }
"""

THEMES = [
    ("1-karanlik", "Karanlık — bugünkü", "dark", {}, ""),
    ("2-acik", "Açık", "light", LIGHT, LIGHT_LEFTOVERS),
    ("3-yuksek-kontrast", "Yüksek kontrast", "dark", HIGH_CONTRAST,
     HIGH_CONTRAST_LEFTOVERS),
]


def override(palette, leftovers):
    if not palette and not leftovers:
        return ""
    block = "\n".join(f"    {name}: {value};"
                      for name, value in palette.items())
    return f"\n\n/* theme preview */\n:root {{\n{block}\n}}\n{leftovers}"


def shoot(page, slug, bootstrap, palette, leftovers):
    css = override(palette, leftovers)

    def rewrite(route):
        response = route.fetch()
        route.fulfill(response=response, body=response.text() + css,
                      headers={**response.headers,
                               "content-type": "text/css"})

    page.unroute_all()
    if css:
        page.route("**/wdash.css*", rewrite)

    files = []
    for name, path in PAGES:
        page.goto(BASE + path, wait_until="networkidle")
        page.evaluate("""t => {
            document.documentElement.setAttribute('data-bs-theme', t.bootstrap);
            if (t.strip) {
                // `<body class="bg-dark text-light">` and the navbar's
                // `navbar-dark bg-dark`. Bootstrap's utilities are a FIXED
                // dark with !important, so they override every token the
                // palette sets — the theme is nailed down in the template,
                // not only in the stylesheet.
                document.body.classList.remove('bg-dark', 'text-light');
                document.querySelectorAll('.navbar').forEach(n =>
                    n.classList.remove('navbar-dark', 'bg-dark'));
            }
        }""", {"bootstrap": bootstrap, "strip": bool(palette)})
        page.wait_for_timeout(350)
        target = SHOTS / f"{slug}-{name.lower().replace(' ', '-')}.png"
        page.screenshot(path=str(target))
        files.append((name, target))
    return files


SHEET = """
<html><head><meta charset="utf-8"><style>
  body {{ margin: 0; padding: 26px; background: {sheet_bg};
          font-family: -apple-system, 'Segoe UI', sans-serif; color: {ink}; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  p.sub {{ margin: 0 0 20px; font-size: 13px; color: {muted}; }}
  figure {{ margin: 0 0 18px; }}
  figcaption {{ font-size: 12px; color: {muted}; margin: 0 0 6px;
                text-transform: uppercase; letter-spacing: .6px; }}
  img {{ width: 100%; display: block; border: 1px solid {edge};
         border-radius: 8px; }}
</style></head><body>
<h1>{title}</h1><p class="sub">{sub}</p>
{figures}
</body></html>
"""


def sheet(page, slug, title, sub, files, light):
    figures = "\n".join(
        f'<figure><figcaption>{name}</figcaption>'
        f'<img src="file://{path}"></figure>' for name, path in files)
    html = SHEET.format(
        title=title, sub=sub, figures=figures,
        sheet_bg="#ffffff" if light else "#0d1117",
        ink="#1f2328" if light else "#f0f6fc",
        muted="#5a636c" if light else "#8b949e",
        edge="#d0d7de" if light else "#30363d")
    path = SHOTS / f"{slug}-sheet.html"
    path.write_text(html)
    page.unroute_all()
    page.goto(f"file://{path}", wait_until="load")
    page.wait_for_timeout(400)
    OUT.mkdir(parents=True, exist_ok=True)
    # JPEG: the same sheet as a PNG is about 1.8MB, and three of those is
    # five megabytes of screenshot in a repository whose point is the code.
    page.screenshot(path=str(OUT / f"{slug}.jpg"), full_page=True,
                    type="jpeg", quality=82)
    print("wrote", OUT / f"{slug}.jpg")


def main():
    SHOTS.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900},
                                device_scale_factor=1)
        page.goto(f"{BASE}/auth/login")
        page.fill("#username", "admin")
        page.fill("#password", "theme-preview-only")
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")
        if "login" in page.url:
            sys.exit("could not sign in")

        for slug, title, bootstrap, palette, leftovers in THEMES:
            files = shoot(page, slug, bootstrap, palette, leftovers)
            sheet(page, slug, title,
                  "WDash — gerçek sayfalar, gerçek veri",
                  files, light=(bootstrap == "light"))
        browser.close()


main()
