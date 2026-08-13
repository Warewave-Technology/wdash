"""Screenshot each theme, on the real screens, through a real browser.

What produced the images beside this file.

It drives the product's own switch — `window.wdashTheme.set(...)` — rather
than rewriting the stylesheet on the way to the page. The first version of
this did rewrite it, because at the time there was no switch to drive and the
palette was only two thirds of a theme; those images and that measurement are
described in README.md.

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
     forward — an empty screen says nothing about a theme.

  2. Run the app against the copy, on a port nothing else holds:

       DATABASE_URL=sqlite:////tmp/themes.db WDASH_DEV_PORT=5055 python main.py

  3. python docs/themes/render.py
"""
import pathlib
import sys
import tempfile

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

THEMES = [
    ("1-karanlik", "Karanlık", "dark",
     "The default. What every installation shows until somebody chooses."),
    ("2-acik", "Açık", "light",
     "A palette and nothing else — no rule outside it knows which theme it "
     "is in."),
]

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


def shoot(page, slug, theme):
    page.goto(BASE + PAGES[0][1], wait_until="networkidle")
    page.evaluate("theme => window.wdashTheme.set(theme)", theme)
    files = []
    for name, path in PAGES:
        page.goto(BASE + path, wait_until="networkidle")
        page.wait_for_timeout(400)
        target = SHOTS / f"{slug}-{name.lower().replace(' ', '-')}.png"
        page.screenshot(path=str(target))
        files.append((name, target))
    return files


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
    page.goto(f"file://{path}", wait_until="load")
    page.wait_for_timeout(400)
    OUT.mkdir(parents=True, exist_ok=True)
    # JPEG at one device pixel: the same sheets as PNG at 2x are five
    # megabytes of screenshot in a repository whose point is the code.
    page.screenshot(path=str(OUT / f"{slug}.jpg"), full_page=True,
                    type="jpeg", quality=82)
    print("wrote", OUT / f"{slug}.jpg")


def main():
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

        for slug, title, theme, sub in THEMES:
            files = shoot(page, slug, theme)
            sheet(page, slug, title, sub, files, light=(theme == "light"))
        browser.close()


main()
