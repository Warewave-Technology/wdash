"""Draw static/img/wdash-mark-32.png from the SVG favicon.

The PNG is for the browsers that do not take an SVG favicon. It cannot
follow `prefers-color-scheme`, so it is the same drawing in ONE colour,
chosen to hold against a light tab strip and a dark one alike: #c35d1a, a
shade of Gruvbox's orange measured at 4.28:1 on white, 3.76:1 on dark
chrome (#202124) and 3.27:1 on light chrome (#dee1e6) — over the 3:1 a
graphic needs on all three. The accent itself does not: bright orange is
2.53:1 on white, faded orange 2.63:1 on dark chrome.

Read from the SVG rather than drawn again here, so the two cannot disagree
about the shape. Needs Playwright, which is a development tool here, not a
dependency:

    ./venv/bin/python docs/logo/render_png.py
"""
import pathlib
import re

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[2]
SVG = ROOT / "static" / "img" / "wdash-mark.svg"
PNG = ROOT / "static" / "img" / "wdash-mark-32.png"
INK = "#c35d1a"


def one_colour(svg):
    """The favicon with its scheme-dependent style replaced by one ink."""
    svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S)
    return re.sub(r"<style>.*?</style>",
                  f"<style>#wdash-mark {{ color: {INK}; }} "
                  f"#wdash-mark .pulse {{ stroke: {INK}; }}</style>",
                  svg, flags=re.S)


def main():
    page_html = ("<!doctype html><html><body style='margin:0;background:transparent'>"
                 + one_colour(SVG.read_text()) + "</body></html>")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 32, "height": 32},
                                device_scale_factor=1)
        page.set_content(page_html)
        page.locator("#wdash-mark").screenshot(path=str(PNG),
                                               omit_background=True)
        browser.close()
    print(f"wrote {PNG.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
