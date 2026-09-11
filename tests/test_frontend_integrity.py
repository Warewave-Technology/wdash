"""
Checks over the browser bundle.

The rest of the suite never loads the JavaScript, so a dead front end passes
every test. Three faults reached the working tree that way, and none of them
were syntax errors:

  * `_bindFieldActions` — called in three places, defined in none
  * `queryKey` — used in the record detail, never declared
  * `highlightJson` — rewrote `09:30:12` as `09: 30: 12` while colouring it

Two layers here. The static checks below need nothing but Python. The real
coverage is `tests/frontend_smoke.js`, which runs the bundle against a fake DOM
and asserts what the user would see; it needs node and jsdom, and skips when
they are absent rather than failing the suite for everyone.

    npm install jsdom && node tests/frontend_smoke.js
"""

import os
import re
import subprocess
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
STATIC = os.path.join(ROOT, "static", "js")
SOURCES = ("wdash.js", "async-dashboard.js")


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _without_comments(source):
    """Drop comments only.

    An earlier version also tried to blank string literals and got it wrong:
    an unpaired quote inside a regex literal let the pattern run across dozens
    of lines and swallow real method definitions, so the check reported
    perfectly good code as missing. A check that cries wolf is worse than no
    check — it teaches you to skip the failure.
    """
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"^\s*//.*$", "", source, flags=re.M)


def _node_available():
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


class BundleParsesTest(unittest.TestCase):
    def test_every_bundle_parses(self):
        if not _node_available():
            self.skipTest("node is not available")
        for name in SOURCES + ("wdash.min.js",):
            result = subprocess.run(["node", "--check", os.path.join(STATIC, name)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0,
                             f"{name} does not parse:\n{result.stderr}")


class MethodsExistTest(unittest.TestCase):
    """Every private `this._foo(...)` must resolve to a method that exists."""

    def test_no_call_to_an_undefined_method(self):
        for name in SOURCES:
            source = _without_comments(_read(os.path.join(STATIC, name)))

            defined = set(re.findall(
                r"^\s{4}(?:static\s+|async\s+)*([A-Za-z_$][\w$]*)\s*\(",
                source, flags=re.M))

            # Locals holding the instance, so `self.foo()` means `this.foo()`.
            aliases = {"this"}
            aliases |= set(re.findall(r"(?:const|let|var)\s+([\w$]+)\s*=\s*this\s*[;,]",
                                      source))

            called = set()
            for alias in aliases:
                called |= set(re.findall(
                    re.escape(alias) + r"\.([A-Za-z_$][\w$]*)\s*\(", source))

            # Only private helpers: a public name may be inherited or built-in.
            missing = sorted(m for m in called - defined if m.startswith("_"))
            self.assertEqual(missing, [],
                             f"{name} calls undefined method(s): {missing}")


class MinifiedBundleIsCurrentTest(unittest.TestCase):
    """`base.html` loads wdash.min.js, so a stale build ships nothing.

    Editing wdash.js and forgetting to rebuild means the browser never sees the
    change, while every test still passes. Method names survive minification,
    so one present in the source and absent from the bundle proves it is stale.
    """

    def test_every_method_reaches_the_bundle(self):
        source = _without_comments(_read(os.path.join(STATIC, "wdash.js")))
        bundle = _read(os.path.join(STATIC, "wdash.min.js"))

        defined = set(re.findall(
            r"^\s{4}(?:static\s+|async\s+)*(_[A-Za-z_$][\w$]*)\s*\(",
            source, flags=re.M))
        missing = sorted(m for m in defined if m not in bundle)
        self.assertEqual(
            missing, [],
            "wdash.min.js is stale — rebuild with:\n"
            "  npx terser static/js/wdash.js -o static/js/wdash.min.js "
            "--compress --mangle\n"
            f"missing: {missing}")


class ElementLookupsTest(unittest.TestCase):
    def test_every_element_looked_up_exists_in_a_template(self):
        """`getElementById` on an id no template defines is dead code."""
        source = "".join(_read(os.path.join(STATIC, name)) for name in SOURCES)

        templates = ""
        template_dir = os.path.join(ROOT, "templates")
        for entry in sorted(os.listdir(template_dir)):
            if entry.endswith(".html"):
                templates += _read(os.path.join(template_dir, entry))

        looked_up = set(re.findall(
            r"getElementById\(\s*['\"]([\w-]+)['\"]\s*\)", source))
        # Ids the JS creates itself, either written into innerHTML or assigned
        # onto a fresh element — they will never appear in a template.
        assigned = set(re.findall(r"\.id\s*=\s*['\"]([\w-]+)['\"]", source))
        self_made = assigned | {i for i in looked_up
                                if f'id="{i}"' in source or f"id='{i}'" in source}

        missing = sorted(i for i in looked_up - self_made
                         if f'id="{i}"' not in templates)
        self.assertEqual(
            missing, [],
            f"the JS looks up element id(s) no template defines: {missing}")


class StackingContextTest(unittest.TestCase):
    """The navbar must outrank page content, or its dropdown disappears.

    `backdrop-filter` establishes a stacking context. It is on `.card`, which
    is on every page, and it was on the navbar — both at `z-index: auto`, so
    paint order fell to document order and the cards won. The account dropdown
    opened behind the page on every screen but Logs, whose first card happens
    to sit far enough down the template to miss it.

    A z-index inside the dropdown cannot fix that: it ranks the element within
    its own stacking context, and the dropdown's context is the navbar's.
    """

    CSS = os.path.join(ROOT, "static", "css", "wdash.css")

    def _rule(self, selector):
        body = _read(self.CSS)
        match = re.search(r"(?<![\w-])" + re.escape(selector) + r"\s*\{([^}]*)\}",
                          body)
        return match.group(1) if match else None

    def _z_index(self, selector):
        rule = self._rule(selector) or ""
        match = re.search(r"z-index:\s*(\d+)", rule)
        return int(match.group(1)) if match else None

    def test_the_navbar_declares_a_stacking_level(self):
        rule = self._rule(".navbar")
        self.assertIsNotNone(rule, "no .navbar rule at all")
        self.assertIn("position", rule,
                      "z-index does nothing on a statically positioned element")
        self.assertIsNotNone(self._z_index(".navbar"),
                             "the navbar is back to competing on document order")

    def test_the_navbar_outranks_a_dropdown_and_loses_to_a_modal(self):
        """Both directions matter, and they pull opposite ways.

        Too low and the dropdown vanishes behind a card. Too high and the
        navbar floats over an open modal's backdrop, which looks like the
        modal failed to open.
        """
        navbar = self._z_index(".navbar")
        self.assertGreater(navbar, 1000, "below Bootstrap's dropdown level")
        self.assertLess(navbar, 1050, "above Bootstrap's modal backdrop")

    def test_page_content_does_not_claim_a_level_of_its_own(self):
        """One element with a bigger number puts the whole fix back."""
        body = _read(self.CSS)
        offenders = []
        for selector, rule in re.findall(r"([^{}]+)\{([^}]*)\}", body):
            selector = selector.strip().split("/*")[-1].strip()
            if not selector or selector.startswith("@") or "navbar" in selector:
                continue
            match = re.search(r"z-index:\s*(\d+)", rule)
            if match and int(match.group(1)) >= 1030:
                offenders.append(f"{selector} ({match.group(1)})")
        self.assertEqual(
            offenders, [],
            f"page content outranks the navbar: {offenders}")


class ChartPluginsTest(unittest.TestCase):
    """A chart's plugins go in its own config, never `Chart.register`.

    The monitor page drew its failure marks with a plugin registered
    globally AFTER the chart was built. Measured on Chart.js 3.9.1 in
    Chromium: a chart resolves its plugins as it draws, so the first paint
    had no marks at all, and they appeared once something redrew the chart —
    a hover, a resize. A global registration also reaches every other chart
    on the page. Read from every template and script that builds a chart.
    """

    def test_nothing_registers_a_plugin_globally(self):
        offenders = []
        folders = ((os.path.join(ROOT, "templates"), ".html"),
                   (os.path.join(ROOT, "static", "js"), ".js"))
        for folder, suffix in folders:
            for name in sorted(os.listdir(folder)):
                if not name.endswith(suffix) or name.endswith(".min.js"):
                    continue
                text = re.sub(r"^\s*//.*$", "", _read(os.path.join(folder, name)),
                              flags=re.M)
                if "Chart.register(" in text:
                    offenders.append(name)
        self.assertEqual(offenders, [], f"global chart plugins in {offenders}")

    def test_the_failure_marks_are_the_charts_own(self):
        page = _read(os.path.join(ROOT, "templates", "monitor_detail.html"))
        self.assertIn("plugins: [failureMarks]", page)


class FrontendSmokeTest(unittest.TestCase):
    """Run the jsdom suites if the toolchain is there; skip if it is not."""

    def _run(self, name):
        if not _node_available():
            self.skipTest("node is not available")

        runner = os.path.join(ROOT, "tests", name)
        result = subprocess.run(["node", runner], capture_output=True, text=True,
                                cwd=ROOT, env=dict(os.environ))

        if result.returncode != 0 and "Cannot find module 'jsdom'" in result.stderr:
            self.skipTest("jsdom is not installed (npm install jsdom)")

        self.assertEqual(result.returncode, 0,
                         f"{name} failures:\n{result.stdout}\n{result.stderr}")

    def test_browser_smoke_suite(self):
        self._run("frontend_smoke.js")

    def test_dashboard_smoke_suite(self):
        """The dashboard bundle is a separate script, loaded only by
        dashboard_view.html — so the log-page suite never touched it, and a
        spinner that never stopped passed everything."""
        self._run("dashboard_smoke.js")

    def test_config_smoke_suite(self):
        """Was in `npm test` and nowhere else, so the Python run — which is
        what CI executes — never touched it. Found by the check below on its
        first run."""
        self._run("config_smoke.js")

    def test_every_jsdom_suite_is_run_from_here(self):
        """A suite nobody runs is a suite that rots. `npm test` lists them
        too, but the Python run is what CI executes."""
        import re
        source = open(__file__).read()
        run_here = set(re.findall(r'self\._run\("([^"]+)"\)', source))
        on_disk = {name for name in os.listdir(os.path.join(ROOT, "tests"))
                   if name.endswith("_smoke.js")}
        self.assertEqual(on_disk - run_here, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)


class LabSeedTest(unittest.TestCase):
    """No two lab seeders may share a random seed.

    `seed_tempo.py` was created by copying `seed_jaeger.py`, seed included.
    Same seed, same generator calls in the same order — so both backends were
    written the SAME trace and span ids under different service names, and the
    trace fan-out merged two unrelated traces into one waterfall.

    It was correct behaviour: a trace id is globally unique by construction,
    so two backends holding one id hold two halves of one trace. The lab was
    lying, and it looked exactly like an adapter bug. A fixed seed makes the
    lab reproducible; a SHARED one makes it wrong.
    """

    def _seeds(self):
        import ast
        import pathlib

        seeds = {}
        directory = pathlib.Path(ROOT) / "lab" / "seed"
        for path in sorted(directory.glob("seed*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and getattr(node.func, "attr", "") == "add_argument"
                        and node.args
                        and getattr(node.args[0], "value", "") == "--seed"):
                    continue
                for keyword in node.keywords:
                    if keyword.arg != "default":
                        continue
                    value = getattr(keyword.value, "value", None)
                    if value is not None:
                        seeds.setdefault(value, []).append(path.name)
        return seeds

    def test_no_two_seeders_share_a_seed(self):
        clashes = {seed: files for seed, files in self._seeds().items()
                   if len(files) > 1}
        self.assertEqual(clashes, {},
                         f"seeders generating identical data: {clashes}")

    def test_the_seeders_are_actually_found(self):
        """A path that matches nothing makes the check above pass forever."""
        self.assertGreaterEqual(len(self._seeds()), 3)


class TheMarkIsOursTest(unittest.TestCase):
    """The navbar carries WDash's own mark, in three places that must agree.

    It replaced a Font Awesome magnifying glass in the navbar and a terminal
    glyph on the landing page — icons the product borrowed, which mean
    "search" and "a shell" on every other site that uses them. The drawing
    now exists four times: the navbar, the landing hero, the favicon, and the
    candidate it was chosen from. Copies of one shape drift, and the only
    symptom is a mark on one screen that has quietly stopped matching the
    others.
    """

    NAVBAR = os.path.join(ROOT, "templates", "base.html")
    HERO = os.path.join(ROOT, "templates", "index.html")
    FAVICON = os.path.join(ROOT, "static", "img", "wdash-mark.svg")
    PNG = os.path.join(ROOT, "static", "img", "wdash-mark-32.png")
    CANDIDATE = os.path.join(ROOT, "docs", "logo", "1-pulse-in-brackets.svg")

    def _paths(self, path):
        """Every `d` attribute in a file, in order."""
        return re.findall(r'\bd="([^"]+)"', _read(path))

    @staticmethod
    def _prose_removed(markup):
        """Jinja and HTML comments dropped.

        Both files explain what the mark replaced, and they name it: the
        check below reads `fa-terminal` in a sentence about `fa-terminal` as
        the fault it is looking for. The same trap as a CSS comment that
        writes out the token it is describing, which is why `stylesheet()`
        in tests/test_contrast.py strips first too.
        """
        markup = re.sub(r"\{#.*?#\}", "", markup, flags=re.S)
        return re.sub(r"<!--.*?-->", "", markup, flags=re.S)

    def _hero(self):
        hero = _read(self.HERO).split('class="landing-logo"')[1]
        return self._prose_removed(hero.split("</div>")[0])

    def test_no_screen_borrows_an_icon_for_the_brand(self):
        brand = _read(self.NAVBAR).split('class="navbar-brand"')[1]
        brand = self._prose_removed(brand.split("</a>")[0])
        self.assertNotIn("fa-search", brand)
        self.assertIn('class="wdash-mark"', brand)
        hero = self._hero()
        self.assertNotIn("fa-terminal", hero)
        self.assertIn("wdash-mark", hero)

    def _inline_marks(self):
        """Every inline copy of the mark in any template, by file.

        Found by scanning rather than by naming the files: the mark went into
        the navbar and the favicon and stopped there, and the landing page
        kept a borrowed glyph for a day because nothing looked wider than the
        two places the change was made.
        """
        found = {}
        templates = os.path.join(ROOT, "templates")
        for name in sorted(os.listdir(templates)):
            if not name.endswith(".html"):
                continue
            markup = self._prose_removed(_read(os.path.join(templates, name)))
            for block in re.findall(r"<svg[^>]*\bwdash-mark\b.*?</svg>",
                                    markup, flags=re.S):
                found.setdefault(name, []).append(
                    re.findall(r'\bd="([^"]+)"', block))
        return found

    def test_every_copy_is_the_same_drawing(self):
        candidate = self._paths(self.CANDIDATE)
        self.assertEqual(len(candidate), 3, "the candidate lost a stroke")
        self.assertEqual(candidate, self._paths(self.FAVICON),
                         "the favicon is not the mark that was chosen")

        inline = self._inline_marks()
        # The three screens that carry it today. Named so that losing one is
        # a failure rather than a test that quietly checks less.
        self.assertEqual(sorted(inline), ["base.html", "index.html",
                                          "setup.html"])
        for name, copies in inline.items():
            for number, paths in enumerate(copies):
                with self.subTest(template=name, copy=number):
                    self.assertEqual(paths, candidate)

    def test_the_navbar_mark_takes_its_ink_from_the_page(self):
        """`currentColor` for the brackets is what makes one file serve both
        themes. The accent is the only colour written, and it is written as
        the palette's own name."""
        brand = _read(self.NAVBAR).split('class="navbar-brand"')[1]
        brand = self._prose_removed(brand.split("</a>")[0])
        self.assertIn('stroke="currentColor"', brand)
        self.assertIn('stroke="var(--accent)"', brand)

    def test_the_brand_gives_the_mark_ink_rather_than_the_brand_colour(self):
        """`.navbar-brand` is accent-coloured, so `currentColor` there IS the
        accent — the whole drawing came out cyan and the pulse, the one
        element meant to stand out, vanished into it."""
        css = _read(os.path.join(ROOT, "static", "css", "wdash.css"))
        rule = re.search(r"\.navbar-brand \.wdash-mark\s*\{([^}]*)\}", css)
        self.assertIsNotNone(rule, "nothing gives the mark its own colour")
        self.assertIn("var(--text-primary)", rule.group(1))

    def test_the_favicon_is_declared_and_present(self):
        head = _read(self.NAVBAR)
        for rel, filename in (('rel="icon" type="image/svg+xml"',
                               "img/wdash-mark.svg"),
                              ('rel="alternate icon" type="image/png"',
                               "img/wdash-mark-32.png")):
            with self.subTest(rel=rel):
                self.assertIn(rel, head)
                self.assertIn(filename, head)
        self.assertTrue(os.path.exists(self.FAVICON))
        self.assertTrue(os.path.exists(self.PNG))

    def test_the_svg_favicon_carries_its_own_ink(self):
        """A browser fetches it on its own, so it inherits nothing. Without a
        `prefers-color-scheme` rule the mark is near-black on a dark tab
        strip, which is where half the readers are."""
        # Comments stripped first. The file explains its own scoping rule in
        # prose, and the prose quotes the selector it is warning against —
        # so the check below read the warning as the fault.
        source = re.sub(r"<!--.*?-->", "", _read(self.FAVICON), flags=re.S)
        self.assertIn("prefers-color-scheme: dark", source)
        # Scoped to its own id: an unscoped rule for `svg` would reach every
        # sparkline on any page this was inlined into.
        self.assertRegex(source, r"#wdash-mark\s*\{[^}]*color:")
        self.assertNotRegex(source, r"(?<![\w#.-])svg\s*\{")

    def test_the_png_fallback_is_a_32_pixel_png(self):
        """Read out of the file rather than trusted: this one is generated,
        and a generator that writes an HTML error page under a .png name
        produces a tab icon nobody notices is missing."""
        with open(self.PNG, "rb") as handle:
            data = handle.read()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(data[12:16], b"IHDR")
        self.assertEqual(int.from_bytes(data[16:20], "big"), 32)
        self.assertEqual(int.from_bytes(data[20:24], "big"), 32)


class AssetsAreVersionedTest(unittest.TestCase):
    """`?v=` on a static URL, and what it was actually doing.

    Every template appended `?v={{ range(1000,9999) | random }}` — a new
    number on every page load. That is not cache-busting, it is cache
    DEFEATING: wdash.css and wdash.min.js were fetched again on every single
    view, and the nginx sidecar's `expires 1y; immutable` never applied to the
    two files it was written for.

    The favicon and the mark had the opposite problem. They carried no version
    at all, so they were the only assets the year-long cache really held — and
    the release that changed the mark would have gone on showing the old one
    to everyone who had loaded a page before it.

    Both halves are one rule: the stamp changes when the files can change, and
    not otherwise.
    """

    ROOT = os.path.join(os.path.dirname(__file__), "..")
    TEMPLATES = os.path.join(ROOT, "templates")

    def _templates(self):
        for directory, _, files in os.walk(self.TEMPLATES):
            for filename in files:
                if filename.endswith(".html"):
                    yield os.path.join(directory, filename)

    def test_every_local_asset_carries_the_version(self):
        """Anything served from /static, including the icons."""
        unversioned = []
        for path in self._templates():
            for line in _read(path).splitlines():
                for match in re.finditer(r"url_for\(\s*'static'.*?\}\}", line):
                    tail = line[match.end():match.end() + 24]
                    if not tail.startswith("?v={{ asset_version }}"):
                        unversioned.append(
                            f"{os.path.basename(path)}: {match.group(0)[:60]}")
        self.assertEqual(unversioned, [], "\n".join([""] + unversioned))

    def test_no_template_stamps_a_number_that_moves_on_its_own(self):
        """The literal that was there. Named so that putting it back fails
        here rather than in a page-load measurement nobody takes."""
        for path in self._templates():
            self.assertNotIn("random }}", _read(path),
                             f"{os.path.basename(path)} versions an asset "
                             f"with a value that changes every render")

    def test_two_renders_of_one_page_ask_for_the_same_url(self):
        """The check that survives a rewrite: whatever the stamp is spelled
        as, a second visit must be allowed to hit the cache."""
        import sys
        sys.path.insert(0, os.path.join(self.ROOT, "src"))
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        class RenderConfig(Config):
            TESTING = True
            SECRET_KEY = "assets"
            DATABASE_URL = "sqlite:///:memory:"
            ELASTICSEARCH_URL = ""
            ENCRYPTION_KEY = SecretBox.generate_key()

        client = create_app(RenderConfig).test_client()
        stamps = []
        for _ in range(2):
            # Followed, because a fresh store sends every route to /setup —
            # and a 302 has no body to measure.
            body = client.get("/auth/login",
                              follow_redirects=True).get_data(as_text=True)
            stamps.append(re.findall(r"\?v=([^\"'&]+)", body))
        self.assertTrue(stamps[0], "the page asks for no versioned asset")
        self.assertEqual(stamps[0], stamps[1])

    def test_the_stamp_is_the_release(self):
        """A number that is not the version is a number nobody can reason
        about during an upgrade."""
        import sys
        sys.path.insert(0, os.path.join(self.ROOT, "src"))
        from wdash import __version__
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        class RenderConfig(Config):
            TESTING = True
            DEBUG = False
            SECRET_KEY = "assets"
            DATABASE_URL = "sqlite:///:memory:"
            ELASTICSEARCH_URL = ""
            ENCRYPTION_KEY = SecretBox.generate_key()

        body = create_app(RenderConfig).test_client().get(
            "/auth/login", follow_redirects=True).get_data(as_text=True)
        self.assertIn(f"?v={__version__}", body)
