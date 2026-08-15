"""
Text that can actually be read.

`.badge` sets `color: var(--surface-page)` — the PAGE BACKGROUND colour. On the
bright fills (warning, info, success) that is right: dark text on a light
chip. On a dark fill it is the same colour as what is behind it, and the
Advisor's "Affected" chips were `#0d1117` on `#212529`: a contrast ratio of
1.23:1, against the 4.5:1 that normal text needs to be legible.

Nothing failed. The badges rendered, the layout was correct, the text was
there — and invisible. That is the whole reason this file exists: a colour
mistake produces no error anywhere, so the only way to catch one is to
measure it.

The ratios come from WCAG 2.1: 4.5:1 for normal text, 3:1 for large or bold.
"""

import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
CSS = os.path.join(ROOT, "static", "css", "wdash.css")

#: WCAG 2.1 AA for normal-sized text.
AA_NORMAL = 4.5

#: And for large or bold text — the wordmark on the landing page is 3.5rem.
AA_LARGE = 3.0


def stylesheet():
    """`wdash.css`, with its comments removed.

    Everything in this file reads CSS with a regex, and a regex cannot tell a
    declaration from prose about one. Renaming the palette, the new header
    explained the old name by writing `--dark-bg: #ffffff` inside a comment —
    and that matched as a declaration whose greedy value ran on to the next
    semicolon, swallowing the real token four lines below it. The palette
    then had no page background at all, and three tests failed a long way
    from the comment that caused it.

    Stripping first is the fix, rather than a rule against explaining
    yourself in a comment.
    """
    with open(CSS) as handle:
        return _without_comments(handle.read())


def _without_comments(css):
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _variables(css):
    return {name: value.strip()
            for name, value in re.findall(r"(--[\w-]+):\s*([^;]+);",
                                          _without_comments(css))}


def flatten(value, variables):
    """A declaration with every token and every `color-mix` written out.

    The parsers below look for literal colours — the stops of a gradient, the
    alpha of a tint. Once the stylesheet says `var(--hue-red)` and
    `color-mix(in srgb, var(--hue-red) 12%, transparent)` instead of the hex
    and the `rgba()`, none of them find anything, and a test that finds
    nothing to measure passes.

    So the tokens are substituted first, and a mix with `transparent` is
    written back as the `rgba()` it renders as: mixing a colour with
    transparent in sRGB is the same colour at that alpha, which is why the
    stylesheet could be converted with no pixel changing at all.
    """
    for _ in range(6):
        substituted = re.sub(
            r"var\((--[\w-]+)\)",
            lambda m: variables.get(m.group(1), m.group(0)), value)
        if substituted == value:
            break
        value = substituted

    def unmix(match):
        colour, share = match.group(1).strip(), float(match.group(2))
        red, green, blue = _rgb(colour)
        return f"rgba({red}, {green}, {blue}, {share / 100})"

    return re.sub(r"color-mix\(\s*in\s+srgb\s*,\s*(#[0-9a-fA-F]{3,8})\s+"
                  r"([\d.]+)%\s*,\s*transparent\s*\)", unmix, value)


def palettes():
    """Every theme's complete palette, by name.

    `_variables` over the whole file would give one flattened dictionary in
    which the last definition wins — so the moment a second theme existed,
    every measurement below would have been of whichever palette happened to
    be written last, and the other would have gone unchecked while reading as
    covered.
    """
    css = stylesheet()
    base = _variables(css[:css.index("}")])
    themes = {"dark": base}
    for match in re.finditer(r':root\[data-theme="(\w+)"\]\s*\{([^}]*)\}',
                             css):
        themes[match.group(1)] = {**base, **_variables(match.group(2))}
    return themes


def measurable_stylesheet(theme="dark"):
    """The stylesheet with every colour written out, in one theme.

    For the tests that MEASURE. The ones that assert the stylesheet says
    `var(--surface-page)` read the real thing instead — flattened, that
    assertion would be checking a colour rather than the token, which is the
    opposite of what it is for.
    """
    return flatten(stylesheet(), palettes()[theme])


def _resolve(value, variables, depth=0):
    """Follow `var(--x)` chains to a literal colour."""
    value = value.strip()
    if depth > 5:
        return None
    match = re.fullmatch(r"var\((--[\w-]+)\)", value)
    if match:
        return _resolve(variables.get(match.group(1), ""), variables, depth + 1)
    match = re.match(r"#[0-9a-fA-F]{3,8}", value)
    return match.group(0) if match else None


def _rgb(colour):
    colour = colour.lstrip("#")
    if len(colour) == 3:
        colour = "".join(c * 2 for c in colour)
    return tuple(int(colour[i:i + 2], 16) for i in (0, 2, 4))


def _luminance(colour):
    def channel(value):
        value /= 255
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4
    red, green, blue = map(channel, _rgb(colour))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast(foreground, background):
    first, second = _luminance(foreground), _luminance(background)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


def _rule(css, selector):
    """The declaration block for an exact selector."""
    pattern = re.compile(re.escape(selector) + r"\s*\{([^}]*)\}")
    match = pattern.search(css)
    return match.group(1) if match else None


def _declaration(block, property_name):
    match = re.search(rf"(?<![\w-]){property_name}:\s*([^;]+);", block or "")
    if not match:
        return None
    return match.group(1).replace("!important", "").strip()


class ContrastMathTest(unittest.TestCase):
    """The measuring stick, before anything is measured with it."""

    def test_black_on_white_is_the_maximum(self):
        self.assertAlmostEqual(contrast("#000000", "#ffffff"), 21.0, places=1)

    def test_a_colour_against_itself_is_the_minimum(self):
        self.assertAlmostEqual(contrast("#21262d", "#21262d"), 1.0, places=3)

    def test_it_does_not_depend_on_the_order(self):
        self.assertAlmostEqual(contrast("#39c5cf", "#21262d"),
                               contrast("#21262d", "#39c5cf"), places=6)

    def test_short_hex_is_understood(self):
        self.assertAlmostEqual(contrast("#fff", "#000"),
                               contrast("#ffffff", "#000000"), places=6)


class BadgeContrastTest(unittest.TestCase):
    THEME = "dark"

    def setUp(self):
        self.css = stylesheet()
        self.variables = palettes()[self.THEME]

    def _colours(self, selector):
        block = _rule(self.css, selector)
        self.assertIsNotNone(block, f"{selector} is not in wdash.css")
        foreground = _resolve(_declaration(block, "color") or "", self.variables)
        background = _resolve(_declaration(block, "background") or
                              _declaration(block, "background-color") or "",
                              self.variables)
        self.assertIsNotNone(foreground, f"{selector} has no readable colour")
        self.assertIsNotNone(background, f"{selector} has no readable background")
        return foreground, background

    def test_the_affected_chips_are_legible(self):
        """The reported fault: black on near-black, 1.23:1."""
        foreground, background = self._colours(".badge.target-chip")
        ratio = contrast(foreground, background)
        self.assertGreaterEqual(
            ratio, AA_NORMAL,
            f"{foreground} on {background} is {ratio:.2f}:1")

    def test_the_affected_chips_are_told_apart_from_a_category_chip(self):
        """"Give it a colour that distinguishes it" — the point was not only
        that it should be visible but that it should not read as another grey
        category badge."""
        target, _ = self._colours(".badge.target-chip")
        plain = _resolve(_declaration(_rule(self.css, ".bg-secondary"), "color"),
                         self.variables)
        self.assertNotEqual(target.lower(), (plain or "").lower())

    def test_a_dark_badge_is_legible_wherever_it_is_used(self):
        """The root cause, not just its one victim: `.badge` defaults its text
        to the page background, so ANY dark-filled badge inherits invisible
        text. Fixed for the class, so the next one does not repeat it."""
        foreground, background = self._colours(".badge.bg-dark")
        ratio = contrast(foreground, background)
        self.assertGreaterEqual(
            ratio, AA_NORMAL, f"{foreground} on {background} is {ratio:.2f}:1")

    def test_the_default_badge_colour_is_ink_rather_than_the_background(self):
        """It WAS the page background, and that was right by coincidence.

        Dark text on a bright warning fill is what it produced, and that is
        what a badge needs. But it produced it by borrowing a colour that
        means something else, and the coincidence only holds while the page
        is dark: a light theme sets the page background to white and the
        warning badge becomes white lettering on yellow.

        So the ink is its own token, dark in every theme, because the fill it
        sits on is bright in every theme. The templates used to patch around
        this by adding Bootstrap's `text-dark` to seven badges — a fixed
        colour, remembered by hand, on the ones somebody noticed.
        """
        block = _rule(self.css, ".badge")
        self.assertEqual(_declaration(block, "color"), "var(--text-on-fill)")

    def test_every_badge_fill_a_page_uses_is_legible(self):
        """Every `badge bg-x` the templates and scripts actually write.

        Discovered rather than listed, so a new one is measured the day it
        appears instead of the day somebody squints at it. Written as a list,
        this test would have been passing about the five fills I happened to
        think of.

        It found a real one: `badge bg-success` is used in three places, and
        Bootstrap's `#198754` is 4.18:1 under dark ink and 4.16:1 under
        light. There is no ink that fixes a mid-tone — the fill had to
        change, and the palette already had hues built to carry dark text.
        """
        css = measurable_stylesheet(self.THEME)
        default_ink = _resolve(_declaration(_rule(css, ".badge"), "color"),
                               self.variables)

        for fill in sorted(self._fills_in_use()):
            block = _rule(css, f".badge.bg-{fill}") or _rule(css, f".bg-{fill}")
            # No rule at all means Bootstrap paints it, and Bootstrap's
            # mid-tones are the thing this test exists to keep out. Asserted
            # rather than skipped: an earlier version of this passed over any
            # fill it could not resolve, so DELETING the rule for
            # `bg-success` — the very failure that prompted the fix — went
            # straight through it.
            self.assertIsNotNone(
                block,
                f"badge bg-{fill} is left to Bootstrap, whose primary, "
                f"success and danger measure about 4.2:1 against any ink")

            ink = _resolve(_declaration(block, "color") or "",
                           self.variables) or default_ink
            painted = (_declaration(block, "background")
                       or _declaration(block, "background-color") or "")
            stops = _gradient_stops(painted) or \
                [_resolve(painted, self.variables)]
            self.assertTrue(stops and stops[0],
                            f"badge bg-{fill} has no colour to measure")
            for stop in stops:
                ratio = contrast(ink, stop)
                self.assertGreaterEqual(
                    ratio, AA_NORMAL,
                    f"badge bg-{fill}: {ink} on {stop} is {ratio:.2f}:1")

    @staticmethod
    def _fills_in_use():
        found = set()
        for folder, suffix in ((os.path.join(ROOT, "templates"), ".html"),
                               (os.path.join(ROOT, "static", "js"), ".js")):
            for name in os.listdir(folder):
                if not name.endswith(suffix) or name.endswith(".min.js"):
                    continue
                with open(os.path.join(folder, name)) as handle:
                    found.update(re.findall(r"badge bg-([a-z]+)",
                                            handle.read()))
        return found

    def test_the_fills_were_actually_found(self):
        """A discovery that discovers nothing passes every assertion above
        it."""
        self.assertGreaterEqual(len(self._fills_in_use()), 5)


class TemplateUsesTheStyleTest(unittest.TestCase):
    """A rule nothing applies is a rule that gets deleted as unused."""

    def test_the_advisor_marks_its_targets(self):
        with open(os.path.join(ROOT, "templates", "advisor.html")) as handle:
            template = handle.read()
        self.assertIn("badge target-chip", template)

    def test_no_template_still_uses_the_invisible_combination(self):
        """`badge bg-dark` without the fix above was the exact fault. It is
        legible now, but grepping keeps the search honest if the CSS moves."""
        templates = os.path.join(ROOT, "templates")
        offenders = []
        for name in sorted(os.listdir(templates)):
            if not name.endswith(".html"):
                continue
            with open(os.path.join(templates, name)) as handle:
                for number, line in enumerate(handle, 1):
                    if "badge bg-dark" in line and "target-chip" not in line:
                        offenders.append(f"{name}:{number}")
        self.assertEqual(offenders, [], f"unstyled dark badges: {offenders}")


if __name__ == "__main__":
    unittest.main()


def composite(foreground_rgba, backdrop):
    """Flatten `rgba(r, g, b, a)` onto an opaque colour.

    Row tints are translucent, so the colour a reader actually sees is the
    blend — measuring the declared rgba against anything would be measuring a
    colour that never appears on screen.
    """
    red, green, blue, alpha = foreground_rgba
    base = _rgb(backdrop)
    blended = tuple(round(alpha * channel + (1 - alpha) * base[i])
                    for i, channel in enumerate((red, green, blue)))
    return "#%02x%02x%02x" % blended


def _parse_rgba(value):
    match = re.search(r"rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)"
                      r"(?:[,\s/]+([\d.]+))?\s*\)", value or "")
    if not match:
        return None
    red, green, blue = (float(match.group(i)) for i in (1, 2, 3))
    alpha = float(match.group(4)) if match.group(4) else 1.0
    return (red, green, blue, alpha)


def _gradient_stops(value):
    """Every hex colour in a `linear-gradient(...)`, in order."""
    return re.findall(r"#[0-9a-fA-F]{3,8}", value or "")


class MonitorColourTest(unittest.TestCase):
    """The Monitors page, in this theme rather than Bootstrap's.

    `.table-danger` and `.table-warning` are built for a light page: they
    paint an opaque pastel row. On a near-black table that arrived as a strip
    of near-white — the loudest thing on screen, and louder than the text it
    was drawing attention to.

    What replaced them is the palette `.log-level` already uses, so a red row
    here is the same red as an ERROR badge on the Logs page. A product with
    two reds has two vocabularies.
    """

    THEME = "dark"

    def setUp(self):
        self.css = measurable_stylesheet(self.THEME)
        self.variables = palettes()[self.THEME]
        self.card = _resolve("var(--surface-card)", self.variables)
        self.page = _resolve("var(--surface-page)", self.variables)

    def _block(self, selector):
        block = _rule(self.css, selector)
        self.assertIsNotNone(block, f"{selector} is not in wdash.css")
        return block

    # ---------- status badges ----------

    def test_every_status_badge_is_legible(self):
        """The text colour comes from `.monitor-status`; each state only
        supplies a gradient. Both ends of the gradient have to work, because a
        badge is wide enough to show both."""
        text = _resolve(_declaration(self._block(".monitor-status"), "color"),
                        self.variables)
        for state in ("up", "down"):
            background = _declaration(self._block(f".monitor-status.{state}"),
                                      "background")
            stops = _gradient_stops(background)
            self.assertTrue(stops, f"{state} has no colour")
            for stop in stops:
                ratio = contrast(text, stop)
                self.assertGreaterEqual(
                    ratio, AA_NORMAL,
                    f".monitor-status.{state}: {text} on {stop} is {ratio:.2f}:1")

    def test_unknown_carries_its_own_text_colour(self):
        """The grey it sits on is dark, so the dark text the others use would
        vanish. It declares its own rather than inheriting one that does not
        work."""
        block = self._block(".monitor-status.unknown")
        text = _resolve(_declaration(block, "color"), self.variables)
        self.assertIsNotNone(text, "unknown inherits a colour that does not fit")
        stops = _gradient_stops(_declaration(block, "background"))
        # Asserted rather than looped over: an empty list would make the loop
        # below a no-op and this test would pass against a badge with no
        # background at all.
        self.assertTrue(stops, "unknown has no background to measure")
        for stop in stops:
            ratio = contrast(text, stop)
            self.assertGreaterEqual(
                ratio, AA_NORMAL, f"{text} on {stop} is {ratio:.2f}:1")

    def test_every_log_level_badge_is_legible_too(self):
        """One standard, not one for the new page.

        `.log-level.TRACE` was the only badge in the theme below AA — light
        text on mid-grey, 2.83:1, on the smallest text on the page. It was
        found by holding the monitor badges to this and noticing they had
        inherited exactly the same pair.
        """
        import re
        pattern = re.compile(r"(\.log-level\.[A-Z,\s.\-]+?)\s*\{([^}]*)\}")
        checked = 0
        for match in pattern.finditer(self.css):
            selector, block = match.group(1).strip(), match.group(2)
            background = _declaration(block, "background")
            text = _resolve(_declaration(block, "color"), self.variables)
            stops = _gradient_stops(background)
            if not stops or not text:
                continue
            checked += 1
            for stop in stops:
                ratio = contrast(text, stop)
                self.assertGreaterEqual(
                    ratio, AA_NORMAL,
                    f"{selector}: {text} on {stop} is {ratio:.2f}:1")
        self.assertGreaterEqual(checked, 6, "the badges were not found at all")

    def test_down_is_the_same_red_the_log_levels_use(self):
        """One vocabulary. A red here that is not the ERROR red teaches the
        reader that the two mean different things."""
        down = _gradient_stops(
            _declaration(self._block(".monitor-status.down"), "background"))
        error = _gradient_stops(
            _declaration(_rule(self.css, ".log-level.ERROR,\n.log-level.FATAL")
                         or _rule(self.css, ".log-level.FATAL"), "background"))
        self.assertEqual([c.lower() for c in down], [c.lower() for c in error])

    # ---------- row tints ----------

    def test_a_tinted_row_keeps_its_text_readable(self):
        """The tint is translucent, so what matters is the blend — and the
        body text still has to be readable on it."""
        body = _resolve("var(--text-primary)", self.variables)
        for selector in ("tr.monitor-row-down,\ntr.monitor-row-critical",
                         "tr.monitor-row-warning"):
            block = _rule(self.css, selector)
            self.assertIsNotNone(block, f"{selector} is not in wdash.css")
            rgba = _parse_rgba(_declaration(block, "background"))
            self.assertIsNotNone(rgba, f"{selector} has no translucent tint")
            blended = composite(rgba, self.card)
            ratio = contrast(body, blended)
            self.assertGreaterEqual(
                ratio, AA_NORMAL,
                f"{selector} blends to {blended}, text {ratio:.2f}:1")

    def test_the_tint_is_a_wash_rather_than_a_fill(self):
        """An opaque row is what Bootstrap did, and it is what made the page
        unreadable. Anything above about a fifth is a fill."""
        for selector in ("tr.monitor-row-down,\ntr.monitor-row-critical",
                         "tr.monitor-row-warning"):
            rgba = _parse_rgba(_declaration(_rule(self.css, selector),
                                            "background"))
            self.assertLess(rgba[3], 0.2, f"{selector} is opaque enough to fill")

    def test_a_tinted_row_also_carries_an_edge(self):
        """Colour alone excludes anybody who cannot see it. The bar down the
        left says the same thing without needing hue."""
        for selector in ("tr.monitor-row-down,\ntr.monitor-row-critical",
                         "tr.monitor-row-warning"):
            self.assertIn("inset", _declaration(_rule(self.css, selector),
                                                "box-shadow") or "")

    # ---------- expiry chips ----------

    def test_every_expiry_state_is_legible_on_its_own_tint(self):
        for state in ("ok", "warning", "critical", "expired"):
            block = _rule(self.css, f".expiry-chip.{state}")
            self.assertIsNotNone(block, f"{state} is not in wdash.css")
            text = _resolve(_declaration(block, "color"), self.variables)
            rgba = _parse_rgba(_declaration(block, "background"))
            blended = composite(rgba, self.card)
            ratio = contrast(text, blended)
            self.assertGreaterEqual(
                ratio, AA_NORMAL,
                f".expiry-chip.{state}: {text} on {blended} is {ratio:.2f}:1")

    def test_expired_is_not_just_another_number_in_the_series(self):
        """It has already happened. Reading it as "very few days left" is
        reading it as the same kind of fact as 3 days."""
        block = self._block(".expiry-chip.expired")
        self.assertIn("uppercase", _declaration(block, "text-transform") or "")


class MonitorTemplateTest(unittest.TestCase):
    """The page has to use the classes, or the CSS is decoration."""

    def setUp(self):
        with open(os.path.join(ROOT, "templates", "monitors.html")) as handle:
            self.template = handle.read()

    def test_no_bootstrap_table_state_survives(self):
        for offender in ("table-danger", "table-warning", "table-success"):
            self.assertNotIn(offender, self.template)

    def test_the_status_cell_uses_the_theme_badge(self):
        self.assertIn("monitor-status", self.template)
        self.assertNotIn("badge bg-danger", self.template)

    def test_the_expiry_cell_uses_the_theme_chip(self):
        self.assertIn("expiry-chip", self.template)

    def test_the_row_state_comes_from_the_server(self):
        """`_certificate_state` owns the thresholds. A template deciding its
        own bands from a number gives the product two, and the one in the HTML
        is the one nobody remembers."""
        self.assertIn("monitor-row-{{ c.state }}", self.template)
        self.assertNotIn("days_remaining <", self.template)


class JourneyStepColourTest(unittest.TestCase):
    THEME = "dark"

    """The step pills inside a journey run.

    Quieter than `.monitor-status` on purpose — they sit in a fold somebody
    opened, and seven shouting pills make the one that failed harder to find.
    Quieter still has to mean legible, and a tinted background over a tinted
    row is exactly where that stops being true by accident.
    """

    def setUp(self):
        self.css = measurable_stylesheet(self.THEME)
        self.variables = palettes()[self.THEME]
        # The steps table sits on `.bg-body-tertiary` inside a card. The card
        # is the darker of the two surfaces it can land on, so it is the one
        # to check against.
        self.card = _resolve("var(--surface-card)", self.variables)

    def _block(self, selector):
        block = _rule(self.css, selector)
        self.assertIsNotNone(block, f"{selector} is not in wdash.css")
        return block

    def test_every_step_state_is_legible(self):
        for state in ("passed", "failed", "skipped"):
            block = self._block(f".journey-step.{state}")
            text = _resolve(_declaration(block, "color"), self.variables)
            ratio = contrast(text, self.card)
            self.assertGreaterEqual(
                ratio, AA_NORMAL,
                f".journey-step.{state}: {text} on the card is {ratio:.2f}:1")

    def test_skipped_does_not_read_as_a_failure(self):
        """A skipped step never ran, because an earlier one stopped the
        journey. Colouring it like a failure says four things broke when one
        did — which is the exact mistake the runner goes out of its way not to
        make."""
        skipped = _resolve(
            _declaration(self._block(".journey-step.skipped"), "color"),
            self.variables)
        failed = _resolve(
            _declaration(self._block(".journey-step.failed"), "color"),
            self.variables)
        self.assertNotEqual(skipped, failed)
        # And it is the palette's muted grey rather than a fourth colour
        # invented for this table. `--text-muted` is what the product
        # already uses for "nothing to report here".
        self.assertEqual(skipped.lower(),
                         _resolve("var(--text-muted)",
                                  self.variables).lower())

    def test_failed_is_the_same_red_the_rest_of_the_product_uses(self):
        """A product with two reds has two vocabularies.

        Against `--hue-red` rather than against the DOWN badge, which is what
        this compared before. The two are the same colour on the dark theme
        and are not meant to be on a light one: the badge is a bright fill
        somebody reads dark text on, and this is text on the page. Comparing
        them was comparing an ink with a surface, and it only looked right
        while every surface happened to be dark.
        """
        failed = _resolve(
            _declaration(self._block(".journey-step.failed"), "color"),
            self.variables).lower()
        self.assertEqual(failed, self.variables["--hue-red"].lower())

    def test_the_ink_red_and_the_fill_red_stay_in_the_same_family(self):
        """Different roles, still one vocabulary. If the ink drifted to
        orange while the fills stayed red, the page would be telling two
        stories about the same fact."""
        ink = _rgb(self.variables["--hue-red"])
        fill = _rgb(self.variables["--fill-red"])
        self.assertEqual(max(range(3), key=lambda i: ink[i]),
                         max(range(3), key=lambda i: fill[i]),
                         "the ink red and the fill red have different "
                         "dominant channels")


# ---------------------------------------------------------------------------
# One place a colour is written down
# ---------------------------------------------------------------------------

#: Colours that do not belong to the theme, with the reason each is exempt.
#: A list like this is where a tokenisation quietly stops being true, so it is
#: kept to things that would be WRONG to theme rather than things that were
#: awkward to convert.
NOT_THEME_COLOURS = {
    "#ff5f57": "the macOS window close button, on the landing page's mock "
               "terminal. A picture of somebody else's chrome.",
    "#febc2e": "the macOS minimise button, same picture.",
    "#28c840": "the macOS zoom button, same picture.",
}


def _blank_comments(text):
    """Comments removed, line numbers kept, so a failure can be found."""
    return re.sub(r"/\*.*?\*/|<!--.*?-->",
                  lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)


class ThePaletteIsTheOnlyPlaceTest(unittest.TestCase):
    """A colour written anywhere else cannot be themed.

    This is the test the light theme is built on, and it is the one that
    keeps it true afterwards. Rendering three palettes onto the real screens
    measured what a theme actually costs, and the palette was the smaller
    half: about a hundred colours were written out across the stylesheet, the
    templates and the scripts, so overriding `:root` moved two thirds of the
    page and left the rest painted for the dark theme.

    The stylesheet is one file and can be read. The scripts are the ones that
    got away with it longest — a chart's gridlines were `#30363d`, which is a
    shade of a dark background and is invisible on a light one, and no test
    about colour had ever looked at a `.js` file.
    """

    def _offenders(self, text, skip_root=False):
        text = _blank_comments(text)
        if skip_root:
            # Every `:root` block, not the first one. Splitting on the first
            # `}` worked while there was one palette and reported the light
            # theme's twenty-two colours as violations the day it arrived —
            # a guard that fails on the correct answer is one people delete.
            text = re.sub(r":root[^{]*\{[^}]*\}",
                          lambda m: "\n" * m.group(0).count("\n"), text)
        found = []
        for number, line in enumerate(text.splitlines(), start=1):
            for literal in re.findall(
                    # Not preceded by `&`: `&#128269;` is a magnifying
                    # glass, and its digits are all valid hex.
                    r"(?<!&)#[0-9a-fA-F]{6}\b|(?<!&)#[0-9a-fA-F]{3}\b"
                    r"(?![0-9a-fA-F;])"
                    r"|rgba?\(\s*\d+[^)]*\)|hsla?\(\s*\d+[^)]*\)", line):
                if literal.lower() in NOT_THEME_COLOURS:
                    continue
                found.append(f"line {number}: {literal}")
        return found

    def test_the_stylesheet_writes_no_colour_outside_the_palette(self):
        offenders = self._offenders(stylesheet(), skip_root=True)
        self.assertEqual(offenders, [], "\n".join(
            ["wdash.css paints with colours a theme cannot reach:"] + offenders))

    def test_no_template_writes_a_colour(self):
        templates = os.path.join(ROOT, "templates")
        offenders = []
        for name in sorted(os.listdir(templates)):
            if not name.endswith(".html"):
                continue
            with open(os.path.join(templates, name)) as handle:
                for line in self._offenders(handle.read()):
                    offenders.append(f"{name} {line}")
        self.assertEqual(offenders, [], "\n".join(
            ["templates paint with colours a theme cannot reach:"] + offenders))

    def test_no_script_writes_a_colour(self):
        scripts = os.path.join(ROOT, "static", "js")
        offenders = []
        for name in sorted(os.listdir(scripts)):
            # The minified bundle is built from wdash.js; checking it as well
            # would report every finding twice and blame a generated file.
            if not name.endswith(".js") or name.endswith(".min.js"):
                continue
            with open(os.path.join(scripts, name)) as handle:
                text = re.sub(r"^\s*//.*$", "", handle.read(), flags=re.M)
            for line in self._offenders(text):
                offenders.append(f"{name} {line}")
        self.assertEqual(offenders, [], "\n".join(
            ["scripts paint with colours a theme cannot reach:"] + offenders))

    def test_every_token_a_script_names_exists(self):
        """`paletteColour` has no fallback, on purpose: a fallback is a
        literal of the theme it was written for. What replaces it is this —
        a token named from a script and missing from the palette is a chart
        drawn in Chart.js's own colours, which nobody would notice.

        Every quoted token name, not only the ones inside a
        `paletteColour(...)` call. The severity table in `wdash.js` carries
        its tokens in an array and hands them over later, so a version of
        this that matched call sites watched the wrong thing: deleting
        `--hue-red-strong` from the palette went straight through it.
        """
        variables = _variables(stylesheet())
        missing = []
        for folder in (os.path.join(ROOT, "static", "js"),
                       os.path.join(ROOT, "templates")):
            for name in sorted(os.listdir(folder)):
                if name.endswith(".min.js"):
                    continue
                if not (name.endswith(".js") or name.endswith(".html")):
                    continue
                with open(os.path.join(folder, name)) as handle:
                    text = _blank_comments(handle.read())
                text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
                for token in re.findall(r"['\"](--[\w-]+)['\"]", text):
                    if token not in variables:
                        missing.append(f"{name}: {token}")
        self.assertEqual(sorted(set(missing)), [],
                         f"named in a script, absent from the palette: "
                         f"{sorted(set(missing))}")

    def test_the_exemptions_are_all_still_used(self):
        """An exemption for a colour nobody writes any more is a hole kept
        open for the next person to fall into."""
        css = stylesheet()
        for colour in NOT_THEME_COLOURS:
            self.assertIn(colour, css.lower(),
                          f"{colour} is exempt and no longer used")


#: Bootstrap utilities that name a theme instead of a role. Each is a fixed
#: colour carrying `!important`, so it wins against every token underneath it
#: — which is the whole problem: a palette can be swapped perfectly and the
#: page still comes out in the theme its classes were written for.
FIXED_THEME_CLASSES = {
    "bg-dark": "`.bg-dark` on <body> painted the page a fixed near-black. "
               "The first light theme rendered white cards floating on a "
               "dark page, and the palette was not the reason.",
    "text-light": "the other half of the same line.",
    "navbar-dark": "the bar looks like the bar; it is not a variant somebody "
                   "selects. The rule moved to `.navbar`.",
    "table-dark": "worse than the others, because it pins the TEXT colour "
                  "too: on a light background the sources table rendered "
                  "white on white. The tokens moved to `.table`, so every "
                  "table follows the theme.",
    "text-dark": "seven badges patched by hand because the default ink was "
                 "the page background. The ink is `--text-on-fill` now.",
    "bg-light": "the same mistake with the colours swapped.",
    "text-white": "a fixed colour where `--text-primary` is meant.",
    "border-dark": "a fixed line colour where `--border` is meant.",
}


class NoTemplateNamesAThemeTest(unittest.TestCase):
    """The half of a theme that does not live in the stylesheet.

    Measured before it was fixed: 24 of these across six templates and three
    scripts. They are why the roadmap said tokenising was only a third of the
    work — with them in place, a light theme is not a palette away, it is a
    palette plus twenty-four edits somebody has to find.
    """

    #: `badge bg-dark` is a Bootstrap class the stylesheet deliberately
    #: restyles — `.badge.bg-dark` exists so that a dark-filled badge is
    #: legible wherever one turns up. Its own test measures it.
    ALLOWED_LINES = ("badge bg-dark",)

    def _scan(self, folder, suffixes):
        offenders = []
        for name in sorted(os.listdir(folder)):
            if not name.endswith(suffixes) or name.endswith(".min.js"):
                continue
            with open(os.path.join(folder, name)) as handle:
                text = _blank_comments(handle.read())
            for number, line in enumerate(text.splitlines(), start=1):
                if any(allowed in line for allowed in self.ALLOWED_LINES):
                    continue
                for fixed in FIXED_THEME_CLASSES:
                    if re.search(rf"(?<![\w-]){fixed}(?![\w-])", line):
                        offenders.append(f"{name}:{number}: {fixed}")
        return offenders

    def test_no_template_names_a_theme(self):
        offenders = self._scan(os.path.join(ROOT, "templates"), (".html",))
        self.assertEqual(offenders, [], "\n".join(
            ["a theme cannot reach these:"] + offenders
            + [f"  {name}: {why}" for name, why in FIXED_THEME_CLASSES.items()
               if any(name in o for o in offenders)]))

    def test_no_script_names_a_theme(self):
        offenders = self._scan(os.path.join(ROOT, "static", "js"), (".js",))
        self.assertEqual(offenders, [], "\n".join(
            ["a theme cannot reach these:"] + offenders))

    def test_nothing_asks_a_third_party_for_a_theme(self):
        """The other way a fixed theme gets in: not a class, a stylesheet.

        flatpickr's dark theme arrived from a CDN and was the last surface in
        the product that could not follow the page — a dark panel over a white
        one. What it was still deciding after the palette took over was
        measured, with every state of the calendar captured with the sheet and
        without it: the rule above the clock, a fixed #20222c, and the month
        dropdown's options, a fixed #3f4458 — dark ink on a dark panel once
        the page was light. Both are in the palette now.

        A `theme:` option in a widget's configuration is the same fault with
        a different spelling, so both are looked for.
        """
        offenders = []
        for folder, suffixes in ((os.path.join(ROOT, "templates"), (".html",)),
                                 (os.path.join(ROOT, "static", "js"),
                                  (".js",))):
            for name in sorted(os.listdir(folder)):
                if not name.endswith(suffixes) or name.endswith(".min.js"):
                    continue
                with open(os.path.join(folder, name)) as handle:
                    text = _blank_comments(handle.read())
                for number, line in enumerate(text.splitlines(), start=1):
                    if re.search(r'href="[^"]*themes?/(dark|light)', line):
                        offenders.append(f"{name}:{number}: a themed "
                                         f"stylesheet from somewhere else")
                    if re.search(r"""["']?theme["']?\s*:\s*["'](dark|light)""",
                                 line):
                        offenders.append(f"{name}:{number}: a widget told "
                                         f"which theme it is in")
        self.assertEqual(offenders, [], "\n".join(
            ["the palette cannot reach these:"] + offenders))

    def test_the_stylesheet_does_not_hang_a_rule_on_one(self):
        """A rule keyed on `.table-dark` is dead the moment the templates stop
        asking for it — and dead in the quietest way, because the table still
        renders, in Bootstrap's colours."""
        css = stylesheet()
        for fixed in ("navbar-dark", "table-dark", "bg-light", "text-light"):
            self.assertIsNone(
                _rule(css, f".{fixed}"),
                f".{fixed} still carries rules, but nothing asks for it")


# ---------------------------------------------------------------------------
# The same measurements, in every theme
# ---------------------------------------------------------------------------
#
# A colour test that reads one palette is a colour test for one theme, and the
# other one ships unmeasured. This is what the roadmap called the honest cost
# of a light theme: not the palette, the fact that everything holding the dark
# one to a standard now has to hold both.
#
# Generated rather than written out, so a theme added to the stylesheet is
# measured by every test above it without anybody remembering to say so — and
# `test_every_theme_in_the_stylesheet_is_measured` fails if that stops being
# true.

_MEASURING = (BadgeContrastTest, MonitorColourTest, JourneyStepColourTest)


def _for_theme(case, theme):
    generated = type(f"{case.__name__}_{theme}", (case,), {"THEME": theme})
    generated.__module__ = __name__
    return generated


for _theme in palettes():
    if _theme == "dark":
        continue                      # the classes above already are dark
    for _case in _MEASURING:
        globals()[f"{_case.__name__}_{_theme}"] = _for_theme(_case, _theme)


class EveryThemeIsMeasuredTest(unittest.TestCase):
    def test_every_theme_in_the_stylesheet_is_measured(self):
        """The generation above is a loop over whatever is in the file. This
        is the assertion that the loop found something — a regex that stops
        matching would silently go back to measuring one theme."""
        for theme in palettes():
            for case in _MEASURING:
                name = case.__name__ if theme == "dark" \
                    else f"{case.__name__}_{theme}"
                self.assertIn(name, globals(),
                              f"{theme} is in the stylesheet and nothing "
                              f"measures it")

    def test_more_than_one_theme_exists(self):
        self.assertGreater(len(palettes()), 1)

    def test_a_theme_inherits_what_it_does_not_override(self):
        """A theme is a patch on the palette, not a replacement. `--fill-*`
        and `--text-on-fill` are deliberately absent from the light theme, so
        they have to arrive from the base."""
        light = palettes()["light"]
        self.assertEqual(light["--fill-red"], palettes()["dark"]["--fill-red"])
        self.assertEqual(light["--text-on-fill"],
                         palettes()["dark"]["--text-on-fill"])


class TextPaintedWithAGradientIsStillTextTest(unittest.TestCase):
    """The one kind of ink no other test in this file can see.

    `-webkit-text-fill-color: transparent` with a gradient clipped to the
    glyphs means the colour a reader sees is the BACKGROUND's, so every check
    here that measures a `color` declaration finds a transparent glyph and
    nothing to measure. It has to be read off the gradient instead.

    Measured on the landing page's wordmark, which ran `--fill-accent` to
    `--fill-blue`: 2.09:1 and 1.95:1 on a white page, against the 3:1 large
    text needs. Those two tokens are deliberately theme-INDEPENDENT — they
    are chip backgrounds, sized to carry `--text-on-fill` on top of them —
    and clipping them to text put the product's own name below the threshold
    on half the installations.
    """

    def _clipped(self):
        """Every rule that paints its text with a gradient."""
        css = stylesheet()
        found = []
        for block in re.findall(r"([^{}]+)\{([^}]*)\}", css):
            selector, body = block[0].strip(), block[1]
            if "text-fill-color: transparent" not in body.replace("-webkit-",
                                                                  ""):
                continue
            gradient = re.search(r"background:\s*([^;]*gradient[^;]*)", body)
            if gradient:
                found.append((selector, gradient.group(1)))
        return found

    def test_there_is_something_to_measure(self):
        """If the landing page stops using one, this class should be deleted
        rather than left passing over nothing."""
        self.assertTrue(self._clipped(),
                        "no clipped gradient found — is this still true?")

    def test_both_ends_are_readable_in_both_themes(self):
        for selector, gradient in self._clipped():
            tokens = re.findall(r"var\((--[\w-]+)\)", gradient)
            self.assertTrue(tokens, f"{selector}: gradient with no token in "
                                    f"it, so nothing here can follow a theme")
            for theme, palette in palettes().items():
                page = palette["--surface-page"]
                for token in tokens:
                    value = palette.get(token)
                    with self.subTest(selector=selector, theme=theme,
                                      token=token):
                        self.assertIsNotNone(value, f"{token} is not in the "
                                                    f"{theme} palette")
                        ratio = contrast(value, page)
                        self.assertGreaterEqual(
                            round(ratio, 2), AA_LARGE,
                            f"{selector} paints text with {token} "
                            f"({value}) on {page}: {ratio:.2f}:1")
