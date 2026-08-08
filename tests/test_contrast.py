"""
Text that can actually be read.

`.badge` sets `color: var(--dark-bg)` — the PAGE BACKGROUND colour. On the
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


def _variables(css):
    return {name: value.strip()
            for name, value in re.findall(r"(--[\w-]+):\s*([^;]+);", css)}


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
    def setUp(self):
        with open(CSS) as handle:
            self.css = handle.read()
        self.variables = _variables(self.css)

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

    def test_the_default_badge_colour_is_still_the_page_background(self):
        """Not a mistake in itself — it is what makes dark text sit on the
        bright warning and info fills. This records that the fix above is a
        deliberate exception rather than a rule nobody looked at."""
        block = _rule(self.css, ".badge")
        self.assertEqual(_declaration(block, "color"), "var(--dark-bg)")


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

    def setUp(self):
        with open(CSS) as handle:
            self.css = handle.read()
        self.variables = _variables(self.css)
        self.card = _resolve("var(--dark-card)", self.variables)
        self.page = _resolve("var(--dark-bg)", self.variables)

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
        body = _resolve("var(--dark-text)", self.variables)
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
    """The step pills inside a journey run.

    Quieter than `.monitor-status` on purpose — they sit in a fold somebody
    opened, and seven shouting pills make the one that failed harder to find.
    Quieter still has to mean legible, and a tinted background over a tinted
    row is exactly where that stops being true by accident.
    """

    def setUp(self):
        with open(CSS) as handle:
            self.css = handle.read()
        self.variables = _variables(self.css)
        # The steps table sits on `.bg-body-tertiary` inside a card. The card
        # is the darker of the two surfaces it can land on, so it is the one
        # to check against.
        self.card = _resolve("var(--dark-card)", self.variables)

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
        # invented for this table. `--dark-text-muted` is what the product
        # already uses for "nothing to report here".
        self.assertEqual(skipped.lower(),
                         _resolve("var(--dark-text-muted)",
                                  self.variables).lower())

    def test_failed_is_the_same_red_the_rest_of_the_product_uses(self):
        """A product with two reds has two vocabularies."""
        failed = _resolve(
            _declaration(self._block(".journey-step.failed"), "color"),
            self.variables).lower()
        down = _gradient_stops(
            _declaration(self._block(".monitor-status.down"), "background"))
        self.assertIn(failed, [stop.lower() for stop in down])
