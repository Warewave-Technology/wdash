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
