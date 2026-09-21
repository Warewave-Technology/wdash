"""
The published site, held to the things that rot silently in one.

`site/` is two pages and a mark, served as static files. Nothing imports
them, nothing renders them in the suite, and every way they go wrong looks
like nothing on the screen that has the fault:

  * a contents entry pointing at a section that was renamed scrolls
    nowhere, and the page underneath it is still perfectly readable;
  * a section nobody links to is a section nobody finds, and the page it is
    on is the one place that cannot say so;
  * a version printed in prose goes stale at the release that changes it,
    and the sentence around it still parses.

So each of those is a test. They are cheap because the pages are plain
files: this module reads them as text and never opens a browser.
"""

import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
SITE = os.path.join(ROOT, "site")

import sys  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "src"))

from wdash import __version__  # noqa: E402

#: Version-shaped strings on the pages that are deliberately NOT this
#: release. Short on purpose: being made to add to it is the point, because
#: it turns a stale number into a decision somebody took.
OLDER_VERSIONS_NAMED_ON_PURPOSE = {
    # "2.4.0 and earlier asked only whether a role had any log container" —
    # the trace-store boundary's upgrade note.
    "2.4.0",
}

_VERSION = re.compile(r"(?<![\d.])\d+\.\d+\.\d+(?![\d.])")

#: How the README may name the documentation page: the path a checkout has,
#: or the address it is published at. `_LINK` captures the base so the four
#: links can be held to ONE of them; `_ANCHOR` captures the section.
_LINK = re.compile(r"\((site/docs/index\.html|https?://[^\s()#]+/docs/)"
                   r"(?:#[a-z0-9-]+)?\)")
_ANCHOR = re.compile(r"(?:site/docs/index\.html|https?://[^\s()#]+/docs/)"
                     r"#([a-z0-9-]+)")


def _read(*parts):
    with open(os.path.join(SITE, *parts), encoding="utf-8") as handle:
        return handle.read()


class TheDocsContentsTest(unittest.TestCase):
    """The sidebar and the sections it is a list of."""

    def setUp(self):
        self.text = _read("docs", "index.html")
        aside = self.text.split("<aside>", 1)[1].split("</aside>", 1)[0]
        self.listed = re.findall(r'<a href="#([a-z0-9-]+)"', aside)
        self.sections = re.findall(r'<section id="([a-z0-9-]+)"', self.text)

        #: The contents as it reads: [(group, [entry, ...]), ...], plus
        #: whatever sits above the first heading.
        self.groups, self.ungrouped = [], []
        for kind, value in re.findall(
                r"<h4>([^<]+)</h4>|<a href=\"#([a-z0-9-]+)\"", aside):
            if kind:
                self.groups.append((kind, []))
            elif self.groups:
                self.groups[-1][1].append(value)
            else:
                self.ungrouped.append(value)

    def test_every_contents_entry_names_a_section_that_exists(self):
        """A renamed section leaves the entry pointing nowhere, and clicking
        it does nothing at all — no error, no movement, no message."""
        missing = [name for name in self.listed if name not in self.sections]
        self.assertEqual(missing, [], "contents entries with no section")

    def test_every_section_is_in_the_contents(self):
        """A section reachable only by scrolling past everything above it is
        one nobody finds, on the page whose whole job is being findable."""
        unlisted = [name for name in self.sections if name not in self.listed]
        self.assertEqual(unlisted, [], "sections nothing links to")

    def test_the_contents_is_in_the_order_the_page_is(self):
        """The mark follows the page. A contents in a different order than
        the document marks entries out of sequence as you scroll, which reads
        as the mark being broken rather than the list being wrong."""
        self.assertEqual(self.listed, self.sections)

    def test_every_entry_is_under_a_group(self):
        """Thirty-odd flat links is a wall; the groups are what make it a
        contents rather than an index. An entry added above the first
        heading, or a heading added with nothing under it, is the way that
        stops being true one line at a time."""
        for name, entries in self.groups:
            self.assertTrue(entries, f"the group {name!r} holds nothing")
        self.assertEqual(self.ungrouped, [],
                         "entries above the first group heading")

    def test_no_group_is_itself_a_wall(self):
        """The ceiling is the size of the longest group there is, so this
        fails on the next one that grows past it rather than on today's.
        What it really catches is a heading deleted from the middle: the two
        groups either side of it become one, and a merged pair is over the
        ceiling wherever the smaller of them is more than a couple of
        entries. Two small groups merging is not caught, and nothing
        mechanical would catch it — which is why the order test above is the
        one doing most of the work here."""
        for name, entries in self.groups:
            self.assertLessEqual(
                len(entries), 8,
                f"the group {name!r} holds {len(entries)} entries")

    def test_every_cross_reference_inside_the_page_resolves(self):
        """The prose links between sections — "see the backends", "the
        capability table". Each is a promise that something is there."""
        body = self.text.split("</aside>", 1)[1]
        referenced = set(re.findall(r'href="#([a-z0-9-]+)"', body))
        dangling = sorted(referenced - set(self.sections))
        self.assertEqual(dangling, [], "cross-references with no section")


class TheLandingPageTest(unittest.TestCase):
    def setUp(self):
        self.text = _read("index.html")
        self.sections = re.findall(r'<section id="([a-z0-9-]+)"',
                                   _read("docs", "index.html"))

    def test_every_link_into_the_docs_names_a_section_that_exists(self):
        """The landing page sends people into the middle of the docs. A
        stale anchor drops them at the top instead — on a page long enough
        that landing at the top and landing at the wrong section look the
        same."""
        deep = sorted(set(re.findall(r'href="docs/#([a-z0-9-]+)"', self.text)))
        self.assertTrue(deep, "the landing page links into no section")
        dangling = [name for name in deep if name not in self.sections]
        self.assertEqual(dangling, [], "landing-page links with no section")


class TheReadmeLinksIntoTheSiteTest(unittest.TestCase):
    """The README's link row is four anchors deep into the docs page.

    Two files away from the page, in a file nobody re-reads when a section
    is renamed — and a reader following a stale one lands at the top of a
    very long page, which is indistinguishable from landing where they
    meant to and the section having been cut.
    """

    def setUp(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
            self.readme = handle.read()
        self.sections = re.findall(r'<section id="([a-z0-9-]+)"',
                                   _read("docs", "index.html"))

    def test_every_anchor_it_names_is_there(self):
        """Asserting there is at least one covers "the README stopped
        linking to the page" as well, which is why that is not a second
        test: it is the same assertion with less of it.

        Both spellings, because the row moved from a path to a published
        address the day the site went up and will move again if it moves:
        what this is about is the ANCHOR, and the anchor is the half that
        goes stale on its own.
        """
        deep = sorted(set(_ANCHOR.findall(self.readme)))
        self.assertTrue(deep, "the README links into no section")
        dangling = [name for name in deep if name not in self.sections]
        self.assertEqual(dangling, [], "README links with no section")

    def test_the_whole_row_points_at_one_place(self):
        """Half an edit is the failure here. The row was four relative
        paths and became four absolute URLs in one commit; one left behind
        still resolves for whoever has the repository checked out, and for
        nobody reading the README on the web."""
        bases = {match.group(1) for match in _LINK.finditer(self.readme)}
        self.assertTrue(bases, "the README links to the docs page nowhere")
        self.assertEqual(len(bases), 1,
                         f"the link row points at {sorted(bases)}")

    def test_the_project_layout_lists_the_site(self):
        """The layout block is the map somebody reads instead of looking.
        `site/` was added to it when the site was linked; a directory the
        map leaves out is one nobody knows to open."""
        layout = self.readme.split("## Project layout", 1)[1].split("```")[1]
        self.assertRegex(layout, re.compile(r"^site/", re.M),
                         msg="`site/` is not in the project layout")


class TheVersionOnThePagesTest(unittest.TestCase):
    """Printed in prose and in sample output, where nothing checks it."""

    def setUp(self):
        self.pages = {
            "site/index.html": _read("index.html"),
            "site/docs/index.html": _read("docs", "index.html"),
        }

    def test_the_docs_say_which_version_they_describe(self):
        self.assertIn(f"Version {__version__}.", self.pages["site/docs/index.html"])

    def test_no_page_prints_a_version_that_is_not_this_one(self):
        """Including the sample `/livez` output, which is the one somebody
        compares their own installation against."""
        allowed = OLDER_VERSIONS_NAMED_ON_PURPOSE | {__version__}
        for page, text in self.pages.items():
            for found in set(_VERSION.findall(text)):
                self.assertIn(found, allowed,
                              f"{page} prints {found}; this is {__version__}")


class TheSiteNeedsNoBuildTest(unittest.TestCase):
    """Two files and a mark, served as they are.

    The stylesheet says so in its own first comment, and a page that starts
    pulling a stylesheet or a script from somewhere else makes that comment
    false — and makes the site depend on a host nobody here operates.
    """

    def setUp(self):
        self.pages = {
            "site/index.html": _read("index.html"),
            "site/docs/index.html": _read("docs", "index.html"),
        }

    def test_nothing_is_fetched_from_anywhere_else(self):
        for page, text in self.pages.items():
            self.assertNotIn("<script src=", text, f"{page} loads a script")
            self.assertNotIn('rel="stylesheet"', text,
                             f"{page} loads a stylesheet")

    def test_each_page_says_where_it_is_published(self):
        """A canonical URL and the three tags a shared link is rendered
        from. Not decoration once the site has an address: without them the
        same page under two hosts is two pages to a crawler, and a link
        posted anywhere shows the URL and nothing else.

        Held to the page's OWN address rather than to one base, because
        `/docs/` and `/` are different pages and a canonical copied between
        them points half the site at the other half.
        """
        for parts, expected in (((), "https://wdash.warewave.tech/"),
                                (("docs",),
                                 "https://wdash.warewave.tech/docs/")):
            page = _read(*parts, "index.html")
            with self.subTest(page=expected):
                self.assertIn(f'<link rel="canonical" href="{expected}">',
                              page, "no canonical, or not this page's")
                self.assertIn(f'<meta property="og:url" content="{expected}">',
                              page)
                for tag in ("og:type", "og:title", "og:description"):
                    self.assertIn(f'property="{tag}"', page, f"no {tag}")

    def test_the_mark_each_page_names_is_there(self):
        for parts, page in (((), "site/index.html"),
                            (("docs",), "site/docs/index.html")):
            href = re.search(r'<link rel="icon"[^>]*href="([^"]+)"',
                             _read(*parts, "index.html"))
            self.assertIsNotNone(href, f"{page} names no icon")
            target = os.path.normpath(
                os.path.join(SITE, *parts, href.group(1)))
            self.assertTrue(os.path.exists(target),
                            f"{page} names {href.group(1)}, which is not there")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
