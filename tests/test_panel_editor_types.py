"""The editor knows every panel type the server accepts.

Two packages built in parallel left a seam here. One added the panel types
`records` and `trace_list` to `PANEL_TYPES`; the other lifted the panel editor
into one include shared by the create and the edit form. Neither knew about
the other, so measured on the merged branch the add menu offered five of the
seven types, and the per-type control chain — a ternary ending in the
TIMESERIES branch — handed a stored records panel a "Split by" select
belonging to another question.

A panel type nobody can add from the page is a panel type that does not exist
for anybody who does not write JSON by hand, and a control chain that falls
through to another type's controls does not fail, it lies.

Shaped after `test_every_panel_type_has_a_hint_the_client_can_draw` in
tests/test_dashboard_tables.py, for the same reason: the Python table and the
template cannot see each other, so the join has to be measured somewhere. It
fails the day a type is added to `PANEL_TYPES` without its row here.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.panels import (  # noqa: E402
    MONITOR_VIEWS, PANEL_TYPES, TRACE_LIST_VIEWS, TRACE_SORTS,
)

TEMPLATES = os.path.join(os.path.dirname(__file__), "..", "templates")
MENU = os.path.join(TEMPLATES, "_dashboard_editor.html")
SCRIPT = os.path.join(TEMPLATES, "_dashboard_editor_script.html")


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _table(source, name):
    """The keys of a `const NAME = Object.assign(Object.create(null), {...})`.

    The tables are read by their own indentation, the way the client's
    PANEL_HINTS is: a key at four spaces is a row of the table, anything
    deeper belongs to the markup inside one.
    """
    block = re.search(name + r" = Object\.assign\(Object\.create\(null\), \{"
                      r"(.*?)^\}\);", source, re.S | re.M)
    if block is None:
        return None
    return set(re.findall(r"^ {4}(\w+):", block.group(1), re.M))


def _list(source, name):
    """The values of a `const NAME = ['a', 'b'];`."""
    block = re.search(name + r" = \[([^\]]*)\]", source)
    return tuple(re.findall(r"'([^']*)'", block.group(1))) if block else None


class TheEditorOffersEveryPanelType(unittest.TestCase):

    def setUp(self):
        self.menu = _read(MENU)
        self.script = _read(SCRIPT)

    def test_every_panel_type_can_be_added_from_the_menu(self):
        """Five of seven buttons. `records` and `trace_list` were accepted by
        `normalise`, drawn by the client, and reachable only by editing a
        dashboard's JSON by hand."""
        offered = set(re.findall(r'data-add-panel="(\w+)"', self.menu))
        self.assertEqual(sorted(set(PANEL_TYPES) - offered), [],
                         "a panel type with no button in the add menu")
        self.assertEqual(sorted(offered - set(PANEL_TYPES)), [],
                         "a button for a panel type the server would refuse")

    def test_every_panel_type_has_controls_of_its_own(self):
        """The defect this file exists for. The chain's last branch was the
        timeseries one, so a type it did not name got a "Split by" select —
        and `normalise` drops `split_by` from a records panel, so the choice
        vanished on save with nothing said."""
        named = _table(self.script, "PANEL_CONTROLS")
        self.assertIsNotNone(named, "PANEL_CONTROLS is not where it was")
        self.assertEqual(sorted(set(PANEL_TYPES) - named), [],
                         "a panel type the editor has no controls for")
        self.assertEqual(sorted(named - set(PANEL_TYPES)), [],
                         "controls for a panel type the server would refuse")

    def test_the_unknown_type_is_offered_nothing_rather_than_another_types_controls(self):
        """A table with no prototype and an empty default, the way the
        client's PANEL_HINTS is. A plain object literal would answer
        `panel.type === 'constructor'` with a function."""
        self.assertIn("PANEL_CONTROLS[panel.type]", self.script)
        self.assertNotIn("panel.type === 'trace_services'", self.script,
                         "the per-type ternary chain is back")
        for table in ("PANEL_CONTROLS", "ROW_CAPTIONS", "BLANK_PANELS",
                      "SORT_LABELS", "TRACE_VIEW_LABELS",
                      "MONITOR_VIEW_LABELS"):
            self.assertIn(f"const {table} = Object.assign(Object.create(null)",
                          self.script, f"{table} carries Object's prototype")

    def test_every_panel_type_has_a_blank_the_button_adds(self):
        """A button whose type has no blank pushed `{...undefined}`: a panel
        with no type, which the save refuses for the whole board with
        "Unknown panel type: (none)"."""
        named = _table(self.script, "BLANK_PANELS")
        self.assertIsNotNone(named, "BLANK_PANELS is not where it was")
        self.assertEqual(sorted(set(PANEL_TYPES) - named), [],
                         "a panel type the add menu has no blank for")

    def test_every_panel_type_says_what_it_is_on_its_row(self):
        """The caption used to fall back to the raw type name."""
        named = _table(self.script, "ROW_CAPTIONS")
        self.assertIsNotNone(named, "ROW_CAPTIONS is not where it was")
        self.assertEqual(sorted(set(PANEL_TYPES) - named), [],
                         "a panel type whose row says nothing about it")

    def test_the_new_rows_say_what_the_panel_costs_to_ask(self):
        """Both of these cost a request the log batch does not already make,
        and the row is where an author finds that out. Measured in
        `_records_panels` and `_trace_list_panels`: a records panel is a
        search rather than an aggregation (one more request, shared by every
        records panel on the board), and a trace list is one request per
        service, view and row count."""
        captions = re.search(r"ROW_CAPTIONS = Object\.assign.*?^\}\);",
                             self.script, re.S | re.M).group(0)
        # Up to the next four-space key OR the end of the table: anchoring on
        # a following key alone meant the last row of the table matched
        # nothing, and the test raised AttributeError — a broken test rather
        # than a missing sentence — the day somebody reordered it.
        def caption(key):
            found = re.search(r"^ {4}%s:(.*?)(?=^ {4}\w+:|^\}\);)" % key,
                              captions, re.S | re.M)
            self.assertIsNotNone(found, f"{key} has no row in ROW_CAPTIONS")
            return found.group(1)

        records, traces = caption("records"), caption("trace_list")
        self.assertIn("one more request", records)
        self.assertIn("request of its own", traces)
        self.assertIn("traces:read", traces)

    def test_the_editor_offers_only_the_views_the_save_accepts(self):
        """A value this form offers that `normalise` refuses is not a warning
        on one panel: `_resubmitted` cannot re-render a list that fails to
        validate, so it falls back to the stored one and the author's whole
        edit goes with it."""
        self.assertEqual(_list(self.script, "TRACE_LIST_VIEWS"),
                         TRACE_LIST_VIEWS)
        self.assertEqual(_list(self.script, "MONITOR_VIEWS"), MONITOR_VIEWS)
        self.assertEqual(_list(self.script, "TRACE_SORTS"), TRACE_SORTS)

    def test_a_trace_list_cannot_be_submitted_without_the_service(self):
        """`normalise` refuses it, and a refused save re-renders the form from
        the STORED list — so the panel and every edit made beside it are gone
        with nothing on the page saying they were ever typed."""
        self.assertIn("event.preventDefault()", self.script)
        guard = re.search(r"const nameless = panels\.filter\((.*?)\);",
                          self.script, re.S)
        self.assertIsNotNone(guard, "the submit guard is not where it was")
        self.assertIn("trace_list", guard.group(1))
        self.assertIn("service", guard.group(1))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
