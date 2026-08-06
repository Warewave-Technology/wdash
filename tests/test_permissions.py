"""
The permission catalogue.

Permission names used to be bare strings scattered through route code, with
three measured consequences: the configuration page accepted `logs:raed`
silently, the UI could only offer a free-text box, and nothing could tell
whether a name was still used by anything.

The static check at the bottom is what keeps the catalogue honest. Without it,
a route can start checking a permission nobody can grant — which fails closed,
and therefore quietly.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.permissions import (  # noqa: E402
    PERMISSIONS, RETIRED, grouped, known, normalise,
)

SOURCE = os.path.join(os.path.dirname(__file__), "..", "src", "wdash")


class CatalogueTest(unittest.TestCase):
    def test_every_entry_describes_what_it_allows(self):
        """The description is shown to administrators; restating the name is
        not a description."""
        for name, (group, label, description) in PERMISSIONS.items():
            self.assertTrue(group, name)
            self.assertTrue(label, name)
            self.assertGreater(len(description), 40,
                               f"{name} has no useful description")
            self.assertNotEqual(description.strip().lower(), name.lower())

    def test_administration_says_it_is_not_a_superuser(self):
        """The single most surprising fact about this permission model."""
        self.assertIn("NOT a superuser", PERMISSIONS["system:admin"][2])

    def test_groups_keep_declaration_order(self):
        self.assertEqual(list(grouped()),
                         ["Logs", "Traces", "Dashboards", "Administration"])

    def test_retired_names_point_at_something_real(self):
        for old_name, replacement in RETIRED.items():
            self.assertNotIn(old_name, PERMISSIONS)
            self.assertIn(replacement, PERMISSIONS)


class NormaliseTest(unittest.TestCase):
    def test_unknown_names_are_reported_not_stored(self):
        """A permission that grants nothing while looking configured is worse
        than one that was refused."""
        permissions, unknown, _ = normalise(["logs:read", "logs:raed"])
        self.assertEqual(permissions, ["logs:read"])
        self.assertEqual(unknown, ["logs:raed"])

    def test_retired_names_are_translated_not_dropped(self):
        """An upgrade must not quietly narrow what a role could do."""
        permissions, unknown, renamed = normalise(["logs:search"])
        self.assertEqual(permissions, ["logs:read"])
        self.assertEqual(unknown, [])
        self.assertEqual(renamed, [("logs:search", "logs:read")])

    def test_duplicates_collapse(self):
        permissions, _, _ = normalise(["logs:read", "logs:search", "logs:read"])
        self.assertEqual(permissions, ["logs:read"])

    def test_output_follows_catalogue_order(self):
        """Two roles with the same permissions store the same list, which is
        what makes them comparable."""
        first, _, _ = normalise(["system:admin", "logs:read"])
        second, _, _ = normalise(["logs:read", "system:admin"])
        self.assertEqual(first, second)
        self.assertEqual(first, ["logs:read", "system:admin"])

    def test_blank_entries_are_ignored(self):
        permissions, unknown, _ = normalise(["", "   ", "logs:read"])
        self.assertEqual(permissions, ["logs:read"])
        self.assertEqual(unknown, [])


class RouteUsageTest(unittest.TestCase):
    """Every permission a route checks must be one an administrator can grant.

    A route checking a name absent from the catalogue fails closed — and
    therefore silently, which is the expensive kind of wrong in an
    authorization system.
    """

    @staticmethod
    def _checked_names():
        found = set()
        for root, _, files in os.walk(SOURCE):
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                # The catalogue itself is the definition, not a consumer, and
                # its docstring names `has_permission("x")` as an example.
                if filename == "permissions.py":
                    continue
                path = os.path.join(root, filename)
                with open(path, encoding="utf-8") as handle:
                    body = handle.read()
                found |= set(re.findall(
                    r'has_permission\(\s*["\']([\w:]+)["\']', body))
        return found

    def test_every_checked_permission_is_in_the_catalogue(self):
        checked = self._checked_names()
        self.assertTrue(checked, "no permission checks found at all")
        missing = sorted(name for name in checked if not known(name))
        self.assertEqual(missing, [],
                         f"routes check permissions nobody can grant: {missing}")

    def test_the_retired_name_is_no_longer_checked_anywhere(self):
        """Searching is reading. Leaving the old check would keep producing
        roles that open a page where every search fails."""
        self.assertNotIn("logs:search", self._checked_names())

    def test_every_catalogue_entry_is_actually_used(self):
        """A permission nothing checks is a promise the UI cannot keep."""
        checked = self._checked_names()
        # dashboard:create gates a page rather than an API path in one place,
        # so allow anything referenced in a template too.
        templates = ""
        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        for entry in sorted(os.listdir(template_dir)):
            if entry.endswith(".html"):
                with open(os.path.join(template_dir, entry),
                          encoding="utf-8") as handle:
                    templates += handle.read()

        unused = [name for name in PERMISSIONS
                  if name not in checked and name not in templates]
        self.assertEqual(unused, [],
                         f"the catalogue offers permissions nothing honours: "
                         f"{unused}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
