"""
What the dependencies are licensed under.

The project's rule is that WDash uses no proprietary or source-available work
— which is why it targets Elasticsearch's open-source line and speaks HTTP to
Loki and Tempo rather than embedding them. A dependency arrives quietly: one
`pip install`, one line in requirements.txt, and the licence is nobody's
question until a release.

Copyleft is not banned here — `ldap3` and `psycopg` are both LGPL v3, used as
libraries over their published interfaces, which is what the LGPL is for. What
this catches is a new dependency under a licence NOBODY HAS LOOKED AT: full
GPL/AGPL, SSPL, the Elastic Licence, or anything marked proprietary.

It reads installed metadata, so it only sees what this environment has. That
is the same set requirements.txt pins, and a dependency nobody installed is
one nobody ships.
"""

import importlib.metadata as metadata
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")

#: Reviewed and accepted, with the reason. Anything else has to be looked at
#: before it can be added here — which is the entire point of the list.
ACCEPTED_COPYLEFT = {
    "ldap3": "LGPL v3; isolated in src/wdash/auth/ldap_auth.py",
    "psycopg": "LGPL v3; only used when DATABASE_URL points at Postgres",
    "psycopg-binary": "ships with psycopg",
}

REFUSED = ("sspl", "elastic license", "elastic-2", "proprietary",
           "commercial", "business source", "busl")


def _requirements():
    names = set()
    with open(os.path.join(ROOT, "requirements.txt")) as handle:
        for line in handle:
            line = line.split("#")[0].strip()
            if line:
                names.add(re.split(r"[<>=!\[]", line)[0].strip().lower())
    return names


def _licence(name):
    """Everything the package says about its licence, lowercased.

    Three fields, because packaging changed twice: `License-Expression` is
    current, `License` is the old free-text field, and the classifiers are
    what most older wheels actually carry.
    """
    try:
        meta = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return None
    parts = []
    for key in ("License-Expression", "License"):
        parts.extend(v for v in (meta.get_all(key) or []) if v)
    parts.extend(c for c in (meta.get_all("Classifier") or [])
                 if c.startswith("License ::"))
    return " | ".join(parts).lower()


class DependencyLicenceTest(unittest.TestCase):
    def setUp(self):
        self.pinned = _requirements()

    def test_nothing_is_proprietary_or_source_available(self):
        """The rule the project is built around. SSPL and the Elastic Licence
        are the two that turn up in this problem space specifically."""
        for name in sorted(self.pinned):
            licence = _licence(name)
            if licence is None:
                continue
            for refused in REFUSED:
                self.assertNotIn(refused, licence,
                                 f"{name} is licensed under {licence}")

    def test_every_copyleft_dependency_has_been_looked_at(self):
        """Not a ban — a record. A new GPL dependency should fail here and be
        argued about, rather than arriving with a `pip install`."""
        unreviewed = []
        for name in sorted(self.pinned):
            licence = _licence(name)
            if licence is None or name in ACCEPTED_COPYLEFT:
                continue
            if "gpl" in licence or "mozilla public" in licence:
                unreviewed.append(f"{name} ({licence})")
        self.assertEqual(unreviewed, [], f"unreviewed copyleft: {unreviewed}")

    def test_the_accepted_list_has_not_gone_stale(self):
        """An entry for a dependency that is gone reads as though something
        copyleft is still in the tree."""
        for name in ACCEPTED_COPYLEFT:
            if name == "psycopg-binary":
                continue    # an extra of psycopg, never named directly
            self.assertIn(name, self.pinned,
                          f"{name} is on the accepted list but not pinned")

    def test_the_accepted_ones_really_are_copyleft(self):
        """Otherwise the list quietly becomes an allowlist for everything."""
        for name in ("ldap3", "psycopg"):
            licence = _licence(name)
            if licence is None:
                continue
            self.assertIn("gpl", licence,
                          f"{name} is not copyleft any more; take it off the list")


if __name__ == "__main__":
    unittest.main()
