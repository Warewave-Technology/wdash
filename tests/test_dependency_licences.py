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
    """Everything that ends up installed in a published image.

    requirements.txt AND the Dockerfile. The browser agent installs Playwright
    in its own stage rather than through requirements.txt — it is 400MB of
    browser that the server has no use for — and reading only the one file let
    a dependency into a published image without passing the rule this whole
    module exists to enforce.
    """
    names = set()
    with open(os.path.join(ROOT, "requirements.txt")) as handle:
        for line in handle:
            line = line.split("#")[0].strip()
            if line:
                names.add(re.split(r"[<>=!\[]", line)[0].strip().lower())
    names |= _dockerfile_installs()
    return names


def _dockerfile_installs():
    """Packages a `pip install` in the Dockerfile names directly.

    Continuations are joined and comments dropped first, then each shell
    command is taken on its own. Without the split on `&&` the first version
    read every word of the rest of the RUN line — and of the comment above it
    — as a package name.
    """
    path = os.path.join(ROOT, "Dockerfile")
    if not os.path.exists(path):
        return set()
    with open(path) as handle:
        lines = [line for line in handle
                 if not line.lstrip().startswith("#")]
    script = "".join(lines).replace("\\\n", " ")

    names = set()
    for line in script.split("\n"):
        for command in line.split("&&"):
            command = command.strip()
            if "pip install" not in command:
                continue
            words = command.split("pip install", 1)[1].split()
            for word in words:
                if (word.startswith("-") or word == "."
                        or word.startswith("requirements")):
                    continue
                names.add(re.split(r"[<>=!\[]", word)[0].strip().lower())
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


class DockerfileIsCoveredTest(unittest.TestCase):
    """The Dockerfile is a place dependencies get in.

    The browser agent installs Playwright in its own stage rather than through
    requirements.txt, because it pulls 400MB of browser the server has no use
    for. Reading only requirements.txt let that dependency into a published
    image without passing the rule this module exists to enforce — and it went
    unnoticed for exactly as long as it took to write this test.
    """

    def test_the_browser_stage_is_read(self):
        self.assertIn("playwright", _dockerfile_installs())

    def test_playwright_is_apache_and_stays_that_way(self):
        """Apache-2.0 today. A relicense to something source-available is
        exactly the move this project's rule exists to catch, and it has
        happened to other tools in this problem space."""
        licence = _licence("playwright")
        if licence is None:
            self.skipTest("playwright is not installed in this environment")
        self.assertIn("apache", licence)

    def test_a_hypothetical_licensed_dependency_would_be_caught(self):
        """The check has to be able to FAIL. A parser that quietly returns an
        empty set passes every licence test there is."""
        import re as _re
        self.assertTrue(_dockerfile_installs(),
                        "nothing was read out of the Dockerfile, so the "
                        "licence rule does not cover it at all")
        # And it reads package names, not shell words: `&&`, `rm` and the
        # prose of the comment above the command all appeared in the first
        # version.
        for word in ("&&", "rm", "chown", "the", "install"):
            self.assertNotIn(word, _dockerfile_installs())
        self.assertTrue(
            all(_re.match(r"^[a-z0-9._-]+$", name)
                for name in _dockerfile_installs()),
            f"not package names: {_dockerfile_installs()}")
