"""
The files a release is made of, and whether they still describe this one.

`v2.4.0` was tagged and nothing stood behind it: no changelog, no published
image, and a tag message doing the work of release notes. The files exist
now, and files like these rot in a particular way — they are written once,
they are read by somebody upgrading, and nothing they say is false in a way
that shows up while you work.

So each of them is held to something that moves: the version to the package,
the notices to what is installed, the process to the commands it names.
"""

import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from wdash import __version__  # noqa: E402


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


class TheChangelogTest(unittest.TestCase):
    def setUp(self):
        self.text = _read("CHANGELOG.md")

    def test_it_has_an_entry_for_the_version_being_shipped(self):
        """A release whose changelog stops at the version before it is a
        release nobody can read the notes for."""
        self.assertRegex(
            self.text,
            re.compile(rf"^## {re.escape(__version__)}\b", re.M),
            "no section for the current version")

    def test_the_newest_entry_is_the_current_version(self):
        """Entries go at the top. One added under an older heading is one
        nobody sees."""
        headings = re.findall(r"^## (\S+)", self.text, re.M)
        self.assertTrue(headings, "no version headings at all")
        self.assertEqual(headings[0], __version__)

    def test_it_leads_with_what_has_to_be_done(self):
        """The section somebody is reading this for. Ordered rather than
        assumed: an upgrade note under "Changed", four screens down, is one
        that gets read after the upgrade."""
        entry = self.text.split(f"## {__version__}", 1)[1]
        sections = re.findall(r"^### (.+)$", entry, re.M)
        self.assertTrue(sections, "the entry has no sections")
        self.assertEqual(sections[0], "Needs action")

    def test_every_upgrade_note_in_the_readme_is_in_it(self):
        """The README carries upgrade notes because that is where somebody
        already is; the changelog carries them because that is where
        somebody upgrading looks. Both, or the one that is missing is the
        one they read."""
        readme = _read("README.md")
        for marker, phrase in (
                ("environment", "ELASTICSEARCH_URL"),
                ("dashboards", "DASHBOARD_STORAGE"),
                ("every source", "reads every source"),
        ):
            with self.subTest(note=marker):
                self.assertIn(phrase, readme)
                self.assertIn(phrase, self.text,
                              f"the README warns about {marker} and the "
                              f"changelog does not")


class TheThirdPartyNoticesTest(unittest.TestCase):
    def setUp(self):
        self.text = _read("THIRD-PARTY-NOTICES.md")

    def generator(self):
        """`tools/third_party_notices.py`, imported by path — `tools` is a
        directory of scripts rather than a package, and a release tool that
        had to be installed to be tested would be one nobody runs."""
        import importlib.util
        path = os.path.join(ROOT, "tools", "third_party_notices.py")
        spec = importlib.util.spec_from_file_location("notices_tool", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_it_is_what_the_generator_would_write_today(self):
        """Stale is the only way this file goes wrong, and it goes wrong
        silently: a dependency is added in one line of requirements.txt and
        its licence is nobody's question until somebody asks for the
        notices.

        Compared here rather than by running the tool's own `--check`. That
        was the first version, and it asked the tool whether the tool was
        right: a `--check` that always answered yes passed it. The file is
        compared to what `render()` produces, and `--check` is what a
        person runs.
        """
        self.assertEqual(self.text, self.generator().render(),
                         "run: python tools/third_party_notices.py")

    def test_its_check_flag_says_no_when_it_should(self):
        """The half RELEASING.md tells somebody to run. Driven against a
        file that is deliberately wrong, because a check nobody has seen
        fail is a check nobody has seen."""
        tool = self.generator()
        original = self.text
        try:
            with open(tool.OUTPUT, "w", encoding="utf-8") as handle:
                handle.write(original + "\n## not-a-package 0.0.0\n")
            self.assertEqual(self._check(tool), 1,
                              "--check passed a file it should have refused")
        finally:
            with open(tool.OUTPUT, "w", encoding="utf-8") as handle:
                handle.write(original)

    @staticmethod
    def _check(tool):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            saved, sys.argv = sys.argv, ["notices", "--check"]
            try:
                return tool.main()
            finally:
                sys.argv = saved

    def test_every_dependency_that_ships_is_in_it(self):
        from tests.test_dependency_licences import _requirements
        for name in sorted(_requirements()):
            with self.subTest(package=name):
                self.assertRegex(
                    self.text, rf"(?im)^## {re.escape(name)} ",
                    f"{name} ships and is not in the notices")

    def test_the_two_copyleft_ones_are_named_as_such(self):
        """They are accepted deliberately — LGPL v3, used as libraries over
        their published interfaces — and a notices file that did not say so
        would leave somebody to work it out from the texts."""
        for name in ("ldap3", "psycopg"):
            self.assertIn(name, self.text)
        self.assertIn("LGPL", self.text)


class TheReleaseProcessTest(unittest.TestCase):
    def setUp(self):
        self.text = _read("RELEASING.md")

    def test_the_commands_it_names_exist(self):
        """A process that names a script nobody kept is a process somebody
        follows until it fails."""
        for path in re.findall(r"(tools/[\w./-]+\.py)", self.text):
            with self.subTest(path=path):
                self.assertTrue(os.path.exists(os.path.join(ROOT, path)),
                                f"{path} does not exist")
        for module in re.findall(r"unittest (tests\.[\w.]+)", self.text):
            with self.subTest(module=module):
                name = module.split(".")[1]
                self.assertTrue(
                    os.path.exists(os.path.join(ROOT, "tests", f"{name}.py")),
                    f"{module} does not exist")

    def test_it_names_every_file_the_version_lives_in(self):
        """The table in it is the list somebody works through by hand.
        `tests/test_version.py` is what proves each one moved; this is what
        proves the table did not quietly lose a row."""
        for path in ("package.json", "package-lock.json",
                     "kubernetes/wdash-deployment.yaml",
                     "kubernetes/wdash-agent.yaml", "kubernetes/README.md",
                     "SECURITY.md", "src/wdash/__init__.py"):
            with self.subTest(path=path):
                self.assertIn(os.path.basename(path), self.text)

    def test_it_says_to_seed_the_lab_before_measuring(self):
        """A suite run against a stale lab is a run full of skips, and a run
        full of skips is a release measured by nothing."""
        self.assertIn("lab.sh seed", self.text)

    def test_it_is_honest_about_what_it_does_not_do(self):
        """Signing and an SBOM are not here. A process that lists only what
        it does reads as complete."""
        self.assertIn("not in this process", self.text.lower())


if __name__ == "__main__":
    unittest.main()
