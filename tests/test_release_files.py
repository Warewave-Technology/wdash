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


def heading_complaint(text, version, tagged, when):
    """Why the changelog's heading for `version` is wrong, or None.

    A function rather than four assertions inside a test, because the
    interesting states are the ones this repository is not in: untagged, or
    tagged under a heading that still says "unreleased". A rule that can
    only be asked about the state you are already in is a rule nothing can
    check.
    """
    heading = next((line for line in text.splitlines()
                    if line.startswith(f"## {version}")), None)
    if heading is None:
        return f"no heading for {version}"
    if not tagged:
        return None          # genuinely unreleased; the word is right
    if "unreleased" in heading.lower():
        return f"v{version} is tagged, so it is released"
    if when not in heading:
        return f"the heading does not carry v{version}'s date, {when}"
    return None


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

    def test_a_version_that_has_been_tagged_carries_its_date(self):
        """`## 3.0.0 — unreleased` shipped, tagged and published like that.

        Nobody notices: the heading is one line above the part people came
        to read, and it is right for the whole of development — which is
        why this asks the only thing that distinguishes the two states.
        A tag exists or it does not, and the answer is in the repository
        rather than in somebody's memory of whether they pushed.

        Skipped where there is no git — a tarball, a Docker build context —
        because then the question genuinely cannot be asked, rather than
        being answered "no tag, so the word is fine".
        """
        tag = f"v{__version__}"
        found = subprocess.run(["git", "tag", "--list", tag], cwd=ROOT,
                               capture_output=True, text=True)
        if found.returncode != 0:
            self.skipTest("not a git checkout")
        tagged = bool(found.stdout.strip())
        # Asked a second way, with a different command, because a test that
        # reads git and then stops using the answer passes for a reason that
        # has nothing to do with the tag. Mutating this line to `False` made
        # everything below vacuous and nothing noticed.
        exists = subprocess.run(["git", "rev-parse", "--verify", "--quiet",
                                 f"{tag}^{{commit}}"], cwd=ROOT,
                                capture_output=True, text=True)
        self.assertEqual(tagged, exists.returncode == 0,
                         f"`git tag --list {tag}` and `git rev-parse {tag}` "
                         f"disagree about whether it exists")

        when = ""
        if tagged:
            dated = subprocess.run(
                ["git", "log", "-1", "--format=%ad",
                 "--date=format:%Y-%m-%d", tag],
                cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(dated.returncode, 0, dated.stderr)
            when = dated.stdout.strip()

        self.assertIsNone(
            heading_complaint(self.text, __version__, tagged, when))

    def test_it_says_which_state_it_is_in(self):
        """The rule above, driven both ways.

        Asking git and then asserting the answer is fine cannot see a check
        that stopped checking: on this repository the tag exists and the
        heading is right, so "pass" is correct AND is what a rule that
        returned early would produce. Two mutations proved exactly that —
        one made the check return before it checked, one deleted the branch
        that lets an untagged version say "unreleased", and both lived.

        So the decision is a function and this drives its four corners.
        """
        released = "## 9.9.9 — 2026-09-22\n\nbody\n"
        pending = "## 9.9.9 — unreleased\n\nbody\n"
        cases = (
            # text, tagged, date, what it should say — or None for nothing
            (released, True, "2026-09-22", None),
            (pending, False, "", None),
            (pending, True, "2026-09-22", "is tagged, so it is released"),
            (released, True, "2026-01-01", "does not carry"),
            ("## 9.9.9\n\nbody\n", True, "2026-09-22", "does not carry"),
            ("## 1.0.0 — 2020-01-01\n", True, "2026-09-22", "no heading"),
        )
        for text, tagged, when, expected in cases:
            with self.subTest(heading=text.splitlines()[0], tagged=tagged):
                said = heading_complaint(text, "9.9.9", tagged, when)
                if expected is None:
                    self.assertIsNone(said)
                else:
                    # The WORDING, not just that it complained. Two of these
                    # states are caught by the date check whatever else the
                    # rule does, so without this the branch that tells you
                    # "it is tagged, so it is released" — the one sentence
                    # that says what to do — can be deleted and nothing
                    # fails.
                    self.assertIsNotNone(said, "it said nothing")
                    self.assertIn(expected, said)

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

    def test_the_version_comes_from_the_pin_and_not_from_the_machine(self):
        """What made this file a description of whoever last ran it.

        The versions used to be read from installed metadata. Every pin is
        an exact `==`, so on a machine with everything installed the two
        agree and nothing showed — and on one missing a package they do
        not, which is every CI job but the browser one.
        """
        tool = self.generator()
        pins = tool.pins()
        self.assertTrue(pins, "the generator found nothing pinned")
        for name, version in pins.items():
            with self.subTest(package=name):
                self.assertIsNotNone(
                    version, f"{name} is installed without an exact pin, so "
                             f"the notices cannot state a version for it")
                self.assertRegex(
                    self.text,
                    re.compile(rf"^## \S+ {re.escape(version)}$", re.M),
                    f"no entry at the pinned version of {name}")

    def test_the_pin_wins_over_the_version_that_happens_to_be_installed(self):
        """Asked where the two differ, because everywhere else they agree.

        Every pin is an exact `==`, so on a healthy machine "the pin" and
        "what is installed" are the same string and a generator reading
        either one looks right. The difference only appears where the
        environment is not what the image installs — which is the case this
        whole change is about, and the case nothing could see.
        """
        from unittest import mock

        from tests import test_dependency_licences as dependencies
        tool = self.generator()
        moved = dict(tool.pins(), flask="9.9.9")
        with mock.patch.object(dependencies, "_pins", return_value=moved):
            written = tool.render(self.text)
        self.assertRegex(written, re.compile(r"^## Flask 9\.9\.9$", re.M),
                         "the generator ignored the pin")

    def test_a_package_that_is_absent_keeps_what_the_file_already_says(self):
        """Regeneration has to be idempotent on a machine missing one of
        them, or the file cannot be checked anywhere but here.

        Measured: CI's `suite` job installs requirements.txt and not
        Playwright — only the browser stage needs it — and regenerating
        there wrote "Not installed in the environment this was generated
        from" over an entry that said `playwright 1.62.0`. That is what took
        the first CI run this repository ever had red.
        """
        tool = self.generator()
        absent = self._without("playwright", tool)
        self.assertEqual(absent, self.text,
                         "a machine without Playwright rewrites the file")

    def test_but_not_when_the_pin_has_moved_under_it(self):
        """The other direction, and the reason this is not just "keep
        whatever was there". The licence of 1.62.0 is not evidence about
        9.9.9, so the entry says so instead of carrying the old text
        forward under a new number."""
        tool = self.generator()
        moved = self._without("playwright", tool, pinned="9.9.9")
        entry = moved.split("## playwright", 1)[1].split("\n## ", 1)[0]
        self.assertIn("9.9.9", entry)
        self.assertIn("Regenerate where it is installed", entry)
        self.assertNotIn("Apache", entry, "it carried the old licence over")

    def _without(self, package, tool, pinned=None):
        """`render()` as it would run where `package` is not installed."""
        import importlib.metadata as metadata
        from unittest import mock

        real = metadata.distribution

        def absent(name):
            if name.lower() == package:
                raise metadata.PackageNotFoundError(name)
            return real(name)

        from tests import test_dependency_licences as dependencies
        pins = dict(dependencies._pins())
        if pinned:
            pins[package] = pinned
        with mock.patch.object(tool.metadata, "distribution", absent), \
                mock.patch.object(dependencies, "_pins", return_value=pins):
            return tool.render(self.text)

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
        full of skips is a release measured by nothing.

        Either command: `demo` starts and seeds every data backend in one
        step, `seed` does the seeding half on a lab that is already up. What
        must not happen is a process with neither, which is a process that
        runs the suite against whatever the lab happens to hold.
        """
        seeds = [command for command in ("lab.sh demo", "lab.sh seed")
                 if command in self.text]
        self.assertTrue(seeds, "the process never seeds the lab")

    def test_it_is_honest_about_what_it_does_not_do(self):
        """Signing and an SBOM are not here. A process that lists only what
        it does reads as complete."""
        self.assertIn("not in this process", self.text.lower())


if __name__ == "__main__":
    unittest.main()
