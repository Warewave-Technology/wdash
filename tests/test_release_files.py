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
        """The section somebody is reading this for, FIRST where there is
        one. Ordered rather than assumed: an upgrade note under "Changed",
        four screens down, is one that gets read after the upgrade.

        Not required to exist. A release where nothing stops working and no
        setting changes meaning has nothing to put there, and demanding the
        heading anyway is demanding a sentence somebody has to invent —
        which is how the one section an operator relies on becomes the one
        they learn to skip. What is held is that it cannot appear LATER,
        which is the failure the ordering is about.
        """
        # Cut at the NEXT version heading. Without it the "sections" are
        # every section of every older entry, and an older release having a
        # Needs action makes this pass for a newer one that does not.
        entry = self.text.split(f"## {__version__}", 1)[1].split("\n## ", 1)[0]
        sections = re.findall(r"^### (.+)$", entry, re.M)
        self.assertTrue(sections, "the entry has no sections")
        if "Needs action" in sections:
            self.assertEqual(sections[0], "Needs action")

    def test_an_upgrade_note_is_never_buried_in_a_later_section(self):
        """The other half of the rule above, and the one a missing heading
        would otherwise let through: a sentence telling somebody to do
        something, under "Fixed" or "Changed", where they read it after
        upgrading."""
        entry = self.text.split(f"## {__version__}", 1)[1]
        entry = entry.split("\n## ", 1)[0]
        parts = re.split(r"^### (.+)$", entry, flags=re.M)[1:]
        for name, body in zip(parts[::2], parts[1::2]):
            if name == "Needs action":
                continue
            with self.subTest(section=name):
                for phrase in ("before you upgrade", "before upgrading",
                               "you have to", "you must"):
                    self.assertNotIn(
                        phrase, body.lower(),
                        f"'{phrase}' is under {name!r}, where it is read "
                        f"after the upgrade rather than before it")

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


class WhatTheImageCarriesTest(unittest.TestCase):
    """`.dockerignore`, held to what it has to keep out.

    Measured on an image built after a test run: 103 `.pyc` files in 14
    `__pycache__` directories, 2.06 MB, compiled by the build HOST's Python
    3.14 and sitting inside an image running 3.11 — which ignores them on
    the magic number, so the whole 2 MB was dead. Worse than dead: present
    only when somebody had run the tests before building, which makes the
    image's contents depend on what the developer did that afternoon.

    `__pycache__/` was the pattern, and it matches the one at the context
    ROOT and nothing nested. Checked here against paths rather than against
    the text of the file, so a pattern that is spelled differently but
    excludes the same things still passes.
    """

    #: Paths that must never reach the image, as they really appear.
    KEPT_OUT = (
        "src/wdash/__pycache__/app.cpython-314.pyc",
        "src/wdash/api/__pycache__/config_routes.cpython-311.pyc",
        "__pycache__/conftest.cpython-312.pyc",
        "src/wdash/hub/adapters/elasticsearch.pyc",
        "data/wdash.db",
        "data/tour.db",
        ".env",
        "venv/bin/python",
        "node_modules/jsdom/package.json",
        "tests/test_release_files.py",
        "lab/docker-compose.yml",
    )

    #: And paths that must reach it, so the check cannot pass by excluding
    #: everything.
    LET_IN = (
        "src/wdash/app.py",
        "templates/services.html",
        "static/js/wdash.min.js",
        "requirements.txt",
        "data/.gitkeep",
        "README.md",
    )

    @staticmethod
    def _patterns():
        lines = []
        for line in _read(".dockerignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
        return lines

    @staticmethod
    def _matches(pattern, path):
        """Docker's matching, not the shell's.

        The distinction is the whole point: `fnmatch` lets `*` cross a `/`,
        so `*.py[cod]` appears to exclude `src/wdash/__pycache__/app.pyc`
        and the first version of this test passed the very pattern it was
        written to reject. Docker matches PATH COMPONENTS — `*` stops at a
        separator and only `**` crosses one — and a pattern matching a
        directory excludes everything under it.
        """
        import fnmatch
        parts, want = path.split("/"), pattern.strip("/").split("/")

        def walk(p, w):
            if not w:
                # The pattern ran out: it named this path or a directory
                # above it, and either way the path is in.
                return True
            if w[0] == "**":
                return any(walk(p[i:], w[1:]) for i in range(len(p) + 1))
            if not p:
                return False
            return fnmatch.fnmatch(p[0], w[0]) and walk(p[1:], w[1:])

        return walk(parts, want)

    @classmethod
    def _excluded(cls, path):
        """Docker's rule: the LAST matching pattern decides, and one
        beginning with `!` puts the path back."""
        verdict = False
        for pattern in cls._patterns():
            negated = pattern.startswith("!")
            candidate = pattern[1:] if negated else pattern
            if cls._matches(candidate, path):
                verdict = not negated
        return verdict

    def test_nothing_that_belongs_to_this_machine_is_copied_in(self):
        for path in self.KEPT_OUT:
            with self.subTest(path=path):
                self.assertTrue(self._excluded(path),
                                f"{path} would be copied into the image")

    def test_and_the_application_itself_still_is(self):
        """A guard on the guard: `*` would pass the check above and ship an
        empty image."""
        for path in self.LET_IN:
            with self.subTest(path=path):
                self.assertFalse(self._excluded(path),
                                 f"{path} is excluded from the image")


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


class WhatTheImagesMeasureTest(unittest.TestCase):
    """The size figures, and whether the four files that quote them agree
    with the one file that measured them.

    `RELEASING.md` carries a table of three measurements per image, and the
    process says to take all three again at every release. Four other files
    then repeat two of them in prose, where they read as facts about the
    current version. 3.3.0 moved every one of the six: the base image grew
    under a tag that does not change, so a release that touched nothing
    about packaging still owed a new table.

    Nothing here can tell whether the table is TRUE — that needs a build.
    What it can tell is whether the prose still agrees with it, which is the
    way these rot: one file gets the new number and the others keep
    yesterday's. This file once carried 260MB, which matched none of the
    three measurements and no version.
    """

    #: Sizes in these files that are not about an image. Each has to be
    #: named, so a new one is a decision somebody took rather than a hole
    #: the sweep quietly grew.
    NOT_AN_IMAGE = {
        "228 MB": "ROADMAP's storage projection, 10 checks at 60s",
        "1.2 GB": "ROADMAP's storage projection, 50 checks at 60s",
        "4.8 GB": "ROADMAP's storage projection, 50 checks at 15s",
        "4 MB": "the agent's results-per-delivery payload",
        "1 MB": "a proxy body limit that turned into a lost delivery",
        "2.58GB": "Elastic's own heartbeat image, which carries a Chromium",
        "2.5GB": "a second Elastic heartbeat, costed and not run",
        "3MB": "the playwright pip package, which is not the browser",
        "150MB": "the Chromium that package downloads separately",
    }

    #: Not swept. `RELEASING.md` is where the measuring happens and carries
    #: older figures on purpose, to say which way they moved; `CHANGELOG.md`
    #: records what was true at a version and must never be brought up to
    #: date. This file is out too: the pattern below names the images, so it
    #: matches its own source, and its docstrings quote history on purpose.
    NOT_SWEPT = {"RELEASING.md", "CHANGELOG.md",
                 os.path.join("tests", "test_release_files.py")}

    #: A file that quotes an image size names the image. Hunting for the
    #: files instead of listing them is the point: the first version of this
    #: test carried a list of four, and `docker-compose.yml`, the
    #: `Dockerfile`, `kubernetes/wdash-agent.yaml` and `test_first_run.py`
    #: were all quoting figures nothing checked — three of them the 260MB
    #: and 1.77GB that this release found had outlived several versions.
    NAMES_AN_IMAGE = re.compile(
        r"wdash-browser|wdash-elastic-dashboard|target:? browser"
        r"|browser target|Chromium")

    #: A floor under the sweep, not a list of what it covers: anything new
    #: that documents the images is found on its own. Every file that carries
    #: a measured figure today is named, because counting the swept files let
    #: a pattern keep its count up on files that quote nothing while the ten
    #: that do quote one dropped out of it. Removing a figure from one of
    #: these is a decision; failing here is how it gets made rather than
    #: noticed two releases later.
    ALWAYS_SWEPT = {
        "README.md", "ROADMAP.md", "Dockerfile", "docker-compose.yml",
        os.path.join("kubernetes", "README.md"),
        os.path.join("kubernetes", "wdash-agent.yaml"),
        os.path.join("site", "docs", "index.html"),
        os.path.join("src", "wdash", "agent", "runner.py"),
        os.path.join("tests", "test_first_run.py"),
        os.path.join(".github", "workflows", "tests.yml"),
    }

    SKIPPED_DIRS = {".git", "venv", "node_modules", "dist", "data",
                    "__pycache__", ".pytest_cache", "coverage"}
    PROSE = (".md", ".html", ".py", ".yml", ".yaml", ".conf", ".sh", ".txt")

    @classmethod
    def _files_that_quote_them(cls):
        for where, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in cls.SKIPPED_DIRS]
            for name in files:
                if not (name.endswith(cls.PROSE) or name.startswith("Docker")):
                    continue
                path = os.path.relpath(os.path.join(where, name), ROOT)
                if path in cls.NOT_SWEPT:
                    continue
                try:
                    text = _read(path)
                except (UnicodeDecodeError, OSError):
                    continue
                if cls.NAMES_AN_IMAGE.search(text):
                    yield path, text

    SIZE = re.compile(r"\b\d+(?:\.\d+)? ?[MG]B\b")

    def setUp(self):
        self.process = _read("RELEASING.md")

    def _measured(self):
        """The figures in the table, which is the only place they are
        measured."""
        rows = [line for line in self.process.splitlines()
                if line.lstrip().startswith("|")
                and ("registry," in line or "docker images" in line)]
        self.assertTrue(rows, "RELEASING.md has no table of measurements")
        found = {size.group() for row in rows
                 for size in self.SIZE.finditer(row)}
        self.assertEqual(
            len(rows) * 2, len(found),
            f"expected two figures per row, got {sorted(found)} from "
            f"{len(rows)} rows")
        return found

    def test_the_table_was_measured_for_the_version_being_shipped(self):
        """Carrying the table forward is the one thing the process tells you
        not to do, and a table says which version it belongs to."""
        self.assertIn(f"Measured for {__version__},", self.process,
                      "RELEASING.md's table is not labelled for "
                      f"{__version__} — re-measure it, or say why not")

    def test_every_size_quoted_elsewhere_is_one_that_was_measured(self):
        measured = self._measured()
        swept = set()
        for path, text in self._files_that_quote_them():
            swept.add(path)
            for size in self.SIZE.finditer(text):
                quoted = size.group()
                if quoted in self.NOT_AN_IMAGE:
                    continue
                with self.subTest(path=path, size=quoted):
                    self.assertIn(
                        quoted.replace(" ", ""),
                        {m.replace(" ", "") for m in measured},
                        f"{path} says {quoted}, which RELEASING.md's table "
                        f"does not measure — it has {sorted(measured)}")
        missed = self.ALWAYS_SWEPT - swept
        self.assertFalse(
            missed, f"the sweep did not reach {sorted(missed)} — a pattern "
            "that stops finding the files that document the images agrees "
            "with the table about nothing")

    #: The two files that tell a reader what to pull, which is where the
    #: figure they wait for has to actually appear.
    TELLS_YOU_WHAT_TO_PULL = ("README.md",
                              os.path.join("site", "docs", "index.html"))

    def test_the_figure_a_reader_waits_for_is_told_to_them(self):
        """A sweep over what a file happens to say proves nothing if the file
        stopped saying it. The amd64 row is the one somebody waits through on
        a pull, so both of its figures have to be present where the pull
        command is, not merely consistent with the table.

        Picked off the row's own label rather than by position, because
        sorting these put the unpacked server figure where the browser's
        belonged and the check passed on the wrong number.
        """
        row = [line for line in self.process.splitlines()
               if line.lstrip().startswith("|") and "linux/amd64" in line]
        self.assertEqual(1, len(row),
                         "RELEASING.md has no one row for linux/amd64")
        waited_for = [size.group() for size in self.SIZE.finditer(row[0])]
        self.assertEqual(2, len(waited_for),
                         f"expected a server and a browser figure, got "
                         f"{waited_for}")
        for path in self.TELLS_YOU_WHAT_TO_PULL:
            text = _read(path)
            for size in waited_for:
                with self.subTest(path=path, size=size):
                    self.assertIn(
                        size, text,
                        f"{path} tells somebody to pull an image without "
                        f"saying it is {size}")


if __name__ == "__main__":
    unittest.main()
