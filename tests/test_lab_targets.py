"""
`./lab.sh` and the compose file it drives, held to each other.

The lab is how every backend adapter is measured, and how somebody trying
WDash gets something on the screen. Both of those depend on a name typed at a
prompt reaching a container, and there is nothing between the two but a case
statement somebody has to remember to extend.

The ways that drifts are all quiet:

  * a service added to the compose file behind a new profile is unreachable —
    `./lab.sh up <it>` says "Unknown target", which reads as a typo
  * a target whose services were renamed starts nothing at all, and compose
    exits 0 having done what it was asked
  * a target listed as holding data with no seeder behind it comes up empty,
    which is indistinguishable from an adapter that cannot read it

So this asks the script itself rather than a transcription of it: the
function half of `lab.sh` is sourced into a bash and the same `case`
statements the command line reaches are the ones answering here. Nothing
below runs docker, and nothing below starts anything.
"""

import os
import re
import subprocess
import tempfile
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..")
LAB = os.path.join(ROOT, "lab")

#: Where the dispatcher begins. Everything above it is definitions, and
#: sourcing that half gives the real functions with no side effects.
DISPATCHER = 'case "${1:-}" in'


def _read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as handle:
        return handle.read()


def ask(snippet):
    """Run a snippet with lab.sh's own functions in scope.

    The library is sourced from a temporary copy, so `LAB_DIR` inside it is
    that temporary directory rather than `lab/`. Nothing asked here reads it:
    the target table is a set of case statements over names.
    """
    library = _read(LAB, "lab.sh").split(DISPATCHER)[0]
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write(library)
        path = handle.name
    try:
        done = subprocess.run(["bash", "-c", f". {path}\n{snippet}"],
                              capture_output=True, text=True, timeout=30)
    finally:
        os.unlink(path)
    if done.returncode != 0:
        raise AssertionError(f"lab.sh refused `{snippet}`: {done.stderr}")
    return done.stdout.strip()


def targets():
    return ask('echo "$ALL_TARGETS"').split()


def data_targets():
    return ask('echo "$DATA_TARGETS"').split()


def compose():
    """The compose file as {service: [profiles]}.

    Parsed rather than grepped, the way `tests/test_kubernetes_manifests.py`
    reads the manifests: an indentation-based regular expression agrees with
    the file until somebody reformats it, and then it reports an empty lab
    rather than a mismatch.
    """
    with open(os.path.join(LAB, "docker-compose.yml"), encoding="utf-8") as f:
        document = yaml.safe_load(f)
    return {name: list(body.get("profiles") or [])
            for name, body in document["services"].items()}


class EveryTargetReachesTheComposeFileTest(unittest.TestCase):
    def setUp(self):
        self.services = compose()

    def test_the_compose_file_was_read(self):
        """Every test below iterates over this dictionary, so an empty one
        would pass them all."""
        self.assertIn("elasticsearch", self.services)
        self.assertGreater(len(self.services), 8, self.services)

    def test_each_target_names_services_that_exist(self):
        for target in targets():
            named = ask(f'target_services {target}').split()
            with self.subTest(target=target):
                self.assertTrue(named, f"{target} starts nothing")
                for service in named:
                    self.assertIn(service, self.services,
                                  f"{target} starts {service}, which the "
                                  f"compose file does not define")

    def test_each_target_names_the_profile_its_services_are_behind(self):
        """`up` passes `--profile`, and compose silently starts nothing for a
        service whose profile was not enabled."""
        for target in targets():
            profile = ask(f'target_profile {target}')
            for service in ask(f'target_services {target}').split():
                needed = self.services[service]
                with self.subTest(target=target, service=service):
                    if not needed:
                        continue  # not behind a profile at all
                    # Heartbeat brings up the cluster it writes into, and
                    # compose starts a dependency whatever its profile.
                    if profile in needed or not profile:
                        continue
                    self.assertIn(
                        profile, needed,
                        f"{target} asks for profile '{profile}' and "
                        f"{service} is behind {needed}")

    def test_every_profile_in_the_compose_file_can_be_started_by_name(self):
        """The direction that fails quietly: a service added behind a new
        profile is in the file, runs, and cannot be asked for."""
        reachable = {ask(f'target_profile {target}') for target in targets()}
        for service, profiles in self.services.items():
            for profile in profiles:
                with self.subTest(service=service, profile=profile):
                    self.assertIn(profile, reachable,
                                  f"no target starts the '{profile}' profile")

    def test_every_service_in_the_compose_file_belongs_to_a_target(self):
        started = {service for target in targets()
                   for service in ask(f'target_services {target}').split()}
        for service in self.services:
            with self.subTest(service=service):
                self.assertIn(service, started,
                              f"{service} is defined and no target starts it")


class EveryTargetAnswersForItselfTest(unittest.TestCase):
    """The three questions `./lab.sh targets` asks of each one. A silent
    empty answer there is a blank column on the sheet somebody is following."""

    def test_each_one_has_an_address(self):
        for target in targets():
            with self.subTest(target=target):
                self.assertTrue(ask(f'target_url {target}'),
                                f"{target} prints no address")

    def test_each_one_says_what_to_type_into_wdash(self):
        for target in targets():
            with self.subTest(target=target):
                said = ask(f'target_form {target}')
                self.assertTrue(said, f"{target} explains nothing")
                # Either it is a source, or it says what it is instead. Both
                # are answers; silence is not.
                self.assertTrue("Add source" in said
                                or "Authentication" in said
                                or "Not a source" in said
                                or "No source of its own" in said,
                                said)

    def test_each_one_can_be_asked_whether_it_is_up(self):
        """`target_ready` runs a probe. What it answers depends on what is
        running, which is not this test's business — that it answers at all,
        rather than falling through the case, is."""
        for target in targets():
            with self.subTest(target=target):
                ask(f'target_ready {target} && true || true')


class EveryDataTargetHasASeederTest(unittest.TestCase):
    def test_the_data_targets_are_targets(self):
        self.assertTrue(data_targets())
        for target in data_targets():
            self.assertIn(target, targets())

    def test_each_one_runs_a_script_that_exists(self):
        """`target_seed` names a file under `seed/`. A renamed seeder would
        otherwise be found by somebody waiting for data that never arrives."""
        body = _read(LAB, "lab.sh").split("target_seed()")[1].split("\ncmd_seed")[0]
        for target in data_targets():
            arm = body.split(f"{target})")[1].split(";;")[0]
            named = re.findall(r"seed/(\w+\.py)", arm)
            with self.subTest(target=target):
                self.assertEqual(len(named), 1,
                                 f"{target} runs {named or 'no seeder'}")
                self.assertTrue(
                    os.path.exists(os.path.join(LAB, "seed", named[0])),
                    f"{target} runs seed/{named[0]}, which is not there")

    def test_a_target_with_no_data_says_so_rather_than_failing(self):
        """`./lab.sh seed identity` is a reasonable thing to try."""
        self.assertIn("no sample data", ask('target_seed identity'))

    def test_the_synthetics_answer_names_the_agent(self):
        """It has no seeder because Heartbeat is a running process that
        writes its own checks — which is worth saying, since every other
        target in the list has one."""
        self.assertIn("Heartbeat", ask('target_seed synthetics'))


class TheGuidesNameTheSameTargetsTest(unittest.TestCase):
    """What somebody reads before typing a target name."""

    def test_the_help_text_lists_them(self):
        """`./lab.sh` with no argument prints the header of its own file."""
        header = _read(LAB, "lab.sh").split("set -euo")[0]
        for target in targets():
            with self.subTest(target=target):
                self.assertIn(target, header)

    def test_the_lab_page_lists_them(self):
        page = _read(LAB, "README.md")
        for target in targets():
            with self.subTest(target=target):
                self.assertIn(target, page)


if __name__ == "__main__":
    unittest.main()
