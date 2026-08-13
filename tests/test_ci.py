"""
What runs before a merge, and whether it still says what it claims.

Every guard in this suite is worth exactly as much as the thing that runs it,
and until `.github/workflows/tests.yml` existed that was somebody
remembering. This file is the other half: the workflow is a promise about
what gets checked, and a promise nothing verifies drifts.

Three drifts in particular, each of which leaves a green tick meaning less
than it looks:

  * the matrix and the packaging claim disagreeing, so `pip install` offers a
    Python nothing tests;
  * the browser job pinning a different Playwright from the image, so a
    journey is measured against a Chromium that never ships;
  * a job losing the command it exists to run.
"""

import os
import re
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..")
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "tests.yml")


def _workflow():
    with open(WORKFLOW) as handle:
        return yaml.safe_load(handle)


def _triggers(workflow):
    """What the workflow runs on.

    YAML 1.1 reads a bare `on` as the boolean true, so the key is `True`
    rather than `"on"` — a trap worth naming once here instead of meeting it
    again in every test that wants to know when a workflow fires.
    """
    return workflow.get("on", workflow.get(True))


def _setup_py():
    with open(os.path.join(ROOT, "setup.py")) as handle:
        return handle.read()


class WorkflowExistsTest(unittest.TestCase):
    def test_there_is_one(self):
        self.assertTrue(os.path.exists(WORKFLOW),
                        "nothing runs the suite except by hand")

    def test_it_runs_on_pull_requests(self):
        """A workflow that only runs on `main` reports a merge that has
        already happened."""
        self.assertIn("pull_request", _triggers(_workflow()))


class MatrixMatchesTheClaimTest(unittest.TestCase):
    """`python_requires` is a promise to somebody else's afternoon.

    It said ">=3.8" with classifiers down to 3.8, and that was false twice
    over: `psycopg==3.3.4` needs 3.10 and `cryptography` needs 3.9, so the
    install could never have resolved there. Nothing caught it because
    nothing had ever tried.
    """

    def setUp(self):
        self.matrix = _workflow()["jobs"]["suite"]["strategy"]["matrix"]
        self.versions = [str(v) for v in self.matrix["python"]]
        self.setup = _setup_py()

    def test_every_tested_version_is_a_claimed_one(self):
        for version in self.versions:
            self.assertIn(f"Programming Language :: Python :: {version}",
                          self.setup,
                          f"CI runs {version} and the package does not offer it")

    def test_every_claimed_version_is_a_tested_one(self):
        claimed = re.findall(r"Programming Language :: Python :: (3\.\d+)",
                             self.setup)
        for version in claimed:
            self.assertIn(version, self.versions,
                          f"the package offers {version} and nothing runs it")

    def test_the_floor_is_the_lowest_version_tested(self):
        floor = re.search(r'python_requires=">=(3\.\d+)"', self.setup).group(1)
        lowest = min(self.versions, key=lambda v: tuple(map(int, v.split("."))))
        self.assertEqual(floor, lowest)

    def test_the_image_python_is_one_of_them(self):
        """The version that actually ships has to be in the matrix, or the
        one configuration every deployment uses is the untested one."""
        with open(os.path.join(ROOT, "Dockerfile")) as handle:
            shipped = re.search(r"FROM python:(3\.\d+)", handle.read()).group(1)
        self.assertIn(shipped, self.versions)


class JobsStillDoWhatTheyAreForTest(unittest.TestCase):
    def setUp(self):
        self.jobs = _workflow()["jobs"]

    def _steps(self, job):
        return "\n".join(step.get("run", "")
                         for step in self.jobs[job]["steps"])

    def test_the_suite_job_runs_the_suite(self):
        self.assertIn("unittest discover", self._steps("suite"))

    def test_the_suite_job_runs_the_front_end_too(self):
        """`test_frontend_integrity` shells out to node and SKIPS when node is
        missing, so a job without it tests no JavaScript and says nothing."""
        steps = self.jobs["suite"]["steps"]
        self.assertTrue(any("setup-node" in str(step.get("uses", ""))
                            for step in steps),
                        "no node, so every front-end check skips itself")
        self.assertIn("npm test", self._steps("suite"))

    def test_the_browser_job_runs_the_journeys(self):
        self.assertIn("tests.test_journeys", self._steps("browser"))

    def test_the_browser_job_refuses_to_pass_by_skipping(self):
        """The failure this is for: Playwright not installing leaves every
        journey test skipped, and a skipped test is a green one.

        Asserted on the EXIT CONDITION rather than on the word appearing
        somewhere in the script. The first version of this checked for
        `result.skipped` anywhere, and passed against a job that printed the
        skips and then exited zero regardless — which is the same green tick
        with a paragraph of explanation above it.
        """
        steps = self._steps("browser")
        self.assertIn("SystemExit(", steps, "the job cannot fail on its own")
        condition = steps.split("SystemExit(", 1)[1].split("else")[0]
        self.assertIn("skipped", condition,
                      "the exit code does not depend on anything skipping")

    def test_the_browser_job_pins_the_playwright_the_image_ships(self):
        with open(os.path.join(ROOT, "Dockerfile")) as handle:
            shipped = re.search(r"playwright==([\d.]+)", handle.read()).group(1)
        self.assertIn(f"playwright=={shipped}", self._steps("browser"),
                      "CI would measure a journey against a Chromium that "
                      "never ships")

    def test_the_live_job_promises_a_cluster(self):
        """Without this the job runs, skips all six tests for want of a
        cluster, and reports success — which is the exact shape of the fault
        it exists to catch."""
        self.assertEqual(
            self.jobs["live-schema"]["env"].get("WDASH_REQUIRE_LAB"), "1")

    def test_the_live_job_does_not_reuse_the_applications_variable(self):
        """`tests/__init__.py` forces `ELASTICSEARCH_URL` empty so no test
        reaches a cluster nobody declared. Pointing this job at that name
        would either undo that or be undone by it — it was the second, and
        these tests skipped every run for a fortnight while printing "start
        the lab"."""
        env = self.jobs["live-schema"]["env"]
        self.assertIn("WDASH_LAB_URL", env)
        self.assertNotIn("ELASTICSEARCH_URL", env)

    def test_the_live_job_seeds_before_it_measures(self):
        steps = self._steps("live-schema")
        self.assertIn("seed.py", steps)
        self.assertLess(steps.index("seed.py"), steps.index("tests.test_hub"),
                        "the tests run before there is anything to read")

    def test_the_image_is_built(self):
        """The Dockerfile is the one artefact every deployment uses and the
        only one no test touches. A `--target browser` build is deliberately
        not here: it differs by one pip install and costs several minutes."""
        steps = self._steps("image")
        self.assertIn("docker build", steps)
        self.assertNotIn("--target browser", steps)

    def test_the_elasticsearch_service_matches_the_lab(self):
        """The document shapes these tests check were read off the lab's
        cluster. Measuring them against a different version is measuring
        something else."""
        with open(os.path.join(ROOT, "lab", ".env")) as handle:
            version = re.search(r"ES_VERSION=([\d.]+)", handle.read()).group(1)
        image = self.jobs["live-schema"]["services"]["elasticsearch"]["image"]
        self.assertTrue(image.endswith(f":{version}"),
                        f"CI runs {image}, the lab runs {version}")


if __name__ == "__main__":
    unittest.main()
