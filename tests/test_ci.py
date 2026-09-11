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

    def test_the_manifests_are_validated_against_the_api_schemas(self):
        """tests/test_kubernetes_manifests.py checks that the manifests still
        describe this application. It cannot check that a cluster would accept
        them: a whole file of Traefik CRDs on `traefik.containo.us/v1alpha1`,
        a group removed in v3, passed every test in this repository.

        `-strict` is the half that matters. Without it an unknown field — a
        typo in `startupProbe`, a field that moved between versions —
        validates happily and is then silently ignored by the cluster, which
        is the same shape as every other fault these files have had.
        """
        steps = self._steps("manifests")
        self.assertIn("kubeconform", steps)
        self.assertIn("-strict", steps,
                      "without -strict an unknown field validates and is then "
                      "ignored by the cluster")
        self.assertIn("kubectl kustomize", steps,
                      "the objects are validated as applied, not as written")

    def test_every_manifest_is_validated_by_something(self):
        """The kustomization deliberately leaves two files out, so building it
        and validating the result covers everything except exactly those two.
        They have to be named in the job or they are the only manifests in the
        repository that nothing checks at all."""
        import yaml as _yaml

        directory = os.path.join(ROOT, "kubernetes")
        with open(os.path.join(directory, "kustomization.yaml")) as handle:
            applied = set(_yaml.safe_load(handle)["resources"])
        steps = self._steps("manifests")
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".yaml") or name == "kustomization.yaml":
                continue
            if name in applied:
                continue
            with self.subTest(manifest=name):
                self.assertIn(f"kubernetes/{name}", steps,
                              f"{name} is in neither the kustomization nor "
                              f"the validation step")

    def test_the_validator_is_pinned(self):
        """An unpinned validator is a check whose meaning changes without a
        commit — and the direction it changes in is usually laxer, because
        that is the change nobody notices."""
        steps = self._steps("manifests")
        job = str(self.jobs["manifests"])
        self.assertRegex(job, r"v\d+\.\d+\.\d+",
                         "the kubeconform release is not pinned")
        self.assertNotIn("/latest/", steps)

    def test_it_validates_more_than_one_kubernetes_version(self):
        """A kind that stops being served between two releases is the failure
        this catches, and one version cannot see it."""
        versions = set(re.findall(r"1\.\d+\.0", self._steps("manifests")))
        self.assertGreaterEqual(len(versions), 2, sorted(versions))

    def test_the_elasticsearch_service_matches_the_lab(self):
        """The document shapes these tests check were read off the lab's
        cluster. Measuring them against a different version is measuring
        something else."""
        with open(os.path.join(ROOT, "lab", ".env")) as handle:
            version = re.search(r"ES_VERSION=([\d.]+)", handle.read()).group(1)
        image = self.jobs["live-schema"]["services"]["elasticsearch"]["image"]
        self.assertTrue(image.endswith(f":{version}"),
                        f"CI runs {image}, the lab runs {version}")


def _dockerfile():
    with open(os.path.join(ROOT, "Dockerfile")) as handle:
        return handle.read()


def _stages():
    """The Dockerfile's stages, in order, with what each one inherits.

    Each is (name, parent, directives): `parent` is the stage it is built
    FROM when that is an earlier stage, and `directives` its own lines. An
    environment is only real along a stage's FROM chain — an ENV written in
    one stage says nothing about a sibling.
    """
    stages = []
    for line in _dockerfile().splitlines():
        match = re.match(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
        if match:
            parent = match.group(1)
            known = {name for name, _, _ in stages}
            stages.append((match.group(2) or f"stage{len(stages)}",
                           parent if parent in known else None, []))
        elif stages and line.strip() and not line.lstrip().startswith("#"):
            stages[-1][2].append(line.strip())
    return stages


def _stage_environment(stage):
    """ENV along a stage's FROM chain, later lines overriding earlier ones —
    an empty value included, because `ENV PYTHONPATH=` is an override too."""
    by_name = {name: (parent, directives)
               for name, parent, directives in _stages()}
    chain = []
    while stage is not None:
        chain.insert(0, stage)
        stage = by_name[stage][0]
    environment = {}
    for name in chain:
        for directive in by_name[name][1]:
            match = re.match(r"^ENV\s+(\w+)=(\S*)$", directive)
            if match:
                environment[match.group(1)] = match.group(2)
            elif re.match(r"^WORKDIR\s+", directive):
                environment["__WORKDIR__"] = directive.split(None, 1)[1]
    return environment


def _module_entry_points():
    """Every `python -m <module>` the image or the manifests start, with the
    stage whose environment it starts in.

    Read from the files that start them — the Dockerfile's exec-form
    ENTRYPOINT/CMD (their own stage) and every container `command` in
    kubernetes/ (the image a plain `docker build` produces, the last stage)
    — so a new process is covered the day it is written down, not the day
    somebody remembers this test.
    """
    found = set()
    stage = None
    for line in _dockerfile().splitlines():
        match = re.match(r"^FROM\s+\S+(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
        if match:
            stage = match.group(1)
        array = re.match(r"^(?:ENTRYPOINT|CMD)\s+(\[.*\])", line)
        if array:
            parts = yaml.safe_load(array.group(1))
            if parts[:2] == ["python", "-m"]:
                found.add((parts[2], stage))
    last = _stages()[-1][0]
    manifests = os.path.join(ROOT, "kubernetes")
    for name in sorted(os.listdir(manifests)):
        if not name.endswith(".yaml"):
            continue
        with open(os.path.join(manifests, name)) as handle:
            for document in yaml.safe_load_all(handle):
                spec = (((document or {}).get("spec") or {})
                        .get("template") or {}).get("spec") or {}
                for container in (spec.get("containers") or []) + (
                        spec.get("initContainers") or []):
                    command = container.get("command") or []
                    if command[:2] == ["python", "-m"]:
                        found.add((command[2], last))
    return found


class EveryEntryPointImportsTest(unittest.TestCase):
    """The package lives at /app/src/wdash and nothing installs it.

    So `wdash` was importable in the image only by main.py, which puts src on
    the path itself — that is, only by gunicorn. The alert evaluator in the
    Kubernetes pod and the agent, the browser image's entry point, are
    `python -m wdash.<something>`, and each died at start with "No module
    named wdash", taking the pod's readiness with it. The CI image job passed
    throughout: it put src on the path by hand before importing anything.

    Measured here without Docker, from the repository root — the image's
    WORKDIR holds the same tree — with the environment the Dockerfile sets
    and none of this process's own.
    """

    def _image_environment(self, stage):
        """The environment `stage` sets, with its paths mapped from the
        image's WORKDIR onto the repository — and none of this process's own
        PYTHONPATH, which would answer the question for it."""
        image = _stage_environment(stage)
        workdir = image.pop("__WORKDIR__", None)
        self.assertEqual(workdir, "/app", "the image's tree moved")
        environment = {key: value for key, value in os.environ.items()
                       if key != "PYTHONPATH"}
        for key, value in image.items():
            if key == "PYTHONPATH":
                value = os.pathsep.join(
                    os.path.abspath(os.path.join(
                        ROOT, os.path.relpath(part, workdir)))
                    for part in value.split(":") if part)
            environment[key] = value
        environment["WDASH_NO_DOTENV"] = "1"
        return environment

    def test_the_processes_that_start_this_way_were_found(self):
        """Otherwise the test below passes by finding nothing to start."""
        modules = {module for module, _ in _module_entry_points()}
        self.assertLessEqual({"wdash.alerts", "wdash.agent"}, modules)
        stages = {stage for _, stage in _module_entry_points()}
        self.assertLessEqual({"browser", "server"}, stages,
                             "the browser image's ENTRYPOINT and the "
                             "manifests' image are both covered")

    def test_each_one_imports_with_its_own_stages_environment(self):
        """Per stage, along its FROM chain: an ENV in a sibling stage is not
        in this one's environment, and a later empty ENV is an override."""
        import subprocess
        import sys

        for module, stage in sorted(_module_entry_points()):
            with self.subTest(module=module, stage=stage):
                result = subprocess.run(
                    [sys.executable, "-m", module, "--help"], cwd=ROOT,
                    env=self._image_environment(stage), capture_output=True,
                    text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr[-500:])
                self.assertIn("usage:", result.stdout)

    def test_the_image_job_starts_them_as_the_image_does(self):
        """A check that fixes the path before it looks cannot see the path
        being wrong — and there are more ways to fix it than sys.path: an
        environment flag, a working directory, a different entry point, or a
        step that cannot fail."""
        steps = "\n".join(step.get("run", "")
                          for step in _workflow()["jobs"]["image"]["steps"])
        for forbidden in ("sys.path", "PYTHONPATH", " -e ", "--env",
                          " -w ", "--workdir", "--entrypoint", "|| true"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, steps)
        for module in sorted({module for module, _ in _module_entry_points()}):
            with self.subTest(module=module):
                self.assertRegex(
                    steps, rf"(?m)^\s*docker run --rm wdash:ci python -m "
                           rf"{re.escape(module)} --help\s*$")


if __name__ == "__main__":
    unittest.main()


class TheBrowserJobRunsEveryBrowserSuiteTest(unittest.TestCase):
    """A suite that needs a browser and is not in that job never runs.

    `tests/test_rendered_pages.py` skips without playwright, so leaving it
    out of the one job that installs playwright would have made it a test
    that only ever ran on the machine it was written on — green everywhere
    else, by skipping.
    """

    #: Every module that needs a real browser. Adding one here and forgetting
    #: the workflow is the mistake this catches.
    BROWSER_SUITES = ("tests.test_journeys", "tests.test_rendered_pages")

    def setUp(self):
        self.jobs = _workflow()["jobs"]

    def test_the_browser_job_runs_all_of_them(self):
        """Looking for `-m unittest <module>`, not for the module's name.

        The step below that fails the job on a skip also names every module,
        so a check for the bare name passes with the step that RUNS it
        deleted — the suite would then only be loaded by the guard, which
        reports it as run and skipped nothing because it never got there.
        """
        commands = " ".join(step.get("run", "")
                            for step in self.jobs["browser"]["steps"])
        for module in self.BROWSER_SUITES:
            with self.subTest(module=module):
                self.assertIn(f"-m unittest {module}", commands)

    def test_the_skip_check_covers_all_of_them(self):
        """The step that fails the job when anything skipped. It names the
        modules it loads, and a suite missing from that list can skip in
        silence."""
        steps = " ".join(str(step) for step in self.jobs["browser"]["steps"])
        guard = steps.split("loadTestsFromNames")[1]
        for module in self.BROWSER_SUITES:
            with self.subTest(module=module):
                self.assertIn(module, guard)
