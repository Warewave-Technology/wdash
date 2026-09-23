"""
One version, in one place, and everything else reading it.

It was written down in four and they had parted company:

    src/wdash/__init__.py   1.0.0
    setup.py                1.0.0   (repeated, not read)
    package.json            1.0.0
    kubernetes manifests    wdash-elastic-dashboard:1.0.0

while the published images had reached 2.2.4. So the manifests in this
repository deployed an image five minor versions behind whatever anybody
thought they were running, and no file in the repository said the number that
was actually shipping.

A running instance could not be asked either — `/health` reported which
backends answered and nothing about itself.

None of that is a bug anybody would file. It is the kind of thing that costs
an afternoon during an incident, which is exactly when nobody has one.
"""

import json
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")

#: Semantic versioning, because the number is read by pip and by whoever is
#: deciding whether an upgrade can wait until Monday.
PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def declared():
    """The version the package states, which is the source everything else
    has to agree with."""
    return re.search(r'__version__ = "([^"]+)"',
                     _read("src", "wdash", "__init__.py")).group(1)


class TheVersionIsWellFormedTest(unittest.TestCase):
    def test_it_is_semantic(self):
        self.assertRegex(declared(), PATTERN)

    def test_it_is_ahead_of_what_was_last_published(self):
        """The published images reached 2.2.4 while the package said 1.0.0.
        A version behind the artefacts is worse than none: it looks like an
        answer."""
        major, minor, patch = (int(p) for p in declared().split("."))
        self.assertGreaterEqual((major, minor, patch), (2, 2, 4),
                                "this is behind an image that already exists")


class EverythingElseReadsItTest(unittest.TestCase):
    def setUp(self):
        self.version = declared()

    def test_setup_py_does_not_repeat_it(self):
        """Two copies of a number are two claims. `setup.py` had its own and
        they diverged, so it reads the package now."""
        source = _read("setup.py")
        self.assertNotRegex(source, r'version="\d+\.\d+\.\d+"',
                            "setup.py states a version of its own")
        self.assertIn("__version__", source,
                      "setup.py does not read the package version")

    def test_the_front_end_package_agrees(self):
        """`package.json` is private tooling and is never published, which
        makes its version meaningless — and a meaningless number that looks
        like the product's is worse than no number."""
        self.assertEqual(json.loads(_read("package.json"))["version"],
                         self.version)

    def test_the_lockfile_agrees_too(self):
        """npm writes the root version into the lockfile as well, and does
        not complain when the two differ — so it is a third copy that drifts
        silently."""
        lock = json.loads(_read("package-lock.json"))
        self.assertEqual(lock["version"], self.version)
        self.assertEqual(lock["packages"][""]["version"], self.version)

    def test_the_bundle_says_which_release_it_is(self):
        """And it has to be this one.

        The page asks for `wdash.min.js?v=<version>`, which says what it
        ASKED for. In the shipped Kubernetes deployment `/static/` is
        served by an nginx sidecar out of an emptyDir that a separate init
        container filled, so the file can come from a different image than
        the HTML — under the new URL, cached `immutable` for a year. The
        stamp in the bundle is what makes that visible, and a stamp that
        drifts from the version would name the wrong release in the one
        message somebody reads when nothing else makes sense.
        """
        for name in ("static/js/wdash.js", "static/js/wdash.min.js"):
            with self.subTest(file=name):
                self.assertIn(f"WDASH_BUNDLE_VERSION = '{self.version}'"
                              if name.endswith("wdash.js")
                              else f'WDASH_BUNDLE_VERSION="{self.version}"',
                              _read(name))

    def test_and_the_page_asks_the_bundle_that_question(self):
        """A stamp nothing reads is a comment. The template calls the
        check, and calls it with the VERSION rather than `asset_version`,
        which is the process start under debug — a local edit must not
        look like a deployment skew."""
        page = _read("templates/base.html")
        self.assertIn("wdashCheckBundleVersion('{{ wdash_version }}')", page)

    def test_a_local_edit_does_not_look_like_a_deployment_skew(self):
        """Under debug the cache buster is the process start, so that
        editing a stylesheet is visible without bumping a version. The
        bundle check must NOT use that number: it would call every page of
        every development run a version mismatch, and a warning that is
        always there is a warning nobody reads when it is true.

        The two are the same string in production, which is why this has
        to be asked with debug on — the only place they differ.
        """
        import sys as _sys
        _sys.path.insert(0, os.path.join(ROOT, "tests"))
        from tests.support import grant
        from tests.test_log_contract import TestConfig, _session
        from wdash.app import create_app

        class Debugging(TestConfig):
            DEBUG = True

        app = create_app(Debugging)
        client = app.test_client()
        grant(app, "u", ["logs:read"], ("*",))
        with client.session_transaction() as session:
            session["user_data"] = _session(["logs:read"], ("*",))
            session["_user_id"] = "1"
        page = client.get("/logs").get_data(as_text=True)
        self.assertIn(f"wdashCheckBundleVersion('{self.version}')", page)
        # And the buster really is something else here, or the assertion
        # above would pass for the wrong reason.
        self.assertNotIn(f"wdash.min.js?v={self.version}", page)

    def test_every_container_in_a_pod_runs_the_same_image(self):
        """Including the init container, and that is the point.

        `copy-static-files` copies `/app/static` into an emptyDir the nginx
        sidecar serves, so the JavaScript a browser gets comes from THAT
        image while the HTML comes from the application container's. Left
        on an older tag — which is what a partial `kubectl set image` or a
        patch naming one container does — it serves last release's file
        under this release's URL, cached `immutable` for a year, and the
        page runs code from a release it is not.

        Reported exactly that way: a control doing nothing, no error, no
        warning. The runtime check says so now; this keeps the manifests
        in the repository from being the thing that caused it.
        """
        import re
        for name in ("kubernetes/wdash-deployment.yaml",
                     "kubernetes/wdash-agent.yaml"):
            text = _read(name)
            ours = re.findall(r"image:\s*(\S*wdash[-\w]*:\S+)", text)
            with self.subTest(file=name):
                self.assertTrue(ours, f"{name} names no WDash image")
                tags = {reference.rsplit(":", 1)[1] for reference in ours}
                self.assertEqual(tags, {self.version},
                                 f"{name} mixes tags: {sorted(set(ours))}")

    def test_the_manifests_deploy_this_version(self):
        """They pinned `:1.0.0`. Whatever else is true of a deployment, the
        manifests in the repository should not install something older than
        the repository.

        Every file in the directory, not just the Deployment: the agent
        manifest pulls the same image under a different entry point, and a
        version bump that moved one and not the other would run an agent from
        a release the server has never seen.
        """
        import os
        directory = os.path.join(ROOT, "kubernetes")
        found = 0
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".yaml"):
                continue
            tags = re.findall(r"image:\s*\S*wdash-elastic-dashboard:(\S+)",
                              _read("kubernetes", name))
            found += len(tags)
            for tag in tags:
                with self.subTest(manifest=name):
                    self.assertEqual(tag, self.version)
        self.assertTrue(found, "no manifest names a wdash image at all")

    def test_the_page_beside_them_names_the_same_image(self):
        """`kubernetes/README.md` tells the reader to build and push the
        image the manifests pull, and gives the `docker build` line to do it
        with. A bump that moves the manifests and not the page hands over a
        command that builds a tag nothing deploys — and it is the page, not
        the YAML, that somebody copies from.

        Both images: the server's and the browser agent's, which is built
        from the same tree under a different target.
        """
        page = _read("kubernetes", "README.md")
        tags = re.findall(r"wdash(?:-elastic-dashboard|-browser):(\d+\.\d+\.\d+)",
                          page)
        self.assertTrue(tags, "the page names no image to build")
        for tag in tags:
            with self.subTest(tag=tag):
                self.assertEqual(tag, self.version)

    def test_a_running_instance_can_be_asked(self):
        """`/health` is the one endpoint that answers before sign-in, which
        makes it the one an operator can reach at three in the morning.

        Asked of a running app rather than of the source. The first version
        of this grepped `app.py` for the payload line, which would have gone
        on passing if the endpoint stopped serving.
        """
        import sys
        sys.path.insert(0, os.path.join(ROOT, "src"))
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "version"
            DATABASE_URL = "sqlite:///:memory:"
            ENCRYPTION_KEY = SecretBox.generate_key()

        payload = create_app(TestConfig).test_client().get("/health").get_json()
        self.assertEqual(payload.get("version"), self.version)


class TheReleaseIsConsistentTest(unittest.TestCase):
    """Things that have to move together with a version bump."""

    def test_the_image_the_manifests_pull_is_the_one_this_builds(self):
        """The Dockerfile builds `wdash`; the manifests pull
        `yigitbasalma/wdash-elastic-dashboard`. Different names are fine —
        one is local, one is published — but the tag has to be the version,
        or the manifest is pinned to something nobody can reproduce from this
        commit."""
        manifest = _read("kubernetes", "wdash-deployment.yaml")
        self.assertNotIn("wdash-elastic-dashboard:latest", manifest,
                         "`latest` is not a version, it is whatever happened "
                         "to be pushed most recently")


class TheProjectFilesSayWhatIsTrueTest(unittest.TestCase):
    """SECURITY.md and CONTRIBUTING.md make checkable claims.

    A security document that overstates the defences is worse than none: it
    tells a reporter not to bother looking at something that is not there.
    One draft of SECURITY.md here claimed the Content-Security-Policy carried
    no `unsafe-inline`, which is true of `script-src` and false of
    `style-src` — where it is deliberate, because a style attribute cannot
    carry a nonce.
    """

    def test_the_supported_version_is_this_one(self):
        line = re.search(r"\| (\d+\.\d+)\.x \| yes \|", _read("SECURITY.md"))
        self.assertIsNotNone(line, "SECURITY.md names no supported line")
        major_minor = ".".join(declared().split(".")[:2])
        self.assertEqual(line.group(1), major_minor)

    def test_the_csp_claim_matches_the_policy(self):
        """Both halves: scripts carry a nonce and no `unsafe-inline`, styles
        allow it and the document says so."""
        policy = _read("src", "wdash", "security.py")
        script = re.search(r'"script-src[^\n]*', policy).group(0)
        style = re.search(r'"style-src[^\n]*', policy).group(0)
        self.assertNotIn("unsafe-inline", script)
        self.assertIn("unsafe-inline", style)

        document = _read("SECURITY.md")
        self.assertIn("`style-src` DOES allow `'unsafe-inline'`", document)

    def test_the_contributing_guide_points_at_tests_that_exist(self):
        """A table of guards is a promise that each one is there."""
        import os
        guide = _read("CONTRIBUTING.md")
        for name in re.findall(r"`(test_\w+\.py)`", guide):
            self.assertTrue(
                os.path.exists(os.path.join(ROOT, "tests", name)),
                f"CONTRIBUTING.md names {name}, which does not exist")

    def test_the_security_document_is_reachable_from_the_guide(self):
        self.assertIn("SECURITY.md", _read("CONTRIBUTING.md"))
