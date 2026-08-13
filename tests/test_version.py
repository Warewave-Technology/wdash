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

    def test_the_manifests_deploy_this_version(self):
        """They pinned `:1.0.0`. Whatever else is true of a deployment, the
        manifests in the repository should not install something older than
        the repository."""
        manifest = _read("kubernetes", "wdash-deployment.yaml")
        tags = re.findall(r"image:\s*\S*wdash-elastic-dashboard:(\S+)",
                          manifest)
        self.assertTrue(tags, "the deployment names no wdash image at all")
        for tag in tags:
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
            ELASTICSEARCH_URL = ""
            OIDC_CLIENT_ID = None
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
