"""
The shipped Kubernetes manifests, checked against the application.

These files drift silently. Nothing runs them in CI, nobody reads them until
a deployment misbehaves, and the ways they go wrong all look like something
else:

  * `DATABASE_URL` unset means the metadata store lands on the container's own
    layer instead of the mounted volume. The symptom is that every restart
    reopens first-run setup — which reads as a bug in setup.
  * `TRUSTED_PROXY_COUNT` unset behind the nginx sidecar means every request is
    counted as coming from 127.0.0.1, so all users share one sign-in throttle
    bucket. The symptom is that a stranger's failed logins lock you out.
  * `WDASH_ENCRYPTION_KEY` unset means the configuration page loads and then
    refuses to save a credential. The symptom reads as a permissions problem.
  * A key the application never reads is worse than a missing one: somebody
    turns it and reports that it had no effect.

So this is a consistency test, not a deployment test. It cannot tell you the
manifests work; it can tell you they still describe this application.
"""

import os
import re
import sys
import unittest

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
MANIFESTS = os.path.join(ROOT, "kubernetes")


def _documents(name):
    with open(os.path.join(MANIFESTS, name)) as handle:
        return [d for d in yaml.safe_load_all(handle) if d]


def _by_name(name, kind, metadata_name):
    for document in _documents(name):
        if (document.get("kind") == kind
                and document.get("metadata", {}).get("name") == metadata_name):
            return document
    raise AssertionError(f"{kind}/{metadata_name} is not in {name}")


def _environment_names_read_by_the_app():
    """Every environment variable the source actually looks at.

    Read out of the source rather than listed here, because a list here would
    be one more thing to keep in step with the code — which is the failure
    this whole file exists to catch.
    """
    names = set()
    patterns = (r"os\.environ\.get\(\s*['\"]([A-Z_][A-Z0-9_]*)['\"]",
                r"os\.getenv\(\s*['\"]([A-Z_][A-Z0-9_]*)['\"]",
                r"os\.environ\[\s*['\"]([A-Z_][A-Z0-9_]*)['\"]\s*\]")
    source = os.path.join(ROOT, "src")
    for directory, subdirectories, files in os.walk(source):
        subdirectories[:] = [d for d in subdirectories if d != "__pycache__"]
        for filename in files:
            if not filename.endswith(".py"):
                continue
            with open(os.path.join(directory, filename)) as handle:
                text = handle.read()
            for pattern in patterns:
                names |= set(re.findall(pattern, text))
    return names


class ConfigMapTest(unittest.TestCase):
    def setUp(self):
        self.data = _by_name("configmap.yaml", "ConfigMap", "wdash-config")["data"]

    def test_every_key_is_one_the_application_reads(self):
        """A key that looks like configuration and changes nothing is worse
        than a missing one. This file used to carry eleven of them —
        LOG_LEVEL, WORKERS, SESSION_TIMEOUT and friends — none read anywhere.
        """
        read = _environment_names_read_by_the_app()
        dead = sorted(key for key in self.data if key.isupper() and key not in read)
        self.assertEqual(dead, [], f"nothing reads these: {dead}")

    def test_the_database_is_on_the_mounted_volume(self):
        """Three slashes instead of four is a relative path, which resolves
        under WORKDIR — the container's own layer. Nothing errors; the data
        is simply gone at the next restart."""
        url = self.data["DATABASE_URL"]
        self.assertTrue(url.startswith("sqlite:////") or "://" in url.split("sqlite")[-1]
                        or not url.startswith("sqlite"),
                        f"{url} is relative, so it is not on the volume")

        if url.startswith("sqlite:////"):
            path = "/" + url[len("sqlite:////"):]
            mounts = _mount_paths()
            self.assertTrue(
                any(path.startswith(m.rstrip("/") + "/") for m in mounts),
                f"{path} is not under any mountPath: {sorted(mounts)}")

    def test_the_proxy_count_matches_the_number_of_proxies(self):
        """The nginx sidecar is one. At zero, every request is counted as
        127.0.0.1 and one attacker throttles everybody."""
        self.assertGreaterEqual(int(self.data["TRUSTED_PROXY_COUNT"]), 1)

    def test_the_session_cookie_is_marked_secure(self):
        """TLS is terminated at the ingress, so without this the cookie also
        goes out over plain HTTP to the same host."""
        self.assertEqual(self.data["SESSION_COOKIE_SECURE"].lower(), "true")

    def test_dashboards_live_with_the_rest_of_the_metadata(self):
        """Left as "file", half the state is on the volume as JSON and half is
        in the database — two things to back up and two to restore in step."""
        self.assertEqual(self.data["DASHBOARD_STORAGE"], "database")


def _mount_paths():
    deployment = _by_name("wdash-deployment.yaml", "Deployment", "wdash")
    out = set()
    for container in deployment["spec"]["template"]["spec"]["containers"]:
        for mount in container.get("volumeMounts", []):
            out.add(mount["mountPath"])
    return out


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        self.deployment = _by_name("wdash-deployment.yaml", "Deployment", "wdash")
        self.container = next(
            c for c in self.deployment["spec"]["template"]["spec"]["containers"]
            if c["name"] == "wdash")
        self.environment = {e["name"]: e for e in self.container.get("env", [])}

    def test_every_configmap_reference_names_a_key_that_exists(self):
        """A missing key stops the pod from starting, but only at rollout —
        long after the manifest was changed."""
        available = set(_by_name("configmap.yaml", "ConfigMap", "wdash-config")["data"])
        for name, entry in self.environment.items():
            reference = entry.get("valueFrom", {}).get("configMapKeyRef")
            if reference and reference["name"] == "wdash-config":
                self.assertIn(reference["key"], available,
                              f"{name} reads a key that is not in the ConfigMap")

    def test_every_secret_reference_names_a_key_that_exists(self):
        available = set(_by_name("secrets.yaml", "Secret", "wdash-secrets")["data"])
        for name, entry in self.environment.items():
            reference = entry.get("valueFrom", {}).get("secretKeyRef")
            if reference and reference["name"] == "wdash-secrets":
                self.assertIn(reference["key"], available,
                              f"{name} reads a key that is not in the Secret")

    def test_the_settings_that_fail_quietly_are_all_wired(self):
        """Each of these fails in a way that points somewhere else."""
        for name in ("DATABASE_URL", "TRUSTED_PROXY_COUNT",
                     "WDASH_ENCRYPTION_KEY", "SESSION_COOKIE_SECURE",
                     "DASHBOARD_STORAGE"):
            self.assertIn(name, self.environment)

    def test_it_does_not_advertise_an_endpoint_that_is_not_there(self):
        """`prometheus.io/scrape` pointed at /metrics, which answers 404. The
        target then sits permanently down, and a down target reads as a broken
        application rather than as a feature nobody built."""
        annotations = (self.deployment["spec"]["template"]["metadata"]
                       .get("annotations") or {})
        if annotations.get("prometheus.io/scrape") == "true":
            path = annotations.get("prometheus.io/path", "/metrics")
            from wdash.app import create_app
            from wdash.config import Config
            application = create_app(Config)
            rules = {str(r) for r in application.url_map.iter_rules()}
            self.assertIn(path, rules,
                          f"scraping {path}, which this application does not serve")

    def test_sqlite_is_not_paired_with_more_than_one_replica(self):
        """Two replicas over one RWO volume is either a scheduling failure or
        two processes writing one SQLite file across a network mount."""
        url = _by_name("configmap.yaml", "ConfigMap", "wdash-config")["data"]["DATABASE_URL"]
        if url.startswith("sqlite:"):
            self.assertEqual(self.deployment["spec"]["replicas"], 1)


class NginxTest(unittest.TestCase):
    """The sidecar's headers, which the application also sets."""

    def setUp(self):
        data = _by_name("configmap.yaml", "ConfigMap", "wdash-nginx-config")["data"]
        self.conf = data["nginx.conf"]
        # Directives only. A comment explaining why a header is absent has to
        # name it, and matching prose would then report the explanation as
        # the thing it explains.
        self.directives = "\n".join(
            line for line in self.conf.splitlines()
            if not line.lstrip().startswith("#"))

    def test_it_does_not_add_headers_the_application_owns(self):
        """`add_header` APPENDS. Setting these here sent two
        X-Frame-Options — the app's DENY and the sidecar's SAMEORIGIN — and a
        browser reading conflicting values may honour either.
        """
        for header in ("X-Frame-Options", "X-Content-Type-Options",
                       "Referrer-Policy", "Content-Security-Policy"):
            self.assertNotIn(f"add_header {header}", self.directives)

    def test_x_xss_protection_is_gone(self):
        """Removed from every current browser, and an XSS vector in itself."""
        self.assertNotIn("X-XSS-Protection", self.directives)

    def test_it_still_forwards_the_client_address(self):
        """TRUSTED_PROXY_COUNT counts on this header being there. Without it
        the throttle silently falls back to the socket address."""
        self.assertIn("X-Forwarded-For", self.directives)

    def test_it_proxies_to_the_port_the_image_listens_on(self):
        with open(os.path.join(ROOT, "Dockerfile")) as handle:
            dockerfile = handle.read()
        match = re.search(r"--bind[\"',\s]+0\.0\.0\.0:(\d+)", dockerfile)
        self.assertIsNotNone(match, "cannot tell which port the image binds")
        self.assertIn(f"127.0.0.1:{match.group(1)}", self.directives)


if __name__ == "__main__":
    unittest.main()
