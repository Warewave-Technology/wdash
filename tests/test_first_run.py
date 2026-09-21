"""
The first two commands somebody types, and what they get.

`docker compose up` is the one command a reader tries before reading
anything, and in this repository it started an Elasticsearch and a Kibana
and not the product: the `wdash` service was commented out. What sat behind
the comment would not have worked either — it set `FLASK_ENV`, which Flask
removed in 2.3, and passed neither of the two keys a first sign-in needs, so
the container would have come up and refused to enrol an authenticator.

And `cp .env.example .env` left nothing to fill in: the quick start says
"then set `WDASH_ENCRYPTION_KEY` in it" and the line was commented out.

None of that is caught by anything else here. The suite tests the
application; these two files are what stands between a checkout and the
application running at all, and they drift silently because nobody runs
them twice.

Measured rather than assumed, on the file as it stands: `docker compose
build wdash` produces the server image, `docker compose up -d wdash` serves
`/livez` 200 and `/` redirects to `/setup`. What cannot go in a test is the
build itself — a minute and a half, and a network — so what is here is the
shape of the file, and the numbers in it that have to agree with the
Dockerfile and the manifests.
"""

import os
import re
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def compose():
    return yaml.safe_load(_read("docker-compose.yml"))


class TheComposeFileRunsTheProductTest(unittest.TestCase):
    def setUp(self):
        self.document = compose()
        self.wdash = self.document["services"].get("wdash")

    def test_there_is_a_wdash_service_at_all(self):
        self.assertIsNotNone(
            self.wdash, "`docker compose up` starts everything but WDash")

    def test_it_builds_the_server_image_rather_than_the_browser_one(self):
        """The browser target is the same tree plus Chromium — 1.77GB
        against 260MB — and nothing a server does needs it."""
        self.assertEqual(self.wdash["build"]["target"], "server")

    def test_it_carries_both_keys_and_will_not_start_without_them(self):
        """`:?` rather than a default. WDash refuses to store a secret with
        no encryption key and no local account can finish signing in, so an
        unset key is a container that comes up and cannot be used — and a
        command that stops with the name of the line to fill in is better
        than one that starts something broken."""
        environment = self.wdash["environment"]
        for key in ("SECRET_KEY", "WDASH_ENCRYPTION_KEY"):
            with self.subTest(key=key):
                self.assertIn(key, environment)
                self.assertIn(":?", str(environment[key]),
                              f"{key} has a default, so it can be unset")

    def test_the_database_is_on_the_volume_and_not_the_container_layer(self):
        """Otherwise every restart reopens first-run setup, which reads as a
        bug in setup."""
        url = self.wdash["environment"]["DATABASE_URL"]
        mounted = [volume.split(":")[1] for volume in self.wdash["volumes"]]
        self.assertTrue(any(url.endswith(f"{path}/wdash.db") or
                            f"{path}/" in url for path in mounted),
                        f"{url} is not under any of {mounted}")

    def test_it_sets_nothing_flask_stopped_reading(self):
        """`FLASK_ENV` was removed in Flask 2.3 and this file pinned 2.3.3.
        A setting the application never reads is worse than a missing one:
        somebody turns it and reports that it had no effect."""
        self.assertNotIn("FLASK_ENV", str(self.wdash["environment"]))

    def test_it_declares_no_version(self):
        """Compose stopped reading `version:` and warns about it, and a
        warning on the first command somebody runs is a bad first sentence."""
        self.assertNotIn("version", compose())

    def test_elasticsearch_is_not_a_dependency(self):
        """WDash starts with no source at all — none is read from the
        environment — so `depends_on` would claim a requirement that does
        not exist and delay the page that explains it."""
        self.assertNotIn("depends_on", self.wdash)


class ThePortsAgreeTest(unittest.TestCase):
    """One number in three files, and a fourth that must differ.

    The container port is what the image exposes, what gunicorn binds and
    what the Kubernetes probes ask for. The published one is deliberately
    NOT that: macOS ships an AirPlay receiver on 5000, which answers before
    anything you started — measured on this machine, `curl
    localhost:5000/livez` returned 403 from `Server: AirTunes` while the
    container answered 200 to the same path from inside.
    """

    def setUp(self):
        published, container = compose()["services"]["wdash"]["ports"][0] \
            .split(":")
        self.published, self.container = int(published), int(container)

    def test_the_container_port_is_the_one_the_image_serves(self):
        exposed = re.search(r"^EXPOSE (\d+)", _read("Dockerfile"), re.M)
        bound = re.search(r'"--bind", "0\.0\.0\.0:(\d+)"', _read("Dockerfile"))
        self.assertEqual(self.container, int(exposed.group(1)))
        self.assertEqual(self.container, int(bound.group(1)))

    def test_the_manifests_probe_the_same_port(self):
        manifest = _read("kubernetes", "wdash-deployment.yaml")
        ports = {int(port) for port in
                 re.findall(r"containerPort: (\d+)", manifest)}
        self.assertIn(self.container, ports)

    def test_the_published_port_is_the_one_every_local_instruction_uses(self):
        """`python main.py` and the quick start say 5001. A compose file
        that published 5000 would give a reader two addresses for one
        product, and the one it printed would be AirPlay's."""
        development = re.search(r"WDASH_DEV_PORT', (\d+)", _read("main.py"))
        self.assertEqual(self.published, int(development.group(1)))
        self.assertIn(f"localhost:{self.published}", _read("docker-compose.yml"))


class TheExampleEnvironmentHasSomethingToFillInTest(unittest.TestCase):
    def setUp(self):
        self.lines = [line for line in _read(".env.example").splitlines()
                      if line.strip() and not line.strip().startswith("#")]

    def test_the_encryption_key_is_a_line_and_not_a_comment(self):
        """`cp .env.example .env` has to leave one. Commented out, the
        quick start's "then set WDASH_ENCRYPTION_KEY in it" pointed at a
        line that was not there, and the first sign of it missing was the
        authenticator page refusing to enrol."""
        self.assertIn("WDASH_ENCRYPTION_KEY=", self.lines)

    def test_the_signing_key_is_there_too_and_empty(self):
        """Empty on purpose: a value printed in this repository is a value
        everybody has read, and WDash refuses to serve over HTTPS on one."""
        self.assertIn("SECRET_KEY=", self.lines)

    def test_neither_carries_a_value(self):
        for line in self.lines:
            name, _, value = line.partition("=")
            if name in ("SECRET_KEY", "WDASH_ENCRYPTION_KEY"):
                with self.subTest(name=name):
                    self.assertEqual(value, "", f"{name} ships a value")


if __name__ == "__main__":
    unittest.main()
