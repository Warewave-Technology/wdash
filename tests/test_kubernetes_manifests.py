"""
The shipped Kubernetes manifests, checked against the application.

These files drift silently. Nobody reads them until a deployment misbehaves,
and the ways they go wrong all look like something else:

  * `DATABASE_URL` unset means the metadata store lands on the container's own
    layer instead of the mounted volume. The symptom is that every restart
    reopens first-run setup — which reads as a bug in setup.
  * `TRUSTED_PROXY_COUNT` set to the wrong NUMBER — not unset, wrong — means
    the address read out of `X-Forwarded-For` is the ingress controller's, the
    same one for everybody. The symptom is that a stranger's failed logins
    lock you out.
  * `WDASH_ENCRYPTION_KEY` unset means the pod starts and no local account
    can sign in — the authenticator every one of them needs is sealed with
    that key. The lesser half of the same fault is the configuration page
    loading and then refusing to save a credential, which reads as a
    permissions problem.
  * A key the application never reads is worse than a missing one: somebody
    turns it and reports that it had no effect. A key the application DOES
    read but which never reaches the process is worse still — it reads as
    configuration and it is documentation.
  * A workload that does not exist at all — there was no alert evaluator
    anywhere in here — has no symptom. Rules are written, nothing evaluates
    them, and nothing says so.

So this is a consistency test, not a deployment test. It cannot tell you the
manifests work; it can tell you they still describe this application.

It also cannot tell you a cluster would accept them — a whole file of Traefik
CRDs on a group removed in v3 passed every test in here. That is the
`manifests` job in .github/workflows/tests.yml, which builds the kustomization
and puts every object through kubeconform in strict mode against three
Kubernetes versions.
"""

import os
import re
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
MANIFESTS = os.path.join(ROOT, "kubernetes")

#: Applied by `kubectl apply -k kubernetes/`, plus the ones that are
#: deliberately not. Anything else in the directory is caught by
#: KustomizationTest, which is the point of naming them.
NOT_APPLIED = {"kustomization.yaml", "secrets.yaml", "wdash-agent.yaml"}


def _files():
    return sorted(f for f in os.listdir(MANIFESTS) if f.endswith(".yaml"))


def _documents(name):
    with open(os.path.join(MANIFESTS, name)) as handle:
        return [d for d in yaml.safe_load_all(handle) if d]


def _every_document():
    for name in _files():
        if name == "kustomization.yaml":
            continue
        for document in _documents(name):
            yield name, document


def _read_manifest(name):
    """A manifest exactly as it is on disk, comments and all.

    The opposite of `_directives` below, and needed for the same reason: some
    of what these files claim is IN the comments, and a claim nothing reads
    is how this directory drifted.
    """
    with open(os.path.join(MANIFESTS, name), encoding="utf-8") as handle:
        return handle.read()


def _directives(name):
    """A manifest with its comments removed.

    Every check that looks for a fault by name has to read this rather than
    the file: these manifests explain what used to be wrong with them, in
    prose that quotes the thing that was wrong. Three tests in this repository
    have already reported an explanation as the fault it explains.
    """
    with open(os.path.join(MANIFESTS, name)) as handle:
        return "\n".join(line for line in handle.read().splitlines()
                          if not line.lstrip().startswith("#"))


def _page():
    """kubernetes/README.md, which nothing checked until it was wrong.

    It is the longest prose in the directory and the only file an operator
    reads before applying anything, and for two versions no test read it at
    all. It said the sidecar was on port 80 while every manifest beside it
    said 8080 — a claim the Deployment, the Service, the NetworkPolicy and
    the nginx.conf all contradict, and which survived because a comment
    nothing checks is the reason this directory drifted in the first place.
    """
    with open(os.path.join(MANIFESTS, "README.md"), encoding="utf-8") as handle:
        return handle.read()


def _by_name(name, kind, metadata_name):
    for document in _documents(name):
        if (document.get("kind") == kind
                and document.get("metadata", {}).get("name") == metadata_name):
            return document
    raise AssertionError(f"{kind}/{metadata_name} is not in {name}")


def _config_map(metadata_name="wdash-config"):
    return _by_name("configmap.yaml", "ConfigMap", metadata_name)["data"]


def _deployment():
    return _by_name("wdash-deployment.yaml", "Deployment", "wdash")


def _container(named):
    for container in (_deployment()["spec"]["template"]["spec"]["containers"]
                      + _deployment()["spec"]["template"]["spec"]
                      .get("initContainers", [])):
        if container["name"] == named:
            return container
    raise AssertionError(f"the pod has no container called {named}")


def _environment(container):
    """Every variable name this container is given, however it arrives.

    `envFrom` is the reason this exists. The Deployment used to name nine
    ConfigMap keys one at a time, and a check that read only `env:` could not
    tell the difference between a key that reaches the process and a key that
    merely sits in the ConfigMap describing a deployment it never touches.
    """
    names = {entry["name"] for entry in container.get("env", [])}
    for source in container.get("envFrom", []):
        reference = source.get("configMapRef")
        if reference:
            names |= {k for k in _config_map(reference["name"]) if k.isupper()}
        reference = source.get("secretRef")
        if reference:
            names |= set(_by_name("secrets.yaml", "Secret",
                                  reference["name"])["data"])
    return names


def _mount_paths(container=None):
    containers = ([container] if container is not None
                  else _deployment()["spec"]["template"]["spec"]["containers"])
    return {mount["mountPath"] for c in containers
            for mount in c.get("volumeMounts", [])}


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
        self.data = _config_map()

    def test_every_key_is_one_the_application_reads(self):
        """A key that looks like configuration and changes nothing is worse
        than a missing one. This file used to carry eleven of them —
        LOG_LEVEL, WORKERS, SESSION_TIMEOUT and friends — none read anywhere.
        """
        read = _environment_names_read_by_the_app()
        dead = sorted(key for key in self.data if key.isupper() and key not in read)
        self.assertEqual(dead, [], f"nothing reads these: {dead}")

    def test_every_key_read_into_the_config_is_used(self):
        """Read is not used. ELASTICSEARCH_TIMEOUT and LOGS_PER_PAGE were in
        this file, in the README's table and in .env.example, and config.py
        read both into the configuration — where nothing looked at either.
        The client kept a ten-second timeout and the page said 50, whatever
        they were set to. The check above only asked whether config.py read
        a key, and it did.

        Used means the setting it becomes is named somewhere in the source
        other than config.py — as a string, `config["KEY"]`, or as an
        attribute, `Config.KEY` — or is one Flask reads itself: FLASK_DEBUG
        becomes DEBUG, which only Flask looks at.
        """
        from flask import Flask
        with open(os.path.join(ROOT, "src", "wdash", "config.py")) as handle:
            config = handle.read()
        texts = []
        for directory, subdirectories, files in os.walk(os.path.join(ROOT, "src")):
            subdirectories[:] = [d for d in subdirectories if d != "__pycache__"]
            for filename in files:
                if filename.endswith(".py") and not (
                        filename == "config.py"
                        and os.path.basename(directory) == "wdash"):
                    with open(os.path.join(directory, filename)) as handle:
                        texts.append(handle.read())
        source = "\n".join(texts)

        def setting(key):
            """The Config attribute an environment key is read into."""
            read = re.search(rf"""os\.environ\.get\(\s*['"]{key}['"]""", config)
            if not read:
                return key
            assigned = re.findall(r"^    ([A-Z_][A-Z0-9_]*)\s*=", config[:read.start()], re.M)
            return assigned[-1] if assigned else key

        def used(key):
            name = setting(key)
            return (name in Flask.default_config
                    or any(re.search(rf"""['"]{n}['"]|\.{n}\b""", source)
                           for n in {key, name}))

        unused = sorted(key for key in self.data if key.isupper() and not used(key))
        self.assertEqual(unused, [], f"read into the config, used nowhere: {unused}")

    def test_every_key_reaches_the_process(self):
        """The other direction, and the one that was wrong.

        Six keys here never reached the pod, because the Deployment named the
        ones it wanted individually. Five of them happened to repeat the
        application's own defaults, so they cost nothing and looked correct.
        The sixth was RBAC_CONFIG_FILE — which is why the roles ConfigMap
        mounted at /etc/config was never opened, and why editing it appeared
        to do nothing.
        """
        given = _environment(_container("wdash"))
        missing = sorted(k for k in self.data if k.isupper() and k not in given)
        self.assertEqual(missing, [],
                         f"in the ConfigMap, never in the pod: {missing}")

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

    def test_the_proxy_count_is_the_number_of_proxies_in_front(self):
        """Not "at least one" — the exact number, counted from the client.

        This said 1, which is the nginx sidecar alone, while an Ingress put a
        controller in front of it as well. `client_address()` reads
        `trusted_proxies` entries in from the RIGHT of `X-Forwarded-For`, so
        one entry in from a chain of "<client>, <controller>" returns the
        CONTROLLER's address — the same value for every request in the
        cluster. Every user then shares one sign-in throttle bucket and one
        attacker locks out everybody, which is the exact failure the setting
        exists to prevent. Too high is no better: a chain shorter than the
        count falls back to the socket address, which behind the sidecar is
        127.0.0.1 for everyone.
        """
        proxies = 1  # the nginx sidecar, which appends to the header
        if any(document.get("kind") == "Ingress"
               for _, document in _every_document()):
            proxies += 1
        self.assertEqual(int(self.data["TRUSTED_PROXY_COUNT"]), proxies)

    def test_the_session_cookie_is_marked_secure(self):
        """TLS is terminated at the ingress, so without this the cookie also
        goes out over plain HTTP to the same host."""
        self.assertEqual(self.data["SESSION_COOKIE_SECURE"].lower(), "true")

    def test_dashboards_live_with_the_rest_of_the_metadata(self):
        """Left as "file", half the state is on the volume as JSON and half is
        in the database — two things to back up and two to restore in step."""
        self.assertEqual(self.data["DASHBOARD_STORAGE"], "database")

    def test_certificate_verification_matches_the_scheme(self):
        """`https://` with verification off talks to whatever answers, which
        is the one thing the scheme was chosen to prevent. Plain http:// with
        it on is merely meaningless, so only one direction is a fault."""
        if self.data["ELASTICSEARCH_URL"].startswith("https://"):
            self.assertEqual(
                self.data["ELASTICSEARCH_VERIFY_CERTS"].lower(), "true",
                "an https cluster with ELASTICSEARCH_VERIFY_CERTS off")


class TheRolesFileIsReadableTest(unittest.TestCase):
    """The rbac.yaml carried in a ConfigMap, put through the real importer.

    It shipped in a schema nothing has read for two versions: `index_patterns`
    where the loader wants `indices`, a nested `users:` block where it wants a
    flat `user_roles:`, no `group_roles` and no `default_role`, and the retired
    permissions `logs:search` and `user:manage`.

    Every one of those differences fails CLOSED — an unread `index_patterns`
    leaves the role with no indices at all — so the file looked perfectly
    valid and would have given every role an empty log screen. YAML that
    parses proves nothing here; only importing it does.
    """

    def setUp(self):
        self.text = _by_name("configmap.yaml", "ConfigMap",
                             "wdash-rbac-config")["data"]["rbac.yaml"]

    def test_the_mounted_file_is_the_one_the_application_opens(self):
        """A ConfigMap mounted somewhere nothing reads is decoration."""
        configured = _config_map()["RBAC_CONFIG_FILE"]
        self.assertTrue(
            any(configured.startswith(m.rstrip("/") + "/")
                for m in _mount_paths(_container("wdash"))),
            f"RBAC_CONFIG_FILE is {configured}, which nothing mounts")
        self.assertTrue(configured.endswith("/rbac.yaml"),
                        "the file name has to be the ConfigMap's key, which "
                        "is what appears in the mounted directory")

    def test_the_roles_survive_the_import(self):
        from wdash.store import Store

        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "rbac.yaml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.text)

        store = Store.open(f"sqlite:///{os.path.join(directory, 'seed.db')}",
                           rbac_file=path)
        roles = {role["name"]: role for role in store.roles.all()}

        self.assertIn("admin", roles, "the file seeded no admin role")
        # The boundary that vanished under the old schema.
        self.assertTrue(roles["admin"]["containers"],
                        "admin was imported with no indices at all — the "
                        "schema is not the one roles.py reads")
        self.assertIn("*", roles["admin"]["containers"])
        # Group mapping is inverted onto the role on the way in; losing it
        # demotes an entire organisation to the default role on upgrade.
        self.assertIn("wdash-admins", roles["admin"]["groups"] or [])
        self.assertEqual(store.settings.get("rbac.default_role"), "viewer")

    def _seed_then_edit(self, second):
        """Boot on this file, edit it, boot again — what the second start saw.

        Two `Store.open` calls against one database, which is a pod restart
        after somebody edited the ConfigMap. Nothing here mocks the reader:
        the question is what the application does with an edited file, and
        only opening the store twice answers it.
        """
        from wdash.store import Store

        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "rbac.yaml")
        url = f"sqlite:///{os.path.join(directory, 'seed.db')}"

        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.text)
        store = Store.open(url, rbac_file=path)
        before = (sorted(role["name"] for role in store.roles.all()),
                  store.settings.get("rbac.default_role"),
                  store.settings.get("rbac.claim_mappings"))
        store.engine.dispose()

        with open(path, "w", encoding="utf-8") as handle:
            handle.write(second)
        store = Store.open(url, rbac_file=path)
        after = (sorted(role["name"] for role in store.roles.all()),
                 store.settings.get("rbac.default_role"),
                 store.settings.get("rbac.claim_mappings"))
        store.engine.dispose()
        return before, after

    def test_an_edit_after_the_first_boot_changes_nothing(self):
        """Which is what the ConfigMap says about this file, in the comment
        beside RBAC_CONFIG_FILE and again at the top of the file itself.

        Both halves, because they are imported by different callers under
        different conditions: `RoleRepository.seed` runs when the roles table
        is empty, and `import_claims` runs when no claim mapping is stored.
        A restart that re-read either would silently undo an edit made on the
        configuration page, which is the one thing the page must be able to
        promise.
        """
        parsed = yaml.safe_load(self.text)
        parsed["roles"]["intruder"] = {
            "description": "added after the first boot",
            "permissions": ["logs:read"], "indices": ["*"]}
        parsed["default_role"] = "intruder"
        parsed["claim_mappings"] = {"email_claim": "mail",
                                    "username_claim": "uid",
                                    "groups_claim": "memberOf"}

        before, after = self._seed_then_edit(yaml.safe_dump(parsed))

        self.assertNotIn("intruder", after[0],
                         "a role added to the file after the first boot was "
                         "imported by the restart")
        self.assertEqual(before, after,
                         "editing the file after the first boot changed what "
                         "the application runs on")

    def test_the_claim_mappings_block_is_what_makes_that_true(self):
        """The claim above holds for this file only because it carries one.

        `import_claims` runs on every `Store.open` and stops at the first
        line only when a mapping is already STORED — so a file that shipped
        without the block stores nothing at the first boot, and every later
        start reads it again. Adding `claim_mappings:` to this ConfigMap
        after an installation is running would then take effect on the next
        restart, which is exactly what the comment beside RBAC_CONFIG_FILE
        promises cannot happen.

        Measured rather than asserted: the same file with the block removed,
        through the same two starts.
        """
        parsed = yaml.safe_load(self.text)
        self.assertTrue(
            parsed.get("claim_mappings"),
            "this file carries no claim_mappings, so the ConfigMap's "
            "'an edit made HERE after the first boot changes nothing at all' "
            "is false: a block added later would be read on the next restart")

        without = dict(parsed)
        without.pop("claim_mappings")
        self.text = yaml.safe_dump(without)
        before, after = self._seed_then_edit(yaml.safe_dump(parsed))
        self.assertIsNone(before[2])
        self.assertEqual(
            after[2], parsed["claim_mappings"],
            "a file with no claim_mappings was expected to pick them up on a "
            "later start — if this changed, the comment can be simplified")

    def test_the_configmap_accounts_for_everything_that_reads_this_file(self):
        """`Store.open` hands the file to TWO importers, not one.

        `roles.seed` gates on an empty roles table; `import_claims` gates on
        no stored claim mapping. The ConfigMap described one condition —
        "Read ONCE, when the roles table is empty" — and drew a categorical
        conclusion from it: "an edit made HERE after the first boot changes
        nothing at all". That is true of the roles and is not a thing the
        roles table can decide about `claim_mappings`, whose block is read
        the first start that finds none stored — not necessarily the first
        start at all, which is the case `import_claims` was added for.

        Read out of `Store.open` rather than listed here, so a third importer
        arriving means this fails rather than quietly describing two.
        """
        import inspect
        from wdash.store import Store

        body = inspect.getsource(Store.open)
        readers = sorted(set(re.findall(
            r"^\s*(?:\w+\.)*(seed|import_claims)\(", body, re.M)))
        self.assertEqual(
            readers, ["import_claims", "seed"],
            f"Store.open reads rbac.yaml with {readers}; the ConfigMap's "
            f"comment describes what these do, so it has to be revisited")

        comment = re.search(
            r"((?:^\s*#.*\n)+)\s*RBAC_CONFIG_FILE:",
            _read_manifest("configmap.yaml"), re.M).group(1)
        self.assertTrue(
            "claim_mappings" in comment,
            "the comment beside RBAC_CONFIG_FILE describes only `seed`, so "
            "it states a condition that does not hold for `import_claims` — "
            "which reads the same file under a different one. It says:\n"
            + comment)

    def test_no_role_asks_for_a_permission_that_was_retired(self):
        """`logs:search` folded into `logs:read` and `user:manage` into
        `system:admin`. A stored role is translated on the way out, so a
        retired name is not an error — it is a file describing a version of
        this application that no longer exists."""
        from wdash.permissions import RETIRED, known

        parsed = yaml.safe_load(self.text)
        for name, definition in parsed["roles"].items():
            for permission in definition["permissions"]:
                with self.subTest(role=name, permission=permission):
                    self.assertNotIn(permission, RETIRED)
                    self.assertTrue(known(permission),
                                    f"{permission} is not a permission this "
                                    f"application has")


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        self.deployment = _deployment()
        self.container = _container("wdash")
        self.environment = _environment(self.container)

    def test_every_configmap_reference_names_a_key_that_exists(self):
        """A missing key stops the pod from starting, but only at rollout —
        long after the manifest was changed."""
        available = set(_config_map())
        for entry in self.container.get("env", []):
            reference = entry.get("valueFrom", {}).get("configMapKeyRef")
            if reference and reference["name"] == "wdash-config":
                self.assertIn(reference["key"], available,
                              f"{entry['name']} reads a key that is not there")

    def test_every_secret_reference_names_a_key_that_exists(self):
        available = set(_by_name("secrets.yaml", "Secret",
                                 "wdash-secrets")["data"])
        for pod_container in self.deployment["spec"]["template"]["spec"]["containers"]:
            for entry in pod_container.get("env", []):
                reference = entry.get("valueFrom", {}).get("secretKeyRef")
                if reference and reference["name"] == "wdash-secrets":
                    self.assertIn(reference["key"], available,
                                  f"{entry['name']} reads a key that is not "
                                  f"in the Secret")

    def test_the_settings_that_fail_quietly_are_all_wired(self):
        """Each of these fails in a way that points somewhere else."""
        for name in ("DATABASE_URL", "TRUSTED_PROXY_COUNT",
                     "WDASH_ENCRYPTION_KEY", "SESSION_COOKIE_SECURE",
                     "DASHBOARD_STORAGE", "RBAC_CONFIG_FILE"):
            self.assertIn(name, self.environment)

    def test_nothing_is_handed_a_variable_the_source_ignores(self):
        """KUBERNETES_NAMESPACE, KUBERNETES_POD_NAME and KUBERNETES_NODE_NAME
        came in from the downward API and were read by nothing. They were the
        visible half of a cluster RBAC grant that was also read by nothing."""
        read = _environment_names_read_by_the_app()
        for pod_container in self.deployment["spec"]["template"]["spec"]["containers"]:
            if pod_container["name"] == "nginx":
                continue
            unread = sorted(n for n in _environment(pod_container)
                            if n not in read)
            self.assertEqual(unread, [],
                             f"{pod_container['name']} is given variables "
                             f"nothing reads: {unread}")

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
        url = _config_map()["DATABASE_URL"]
        if url.startswith("sqlite:"):
            self.assertEqual(self.deployment["spec"]["replicas"], 1)

    def test_a_read_write_once_volume_is_not_rolled(self):
        """RollingUpdate starts the new pod before the old one releases the
        volume. On another node that is a Multi-Attach error and the rollout
        stops dead; on the same node it is two processes writing one SQLite
        file. Either way the symptom is an upgrade stuck in ContainerCreating
        behind a healthy-looking old pod, which reads as a storage fault."""
        claims = {volume["persistentVolumeClaim"]["claimName"]
                  for volume in self.deployment["spec"]["template"]["spec"]["volumes"]
                  if "persistentVolumeClaim" in volume}
        exclusive = any(
            "ReadWriteOnce" in _by_name("wdash-deployment.yaml",
                                        "PersistentVolumeClaim",
                                        claim)["spec"]["accessModes"]
            for claim in claims)
        if exclusive:
            self.assertEqual(self.deployment["spec"]["strategy"]["type"],
                             "Recreate")

    def test_the_probes_leave_room_for_a_slow_start(self):
        """Migrations run at start-up. A liveness probe with a fixed head
        start restarts the container in the middle of one, repeatedly — which
        looks like a crash loop and is a timeout."""
        self.assertIn("startupProbe", self.container)
        probe = self.container["startupProbe"]
        grace = probe.get("periodSeconds", 10) * probe.get("failureThreshold", 3)
        self.assertGreaterEqual(grace, 60,
                                "the startup grace is shorter than a slow "
                                "migration, so it buys nothing")

    def test_no_container_can_write_its_own_filesystem(self):
        """Including the init container, which was the one without it."""
        specification = self.deployment["spec"]["template"]["spec"]
        for pod_container in (specification["containers"]
                              + specification.get("initContainers", [])):
            with self.subTest(container=pod_container["name"]):
                security = pod_container.get("securityContext", {})
                self.assertTrue(security.get("readOnlyRootFilesystem"))
                self.assertEqual(security.get("capabilities", {}).get("drop"),
                                 ["ALL"])


class TheAlertEvaluatorRunsTest(unittest.TestCase):
    """There was no workload for it anywhere in these manifests.

    `python -m wdash.alerts` is a separate process because evaluation has to
    run when nothing is arriving — an agent going completely silent produces
    no requests at all, and that is exactly when somebody needs telling. A
    deployment made from the old manifests let people write rules that were
    never evaluated, and nothing anywhere said so: the rules page listed them,
    the alerts page was simply empty, and empty is what a healthy system looks
    like.
    """

    def setUp(self):
        self.deployment = _deployment()
        self.evaluators = [
            c for c in self.deployment["spec"]["template"]["spec"]["containers"]
            if "wdash.alerts" in " ".join(c.get("command", [])
                                          + c.get("args", []))]

    def test_something_evaluates_the_rules(self):
        self.assertEqual(len(self.evaluators), 1,
                         "no container runs `python -m wdash.alerts`")

    def test_only_one_of_it_runs(self):
        """Two would evaluate the same rules and deliver the same alert twice.
        The state table is shared, so the second usually finds the transition
        already made — and "usually" is not a guarantee to page somebody on.
        In this pod, the replica count is what holds it."""
        self.assertEqual(self.deployment["spec"]["replicas"], 1)

    def test_it_reads_the_same_store_as_the_server(self):
        """A rule is a row in the metadata database. An evaluator pointed
        somewhere else evaluates nothing and reports no error."""
        evaluator = self.evaluators[0]
        self.assertIn("DATABASE_URL", _environment(evaluator))
        url = _config_map()["DATABASE_URL"]
        if url.startswith("sqlite:////"):
            path = "/" + url[len("sqlite:////"):]
            self.assertTrue(
                any(path.startswith(m.rstrip("/") + "/")
                    for m in _mount_paths(evaluator)),
                "the evaluator does not mount the volume the database is on")

    def test_it_can_decrypt_what_the_server_stored(self):
        """It queries the backends, and their credentials are encrypted with
        the same key. Without it the runner starts, reads the rules and finds
        no usable source — which is indistinguishable from nothing being
        wrong."""
        self.assertIn("WDASH_ENCRYPTION_KEY", _environment(self.evaluators[0]))


class TheServiceTest(unittest.TestCase):
    def test_the_application_port_is_not_published(self):
        """It was, beside the proxied one, so anything in the cluster could
        skip the sidecar. That matters because TRUSTED_PROXY_COUNT tells WDash
        to believe `X-Forwarded-For`: a request arriving straight on 5000 can
        name any client address it likes, walk through the per-address sign-in
        throttle, and write somebody else's address into the audit trail."""
        service = _by_name("wdash-deployment.yaml", "Service", "wdash")
        published = {port["port"] for port in service["spec"]["ports"]}
        self.assertNotIn(5000, published)
        self.assertEqual(published, {80})


class TheServiceAccountTest(unittest.TestCase):
    def test_no_api_token_is_mounted(self):
        """WDash never calls the Kubernetes API — no client library in
        requirements.txt, no import anywhere in src/ — so a token in the pod
        is a credential and nothing else."""
        account = _by_name("serviceaccount.yaml", "ServiceAccount", "wdash")
        self.assertIs(account.get("automountServiceAccountToken"), False)

    def test_nothing_grants_this_account_the_cluster(self):
        """It used to hold a ClusterRole over pods, services, endpoints,
        configmaps, deployments, replicasets and ingresses, plus a namespace
        Role with create/update/patch on `secrets`. Nothing asked for any of
        it, so the manifests turned a web-application compromise into
        namespace secret access in exchange for no feature at all."""
        grants = [f"{name}: {document['kind']}"
                  for name, document in _every_document()
                  if document.get("kind") in {"Role", "ClusterRole",
                                              "RoleBinding",
                                              "ClusterRoleBinding"}]
        self.assertEqual(grants, [], f"unexplained grants: {grants}")

    def test_no_binding_hard_codes_a_namespace(self):
        """The old bindings named `namespace: default` in their subjects, so
        installing anywhere else bound permissions to an account that did not
        exist. The namespace belongs to the kustomization, which sets it in
        one place."""
        for name, document in _every_document():
            for subject in document.get("subjects", []):
                self.assertNotIn("namespace", subject,
                                 f"{name} pins a namespace in a subject")


class TheIngressTest(unittest.TestCase):
    """It was two Traefik CRDs and three middlewares, and each of the three
    did something the application had already decided."""

    def setUp(self):
        self.ingress = _by_name("ingress.yaml", "Ingress", "wdash")

    def test_it_is_a_kind_every_cluster_has(self):
        """`traefik.containo.us/v1alpha1` is a group Traefik removed in v3.
        On a current installation the whole file failed to apply with "no
        matches for kind IngressRoute" — so the manifests described a way in
        that did not exist."""
        self.assertEqual(self.ingress["apiVersion"], "networking.k8s.io/v1")
        for name in _files():
            # Comments stripped first: ingress.yaml explains at the top which
            # group it used to be on, and a check reading the whole file
            # reports that explanation as the fault it explains.
            self.assertNotIn("traefik.containo.us", _directives(name),
                             f"{name} names a CRD group Traefik removed")

    def test_a_secure_cookie_has_somewhere_secure_to_travel(self):
        """SESSION_COOKIE_SECURE and `tls:` are one decision in two files. The
        old manifests had the cookie marked Secure and served the host over
        plain HTTP with no redirect, so the browser never stored it: sign-in
        succeeded and returned to the sign-in page, with no error anywhere."""
        if _config_map()["SESSION_COOKIE_SECURE"].lower() != "true":
            return
        self.assertTrue(self.ingress["spec"].get("tls"),
                        "the session cookie is Secure and the way in is not")
        served = {rule["host"] for rule in self.ingress["spec"]["rules"]}
        covered = {host for entry in self.ingress["spec"]["tls"]
                   for host in entry["hosts"]}
        self.assertEqual(served - covered, set(),
                         "a host is served without TLS while the cookie is "
                         "marked Secure")

    def test_it_does_not_set_headers_the_application_owns(self):
        """The Traefik middleware SET them rather than appending, so it
        replaced the application's Content-Security-Policy — which carries a
        per-response script nonce — with one containing `'unsafe-inline'`,
        turning the nonce protection off at the door. It also downgraded
        X-Frame-Options from DENY to SAMEORIGIN and brought back
        X-XSS-Protection, which was deliberately removed from the sidecar for
        being an XSS vector in itself."""
        for name in _files():
            # Directives only, for the same reason: this file's own prose has
            # to be able to name the headers it is explaining.
            text = _directives(name)
            for header in ("Content-Security-Policy", "X-Frame-Options",
                           "X-XSS-Protection", "Referrer-Policy",
                           "Strict-Transport-Security"):
                self.assertNotIn(header, text,
                                 f"{name} sets {header}, which "
                                 f"src/wdash/security.py owns")

    def test_it_enters_through_the_proxy(self):
        """Port 80 is the sidecar, which serves the static files and appends
        the `X-Forwarded-For` entry TRUSTED_PROXY_COUNT counts."""
        for rule in self.ingress["spec"]["rules"]:
            for path in rule["http"]["paths"]:
                service = path["backend"]["service"]
                self.assertEqual(service["name"], "wdash")
                self.assertEqual(service["port"]["number"], 80)

    def test_the_identity_provider_sends_people_back_here(self):
        """OIDC_REDIRECT_URI pointed at `http://wdash.local` while the TLS
        route served `wdash.yourdomain.com`. The provider then refuses with a
        message about a mismatched redirect URI, which names neither of the
        two files that disagree."""
        redirect = _config_map()["OIDC_REDIRECT_URI"]
        hosts = {rule["host"] for rule in self.ingress["spec"]["rules"]}
        self.assertTrue(redirect.startswith("https://"),
                        f"{redirect} is not over TLS")
        self.assertIn(redirect.split("/")[2], hosts,
                      f"{redirect} is not a host this Ingress serves")


class TheNetworkPolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = _by_name("networkpolicy.yaml", "NetworkPolicy",
                               "wdash-ingress")

    def test_it_covers_the_application(self):
        selector = self.policy["spec"]["podSelector"]["matchLabels"]
        labels = _deployment()["spec"]["template"]["metadata"]["labels"]
        for key, value in selector.items():
            self.assertEqual(labels.get(key), value,
                             "the policy selects labels the pod does not carry")

    def test_the_application_port_is_reachable_from_nowhere(self):
        """Half of closing that door is the Service publishing only 80. The
        other half is here: no rule may open 5000 to the network."""
        for rule in self.policy["spec"]["ingress"]:
            for port in rule.get("ports", []):
                self.assertNotEqual(port["port"], 5000)

    def test_it_does_not_claim_to_know_where_wdash_may_talk(self):
        """An egress rule would be a bigger claim than these files can make:
        the identity provider, the backends and an alert channel's webhook are
        all chosen after this is applied, and none of them announce themselves
        when they are blocked. A rule that silently stops an alert being
        delivered is worse than no rule."""
        self.assertEqual(self.policy["spec"]["policyTypes"], ["Ingress"])


class TheSecretsTest(unittest.TestCase):
    def test_nothing_ships_with_a_working_value(self):
        """`secret-key` shipped as a real base64 of a string printed in this
        repository, with a comment asking for it to be changed. An unedited
        apply therefore ran a production deployment on a session key anybody
        can read — and that key signs the administrator's cookie. A
        placeholder that works is not a placeholder."""
        secret = _by_name("secrets.yaml", "Secret", "wdash-secrets")
        filled = sorted(key for key, value in secret["data"].items() if value)
        self.assertEqual(filled, [],
                         f"these ship with a value: {filled}")

    def test_the_development_key_cannot_run_a_deployment_like_this_one(self):
        """Which is what makes an empty value safe rather than merely quiet.

        An empty environment variable lands straight back on the built-in
        development key, so emptying the Secret would have left the deployment
        just as forgeable and no longer obvious. SESSION_COOKIE_SECURE is the
        signal: nobody turns it on except to serve real people over TLS.
        """
        from wdash.app import create_app
        from wdash.config import Config

        class TLSConfig(Config):
            SECRET_KEY = ""          # exactly what the empty Secret produces
            SESSION_COOKIE_SECURE = True
            DATABASE_URL = "sqlite:///:memory:"
            ELASTICSEARCH_URL = ""

        with self.assertRaises(RuntimeError) as raised:
            create_app(TLSConfig)
        self.assertIn("SECRET_KEY", str(raised.exception))

    def test_an_unfilled_secret_arrives_as_the_development_key(self):
        """The link between the two halves, and the reason the check above is
        about this deployment rather than about a Python subclass.

        `Config` reads the variable with `or`, so an environment holding an
        empty string produces the development key rather than an empty one.
        Run in a subprocess because the class attribute is computed at import
        and this has to be measured from a clean one.
        """
        import subprocess

        source = ("import os, sys;"
                  "os.environ['SECRET_KEY'] = '';"
                  "os.environ['WDASH_NO_DOTENV'] = '1';"
                  "sys.path.insert(0, 'src');"
                  "from wdash.config import Config, DEV_SECRET_KEY;"
                  "print(Config.SECRET_KEY == DEV_SECRET_KEY)")
        result = subprocess.run([sys.executable, "-c", source],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "True", result.stderr)


class KustomizationTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(MANIFESTS, "kustomization.yaml")) as handle:
            self.text = handle.read()
        self.kustomization = yaml.safe_load(self.text)

    def test_every_manifest_is_either_applied_or_explained(self):
        """A file in this directory that nothing applies is a file somebody
        will apply by hand, in an order derived from its name."""
        applied = set(self.kustomization["resources"])
        for name in _files():
            with self.subTest(manifest=name):
                if name in applied or name in NOT_APPLIED:
                    continue
                self.fail(f"{name} is in kubernetes/ but not in the "
                          f"kustomization, and not named as deliberately left "
                          f"out")

    def test_what_is_left_out_says_why(self):
        for name in NOT_APPLIED - {"kustomization.yaml"}:
            self.assertIn(name, self.text,
                          f"{name} is skipped without a reason on the page")

    def test_every_resource_exists(self):
        for name in self.kustomization["resources"]:
            self.assertTrue(os.path.exists(os.path.join(MANIFESTS, name)),
                            f"the kustomization applies {name}, which is not "
                            f"in the directory")

    def test_it_installs_somewhere_of_its_own(self):
        """`namespace: default` was hard-coded in two RoleBindings and nowhere
        else, which is the worst of both: not configurable, and wrong the
        moment anybody installs beside something."""
        self.assertTrue(self.kustomization.get("namespace"))


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

    def test_the_year_long_cache_is_earned(self):
        """`expires 1y; immutable` is only safe because every asset the
        templates ask for carries `?v=<version>`. It did not: the version was
        a random number regenerated on every page load, so the two biggest
        files were never cached at all — while the favicon and the mark, which
        carried no version, were the only things this header really held.
        tests/test_frontend_integrity.py holds the other end."""
        if "immutable" not in self.directives:
            return
        templates = os.path.join(ROOT, "templates")
        for directory, _, files in os.walk(templates):
            for filename in files:
                if not filename.endswith(".html"):
                    continue
                with open(os.path.join(directory, filename)) as handle:
                    text = handle.read()
                for line in text.splitlines():
                    for match in re.finditer(r"url_for\(\s*'static'.*?\}\}",
                                             line):
                        self.assertTrue(
                            line[match.end():].startswith("?v="),
                            f"{filename} asks for a static file with no "
                            f"version, under a year-long immutable cache")


class TheAgentTest(unittest.TestCase):
    """The probe agent, which had no manifest at all."""

    def setUp(self):
        self.deployment = _by_name("wdash-agent.yaml", "Deployment",
                                   "wdash-agent")
        self.container = self.deployment["spec"]["template"]["spec"]["containers"][0]
        self.environment = {e["name"]: e for e in self.container["env"]}

    def test_it_runs_the_agent_rather_than_the_server(self):
        self.assertEqual(self.container["command"],
                         ["python", "-m", "wdash.agent"])

    def test_the_token_comes_from_a_secret(self):
        """An argument is visible in `ps` to anything sharing the namespace,
        which the agent's own argument parser says in as many words."""
        self.assertIn("secretKeyRef",
                      self.environment["WDASH_AGENT_TOKEN"]["valueFrom"])
        self.assertNotIn("--token", self.container.get("args", []))

    def test_the_spool_is_somewhere_it_can_be_written(self):
        """The spool exists so a restart loses no measurement. Its default
        path is under /app, which is read-only here — so the default would
        fail to open, and the results it was protecting would be the ones
        lost."""
        spool = self.environment["WDASH_AGENT_SPOOL"]["value"]
        mounts = {m["mountPath"] for m in self.container["volumeMounts"]}
        self.assertTrue(
            any(spool.startswith(m.rstrip("/") + "/") for m in mounts),
            f"{spool} is not on a mounted volume")

    def test_it_reaches_the_server_through_the_same_door(self):
        server = self.environment["WDASH_SERVER"]["value"]
        self.assertTrue(server.rstrip("/").endswith("wdash"),
                        "the agent is pointed somewhere other than the "
                        "in-cluster Service")

    def test_the_network_policy_lets_it_in(self):
        """It pushes results back, so a policy that forgets it turns every
        check into silence — which on a monitoring screen is the same shape as
        everything being fine."""
        labels = self.deployment["spec"]["template"]["metadata"]["labels"]
        policy = _by_name("networkpolicy.yaml", "NetworkPolicy",
                          "wdash-ingress")
        allowed = [selector["podSelector"]["matchLabels"]
                   for rule in policy["spec"]["ingress"]
                   for selector in rule["from"] if "podSelector" in selector]
        self.assertTrue(
            any(all(labels.get(k) == v for k, v in match.items())
                for match in allowed),
            "no ingress rule matches the agent's labels")


if __name__ == "__main__":
    unittest.main()


def _nginx_directives():
    conf = _by_name("configmap.yaml", "ConfigMap", "wdash-nginx-config")["data"]["nginx.conf"]
    return "\n".join(line for line in conf.splitlines()
                     if not line.lstrip().startswith("#"))


def _bytes(size):
    """nginx's `16m` and friends, in bytes."""
    number, unit = re.fullmatch(r"(\d+)([kKmMgG]?)", size.strip()).groups()
    return int(number) * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[unit.lower()]


class TheWayInTest(unittest.TestCase):
    """The port and the size of a request, at every door it passes."""

    def test_every_hop_names_the_same_port(self):
        """Ingress to Service port 80, Service to the sidecar, the policy on
        the pod's port. Change one and the pod runs, healthy, while nothing
        reaches it — the probes go straight to port 5000 and never notice."""
        listen = int(re.search(r"^\s*listen\s+(\d+);", _nginx_directives(), re.M).group(1))
        sidecar = [port["containerPort"] for port in _container("nginx")["ports"]]
        service = _by_name("wdash-deployment.yaml", "Service", "wdash")
        policy = _by_name("networkpolicy.yaml", "NetworkPolicy", "wdash-ingress")
        self.assertEqual(sidecar, [listen])
        self.assertEqual([port["targetPort"] for port in service["spec"]["ports"]],
                         [listen])
        for rule in policy["spec"]["ingress"]:
            self.assertEqual([port["port"] for port in rule["ports"]], [listen])

    def test_the_sidecar_needs_no_privilege_to_listen(self):
        """It listened on 80 as uid 101 with NET_BIND_SERVICE added back. A
        capability added in a security context reaches a non-root process
        only as an ambient one, which no runtime sets, so the bind depended
        on the node: containerd 1.x and CRI-O leave unprivileged ports at
        1024, and the sidecar crash-looped on its first bind()."""
        listen = int(re.search(r"^\s*listen\s+(\d+);", _nginx_directives(), re.M).group(1))
        self.assertGreaterEqual(listen, 1024)
        specification = _deployment()["spec"]["template"]["spec"]
        for pod_container in specification["containers"] + specification.get("initContainers", []):
            with self.subTest(container=pod_container["name"]):
                self.assertNotIn("add", pod_container.get("securityContext", {})
                                 .get("capabilities", {}))

    def test_a_delivery_fits_through_every_door(self):
        """An agent's results and their screenshots pass the ingress, the
        sidecar and the application, and each has its own limit. The
        sidecar's and the controller's were nginx's default of 1m, and a
        refused batch was a dropped one."""
        from wdash.agent.runner import MAX_BATCH_BYTES
        from wdash.config import Config
        application = Config.MAX_CONTENT_LENGTH
        sidecar = _bytes(re.search(r"client_max_body_size\s+(\S+);",
                                   _nginx_directives()).group(1))
        ingress = _bytes(_by_name("ingress.yaml", "Ingress", "wdash")["metadata"]
                         ["annotations"]["nginx.ingress.kubernetes.io/proxy-body-size"])
        self.assertGreaterEqual(sidecar, application)
        self.assertGreaterEqual(ingress, application)
        self.assertLess(MAX_BATCH_BYTES, application)


class TheProbesTest(unittest.TestCase):
    """Which question each probe asks. All three read /health, which asked
    every backend in turn: one that hung made it answer in twenty seconds,
    past every timeout here, and the kubelet restarted a container that was
    fine."""

    def setUp(self):
        self.container = _container("wdash")

    def test_each_probe_asks_only_what_its_answer_can_fix(self):
        self.assertEqual(self.container["startupProbe"]["httpGet"]["path"], "/livez")
        self.assertEqual(self.container["livenessProbe"]["httpGet"]["path"], "/livez")
        self.assertEqual(self.container["readinessProbe"]["httpGet"]["path"], "/readyz")

    def test_every_probe_says_how_long_it_waits(self):
        """The startup probe had none, so the kubelet's one second applied."""
        for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
            with self.subTest(probe=probe):
                self.assertIn("timeoutSeconds", self.container[probe])

    def test_the_images_own_check_asks_what_readiness_asks(self):
        """Docker's HEALTHCHECK read /health too: a compose service waiting
        on `service_healthy` waited on every backend answering in time."""
        with open(os.path.join(ROOT, "Dockerfile")) as handle:
            dockerfile = handle.read()
        check = re.search(r"^HEALTHCHECK .*?localhost:5000(/\w+)", dockerfile,
                          re.M | re.S)
        self.assertIsNotNone(check, "the server image has no health check")
        self.assertEqual(check.group(1), self.container["readinessProbe"]["httpGet"]["path"])

    def test_the_paths_are_ones_the_application_serves(self):
        from wdash.app import create_app
        from wdash.config import Config
        rules = {str(rule) for rule in create_app(Config).url_map.iter_rules()}
        for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
            with self.subTest(probe=probe):
                self.assertIn(self.container[probe]["httpGet"]["path"], rules)


class TheBrowserAgentTest(unittest.TestCase):
    def test_it_has_somewhere_to_write_temporary_files(self):
        """The root filesystem is read-only, and Playwright makes its
        artifacts directory in the temp dir before Chromium opens a page:
        every journey on the browser image reported down with "the browser
        could not start"."""
        deployment = _by_name("wdash-agent.yaml", "Deployment", "wdash-agent")
        specification = deployment["spec"]["template"]["spec"]
        container = specification["containers"][0]
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        mounts = {m["mountPath"]: m["name"] for m in container["volumeMounts"]}
        self.assertIn("/tmp", mounts)
        volume = next(v for v in specification["volumes"] if v["name"] == mounts["/tmp"])
        self.assertIn("emptyDir", volume)
        self.assertIn("sizeLimit", volume["emptyDir"],
                      "an unbounded emptyDir fills the node's disk")


def _hub_from_the_configmap():
    """The hub an application built from THIS ConfigMap would register.

    The point is the names. `ELASTICSEARCH_URL` registers sources of its own,
    and which names they take depends on two other keys in the same file —
    `TRACE_INDEX_PATTERNS` decides whether there is a trace source at all.
    Built from the file rather than from a fixture, so a ConfigMap that
    empties one of them is answered honestly.
    """
    from wdash.app import create_app
    from wdash.config import Config
    from wdash.store.secrets import SecretBox

    data = _config_map()

    def patterns(key):
        return tuple(p for p in (data.get(key) or "").split(",") if p.strip())

    class FromTheConfigMap(Config):
        TESTING = True
        SECRET_KEY = "manifests"
        DATABASE_URL = "sqlite:///:memory:"
        ELASTICSEARCH_URL = data["ELASTICSEARCH_URL"]
        TRACE_INDEX_PATTERNS = patterns("TRACE_INDEX_PATTERNS")
        MONITOR_INDEX_PATTERNS = patterns("MONITOR_INDEX_PATTERNS")
        OIDC_CLIENT_ID = None
        ENCRYPTION_KEY = SecretBox.generate_key()

    return create_app(FromTheConfigMap).hub


class TheEnvironmentSourcesTest(unittest.TestCase):
    """What ELASTICSEARCH_URL in this file registers, and under what names.

    Sources are edited in the product now, and the names matter for more than
    tidiness: a role's rules address a source by name, a saved link names one,
    and the repository REFUSES a configured source that collides with one of
    these — with a message quoting the name. A ConfigMap that names them
    wrongly sends somebody to look for a source that was never registered.

    This file said the key registers "a source of its own, named
    elasticsearch". No source has ever been called that.
    """

    def setUp(self):
        self.hub = _hub_from_the_configmap()
        self.registered = set(self.hub.base_source_names())

    def test_the_comment_names_sources_that_exist(self):
        block = re.search(
            r"((?:^\s*#.*\n)+)\s*ELASTICSEARCH_URL:",
            _read_manifest("configmap.yaml"), re.M).group(1)
        # Lowercase and starting with `elasticsearch`, which is what a source
        # name looks like here. Not `[a-z]+-[a-z]+`, which was the first
        # attempt and was worse than nothing: the name this comment actually
        # carried was a bare `elasticsearch`, with no hyphen, so the pattern
        # skipped the one thing it existed to find and passed on the two
        # correct names beside it. A mutation put the bare name back and
        # survived.
        #
        # `ELASTICSEARCH_URL` is excluded by case and `'prod-logs'` by the
        # prefix — it is the example of a CONFIGURED source in the warning
        # quoted here, and is deliberately not one of these.
        named = set(re.findall(r"[`\"'](elasticsearch[a-z-]*)[`\"']", block))
        self.assertTrue(
            named,
            "the comment beside ELASTICSEARCH_URL names no source at all, so "
            "nobody reading it can tell what the key registers")
        self.assertEqual(
            named - self.registered, set(),
            f"the comment names {sorted(named - self.registered)}, which this "
            f"ConfigMap registers nothing under. Registered: "
            f"{sorted(self.registered)}")

    def test_a_configured_source_cannot_take_one_of_those_names(self):
        """Which is the reason the names have to be right here.

        The form refuses the collision and quotes the name back. Somebody
        who was told the source is called `elasticsearch` types that, is not
        refused, and ends up with a source nothing can reach.
        """
        from wdash.store.sources import SourceError, _check_name

        for name in sorted(self.registered):
            with self.subTest(source=name):
                with self.assertRaises(SourceError):
                    _check_name(name, self.registered)
        # And the name the comment used to give is not one of them, which is
        # why it was never refused and never worked.
        _check_name("elasticsearch", self.registered)


class ThePageTest(unittest.TestCase):
    """kubernetes/README.md, held against the manifests and the application.

    Nothing read this file until it was wrong in three places at once. It is
    the only thing in the directory an operator reads end to end before
    applying anything, so a sentence in here that the code stopped honouring
    costs more than the same sentence in a comment.
    """

    def setUp(self):
        self.page = _page()

    def test_the_ports_it_names_are_the_ports_the_pod_opens(self):
        """"What is in the pod" is a table of containers and their ports.

        It said the nginx sidecar was on port 80. The sidecar has listened on
        8080 since it was made to run without privileges — the Deployment,
        the Service's targetPort, the NetworkPolicy and the nginx.conf all
        say so, and this table was the only thing left claiming otherwise.
        An operator debugging with `kubectl port-forward` reads this table.
        """
        rows = re.findall(r"^\|\s*`(\w+)`\s*\|([^|]*)\|", self.page, re.M)
        self.assertTrue(rows, "the page has no container table any more")

        checked = 0
        for name, description in rows:
            named = re.findall(r"port (\d+)", description)
            if not named:
                continue
            opened = {str(p["containerPort"])
                      for p in _container(name).get("ports", [])}
            for port in named:
                checked += 1
                with self.subTest(container=name, port=port):
                    self.assertIn(
                        port, opened,
                        f"the page puts `{name}` on port {port}; the pod "
                        f"opens {sorted(opened) or 'none'}")
        self.assertTrue(checked, "the table names no port at all")

    def test_the_probe_table_is_the_probes_the_pod_declares(self):
        """The page repeats the three probes, which is a fourth copy of them.

        Worth having — an operator reading about a restart loop is on this
        page, not in the Deployment — and worth checking, because the whole
        point of /livez and /readyz is that the kubelet stopped asking
        /health, and a page that went on naming /health would send somebody
        to debug the endpoint that is deliberately not wired to anything.
        """
        container = _container("wdash")
        declared = {kind: container[f"{kind}Probe"]["httpGet"]["path"]
                    for kind in ("startup", "liveness", "readiness")}

        rows = dict(re.findall(r"^\|\s*(startup|liveness|readiness)\s*\|"
                               r"\s*`([^`]+)`\s*\|", self.page, re.M))
        self.assertEqual(
            set(rows), set(declared),
            "the page's probe table does not name the same three probes the "
            "pod declares")
        for kind, path in sorted(declared.items()):
            with self.subTest(probe=kind):
                self.assertEqual(
                    rows[kind], path,
                    f"the page says the {kind} probe asks {rows[kind]}; the "
                    f"pod asks {path}")

    def test_it_says_what_the_first_sign_in_asks_for(self):
        """The page walked the reader to `/setup` and stopped there.

        Setup no longer ends at an account. Every local account needs an
        authenticator, and claiming the installation hands straight over to
        enrolling one — measured here rather than asserted, because where it
        hands over is the thing the page has to keep up with.
        """
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.store.secrets import SecretBox

        directory = tempfile.mkdtemp()

        class Fresh(Config):
            TESTING = True
            SECRET_KEY = "manifests"
            DATABASE_URL = f"sqlite:///{os.path.join(directory, 'first.db')}"
            ELASTICSEARCH_URL = ""
            OIDC_CLIENT_ID = None
            WTF_CSRF_ENABLED = False
            ENCRYPTION_KEY = SecretBox.generate_key()

        client = create_app(Fresh).test_client()
        self.assertEqual(client.get("/").headers.get("Location"), "/setup",
                         "the first visit no longer lands on /setup")

        claimed = client.post("/setup", data={
            "username": "operator",
            "password": "a-long-enough-passphrase-9",
            "confirm": "a-long-enough-passphrase-9",
        })
        landing = claimed.headers.get("Location", "")
        self.assertTrue(
            landing, "claiming the installation redirected nowhere")
        # `assertTrue`, not `assertIn`: a failing `assertIn` prints the
        # haystack, and the haystack here is the whole page.
        self.assertTrue(
            landing in self.page,
            f"claiming the installation hands over to {landing}, and the "
            f"page does not mention it — so the reader is told setup ends "
            f"with an account when it ends with an authenticator")

    def test_it_and_the_secret_agree_about_the_encryption_key(self):
        """`encryption-key` ships empty, and an empty value is valid base64.

        So a deployment that forgets it starts. What it cannot then do is let
        anybody sign in locally: the authenticator every local account needs
        is sealed with this key, and the store refuses to write a secret as
        plain text. The application says so at start-up as an ERROR; both
        documents said only that the configuration page would refuse to save
        a credential, which is the smaller half and reads as a permissions
        problem.

        The phrase is taken from what the application actually logs, so the
        two files are held to the application's own words rather than to a
        sentence written here.
        """
        import logging

        from wdash.app import create_app
        from wdash.config import Config

        class NoKey(Config):
            TESTING = True
            SECRET_KEY = "manifests"
            DATABASE_URL = "sqlite:///:memory:"
            ELASTICSEARCH_URL = ""
            OIDC_CLIENT_ID = None
            ENCRYPTION_KEY = None

        class Captured(logging.Handler):
            def __init__(self):
                super().__init__()
                self.errors = []

            def emit(self, record):
                if record.levelno >= logging.ERROR:
                    self.errors.append(record.getMessage())

        handler = Captured()
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            create_app(NoKey)
        finally:
            root.removeHandler(handler)

        spoken = " ".join(handler.errors).lower()
        self.assertIn(
            "no local account can sign in", spoken,
            "the application no longer says this at start-up, so the two "
            "documents below are quoting something that is gone")

        for name, text in (("kubernetes/README.md", self.page),
                           ("kubernetes/secrets.yaml",
                            _read_manifest("secrets.yaml"))):
            # Whitespace flattened: both documents wrap at 72 or 79, so the
            # sentence they are held to falls across a line break in places
            # and would otherwise be found only where it happens to fit.
            flattened = " ".join(text.lower().split())
            with self.subTest(document=name):
                self.assertTrue(
                    "no local account can sign in" in flattened,
                    f"{name} does not say what an empty encryption-key "
                    f"costs, and the application says it as an ERROR")

    def test_the_number_it_gives_for_picking_up_a_source_is_the_real_one(self):
        """"More than one replica" promises that a source saved on the page
        reaches every replica within five seconds and without a restart.

        That is the hub's `RELOAD_TTL`, and it is the sentence that decides
        whether somebody rolls the Deployment after every configuration
        change. A vague "a few seconds" needed no check; a number does.
        """
        from wdash.hub import Hub

        stated = re.search(r"reaches every replica within (\w+)\s*\n?seconds",
                           self.page)
        self.assertIsNotNone(
            stated, "the page no longer says how long a replica takes")
        words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
                 "six": 6, "ten": 10, "thirty": 30}
        said = words.get(stated.group(1), None) or int(stated.group(1))
        self.assertEqual(
            said, int(Hub.RELOAD_TTL),
            f"the page says {said} seconds; Hub.RELOAD_TTL is "
            f"{Hub.RELOAD_TTL}")

    def test_the_shell_it_sends_you_to_can_reach_the_store(self):
        """The page says to exec into the `wdash` container and run the
        recovery commands there, because `DATABASE_URL` is already in that
        environment and the commands read it the way the application does.

        Run anywhere else — a laptop, a debug pod — and they default to
        `sqlite:///data/wdash.db` beside the working directory: a store that
        is empty, created on the spot, and reported on as though it were the
        installation. The operator is locked out and has just been shown a
        healthy-looking answer about nothing.
        """
        given = _environment(_container("wdash"))
        for name in ("DATABASE_URL", "WDASH_ENCRYPTION_KEY"):
            with self.subTest(variable=name):
                self.assertIn(
                    name, given,
                    f"the page sends a locked-out operator into this "
                    f"container, and {name} is not in its environment")

    def test_every_recovery_command_it_gives_is_one_that_exists(self):
        """A way back that does not parse is worse than none.

        The page tells a locked-out operator what to run. Two of those
        commands exist only because a second factor is mandatory and the
        one-directory rule can shut everybody out — neither is reachable
        from a browser, which is the whole point — so a flag that has been
        renamed strands the reader at the exact moment the page is for.
        """
        import argparse
        import importlib

        quoted = re.findall(r"python -m (wdash\.store\.\w+)((?: +--[\w-]+)*)",
                            self.page)
        self.assertTrue(quoted, "the page gives no recovery command at all")

        by_module = {}
        for module, flags in quoted:
            by_module.setdefault(module, set()).update(re.findall(r"--[\w-]+",
                                                                  flags))

        for module, flags in sorted(by_module.items()):
            parser = _parser_of(importlib.import_module(module))
            accepted = {option
                        for action in parser._actions
                        for option in action.option_strings}
            for flag in sorted(flags):
                with self.subTest(command=module, flag=flag):
                    self.assertIn(
                        flag, accepted,
                        f"the page runs `python -m {module} {flag}`, which "
                        f"that command does not accept")

        self.assertIn(
            "--reset-totp", by_module.get("wdash.store.recover", set()),
            "a local account cannot sign in without a code and the page that "
            "would reset one is behind the sign-in that needs it, so this is "
            "the only way back and the page has to name it")


def _parser_of(module):
    """The ArgumentParser a `python -m wdash.store.x` command builds.

    Built by calling `main` with `--help` under a parser that records itself,
    because these modules construct the parser inside `main` rather than at
    import — which is right for them and awkward for exactly one reader.
    """
    import argparse

    captured = []
    original = argparse.ArgumentParser.parse_args

    def record(self, *arguments, **keywords):
        captured.append(self)
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = record
    try:
        try:
            module.main([])
        except SystemExit:
            pass
    finally:
        argparse.ArgumentParser.parse_args = original

    assert captured, f"{module.__name__} built no parser"
    return captured[-1]
