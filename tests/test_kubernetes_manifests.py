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
  * `WDASH_ENCRYPTION_KEY` unset means the configuration page loads and then
    refuses to save a credential. The symptom reads as a permissions problem.
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
