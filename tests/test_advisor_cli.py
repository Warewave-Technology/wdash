"""
`python -m wdash.advisor`, the way CI and an operator run it.

Two things it owes whoever runs it, and did not give.

**An exit code that means what CI reads it as.** `--fail-on critical`
exited 0 against a port nothing listened on, against a cluster that answered
every call 401, and against a saved snapshot of thirteen failures — each
time printing "score: 100/100" and "No findings." A gate that passes when it
cannot see is not a gate.

**The credentials only to the cluster.** It hard-coded `verify_certs=False`
and sent the credentials to whatever certificate answered. Measured here
with a listener holding a certificate nobody vouches for, and what reaches
it.

**And nothing from the environment.** The web process takes its clusters
from the configuration page; this takes its one from `--url`, its
credentials from `--username` and `--password-file`, and its authority from
`--ca-certs`. A variable the command once read is a variable somebody sets
for a process that does not read it.
"""

import base64
import contextlib
import datetime as dt
import io
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from tests.support import serve_in_background

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from wdash.advisor import ClusterSnapshot  # noqa: E402
from wdash.advisor.__main__ import _client_config, _exit_status, main  # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "lab-cluster.json")


def run_cli(*argv, env=None, stdin=None):
    """main() in this process. Returns (exit code, stdout, stderr).

    `env` is added to the environment for the call — to show it is NOT read,
    which is the only thing the command does with it."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env or {}):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch("sys.stdin", io.StringIO(stdin or "")):
            try:
                code = main(["--no-color", *argv])
            except SystemExit as exc:
                code = exc.code
    return code, out.getvalue(), err.getvalue()


def password_file(directory, password):
    path = os.path.join(directory, "password")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(password + "\n")
    return path


def closed_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Expired(BaseHTTPRequestHandler):
    """An Elasticsearch that answers every request 401."""

    def log_message(self, *_):
        pass

    def _answer(self):
        body = json.dumps({"error": {"type": "security_exception",
                                     "reason": "unable to authenticate user"},
                           "status": 401}).encode()
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Elastic-Product", "Elasticsearch")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_HEAD = do_POST = _answer


def failed(snapshot, *names):
    for name in names:
        setattr(snapshot, name, type(getattr(snapshot, name))())
        snapshot.errors[name] = "ConnectionTimeout(30s)"
    return snapshot


class FailOnTest(unittest.TestCase):
    """The exit code: 0 clean, 1 findings at the level, 2 could not tell."""

    def setUp(self):
        self.scratch = tempfile.mkdtemp()

    def saved(self, snapshot):
        path = os.path.join(self.scratch, "snapshot.json")
        snapshot.save(path)
        return path

    def test_a_refused_cluster_fails_the_gate(self):
        code, out, err = run_cli("--url", f"http://127.0.0.1:{closed_port()}",
                                 "--fail-on", "critical")
        self.assertEqual(code, 2)
        self.assertNotIn("100/100", out)
        self.assertNotIn("No findings.", out)
        self.assertIn("info", err, "what could not be collected, on stderr")

    def test_expired_credentials_fail_the_gate(self):
        server = serve_in_background(HTTPServer(("127.0.0.1", 0), Expired))
        try:
            code, out, _ = run_cli(
                "--url", f"http://127.0.0.1:{server.server_address[1]}",
                "--fail-on", "critical", "--username", "elastic",
                "--password-file", password_file(self.scratch, "expired"))
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(code, 2)
        self.assertNotIn("100/100", out)

    def test_a_missing_url_is_refused_rather_than_defaulted(self):
        """There is no cluster address anywhere but this flag: the web
        process takes its clusters from the configuration page, and a
        default here would be the one address in the product that came from
        nowhere anybody configured."""
        code, _, err = run_cli("--fail-on", "critical")
        self.assertEqual(code, 2)
        self.assertIn("--url", err)
        self.assertIn("--from-snapshot", err)

    def test_a_username_without_a_password_file_is_refused(self):
        code, _, err = run_cli("--url", "http://127.0.0.1:1",
                               "--username", "elastic")
        self.assertEqual(code, 2)
        self.assertIn("--password-file", err)

    def test_a_saved_snapshot_of_nothing_fails_the_gate(self):
        snapshot = failed(ClusterSnapshot(taken_at="x"),
                          *(n for n in ClusterSnapshot.__dataclass_fields__
                            if n not in ("taken_at", "errors")))
        code, out, _ = run_cli("--from-snapshot", self.saved(snapshot),
                               "--fail-on", "info")
        self.assertEqual(code, 2)
        self.assertIn("n/a", out)

    def test_nothing_collected_fails_even_without_the_gate(self):
        code, _, _ = run_cli("--url", f"http://127.0.0.1:{closed_port()}")
        self.assertEqual(code, 2)

    def test_an_unusable_url_is_not_a_finding(self):
        """It exited through sys.exit(message), which is status 1 — what CI
        reads as "the cluster has findings"."""
        code, _, err = run_cli("--url", "not a url", "--fail-on", "critical")
        self.assertEqual(code, 2)
        self.assertIn("not a url", err)

    def test_a_partial_report_with_nothing_at_the_level_fails_the_gate(self):
        """The three critical findings in the lab fixture come from mappings
        and nodes. Without those calls there is no critical finding, and no
        way to say there is none."""
        snapshot = failed(ClusterSnapshot.load(FIXTURE), "nodes_info", "index_mappings")
        code, out, err = run_cli("--from-snapshot", self.saved(snapshot),
                                 "--fail-on", "critical")
        self.assertEqual(code, 2)
        self.assertIn("not evaluated", out)
        self.assertIn("nodes_info", err)

    def test_a_partial_report_without_the_gate_still_exits_0(self):
        """The printed report says what is missing; without --fail-on
        nobody asked for a verdict on it."""
        snapshot = failed(ClusterSnapshot.load(FIXTURE), "nodes_info")
        code, _, _ = run_cli("--from-snapshot", self.saved(snapshot))
        self.assertEqual(code, 0)

    def test_findings_at_the_level_still_exit_1(self):
        """Even from a partial report: what was found is found."""
        snapshot = failed(ClusterSnapshot.load(FIXTURE), "nodes_info")
        code, _, _ = run_cli("--from-snapshot", self.saved(snapshot),
                             "--fail-on", "critical")
        self.assertEqual(code, 1)

    def test_a_complete_report_below_the_level_exits_0(self):
        snapshot = ClusterSnapshot(
            taken_at="x", info={"version": {"number": "8.19.9"}},
            health={"status": "green"},
            nodes_info={"nodes": {"n": {"name": "n", "roles": ["data", "master"]}}},
            cluster_settings={"defaults": {"action.destructive_requires_name": "true"}})
        code, out, err = run_cli("--from-snapshot", self.saved(snapshot),
                                 "--fail-on", "critical")
        self.assertEqual(code, 0, out + err)

    def test_a_report_where_every_rule_raised_does_not_pass_the_gate(self):
        """Nothing was evaluated, so the status is 2 — with or without
        --fail-on. It exited 0 without one, because `unavailable` did not
        count rules that raised."""
        from wdash.advisor.models import Report, all_rules

        report = Report(taken_at="x", cluster_name="c", version="8.19.9",
                        distribution="elasticsearch",
                        errors=[(r.id, "TypeError: boom")
                                for r in all_rules("elasticsearch")])
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(_exit_status(report, None), 2)
            self.assertEqual(_exit_status(report, "critical"), 2)
        self.assertIn("CLU001", err.getvalue(), "the reasons go to stderr")

    def test_the_exit_code_reaches_the_shell(self):
        snapshot = failed(ClusterSnapshot(taken_at="x"), "info", "health")
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.path.join(ROOT, "src")
        finished = subprocess.run(
            [sys.executable, "-m", "wdash.advisor", "--from-snapshot",
             self.saved(snapshot), "--fail-on", "info", "--no-color"],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(finished.returncode, 2, finished.stdout + finished.stderr)


def _authority(directory, name):
    """A CA that could sign for anything, and nothing trusts."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .sign(key, hashes.SHA256()))
    path = os.path.join(directory, f"{name}.crt")
    with open(path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate, key, path


def _leaf(directory, authority, authority_key):
    """A server certificate for 127.0.0.1, signed by `authority`."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "impostor")]))
        .issuer_name(authority.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            authority_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .sign(authority_key, hashes.SHA256()))
    cert_path = os.path.join(directory, "impostor.crt")
    key_path = os.path.join(directory, "impostor.key")
    with open(cert_path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return cert_path, key_path


class CertificateTest(unittest.TestCase):
    """Something answering in the cluster's place, and what it is sent."""

    USER, PASSWORD = "elastic", "s3cret-advisor-cli"

    def setUp(self):
        self.scratch = tempfile.mkdtemp()
        authority, authority_key, self.authority = _authority(self.scratch, "its-own-ca")
        _, _, self.other_authority = _authority(self.scratch, "some-other-ca")
        cert, key = _leaf(self.scratch, authority, authority_key)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.port = self.listener.getsockname()[1]
        self.received = []
        threading.Thread(target=self._serve, daemon=True).start()

    def tearDown(self):
        self.listener.close()

    def _serve(self):
        while True:
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(raw,), daemon=True).start()

    def _one(self, raw):
        # What arrives before any handshake, too: a request sent in the clear
        # fails the handshake here, and a listener that read only after one
        # would see nothing of it.
        try:
            raw.settimeout(3)
            self.received.append(raw.recv(4096, socket.MSG_PEEK))
        except Exception:
            pass
        try:
            with self.context.wrap_socket(raw, server_side=True) as tls:
                tls.settimeout(3)
                self.received.append(tls.recv(4096))
                tls.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                            b"X-Elastic-Product: Elasticsearch\r\n\r\n")
        except Exception:
            self.received.append(b"")

    def advise(self, *argv, credentials=True, **env):
        flags = (["--username", self.USER,
                  "--password-file", password_file(self.scratch, self.PASSWORD)]
                 if credentials else [])
        return run_cli("--url", f"https://127.0.0.1:{self.port}", *flags,
                       *argv, env=env)

    def credentials_sent(self):
        token = base64.b64encode(f"{self.USER}:{self.PASSWORD}".encode())
        return any(token in chunk or self.PASSWORD.encode() in chunk
                   for chunk in self.received)

    def dialled(self):
        """The ClientHello arrived: 'nothing was sent' is not 'nothing
        connected'."""
        return any(self.received)

    def test_by_default_a_certificate_nobody_vouches_for_gets_nothing(self):
        code, _, err = self.advise()
        self.assertTrue(self.dialled())
        self.assertFalse(self.credentials_sent(),
                         "the password went to a certificate nobody vouches for")
        self.assertEqual(code, 2)
        self.assertIn("--ca-certs", err)
        self.assertIn("--insecure", err)

    def test_verification_with_another_ca_gets_nothing(self):
        self.advise("--ca-certs", self.other_authority)
        self.assertTrue(self.dialled())
        self.assertFalse(self.credentials_sent())

    def test_the_named_ca_is_what_the_certificate_is_checked_against(self):
        """Given its own CA, the same listener is trusted — which is also
        what shows `credentials_sent` can see a password when one comes."""
        self.advise("--ca-certs", self.authority)
        self.assertTrue(self.credentials_sent())

    def test_insecure_is_a_choice_and_does_what_it_says(self):
        self.advise("--insecure")
        self.assertTrue(self.credentials_sent())

    def test_insecure_wins_over_a_named_ca(self):
        self.advise("--insecure", "--ca-certs", self.other_authority)
        self.assertTrue(self.credentials_sent())

    def test_the_password_can_come_from_standard_input(self):
        """`-`, for a pipeline that holds the secret in a variable and has
        no file to point at. The listener is trusted, so what arrives is
        what was piped."""
        code, _, _ = run_cli("--url", f"https://127.0.0.1:{self.port}",
                             "--username", self.USER, "--password-file", "-",
                             "--ca-certs", self.authority,
                             stdin=self.PASSWORD + "\n")
        self.assertTrue(self.credentials_sent())

    def test_nothing_is_read_from_the_environment(self):
        """The variables the command once read, exported, with the listener
        trusted and no credential flag: nothing arrives. A variable the
        command reads is a variable somebody sets for the web process too,
        which reads none of them."""
        self.advise("--ca-certs", self.authority, credentials=False,
                    ELASTICSEARCH_USERNAME=self.USER,
                    ELASTICSEARCH_PASSWORD=self.PASSWORD)
        self.assertTrue(self.dialled())
        self.assertFalse(self.credentials_sent(),
                         "a credential was read from the environment")


class _Args:
    def __init__(self, url="https://es.example:9200", insecure=False,
                 username=None, password_file=None, ca_certs=None):
        self.url, self.insecure = url, insecure
        self.username, self.password_file = username, password_file
        self.ca_certs = ca_certs


class ClientConfigTest(unittest.TestCase):
    """What the command hands the client, from the flags and nothing else.

    Two faults lived here when the switches were environment variables. The
    verification switch was fail-open on any spelling but "true", so `=1`
    meaning "on" turned the check off — a flag cannot be misspelled. And
    the CA bundle went to the client whatever the URL's scheme was, which
    elastic-transport refuses for a plain-http host, so a CA in the
    environment stopped the command running at all.
    """

    def config(self, url="https://es.example:9200", **flags):
        return _client_config(_Args(url, **flags))

    def test_the_certificate_is_checked_unless_insecure_says_otherwise(self):
        self.assertTrue(self.config()["verify_certs"])
        self.assertFalse(self.config(insecure=True)["verify_certs"])

    def test_certificate_warnings_are_only_silenced_when_asked_for(self):
        """Silencing them while verifying hides the problem being verified."""
        self.assertTrue(self.config()["ssl_show_warn"])
        self.assertFalse(self.config(insecure=True)["ssl_show_warn"])

    def test_a_ca_bundle_is_not_sent_to_a_plain_http_cluster(self):
        """TLS options with an http host are refused by the transport, and
        the whole command died before it reached the cluster."""
        self.assertNotIn("ca_certs", self.config(url="http://localhost:9200",
                                                 ca_certs="/etc/ssl/cert.pem"))

    def test_a_ca_bundle_reaches_an_https_cluster(self):
        self.assertEqual(self.config(ca_certs="/etc/ssl/cert.pem")["ca_certs"],
                         "/etc/ssl/cert.pem")

    def test_a_ca_bundle_is_not_sent_with_insecure(self):
        """A CA under `--insecure` is a contradiction; the switch wins."""
        self.assertNotIn("ca_certs", self.config(insecure=True,
                                                 ca_certs="/etc/ssl/cert.pem"))

    def test_credentials_come_from_the_flags(self):
        scratch = tempfile.mkdtemp()
        built = self.config(username="elastic",
                            password_file=password_file(scratch, "s3cret"))
        self.assertEqual(built["basic_auth"], ("elastic", "s3cret"))
        self.assertNotIn("basic_auth", self.config())

    def test_the_cluster_is_asked_for_thirty_seconds(self):
        """The searches ask the cluster for thirty; a client that gave up at
        its own default of ten cut a slow answer off with a timeout the
        setting said it would not get."""
        self.assertEqual(self.config()["request_timeout"], 30)


class CaBundleWithHttpTest(unittest.TestCase):
    """The regression, end to end: the command has to run at all."""

    def test_a_ca_bundle_does_not_stop_an_http_cluster_being_read(self):
        scratch = tempfile.mkdtemp()
        bundle = os.path.join(scratch, "ca.pem")
        with open(bundle, "w") as handle:
            handle.write("-----BEGIN CERTIFICATE-----\n")
        server = serve_in_background(HTTPServer(("127.0.0.1", 0), Expired))
        try:
            code, out, err = run_cli(
                "--url", f"http://127.0.0.1:{server.server_address[1]}",
                "--ca-certs", bundle)
        finally:
            server.shutdown()
            server.server_close()
        self.assertNotIn("TLS options require scheme", err,
                         "a CA bundle stopped a plain-http cluster being read")
        # It answered 401 to everything, so the report is of nothing — which
        # is exit 2, reached by collecting rather than by failing to start.
        self.assertEqual(code, 2, out + err)
        self.assertIn("info", err)
