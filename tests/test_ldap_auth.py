"""
Directory sign-in, without a directory.

Two faults, each measured before it was fixed:

  * ldaps:// was not checked at all. ldap3's default is CERT_NONE, so the
    service account's password — and after it the password a person typed —
    went to anything that answered in the directory's place. Measured: a TLS
    listener with a certificate nobody vouches for received the service bind,
    password in the clear, on every sign-in.
  * a directory that could not answer was "no such user". An outage, a
    service account whose password had changed, a base DN that did not exist:
    each was recorded as a wrong password against every name that tried, and
    five of those locked people out of accounts that were fine.

The live half of this is tests/test_identity_lab.py, against the lab's
OpenLDAP.
"""

import datetime as dt
import os
import socket
import ssl
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.auth import ldap_auth  # noqa: E402
from wdash.auth.ldap_auth import DirectoryUnavailable  # noqa: E402

SETTINGS = {"server": "ldap://directory.invalid:389", "base_dn": "dc=corp",
            "bind_dn": "cn=wdash,dc=corp", "bind_password": "svc-password",
            "user_filter": "(uid={username})", "group_attribute": "memberOf"}


class FakeEntry:
    def __init__(self, dn):
        self.entry_dn = dn
        self.entry_attributes = ["mail", "memberOf"]
        self._values = {"mail": ["alice@corp"], "memberOf": ["cn=admins,dc=corp"]}

    def __getitem__(self, name):
        class Attribute:
            values = self._values[name]
        return Attribute()


class FakeConnection:
    """One ldap3 connection: what bind and search answer."""

    def __init__(self, bind=True, bind_code=0, raises=None, search=True,
                 search_code=0, entries=1, search_raises=False):
        self._bind, self._bind_code, self._raises = bind, bind_code, raises
        self._search_raises = search_raises
        self._search, self._search_code = search, search_code
        self.entries = [FakeEntry("uid=alice,dc=corp")] * entries if search else []
        self.result = {}

    def bind(self):
        if self._raises:
            from ldap3.core.exceptions import LDAPSocketOpenError
            raise LDAPSocketOpenError("unable to open socket")
        self.result = {"result": self._bind_code,
                       "description": "invalidCredentials"
                       if self._bind_code == 49 else "unavailable"}
        return self._bind

    def search(self, **kw):
        if self._search_raises:
            from ldap3.core.exceptions import LDAPSessionTerminatedByServerError
            raise LDAPSessionTerminatedByServerError("session terminated")
        self.result = {"result": self._search_code,
                       "description": "noSuchObject"
                       if self._search_code == 32 else "success"}
        return self._search

    def unbind(self):
        pass


class OutcomeTest(unittest.TestCase):
    def authenticate(self, service, user=None, password="typed"):
        """`service` answers the search; `user`, the bind that checks."""
        connections = iter([service] + ([user] if user else []))
        original = ldap_auth._connection
        ldap_auth._connection = lambda *a, **k: next(connections)
        try:
            return ldap_auth.authenticate(SETTINGS, "alice", password)
        finally:
            ldap_auth._connection = original

    def test_the_right_password_signs_in(self):
        result = self.authenticate(FakeConnection(), FakeConnection())
        self.assertEqual(result["username"], "alice")

    def test_a_wrong_password_is_a_refusal(self):
        self.assertIsNone(self.authenticate(
            FakeConnection(), FakeConnection(bind=False, bind_code=49)))

    def test_an_unknown_name_is_a_refusal(self):
        self.assertIsNone(self.authenticate(FakeConnection(entries=0)))

    def test_a_directory_that_cannot_be_reached_is_not_a_refusal(self):
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(raises=True))

    def test_a_service_account_that_cannot_bind_is_not_a_refusal(self):
        """A changed service password answered every sign-in with "wrong
        password"."""
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(bind=False, bind_code=49))

    def test_a_search_that_fails_is_not_a_refusal(self):
        """A base DN that does not exist answered exactly like a name that
        does not."""
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(search=False, search_code=32))

    def test_a_user_bind_that_fails_for_another_reason_is_not_a_refusal(self):
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(),
                              FakeConnection(bind=False, bind_code=52))

    def test_a_user_bind_that_cannot_reach_the_directory_is_not_a_refusal(self):
        """The directory went away between the search and the check."""
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(), FakeConnection(raises=True))

    def test_a_search_the_directory_breaks_off_is_not_a_refusal(self):
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(search_raises=True))

    def test_a_filter_matching_several_is_still_a_refusal(self):
        """sizeLimitExceeded is what size_limit=2 asks for when two match;
        an ambiguous filter must not pick one, and it is not an outage."""
        self.assertIsNone(self.authenticate(
            FakeConnection(search=False, search_code=4, entries=2)))


def _certificate(directory):
    """A self-signed certificate nobody vouches for."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-the-directory")])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(minutes=1))
                   .not_valid_after(now + dt.timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName(
                       [x509.DNSName("localhost")]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path = os.path.join(directory, "impostor.crt")
    key_path = os.path.join(directory, "impostor.key")
    with open(cert_path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
    return cert_path, key_path


class ImpostorTest(unittest.TestCase):
    """Something that answers in the directory's place, with a certificate
    nobody vouches for, and what it is sent."""

    SECRET = "svc-password-6u8"

    def setUp(self):
        self.scratch = tempfile.mkdtemp()
        cert, key = _certificate(self.scratch)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.cert = cert
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
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
            try:
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(3)
                    self.received.append(tls.recv(4096))
            except Exception:
                self.received.append(b"")

    def sign_in(self, **overrides):
        settings = {**SETTINGS, "server": f"ldaps://localhost:{self.port}",
                    "bind_password": self.SECRET, **overrides}
        try:
            ldap_auth.authenticate(settings, "alice", "typed-by-alice")
        except Exception as exc:
            return exc
        return None

    def leaked(self):
        return any(self.SECRET.encode() in chunk for chunk in self.received)

    def test_an_impostor_is_refused_before_anything_is_sent(self):
        outcome = self.sign_in()
        self.assertIsInstance(outcome, DirectoryUnavailable)
        self.assertFalse(self.leaked(), "the service password went to an impostor")

    def test_a_ca_file_is_what_the_certificate_is_checked_against(self):
        """Given as the CA, the same certificate is accepted — which is what
        a directory with its own CA needs."""
        self.sign_in(ca_certs=self.cert)
        self.assertTrue(self.leaked(), "a certificate from the given CA was refused")

    def test_turning_the_check_off_is_a_choice_and_it_does_what_it_says(self):
        self.sign_in(verify_certs=False)
        self.assertTrue(self.leaked())


if __name__ == "__main__":
    unittest.main()
