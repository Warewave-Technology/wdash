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
    """One ldap3 connection: what bind and search answer.

    As ldap3 answers, which the first version did not: its search returned
    True with nothing found, where ldap3 returns False with result 0, so
    "an unknown name" never reached the branch that tells an unknown name
    from a failed search; and "several match" had no entries at all, so the
    guard against signing in as the first of them was never run.
    """

    def __init__(self, bind=True, bind_code=0, raises=None, search=True,
                 search_code=0, entries=1, search_raises=False):
        self._bind, self._bind_code, self._raises = bind, bind_code, raises
        self._search_raises = search_raises
        self._search, self._search_code = search, search_code
        self.entries = [FakeEntry(f"uid=alice{i or ''},dc=corp")
                        for i in range(entries)]
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
                       "description": {32: "noSuchObject", 4: "sizeLimitExceeded"}
                       .get(self._search_code, "success")}
        if not self._search:
            self.entries = []
        return self._search and bool(self.entries)

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

    def test_a_user_bind_the_directory_cannot_answer_is_not_a_refusal(self):
        for code in (52, 51, 1, 80):
            with self.subTest(code=code), self.assertRaises(DirectoryUnavailable):
                self.authenticate(FakeConnection(),
                                  FakeConnection(bind=False, bind_code=code))

    def test_a_user_bind_refused_for_the_account_is_a_refusal(self):
        """389-ds and FreeIPA answer an inactivated account with 53, a
        password policy's lockout is 19. Each was a directory outage: a 503
        saying "try again shortly", and no limit counting it."""
        for code in (53, 19, 50):
            with self.subTest(code=code):
                self.assertIsNone(self.authenticate(
                    FakeConnection(), FakeConnection(bind=False, bind_code=code)))

    def test_the_service_account_refused_for_any_reason_is_an_outage(self):
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(bind=False, bind_code=53))

    def test_a_user_bind_that_cannot_reach_the_directory_is_not_a_refusal(self):
        """The directory went away between the search and the check."""
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(), FakeConnection(raises=True))

    def test_a_search_the_directory_breaks_off_is_not_a_refusal(self):
        with self.assertRaises(DirectoryUnavailable):
            self.authenticate(FakeConnection(search_raises=True))

    def test_a_filter_matching_several_is_still_a_refusal(self):
        """sizeLimitExceeded is what size_limit=2 asks for when more match;
        an ambiguous filter must not pick one, and it is not an outage."""
        user = FakeConnection()
        self.assertIsNone(self.authenticate(
            FakeConnection(search_code=4, entries=2), user))
        self.assertIsNone(user.result.get("result"), "the first match was tried")


def _certificate(directory, names=("localhost",), addresses=()):
    """A self-signed certificate nobody vouches for."""
    import ipaddress
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
                       [x509.DNSName(name) for name in names]
                       + [x509.IPAddress(ipaddress.ip_address(address))
                          for address in addresses]), critical=False)
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


class ImpostorTestCase(unittest.TestCase):
    """Something that answers in the directory's place, with a certificate
    nobody vouches for, and what it is sent."""

    SECRET = "svc-password-6u8"

    NAMES = ("localhost",)
    ADDRESSES = ()

    def setUp(self):
        self.scratch = tempfile.mkdtemp()
        cert, key = _certificate(self.scratch, names=self.NAMES,
                                 addresses=self.ADDRESSES)
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
            # What arrives before any handshake, too: a bind sent in the
            # clear to the ldaps port fails the handshake here, and a
            # listener that only read after one saw nothing of it.
            try:
                raw.settimeout(3)
                self.received.append(raw.recv(4096, socket.MSG_PEEK))
            except Exception:
                pass
            try:
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(3)
                    self.received.append(tls.recv(4096))
            except Exception:
                self.received.append(b"")

    def sign_in(self, host="localhost", **overrides):
        settings = {**SETTINGS, "server": f"ldaps://{host}:{self.port}",
                    "bind_password": self.SECRET, **overrides}
        try:
            ldap_auth.authenticate(settings, "alice", "typed-by-alice")
        except Exception as exc:
            return exc
        return None

    def leaked(self):
        return any(self.SECRET.encode() in chunk for chunk in self.received)


class ImpostorTest(ImpostorTestCase):
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

    def test_the_name_on_the_certificate_is_checked_too(self):
        """A certificate from the given CA, for another name: the
        certificate says `localhost`, the directory was asked for as
        127.0.0.1."""
        outcome = self.sign_in(host="127.0.0.1", ca_certs=self.cert)
        self.assertIsInstance(outcome, DirectoryUnavailable)
        self.assertFalse(self.leaked(), "the password went to the wrong name")

    def test_a_bind_in_the_clear_would_be_seen(self):
        """What makes `leaked` able to fail: plain LDAP to the same port."""
        self.sign_in(server=f"ldap://localhost:{self.port}")
        self.assertTrue(self.leaked())


class OtherNameCertificateTest(ImpostorTestCase):
    """A certificate from the given CA, made out to another name, dialled
    by name: the name check is what refuses it."""

    NAMES = ("directory.example",)

    def test_a_name_the_certificate_does_not_carry_is_refused(self):
        outcome = self.sign_in(ca_certs=self.cert)
        self.assertIsInstance(outcome, DirectoryUnavailable)
        self.assertFalse(self.leaked())


class AddressCertificateTest(ImpostorTestCase):
    """ldaps:// by address, with the address in the certificate.

    Refused on Python 3.12 and later with the right CA given: ldap3's
    fallback hostname check knows no IP addresses."""

    ADDRESSES = ("127.0.0.1",)

    def test_an_address_the_certificate_names_is_accepted(self):
        self.sign_in(host="127.0.0.1", ca_certs=self.cert)
        self.assertTrue(self.leaked(), "a certificate naming the address was refused")



class AddressMatchTest(unittest.TestCase):
    """The address half of the name check, on its own. Dialled, another
    address proves nothing here: 127.0.0.2 is not routed on every machine,
    and a refused connection passes for a refused certificate."""

    CERTIFICATE = {"subjectAltName": (("DNS", "directory.example"),
                                      ("IP Address", "10.0.0.5"),
                                      ("IP Address", "0:0:0:0:0:0:0:1\n"))}

    def setUp(self):
        from ldap3.core import tls
        ldap_auth._match_addresses()
        self.match, self.refused = tls.match_hostname, tls.CertificateError

    def test_an_address_it_names_matches(self):
        self.assertIsNone(self.match(self.CERTIFICATE, "10.0.0.5"))
        self.assertIsNone(self.match(self.CERTIFICATE, "::1"),
                          "an address written out in full is the same address")

    def test_an_address_it_does_not_name_is_refused(self):
        for address in ("10.0.0.6", "127.0.0.1"):
            with self.subTest(address=address), self.assertRaises(self.refused):
                self.match(self.CERTIFICATE, address)

    def test_a_name_is_still_ldap3s_to_judge(self):
        self.assertIsNone(self.match(self.CERTIFICATE, "directory.example"))
        with self.assertRaises(self.refused):
            self.match(self.CERTIFICATE, "other.example")

    def test_it_is_installed_once(self):
        from ldap3.core import tls
        ldap_auth._match_addresses()
        self.assertIs(tls.match_hostname, self.match)


if __name__ == "__main__":
    unittest.main()
