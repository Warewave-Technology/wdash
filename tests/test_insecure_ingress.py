"""
WDash behind an ingress with no certificate the browser accepts.

Reported from a real cluster: every form refused with "That request did not
carry a valid security token", including the sign-in form, on a deployment
reached over plain `http` because its ingress had no usable certificate.

The chain is short and none of it is a bug on its own. The shipped
`kubernetes/configmap.yaml` sets `SESSION_COOKIE_SECURE: "true"`, so the
session cookie is marked `Secure`; a browser will not send a `Secure` cookie
over `http`; `install_csrf` finds no cookie and refuses. What WAS a bug is
what the page then said — "the ordinary cause is a page left open while the
session behind it ended" — which is a cause the reader does not have, and
which sends them to reload a page that will fail again for ever.

The second half of this file is the other thing that turned up while
reading it: HSTS was sent on responses to plain `http`, because the
condition asked the CONFIGURATION whether the deployment was behind TLS and
never asked the REQUEST.

The first attempt at that was wrong and `tests/test_security_headers.py`
caught it. Asking "did this arrive securely" withholds HSTS from a proxy
that terminates TLS and sets no `X-Forwarded-Proto` — a real and common
configuration — which is protection lost, silently, to fix something that
RFC 6797 already tells browsers to ignore. So the question is the other way
round: withhold only where a trusted header says `http` in so many words.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wdash.security import _known_to_be_plain_http  # noqa: E402

PASSWORD = "a-long-password-12"


def _app(secure=True, proxies=2):
    """An app configured the way the Kubernetes manifests configure one."""
    from wdash.app import create_app
    from wdash.config import Config
    from wdash.store.secrets import SecretBox

    class _Config(Config):
        SECRET_KEY = "x" * 50
        DATABASE_URL = "sqlite:///:memory:"
        SESSION_COOKIE_SECURE = secure
        TRUSTED_PROXY_COUNT = proxies
        ENCRYPTION_KEY = SecretBox.generate_key()

    app = create_app(_Config)
    app.store.users.create_first_admin("admin", PASSWORD, role="admin")
    return app


class WhatTheRefusalSaysTest(unittest.TestCase):
    """The page has two causes to choose between and they are exclusive: a
    stale session still SENDS its cookie."""

    def refuse(self, secure=True, with_cookie=False):
        app = _app(secure=secure)
        client = app.test_client()
        if with_cookie:
            client.get("/auth/login", base_url="http://wdash.test")
        answer = client.post("/auth/login",
                             data={"username": "admin", "password": "x"},
                             base_url="http://wdash.test")
        return answer, answer.get_data(as_text=True)

    def test_a_secure_cookie_over_http_is_refused(self):
        """The report, reproduced. Not a regression test for a fix — this
        refusal is correct and stays."""
        answer, _ = self.refuse()
        self.assertEqual(answer.status_code, 400)

    def test_and_the_page_names_that_cause(self):
        _, body = self.refuse()
        self.assertIn("No cookie arrived", body)
        self.assertIn("Secure", body)

    def test_and_stops_offering_the_one_the_reader_does_not_have(self):
        """"Go back and reload" is advice that cannot work here, and a
        reader who follows it concludes the product is broken rather than
        the deployment."""
        _, body = self.refuse()
        self.assertNotIn("a page left open", body)

    def test_it_says_what_to_do_about_it(self):
        _, body = self.refuse()
        self.assertIn("SESSION_COOKIE_SECURE=false", body)
        self.assertIn("TLS", body)

    def test_a_stale_token_with_a_cookie_keeps_the_ordinary_wording(self):
        """The other branch, and the one that was right all along. A
        session that ended still sends its cookie, so this reader SHOULD
        reload."""
        _, body = self.refuse(secure=False, with_cookie=True)
        self.assertIn("a page left open", body)
        self.assertNotIn("No cookie arrived", body)

    def test_a_cookie_that_did_arrive_is_never_blamed_on_the_scheme(self):
        """Over https, with the Secure flag on and a cookie in hand, a bad
        token is the ordinary stale-session case.

        The class above tests the other three corners and a mutation lived
        through all of them: dropping `not request.cookies` and keeping only
        `SESSION_COOKIE_SECURE` agrees everywhere the flag is off, which is
        everywhere else this file looks.
        """
        app = _app(secure=True)
        client = app.test_client()
        client.get("/auth/login", base_url="https://wdash.test")
        answer = client.post("/auth/login",
                             data={"username": "admin", "password": "x",
                                   "csrf_token": "not-the-one"},
                             base_url="https://wdash.test")
        body = answer.get_data(as_text=True)
        self.assertEqual(answer.status_code, 400)
        self.assertIn("a page left open", body)
        self.assertNotIn("No cookie arrived", body)

    def test_a_cookieless_post_without_the_secure_flag_does_not_blame_it(self):
        """Cookies blocked in the browser produces no cookie either, and on
        an installation that does not mark the cookie `Secure` that
        explanation would be a guess dressed as a finding."""
        _, body = self.refuse(secure=False, with_cookie=False)
        self.assertNotIn("No cookie arrived", body)


class WhenWeCanTellItWasPlainHttpTest(unittest.TestCase):
    """The question is "can we POSITIVELY tell", not "did it arrive
    securely", and the polarity is the design.

    Asked the other way, a proxy that terminates TLS and sets no
    `X-Forwarded-Proto` looks insecure, and HSTS silently stops being sent
    to a deployment that is correctly behind TLS. `test_security_headers`
    caught that on the first attempt at this.

    `request.is_secure` is not the question either: behind an ingress that
    terminates TLS, the connection this process accepted is plain http on
    every request, including the ones a browser made over https.
    """

    class _Request:
        def __init__(self, proto=None, secure=False):
            self.is_secure = secure
            self.headers = {} if proto is None else {"X-Forwarded-Proto": proto}

    def test_a_tls_connection_here_settles_it(self):
        self.assertFalse(
            _known_to_be_plain_http(self._Request(secure=True), 0))

    def test_and_it_beats_a_header_that_disagrees(self):
        """Direct evidence over hearsay. This process accepted a TLS
        connection; a forwarded header saying otherwise is describing a hop
        that is not this one.

        Asserted at a depth where the header WOULD be believed, because at
        depth 0 the header is ignored anyway and the early return looks
        redundant — which is how a mutation deleting it survived.
        """
        self.assertFalse(
            _known_to_be_plain_http(self._Request("http", secure=True), 1))

    def test_silence_is_not_evidence(self):
        """No header at all is the case that made the first attempt wrong.
        A proxy that does not set one is not a proxy that spoke http."""
        self.assertFalse(_known_to_be_plain_http(self._Request(), 2))

    def test_with_no_proxy_configured_the_header_is_ignored(self):
        """Depth 0 means nothing is in front of this process, so the header
        is whatever a client typed. Believing it would let anybody turn HSTS
        off for everyone else."""
        self.assertFalse(_known_to_be_plain_http(self._Request("http"), 0))

    def test_behind_a_proxy_a_header_that_says_http_settles_it(self):
        self.assertTrue(_known_to_be_plain_http(self._Request("http"), 1))
        self.assertFalse(_known_to_be_plain_http(self._Request("https"), 1))

    def test_the_nearest_trusted_proxy_is_the_one_that_counts(self):
        """Counted from the RIGHT, like the client address. A client that
        sends `https` to a proxy speaking http produces `https,http`, and
        with one trusted proxy the rightmost is the one that was there."""
        self.assertTrue(_known_to_be_plain_http(self._Request("https,http"), 1))

    def test_and_the_depth_says_how_far_back_the_edge_is(self):
        """Two trusted proxies: the browser spoke to the outermost, whose
        word is second from the right."""
        self.assertFalse(
            _known_to_be_plain_http(self._Request("https,http"), 2))

    def test_a_depth_that_is_nonsense_decides_nothing(self):
        for depth in ("", None, "two", -1):
            with self.subTest(depth=depth):
                self.assertFalse(
                    _known_to_be_plain_http(self._Request("http"), depth))


class WhenHstsIsSentTest(unittest.TestCase):
    """Never over http, whatever the configuration says.

    RFC 6797 tells a browser to ignore an STS header on insecure transport,
    so this was most likely inert — and "most likely inert" is not the
    standard for a header carrying a year and `includeSubDomains`.

    This class is also the first thing in the suite to run with
    `SESSION_COOKIE_SECURE` on. The branch it covers had never executed, and
    a `NameError` in it passed 4,300 tests.
    """

    def header(self, secure=True, proto=None, proxies=2):
        client = _app(secure=secure, proxies=proxies).test_client()
        headers = {} if proto is None else {"X-Forwarded-Proto": proto}
        answer = client.get("/auth/login", base_url="http://wdash.test",
                            headers=headers)
        return answer.headers.get("Strict-Transport-Security")

    def test_not_where_a_trusted_proxy_says_it_was_http(self):
        """The reported deployment: an ingress with no usable certificate,
        forwarding plain http and saying so."""
        self.assertIsNone(self.header(proto="http"))

    def test_but_yes_behind_a_proxy_that_terminated_tls(self):
        self.assertIn("max-age", self.header(proto="https") or "")

    def test_and_yes_where_the_proxy_says_nothing_at_all(self):
        """Silence is not evidence, and this is the case that makes the
        polarity matter. A proxy that terminates TLS and sets no
        `X-Forwarded-Proto` is real and common; reading its silence as
        `http` would take HSTS away from a deployment that has it right.
        `tests/test_security_headers.py` asserts the same thing from the
        other side, which is how the first attempt at this was caught."""
        self.assertIn("max-age", self.header(proto=None) or "")

    def test_and_never_where_the_deployment_says_it_is_not_behind_tls(self):
        self.assertIsNone(self.header(secure=False, proto="https"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
