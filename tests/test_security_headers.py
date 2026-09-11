"""
Response headers, and the sign-in hardening that goes with them.

A browser given no instructions makes the permissive choice every time, so the
absence of a header is a decision — just not one anybody made on purpose.
These hold the decisions that WERE made, including the deliberate compromise
in `style-src`, so that loosening any of them has to be done knowingly.
"""

import os
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

PASSWORD = "correct-horse-battery"

#: A page that renders the layout without needing an account. `/auth/login`
#: does not: on a fresh installation every route redirects to first-run setup,
#: so assertions over its body have nothing to assert against.
RENDERS = "/setup"


class HeaderTestCase(unittest.TestCase):
    SECURE = False

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database, secure = self.database, self.SECURE

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "headers"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = SecretBox.generate_key()
            OIDC_CLIENT_ID = None
            SESSION_COOKIE_SECURE = secure

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def headers(self, path="/auth/login"):
        return self.client.get(path).headers

    def policy(self, path="/auth/login"):
        return self.headers(path).get("Content-Security-Policy", "")

    def directive(self, name, path="/auth/login"):
        for part in self.policy(path).split(";"):
            part = part.strip()
            if part.startswith(name + " ") or part == name:
                return part
        return ""


class PolicyTest(HeaderTestCase):
    def test_a_policy_is_sent_at_all(self):
        self.assertTrue(self.policy(), "no Content-Security-Policy")

    def test_scripts_are_nonce_based_and_not_merely_listed(self):
        """A policy with 'unsafe-inline' on script-src lists the same
        directives as this one and stops nothing."""
        script = self.directive("script-src")
        self.assertIn("nonce-", script)
        self.assertNotIn("unsafe-inline", script)
        self.assertNotIn("unsafe-eval", script)

    def test_the_nonce_changes_between_responses(self):
        """A fixed nonce is a password an attacker only has to read once."""
        first = re.search(r"nonce-([\w-]+)", self.policy()).group(1)
        second = re.search(r"nonce-([\w-]+)", self.policy()).group(1)
        self.assertNotEqual(first, second)

    def test_every_script_tag_carries_the_nonce(self):
        """One tag without it is a broken page; one without it that somebody
        then 'fixes' with 'unsafe-inline' is a broken policy."""
        response = self.client.get(RENDERS)
        body = response.get_data(as_text=True)
        nonce = re.search(r"nonce-([\w-]+)",
                          response.headers["Content-Security-Policy"]).group(1)
        tags = re.findall(r"<script[^>]*>", body)
        # Asserted, because this test used to run against `/auth/login`, which
        # redirects to setup on a fresh installation. Zero tags, zero
        # assertions, green.
        self.assertTrue(tags, "no scripts on the page at all")
        for tag in tags:
            self.assertIn(f'nonce="{nonce}"', tag, f"unnonced script: {tag}")

    def test_styles_are_permissive_and_say_so(self):
        """121 style attributes, and a nonce cannot cover an attribute at all.
        The residual risk is defacement rather than script execution, which is
        why this is the compromise to take and script-src is not."""
        self.assertIn("unsafe-inline", self.directive("style-src"))

    def test_framing_is_refused(self):
        self.assertIn("frame-ancestors 'none'", self.policy())
        self.assertEqual(self.headers().get("X-Frame-Options"), "DENY")

    def test_an_injected_base_tag_cannot_redirect_the_page(self):
        """Without this, one HTML injection turns every relative URL on the
        page — including the script sources — into an attacker's."""
        self.assertIn("base-uri 'self'", self.policy())

    def test_the_front_end_can_only_talk_to_this_origin(self):
        self.assertIn("connect-src 'self'", self.policy())
        self.assertIn("form-action 'self'", self.policy())

    def test_plugins_are_refused(self):
        self.assertIn("object-src 'none'", self.policy())


class ThirdPartyAssetTest(HeaderTestCase):
    """A nonce says "this tag is ours". It says nothing about the bytes.

    A compromised or substituted CDN would serve attacker code under a
    perfectly valid nonce. Subresource Integrity is what makes that fail
    closed — and it cannot exist without a pinned version, because an
    unversioned path means "whatever is latest today".
    """

    def _tags(self):
        body = self.client.get(RENDERS).get_data(as_text=True)
        tags = [tag for tag in re.findall(r"<(?:script|link)[^>]*>", body)
                if "https://" in tag]
        self.assertTrue(tags, "no third-party assets found to check")
        return tags

    def test_every_third_party_asset_is_pinned_to_a_version(self):
        for tag in self._tags():
            url = re.search(r'(?:src|href)="(https://[^"]+)"', tag).group(1)
            self.assertRegex(
                url, r"@\d+\.\d+|/\d+\.\d+\.\d+/",
                f"unpinned, so its content can change under us: {url}")

    def test_every_third_party_asset_carries_an_integrity_hash(self):
        for tag in self._tags():
            self.assertIn("integrity=", tag, f"unhashed asset: {tag[:90]}")

    def test_the_integrity_check_can_actually_run(self):
        """Without `crossorigin`, the browser skips the check silently — the
        attribute is present, the page loads, and nothing is verified."""
        for tag in self._tags():
            self.assertIn("crossorigin=", tag, f"unchecked asset: {tag[:90]}")

    def test_every_allowed_origin_is_one_that_is_used(self):
        """A source list longer than the assets is a hole nobody notices."""
        from wdash.security import SCRIPT_SOURCES
        used = {re.match(r"https://[^/]+",
                         re.search(r'src="(https://[^"]+)"', tag).group(1)).group(0)
                for tag in self._tags() if "src=" in tag}
        self.assertEqual(set(SCRIPT_SOURCES) - used, set())


class OtherHeaderTest(HeaderTestCase):
    def test_content_type_sniffing_is_off(self):
        self.assertEqual(self.headers().get("X-Content-Type-Options"),
                         "nosniff")

    def test_full_urls_do_not_travel_to_other_origins(self):
        """A log query can hold a customer identifier or a pasted token."""
        self.assertEqual(self.headers().get("Referrer-Policy"),
                         "strict-origin-when-cross-origin")

    def test_unused_capabilities_are_refused(self):
        policy = self.headers().get("Permissions-Policy", "")
        for capability in ("geolocation", "camera", "microphone"):
            self.assertIn(f"{capability}=()", policy)

    def test_hsts_is_not_sent_over_plain_http(self):
        """Sent by an installation not on TLS, it locks that installation out
        of its own hostname for a year."""
        self.assertIsNone(self.headers().get("Strict-Transport-Security"))

    def test_errors_and_redirects_carry_the_headers_too(self):
        response = self.client.get("/logs")          # redirects to sign-in
        self.assertEqual(response.status_code, 302)
        self.assertIn("Content-Security-Policy", response.headers)


class SecureDeploymentTest(HeaderTestCase):
    SECURE = True

    def test_hsts_is_sent_when_the_deployment_says_it_is_on_tls(self):
        header = self.headers().get("Strict-Transport-Security", "")
        self.assertIn("max-age=", header)
        self.assertIn("includeSubDomains", header)


class SessionTest(HeaderTestCase):
    def test_signing_in_drops_everything_the_session_held_before(self):
        """Anything planted before sign-in — a stale `user_data`, a key some
        future code decides to trust — must not survive into an authenticated
        session."""
        with self.client.session_transaction() as session:
            session["planted"] = "from before sign-in"

        self.client.post("/setup", data={"username": "owner",
                                         "password": PASSWORD,
                                         "confirm": PASSWORD})
        with self.client.session_transaction() as session:
            self.assertIn("user_data", session, "setup did not sign anybody in")
            self.assertNotIn("planted", session)

    def test_the_session_cookie_is_not_readable_from_script(self):
        response = self.client.post("/auth/login",
                                    data={"username": "x", "password": "y"})
        cookie = response.headers.get("Set-Cookie", "")
        if cookie:
            self.assertIn("HttpOnly", cookie)
            self.assertIn("SameSite=Lax", cookie)


class OidcCallbackTest(HeaderTestCase):
    """The callback is reachable without signing in."""

    def setUp(self):
        super().setUp()
        # Otherwise every route redirects to first-run setup and the callback
        # is never reached.
        self.client.post("/setup", data={"username": "owner",
                                         "password": PASSWORD,
                                         "confirm": PASSWORD})
        self.client.get("/auth/logout")
        self.app.store.settings.set("auth.oidc", {
            "enabled": True, "client_id": "wdash",
            "discovery_url": "https://idp.example/.well-known/openid-configuration",
            "redirect_uri": "http://localhost/auth/callback"})

    def test_a_callback_that_did_not_start_here_is_refused(self):
        """No nonce in the session means no sign-in was begun in this browser
        — a stray link, a replayed URL, or a forged one.

        Asserted on the token exchange rather than on the redirect: without
        the check the exchange fails anyway and lands on the same page, so the
        destination cannot tell the two apart. Whether the code was ever
        presented to the provider can.
        """
        client = mock.MagicMock()
        with mock.patch("wdash.auth.auth.init_oauth",
                        return_value=(mock.MagicMock(), client)):
            response = self.client.get("/auth/callback?code=whatever&state=x",
                                       follow_redirects=False)
        client.authorize_access_token.assert_not_called()
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_the_sign_in_redirect_carries_a_nonce(self):
        """The session half is useless on its own: Authlib only generates and
        validates a nonce when it is handed one, so a nonce kept locally and
        never sent binds nothing."""
        client = mock.MagicMock()
        with mock.patch("wdash.auth.auth.init_oauth",
                        return_value=(mock.MagicMock(), client)):
            self.client.get("/auth/oidc")

        client.authorize_redirect.assert_called_once()
        sent = client.authorize_redirect.call_args.kwargs.get("nonce")
        self.assertTrue(sent, "no nonce reached the provider")

        with self.client.session_transaction() as session:
            self.assertEqual(session.get("oidc_nonce"), sent,
                             "the nonce sent is not the one that will be checked")

    def test_a_failure_does_not_put_the_detail_on_the_page(self):
        """An exception raised while exchanging a code carries request URLs
        and provider responses, and this page needs no sign-in."""
        with self.client.session_transaction() as session:
            session["oidc_nonce"] = "n-once"
        body = self.client.get("/auth/callback?code=whatever&state=x",
                               follow_redirects=True).get_data(as_text=True)
        self.assertIn("Sign-in failed", body)
        self.assertNotIn("idp.example", body)
        self.assertNotIn("Traceback", body)

    def test_the_nonce_is_used_once(self):
        with self.client.session_transaction() as session:
            session["oidc_nonce"] = "n-once"
        self.client.get("/auth/callback?code=whatever&state=x")
        with self.client.session_transaction() as session:
            self.assertNotIn("oidc_nonce", session,
                             "a nonce that outlives its use is not a nonce")


class PublishedSessionKeyTest(unittest.TestCase):
    """A session key printed in this repository signs a cookie anybody can
    forge, the administrator's included.

    The refusal knew one printed key, the development fallback. The quick
    start copies `.env.example` into `.env`, and `.env.example` carried a
    different one, so a TLS deployment built from the README signed its
    administrator's cookie with a published string and started without a
    word. Measured before the fix: with that `.env` and
    SESSION_COOKIE_SECURE=true, create_app started, and a cookie signed with
    the published key from outside the process opened /admin/config.
    """

    ROOT = os.path.join(os.path.dirname(__file__), "..")

    def _starts_under_tls(self, environment):
        """Whether create_app starts, measured in a clean interpreter:
        `Config` is computed from the environment at import, so the chain
        from a file to the refusal can only be observed from a fresh one."""
        import subprocess

        source = (
            "import os, sys, json;"
            "os.environ.update(json.loads(sys.argv[1]));"
            "sys.path.insert(0, 'src');"
            "from wdash.app import create_app\n"
            "try:\n"
            "    create_app()\n"
            "except RuntimeError as exc:\n"
            "    print('refused' if 'SECRET_KEY' in str(exc) else exc)\n"
            "else:\n"
            "    print('started')")
        import json
        environment = dict(environment,
                           SESSION_COOKIE_SECURE="true",
                           DATABASE_URL="sqlite:///:memory:",
                           ELASTICSEARCH_URL="",
                           WDASH_NO_DOTENV="1")
        result = subprocess.run(
            [sys.executable, "-c", source, json.dumps(environment)],
            cwd=self.ROOT, capture_output=True, text=True)
        verdict = result.stdout.strip().splitlines()[-1:] or [result.stderr]
        return verdict[0]

    def test_the_example_environment_ships_no_key(self):
        """A value here is a value everybody has read. Empty lands on the
        development key, which says so on a laptop and refuses under TLS."""
        from dotenv import dotenv_values

        values = dotenv_values(os.path.join(self.ROOT, ".env.example"))
        self.assertIn("SECRET_KEY", values,
                      "the example should still show where the key goes")
        self.assertFalse(values["SECRET_KEY"],
                         f".env.example ships SECRET_KEY="
                         f"{values['SECRET_KEY']!r}")

    def test_what_the_quick_start_produces_cannot_serve_tls(self):
        """The whole chain, as an operator following the README meets it:
        `.env.example` read as a dotenv file, `Config` computed from it, and
        create_app asked to start behind TLS."""
        from dotenv import dotenv_values

        values = {key: value for key, value in dotenv_values(
            os.path.join(self.ROOT, ".env.example")).items()
            if value is not None}
        self.assertEqual(self._starts_under_tls(values), "refused")

    def test_an_env_copied_before_the_fix_still_cannot_serve_tls(self):
        """Emptying the example changes nothing for the `.env` files already
        copied from it: they carry the old literal until somebody edits them.
        So does a Kubernetes Secret filled from the old manifest."""
        for published in ("your-secret-key-here-change-in-production",
                          "your-super-secret-key-change-in-production",
                          "dev-secret-key-change-in-production"):
            with self.subTest(key=published):
                self.assertEqual(
                    self._starts_under_tls({"SECRET_KEY": published}),
                    "refused")

    def test_a_real_key_still_starts(self):
        """The refusal is about printed keys, not about TLS: without this the
        tests above pass on a check that refuses everything."""
        import secrets

        self.assertEqual(
            self._starts_under_tls({"SECRET_KEY": secrets.token_urlsafe(48)}),
            "started")


if __name__ == "__main__":
    unittest.main()


class DevelopmentServerTest(unittest.TestCase):
    """Which interface `python main.py` listens on.

    `debug=True` turns on the Werkzeug debugger, and its traceback page offers
    an interactive Python console. Bound to 0.0.0.0 that is a shell published
    to whatever network the machine is on — a laptop on conference wifi, a
    VM with a public address, a container with a mapped port. The PIN slows
    it down; it is not a boundary.

    Read as text rather than executed, because running it would start a
    server. What matters is the default in the source somebody copies.
    """

    ROOT = os.path.join(os.path.dirname(__file__), "..")

    def _source(self, name):
        with open(os.path.join(self.ROOT, name)) as handle:
            return handle.read()

    def test_neither_entry_point_binds_every_interface_by_default(self):
        for name in ("main.py", "src/wdash/app.py"):
            source = self._source(name)
            self.assertNotIn("host='0.0.0.0'", source, name)
            self.assertNotIn('host="0.0.0.0"', source, name)

    def test_the_default_is_loopback(self):
        for name in ("main.py", "src/wdash/app.py"):
            self.assertIn("'127.0.0.1'", self._source(name), name)

    def test_it_can_still_be_opened_up_on_purpose(self):
        """A default nobody can override is a default people edit out."""
        for name in ("main.py", "src/wdash/app.py"):
            self.assertIn("WDASH_DEV_HOST", self._source(name), name)

    def test_the_container_still_serves_every_interface(self):
        """gunicorn binds 0.0.0.0 in the Dockerfile, and must: a container
        that only listens on loopback publishes nothing."""
        self.assertIn("0.0.0.0:5000", self._source("Dockerfile"))
