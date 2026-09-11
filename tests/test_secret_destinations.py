"""
A stored secret goes where it was stored for.

The configuration page never shows a password, and until this it did not
need to: a blank password box means "keep the stored one", so whoever held
an administrator session could point the stored password somewhere else and
have the server send it there. Measured through the routes, with a listener
standing in for the somewhere else:

  * the connection test took any URL with a saved source's id, and the
    listener received `Authorization: Basic eDpTM2NyZXRQVw==` — `x:S3cretPW`
    — with nothing written to the audit trail;
  * saving the source with the listener's URL kept the password, for the
    next query to send;
  * the same for the LDAP server and its bind password, and for a monitor's
    target and its sealed X-Api-Key.

Rule 4 in store/secrets.py; `may_follow` decides.
"""

import base64
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.test_config_page import ConfigTestCase  # noqa: E402
from wdash.store.secrets import destination, may_follow  # noqa: E402


class MayFollowTest(unittest.TestCase):
    def test_the_same_server_by_another_path(self):
        self.assertTrue(may_follow("http://es:9200", "http://es:9200/prefix"))
        self.assertTrue(may_follow("http://ES:9200/", "http://es:9200"))

    def test_a_default_port_is_the_same_port(self):
        self.assertTrue(may_follow("https://es/", "https://es:443/"))
        self.assertEqual(destination("ldap://dir"), ("ldap", "dir", 389))

    def test_encryption_turned_on_on_the_same_host(self):
        self.assertTrue(may_follow("http://es:9200", "https://es:9200"))
        self.assertTrue(may_follow("http://es", "https://es"))
        self.assertTrue(may_follow("ldap://dir", "ldaps://dir"))

    def test_anything_else_is_somewhere_else(self):
        for new in ("http://evil:9200", "http://es:9201", "https://es:8443",
                    "http://es.evil.example:9200", ""):
            with self.subTest(new=new):
                self.assertFalse(may_follow("http://es:9200", new))

    def test_encryption_turned_off_is_somewhere_else(self):
        """The secret would cross the network in the clear."""
        self.assertFalse(may_follow("https://es", "http://es"))
        self.assertFalse(may_follow("ldaps://dir", "ldap://dir"))

    def test_an_upgrade_onto_another_port_is_not_the_same_server(self):
        self.assertFalse(may_follow("http://es", "https://es:9200"))


class _Listener:
    """Somewhere else, and what it was sent."""

    def __init__(self):
        self.received = []
        received = self.received

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get("Authorization"))
                body = json.dumps({"version": {"number": "8.15.0"},
                                   "cluster_name": "x"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class DestinationTestCase(ConfigTestCase):
    SECRET = "S3cretPW"

    def setUp(self):
        super().setUp()
        self.listener = _Listener()

    def tearDown(self):
        self.listener.stop()
        super().tearDown()

    def stored(self, url="http://elasticsearch.internal:9200", verify=True):
        return self.app.store.sources.create(
            "primary", "logs", "elasticsearch",
            {"url": url, "username": "wdash", "verify_certs": verify},
            secret=self.SECRET)

    def audited(self, action):
        return [row for row in self.app.store.audit.recent()
                if row["action"] == action]

    def sent_the_secret(self):
        return any(self.SECRET in base64.b64decode(value.split()[1]).decode()
                   for value in self.listener.received if value)


class ConnectionTestTest(DestinationTestCase):
    def probe(self, source, **payload):
        body = {"id": source["id"], "kind": "elasticsearch", "username": "x",
                "verify_certs": True, **payload}
        return self.client.post("/admin/api/sources/test", json=body).get_json()

    def test_a_stored_password_is_not_sent_to_a_url_the_test_names(self):
        reply = self.probe(self.stored(), url=self.listener.url)
        self.assertFalse(self.sent_the_secret(), "the stored password left")
        self.assertEqual(self.listener.received, [],
                         "the listener was asked at all")
        self.assertFalse(reply["ok"])
        self.assertIn("Type the password", reply["message"])
        self.assertIn(f"127.0.0.1:{self.listener.server.server_port}",
                      reply["message"])
        refused = self.audited("source test refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["state"]["target"], self.listener.url)

    def test_it_is_still_used_for_the_connection_it_was_saved_for(self):
        """The reason the stored password is reused at all: testing a saved
        source without retyping it."""
        source = self.stored(url=self.listener.url)
        reply = self.probe(source, url=self.listener.url)
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(self.sent_the_secret())
        tested = self.audited("source tested")
        self.assertEqual(tested[0]["state"]["target"], self.listener.url)
        self.assertTrue(tested[0]["state"]["stored_password"])

    def test_a_test_that_turns_certificate_checks_off_does_not_get_it(self):
        source = self.stored(url="https://elasticsearch.internal:9200")
        reply = self.probe(source, url="https://elasticsearch.internal:9200",
                          verify_certs=False)
        self.assertFalse(reply["ok"])
        self.assertIn("certificate checks off", reply["message"])

    def test_another_type_does_not_get_it(self):
        source = self.stored(url=self.listener.url)
        reply = self.probe(source, url=self.listener.url, kind="loki")
        self.assertFalse(reply["ok"])
        self.assertEqual(self.listener.received, [])

    def test_a_typed_password_goes_where_it_is_typed_for(self):
        """Nothing stored is involved, so there is nothing to refuse — but
        the request is the server's, to a host an administrator named, and
        is written down."""
        reply = self.probe(self.stored(), url=self.listener.url,
                          password="typed-here")
        self.assertTrue(reply["ok"], reply)
        self.assertFalse(self.sent_the_secret())
        tested = self.audited("source tested")
        self.assertEqual(len(tested), 1)
        self.assertFalse(tested[0]["state"]["stored_password"])
        self.assertNotIn("typed-here", json.dumps(tested[0], default=str))


class SourceSaveTest(DestinationTestCase):
    def save(self, source, **overrides):
        form = {"id": source["id"], "name": "primary", "signals": "logs",
                "kind": "elasticsearch", "url": source["config"]["url"],
                "username": "wdash", "password": "", "verify_certs": "on",
                "enabled": "on"}
        form.update(overrides)
        return self.client.post("/admin/sources", data=form,
                                follow_redirects=True)

    def test_a_save_that_repoints_a_stored_password_is_refused(self):
        source = self.stored()
        page = self.save(source, url=self.listener.url)
        self.assertIn(b"only sent where it was saved for", page.data)
        self.assertEqual(self.app.store.sources.get(source["id"])["config"]["url"],
                         "http://elasticsearch.internal:9200")
        self.assertEqual(len(self.audited("source update refused")), 1)

    def test_with_the_password_typed_it_goes_through(self):
        source = self.stored()
        self.save(source, url=self.listener.url, password="new-one")
        saved = self.app.store.sources.get(source["id"])
        self.assertEqual(saved["config"]["url"], self.listener.url)
        self.assertEqual(self.app.store.sources.credential(source["id"]),
                         "new-one")

    def test_a_new_path_or_https_on_the_same_server_keeps_it(self):
        source = self.stored()
        for url in ("http://elasticsearch.internal:9200/es",
                    "https://elasticsearch.internal:9200"):
            with self.subTest(url=url):
                self.save(source, url=url)
                saved = self.app.store.sources.get(source["id"])
                self.assertEqual(saved["config"]["url"], url)
                self.assertTrue(saved["has_secret"])

    def test_turning_certificate_checks_off_needs_it_typed(self):
        source = self.stored(url="https://elasticsearch.internal:9200")
        self.save(source, verify_certs="")
        self.assertTrue(
            self.app.store.sources.get(source["id"])["config"]["verify_certs"])

    def test_a_source_without_a_password_moves_freely(self):
        source = self.app.store.sources.create(
            "open", "logs", "elasticsearch",
            {"url": "http://elasticsearch.internal:9200", "verify_certs": True})
        self.save(source, name="open", url=self.listener.url)
        self.assertEqual(self.app.store.sources.get(source["id"])["config"]["url"],
                         self.listener.url)


class IdentityProviderTest(DestinationTestCase):
    LDAP = {"provider": "ldap", "server": "ldaps://ldap.internal:636",
            "bind_dn": "cn=wdash,dc=corp", "base_dn": "dc=corp",
            "verify_certs": "on"}
    OIDC = {"provider": "oidc", "client_id": "wdash",
            "discovery_url": "https://idp.internal/.well-known/openid-configuration",
            "redirect_uri": "https://wdash/auth/callback", "enabled": "on"}

    def post(self, form, **overrides):
        return self.client.post("/admin/auth", data={**form, **overrides},
                                follow_redirects=True)

    def test_the_directory_cannot_be_repointed_with_the_bind_password_kept(self):
        self.post(self.LDAP, bind_password="B1ndPW")
        page = self.post(self.LDAP, server=f"ldap://127.0.0.1:1",
                         bind_password="")
        self.assertIn(b"stored bind password is only sent", page.data)
        self.assertEqual(self.app.store.settings.get("auth.ldap")["server"],
                         "ldaps://ldap.internal:636")
        self.assertEqual(len(self.audited("LDAP settings refused")), 1)

    def test_nor_have_its_certificate_checks_turned_off(self):
        self.post(self.LDAP, bind_password="B1ndPW")
        self.post(self.LDAP, verify_certs="", bind_password="")
        self.assertTrue(self.app.store.settings.get("auth.ldap")["verify_certs"])

    def test_with_the_bind_password_typed_it_can(self):
        self.post(self.LDAP, bind_password="B1ndPW")
        self.post(self.LDAP, server="ldaps://ldap2.internal:636",
                  bind_password="B1ndPW-2")
        self.assertEqual(self.app.store.settings.get("auth.ldap")["server"],
                         "ldaps://ldap2.internal:636")
        self.assertEqual(self.app.store.settings.secret("auth.ldap"), "B1ndPW-2")

    def test_the_client_secret_stays_with_its_provider(self):
        self.post(self.OIDC, client_secret="oidc-secret")
        self.post(self.OIDC, discovery_url="https://evil.example/.well-known/x",
                  client_secret="")
        self.assertEqual(self.app.store.settings.get("auth.oidc")["discovery_url"],
                         self.OIDC["discovery_url"])

    def test_the_rest_of_the_form_is_saved_as_before(self):
        """Other settings, the secret kept: only the destination is bound."""
        self.post(self.LDAP, bind_password="B1ndPW")
        self.post(self.LDAP, base_dn="dc=corp,dc=example", bind_password="")
        self.assertEqual(self.app.store.settings.get("auth.ldap")["base_dn"],
                         "dc=corp,dc=example")
        self.assertEqual(self.app.store.settings.secret("auth.ldap"), "B1ndPW")


class WhatTheAuditSaysTest(DestinationTestCase):
    """Where a source or a provider pointed, and from when: what somebody
    reconstructing an incident asks. A source update was audited as its name
    and id, and a provider's as whether it was enabled."""

    def test_a_source_update_records_the_state_it_left(self):
        source = self.stored()
        self.client.post("/admin/sources", data={
            "id": source["id"], "name": "primary-es", "signals": "logs",
            "kind": "elasticsearch", "url": "http://elasticsearch.internal:9200/x",
            "username": "reader", "password": "", "verify_certs": "on",
            "enabled": "on"})
        row = self.audited("source updated")[0]
        self.assertEqual(row["subject"], f"source:{source['id']}")
        state = row["state"]
        self.assertEqual(state["name"], "primary-es")
        self.assertEqual(state["previous_name"], "primary")
        self.assertEqual(state["config"]["url"],
                         "http://elasticsearch.internal:9200/x")
        self.assertEqual(state["config"]["username"], "reader")
        self.assertIs(state["has_secret"], True)
        self.assertIs(state["secret_replaced"], False)
        self.assertNotIn(self.SECRET, json.dumps(row, default=str))

    def test_creation_and_deletion_record_it_too(self):
        self.add_source(name="lab", password="lab-password-1")
        source = self.app.store.sources.all()[0]
        self.client.post(f"/admin/sources/{source['id']}/delete")
        for action in ("source created", "source deleted"):
            row = self.audited(action)[0]
            self.assertEqual(row["state"]["config"]["url"],
                             "http://elasticsearch:9200", action)
            self.assertNotIn("lab-password-1", json.dumps(row, default=str))

    def test_a_password_written_into_the_url_is_not(self):
        self.add_source(name="lab", url="http://reader:inline-pass-9@es:9200")
        row = self.audited("source created")[0]
        self.assertNotIn("inline-pass-9", json.dumps(row, default=str))
        self.assertIn("reader:***@es:9200", row["state"]["config"]["url"])

    def test_a_provider_save_records_what_it_trusts(self):
        self.client.post("/admin/auth", data={
            **IdentityProviderTest.OIDC, "client_secret": "oidc-secret-1"})
        row = self.audited("OIDC settings updated")[0]
        self.assertEqual(row["subject"], "auth:oidc")
        self.assertEqual(row["state"]["discovery_url"],
                         IdentityProviderTest.OIDC["discovery_url"])
        self.assertEqual(row["state"]["client_id"], "wdash")
        self.assertIs(row["state"]["secret_replaced"], True)
        self.assertNotIn("oidc-secret-1", json.dumps(row, default=str))


if __name__ == "__main__":
    unittest.main()
