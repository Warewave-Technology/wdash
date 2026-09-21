"""
The configuration screen.

Possible only because authorization moved out of the session cookie: a page
that edits roles while permissions are frozen at sign-in shows a revocation
that has not happened, which is worse than having no such page.

What these tests hold:

  * `system:admin` on every route, including the ones that only read
  * secrets are written and never rendered — a settings page that shows stored
    credentials is an exfiltration endpoint for anyone with an admin session
  * a blank credential field means "keep", not "delete"
  * a role change reaches an already-signed-in session
  * the URL a source points at is checked before the server will fetch it
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store import SecretBox  # noqa: E402
from wdash.store.sources import SourceError, validate_url  # noqa: E402

PASSWORD = "a-sufficiently-long-password"


class ConfigTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)

        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "config-page"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        support.set_up(self.client, username="owner", password=PASSWORD)
    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def demote(self):
        """Take system:admin away from the signed-in account."""
        self.app.store.roles.upsert(
            "admin", permissions=["logs:read"], containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()

    def add_source(self, **overrides):
        form = {"name": "lab", "signal": "logs", "kind": "elasticsearch",
                "url": "http://elasticsearch:9200", "verify_certs": "on",
                "enabled": "on"}
        form.update(overrides)
        return self.client.post("/admin/sources", data=form,
                                follow_redirects=True)


class AccessTest(ConfigTestCase):
    def test_the_page_needs_the_admin_permission(self):
        self.demote()
        response = self.client.get("/admin/config")
        self.assertEqual(response.status_code, 302)

    def test_every_write_route_needs_it_too(self):
        """A page guard is not a route guard."""
        self.demote()
        for path in ("/admin/sources", "/admin/auth", "/admin/roles",
                     "/admin/mappings"):
            response = self.client.post(path, data={})
            self.assertEqual(response.status_code, 302, path)

    def test_the_json_route_answers_403_rather_than_redirecting(self):
        self.demote()
        response = self.client.post("/admin/api/sources/test", json={})
        self.assertEqual(response.status_code, 403)

    def test_an_administrator_gets_the_page(self):
        response = self.client.get("/admin/config")
        self.assertEqual(response.status_code, 200)
        for section in (b"Sources", b"Authentication", b"Roles"):
            self.assertIn(section, response.data)


class SourceTest(ConfigTestCase):
    def rename(self, source, to):
        return self.client.post("/admin/sources", data={
            "id": source["id"], "name": to, "signal": "logs",
            "kind": "elasticsearch", "url": "http://elasticsearch:9200",
            "password": "", "verify_certs": "on", "enabled": "on"},
            follow_redirects=True)

    def test_a_rename_a_role_depends_on_is_refused(self):
        """Role patterns name sources, compared by exact name. Renaming
        `lab-es` made `-lab-es:secret-*` stop excluding — a role of `*` read
        `secret-*` the moment the page saved — with no preview and nothing
        in the audit row but the new name."""
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "readers", permissions=["logs:read"],
            containers=["*", "-lab-es:secret-*"], trace_containers=[])
        source = self.app.store.sources.all()[0]

        response = self.rename(source, "lab-es-2")
        # The roles table lists "readers" whatever happens; the refusal is
        # what has to say it, or the admin sees the old name and no reason.
        self.assertIn(b"would change what these roles reach: readers",
                      response.data)
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "source rename refused"]
        self.assertEqual(refused[0]["state"]["roles"], ["readers"])

    def test_a_trace_store_pattern_counts_too(self):
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=["lab-es:otel-*"])
        source = self.app.store.sources.all()[0]
        self.rename(source, "lab-es-2")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_rename_to_a_name_a_role_already_names_is_refused(self):
        """`staging:*`, left from a deleted source or written ahead of one,
        reaches nothing until a source is called `staging`. The guard asked
        only about the OLD name, so renaming a source to `staging` handed
        the role every index in it."""
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "contractor", permissions=["logs:read"],
            containers=["staging:*"], trace_containers=[])
        self.rename(self.app.store.sources.all()[0], "staging")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_blank_name_is_not_a_way_around_the_guard(self):
        """A name of spaces passes the input's `required`, stripped to "",
        skipped the guard, and was stored: a source called "" matches no
        rule, so `-lab-es:secret-*` stopped excluding."""
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "readers", permissions=["logs:read"],
            containers=["*", "-lab-es:secret-*"], trace_containers=[])
        self.rename(self.app.store.sources.all()[0], "   ")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_blank_name_is_refused_even_when_no_role_names_the_source(self):
        self.add_source(name="lab-es")
        response = self.rename(self.app.store.sources.all()[0], "   ")
        self.assertIn(b"A name is required", response.data)
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_rename_onto_another_source_s_name_is_refused_not_a_crash(self):
        """Create checked for a duplicate name; update did not, and the
        database's refusal came out as a server error."""
        self.add_source(name="lab-es")
        self.add_source(name="lab-es-2")
        first = next(s for s in self.app.store.sources.all()
                     if s["name"] == "lab-es")
        response = self.rename(first, "lab-es-2")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already exists", response.data)

    def test_a_source_name_cannot_hold_a_colon(self):
        """In a rule the colon separates a source's name from its pattern,
        so a source called `eu:prod` could not be named by one:
        `-eu:prod:secret-*` read as a rule for a source called `eu`."""
        response = self.add_source(name="eu:prod")
        self.assertIn(b"cannot contain", response.data)
        self.assertEqual(self.app.store.sources.all(), [])

    def test_nor_can_a_renamed_one(self):
        self.add_source(name="lab-es")
        response = self.rename(self.app.store.sources.all()[0], "eu:prod")
        self.assertIn(b"cannot contain", response.data)
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def test_a_source_cannot_be_created_under_a_name_rules_already_use(self):
        """A colon qualifies a rule only when a source has that name, so
        `staging:*` is a plain name today. Creating a source called
        `staging` would make it a grant of everything in it."""
        self.app.store.roles.upsert(
            "contractor", permissions=["logs:read"],
            containers=["staging:*"], trace_containers=[])
        response = self.add_source(name="staging")
        self.assertIn(b"would turn them from names into rules", response.data)
        self.assertEqual(self.app.store.sources.all(), [])
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "source creation refused"]
        self.assertEqual(refused[0]["state"]["roles"], ["contractor"])

    def test_a_service_rule_counts_for_that_too(self):
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=["*"], services=["*", "-staging:payments"])
        self.add_source(name="staging")
        self.assertEqual(self.app.store.sources.all(), [])

    def test_a_rename_nothing_depends_on_goes_through(self):
        self.add_source(name="lab-es")
        source = self.app.store.sources.all()[0]
        self.rename(source, "lab-es-2")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es-2"])

    def test_a_service_rule_naming_the_source_counts_too(self):
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=["*"], services=["*", "-lab-es:payments"])
        self.rename(self.app.store.sources.all()[0], "lab-es-2")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es"])

    def _tempo(self, role_stores):
        self.add_source(name="lab-tempo", kind="tempo", signal="traces",
                        url="http://tempo:3200")
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=role_stores)
        source = self.app.store.sources.all()[0]
        self.client.post("/admin/sources", data={
            "id": source["id"], "name": "tempo-2", "signal": "traces",
            "kind": "tempo", "url": "http://tempo:3200", "password": "",
            "verify_certs": "on", "enabled": "on"}, follow_redirects=True)
        return [s["name"] for s in self.app.store.sources.all()]

    def test_a_tempo_store_excluded_by_name_cannot_be_renamed_open(self):
        """Tempo's one trace store is matched by the source's name, so
        `-lab-tempo` beside `*` stops excluding under any other name."""
        self.assertEqual(self._tempo(["*", "-lab-tempo"]), ["lab-tempo"])

    def test_a_tempo_store_granted_by_name_cannot_be_renamed_shut(self):
        self.assertEqual(self._tempo(["lab-tempo"]), ["lab-tempo"])

    def test_a_tempo_rename_the_patterns_do_not_notice_goes_through(self):
        self.assertEqual(self._tempo(["*", "-otel-*"]), ["tempo-2"])

    def test_an_elasticsearch_source_name_is_not_a_trace_store(self):
        """Its trace stores are indices; a pattern that happens to spell the
        source's name says nothing about it."""
        self.add_source(name="lab-es")
        self.app.store.roles.upsert(
            "tracers", permissions=["traces:read"], containers=[],
            trace_containers=["*", "-lab-es"])
        self.rename(self.app.store.sources.all()[0], "lab-es-2")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["lab-es-2"])

    def test_a_source_can_be_added(self):
        self.add_source(name="lab-es")
        names = [s["name"] for s in self.app.store.sources.all()]
        self.assertEqual(names, ["lab-es"])

    def test_the_password_is_stored_encrypted_and_never_rendered(self):
        self.add_source(name="lab-es", password="super-secret")
        page = self.client.get("/admin/config").data

        self.assertNotIn(b"super-secret", page,
                         "the stored credential was rendered into the page")
        source = self.app.store.sources.all()[0]
        self.assertTrue(source["has_secret"])
        self.assertNotIn("password", source)
        self.assertEqual(
            self.app.store.sources.credential(source["id"]), "super-secret")

    def test_a_blank_password_keeps_the_stored_one(self):
        """Blank means 'leave it alone'. Treating it as deletion means anyone
        who saves this form without retyping the password breaks the source."""
        self.add_source(name="lab-es", password="super-secret")
        source = self.app.store.sources.all()[0]

        self.client.post("/admin/sources", data={
            "id": source["id"], "name": "renamed", "signal": "logs",
            "kind": "elasticsearch", "url": "http://elasticsearch:9200",
            "password": "", "verify_certs": "on", "enabled": "on"},
            follow_redirects=True)

        self.assertEqual(
            self.app.store.sources.credential(source["id"]), "super-secret")
        self.assertEqual(self.app.store.sources.all()[0]["name"], "renamed")

    def test_the_metadata_address_is_refused(self):
        """169.254.169.254 hands out instance credentials to anything asking."""
        response = self.add_source(name="bad", url="http://169.254.169.254/")
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"link-local", response.data)

    def test_a_non_http_scheme_is_refused(self):
        response = self.add_source(name="bad", url="file:///etc/passwd")
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"http and https", response.data)

    def test_internal_addresses_stay_allowed(self):
        """Blocking them would make the feature useless: these backends are
        on internal networks essentially always."""
        for url in ("http://127.0.0.1:9200", "http://10.0.0.5:9200",
                    "http://elasticsearch:9200"):
            self.assertEqual(validate_url(url), url)

    def test_a_source_kind_cannot_serve_a_signal_it_does_not_have(self):
        response = self.add_source(name="bad", kind="loki", signal="traces",
                                   url="http://loki:3100")
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"cannot serve", response.data)

    def test_two_sources_cannot_share_a_name_and_signal(self):
        self.add_source(name="lab")
        response = self.add_source(name="lab")
        self.assertEqual(len(self.app.store.sources.all()), 1)
        self.assertIn(b"already exists", response.data)

    def test_a_source_can_be_deleted(self):
        self.add_source(name="lab")
        source = self.app.store.sources.all()[0]
        self.client.post(f"/admin/sources/{source['id']}/delete",
                         follow_redirects=True)
        self.assertEqual(self.app.store.sources.all(), [])

    def test_the_connection_test_reports_rather_than_raising(self):
        response = self.client.post("/admin/api/sources/test", json={
            "kind": "elasticsearch", "url": "http://127.0.0.1:1",
            "verify_certs": False})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["ok"])

    def test_the_connection_test_refuses_a_bad_url_before_fetching(self):
        response = self.client.post("/admin/api/sources/test", json={
            "kind": "elasticsearch", "url": "file:///etc/passwd"})
        self.assertFalse(response.get_json()["ok"])



class ACredentialNeedsAVerifiedConnectionTest(ConfigTestCase):
    """A source that does not verify must not hold one.

    The rule a check has had since the monitor TLS work, arrived at from the
    other side. Measured before this, on an Elasticsearch at
    https://es.internal:9200 with a stored password: turning `verify_certs`
    off was refused while the box was blank — "the stored password is only
    sent where it was saved for … type the password again to save it" — and
    ACCEPTED when the password was typed again. WDash then sent that
    password on every query to whatever answered for that address.

    Retyping is consent, and consent is not protection. The stored-secret
    rule it borrowed is a different question — may a secret FOLLOW a change
    — and keeps its retype for a change of address.
    """

    def setUp(self):
        super().setUp()
        self.add_source(name="cluster", url="https://es.internal:9200",
                        password="hunter2", verify_certs="on")
        self.source = self.app.store.sources.all()[0]

    def save(self, **overrides):
        form = {"id": self.source["id"], "name": "cluster", "signal": "logs",
                "kind": "elasticsearch", "url": "https://es.internal:9200",
                "enabled": "on"}
        form.update(overrides)
        return self.client.post("/admin/sources", data=form,
                                follow_redirects=True)

    def stored(self):
        return self.app.store.sources.all()[0]

    def test_turning_verification_off_under_a_credential_is_refused(self):
        response = self.save()
        self.assertIn(b"send there on every query", response.data)
        self.assertTrue(self.stored()["config"]["verify_certs"],
                        "the switch was saved anyway")

    def test_retyping_the_password_does_not_buy_it(self):
        """The change. It used to be the way through."""
        response = self.save(password="hunter2")
        self.assertIn(b"send there on every query", response.data)
        self.assertTrue(self.stored()["config"]["verify_certs"])

    def test_a_new_source_cannot_be_created_that_way_either(self):
        """The refusal is about the state the save would leave behind, not
        about editing: a first save can arrive in that state too."""
        response = self.client.post("/admin/sources", data={
            "name": "second", "signal": "logs", "kind": "elasticsearch",
            "url": "https://other.internal:9200", "password": "hunter2",
            "enabled": "on"}, follow_redirects=True)
        self.assertIn(b"send there on every query", response.data)
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["cluster"])

    def test_without_a_credential_it_is_allowed(self):
        """Nothing to leak. A private cluster on a self-signed certificate
        and no password is a deliberate, common configuration, and refusing
        it would be a rule about certificates rather than about secrets."""
        self.save(forget_password="on")          # the credential first
        response = self.save()                   # now verification off
        self.assertNotIn(b"send there on every query", response.data)
        self.assertFalse(self.stored()["config"]["verify_certs"])

    def test_the_remedy_it_names_is_one_that_exists(self):
        """`clear_secret` was in the store and on no form, so "clear the
        credential" would have been advice nobody could take."""
        response = self.save(verify_certs="on", forget_password="on")
        self.assertNotIn(b"send there on every query", response.data)
        self.assertFalse(self.stored()["has_secret"])
        self.assertTrue(self.stored()["config"]["verify_certs"],
                        "forgetting the password changed the switch")

    def test_forgetting_and_turning_it_off_in_one_save_is_allowed(self):
        """Read against the state the save would LEAVE, like the check's own
        rule: one submission can remove the credential and turn verification
        off, and refusing that would refuse the remedy."""
        response = self.save(forget_password="on")
        self.assertNotIn(b"send there on every query", response.data)
        self.assertFalse(self.stored()["has_secret"])
        self.assertFalse(self.stored()["config"]["verify_certs"])

    def test_a_password_typed_beside_the_tick_is_a_replacement(self):
        """Both submitted is somebody replacing it, and throwing away what
        they just typed would be the worse reading."""
        self.save(verify_certs="on", forget_password="on",
                  password="new-password")
        self.assertTrue(self.stored()["has_secret"])
        self.assertEqual(self.app.store.sources.credential(self.source["id"]),
                         "new-password")

    def test_a_plain_http_source_is_not_what_this_rule_is_about(self):
        """`verify_certs` decides nothing without TLS. A Loki at
        http://localhost:3100 has no certificate to check, and refusing a
        password there would be a rule about a box rather than about a
        connection — it would also have refused every save the lab makes.

        What a credential over plain HTTP costs is a separate question, and
        this is deliberately not an answer to it.
        """
        response = self.client.post("/admin/sources", data={
            "name": "loki", "signals": ["logs"], "kind": "loki",
            "url": "http://localhost:3100", "password": "hunter2",
            "enabled": "on"}, follow_redirects=True)
        self.assertNotIn(b"send there on every query", response.data)
        stored = [s for s in self.app.store.sources.all()
                  if s["name"] == "loki"]
        self.assertEqual(len(stored), 1)
        self.assertTrue(stored[0]["has_secret"])

    def test_the_refusal_is_recorded(self):
        self.save(password="hunter2")
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "source save refused"]
        self.assertEqual(len(refused), 1, "the refusal was not recorded")
        self.assertIn("certificate checks off", refused[0]["state"]["reason"])

    def test_a_forgotten_credential_is_recorded_as_forgotten(self):
        self.save(verify_certs="on", forget_password="on")
        updated = [row for row in self.app.store.audit.recent()
                   if row["action"] == "source updated"][0]
        self.assertIs(updated["state"]["secret_forgotten"], True)
        self.assertIs(updated["state"]["has_secret"], False)

    def test_the_tick_is_offered_only_where_there_is_one_to_forget(self):
        """It is in the modal, hidden, and `config.js` reveals it for a
        source that has a password — so what the page ships is the hidden
        row and the script that shows it."""
        page = self.client.get("/admin/config").get_data(as_text=True)
        row = page.split('id="sourceForgetRow"', 1)[1].split(">", 1)[0]
        self.assertIn("d-none", page.split('id="sourceForgetRow"', 1)[0]
                      .rsplit("<div", 1)[1] + row)
        self.assertIn('name="forget_password"', page)


class APasswordInTheAddressTest(ConfigTestCase):
    """`https://reader:secret@es:9200` is a credential stored as an address.

    Measured before this, one save of an Elasticsearch written that way: the
    password sat in clear text in the `config` column while `secrets` stayed
    NULL; /admin/config printed it twice, in the URL cell and inside the edit
    button's `data-source` JSON; and because both protections read
    `has_secret` — false, since nothing was sealed — the source was repointed
    at another host with the password box blank, and saved with certificate
    checks off, neither refused. The same password typed into the password
    box was refused on both counts, which is what makes this a hole in one
    box rather than a policy.
    """

    URL = "https://reader:inline-Zx9-secret@es.internal:9200"

    def test_the_save_is_refused_and_nothing_is_stored(self):
        response = self.add_source(name="bad", url=self.URL)
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"Take the password out of the address", response.data)

    def test_the_refusal_names_the_address_to_use_instead(self):
        """Advice somebody can follow without deleting their own URL."""
        response = self.add_source(name="bad", url=self.URL)
        self.assertIn(b"https://es.internal:9200", response.data)
        self.assertNotIn(b"inline-Zx9-secret", response.data)

    def test_a_token_written_as_a_password_with_no_user_is_refused_too(self):
        """`https://:t0ken@host/` is how a bearer token gets put in a URL."""
        response = self.add_source(name="bad",
                                   url="https://:t0ken-9@es.internal:9200")
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"Take the password out of the address", response.data)

    def test_a_bare_user_in_the_address_is_still_allowed(self):
        """A name is not a secret, and refusing it would make this a rule
        about the `@` character rather than about credentials."""
        self.add_source(name="named", url="https://reader@es.internal:9200")
        self.assertEqual(self.app.store.sources.all()[0]["config"]["url"],
                         "https://reader@es.internal:9200")

    def stored_the_old_way(self):
        """A row as a build before this one would have written it."""
        from sqlalchemy import update

        from wdash.store.schema import sources
        self.add_source(name="legacy", url="https://es.internal:9200")
        row = self.app.store.sources.all()[0]
        with self.app.store.engine.begin() as connection:
            connection.execute(update(sources).where(
                sources.c.id == row["id"]).values(
                    config={**row["config"], "url": self.URL}))
        return row

    def test_a_row_saved_by_an_older_build_is_masked_on_the_page(self):
        """Both copies. The `data-source` JSON is the one an administrator's
        browser hands to anything that can read the DOM."""
        self.stored_the_old_way()
        page = self.client.get("/admin/config").get_data(as_text=True)
        self.assertNotIn("inline-Zx9-secret", page)
        self.assertEqual(page.count("reader:***@es.internal:9200"), 2, page)

    def test_masking_it_cannot_become_the_stored_password(self):
        """The reason masking is safe here: the masked form carries a
        password too, so pressing Save on that row is refused for the same
        reason the real one is. Without this, showing `***` on the page would
        be a way to set the password to `***`."""
        row = self.stored_the_old_way()
        response = self.client.post("/admin/sources", data={
            "id": row["id"], "name": "legacy", "signal": "logs",
            "kind": "elasticsearch", "verify_certs": "on", "enabled": "on",
            "url": "https://reader:***@es.internal:9200"},
            follow_redirects=True)
        self.assertIn(b"Take the password out of the address", response.data)
        self.assertEqual(self.app.store.sources.all()[0]["config"]["url"],
                         self.URL, "the masked value was stored")

    def test_the_rule_the_url_credential_used_to_walk_past(self):
        """`holds_secret` read `has_secret`, and nothing was sealed — so the
        one save this page refuses hardest went through."""
        response = self.add_source(name="bad", url=self.URL, verify_certs="")
        self.assertEqual(self.app.store.sources.all(), [])
        self.assertIn(b"Take the password out of the address", response.data)


class TheLockoutQuestionIsAskedAboutNowTest(ConfigTestCase):
    """The invariants ask what role the asker would land on after a change.

    They were handed `local_role` out of the session cookie, which is
    written at sign-in and never rewritten. `load_user_from_session`
    deliberately stopped trusting it — it re-reads the account, and its
    comment says why — so authorization was fresh and the question "would
    this leave nobody able to administer" was stale. `_actor` reads the
    account now, the same way.
    """

    def signed_in_as(self, role):
        """Change the stored role of the signed-in account, leaving the
        cookie exactly as the sign-in wrote it."""
        self.app.store.users.set_role("owner", role)
        self.app.store.rbac.invalidate()

    def stored_role(self):
        return self.app.store.users.by_username("owner")["role"]

    def test_the_actor_carries_the_stored_role_not_the_cookie(self):
        from wdash.api.config_routes import _actor
        self.app.store.roles.upsert("co-admin", permissions=["system:admin"],
                                    containers=["*"], trace_containers=["*"])
        self.signed_in_as("co-admin")
        with self.client:
            self.client.get("/admin/config")
            self.assertEqual(_actor()["local_role"], "co-admin")

    def test_a_promotion_that_has_already_happened_counts(self):
        """The other direction, and the one that matters: an account
        promoted after signing in IS an administrator, and a change that
        relies on it is safe. The cookie said `viewer`."""
        self.app.store.roles.upsert("co-admin", permissions=["system:admin"],
                                    containers=["*"], trace_containers=["*"])
        self.signed_in_as("co-admin")
        response = self.client.post("/admin/roles/admin/delete",
                                    follow_redirects=True)
        self.assertIsNone(self.app.store.roles.get("admin"),
                          "the delete was refused on a stale picture")
        self.assertEqual(self.stored_role(), "co-admin")

    def test_a_directory_session_still_reads_its_groups(self):
        """`local_role` is a local account's field. A directory principal
        has none, and inventing one would give it a role nobody granted."""
        from wdash.api.config_routes import _actor
        with self.client.session_transaction() as session:
            # Reassigned, not mutated in place: Flask marks the session
            # modified on assignment, and a nested edit is not one.
            session["user_data"] = dict(session["user_data"],
                                        provider="directory",
                                        local_role=None)
        with self.client:
            self.client.get("/admin/config")
            self.assertIsNone(_actor()["local_role"])


class WhatTheConfigurationPageRefusesIsRecordedTest(ConfigTestCase):
    """Every refusal on this page leaves a row. These left none.

    The route's own refusals all audit — `source save refused`, `source
    update refused`, `source rename refused`, `source creation refused`,
    `source test refused`. The VALIDATOR's did not: `save_source` and
    `test_source` each caught `SourceError` and only answered. Measured,
    six refusals through both routes including
    `http://169.254.169.254/latest/meta-data/`: zero new audit rows.
    SECURITY.md calls the trail "an append-only audit trail … recording
    refused changes as well as accepted ones", and the SSRF guard is one of
    the things it is about.
    """

    def audited(self, action):
        return [row for row in self.app.store.audit.recent()
                if row["action"] == action]

    def test_a_refused_connection_test_is_recorded(self):
        response = self.client.post("/admin/api/sources/test", json={
            "kind": "elasticsearch",
            "url": "http://169.254.169.254/latest/meta-data/"})
        self.assertFalse(response.get_json()["ok"])
        rows = self.audited("source test refused")
        self.assertEqual(len(rows), 1)
        self.assertIn("link-local", rows[0]["state"]["reason"])

    def test_a_refused_save_is_recorded(self):
        self.add_source(name="bad", url="file:///etc/passwd")
        rows = self.audited("source save refused")
        self.assertEqual(len(rows), 1)
        self.assertIn("http and https", rows[0]["state"]["reason"])

    def test_a_test_that_runs_is_still_recorded_as_one(self):
        """The refusal row must not replace the ordinary one."""
        self.client.post("/admin/api/sources/test", json={
            "kind": "elasticsearch", "url": "http://127.0.0.1:1",
            "verify_certs": False})
        self.assertEqual(len(self.audited("source tested")), 1)
        self.assertEqual(self.audited("source test refused"), [])


class ATestThatCannotReadTheSecretTest(ConfigTestCase):
    """Testing a saved source whose password will not decrypt.

    It probed WITHOUT the password and reported the far end's answer as a
    success. So one render of this page carried the red "not in use" badge
    and the sentence about a secret that could not be decrypted for a
    source whose Test connection answered ok — two sentences about one row,
    in one response, disagreeing, which is the shape `_not_live` exists to
    prevent. Measured after replacing the key under a running app, as a
    rotated `WDASH_ENCRYPTION_KEY` does.
    """

    def setUp(self):
        super().setUp()
        self.add_source(name="lab", url="http://127.0.0.1:1",
                        username="elastic", password="a-stored-password")
        self.source = self.app.store.sources.all()[0]

    def lose_the_key(self):
        from wdash.store import SecretBox
        self.app.store.secrets._fernet = SecretBox(
            SecretBox.generate_key())._fernet

    def test(self, **overrides):
        body = {"id": self.source["id"], "kind": "elasticsearch",
                "url": "http://127.0.0.1:1", "username": "elastic",
                "verify_certs": True}
        body.update(overrides)
        return self.client.post("/admin/api/sources/test",
                                json=body).get_json()

    def test_it_is_refused_rather_than_probed_anonymously(self):
        self.lose_the_key()
        answer = self.test()
        self.assertFalse(answer["ok"])
        self.assertIn("could not be read", answer["message"])
        self.assertIn("WDASH_ENCRYPTION_KEY", answer["message"])
        # And what to do about it. A refusal that names no remedy sends
        # somebody to the logs to find out what this page already knows —
        # and the remedy it names is one that works, which is the next test.
        self.assertIn("type the password", answer["message"])

    def test_the_refusal_is_recorded(self):
        self.lose_the_key()
        self.test()
        rows = [row for row in self.app.store.audit.recent()
                if row["action"] == "source test refused"]
        self.assertEqual(len(rows), 1)
        self.assertIn("could not be read", rows[0]["state"]["reason"])

    def test_typing_the_password_is_still_a_way_to_test_it(self):
        """The remedy the message names has to exist."""
        self.lose_the_key()
        answer = self.test(password="a-stored-password")
        self.assertIn("ok", answer)
        self.assertNotIn("could not be read", answer.get("message", ""))


class DeleteAsksFirstTest(ConfigTestCase):
    """The listener in config.js asks before a form with `data-confirm` is
    sent. The attribute has to be on the forms the page renders, or the
    listener binds to nothing and Delete deletes on the first click — what
    the inline onsubmit it replaced did, because the policy refuses those."""

    def test_every_delete_form_carries_its_question(self):
        import re
        self.add_source(name="lab-es")
        self.app.store.roles.upsert("auditor", permissions=["logs:read"],
                                    containers=["*"], trace_containers=[])
        page = self.client.get("/admin/config").get_data(as_text=True)
        forms = [tag for tag in re.findall(r"<form[^>]*>", page, re.S)
                 if re.search(r'action="[^"]*/delete"', tag)]
        self.assertGreaterEqual(len(forms), 2, "no delete forms rendered")
        for tag in forms:
            self.assertIn("data-confirm=", tag, tag)
        self.assertTrue(any("Delete lab-es?" in tag for tag in forms))
        self.assertTrue(any("Delete role auditor?" in tag for tag in forms))


class AuthSettingsTest(ConfigTestCase):
    def save_oidc(self, **overrides):
        form = {"provider": "oidc", "client_id": "wdash",
                "discovery_url": "https://idp/.well-known/openid-configuration",
                "redirect_uri": "https://wdash/auth/callback",
                "client_secret": "wdash-client-secret", "enabled": "on"}
        form.update(overrides)
        return self.client.post("/admin/auth", data=form, follow_redirects=True)

    def test_settings_are_stored(self):
        self.save_oidc()
        stored = self.app.store.settings.get("auth.oidc")
        self.assertEqual(stored["client_id"], "wdash")
        self.assertTrue(stored["enabled"])

    def test_the_client_secret_is_never_rendered(self):
        self.save_oidc(client_secret="oidc-client-secret")
        page = self.client.get("/admin/config").data
        self.assertNotIn(b"oidc-client-secret", page)
        self.assertEqual(self.app.store.settings.secret("auth.oidc"),
                         "oidc-client-secret")

    def test_a_blank_secret_keeps_the_stored_one(self):
        self.save_oidc(client_secret="oidc-client-secret")
        self.save_oidc(client_id="renamed", client_secret="")
        self.assertEqual(self.app.store.settings.secret("auth.oidc"),
                         "oidc-client-secret")
        self.assertEqual(self.app.store.settings.get("auth.oidc")["client_id"],
                         "renamed")

    def test_ldap_settings_are_separate_from_oidc(self):
        """One row per key, so saving one cannot clobber the other."""
        self.save_oidc()
        self.client.post("/admin/auth", data={
            "provider": "ldap", "server": "ldaps://ldap:636",
            "base_dn": "dc=example,dc=com"}, follow_redirects=True)

        self.assertEqual(self.app.store.settings.get("auth.oidc")["client_id"],
                         "wdash")
        self.assertEqual(self.app.store.settings.get("auth.ldap")["server"],
                         "ldaps://ldap:636")


class IdentityProviderSettingsTest(AuthSettingsTest):
    def save_ldap(self, **overrides):
        form = {"provider": "ldap", "server": "ldaps://ldap:636",
                "base_dn": "dc=example,dc=com", "enabled": "on",
                "verify_certs": "on"}
        form.update(overrides)
        return self.client.post("/admin/auth", data=form, follow_redirects=True)

    def test_the_claims_and_the_email_rule_are_saved(self):
        self.save_oidc(username_claim="login", groups_claim="realm_access.roles",
                       trust_unverified_email="on")
        stored = self.app.store.settings.get("auth.oidc")
        self.assertEqual(stored["username_claim"], "login")
        self.assertEqual(stored["groups_claim"], "realm_access.roles")
        self.assertTrue(stored["trust_unverified_email"])
        self.save_oidc()
        self.assertFalse(self.app.store.settings.get("auth.oidc")
                         ["trust_unverified_email"])

    def test_a_ca_file_that_cannot_be_read_is_not_saved(self):
        """It was saved without a word, and every ldaps:// sign-in then
        failed as "the directory could not be reached"."""
        import tempfile
        from tests.test_ldap_auth import _certificate
        empty = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        empty.write(b"not a certificate")
        empty.close()
        for path in ("/nonexistent/corp-ca.pem", empty.name):
            with self.subTest(path=path):
                page = self.save_ldap(ca_certs=path).get_data(as_text=True)
                self.assertIn("cannot be used", page)
                self.assertIsNone(self.app.store.settings.get("auth.ldap"))
        good, _ = _certificate(tempfile.mkdtemp())
        self.save_ldap(ca_certs=good)
        self.assertEqual(self.app.store.settings.get("auth.ldap")["ca_certs"], good)

    def test_the_certificate_check_is_on_unless_turned_off(self):
        from wdash.auth.providers import ldap_settings
        # Saved before the switch existed: no key at all.
        self.app.store.settings.set("auth.ldap", {
            "enabled": True, "server": "ldaps://ldap:636", "base_dn": "dc=x"})
        self.assertTrue(ldap_settings(self.app)["verify_certs"])
        page = self.client.get("/admin/config").get_data(as_text=True)
        self.assertRegex(page, r'name="verify_certs"\s+id="ldapVerify"\s+checked')

        self.save_ldap(verify_certs="", ca_certs="/etc/ssl/corp.pem")
        settings = ldap_settings(self.app)
        self.assertFalse(settings["verify_certs"])
        self.assertEqual(settings["ca_certs"], "/etc/ssl/corp.pem")

    def test_a_clear_text_directory_is_pointed_out(self):
        self.save_ldap(server="ldap://ldap:389")
        self.assertIn(b"sends every password in clear text",
                      self.client.get("/admin/config").data)


LDAP_FORM = {"provider": "ldap", "server": "ldaps://ldap:636",
             "base_dn": "dc=example,dc=com", "verify_certs": "on"}
#: A complete card, because switching a provider on takes one. The secret is
#: part of that for OpenID Connect: WDash is a confidential client and the
#: token request carries it, so a card enabled without one is a sign-in that
#: gets as far as the provider and fails there.
OIDC_FORM = {"provider": "oidc", "client_id": "wdash",
             "discovery_url": "https://idp/.well-known/openid-configuration",
             "client_secret": "wdash-client-secret"}



class AProviderNeedsFillingInTest(ConfigTestCase):
    """What a card has to hold before it can be saved, and before it can be
    switched on.

    Measured before the rule, on an empty OpenID Connect card with Enabled
    ticked: HTTP 302, a row of empty strings written, "OIDC settings saved
    and in force now — no restart needed", `directory()` reporting it as the
    directory in force, and LDAP then refused as "a second directory". No
    sign-in was ever offered through it — `_oidc_effective` declined it, out
    of sight, in a log line — so the page said one thing and every visitor
    met another.

    The three rules, in the order the handler applies them: there has to be
    something in the card at all; what is filled in has to be usable; and
    switching it on takes everything a sign-in needs.
    """

    def stored(self, which):
        return self.app.store.settings.get(f"auth.{which}")

    def refusals(self):
        return [row for row in self.app.store.audit.recent()
                if "settings refused" in row["action"]]

    def save(self, **form):
        return self.client.post("/admin/auth", data=form,
                                follow_redirects=True)

    # --- there has to be something in it ---------------------------------

    def test_an_empty_card_is_not_a_saved_provider(self):
        for which in ("oidc", "ldap"):
            with self.subTest(provider=which):
                response = self.save(provider=which)
                self.assertIn(b"There is nothing to save", response.data)
                self.assertIsNone(self.stored(which))

    def test_an_empty_card_cannot_be_switched_on_either(self):
        response = self.save(provider="oidc", enabled="on")
        self.assertIn(b"There is nothing to save", response.data)
        self.assertIsNone(self.stored("oidc"))

    def test_an_existing_card_blanked_and_switched_on_is_refused_by_name(self):
        """The same submission against a provider that is already stored.
        "Nothing to save" would be wrong there — blanking it is how one is
        removed — so what refuses it is the completeness rule, which names
        the fields rather than calling the card empty."""
        self.save(**{**LDAP_FORM, "enabled": "on"})
        response = self.save(provider="ldap", enabled="on")
        self.assertIn(b"a Server and a Base DN", response.data)
        self.assertNotIn(b"There is nothing to save", response.data)
        self.assertEqual(self.stored("ldap")["server"], "ldaps://ldap:636",
                         "nothing was supposed to be saved")

    def test_clearing_a_provider_that_exists_is_still_allowed(self):
        """Blanking the card is how a provider is removed — there is no
        delete button — so "nothing in it" refuses a first save and not a
        later one."""
        self.save(**{**LDAP_FORM, "enabled": "on"})
        self.save(provider="ldap")
        self.assertEqual(self.stored("ldap")["server"], "")

    # --- what is filled in has to be usable ------------------------------

    def test_a_server_with_no_protocol_is_refused_even_as_a_draft(self):
        """ldap3 is handed the string as it stands. Saved, the first person
        to try signing in is where this would have been found."""
        response = self.save(provider="ldap", server="ldap.example.com",
                             base_dn="dc=example,dc=com")
        self.assertIn(b"has to start with ldap:// or ldaps://", response.data)
        self.assertIsNone(self.stored("ldap"))

    def test_a_discovery_url_that_is_not_a_url_is_refused(self):
        response = self.save(provider="oidc", client_id="wdash",
                             discovery_url="file:///etc/passwd")
        self.assertIn(b"Discovery URL cannot be used", response.data)
        self.assertIsNone(self.stored("oidc"))

    def test_a_redirect_uri_that_is_not_a_url_is_refused(self):
        response = self.save(**{**OIDC_FORM, "redirect_uri": "not a url"})
        self.assertIn(b"Redirect URI cannot be used", response.data)
        self.assertIsNone(self.stored("oidc"))

    def test_a_usable_address_is_saved(self):
        self.save(**{**LDAP_FORM, "enabled": "on"})
        self.assertEqual(self.stored("ldap")["server"], "ldaps://ldap:636")

    # --- switching it on takes everything a sign-in needs -----------------

    def test_enabling_without_a_client_secret_is_refused(self):
        """WDash is a confidential client: the token request carries it.
        Enabled without one, the sign-in gets as far as the provider and
        fails there, which reads as the provider's fault."""
        response = self.save(provider="oidc", client_id="wdash",
                             discovery_url="https://idp/.well-known/x",
                             enabled="on")
        self.assertIn(b"a Client secret", response.data)
        self.assertIsNone(self.stored("oidc"))

    def test_the_refusal_names_every_field_that_is_blank(self):
        response = self.save(provider="oidc", redirect_uri="https://w/cb",
                             enabled="on").get_data(as_text=True)
        self.assertIn("a Client ID, a Discovery URL and a Client secret",
                      response)

    def test_enabling_ldap_without_a_server_is_refused(self):
        response = self.save(provider="ldap", base_dn="dc=example,dc=com",
                             enabled="on")
        self.assertIn(b"a Server", response.data)
        self.assertIsNone(self.stored("ldap"))

    def test_a_bind_dn_with_no_password_is_refused(self):
        """A DN with no password binds anonymously under a name, and the
        directory reports that as "the service account could not bind" —
        two screens from the box that is empty."""
        response = self.save(**{**LDAP_FORM, "bind_dn": "cn=admin,dc=x",
                                "enabled": "on"})
        self.assertIn(b"a Bind password", response.data)
        self.assertIsNone(self.stored("ldap"))

    def test_no_bind_dn_needs_no_password(self):
        """An anonymous search is a real configuration, and ldap_auth.py
        supports it: `bind_dn` is read with `or None`."""
        self.save(**{**LDAP_FORM, "enabled": "on"})
        self.assertTrue(self.stored("ldap")["enabled"])

    def test_a_draft_may_be_half_filled_as_long_as_it_is_off(self):
        """Somebody filling a card in over two visits. Nothing is signing
        anybody in, so nothing is broken."""
        self.save(provider="oidc", client_id="wdash")
        self.assertEqual(self.stored("oidc")["client_id"], "wdash")
        self.assertFalse(self.stored("oidc")["enabled"])

    def test_a_secret_already_stored_counts_as_filled_in(self):
        """The box is blank on every visit after the first, because a sealed
        secret is replaced rather than shown. Requiring the BOX would refuse
        every later save of a card that is complete."""
        self.save(**{**OIDC_FORM, "enabled": "on"})
        response = self.save(**{**OIDC_FORM, "client_secret": "",
                                "client_id": "renamed", "enabled": "on"})
        self.assertIn(b"saved and in force", response.data)
        self.assertEqual(self.stored("oidc")["client_id"], "renamed")

    # --- and the form says so before anybody submits it -------------------

    def card(self, which):
        """One provider's form, as the page renders it."""
        page = self.client.get("/admin/config").get_data(as_text=True)
        after = page.split(f'name="provider" value="{which}"', 1)[1]
        return after.split("</form>", 1)[0]

    def test_the_card_marks_every_field_enabling_needs(self):
        """The browser's half of the rule, held to the server's list. A field
        the form does not mark is one somebody fills the card in around,
        submits, and is sent back to."""
        from wdash.auth.providers import REQUIRED

        for which in ("oidc", "ldap"):
            card = self.card(which)
            for field, _ in REQUIRED[which]:
                with self.subTest(provider=which, field=field):
                    box = card.split(f'name="{field}"', 1)[1].split(">", 1)[0]
                    self.assertIn("data-needed-to-enable", box,
                                  f"{which}.{field} is required to enable and "
                                  f"the form does not say so")

    def test_the_secret_is_marked_only_while_there_is_none_stored(self):
        """It is blank on every visit after the first, because a sealed
        secret is replaced rather than shown — so a form that went on asking
        for it would refuse every later save of a complete card."""
        card = self.card("oidc")
        box = card.split('name="client_secret"', 1)[1].split(">", 1)[0]
        self.assertIn("data-needed-to-enable", box)

        self.save(**{**OIDC_FORM, "enabled": "on"})
        card = self.card("oidc")
        box = card.split('name="client_secret"', 1)[1].split(">", 1)[0]
        self.assertNotIn("data-needed-to-enable", box)

    def test_the_bind_password_is_marked_as_following_the_bind_dn(self):
        """Needed only where a DN names a service account, so the form asks
        for it only then — the same condition the server applies."""
        box = self.card("ldap").split('name="bind_password"', 1)[1] \
                               .split(">", 1)[0]
        self.assertIn("data-needed-to-enable", box)
        self.assertIn('data-needed-with="bind_dn"', box)

    def test_a_refusal_is_recorded_with_its_reason(self):
        self.save(provider="oidc", client_id="wdash", enabled="on")
        refused = self.refusals()
        self.assertEqual(len(refused), 1, "the refusal was not recorded")
        self.assertIn("a Discovery URL", refused[0]["state"]["reason"])

    def test_a_refusal_records_no_secret(self):
        """The audit trail carries the card's state, and a refused save is
        still a save that was submitted with one."""
        self.save(provider="oidc", client_id="wdash",
                  client_secret="hunter2", enabled="on")
        recorded = json.dumps(self.refusals()[0]["state"])
        self.assertNotIn("hunter2", recorded)


class OneDirectoryOnThePageTest(ConfigTestCase):
    """WDash signs people in through one directory at a time.

    Measured before the rule: posting the OIDC card with Enabled ticked while
    LDAP was enabled returned 302, stored the row, left both usable, and wrote
    one ordinary "OIDC settings updated" row.
    """

    def save(self, form, **overrides):
        return self.client.post("/admin/auth", data={**form, **overrides},
                                follow_redirects=True)

    def actions(self):
        return [row["action"] for row in self.app.store.audit.recent()]

    def test_enabling_the_second_directory_is_refused_either_way_round(self):
        for first, second in ((LDAP_FORM, OIDC_FORM), (OIDC_FORM, LDAP_FORM)):
            with self.subTest(enabling=second["provider"]):
                self.setUp()
                self.save(first, enabled="on")
                page = self.save(second, enabled="on").get_data(as_text=True)
                label = {"ldap": "LDAP",
                         "oidc": "OpenID Connect"}[first["provider"]]
                self.assertIn(f"{label} is the directory in use here", page)
                self.assertIn("one directory at a time", page)
                self.assertIsNone(
                    self.app.store.settings.get(f"auth.{second['provider']}"),
                    "nothing was supposed to be saved")
                self.assertIn(
                    f"{'LDAP' if second['provider'] == 'ldap' else 'OIDC'}"
                    f" settings refused", self.actions())
                self.tearDown()

    def test_the_directory_in_force_can_still_be_edited(self):
        """Otherwise an administrator on that installation can never touch
        the settings of the directory they are actually using."""
        self.save(OIDC_FORM, enabled="on")
        page = self.save(OIDC_FORM, client_id="renamed",
                         enabled="on").get_data(as_text=True)
        self.assertNotIn("directory in use here", page)
        self.assertEqual(self.app.store.settings.get("auth.oidc")["client_id"],
                         "renamed")

    def test_the_refusal_names_no_variable_and_says_how_to_switch(self):
        self.save(OIDC_FORM, enabled="on")
        page = self.save(LDAP_FORM, enabled="on").get_data(as_text=True)
        self.assertIn("OpenID Connect is the directory in use here", page)
        self.assertIn("turn it off on this page and save, then enable LDAP",
                      page)
        self.assertNotIn("environment", page.split("directory in use here")[1]
                         [:600])

    def test_turning_the_second_one_off_is_never_refused(self):
        self.save(LDAP_FORM, enabled="on")
        self.save(OIDC_FORM)          # no `enabled`, so off
        self.assertFalse(self.app.store.settings.get("auth.oidc")["enabled"])
        self.assertNotIn("OIDC settings refused", self.actions())


class DirectorySwitchTest(ConfigTestCase):
    """What a deliberate switch hands over, said at the moment it happens.

    Ownership is the username with no provider attached to it, so whoever
    signs in as a name at the new directory gets that name's dashboards and
    role mapping. Nothing is migrated — a name keeping what it owns is what
    makes a switch work — but the site is told rather than finding out.
    """

    def setUp(self):
        super().setUp()
        self.app.store.settings.set("rbac.user_roles", {"alice": "admin"})
        self.app.dashboard_manager.create_dashboard(
            name="Alice private", description="", query="",
            created_by="alice", visibility="private")
        self.app.dashboard_manager.create_dashboard(
            name="Owner's own", description="", query="",
            created_by="owner", visibility="private")

    def save(self, form, **overrides):
        return self.client.post("/admin/auth", data={**form, **overrides},
                                follow_redirects=True)

    def audited(self, action):
        return [row for row in self.app.store.audit.recent()
                if row["action"] == action]

    def test_the_sentence_lands_on_the_save_that_turns_the_old_one_off(self):
        """The handover happens there whenever the incoming directory is
        already stored and enabled — the shape an installation that once had
        both is in. Keyed to the checkbox that switches a directory ON, the
        sentence would never appear on this path at all."""
        self.app.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": "https://idp/.well-known/openid-configuration"})
        self.app.store.settings.set("auth.ldap", {
            "server": "ldaps://ldap:636", "base_dn": "dc=x", "enabled": True})

        page = self.save(LDAP_FORM).get_data(as_text=True)  # enabled off
        self.assertIn("OpenID Connect is now the directory", page)
        self.assertIn("alice", page)
        self.assertIn("1 dashboard and 1 role mapping", page)
        self.assertNotIn("2 dashboards", page,
                         "the owner's own dashboard is not inherited")

        row = self.audited("LDAP settings updated")[0]
        self.assertEqual(row["state"]["directory_in_force"], "oidc")
        self.assertEqual(row["state"]["directory_was"], "ldap")
        self.assertEqual(row["state"]["inherited"]["dashboards"], 1)
        self.assertEqual(row["state"]["inherited"]["names"], ["alice"])

    def test_the_resolution_change_is_audited_where_it_changes(self):
        """Not only at startup: a change made while the process is running
        would otherwise never reach the trail, and the banner would say one
        thing while the audit said another."""
        self.save(LDAP_FORM, enabled="on")
        row = self.audited("directory in force changed")[0]
        self.assertEqual((row["state"]["was"], row["state"]["now"]),
                         (None, "ldap"))
        self.assertEqual(row["subject"], "auth")

    def test_dashboards_that_cannot_be_read_are_not_reported_as_none(self):
        """"0 dashboards belong to names that are not local accounts" is a
        sentence somebody acts on, and it is the one thing the page cannot
        know when the read failed."""
        def raise_instead():
            raise RuntimeError("the dashboard file is not readable")

        self.app.dashboard_manager.get_all_dashboards = raise_instead
        page = self.save(LDAP_FORM, enabled="on").get_data(as_text=True)
        self.assertIn("an unknown number of dashboards", page)
        self.assertNotIn("0 dashboards", page)

    def test_the_audit_row_records_a_count_not_a_copy_of_the_directory(self):
        """The flash was trimmed to a few names and the audit row was not, so
        one save on an installation with a large directory wrote every
        directory-owned name into one row. The trail should record what
        happened, not the directory it happened to."""
        self.app.store.settings.set(
            "rbac.user_roles",
            {"alice": "admin", **{f"mapped{n}": "admin" for n in range(40)}})

        page = self.save(LDAP_FORM, enabled="on").get_data(as_text=True)
        state = self.audited("LDAP settings updated")[0]["state"]
        self.assertEqual(state["inherited"]["mappings"], 41)
        self.assertEqual(state["inherited"]["name_count"], 41)
        self.assertLessEqual(len(state["inherited"]["names"]), 5)
        self.assertIn("and 36 more", page, "the sentence still counts them")

    def test_an_ordinary_re_save_says_nothing_about_inheritance(self):
        self.save(LDAP_FORM, enabled="on")
        page = self.save(LDAP_FORM, base_dn="dc=corp",
                         enabled="on").get_data(as_text=True)
        self.assertNotIn("is now the directory", page)
        self.assertEqual(len(self.audited("directory in force changed")), 1)
        self.assertNotIn("inherited",
                         self.audited("LDAP settings updated")[0]["state"])


class TurningTheDirectoryOffTest(ConfigTestCase):
    """Turning off the directory in force, by somebody who arrived through it.

    Measured before the rule: the same post was accepted unconditionally, and
    an installation whose only local administrator was disabled ended with
    nobody able to open the page.
    """

    def setUp(self):
        super().setUp()
        self.app.store.settings.set("auth.ldap", {
            "server": "ldaps://ldap:636", "base_dn": "dc=x", "enabled": True})
        self.arrive("directory")

    def arrive(self, provider):
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "directory-1", "email": "alice@example.com",
                "username": "alice", "groups": ["wdash-admins"],
                "local_role": None, "provider": provider}
            session["_user_id"] = "directory-1"
        self.app.store.rbac.invalidate()

    def turn_off(self):
        return self.client.post("/admin/auth", data=LDAP_FORM,
                                follow_redirects=True).get_data(as_text=True)

    def test_with_an_enabled_local_administrator_it_is_allowed(self):
        self.turn_off()
        self.assertFalse(self.app.store.settings.get("auth.ldap")["enabled"])

    def test_with_the_only_local_administrator_disabled_it_is_refused(self):
        self.app.store.users.set_disabled("owner", True)
        page = self.turn_off()
        self.assertIn("nobody able to open this page", page)
        self.assertIn("--enable owner", page)
        self.assertTrue(self.app.store.settings.get("auth.ldap")["enabled"])
        self.assertIn("LDAP settings refused",
                      [row["action"] for row in self.app.store.audit.recent()])

    def test_somebody_who_arrived_through_the_other_one_may(self):
        self.app.store.users.set_disabled("owner", True)
        self.arrive("oidc")
        self.turn_off()
        self.assertFalse(self.app.store.settings.get("auth.ldap")["enabled"])

    def test_handing_over_to_the_other_directory_is_not_a_lockout(self):
        """The shape the rule exists for, and the one it used to make
        unresolvable: both directories stored and enabled, no enabled local
        administrator, the actor arrived through the one in force. Turning it
        off is a SWITCH — the other one takes over on the same save — and it
        is the only in-page direction, because enabling the other one is
        refused by the one-directory rule.

        Measured before: refused, saying "Turning OpenID Connect off would
        leave nobody able to open this page" while disabling auth.oidc in the
        same process made directory()['in_force'] == 'ldap'. Both directions
        refused, both rows left enabled, two "settings refused" rows.
        """
        self.app.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": "https://idp/.well-known/openid-configuration"})
        self.app.store.users.set_disabled("owner", True)
        self.arrive("oidc")

        page = self.client.post("/admin/auth", data=OIDC_FORM,
                                follow_redirects=True).get_data(as_text=True)
        self.assertNotIn("nobody able to open this page", page)
        self.assertIs(self.app.store.settings.get("auth.oidc")["enabled"],
                      False)
        self.assertIn("LDAP is now the directory this installation signs "
                      "people in through", page)
        self.assertNotIn("OIDC settings refused",
                         [row["action"] for row in
                          self.app.store.audit.recent()])

    def test_a_handover_to_a_directory_that_cannot_be_used_is_refused(self):
        """The other half: the one that would take over is enabled but
        half-filled, so nobody arrives through it either. Still refused —
        and the sentence says that, rather than the one for an installation
        whose last door is closing."""
        self.app.store.settings.set("auth.ldap", {
            "server": "", "base_dn": "dc=x", "enabled": True})
        self.app.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": "https://idp/.well-known/openid-configuration"})
        self.app.store.users.set_disabled("owner", True)
        self.arrive("oidc")

        page = self.client.post("/admin/auth", data=OIDC_FORM,
                                follow_redirects=True).get_data(as_text=True)
        self.assertIn("hand this installation to LDAP", page)
        # Which field, by the name the card gives it, rather than "one of
        # them is blank" about a pair.
        self.assertIn("a Server is required and blank", page)
        self.assertIs(self.app.store.settings.get("auth.oidc")["enabled"],
                      True)

    def test_the_directory_that_is_not_in_force_is_never_guarded(self):
        """Only the directory actually signing people in can take anybody's
        access away with it. A session that does not say which door it used is
        refused conservatively for THAT one, and must not be for the other."""
        self.app.store.users.set_disabled("owner", True)
        self.arrive(None)
        self.client.post("/admin/auth", data=OIDC_FORM, follow_redirects=True)
        self.assertIs(self.app.store.settings.get("auth.oidc")["enabled"],
                      False)
        self.assertTrue(self.app.store.settings.get("auth.ldap")["enabled"])


class TwoDirectoriesAreReportedTest(unittest.TestCase):
    """An installation that already has both loses one door at the moment it
    upgrades, without anybody pressing anything. Made loud rather than quiet:
    the log, one audit row, and a banner on this page."""

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.key = SecretBox.generate_key()

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def build(self):
        database, key = self.database, self.key

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "two-directories"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key

        return create_app(TestConfig)

    def test_the_conflict_is_logged_audited_and_shown(self):
        first = self.build()
        client = first.test_client()
        secret = support.set_up(client, username="owner", password=PASSWORD)
        # Both rows enabled — written by an earlier version, or by hand —
        # and a restart: nobody pressed anything, and the installation has
        # two. LDAP saved last, so it is the one in force.
        first.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": "https://idp/.well-known/openid-configuration"})
        first.store.settings.set("auth.ldap", {
            "server": "ldaps://ldap:636", "base_dn": "dc=x", "enabled": True})

        second = self.build()
        rows = [row for row in second.store.audit.recent()
                if row["action"] == "two directories configured"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"]["in_force"], "ldap")
        self.assertEqual(rows[0]["state"]["shadowed"], "oidc")
        self.assertEqual(rows[0]["actor"], "system")

        client = second.test_client()
        support.sign_in(client, "owner", PASSWORD, secret)
        page = client.get("/admin/config").get_data(as_text=True)
        self.assertIn("One directory at a time", page)
        self.assertIn("LDAP is in force", page)
        self.assertIn("--use-directory", page)

    def test_every_worker_coming_up_adds_one_row_between_them(self):
        """It is a fact about the installation, not an act by a process.

        Measured before this: `create_app` records at start-up and gunicorn
        runs it per worker, so four workers wrote four identical rows on
        every restart — and a trail whose rows are not events is one nobody
        can count anything in. The demo runs two workers and had two.
        """
        first = self.build()
        support.set_up(first.test_client(), username="owner",
                       password=PASSWORD)
        first.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": "https://idp/.well-known/openid-configuration"})
        first.store.settings.set("auth.ldap", {
            "server": "ldaps://ldap:636", "base_dn": "dc=x", "enabled": True})

        workers = [self.build() for _ in range(4)]
        rows = [row for row in workers[-1].store.audit.recent()
                if row["action"] == "two directories configured"]
        self.assertEqual(len(rows), 1, f"{len(rows)} rows for one conflict")

    def test_a_conflict_that_changes_is_a_new_row(self):
        """Silence is for a fact that persists. A conflict whose shape
        changes — the other directory now in force — is a different fact,
        and a trail that swallowed it would show the first arrangement for
        ever."""
        first = self.build()
        support.set_up(first.test_client(), username="owner",
                       password=PASSWORD)
        first.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": "https://idp/.well-known/openid-configuration"})
        first.store.settings.set("auth.ldap", {
            "server": "ldaps://ldap:636", "base_dn": "dc=x", "enabled": True})
        self.build()

        # OIDC saved last now, so it is the one in force and LDAP is the
        # one being shadowed: the same conflict the other way round.
        first.store.settings.set("auth.oidc", {
            "client_id": "wdash", "enabled": True,
            "discovery_url": "https://idp/.well-known/openid-configuration"})
        latest = self.build()

        rows = [row for row in latest.store.audit.recent()
                if row["action"] == "two directories configured"]
        self.assertEqual(len(rows), 2, [row["state"] for row in rows])
        self.assertEqual(rows[0]["state"]["in_force"], "oidc")
        self.assertEqual(rows[1]["state"]["in_force"], "ldap")

    def test_one_directory_alone_says_nothing(self):
        app = self.build()
        client = app.test_client()
        support.set_up(client, username="owner", password=PASSWORD)
        app.store.settings.set("auth.ldap", {
            "server": "ldaps://ldap:636", "base_dn": "dc=x", "enabled": True})
        again = self.build()
        self.assertEqual(
            [row for row in again.store.audit.recent()
             if row["action"] == "two directories configured"], [])
        page = again.test_client().get("/auth/login").get_data(as_text=True)
        self.assertNotIn("Another sign-in method", page)


class RoleEditingTest(ConfigTestCase):
    def setUp(self):
        super().setUp()
        # One test here probes `/api/search` to show an edit reaching a live
        # session. Declared rather than inherited from whatever is listening
        # on port 9200 — which is what it used to be.
        from tests.support import with_stub_logs
        with_stub_logs(self.app)

    def save_role(self, **overrides):
        form = {"name": "auditor", "permissions": "logs:read\ntraces:read",
                "containers": "audit-*", "trace_containers": "",
                "services": "", "groups": "auditors"}
        form.update(overrides)
        return self.client.post("/admin/roles", data=form, follow_redirects=True)

    def test_a_role_can_be_created(self):
        self.save_role()
        role = self.app.store.roles.get("auditor")
        self.assertEqual(role["permissions"], ["logs:read", "traces:read"])
        self.assertEqual(role["containers"], ["audit-*"])
        self.assertEqual(role["groups"], ["auditors"])

    def test_a_blank_services_box_means_unrestricted_not_nothing(self):
        """The one field where empty is permissive, and it says so on the form."""
        self.save_role(services="")
        self.assertIsNone(self.app.store.roles.get("auditor")["services"])

        self.save_role(services="payment-service")
        self.assertEqual(self.app.store.roles.get("auditor")["services"],
                         ["payment-service"])

    def test_a_blank_containers_box_grants_nothing(self):
        self.save_role(containers="")
        self.assertEqual(self.app.store.roles.get("auditor")["containers"], [])

    def test_an_edit_reaches_a_session_that_is_already_signed_in(self):
        """The whole reason this page can exist."""
        self.assertEqual(self.client.get("/api/search?q=*").status_code, 200)

        self.client.post("/admin/roles", data={
            "name": "admin", "permissions": "system:admin",
            "containers": "*", "trace_containers": "*",
            "services": "", "groups": ""}, follow_redirects=True)

        self.assertEqual(self.client.get("/api/search?q=*").status_code, 403)

    def test_you_cannot_delete_the_role_you_are_standing_on(self):
        """With another administrator role present, the guard that fires is
        the personal one rather than the system-wide one."""
        self.app.store.roles.upsert(
            "co-admin", permissions=["system:admin"], containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()

        response = self.client.post("/admin/roles/admin/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("admin"))
        self.assertIn(b"lock you out", response.data)

    def test_the_only_administrator_role_cannot_be_deleted(self):
        """system:admin is not a superuser, so nothing else can recover it."""
        response = self.client.post("/admin/roles/admin/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("admin"))
        self.assertIn(b"only role that can administer", response.data)

    def test_the_last_role_cannot_be_deleted(self):
        for name in ("developer", "viewer"):
            self.app.store.roles.delete(name)
        self.app.store.rbac.invalidate()
        response = self.client.post("/admin/roles/admin/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("admin"))
        self.assertIn(b"last role", response.data)


class ChangePreviewTest(ConfigTestCase):
    """The editor answers "what does this change", not just "what is this".

    An end state is easy to read and impossible to review: `app-*` and `ap-*`
    both look deliberate, produce a plausible count, and reach completely
    different sets. The delta is the sentence that catches it.
    """

    def setUp(self):
        super().setUp()
        from tests.test_fanout import StubSource
        # Replace, not add: a test declares the sources it depends on rather
        # than inheriting whatever the app registered.
        self.app.hub.replace_all(logs=[StubSource(
            "lab", "elasticsearch",
            ["app-logs", "infra-logs", "bad-logs"], [])])
        self.client.post("/admin/roles", data={
            "name": "auditor", "permissions": "logs:read",
            "containers": "app-*", "trace_containers": "",
            "services": "", "groups": ""}, follow_redirects=True)

    def preview(self, **overrides):
        payload = {"name": "auditor", "permissions": ["logs:read"],
                   "containers": ["app-*"], "trace_containers": [],
                   "services": []}
        payload.update(overrides)
        return self.client.post("/admin/api/roles/preview",
                                json=payload).get_json()["change"]

    def test_a_colon_that_names_no_source_is_pointed_out(self):
        """It is right when that is the name and a typo when a source was
        meant; only the person writing it knows which."""
        result = self.client.post("/admin/api/roles/preview", json={
            "name": "auditor", "permissions": ["logs:read"],
            "containers": ["staging:*", "lab:app-*"],
            "trace_containers": [], "services": ["unknown_service:java"],
        }).get_json()
        said = " ".join(result["warnings"])
        self.assertIn("no source is called 'staging'", said)
        self.assertIn("no source is called 'unknown_service'", said)
        self.assertNotIn("'lab'", said)

    def test_a_new_role_has_nothing_to_compare_against(self):
        self.assertIsNone(self.preview(name="brand-new"))

    def test_an_unchanged_role_reports_no_change(self):
        change = self.preview()
        self.assertEqual(change["logs_added"], [])
        self.assertEqual(change["logs_removed"], [])
        self.assertFalse(change["widens"])

    def test_a_typo_shows_up_as_a_loss_rather_than_a_count(self):
        change = self.preview(containers=["ap-*"])
        self.assertEqual(change["logs_removed"], ["app-logs"])
        self.assertEqual(change["logs_added"], [])
        self.assertFalse(change["widens"])

    def test_widening_is_called_widening(self):
        change = self.preview(containers=["*"])
        self.assertEqual(change["logs_added"], ["bad-logs", "infra-logs"])
        self.assertTrue(change["widens"])

    def test_an_exclusion_is_reflected_in_what_is_granted(self):
        change = self.preview(containers=["*", "-bad-*"])
        self.assertNotIn("bad-logs", change["logs_added"])
        self.assertIn("infra-logs", change["logs_added"])

    def test_a_new_permission_widens_even_with_identical_containers(self):
        """Access is not only about where; system:admin reaches everything."""
        change = self.preview(permissions=["logs:read", "system:admin"])
        self.assertEqual(change["permissions_added"], ["system:admin"])
        self.assertEqual(change["logs_added"], [])
        self.assertTrue(change["widens"])

    def test_removing_a_permission_does_not_widen(self):
        change = self.preview(permissions=[])
        self.assertEqual(change["permissions_removed"], ["logs:read"])
        self.assertFalse(change["widens"])

    def test_clearing_the_services_box_widens(self):
        """Blank is every service — the widest value that box holds — and the
        diff left services out, so this edit showed no change at all."""
        self.client.post("/admin/roles", data={
            "name": "auditor", "permissions": "logs:read",
            "containers": "app-*", "trace_containers": "",
            "services": "payment-service", "groups": ""}, follow_redirects=True)
        change = self.preview(services=[])
        self.assertEqual(change["services_added"], ["every service"])
        self.assertTrue(change["widens"])

    def test_restricting_services_narrows(self):
        change = self.preview(services=["payment-service"])
        self.assertEqual(change["services_removed"], ["every service"])
        self.assertEqual(change["services_added"], [])
        self.assertFalse(change["widens"])

    def _with_services(self, services):
        self.client.post("/admin/roles", data={
            "name": "auditor", "permissions": "logs:read",
            "containers": "app-*", "trace_containers": "",
            "services": "\n".join(services), "groups": ""},
            follow_redirects=True)

    def test_taking_an_exclusion_off_widens(self):
        """As strings, `-payments` leaving a role of `*` was "removes
        services" and "narrows access" — on the edit that makes payments
        visible."""
        self._with_services(["*", "-payments"])
        change = self.preview(services=["*"])
        self.assertEqual(change["exclusions_removed"], ["-payments"])
        self.assertEqual(change["services_removed"], [])
        self.assertTrue(change["widens"])

    def test_putting_an_exclusion_on_narrows(self):
        """…and adding it was "grants services" and "widens"."""
        self._with_services(["*"])
        change = self.preview(services=["*", "-payments"])
        self.assertEqual(change["exclusions_added"], ["-payments"])
        self.assertEqual(change["services_added"], [])
        self.assertFalse(change["widens"])

    def test_an_exclusion_is_one_with_the_marker_after_the_qualifier_too(self):
        self._with_services(["*", "lab:-payments"])
        change = self.preview(services=["*"])
        self.assertEqual(change["exclusions_removed"], ["lab:-payments"])
        self.assertTrue(change["widens"])

    def test_a_marker_after_a_colon_that_names_no_source_is_a_name(self):
        """`x:-y` with no source called x is the name "x:-y": taking it off
        removes a grant, not an exclusion."""
        self._with_services(["*", "x:-y"])
        change = self.preview(services=["*"])
        self.assertEqual(change["services_removed"], ["x:-y"])
        self.assertEqual(change["exclusions_removed"], [])

    def test_adding_a_group_widens(self):
        """A group is who gets the role: adding one hands everything it
        reaches to a whole directory group."""
        change = self.preview(groups=["contractors"])
        self.assertEqual(change["groups_added"], ["contractors"])
        self.assertTrue(change["widens"])


class MappingTest(ConfigTestCase):
    def test_mappings_are_parsed_and_stored(self):
        self.client.post("/admin/mappings", data={
            "default_role": "viewer",
            "user_roles": "alice@example.com = admin\nbob = viewer"},
            follow_redirects=True)
        self.assertEqual(self.app.store.settings.get("rbac.user_roles"),
                         {"alice@example.com": "admin", "bob": "viewer"})

    def test_a_mapping_to_a_role_that_does_not_exist_is_reported(self):
        """Silently dropping one is silently changing somebody's access."""
        response = self.client.post("/admin/mappings", data={
            "default_role": "viewer",
            "user_roles": "alice@example.com = nonexistent"},
            follow_redirects=True)
        self.assertEqual(self.app.store.settings.get("rbac.user_roles"), {})
        self.assertIn(b"not understood", response.data)

    def test_an_unparseable_line_is_reported(self):
        response = self.client.post("/admin/mappings", data={
            "default_role": "viewer", "user_roles": "this is not a mapping"},
            follow_redirects=True)
        self.assertIn(b"not understood", response.data)

    def test_a_default_role_that_does_not_exist_is_refused(self):
        response = self.client.post("/admin/mappings", data={
            "default_role": "nonexistent", "user_roles": ""},
            follow_redirects=True)
        self.assertIn(b"no longer exists", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.default_role"),
                         "viewer")

    def test_a_blank_default_is_refused_rather_than_replaced(self):
        """It used to be saved as "viewer" — whether or not a role of that
        name existed. The default only ever changes to something chosen."""
        self.app.store.settings.set("rbac.default_role", "developer")
        response = self.client.post("/admin/mappings", data={
            "default_role": "", "user_roles": ""}, follow_redirects=True)
        self.assertIn(b"Choose a default role", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.default_role"),
                         "developer")

    def test_a_default_that_no_longer_exists_is_not_shown_as_the_first_role(
            self):
        """With no option selected the browser selects the FIRST one — `admin`
        — and the next "Save mappings" made everybody unmapped an
        administrator. Measured on the rendered page, where the browser
        decides."""
        self.app.store.settings.set("rbac.default_role", "auditor")
        page = self.client.get("/admin/config").get_data(as_text=True)
        select = page.split('id="defaultRole"', 1)[1].split("</select>", 1)[0]
        selected = [option for option in select.split("<option")[1:]
                    if " selected" in option.split(">", 1)[0]]
        self.assertEqual(len(selected), 1, select)
        self.assertIn('value="auditor"', selected[0])
        self.assertIn("no longer exists", selected[0])

        # And what the browser would therefore submit is refused, by name.
        # Asserted on what only a refusal produces: the page re-renders the
        # missing default with "no longer exists" either way, and the stored
        # value was already "auditor".
        response = self.client.post("/admin/mappings", data={
            "default_role": "auditor", "user_roles": ""}, follow_redirects=True)
        self.assertIn(b"The default role &#39;auditor&#39; no longer exists",
                      response.data)
        self.assertNotIn(b"Role mappings saved", response.data)
        self.assertNotIn("mappings updated", [
            row["action"] for row in self.app.store.audit.recent()])



class OneMappingAtATimeTest(ConfigTestCase):
    """The table on Roles & access, where a row is a record.

    Every mapping used to ride on one form: the page held a stack of input
    groups and "Save mappings" submitted all of them plus the default role
    together. Three things followed from that, and all three are what these
    ask about. Adding one person re-sent everybody, so a row nobody had
    finished went to the server with the rest. A mapping could not be changed
    without the set being rewritten. And the default role and the mappings
    shared a submission, so a handler reading a missing field as "no
    mappings" would empty the table on a save that never mentioned it.
    """

    def stored(self):
        return self.app.store.settings.get("rbac.user_roles") or {}

    def save(self, **form):
        return self.client.post("/admin/mappings/entry", data=form,
                                follow_redirects=True)

    def test_one_is_added_and_the_others_are_untouched(self):
        self.app.store.settings.set("rbac.user_roles", {"carol": "viewer"})
        response = self.save(identifier="bob", role="developer", original="")
        self.assertEqual(self.stored(),
                         {"carol": "viewer", "bob": "developer"})
        self.assertIn(b"mapped to developer", response.data)

    def test_editing_the_role_replaces_only_that_row(self):
        self.app.store.settings.set("rbac.user_roles",
                                    {"carol": "viewer", "bob": "developer"})
        self.save(identifier="carol", role="developer", original="carol")
        self.assertEqual(self.stored(),
                         {"carol": "developer", "bob": "developer"})

    def test_editing_the_identifier_moves_it_rather_than_copying_it(self):
        """The old row still granted. A mapping left behind under the name
        somebody was editing away from is access nobody can see they gave."""
        self.app.store.settings.set("rbac.user_roles",
                                    {"alice@example.com": "developer"})
        response = self.save(identifier="alice", role="developer",
                             original="alice@example.com")
        self.assertEqual(self.stored(), {"alice": "developer"})
        self.assertIn(b"is now", response.data)

    def test_a_blank_identifier_is_refused(self):
        self.save(identifier="  ", role="viewer", original="")
        self.assertEqual(self.stored(), {})

    def test_a_role_nobody_chose_is_refused_rather_than_the_first_one(self):
        """The first role is `admin`. An empty select submits its first
        option unless it has one of its own, and the page gives it one —
        this is the half that does not depend on the browser."""
        response = self.save(identifier="bob", role="", original="")
        self.assertEqual(self.stored(), {})
        self.assertIn(b"Choose a role", response.data)

    def test_a_role_that_does_not_exist_is_refused_by_name(self):
        response = self.save(identifier="bob", role="auditor", original="")
        self.assertEqual(self.stored(), {})
        self.assertIn(b"no role called", response.data)
        self.assertIn(b"auditor", response.data)

    def test_adding_one_is_audited_with_what_it_grants(self):
        self.save(identifier="bob", role="viewer", original="")
        rows = [row for row in self.app.store.audit.recent()
                if row["action"] == "mapping added"]
        self.assertEqual(len(rows), 1, "the change was not recorded")
        self.assertEqual(rows[0]["state"]["role"], "viewer")
        self.assertEqual(rows[0]["state"]["user_roles"], {"bob": "viewer"})

    def test_a_refused_one_is_audited_too(self):
        self.save(identifier="bob", role="auditor", original="")
        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertNotIn("mapping added", actions)

    def test_deleting_one_leaves_the_rest(self):
        self.app.store.settings.set("rbac.user_roles",
                                    {"carol": "viewer", "bob": "developer"})
        response = self.client.post("/admin/mappings/delete",
                                    data={"identifier": "carol"},
                                    follow_redirects=True)
        self.assertEqual(self.stored(), {"bob": "developer"})
        self.assertIn(b"is gone", response.data)
        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertIn("mapping removed", actions)

    def test_deleting_one_that_is_already_gone_says_so(self):
        self.app.store.settings.set("rbac.user_roles", {"bob": "developer"})
        response = self.client.post("/admin/mappings/delete",
                                    data={"identifier": "carol"},
                                    follow_redirects=True)
        self.assertEqual(self.stored(), {"bob": "developer"})
        self.assertIn(b"no longer there", response.data)

    def test_saving_the_default_role_alone_does_not_empty_the_table(self):
        """The form that carries the default no longer carries the mappings.
        A handler reading an ABSENT field as "none" would delete everybody's
        mapping every time somebody changed the default."""
        self.app.store.settings.set("rbac.user_roles", {"bob": "developer"})
        response = self.client.post("/admin/mappings",
                                    data={"default_role": "viewer"},
                                    follow_redirects=True)
        self.assertEqual(self.stored(), {"bob": "developer"})
        self.assertEqual(self.app.store.settings.get("rbac.default_role"),
                         "viewer")
        self.assertIn(b"now gets", response.data)

    def test_an_empty_field_still_means_none(self):
        """Absent is "not mentioned"; empty is a submission saying there are
        none. The bulk form is still how a whole set is replaced."""
        self.app.store.settings.set("rbac.user_roles", {"bob": "developer"})
        self.client.post("/admin/mappings",
                         data={"default_role": "viewer", "user_roles": ""},
                         follow_redirects=True)
        self.assertEqual(self.stored(), {})

    def test_a_default_role_that_does_not_exist_is_still_refused_alone(self):
        self.client.post("/admin/mappings", data={"default_role": "auditor"},
                         follow_redirects=True)
        self.assertEqual(self.app.store.settings.get("rbac.default_role"),
                         "viewer")


class TheMappingTableSaysWhatIsStoredTest(ConfigTestCase):
    """What the page renders, asked of the page."""

    def page(self):
        return self.client.get("/admin/config").get_data(as_text=True)

    def test_a_row_carries_its_own_values_and_its_own_delete(self):
        self.app.store.settings.set("rbac.user_roles",
                                    {"alice@example.com": "developer"})
        page = self.page()
        table = page.split('id="mappingsTable"', 1)[1].split("</table>", 1)[0]
        self.assertIn("alice@example.com", table)
        self.assertIn("developer", table)
        self.assertIn("/admin/mappings/delete", table)
        self.assertIn("data-mapping=", table)

    def test_a_role_that_no_longer_exists_is_marked_rather_than_shown_plain(
            self):
        """It is still granting nothing, and a row that looks like every
        other row says the opposite."""
        self.app.store.settings.set("rbac.user_roles", {"bob": "auditor"})
        table = self.page().split('id="mappingsTable"', 1)[1]
        self.assertIn("no longer exists", table.split("</table>", 1)[0])

    def test_with_none_stored_it_says_what_happens_instead(self):
        page = self.page()
        self.assertNotIn('id="mappingsTable"', page)
        self.assertIn("No direct mappings", page)

    def test_the_modal_offers_no_role_before_one_is_chosen(self):
        """A select with nothing selected shows, and submits, its FIRST
        option — and the first role is `admin`."""
        modal = self.page().split('id="mappingRole"', 1)[1].split("</select>", 1)[0]
        first = modal.split("<option", 2)[1]
        self.assertIn('value=""', first)

    def test_a_local_account_is_told_its_own_role_wins(self):
        """A local account's stored role is read first, so a mapping naming
        one does nothing while it exists. The accounts table says so from its
        side; a reader on this tab would otherwise believe the row."""
        self.app.store.settings.set("rbac.user_roles", {"owner": "viewer"})
        table = self.page().split('id="mappingsTable"', 1)[1].split("</table>", 1)[0]
        self.assertIn("its own role wins", table)


class RoleDependentsTest(ConfigTestCase):
    """A role something still points at stays until it points elsewhere.

    Deleting a role never asked who depended on it. The page then offered
    its first role — `admin` — in every select that had pointed at the one
    deleted, so the next "Save mappings" handed out administration: to the
    people mapped to it, or, for the default role, to everybody unmapped.
    """

    def test_the_default_role_cannot_be_deleted(self):
        response = self.client.post("/admin/roles/viewer/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("viewer"))
        self.assertIn(b"is the default role", response.data)

    def test_a_role_a_mapping_names_cannot_be_deleted(self):
        self.app.store.settings.set("rbac.user_roles",
                                    {"alice@example.com": "developer"})
        response = self.client.post("/admin/roles/developer/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("developer"))
        # The page embeds the stored mappings whatever happened, so the
        # identifier is read from the refusal itself.
        self.assertIn(b"These mappings still give", response.data)
        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "role delete refused"]
        self.assertIn("alice@example.com", refused[0]["state"]["reason"])

    def test_a_role_a_local_account_holds_cannot_be_deleted(self):
        """Its stored role is what makes a local account the way back in."""
        self.app.store.roles.upsert(
            "co-admin", permissions=["system:admin"], containers=["*"],
            trace_containers=["*"])
        self.app.store.users.create("breakglass", PASSWORD, role="co-admin")
        self.app.store.rbac.invalidate()
        response = self.client.post("/admin/roles/co-admin/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("co-admin"))
        self.assertIn(b"breakglass", response.data)

    def test_a_role_nothing_points_at_can_go(self):
        response = self.client.post("/admin/roles/developer/delete",
                                    follow_redirects=True)
        self.assertIsNone(self.app.store.roles.get("developer"))
        self.assertIn(b"deleted", response.data)

    def test_a_refused_deletion_is_recorded(self):
        """README and SECURITY both say refused attempts sit beside the
        successful ones; for deletions they did not."""
        self.client.post("/admin/roles/viewer/delete")
        actions = [row["action"] for row in self.app.store.audit.recent()]
        self.assertIn("role delete refused", actions)


class DirectoryAdministratorTest(ConfigTestCase):
    """An administrator who is one because a directory group says so.

    Every other test here signs in as the local `owner`, whose stored role
    comes first in the resolver's order — so nothing these routes now pass
    the invariants (email, groups, mappings, the default) could change an
    answer. These sign in the way an OIDC or LDAP administrator does.
    """

    def setUp(self):
        super().setUp()
        admin = self.app.store.roles.get("admin")
        self.assertIn("wdash-admins", admin["groups"])  # a built-in role
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "directory-1", "email": "alice@example.com",
                "username": "alice", "groups": ["wdash-admins"],
                "local_role": None}
            session["_user_id"] = "directory-1"
        self.app.store.rbac.invalidate()
        self.assertEqual(self.client.get("/admin/config").status_code, 200,
                         "alice should reach the page through her group")

    def test_changing_the_default_role_is_allowed(self):
        """Refused before: the old rule never looked at groups, decided she
        would land on the new default, and blocked a harmless edit."""
        response = self.client.post("/admin/mappings", data={
            "default_role": "developer", "user_roles": ""},
            follow_redirects=True)
        self.assertIn(b"Role mappings saved", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.default_role"),
                         "developer")

    def test_mapping_her_email_below_her_username_is_refused(self):
        """The resolver reads the email first. The old rule read the username
        first, saw admin, and saved a change that demoted her on the next
        request."""
        response = self.client.post("/admin/mappings", data={
            "default_role": "viewer",
            "user_roles": "alice@example.com = viewer\nalice = admin"},
            follow_redirects=True)
        self.assertIn(b"lose access", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.user_roles") or {},
                         {})

        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "mappings save refused"]
        self.assertEqual(len(refused), 1, "the refusal was not recorded")
        self.assertIn("lose access", refused[0]["state"]["reason"])

    def test_mapping_her_email_below_her_username_one_row_at_a_time(self):
        """The same rule, through the table. A row saved on its own is still
        a change to the whole picture — the invariant reads the set it would
        leave behind, not the row."""
        response = self.client.post("/admin/mappings/entry", data={
            "identifier": "alice@example.com", "role": "viewer",
            "original": ""}, follow_redirects=True)
        self.assertIn(b"lose access", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.user_roles") or {},
                         {})

        refused = [row for row in self.app.store.audit.recent()
                   if row["action"] == "mapping added refused"]
        self.assertEqual(len(refused), 1, "the refusal was not recorded")
        self.assertIn("lose access", refused[0]["state"]["reason"])

    def test_removing_the_mapping_that_administers_her_is_refused(self):
        """Deletion is a change to the set too. Hers is the only thing
        putting her on a role that can administer, so removing it empties the
        page she would need to put it back."""
        admin = self.app.store.roles.get("admin")
        self.app.store.roles.upsert(
            "admin", permissions=admin["permissions"],
            containers=admin["containers"],
            trace_containers=admin["trace_containers"], groups=[])
        self.app.store.settings.set("rbac.user_roles",
                                    {"alice@example.com": "admin"})
        self.app.store.rbac.invalidate()

        response = self.client.post("/admin/mappings/delete",
                                    data={"identifier": "alice@example.com"},
                                    follow_redirects=True)
        self.assertIn(b"lose access", response.data)
        self.assertEqual(self.app.store.settings.get("rbac.user_roles"),
                         {"alice@example.com": "admin"})

    def test_taking_her_group_off_the_admin_role_is_refused(self):
        admin = self.app.store.roles.get("admin")
        response = self.client.post("/admin/roles", data={
            "name": "admin", "permissions": "\n".join(admin["permissions"]),
            "containers": "\n".join(admin["containers"] or []),
            "trace_containers": "\n".join(admin["trace_containers"] or []),
            "services": "", "groups": ""}, follow_redirects=True)
        self.assertIn(b"lock you out", response.data)
        self.assertIn("wdash-admins", self.app.store.roles.get("admin")["groups"])


class SecretsUnavailableTest(unittest.TestCase):
    """With no encryption key, the page works but refuses to store secrets.

    Reached by taking the key away AFTER the administrator signed in, which
    is the shape a real installation gets into: a key that was set is lost,
    or was never carried into a new deployment. It cannot be reached by
    starting with none — a local account's authenticator has to be sealed,
    so an installation with no key has no local sign-in at all. One box is
    shared by every repository in the store, so emptying it empties all of
    them at once, exactly as a missing key would.
    """

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "no-key"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        support.set_up(self.client, username="owner", password=PASSWORD)
        self.app.store.secrets._fernet = None
        assert not self.app.store.secrets.available
    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def test_the_page_says_so_rather_than_failing_quietly(self):
        page = self.client.get("/admin/config").data
        self.assertIn(b"WDASH_ENCRYPTION_KEY", page)

    def test_storing_a_secret_is_refused_not_written_as_plaintext(self):
        response = self.client.post("/admin/auth", data={
            "provider": "oidc", "client_id": "wdash",
            "client_secret": "would-be-plaintext"}, follow_redirects=True)
        self.assertIn(b"not set", response.data)
        self.assertIsNone(self.app.store.settings.get("auth.oidc"))

    def test_settings_without_secrets_still_save(self):
        self.client.post("/admin/roles", data={
            "name": "auditor", "permissions": "logs:read",
            "containers": "audit-*", "trace_containers": "",
            "services": "", "groups": ""}, follow_redirects=True)
        self.assertIsNotNone(self.app.store.roles.get("auditor"))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class OidcScopesTest(ConfigTestCase):
    """The scopes a sign-in asks for are on the card, with the rest of the
    provider. They were an environment variable, the one part of the
    provider the page could not change — a provider that refused a scope it
    did not know needed a redeploy."""

    def save(self, **overrides):
        return self.client.post("/admin/auth", data={**OIDC_FORM, **overrides,
                                                     "enabled": "on"},
                                follow_redirects=True)

    def test_the_field_is_stored_and_used(self):
        from wdash.auth.providers import oidc_settings
        self.save(scopes="openid email")
        self.assertEqual(self.app.store.settings.get("auth.oidc")["scopes"],
                         "openid email")
        self.assertEqual(oidc_settings(self.app)["scopes"], "openid email")

    def test_a_blank_field_is_stored_blank_so_a_changed_default_reaches_it(self):
        from wdash.auth.providers import oidc_settings
        self.save()
        self.assertEqual(self.app.store.settings.get("auth.oidc")["scopes"], "")
        self.assertIsNone(oidc_settings(self.app)["scopes"])

    def test_the_card_shows_what_is_stored(self):
        self.save(scopes="openid email")
        page = self.client.get("/admin/config").get_data(as_text=True)
        self.assertIn('name="scopes"', page)
        self.assertIn('value="openid email"', page)


class AStoredSourceNeedsAnAddressTest(ConfigTestCase):
    """A source is where a query goes, and a row without an address is a row
    that answers nothing while looking configured."""

    def test_a_stored_source_can_never_have_an_empty_url(self):
        from wdash.store.sources import SourceError
        with self.assertRaises(SourceError):
            self.app.store.sources.create(
                name="empty", signal=["logs"], kind="elasticsearch",
                config={"url": "", "verify_certs": False})


class SignalFormTest(ConfigTestCase):
    """The form has to offer every signal the catalogue declares.

    `signal_map` was derived from SOURCE_KINDS with a comment saying a copy in
    JavaScript would give the product two answers to one question. The
    checkboxes beside it were hand-written — two of them — so adding
    `monitors` to the catalogue produced a page that knew about a signal and
    could not offer it. The Monitors screen then said "no monitor source is
    configured", which was true and unfixable from the configuration page.
    """

    def _page(self):
        return self.client.get("/admin/config").get_data(as_text=True)

    def test_every_declared_signal_has_a_checkbox(self):
        from wdash.store.sources import SOURCE_KINDS
        body = self._page()
        declared = {signal for kind in SOURCE_KINDS.values()
                    for signal in kind["signals"]}
        missing = sorted(s for s in declared
                         if f'data-signal="{s}"' not in body)
        self.assertEqual(missing, [], f"no checkbox for: {missing}")

    def test_the_map_the_form_reads_matches_the_catalogue(self):
        from wdash.store.sources import SOURCE_KINDS
        import json
        import re
        body = self._page()
        match = re.search(r'id="sourceSignals"[^>]*>\s*(\{.*?\})\s*</script>',
                          body, re.S)
        self.assertIsNotNone(match, "the page ships no signal map")
        served = json.loads(match.group(1))
        self.assertEqual(
            served, {k: list(v["signals"]) for k, v in SOURCE_KINDS.items()})

    def test_a_signal_with_per_signal_fields_has_somewhere_to_put_them(self):
        """A signal that can be ticked but has no index-pattern box saves a
        source pointing at whatever the default is, with no way to say
        otherwise."""
        body = self._page()
        for signal in ("logs", "traces", "monitors"):
            self.assertIn(f'data-needs="{signal}"', body,
                          f"{signal} can be ticked with nowhere to configure it")

    def test_a_source_can_be_saved_serving_all_three(self):
        response = self.client.post("/admin/sources", data={
            "name": "cluster", "kind": "elasticsearch",
            "signals": ["logs", "traces", "monitors"],
            "url": "http://cluster:9200", "enabled": "on",
            "logs_index_patterns": "app-*",
            "traces_index_patterns": "*apm*",
            "monitors_index_patterns": "heartbeat-*",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        row = next(r for r in self.app.store.sources.all()
                   if r["name"] == "cluster")
        self.assertEqual(row["signals"], ["logs", "traces", "monitors"])
        self.assertEqual(row["config"]["monitors"]["index_patterns"],
                         ["heartbeat-*"])

    def test_a_field_the_form_does_not_carry_is_not_saved_blank(self):
        """The save writes every per-signal field the catalogue declares,
        whatever the form sent. The modal has one exclude box —
        `logs_exclude_patterns` — so an edit made to rename a source, or to
        rotate its password, silently emptied `traces.exclude_patterns` and
        `monitors.exclude_patterns`. The same shape as the monitor pattern
        box, one field further along: a field the editor does not fill is a
        field saved empty.

        A box that IS on the form and left empty still means empty. The
        difference is between "" and the field not being submitted at all.
        """
        row = self.app.store.sources.create(
            name="cluster", signal=["logs", "traces"], kind="elasticsearch",
            config={"url": "http://cluster:9200",
                    "logs": {"index_patterns": ["app-*"],
                             "exclude_patterns": ["*audit*"]},
                    "traces": {"index_patterns": ["*traces*"],
                               "exclude_patterns": ["*-pii-*"]}})

        # Exactly the fields the page's form carries, nothing more.
        self.client.post("/admin/sources", data={
            "id": row["id"], "name": "cluster", "kind": "elasticsearch",
            "signals": ["logs", "traces"], "url": "http://cluster:9200",
            "enabled": "on", "logs_index_patterns": "app-*",
            "traces_index_patterns": "*traces*", "logs_exclude_patterns": "",
        }, follow_redirects=True)

        stored = self.app.store.sources.get(row["id"])["config"]
        self.assertEqual(stored["traces"].get("exclude_patterns"), ["*-pii-*"])
        self.assertEqual(stored["traces"].get("index_patterns"), ["*traces*"])
        # The box the form does have, cleared on purpose, is cleared.
        self.assertEqual(stored["logs"].get("exclude_patterns"), [])

    def test_saving_it_registers_a_monitor_adapter(self):
        """Stored and unreachable is worse than absent: the configuration page
        says it is there."""
        from wdash.hub import Hub
        from wdash.hub.factory import register_configured_sources

        self.client.post("/admin/sources", data={
            "name": "cluster", "kind": "elasticsearch",
            "signals": ["logs", "monitors"],
            "url": "http://cluster:9200", "enabled": "on",
            "logs_index_patterns": "app-*",
            "monitors_index_patterns": "",
        }, follow_redirects=True)

        hub = Hub()
        register_configured_sources(hub, self.app.store)
        self.assertEqual([s.name for s in hub.monitor_sources], ["cluster"])
        # Left empty, it must fall back to Heartbeat's own names rather than
        # to `*`, which would read every index in the cluster to find nothing.
        self.assertEqual(hub.monitor_sources[0]._patterns,
                         ("heartbeat-*", "synthetics-*"))


class ShadowedSourcesAreMarkedOnThePageTest(ConfigTestCase):
    """Two sources sharing a name within one signal, as the page shows them.

    `SourceRepository` refuses to make the pair now, and migration 15 reports
    the pairs a store already had — once, at upgrade time. Neither covers a
    collision that arrives afterwards: a pg_restore, an UPDATE run straight
    against the database, an older node still writing rows. The page listed
    both as ordinary healthy sources, and a trace search quietly answered
    from one of them, so the only signal was a log line at the next hub
    reload. A failure has to reach the screen it is about.
    """

    ELASTIC = {"url": "http://cluster:9200",
               "logs": {"index_patterns": ["app-*"]},
               "traces": {"index_patterns": ["*apm*"]}}

    def shadow(self, name="prod", signals=("traces",), enabled=True,
               identifier="shadow-one"):
        """A row written the way the things that produce this write it:
        straight into the table, past the repository's refusal."""
        from datetime import datetime, timezone

        from wdash.store.schema import sources

        now = datetime.now(timezone.utc)
        with self.app.store.engine.begin() as connection:
            connection.execute(sources.insert().values(
                id=identifier, name=name, kind="jaeger",
                signal=list(signals)[0], signals=list(signals),
                config={"url": "http://jaeger:16686"}, secrets=None,
                enabled=enabled, created_at=now, updated_at=now))

    def page(self):
        return self.client.get("/admin/config").get_data(as_text=True)

    def test_both_rows_of_a_colliding_pair_are_marked(self):
        self.app.store.sources.create(
            name="prod", signal=["logs", "traces"], kind="elasticsearch",
            config=dict(self.ELASTIC))
        self.shadow()
        body = self.page()
        self.assertEqual(body.count("only one of these answers a traces"), 2,
                         "both rows of the pair have to say it")

    def test_a_page_with_no_collision_says_nothing(self):
        self.app.store.sources.create(
            name="prod", signal=["logs", "traces"], kind="elasticsearch",
            config=dict(self.ELASTIC))
        self.assertNotIn("only one of these answers", self.page())

    def test_the_legacy_pair_is_not_marked(self):
        """One row for logs and one for traces sharing a name is the shape
        migration 7 left on purpose. Neither shadows the other."""
        self.app.store.sources.create(
            name="eu", signal=["logs"], kind="elasticsearch",
            config={"url": "http://cluster:9200",
                    "logs": {"index_patterns": ["app-*"]}})
        self.shadow(name="eu")
        self.assertNotIn("only one of these answers", self.page())

    def test_a_switched_off_row_shadows_nothing(self):
        """Only enabled rows are built into adapters, so a disabled twin is
        not answering in anybody's place — saying it is would be the same
        kind of untrue sentence in the other direction."""
        self.app.store.sources.create(
            name="prod", signal=["logs", "traces"], kind="elasticsearch",
            config=dict(self.ELASTIC))
        self.shadow(enabled=False)
        self.assertNotIn("only one of these answers", self.page())
