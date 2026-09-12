"""
Local accounts, from the product.

WDash has had a local account table since the first commit and no screen for
it: an account could be made by first-run setup or by `python -m
wdash.store.recover`, and after that nobody could see who held one, what role
it had, or whether one left over from a contractor was still enabled. The
break-glass path was the one door with no window.

What these tests hold:

  * `system:admin` on every route, including the ones that only read
  * a password is written and never rendered, never logged, never audited
  * the installation cannot be left without an enabled local account that can
    administer — and an administrator cannot do it to themselves
  * every change writes an audit row, refusals included, and a refusal saves
    nothing
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store import SecretBox  # noqa: E402

PASSWORD = "a-sufficiently-long-password"
OTHER = "another-sufficiently-long-one"


class AccountPageTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)

        database, key = self.database, SecretBox.generate_key()

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "local-accounts"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = key
            OIDC_CLIENT_ID = None

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.client.post("/setup", data={
            "username": "owner", "password": PASSWORD, "confirm": PASSWORD})

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    # ---------- helpers ----------

    def create(self, username="bob", role="viewer", password=OTHER,
               confirm=None, email=""):
        return self.client.post("/admin/accounts", data={
            "username": username, "role": role, "email": email,
            "password": password,
            "confirm": password if confirm is None else confirm},
            follow_redirects=True)

    def save(self, username, role, enabled=True):
        form = {"role": role}
        if enabled:
            form["enabled"] = "on"
        return self.client.post(f"/admin/accounts/{username}", data=form,
                                follow_redirects=True)

    def second_administrator(self, username="spare"):
        """Another enabled account that can administer, so the invariants
        stop being the thing under test."""
        self.app.store.users.create(username, OTHER, "admin")
        return username

    def audit_actions(self):
        return [row["action"] for row in self.app.store.audit.recent(limit=50)]

    def demote(self):
        """Take system:admin away from the signed-in account."""
        self.app.store.roles.upsert(
            "admin", permissions=["logs:read"], containers=["*"],
            trace_containers=["*"])
        self.app.store.rbac.invalidate()


class AccessTest(AccountPageTestCase):
    def test_every_account_route_needs_the_admin_permission(self):
        """A page guard is not a route guard: the write routes are where the
        damage is, and they are reachable without rendering the page.

        Each one is sent a form that WOULD work, so what is measured is that
        nothing changed — not that a malformed request was turned away, which
        a route with no guard at all does just as well.
        """
        self.second_administrator()
        self.demote()
        fresh = "a-completely-different-password"
        attempts = (
            ("/admin/accounts", {"username": "intruder", "role": "admin",
                                 "password": OTHER, "confirm": OTHER}),
            # No `enabled`, so this save would disable the account.
            ("/admin/accounts/spare", {"role": "admin"}),
            ("/admin/accounts/spare/password", {"password": fresh,
                                                "confirm": fresh}),
            ("/admin/accounts/spare/delete", {}),
        )
        for path, form in attempts:
            response = self.client.post(path, data=form)
            self.assertEqual(response.status_code, 302, path)

        self.assertIsNone(self.app.store.users.by_username("intruder"),
                          "the account was created")
        spare = self.app.store.users.by_username("spare")
        self.assertIsNotNone(spare, "the account was deleted")
        self.assertFalse(spare["disabled"], "the save went through")
        self.assertIsNone(self.app.store.users.verify("spare", fresh),
                          "the password was reset")

    def test_signing_out_is_not_a_way_round_it(self):
        self.client.get("/auth/logout")
        response = self.client.post("/admin/accounts", data={
            "username": "intruder", "role": "admin", "password": OTHER,
            "confirm": OTHER})
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.app.store.users.by_username("intruder"))


class ListingTest(AccountPageTestCase):
    def test_the_page_lists_the_accounts_that_exist(self):
        self.create(username="bob", role="viewer", email="bob@example.com")
        page = self.client.get("/admin/config").data.decode()
        self.assertIn("Local accounts", page)
        self.assertIn("bob@example.com", page)
        self.assertIn("owner", page)

    def test_a_password_hash_never_reaches_the_page(self):
        stored = self.app.store.users.by_username("owner")["password_hash"]
        page = self.client.get("/admin/config").data.decode()
        self.assertNotIn(stored, page)
        self.assertNotIn("$argon2", page)

    def test_an_account_that_never_signed_in_says_so(self):
        self.create(username="bob")
        page = self.client.get("/admin/config").data.decode()
        self.assertIn("never", page)

    def test_deleting_takes_the_confirmation_the_other_buttons_take(self):
        """Whatever a person cannot recover from must not be one click."""
        self.create(username="bob")
        page = self.client.get("/admin/config").data.decode()
        self.assertIn('action="/admin/accounts/bob/delete"', page)
        tag = page.split('action="/admin/accounts/bob/delete"')[1].split(">")[0]
        self.assertIn("data-confirm", tag)

    def test_a_mapping_that_names_an_account_says_the_account_wins(self):
        """The two can disagree and the reader cannot see why: a local
        account's own role is what the resolver reads first."""
        self.create(username="bob", role="viewer")
        self.app.store.settings.set("rbac.user_roles", {"bob": "admin"})
        page = self.client.get("/admin/config").data.decode()
        self.assertIn("The role chosen here wins", page)

    def test_nothing_is_said_about_a_mapping_that_does_not_exist(self):
        self.create(username="bob", role="viewer")
        page = self.client.get("/admin/config").data.decode()
        self.assertNotIn("The role chosen here wins", page)

    def test_the_role_select_offers_the_roles_that_exist(self):
        self.app.store.roles.upsert("auditor", permissions=["logs:read"],
                                    containers=[], trace_containers=[])
        page = self.client.get("/admin/config").data.decode()
        self.assertIn('<option value="auditor"', page)


class CreateTest(AccountPageTestCase):
    def test_an_account_is_created_and_can_sign_in(self):
        self.create(username="Bob", role="viewer")
        account = self.app.store.users.by_username("bob")
        self.assertIsNotNone(account, "usernames are folded to lower case")
        self.assertEqual(account["role"], "viewer")
        self.assertFalse(account["disabled"])
        self.assertIsNotNone(self.app.store.users.verify("bob", OTHER))

    def test_it_is_audited_without_the_password_or_its_hash(self):
        self.create(username="bob")
        row = self.app.store.audit.recent(limit=1)[0]
        self.assertEqual(row["action"], "account created")
        self.assertEqual(row["subject"], "user:bob")
        self.assertNotIn("password_hash", row["state"])
        self.assertNotIn(OTHER, str(row["state"]))

    def test_a_short_password_is_refused_with_the_reason(self):
        response = self.create(username="bob", password="short")
        self.assertIn(b"12 characters", response.data)
        self.assertIsNone(self.app.store.users.by_username("bob"))

    def test_mismatched_passwords_are_refused(self):
        self.create(username="bob", password=OTHER, confirm="something-else")
        self.assertIsNone(self.app.store.users.by_username("bob"))

    def test_a_name_that_is_taken_is_refused_rather_than_replacing_it(self):
        before = self.app.store.users.by_username("owner")["password_hash"]
        response = self.create(username="owner", role="viewer")
        self.assertIn(b"already taken", response.data)
        after = self.app.store.users.by_username("owner")
        self.assertEqual(after["password_hash"], before)
        self.assertEqual(after["role"], "admin")

    def test_a_role_that_does_not_exist_is_refused(self):
        """A role nothing defines grants nothing, silently: the account would
        land on the default role with nothing on any page to say why."""
        response = self.create(username="bob", role="does-not-exist")
        self.assertIn(b"no role called", response.data)
        self.assertIsNone(self.app.store.users.by_username("bob"))

    def test_a_blank_username_is_refused(self):
        self.create(username="   ")
        self.assertEqual(len(self.app.store.users.all()), 1)


class SaveTest(AccountPageTestCase):
    def test_a_role_change_is_saved_and_reaches_the_resolver(self):
        self.create(username="bob", role="viewer")
        self.save("bob", "admin")
        self.assertEqual(self.app.store.users.by_username("bob")["role"],
                         "admin")
        # Not the column alone: what the account can DO has to have changed,
        # and that is the resolver's answer.
        self.assertIn("system:admin", self.app.store.rbac.resolve(
            email=None, username="bob", groups=[], explicit="admin")
            .get("permissions"))

    def test_disabling_stops_the_account_signing_in(self):
        self.create(username="bob", role="viewer")
        self.save("bob", "viewer", enabled=False)
        self.assertTrue(self.app.store.users.by_username("bob")["disabled"])
        self.assertIsNone(self.app.store.users.verify("bob", OTHER))

    def test_re_enabling_lets_it_sign_in_again(self):
        self.create(username="bob", role="viewer")
        self.save("bob", "viewer", enabled=False)
        self.save("bob", "viewer", enabled=True)
        self.assertIsNotNone(self.app.store.users.verify("bob", OTHER))

    def test_every_save_is_audited_with_what_it_left_behind(self):
        self.create(username="bob", role="viewer")
        self.save("bob", "admin", enabled=False)
        row = self.app.store.audit.recent(limit=1)[0]
        self.assertEqual(row["action"], "account saved")
        self.assertEqual(row["subject"], "user:bob")
        self.assertEqual(row["state"]["role"], "admin")
        self.assertTrue(row["state"]["disabled"])
        self.assertNotIn("password_hash", row["state"])

    def test_a_role_that_does_not_exist_is_refused(self):
        self.create(username="bob", role="viewer")
        self.save("bob", "does-not-exist")
        self.assertEqual(self.app.store.users.by_username("bob")["role"],
                         "viewer")

    def test_an_account_that_is_gone_is_said_rather_than_500(self):
        response = self.save("ghost", "viewer")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"no local account called", response.data)


class PasswordTest(AccountPageTestCase):
    def test_a_reset_takes_effect(self):
        self.create(username="bob", role="viewer")
        self.client.post("/admin/accounts/bob/password", data={
            "password": "a-brand-new-long-password",
            "confirm": "a-brand-new-long-password"}, follow_redirects=True)
        self.assertIsNone(self.app.store.users.verify("bob", OTHER))
        self.assertIsNotNone(
            self.app.store.users.verify("bob", "a-brand-new-long-password"))

    def test_the_new_password_is_never_audited(self):
        self.create(username="bob", role="viewer")
        secret = "a-brand-new-long-password"
        self.client.post("/admin/accounts/bob/password", data={
            "password": secret, "confirm": secret}, follow_redirects=True)
        row = self.app.store.audit.recent(limit=1)[0]
        self.assertEqual(row["action"], "account password reset")
        self.assertNotIn(secret, str(row))
        self.assertNotIn("password_hash", str(row["state"]))

    def test_a_short_one_is_refused_and_the_old_one_still_works(self):
        self.create(username="bob", role="viewer")
        response = self.client.post("/admin/accounts/bob/password", data={
            "password": "short", "confirm": "short"}, follow_redirects=True)
        self.assertIn(b"12 characters", response.data)
        self.assertIsNotNone(self.app.store.users.verify("bob", OTHER))

    def test_mismatched_passwords_are_refused(self):
        self.create(username="bob", role="viewer")
        self.client.post("/admin/accounts/bob/password", data={
            "password": "a-brand-new-long-password",
            "confirm": "a-different-long-password"}, follow_redirects=True)
        self.assertIsNotNone(self.app.store.users.verify("bob", OTHER))

    def test_resetting_your_own_password_is_allowed(self):
        """The invariant asks the same question with no edit in it, and must
        not read "unchanged" as "demoted"."""
        self.client.post("/admin/accounts/owner/password", data={
            "password": "a-brand-new-long-password",
            "confirm": "a-brand-new-long-password"}, follow_redirects=True)
        self.assertIsNotNone(
            self.app.store.users.verify("owner", "a-brand-new-long-password"))


class DeleteTest(AccountPageTestCase):
    def test_an_account_is_deleted_and_audited(self):
        self.create(username="bob", role="viewer")
        self.client.post("/admin/accounts/bob/delete", follow_redirects=True)
        self.assertIsNone(self.app.store.users.by_username("bob"))
        row = self.app.store.audit.recent(limit=1)[0]
        self.assertEqual(row["action"], "account deleted")
        self.assertNotIn("password_hash", row["state"])

    def test_an_account_that_is_gone_is_said_rather_than_500(self):
        response = self.client.post("/admin/accounts/ghost/delete",
                                    follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"no local account called", response.data)


class OpenSessionTest(AccountPageTestCase):
    """What a change here does to somebody already signed in.

    A local account's role used to be written into the session cookie at
    sign-in and never read again — the same frozen authorization that moving
    permissions out of the session was meant to end. It is the ONE role that
    wins the resolver's order, so a demotion changed nothing until the person
    happened to sign out, and the refusal that says "this would lock you out
    immediately" was not true.
    """

    def bob(self, role="admin"):
        self.create(username="bob", role=role)
        client = self.app.test_client()
        client.post("/auth/login", data={"username": "bob",
                                         "password": OTHER})
        return client

    def test_a_demotion_reaches_a_session_that_is_already_open(self):
        client = self.bob()
        self.assertEqual(client.get("/admin/config").status_code, 200)
        self.save("bob", "viewer")
        self.assertEqual(client.get("/admin/config").status_code, 302)

    def test_a_promotion_reaches_it_too(self):
        client = self.bob(role="viewer")
        self.assertEqual(client.get("/admin/config").status_code, 302)
        self.save("bob", "admin")
        self.assertEqual(client.get("/admin/config").status_code, 200)

    def test_disabling_ends_a_session_that_is_already_open(self):
        """Half a switch otherwise, and it is the half somebody reaches for
        when an account is being abused."""
        client = self.bob()
        self.save("bob", "admin", enabled=False)
        response = client.get("/logs")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_deleting_ends_a_session_that_is_already_open(self):
        client = self.bob()
        self.client.post("/admin/accounts/bob/delete", follow_redirects=True)
        self.assertEqual(client.get("/logs").status_code, 302)

    def test_a_directory_session_is_not_asked_about_a_local_account(self):
        """Only a session that came through a local account reads one. A
        directory principal has no stored role, and looking one up by name
        would hand it whatever a local account of that name holds."""
        self.create(username="bob", role="viewer")
        with self.client.session_transaction() as session:
            session["user_data"] = {**session["user_data"],
                                    "username": "bob", "local_role": None,
                                    "provider": "oidc"}
        self.app.store.settings.set("rbac.user_roles", {"bob": "admin"})
        self.app.store.rbac.invalidate()
        self.assertEqual(self.client.get("/admin/config").status_code, 200)


class InvariantTest(AccountPageTestCase):
    """The refusals, through the routes: a message naming what would break,
    an audit row, and nothing saved."""

    def test_the_last_administrator_cannot_be_demoted(self):
        self.create(username="bob", role="viewer")
        # Signed in as bob's directory-free equivalent would not help; this is
        # about the installation, so ask as somebody else entirely.
        self.app.store.users.create("other", OTHER, "admin")
        self.save("other", "viewer")
        self.save("owner", "viewer")
        self.assertEqual(self.app.store.users.by_username("owner")["role"],
                         "admin", "nothing was saved")
        self.assertIn("account save refused", self.audit_actions())

    def test_the_refusal_says_what_would_break_and_what_to_do(self):
        self.app.store.users.create("other", OTHER, "admin")
        self.save("other", "viewer")
        response = self.save("owner", "viewer")
        self.assertIn(b"only local account", response.data)
        self.assertIn(b"way back in", response.data)
        self.assertIn(b"administering role first", response.data)

    def test_the_last_administrator_cannot_be_disabled(self):
        self.save("owner", "admin", enabled=False)
        self.assertFalse(self.app.store.users.by_username("owner")["disabled"])

    def test_the_last_administrator_cannot_be_deleted(self):
        response = self.client.post("/admin/accounts/owner/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.users.by_username("owner"))
        self.assertIn(b"only local account", response.data)
        self.assertIn("account delete refused", self.audit_actions())

    def test_you_cannot_demote_yourself_even_with_a_spare_administrator(self):
        self.second_administrator()
        response = self.save("owner", "viewer")
        self.assertIn(b"the account you are signed in with", response.data)
        self.assertEqual(self.app.store.users.by_username("owner")["role"],
                         "admin")

    def test_you_cannot_disable_yourself(self):
        self.second_administrator()
        self.save("owner", "admin", enabled=False)
        self.assertFalse(self.app.store.users.by_username("owner")["disabled"])

    def test_you_cannot_delete_yourself(self):
        self.second_administrator()
        response = self.client.post("/admin/accounts/owner/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.users.by_username("owner"))
        self.assertIn(b"lock you out", response.data)

    def test_another_administrator_may_be_demoted(self):
        self.second_administrator()
        self.save("spare", "viewer")
        self.assertEqual(self.app.store.users.by_username("spare")["role"],
                         "viewer")

    def test_the_last_account_of_all_cannot_be_deleted_either(self):
        """The repository's own rule, reached where the invariant says
        nothing: a directory administrator deleting the one local account,
        which is a viewer. Nobody is losing administration — and an
        installation with no local account at all cannot be reached when the
        directory stops answering, which is what that account is for."""
        self.app.store.settings.set("rbac.user_roles", {"owner": "admin"})
        self.app.store.users.set_role("owner", "viewer")
        self.app.store.rbac.invalidate()
        # The same person, arriving through the directory instead: a session
        # carries which door it came through, and this rule turns on that.
        with self.client.session_transaction() as session:
            # Reassigned whole: mutating the dict in place does not mark the
            # session modified, so the cookie goes back out unchanged.
            session["user_data"] = {**session["user_data"],
                                    "local_role": None, "provider": "oidc"}

        response = self.client.post("/admin/accounts/owner/delete",
                                    follow_redirects=True)
        self.assertIsNotNone(self.app.store.users.by_username("owner"))
        self.assertIn(b"last local account", response.data)
        self.assertIn("account delete refused", self.audit_actions())


if __name__ == "__main__":
    unittest.main(verbosity=2)
