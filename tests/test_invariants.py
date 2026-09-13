"""
Changes that must not be allowed to succeed.

Not permission checks — those decide whether *you* may act. These decide
whether the resulting system is still operable, whoever is asking. An
administrator holding every permission still must not be able to leave the
installation with nobody able to administer it.

The hazard is specific: `system:admin` is not a superuser. It gates the
administration tools and nothing else, so no other permission can recover from
its loss. Once the last role carrying it is gone, the only way back is the
database — which is why `wdash.store.recover` exists as well.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.invariants import (  # noqa: E402
    refuses_account_change, refuses_directory_off, refuses_mapping_save,
    refuses_role_delete, refuses_role_save,
)


def role(name, *permissions, groups=()):
    return {"name": name, "permissions": list(permissions),
            "groups": list(groups)}


ADMIN = role("admin", "system:admin", "logs:read")
CO_ADMIN = role("co-admin", "system:admin")
VIEWER = role("viewer", "logs:read")


def local(role_name, username="owner"):
    """A local account holding `role_name`: its stored role comes first."""
    return {"username": username, "local_role": role_name}


def person(username="alice", email=None, groups=()):
    """A directory or OIDC principal: no stored role, only identity."""
    return {"username": username, "email": email, "groups": list(groups)}


class RoleSaveTest(unittest.TestCase):
    def test_an_ordinary_edit_is_allowed(self):
        self.assertIsNone(refuses_role_save(
            [ADMIN, VIEWER], "viewer", ["logs:read", "traces:read"],
            local("admin")))

    def test_the_last_administrator_role_cannot_drop_the_permission(self):
        refusal = refuses_role_save([ADMIN, VIEWER], "admin", ["logs:read"],
                                    local("admin"))
        self.assertIsNotNone(refusal)
        self.assertIn("only role that can administer", refusal)

    def test_it_can_once_another_role_carries_it(self):
        """The system stays operable, so only the personal guard is left."""
        refusal = refuses_role_save([ADMIN, CO_ADMIN], "admin", ["logs:read"],
                                    local("co-admin"))
        self.assertIsNone(refusal)

    def test_you_still_cannot_remove_it_from_your_own_role(self):
        refusal = refuses_role_save([ADMIN, CO_ADMIN], "admin", ["logs:read"],
                                    local("admin"))
        self.assertIsNotNone(refusal)
        self.assertIn("lock you out", refusal)

    def test_the_system_message_comes_before_the_personal_one(self):
        """'Nobody could administer' says what is wrong; 'you would be locked
        out' says what it means for you. The first is more useful."""
        refusal = refuses_role_save([ADMIN], "admin", ["logs:read"],
                                    local("admin"))
        self.assertIn("only role that can administer", refusal)

    def test_creating_a_new_role_without_admin_is_fine(self):
        self.assertIsNone(refuses_role_save(
            [ADMIN], "auditor", ["logs:read"], local("admin")))

    def test_taking_your_own_group_off_your_role_is_refused(self):
        """A directory administrator is one because a role lists their group.
        Taking the group off locks them out as surely as taking the
        permission off, and the old rule only looked at permissions."""
        roles = [role("admin", "system:admin", groups=["wdash-admins"]),
                 CO_ADMIN, VIEWER]
        refusal = refuses_role_save(
            roles, "admin", ["system:admin"],
            person(groups=["wdash-admins"]), groups=[],
            default_role="viewer")
        self.assertIsNotNone(refusal)
        self.assertIn("lock you out", refusal)

    def test_another_persons_group_can_come_off(self):
        roles = [role("admin", "system:admin",
                      groups=["wdash-admins", "contractors"]), VIEWER]
        self.assertIsNone(refuses_role_save(
            roles, "admin", ["system:admin"],
            person(groups=["wdash-admins"]), groups=["wdash-admins"],
            default_role="viewer"))


class RoleDeleteTest(unittest.TestCase):
    def test_the_last_role_cannot_go(self):
        self.assertIn("last role",
                      refuses_role_delete([ADMIN], "admin", local("admin")))

    def test_the_only_administrator_role_cannot_go(self):
        refusal = refuses_role_delete([ADMIN, VIEWER], "admin",
                                      local("viewer"))
        self.assertIn("only role that can administer", refusal)

    def test_your_own_role_cannot_go(self):
        refusal = refuses_role_delete([ADMIN, CO_ADMIN, VIEWER], "admin",
                                      local("admin"))
        self.assertIn("lock you out", refusal)

    def test_another_role_can(self):
        self.assertIsNone(refuses_role_delete(
            [ADMIN, CO_ADMIN, VIEWER], "viewer", local("admin"),
            default_role="co-admin"))

    def test_the_default_role_cannot_go(self):
        """With the default gone, the page selected its first role for the
        default — `admin` — and the next save made everybody unmapped an
        administrator."""
        refusal = refuses_role_delete(
            [ADMIN, CO_ADMIN, VIEWER], "viewer", local("admin"),
            default_role="viewer")
        self.assertIn("default role", refusal)

    def test_a_role_mappings_still_give_cannot_go(self):
        refusal = refuses_role_delete(
            [ADMIN, CO_ADMIN, VIEWER], "co-admin", local("admin"),
            default_role="viewer",
            user_roles={"bob": "co-admin", "carol": "viewer"})
        self.assertIn("bob", refusal)
        self.assertNotIn("carol", refusal)

    def test_a_role_a_local_account_holds_cannot_go(self):
        refusal = refuses_role_delete(
            [ADMIN, CO_ADMIN, VIEWER], "co-admin", local("admin"),
            default_role="viewer",
            local_accounts=[{"username": "breakglass", "role": "co-admin"}])
        self.assertIn("breakglass", refusal)

    def test_a_disabled_local_account_does_not_hold_it(self):
        self.assertIsNone(refuses_role_delete(
            [ADMIN, CO_ADMIN, VIEWER], "co-admin", local("admin"),
            default_role="viewer",
            local_accounts=[{"username": "old", "role": "co-admin",
                             "disabled": True}]))


class MappingTest(unittest.TestCase):
    """The third way to lose administration, and the least obvious."""

    def test_reassigning_yourself_to_a_lesser_role_is_refused(self):
        refusal = refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer",
            mappings={"alice": "viewer"},
            actor=person("alice", "alice@example.com"))
        self.assertIn("lose access", refusal)

    def test_changing_the_default_is_refused_when_it_would_move_you(self):
        refusal = refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer", mappings={},
            actor=person("alice"))
        self.assertIsNotNone(refusal)

    def test_a_local_account_is_exempt(self):
        """Its role is stored with the account and beats every mapping — which
        is exactly what makes it the way back in."""
        self.assertIsNone(refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer", mappings={},
            actor=local("admin")))

    def test_a_local_role_that_no_longer_exists_is_not_an_exemption(self):
        self.assertIsNotNone(refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer", mappings={},
            actor=local("deleted-role")))

    def test_mapping_yourself_to_an_administrator_role_is_fine(self):
        self.assertIsNone(refuses_mapping_save(
            [ADMIN, CO_ADMIN, VIEWER], default_role="viewer",
            mappings={"alice": "co-admin"}, actor=person("alice")))

    def test_an_administrator_by_group_may_change_the_default(self):
        """They were refused: the old rule never looked at groups, decided
        they would land on the new default, and blocked a harmless edit."""
        roles = [role("admin", "system:admin", groups=["wdash-admins"]),
                 VIEWER]
        self.assertIsNone(refuses_mapping_save(
            roles, default_role="viewer", mappings={},
            actor=person("alice", groups=["wdash-admins"])))

    def test_your_email_is_read_before_your_username(self):
        """The resolver reads the email first. The old rule read the username
        first, so mapping your email to a lesser role was allowed while your
        username still pointed at admin — and on the next request the
        resolver put you on the lesser role."""
        refusal = refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer",
            mappings={"alice@example.com": "viewer", "alice": "admin"},
            actor=person("alice", "alice@example.com"))
        self.assertIsNotNone(refusal)


class TheRulesAskTheResolverTest(unittest.TestCase):
    """Two copies of the order is how the invariants came to disagree with
    the resolver. There is one now; this holds the resolver to it."""

    def test_the_resolver_answers_with_the_shared_rule(self):
        from unittest import mock

        from wdash.store.rbac import RoleResolver, choose_role

        roles = mock.Mock()
        roles.all.return_value = [
            role("admin", "system:admin", groups=["wdash-admins"]), VIEWER]
        settings = mock.Mock()
        settings.get.side_effect = lambda key, default=None: {
            "rbac.default_role": "viewer",
            "rbac.user_roles": {"alice@example.com": "viewer"},
        }.get(key, default)
        resolver = RoleResolver(roles, settings)

        # Each with the answer written down, not recomputed: a comparison
        # of choose_role with itself would move with it and prove nothing
        # about the order.
        cases = [
            # a direct mapping beats a group
            (dict(email="alice@example.com", username="alice",
                  groups=["wdash-admins"]), "viewer"),
            # a group beats the default
            (dict(email=None, username="bob", groups=["wdash-admins"]),
             "admin"),
            # nothing matches: the default
            (dict(email=None, username="carol", groups=[]), "viewer"),
            # a local account's own role beats everything
            (dict(email="alice@example.com", username="owner", groups=[],
                  explicit="admin"), "admin"),
            # the email is read before the username
            (dict(email="dave@example.com", username="dave", groups=[]),
             "viewer"),
        ]
        user_roles = {"alice@example.com": "viewer",
                      "dave@example.com": "viewer", "dave": "admin"}
        settings.get.side_effect = lambda key, default=None: {
            "rbac.default_role": "viewer", "rbac.user_roles": user_roles,
        }.get(key, default)
        resolver.invalidate()
        by_name = {r["name"]: r for r in roles.all.return_value}
        for case, expected in cases:
            with self.subTest(**case):
                self.assertEqual(
                    choose_role(by_name, user_roles, "viewer", **case),
                    expected)
                self.assertEqual(resolver.role_for(**case), expected)


def account(username="owner", role_name="admin", disabled=False):
    return {"username": username, "role": role_name, "disabled": disabled}


class DirectoryOffTest(unittest.TestCase):
    """The fourth way to lose administration, and the one the one-directory
    rule creates: with at most one directory signing people in, turning it off
    takes every non-local administrator with it."""

    ROLES = [ADMIN, VIEWER]

    def arrived(self, provider, **extra):
        return {**person("alice", groups=["wdash-admins"]),
                "provider": provider, **extra}

    def test_a_local_administrator_may_always_turn_it_off(self):
        self.assertIsNone(refuses_directory_off(
            "ldap", {**local("admin"), "provider": "local account"},
            self.ROLES, [account()]))

    def test_an_enabled_local_administrator_is_enough(self):
        self.assertIsNone(refuses_directory_off(
            "ldap", self.arrived("directory"), self.ROLES, [account()]))

    def test_with_the_only_local_administrator_disabled_it_is_refused(self):
        refusal = refuses_directory_off(
            "ldap", self.arrived("directory"), self.ROLES,
            [account(disabled=True)])
        self.assertIsNotNone(refusal)
        self.assertIn("nobody able to open this page", refusal)
        self.assertIn("--enable owner", refusal,
                      "a refusal whose way out cannot be taken is a lockout")

    def test_a_local_account_that_cannot_administer_is_not_a_way_back(self):
        refusal = refuses_directory_off(
            "ldap", self.arrived("directory"), self.ROLES,
            [account(role_name="viewer")])
        self.assertIsNotNone(refusal)
        self.assertIn("--grant-admin", refusal)

    def test_arriving_through_the_other_directory_is_allowed(self):
        """She is the person who should be able to resolve the conflict in
        her own favour, and the session says which door she used rather than
        the rule guessing from "not local"."""
        self.assertIsNone(refuses_directory_off(
            "ldap", self.arrived("oidc"), self.ROLES,
            [account(disabled=True)]))
        self.assertIsNotNone(refuses_directory_off(
            "oidc", self.arrived("oidc"), self.ROLES,
            [account(disabled=True)]))

    def test_the_other_directory_taking_over_is_a_switch_not_a_lockout(self):
        """Both stored and enabled, no enabled local administrator, and she
        arrived through the one in force. Turning it off hands the
        installation to the other one on the same save — that is the switch,
        and on a conflicted installation it is the only in-page direction
        there is, because enabling the other one is refused by the
        one-directory rule. Measured before this: refused, in a sentence that
        said nobody would be able to open this page."""
        self.assertIsNone(refuses_directory_off(
            "oidc", self.arrived("oidc"), self.ROLES, [account(disabled=True)],
            {"name": "ldap", "unusable": None}))

    def test_a_takeover_that_cannot_be_used_is_still_a_lockout(self):
        """The other half of the same question: a directory that takes over
        and does not work leaves the same nobody, so the rule still refuses —
        but it says what is actually wrong rather than reusing the sentence
        for a case this is not."""
        refusal = refuses_directory_off(
            "oidc", self.arrived("oidc"), self.ROLES, [account(disabled=True)],
            {"name": "ldap", "unusable": "a server and a base DN are both "
                                         "required and one of them is blank"})
        self.assertIsNotNone(refusal)
        self.assertIn("hand this installation to LDAP", refusal)
        self.assertIn("one of them is blank", refusal)

    def test_a_session_that_does_not_say_is_refused_without_claiming(self):
        """Written before the provider was recorded. Refuse conservatively,
        but do not tell her she used a door she may not have used."""
        refusal = refuses_directory_off("ldap", self.arrived(None), self.ROLES,
                                        [account(disabled=True)])
        self.assertIsNotNone(refusal)
        self.assertNotIn("you signed in through", refusal.lower())
        self.assertIn("did not sign in with a local account", refusal)


class RecoveryToolTest(unittest.TestCase):
    """"Impossible" is a claim about code that has been reasoned about."""

    def setUp(self):
        import tempfile
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)

        from wdash.store import Store
        self.store = Store.open(f"sqlite:///{self.database}")
        self.store.users.create_first_admin("owner", "a-long-enough-password")

    def tearDown(self):
        if os.path.exists(self.database):
            os.unlink(self.database)

    def run_tool(self, *arguments):
        import contextlib
        import io

        from wdash.store.recover import main
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(output):
            code = main(["--database-url", f"sqlite:///{self.database}",
                         *arguments])
        return code, output.getvalue()

    def break_everything(self):
        for role_definition in self.store.roles.all():
            self.store.roles.upsert(
                role_definition["name"], permissions=["logs:read"],
                containers=[], trace_containers=[])

    def test_status_names_who_can_administer(self):
        _, output = self.run_tool("--status")
        self.assertIn("admin", output)

    def test_an_account_can_be_moved_to_a_role_that_exists(self):
        """The configuration page refuses to delete a role a local account
        holds and has no control for that account's role, so this is how the
        account is moved first. `--grant-admin` could not do it: it always
        lands on `recovery-admin`, which then could never be deleted."""
        self.run_tool("--grant-admin", "owner")
        code, _ = self.run_tool("--set-role", "owner", "admin")
        self.assertEqual(code, 0)
        self.assertEqual(self.store.users.by_username("owner")["role"], "admin")

        from wdash.dashboard.invariants import refuses_role_delete
        self.assertIsNone(refuses_role_delete(
            self.store.roles.all(), "recovery-admin", local("admin"),
            default_role="viewer", user_roles={},
            local_accounts=self.store.users.all()),
            "the role the account left is still held by something")

    def test_a_role_that_does_not_exist_is_refused(self):
        code, output = self.run_tool("--set-role", "owner", "nonexistent")
        self.assertEqual(code, 1)
        self.assertIn("No role called", output)
        self.assertEqual(self.store.users.by_username("owner")["role"], "admin")

    def test_it_says_when_the_account_stops_being_a_way_back_in(self):
        _, output = self.run_tool("--set-role", "owner", "viewer")
        self.assertIn("NOT grant system:admin", output)

    def test_the_delete_refusal_names_a_remedy_that_works(self):
        """It named `--grant-admin`, which cannot move an account OFF the
        recovery role — following the advice changed nothing."""
        from wdash.dashboard.invariants import refuses_role_delete
        refusal = refuses_role_delete(
            [ADMIN, CO_ADMIN, VIEWER], "co-admin", local("admin"),
            default_role="viewer",
            local_accounts=[{"username": "breakglass", "role": "co-admin"}])
        self.assertIn("--set-role", refusal)
        self.assertNotIn("--grant-admin", refusal)

    def test_status_says_plainly_when_nobody_can(self):
        self.break_everything()
        _, output = self.run_tool("--status")
        self.assertIn("NOBODY", output)

    def test_granting_admin_restores_access(self):
        self.break_everything()
        code, _ = self.run_tool("--grant-admin", "owner")
        self.assertEqual(code, 0)

        resolved = self.store.rbac.resolve(
            username="owner",
            explicit=self.store.users.by_username("owner")["role"])
        self.assertIn("system:admin", resolved["permissions"])

    def test_the_recovery_role_grants_no_data_access(self):
        """Repairing the system is not a reason to be able to read everything."""
        self.break_everything()
        self.run_tool("--grant-admin", "owner")
        recovery = self.store.roles.get("recovery-admin")
        self.assertEqual(recovery["containers"], [])
        self.assertEqual(recovery["trace_containers"], [])

    def test_granting_to_an_unknown_account_fails_with_the_options(self):
        code, output = self.run_tool("--grant-admin", "nobody")
        self.assertEqual(code, 1)
        self.assertIn("owner", output)

    def test_a_password_can_be_reset(self):
        code, _ = self.run_tool("--reset-password", "owner",
                                "--password", "another-long-password")
        self.assertEqual(code, 0)
        self.assertIsNotNone(
            self.store.users.verify("owner", "another-long-password"))

    def test_a_disabled_account_can_be_re_enabled(self):
        """`--grant-admin` moves the role and stops there, so a disabled
        account with the recovery role still cannot sign in: verify() refuses
        it before the password is checked. The one-directory refusal names
        this command, so it has to exist."""
        self.store.users.set_disabled("owner", True)
        self.assertIsNone(self.store.users.verify("owner",
                                                  "a-long-enough-password"))
        code, output = self.run_tool("--enable", "owner")
        self.assertEqual(code, 0, output)
        self.assertIsNotNone(self.store.users.verify("owner",
                                                     "a-long-enough-password"))

    def test_enabling_an_unknown_account_fails_with_the_options(self):
        code, output = self.run_tool("--enable", "nobody")
        self.assertEqual(code, 1)
        self.assertIn("owner", output)

    def test_a_directory_can_be_chosen_from_the_command_line(self):
        """The way back when both were enabled and the losing directory held
        every administrator: nobody can reach the page that would fix it."""
        for key in ("auth.ldap", "auth.oidc"):
            self.store.settings.set(key, {"enabled": True, "server": "ldap://x",
                                          "base_dn": "dc=x", "client_id": "w",
                                          "discovery_url": "https://idp/x"})
        code, output = self.run_tool("--use-directory", "ldap")
        self.assertEqual(code, 0, output)
        self.assertTrue(self.store.settings.get("auth.ldap")["enabled"])
        self.assertFalse(self.store.settings.get("auth.oidc")["enabled"])
        self.assertIn("LDAP is now the directory in force", output)
        # The settings themselves survive: only the flags are written.
        self.assertEqual(self.store.settings.get("auth.oidc")["client_id"], "w")

    def test_none_turns_every_directory_off(self):
        self.store.settings.set("auth.ldap", {"enabled": True,
                                              "server": "ldap://x",
                                              "base_dn": "dc=x"})
        code, output = self.run_tool("--use-directory", "none")
        self.assertEqual(code, 0, output)
        self.assertFalse(self.store.settings.get("auth.ldap")["enabled"])
        self.assertIn("No directory is in force", output)

    def test_choosing_a_directory_that_is_not_configured_is_refused(self):
        code, output = self.run_tool("--use-directory", "ldap")
        self.assertEqual(code, 1)
        self.assertIn("No LDAP settings are stored", output)
        self.assertIsNone(self.store.settings.get("auth.oidc"),
                          "a refusal must not have written the other flag")

    def test_a_directory_that_cannot_be_used_is_not_put_in_force(self):
        """The guard asked whether a settings ROW existed, not whether the
        directory worked. Measured on a half-typed OIDC card beside a working
        LDAP: rc 0, "OpenID Connect is now the directory in force.", the
        blank card enabled, LDAP disabled — and oidc_settings() and
        ldap_settings() both None, so every directory user was locked out by
        the command documented as the way back in."""
        self.store.settings.set("auth.ldap", {"enabled": True,
                                              "server": "ldap://x",
                                              "base_dn": "dc=x"})
        self.store.settings.set("auth.oidc", {"client_id": "half-typed",
                                              "discovery_url": "",
                                              "enabled": False})
        code, output = self.run_tool("--use-directory", "oidc")
        self.assertEqual(code, 1)
        self.assertIn("cannot be used as it stands", output)
        self.assertIn("discovery URL", output, "it must name what is missing")
        self.assertTrue(self.store.settings.get("auth.ldap")["enabled"],
                        "the directory that worked was turned off anyway")
        self.assertIs(self.store.settings.get("auth.oidc")["enabled"], False)

    def test_a_half_typed_card_is_read_as_though_it_were_switched_on(self):
        """The same question of the other directory, and the reason it has to
        be asked of a row that is currently OFF: a row saying `enabled: false`
        is not a complaint about its settings, so silence there is what let
        the tool enable a card nobody could sign in through."""
        self.store.settings.set("auth.ldap", {"server": "",
                                              "base_dn": "dc=x",
                                              "enabled": False})
        code, output = self.run_tool("--use-directory", "ldap")
        self.assertEqual(code, 1)
        self.assertIn("cannot be used as it stands", output)
        self.assertIn("server and a base DN", output)
        self.assertIs(self.store.settings.get("auth.ldap")["enabled"],
                      False)
        self.assertIsNone(self.store.settings.get("auth.oidc"),
                          "a refusal must not have written the other flag")

    def test_a_directory_that_was_never_configured_gets_no_row(self):
        """It wrote `auth.ldap = {"enabled": False}` on an installation that
        only ever had OIDC. That row is not a configuration — nothing was
        typed into it — but it then answered the tool's own "is it
        configured" guard, and the next `--use-directory ldap` was accepted."""
        self.store.settings.set("auth.oidc", {"client_id": "w",
                                              "discovery_url": "https://i/.w",
                                              "enabled": False})
        code, output = self.run_tool("--use-directory", "oidc")
        self.assertEqual(code, 0, output)
        self.assertTrue(self.store.settings.get("auth.oidc")["enabled"])
        self.assertIsNone(self.store.settings.get("auth.ldap"))

        code, output = self.run_tool("--use-directory", "ldap")
        self.assertEqual(code, 1)
        self.assertIn("No LDAP settings are stored", output)

    def test_an_off_switch_row_is_not_a_directory(self):
        """A row holding nothing but `enabled: False` — which an earlier
        version wrote to turn off a provider read from the environment, and
        which is still in databases — is an off-switch, not a directory.
        Read as one, this tool enabled a blank card, disabled the LDAP that
        worked, and printed that OpenID Connect was in force."""
        self.store.settings.set("auth.ldap", {"enabled": True,
                                              "server": "ldap://x",
                                              "base_dn": "dc=x"})
        self.store.settings.set("auth.oidc", {"enabled": False})
        code, output = self.run_tool("--use-directory", "oidc")
        self.assertEqual(code, 1)
        self.assertIn("No OIDC settings are stored", output)
        self.assertTrue(self.store.settings.get("auth.ldap")["enabled"],
                        "the directory that worked was turned off anyway")
        self.assertEqual(self.store.settings.get("auth.oidc"),
                         {"enabled": False})

    def test_status_says_which_directory_would_sign_people_in(self):
        self.store.settings.set("auth.ldap", {"enabled": True,
                                              "server": "ldap://x",
                                              "base_dn": "dc=x"})
        _, output = self.run_tool("--status")
        self.assertIn("Directory: LDAP", output)

    def test_status_names_the_directory_that_is_configured_and_not_in_use(self):
        """The one line that says why every LDAP administrator is locked
        out, read from the pod when the page cannot be. Two rows enabled,
        OpenID Connect saved last: it is in force, and LDAP is said to be
        configured and not in use rather than left out."""
        self.store.settings.set("auth.ldap", {"enabled": True,
                                              "server": "ldap://x",
                                              "base_dn": "dc=x"})
        self.store.settings.set("auth.oidc", {"enabled": True,
                                              "client_id": "w",
                                              "discovery_url": "https://i/.w"})
        _, output = self.run_tool("--status")
        self.assertIn("Directory: OpenID Connect; LDAP is configured and "
                      "NOT in use", output)


class AccountChangeTest(unittest.TestCase):
    """The fifth way to lose administration: the accounts page.

    Until there was one, a local account could only be made by first-run setup
    or by the recovery tool, and neither can demote, disable or delete the
    account that reaches the configuration page. A form can, which is what
    this rule is for.
    """

    ROLES = [ADMIN, CO_ADMIN, VIEWER]

    def test_an_ordinary_demotion_is_allowed_while_another_admin_remains(self):
        self.assertIsNone(refuses_account_change(
            [account("owner", "admin"), account("bob", "co-admin")],
            self.ROLES, "bob", local("admin"), role="viewer"))

    def test_the_last_enabled_administrator_cannot_be_demoted(self):
        refusal = refuses_account_change(
            [account("owner", "admin"), account("bob", "viewer")],
            self.ROLES, "owner", person("carol"), role="viewer")
        self.assertIn("only local account", refusal)
        self.assertIn("way back in", refusal)
        self.assertIn("viewer", refusal)

    def test_the_last_enabled_administrator_cannot_be_disabled(self):
        refusal = refuses_account_change(
            [account("owner", "admin")], self.ROLES, "owner", person("carol"),
            disabled=True)
        self.assertIn("Disabling it", refusal)

    def test_the_last_enabled_administrator_cannot_be_deleted(self):
        refusal = refuses_account_change(
            [account("owner", "admin")], self.ROLES, "owner", person("carol"),
            deleting=True)
        self.assertIn("Deleting it", refusal)

    def test_an_account_already_disabled_does_not_count_as_a_way_back_in(self):
        """A disabled account holding an administering role is not one:
        `verify()` refuses it before the password is checked."""
        refusal = refuses_account_change(
            [account("owner", "admin"),
             account("spare", "admin", disabled=True)],
            self.ROLES, "owner", person("carol"), deleting=True)
        self.assertIsNotNone(refusal)

    def test_re_enabling_the_spare_first_makes_the_demotion_allowed(self):
        self.assertIsNone(refuses_account_change(
            [account("owner", "admin"), account("spare", "admin")],
            self.ROLES, "owner", person("carol"), deleting=True))

    def test_you_cannot_demote_yourself(self):
        refusal = refuses_account_change(
            [account("owner", "admin"), account("bob", "co-admin")],
            self.ROLES, "owner", local("admin", "owner"), role="viewer")
        self.assertIn("the account you are signed in with", refusal)
        self.assertIn("recover --grant-admin owner", refusal)

    def test_you_cannot_disable_yourself(self):
        self.assertIn("lock you out", refuses_account_change(
            [account("owner", "admin"), account("bob", "co-admin")],
            self.ROLES, "owner", local("admin", "owner"), role="admin",
            disabled=True))

    def test_you_cannot_delete_yourself(self):
        self.assertIn("lock you out", refuses_account_change(
            [account("owner", "admin"), account("bob", "co-admin")],
            self.ROLES, "owner", local("admin", "owner"), deleting=True))

    def test_a_directory_administrator_may_edit_the_account_of_that_name(self):
        """"Yours" is the account you signed in WITH, not a name that matches.
        A session says which door it came through, and this one is not local."""
        self.assertIsNone(refuses_account_change(
            [account("owner", "admin"), account("bob", "co-admin")],
            self.ROLES, "bob",
            {"username": "bob", "provider": "oidc", "groups": []},
            role="viewer"))

    def test_the_system_rule_is_reported_before_the_personal_one(self):
        """Both are true when you are the only administrator. "Nobody would be
        left" is what is actually wrong; "you would be locked out" is what it
        means for one person."""
        refusal = refuses_account_change(
            [account("owner", "admin")], self.ROLES, "owner",
            local("admin", "owner"), deleting=True)
        self.assertIn("only local account", refusal)

    def test_a_password_reset_changes_nothing_and_is_never_refused(self):
        """The same question, asked with no edit: role and disabled unchanged
        must not read as "moved to None" or "disabled"."""
        self.assertIsNone(refuses_account_change(
            [account("owner", "admin")], self.ROLES, "owner",
            local("admin", "owner")))

    def test_re_enabling_an_account_is_never_refused(self):
        self.assertIsNone(refuses_account_change(
            [account("owner", "admin"), account("bob", "viewer", disabled=True)],
            self.ROLES, "bob", local("admin", "owner"), role="viewer",
            disabled=False))

    def test_an_installation_already_without_one_is_not_frozen(self):
        """`--set-role` can leave a store with no administering local account.
        Refusing every edit from there would make the page unable to repair
        what the command line broke."""
        self.assertIsNone(refuses_account_change(
            [account("owner", "viewer"), account("bob", "viewer")],
            self.ROLES, "bob", person("carol"), role="viewer", disabled=True))

    def test_an_account_that_does_not_exist_breaks_nothing(self):
        self.assertIsNone(refuses_account_change(
            [account("owner", "admin")], self.ROLES, "ghost", person("carol"),
            deleting=True))

    def test_a_role_that_no_longer_exists_falls_through_to_the_mapping(self):
        """The stored role is not read off the row: a name nothing defines
        resolves through the mappings and then the default, exactly as it does
        at sign-in. Read off the row, `owner` is not an administrator and this
        delete is refused — for a reason that is not true of the installation
        the person would be left with."""
        self.assertIsNone(refuses_account_change(
            [account("owner", "gone"), account("bob", "admin")],
            self.ROLES, "bob", person("carol"), deleting=True,
            user_roles={"owner": "admin"}, default_role="viewer"))

    def test_a_role_that_no_longer_exists_and_maps_nowhere_is_not_a_way_back(self):
        refusal = refuses_account_change(
            [account("owner", "gone"), account("bob", "admin")],
            self.ROLES, "bob", person("carol"), deleting=True,
            user_roles={"owner": "viewer"}, default_role="viewer")
        self.assertIn("only local account", refusal)


if __name__ == "__main__":
    unittest.main(verbosity=2)
