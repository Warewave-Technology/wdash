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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.invariants import (  # noqa: E402
    refuses_mapping_save, refuses_role_delete, refuses_role_save,
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

        cases = [dict(email="alice@example.com", username="alice",
                      groups=["wdash-admins"]),
                 dict(email=None, username="bob", groups=["wdash-admins"]),
                 dict(email=None, username="carol", groups=[]),
                 dict(email=None, username="owner", groups=[],
                      explicit="admin")]
        by_name = {r["name"]: r for r in roles.all.return_value}
        for case in cases:
            with self.subTest(**case):
                self.assertEqual(
                    resolver.role_for(**case),
                    choose_role(by_name, {"alice@example.com": "viewer"},
                                "viewer", **case))


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
