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


def role(name, *permissions):
    return {"name": name, "permissions": list(permissions)}


ADMIN = role("admin", "system:admin", "logs:read")
CO_ADMIN = role("co-admin", "system:admin")
VIEWER = role("viewer", "logs:read")


class RoleSaveTest(unittest.TestCase):
    def test_an_ordinary_edit_is_allowed(self):
        self.assertIsNone(refuses_role_save(
            [ADMIN, VIEWER], "viewer", ["logs:read", "traces:read"], "admin"))

    def test_the_last_administrator_role_cannot_drop_the_permission(self):
        refusal = refuses_role_save([ADMIN, VIEWER], "admin", ["logs:read"],
                                    "admin")
        self.assertIsNotNone(refusal)
        self.assertIn("only role that can administer", refusal)

    def test_it_can_once_another_role_carries_it(self):
        """The system stays operable, so only the personal guard is left."""
        refusal = refuses_role_save([ADMIN, CO_ADMIN], "admin", ["logs:read"],
                                    actor_role="co-admin")
        self.assertIsNone(refusal)

    def test_you_still_cannot_remove_it_from_your_own_role(self):
        refusal = refuses_role_save([ADMIN, CO_ADMIN], "admin", ["logs:read"],
                                    actor_role="admin")
        self.assertIsNotNone(refusal)
        self.assertIn("lock you out", refusal)

    def test_the_system_message_comes_before_the_personal_one(self):
        """'Nobody could administer' says what is wrong; 'you would be locked
        out' says what it means for you. The first is more useful."""
        refusal = refuses_role_save([ADMIN], "admin", ["logs:read"], "admin")
        self.assertIn("only role that can administer", refusal)

    def test_creating_a_new_role_without_admin_is_fine(self):
        self.assertIsNone(refuses_role_save(
            [ADMIN], "auditor", ["logs:read"], "admin"))


class RoleDeleteTest(unittest.TestCase):
    def test_the_last_role_cannot_go(self):
        self.assertIn("last role",
                      refuses_role_delete([ADMIN], "admin", "admin"))

    def test_the_only_administrator_role_cannot_go(self):
        refusal = refuses_role_delete([ADMIN, VIEWER], "admin", "viewer")
        self.assertIn("only role that can administer", refusal)

    def test_your_own_role_cannot_go(self):
        refusal = refuses_role_delete([ADMIN, CO_ADMIN, VIEWER], "admin",
                                      "admin")
        self.assertIn("lock you out", refusal)

    def test_another_role_can(self):
        self.assertIsNone(
            refuses_role_delete([ADMIN, CO_ADMIN, VIEWER], "viewer", "admin"))


class MappingTest(unittest.TestCase):
    """The third way to lose administration, and the least obvious."""

    def test_reassigning_yourself_to_a_lesser_role_is_refused(self):
        refusal = refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer",
            mappings={"alice": "viewer"}, actor_role="admin",
            actor_identifiers=("alice", "alice@example.com"))
        self.assertIn("lose access", refusal)

    def test_changing_the_default_is_refused_when_it_would_move_you(self):
        refusal = refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer", mappings={},
            actor_role="admin", actor_identifiers=("alice",))
        self.assertIsNotNone(refusal)

    def test_a_local_account_is_exempt(self):
        """Its role is stored with the account and beats every mapping — which
        is exactly what makes it the way back in."""
        self.assertIsNone(refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer", mappings={},
            actor_role="admin", actor_identifiers=("owner",),
            actor_local_role="admin"))

    def test_a_local_role_that_no_longer_exists_is_not_an_exemption(self):
        self.assertIsNotNone(refuses_mapping_save(
            [ADMIN, VIEWER], default_role="viewer", mappings={},
            actor_role="admin", actor_identifiers=("owner",),
            actor_local_role="deleted-role"))

    def test_mapping_yourself_to_an_administrator_role_is_fine(self):
        self.assertIsNone(refuses_mapping_save(
            [ADMIN, CO_ADMIN, VIEWER], default_role="viewer",
            mappings={"alice": "co-admin"}, actor_role="admin",
            actor_identifiers=("alice",)))


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
