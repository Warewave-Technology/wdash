"""
Sign-in throttling.

A password form with no limit is an offline attack conducted online. What
these hold is that the limit exists, that it is not itself a weapon, and that
it cannot be walked around by changing a header.
"""

import datetime as dt
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import create_engine  # noqa: E402

from wdash.store.schema import metadata, signin_attempts  # noqa: E402
from wdash.store.signin import (  # noqa: E402
    FAILURE, LOCKED, SUCCESS, Limit, SignInGuard, client_address)


class GuardTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.engine = create_engine(f"sqlite:///{self.database}")
        metadata.create_all(self.engine)
        self.guard = SignInGuard(self.engine)

    def tearDown(self):
        self.engine.dispose()
        os.unlink(self.database)

    def fail(self, times, username="owner", address="10.0.0.1"):
        for _ in range(times):
            self.guard.record(username, address, FAILURE)

    def backdate(self, delta):
        """Move every recorded attempt into the past."""
        with self.engine.begin() as connection:
            for row in connection.execute(
                    signin_attempts.select()).mappings().all():
                at = row["at"]
                if at.tzinfo is None:
                    at = at.replace(tzinfo=timezone.utc)
                connection.execute(
                    signin_attempts.update()
                    .where(signin_attempts.c.id == row["id"])
                    .values(at=at - delta))


class ThresholdTest(GuardTestCase):
    def test_an_ordinary_mistype_is_not_punished(self):
        """Four wrong passwords is a person, not an attack."""
        self.fail(4)
        self.assertIsNone(self.guard.check("owner", "10.0.0.1"))

    def test_repeated_failure_locks_the_pair(self):
        self.fail(6)
        lockout = self.guard.check("owner", "10.0.0.1")
        self.assertIsNotNone(lockout, "unlimited guessing was allowed")
        self.assertEqual(lockout.limit, "pair")

    def test_the_wait_grows_but_stops_growing(self):
        """An uncapped backoff is a permanent lockout under another name, and
        the account it locks out is whichever one somebody chose to attack."""
        limit = Limit("pair", threshold=5, window=dt.timedelta(minutes=15),
                      base_wait=dt.timedelta(minutes=1),
                      max_wait=dt.timedelta(minutes=15))
        self.assertLess(limit.wait_for(6), limit.wait_for(8))
        self.assertEqual(limit.wait_for(500), dt.timedelta(minutes=15))

    def test_the_lockout_lifts(self):
        self.fail(6)
        self.assertIsNotNone(self.guard.check("owner", "10.0.0.1"))
        self.backdate(dt.timedelta(hours=2))
        self.assertIsNone(self.guard.check("owner", "10.0.0.1"),
                          "the lockout never lifted")

    def test_the_wait_is_measured_from_the_last_failure(self):
        """Measured from the first, the wait is spent while the attacker is
        still going and expires the moment they pause."""
        self.fail(6)
        self.backdate(dt.timedelta(minutes=10))
        self.fail(1)          # still at it
        self.assertIsNotNone(self.guard.check("owner", "10.0.0.1"))


class BlastRadiusTest(GuardTestCase):
    """A rate limit that locks the wrong people out is a denial of service."""

    def test_one_locked_pair_does_not_lock_the_account_elsewhere(self):
        self.fail(6, address="10.0.0.1")
        self.assertIsNotNone(self.guard.check("owner", "10.0.0.1"))
        self.assertIsNone(self.guard.check("owner", "192.168.1.5"),
                          "an attacker locked the owner out of every machine")

    def test_one_locked_pair_does_not_lock_the_address_for_others(self):
        self.fail(6, username="owner")
        self.assertIsNone(self.guard.check("someone-else", "10.0.0.1"),
                          "one colleague's typo locked out a shared office")

    def test_locking_one_account_from_anywhere_takes_real_effort(self):
        """The username limit exists, and its threshold is high on purpose:
        a low one hands anybody who knows the administrator's username a way
        to lock them out deliberately."""
        for index in range(60):
            self.guard.record("owner", f"10.0.{index}.1", FAILURE)
        lockout = self.guard.check("owner", "10.9.9.9")
        self.assertIsNotNone(lockout)
        self.assertEqual(lockout.limit, "username")

    def test_no_lockout_is_permanent(self):
        for index in range(200):
            self.guard.record("owner", f"10.0.{index % 250}.1", FAILURE)
        for limit in self.guard._limits:
            self.assertLessEqual(limit.wait_for(200), dt.timedelta(minutes=30))


class SprayTest(GuardTestCase):
    def test_one_host_working_through_a_list_of_names_is_stopped(self):
        """Each name stays under the pair limit; the address limit is what
        sees the pattern."""
        for index in range(25):
            self.guard.record(f"user{index}", "10.0.0.7", FAILURE)
        lockout = self.guard.check("user99", "10.0.0.7")
        self.assertIsNotNone(lockout)
        self.assertEqual(lockout.limit, "address")

    def test_attempts_against_names_that_never_existed_are_kept(self):
        """A burst against names that were never real is the clearest signal
        there is, and dropping it loses it."""
        self.guard.record("nobody-here", "10.0.0.7", FAILURE)
        self.assertTrue(self.guard.recent(username="nobody-here"))


class SuccessTest(GuardTestCase):
    def test_signing_in_resets_the_counter_for_that_pair(self):
        self.fail(4)
        self.guard.record("owner", "10.0.0.1", SUCCESS)
        self.fail(4)
        self.assertIsNone(self.guard.check("owner", "10.0.0.1"),
                          "the counter never reset after a real sign-in")

    def test_the_reset_counts_forward_rather_than_deleting_backward(self):
        """The counter resets; the history does not.

        Deleting the failures was the first attempt at this, and it meant
        somebody who eventually guessed the password erased the attempts that
        got them there — on the one screen an administrator would look at
        afterwards.
        """
        self.fail(4)
        self.guard.record("owner", "10.0.0.1", SUCCESS)
        outcomes = [row["outcome"] for row in self.guard.recent()]
        self.assertEqual(outcomes.count(FAILURE), 4,
                         "a success erased the failures that preceded it")

    def test_a_success_here_does_not_reset_the_counter_there(self):
        """Otherwise an attacker arranges a success of their own to reset it."""
        self.fail(6, address="10.0.0.99")
        self.guard.record("owner", "10.0.0.1", SUCCESS)
        self.assertIsNotNone(self.guard.check("owner", "10.0.0.99"),
                             "a sign-in elsewhere lifted a lockout")

    def test_a_success_does_not_reset_a_shared_address(self):
        """One person getting in says nothing about twenty failures against
        twenty other usernames from the same office."""
        for index in range(25):
            self.guard.record(f"user{index}", "10.0.0.7", FAILURE)
        self.guard.record("owner", "10.0.0.7", SUCCESS)
        lockout = self.guard.check("user99", "10.0.0.7")
        self.assertIsNotNone(lockout)
        self.assertEqual(lockout.limit, "address")

    def test_a_success_does_not_count_towards_a_lockout(self):
        for _ in range(10):
            self.guard.record("owner", "10.0.0.1", SUCCESS)
        self.assertIsNone(self.guard.check("owner", "10.0.0.1"))


class RecordKeepingTest(GuardTestCase):
    def test_a_refused_attempt_is_recorded_as_refused(self):
        """It says the pressure is still on, which 'failure' alone does not."""
        self.guard.record("owner", "10.0.0.1", LOCKED)
        self.assertEqual(self.guard.recent()[0]["outcome"], LOCKED)

    def test_old_attempts_are_pruned(self):
        self.fail(3)
        self.backdate(dt.timedelta(days=60))
        self.guard.prune()
        self.assertEqual(self.guard.recent(), [])

    def test_pruning_keeps_what_is_still_relevant(self):
        self.fail(3)
        self.guard.prune()
        self.assertEqual(len(self.guard.recent()), 3)

    def test_a_broken_table_does_not_take_sign_in_down(self):
        """Passwords, roles and group mappings live in the same database, so
        an installation that cannot read this table cannot authorise anybody
        either. Failing closed here buys nothing and costs everything."""
        metadata.drop_all(self.engine)
        self.assertIsNone(self.guard.check("owner", "10.0.0.1"))
        self.guard.record("owner", "10.0.0.1", FAILURE)   # must not raise


class ClientAddressTest(unittest.TestCase):
    """`X-Forwarded-For` is written by whatever spoke to the proxy."""

    class _Request:
        def __init__(self, remote_addr, forwarded=None):
            self.remote_addr = remote_addr
            self.headers = {"X-Forwarded-For": forwarded} if forwarded else {}

    def test_the_header_is_ignored_when_no_proxy_is_configured(self):
        request = self._Request("10.0.0.1", forwarded="1.2.3.4")
        self.assertEqual(client_address(request), "10.0.0.1")

    def test_a_client_cannot_name_its_own_address(self):
        """Reading the leftmost entry — the usual mistake — lets a client walk
        around a per-address limit by changing a header."""
        request = self._Request("10.0.0.1", forwarded="9.9.9.9, 203.0.113.5")
        self.assertEqual(client_address(request, trusted_proxies=1),
                         "203.0.113.5")

    def test_a_short_chain_falls_back_to_the_socket(self):
        """Fewer entries than proxies means the header is not what it claims."""
        request = self._Request("10.0.0.1", forwarded="9.9.9.9")
        self.assertEqual(client_address(request, trusted_proxies=2), "10.0.0.1")

    def test_a_missing_address_is_still_a_key(self):
        self.assertEqual(client_address(self._Request(None)), "unknown")


if __name__ == "__main__":
    unittest.main()
