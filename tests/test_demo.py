"""
`python -m wdash.demo`, and the one thing it must never do.

The command exists to fill an EMPTY installation. Everything it writes —
an administrator, five sources — is something somebody else's installation
already has its own version of, so the interesting test is not that it
writes them. It is that it refuses to.

The first version of the module claimed that refusal in its docstring and
did not implement it: it asked whether an account existed, skipped creating
one, and carried on to add the sources anyway. Run by hand against a
database that had an administrator, it added four. These tests are written
against that, which is why so many of them count rows before and after.
"""

import io
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wdash import demo  # noqa: E402
from wdash.store import Store  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

#: Two of the lab's, as `look()` reports them. Enough to tell "added one"
#: from "added everything" without pretending the whole lab is up.
PRESENT = [
    {"name": "main-elasticsearch", "kind": "elasticsearch",
     "signals": ["logs", "traces", "monitors"],
     "url": "http://localhost:9200", "target": "elasticsearch"},
    {"name": "lab-loki", "kind": "loki", "signals": ["logs"],
     "url": "http://localhost:3100", "target": "loki"},
]

PASSWORD = "a-demo-password-12"


def _store():
    """An empty installation, in memory."""
    return Store.open("sqlite:///:memory:",
                      secret_box=SecretBox(SecretBox.generate_key()))


class AnEmptyInstallationTest(unittest.TestCase):
    def setUp(self):
        self.store = _store()
        self.out = io.StringIO()

    def fill(self, **extra):
        return demo.fill(self.store, "demo", PASSWORD, PRESENT,
                         out=self.out, **extra)

    def test_it_creates_the_administrator(self):
        created = self.fill()
        self.assertEqual(created["account"], "demo")
        self.assertIsNotNone(self.store.users.by_username("demo"))

    def test_the_account_still_has_to_enrol_an_authenticator(self):
        """The demo saves a form, not the second factor. An account arriving
        with a secret somebody could read out of the repository — or out of
        this command's output — is the one hole that would make the whole
        TOTP guard decorative."""
        self.fill()
        self.assertIsNone(self.store.users.totp_secret("demo"))

    def test_the_role_it_is_given_exists(self):
        """`Store.open` migrates, and migration 19 is what writes the three
        built-in roles. Skipping it would leave an administrator holding a
        role nothing defines, which resolves to the fallback."""
        self.fill()
        names = {role["name"] for role in self.store.roles.all()}
        self.assertIn("admin", names)
        self.assertEqual(self.store.users.by_username("demo")["role"], "admin")

    def test_it_adds_every_source_it_was_given(self):
        created = self.fill()
        self.assertEqual(sorted(created["sources"]),
                         ["lab-loki", "main-elasticsearch"])
        stored = {source["name"]: source for source in self.store.sources.all()}
        self.assertEqual(sorted(stored), ["lab-loki", "main-elasticsearch"])

    def test_the_catalogue_gives_the_cluster_all_three_signals(self):
        """Asked of `BACKENDS`, not of the fixture above.

        The fixture says what `fill` is handed; this says what the command
        would actually offer, and they are different claims. Narrowing the
        catalogue to logs left every test here passing, because every one of
        them was handed the fixture.
        """
        from wdash.store.sources import SOURCE_KINDS
        catalogue = {name: (kind, signals)
                     for name, kind, signals, *_ in demo.BACKENDS}
        self.assertEqual(sorted(catalogue["main-elasticsearch"][1]),
                         ["logs", "monitors", "traces"])
        for name, (kind, signals) in catalogue.items():
            with self.subTest(source=name):
                offered = set(SOURCE_KINDS[kind]["signals"])
                self.assertTrue(signals, f"{name} serves nothing")
                self.assertEqual(set(signals) - offered, set(),
                                 f"{kind} cannot serve that")

    def test_the_cluster_serves_all_three_signals(self):
        """One entry with three boxes ticked, not three entries. The page
        says so and a demo that did otherwise would teach the wrong shape."""
        self.fill()
        cluster = next(s for s in self.store.sources.all()
                       if s["name"] == "main-elasticsearch")
        self.assertEqual(sorted(cluster["signals"]),
                         ["logs", "monitors", "traces"])

    def test_running_it_twice_adds_nothing_the_second_time(self):
        self.fill()
        again = demo.fill(self.store, "demo", PASSWORD, PRESENT,
                          out=self.out, into_claimed=True)
        self.assertEqual(again["sources"], [])
        self.assertEqual(len(self.store.sources.all()), 2)


class AClaimedInstallationTest(unittest.TestCase):
    """The refusal, and that it happens BEFORE anything is written."""

    def setUp(self):
        self.store = _store()
        self.store.users.create_first_admin("someone", PASSWORD, role="admin")
        self.out = io.StringIO()

    def test_it_refuses(self):
        with self.assertRaises(demo.AlreadyClaimed):
            demo.fill(self.store, "demo", PASSWORD, PRESENT, out=self.out)

    def test_it_writes_no_source_on_the_way_to_refusing(self):
        """The bug, exactly. A refusal that has already added five sources
        is not a refusal, and it is the shape a check placed *alongside* the
        work rather than in front of it produces."""
        with self.assertRaises(demo.AlreadyClaimed):
            demo.fill(self.store, "demo", PASSWORD, PRESENT, out=self.out)
        self.assertEqual(self.store.sources.all(), [])

    def test_it_leaves_the_account_alone(self):
        with self.assertRaises(demo.AlreadyClaimed):
            demo.fill(self.store, "demo", PASSWORD, PRESENT, out=self.out)
        self.assertEqual([user["username"] for user in self.store.users.all()],
                         ["someone"])
        self.assertIsNone(self.store.users.by_username("demo"))

    def test_into_claimed_adds_the_sources_and_no_account(self):
        created = demo.fill(self.store, "demo", PASSWORD, PRESENT,
                            out=self.out, into_claimed=True)
        self.assertIsNone(created["account"])
        self.assertEqual(sorted(created["sources"]),
                         ["lab-loki", "main-elasticsearch"])
        self.assertEqual([user["username"] for user in self.store.users.all()],
                         ["someone"])


class WhatItLooksForTest(unittest.TestCase):
    def test_it_offers_only_what_answered(self):
        with mock.patch.object(demo, "answers",
                               side_effect=lambda url, path: "9200" in url):
            present, missing = demo.look()
        self.assertEqual([one["name"] for one in present],
                         ["main-elasticsearch"])
        self.assertEqual(sorted(one["name"] for one in missing),
                         ["lab-jaeger", "lab-loki", "lab-tempo",
                          "lab-victorialogs"])

    def test_it_reads_the_same_variables_the_lab_helper_does(self):
        """One set of exports moves the lab for the tests and for this.

        Compared against `tests/lab.py`'s own `_url` calls rather than
        against a list written here: two spellings of one address is how
        they come to point at different machines, and a copy of the names
        in this file would be the third spelling.
        """
        import inspect

        from tests import lab
        named = set(re.findall(r'"(WDASH_LAB_[A-Z_]+)"',
                               inspect.getsource(lab)))
        mine = {name for _, _, _, variables, *_ in demo.BACKENDS
                for name in variables}
        self.assertTrue(mine, "the demo names no lab variable")
        self.assertEqual(mine - named, set(),
                         "the demo reads a variable tests/lab.py does not")

    def test_an_exported_address_moves_it(self):
        with mock.patch.dict(os.environ, {"WDASH_LAB_LOKI": "http://x:1"}), \
                mock.patch.object(demo, "answers", return_value=True):
            present, _ = demo.look()
        loki = next(one for one in present if one["name"] == "lab-loki")
        self.assertEqual(loki["url"], "http://x:1")

    def test_a_backend_that_answers_at_all_counts_as_there(self):
        """A 401 is a backend that exists and wants a credential, which is a
        different sentence from "nothing is listening" — and the one worth
        telling somebody. Only a connection that fails means absent."""
        import requests
        with mock.patch.object(requests, "get",
                               return_value=mock.Mock(status_code=401)):
            self.assertTrue(demo.answers("http://x", "/"))
        with mock.patch.object(requests, "get",
                               side_effect=OSError("refused")):
            self.assertFalse(demo.answers("http://x", "/"))


class TheDryRunTest(unittest.TestCase):
    def test_it_opens_no_database(self):
        """`Store.open` MIGRATES. Against a path that does not exist that
        means creating the file and writing a schema into it, which a run
        that says it writes nothing must not do — however harmless the file
        would be."""
        with mock.patch.object(demo, "answers", return_value=True), \
                mock.patch.object(Store, "open") as opened, \
                mock.patch("sys.stdout", io.StringIO()):
            code = demo.main(["--dry-run",
                              "--database-url", "sqlite:///nowhere.db"])
        self.assertEqual(code, 0)
        opened.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
