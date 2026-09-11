"""
A source that is stored is not the same as a source that answers.

The configuration page had one list — the rows in the table — and told the
administrator "saved and in use now" about every one of them. Three ways that
sentence was false:

  * the row could not be BUILT. `Hub.reload()` logs a row it cannot build and
    returns a count, so it never raises, so the only branch that said anything
    but "in use now" could not fire. A Loki source whose stored password no
    longer decrypts was reported as in use while `hub.logs('loki-a')` raised
    "no log source named loki-a".
  * the row's NAME was one the environment already registered. The registry
    merged `{**base, **configured}`, which keeps the key's position and swaps
    the value, so a Loki source called `elasticsearch-logs` took the
    environment's cluster out of the registry and answered in its place.
  * with no environment source at all, the unnamed default was whichever
    configured name sorted FIRST, because the repository lists by name. Adding
    `archive-es` to a deployment that had always answered from `loki-prod`
    moved every unnamed search onto it.

And the role editor's service picker dropped a trace store that could not be
asked — `except Exception: continue` — so a shorter list of services looked
like a quiet week rather than a backend that is down.
"""

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.app import create_app  # noqa: E402
from wdash.config import Config  # noqa: E402
from wdash.store import SecretBox  # noqa: E402
from wdash.store.sources import SourceError  # noqa: E402

PASSWORD = "a-sufficiently-long-password"
#: Refused at once: nothing listens on port 1.
NOWHERE = "http://127.0.0.1:1"


def flashes(response):
    """The alerts the page is showing, as text."""
    body = response.get_data(as_text=True)
    import html
    return [html.unescape(re.sub(r"<[^>]+>", "", block)).strip()
            for block in re.findall(r'<div class="alert alert-[^"]*"[^>]*>(.*?)</div>',
                                    body, re.S)]


class _Store(unittest.TestCase):
    """One database, and as many app objects as a test needs workers."""

    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.key = SecretBox.generate_key()
        self.app = self.worker()
        self.client = self.app.test_client()
        self.client.post("/setup", data={"username": "owner",
                                         "password": PASSWORD,
                                         "confirm": PASSWORD})
        self.sign_in(self.client)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def worker(self, elasticsearch="", key=None):
        """Another process's app object, on the same store."""
        database, secret = self.database, key or self.key

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "source-liveness"
            DATABASE_URL = f"sqlite:///{database}"
            ENCRYPTION_KEY = secret
            ELASTICSEARCH_URL = elasticsearch
            TRACE_INDEX_PATTERNS = ("*traces*",)
            OIDC_CLIENT_ID = None
            DASHBOARD_STORAGE = "database"

        return create_app(TestConfig)

    @staticmethod
    def sign_in(client):
        client.post("/auth/login", data={"username": "owner",
                                         "password": PASSWORD},
                    follow_redirects=True)

    def save(self, client=None, **fields):
        form = {"name": "loki-a", "kind": "loki", "url": "http://localhost:3100",
                "signals": ["logs"], "enabled": "on"}
        form.update(fields)
        if form.get("enabled") is None:
            form.pop("enabled")
        return (client or self.client).post("/admin/sources", data=form,
                                            follow_redirects=True)


class SavedButNotInUseTest(_Store):
    """The realistic trigger: WDASH_ENCRYPTION_KEY was rotated, and the
    administrator saves the source again with the password box left blank."""

    def setUp(self):
        super().setUp()
        self.save(name="loki-a", username="u", password="p")
        # Another worker, another deployment key, the same store.
        self.other = self.worker(key=SecretBox.generate_key())
        self.client2 = self.other.test_client()
        self.sign_in(self.client2)
        self.row = next(s for s in self.other.store.sources.all()
                        if s["name"] == "loki-a")

    def resave(self):
        return self.save(client=self.client2, id=self.row["id"],
                         name="loki-a", username="u", password="")

    def test_the_first_save_is_reported_as_in_use_because_it_is(self):
        """The other side of the check: it must not cry wolf."""
        response = self.save(name="loki-b", url="http://localhost:3101")
        said = " ".join(flashes(response))
        self.assertIn("'loki-b' saved and in use now", said)
        self.assertEqual(
            self.app.hub.logs("loki-b").name, "loki-b")

    def test_a_row_that_cannot_be_built_is_not_reported_as_in_use(self):
        said = " ".join(flashes(self.resave()))
        self.assertIn("NOT in use", said)
        self.assertNotIn("in use now", said)

    def test_the_reason_is_in_the_sentence(self):
        said = " ".join(flashes(self.resave()))
        self.assertIn("could not be decrypted", said)

    def test_and_the_source_really_is_unreachable(self):
        """The sentence is only worth anything if it is about reality."""
        self.resave()
        with self.other.app_context():
            self.assertEqual([s.name for s in self.other.hub.log_sources], [])
            with self.assertRaises(KeyError):
                self.other.hub.logs("loki-a")

    def test_the_page_marks_the_row(self):
        self.resave()
        body = self.client2.get("/admin/config").get_data(as_text=True)
        self.assertIn("not in use", body)
        self.assertIn("could not be decrypted", body)

    def test_a_working_row_is_not_marked(self):
        body = self.client.get("/admin/config").get_data(as_text=True)
        self.assertIn("loki-a", body)
        self.assertNotIn("not in use", body)

    def test_the_hub_names_the_row_and_says_why(self):
        self.resave()
        with self.other.app_context():
            failures = self.other.hub.source_failures
        self.assertIn("loki-a", failures)
        self.assertIn("could not be decrypted", failures["loki-a"])

    def test_a_hub_that_does_not_rebuild_is_not_a_build_failure(self):
        """`reload()` answers 0 to everything on a hub assembled by hand —
        every test that calls `replace_all`. That is not the same statement
        as "the row you just saved could not be built", and reporting it as
        one would put a fault in front of somebody who does not have one."""
        self.app.hub.replace_all()
        said = " ".join(flashes(self.save(name="loki-c",
                                          url="http://localhost:3103")))
        self.assertNotIn("NOT in use", said)

    def test_a_disabled_source_is_not_called_in_use_either(self):
        """It is not a failure, and it is not in use. Both have to be said,
        or "in use now" is the answer to every save."""
        response = self.save(name="loki-off", url="http://localhost:3102",
                             enabled=None)
        said = " ".join(flashes(response))
        self.assertIn("disabled", said)
        self.assertNotIn("in use now", said)


class ABaseNameIsNotAvailableTest(_Store):
    """`elasticsearch-logs` belongs to the environment's source."""

    def setUp(self):
        super().setUp()
        self.app = self.worker(elasticsearch="http://127.0.0.1:1")
        self.client = self.app.test_client()
        self.sign_in(self.client)

    def test_the_form_refuses_the_name(self):
        response = self.save(name="elasticsearch-logs")
        said = " ".join(flashes(response))
        self.assertIn("reachable by nothing", said)
        self.assertEqual([s["name"] for s in self.app.store.sources.all()], [])

    def test_the_environment_source_is_still_the_default(self):
        self.save(name="elasticsearch-logs")
        with self.app.app_context():
            source = self.app.hub.logs()
        self.assertEqual(source.backend, "elasticsearch")
        self.assertEqual(source.name, "elasticsearch-logs")

    def test_a_source_cannot_be_called_every_source(self):
        response = self.save(name="*")
        self.assertIn("means every source", " ".join(flashes(response)))
        self.assertEqual([s["name"] for s in self.app.store.sources.all()], [])

    def test_the_agents_monitor_source_is_reserved_too(self):
        response = self.save(name="wdash-agents", kind="elasticsearch",
                             url="http://localhost:9200", signals=["monitors"])
        self.assertIn("reachable by nothing", " ".join(flashes(response)))

    def test_another_name_is_still_fine(self):
        self.save(name="loki-a")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["loki-a"])

    def test_a_rename_onto_a_base_name_is_refused(self):
        self.save(name="loki-a")
        row = next(s for s in self.app.store.sources.all())
        response = self.save(id=row["id"], name="elasticsearch-logs")
        self.assertIn("reachable by nothing", " ".join(flashes(response)))
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["loki-a"])

    def test_a_row_stored_before_the_check_keeps_the_environment_source(self):
        """Rows written before this existed are still in databases. The base
        source keeps the name; the stored one is shown as not in use."""
        self.app.store.sources.reserved_names = None
        self.app.store.sources.create(
            name="elasticsearch-logs", signal=["logs"], kind="loki",
            config={"url": "http://localhost:3100"})
        self.app.store.sources.reserved_names = self.app.hub.base_source_names
        with self.app.app_context():
            self.app.hub.reload()
            source = self.app.hub.logs("elasticsearch-logs")
            self.assertEqual(source.backend, "elasticsearch")
            self.assertEqual(self.app.hub.logs().name, "elasticsearch-logs")
            self.assertIn("elasticsearch-logs", self.app.hub.source_failures)
        body = self.client.get("/admin/config").get_data(as_text=True)
        self.assertIn("not in use", body)

    def test_a_row_can_still_be_edited_under_the_name_it_already_has(self):
        """Refusing the name on every save would leave such a row unsavable —
        it could not even be disabled."""
        self.app.store.sources.reserved_names = None
        row = self.app.store.sources.create(
            name="elasticsearch-logs", signal=["logs"], kind="loki",
            config={"url": "http://localhost:3100"})
        self.app.store.sources.reserved_names = self.app.hub.base_source_names
        updated = self.app.store.sources.update(row["id"],
                                                name="elasticsearch-logs",
                                                enabled=False)
        self.assertFalse(updated["enabled"])
        with self.assertRaises(SourceError):
            self.app.store.sources.update(row["id"], name="elasticsearch-traces")


class TheDefaultDoesNotMoveTest(_Store):
    """No environment source: the first source configured stays the default.

    The repository lists by name, and the hub's order is the interface, so
    `archive-es` added a month later took over every query that names no
    source — searches, the dashboard, the trace screen.
    """

    def test_adding_a_source_that_sorts_first_does_not_take_over(self):
        self.save(name="loki-prod", url="http://localhost:3100")
        with self.app.app_context():
            self.assertEqual(self.app.hub.logs().name, "loki-prod")
        self.save(name="archive-es", kind="victorialogs",
                  url="http://localhost:9428")
        with self.app.app_context():
            self.assertEqual(self.app.hub.logs().name, "loki-prod")
            self.assertEqual([s.name for s in self.app.hub.log_sources],
                             ["loki-prod", "archive-es"])

    def test_another_worker_agrees_about_which_one_it_is(self):
        """Order that came from the store, not from this process's history."""
        self.save(name="loki-prod", url="http://localhost:3100")
        self.save(name="archive-es", kind="victorialogs",
                  url="http://localhost:9428")
        other = self.worker()
        with other.app_context():
            self.assertEqual(other.hub.logs().name, "loki-prod")

    def test_the_page_still_lists_them_by_name(self):
        """The table is for reading; only the hub's order is the interface."""
        self.save(name="loki-prod", url="http://localhost:3100")
        self.save(name="archive-es", kind="victorialogs",
                  url="http://localhost:9428")
        self.assertEqual([s["name"] for s in self.app.store.sources.all()],
                         ["archive-es", "loki-prod"])


class ServicePickerTest(_Store):
    """A trace store that cannot be asked is named, not dropped."""

    def sources(self):
        from tests.test_trace_fanout import StubTraceSource
        from wdash.hub.adapters.tempo import TempoTraceSource
        from wdash.hub.models import Service

        answering = StubTraceSource(
            "jaeger-up",
            services=[Service(name="api-gateway", span_count=3, error_count=0)])
        down = TempoTraceSource(url=NOWHERE, name="tempo-down", timeout=5)
        return [answering, down]

    def setUp(self):
        super().setUp()
        self.app.hub.replace_all(logs=[], traces=self.sources())

    def test_the_store_that_did_not_answer_is_named(self):
        available = self.client.get("/admin/api/available").get_json()
        errors = {entry["source"]: entry["error"]
                  for entry in available["service_errors"]}
        self.assertIn("tempo-down", errors)
        self.assertTrue(errors["tempo-down"], available)

    def test_what_the_others_saw_is_still_offered(self):
        available = self.client.get("/admin/api/available").get_json()
        self.assertEqual(available["services"], ["api-gateway"])

    def test_every_store_answering_reports_no_errors(self):
        from tests.test_trace_fanout import StubTraceSource
        from wdash.hub.models import Service
        self.app.hub.replace_all(logs=[], traces=[StubTraceSource(
            "jaeger-up",
            services=[Service(name="api-gateway", span_count=3,
                              error_count=0)])])
        available = self.client.get("/admin/api/available").get_json()
        self.assertEqual(available["service_errors"], [])


if __name__ == "__main__":  # pragma: no cover - run through unittest
    raise SystemExit(
        "Run this through unittest: python -m unittest tests.test_source_liveness")
