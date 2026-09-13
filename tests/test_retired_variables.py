"""
Variables an earlier version configured a whole subsystem from, and what an
installation that still sets one is told.

The Elasticsearch a deployment ran on used to be declared in the
environment, ahead of everything stored. It is a stored source now, and the
only kind. An installation upgrading with the variables still set would
come up with no log source, and a page saying "No log source is configured"
over a cluster that was answering yesterday reads as an outage rather than
as a variable. So the application looks at those names at start-up — to say
so, as an ERROR naming them and the page, and for nothing else. They are not
imported into the store either: a one-shot import at start-up is exactly the
mechanism that was removed.
"""

import logging
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import RETIRED  # noqa: E402

from wdash.app import (  # noqa: E402
    RETIRED_VARIABLES, create_app, variables_left_behind,
)
from wdash.config import Config  # noqa: E402
from wdash.store.secrets import SecretBox  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "retired"
    DATABASE_URL = "sqlite:///:memory:"
    ENCRYPTION_KEY = SecretBox.generate_key()
    OIDC_CLIENT_ID = None


class Captured(logging.Handler):
    def __init__(self):
        super().__init__()
        self.errors = []

    def emit(self, record):
        if record.levelno >= logging.ERROR:
            self.errors.append(record.getMessage())


def started_with(**environment):
    """An app started with these variables set, and the ERRORs it logged."""
    handler = Captured()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        with mock.patch.dict(os.environ, environment):
            app = create_app(TestConfig)
    finally:
        root.removeHandler(handler)
    return app, handler.errors


class TheSentenceTest(unittest.TestCase):
    """`variables_left_behind`, pure, over any mapping."""

    def test_nothing_set_says_nothing(self):
        self.assertEqual(variables_left_behind({}), [])
        self.assertEqual(variables_left_behind({"DATABASE_URL": "x"}), [])

    def test_an_empty_value_is_not_set(self):
        """It configured nothing before either — an empty cluster address
        was how a deployment said "no cluster here"."""
        self.assertEqual(variables_left_behind({"ELASTICSEARCH_URL": "",
                                                "TRACE_INDEX_PATTERNS": " "}),
                         [])

    def test_every_variable_that_is_set_is_named_and_the_page_with_it(self):
        said = variables_left_behind({"ELASTICSEARCH_URL": "http://es:9200",
                                      "TRACE_INDEX_PATTERNS": "*traces*",
                                      "DATABASE_URL": "sqlite:///x"})
        self.assertEqual(len(said), 1, said)
        sentence = said[0]
        self.assertIn("ELASTICSEARCH_URL and TRACE_INDEX_PATTERNS are set",
                      sentence)
        self.assertNotIn("ELASTICSEARCH_USERNAME", sentence)
        self.assertIn("no longer reads them", sentence)
        self.assertIn("configuration page, under Sources", sentence)
        self.assertIn("Nothing was read", sentence)
        self.assertIn("have no source", sentence)

    def test_one_variable_is_named_in_the_singular(self):
        said = variables_left_behind({"MONITOR_INDEX_PATTERNS": "hb-*"})
        self.assertEqual(len(said), 1)
        self.assertIn("MONITOR_INDEX_PATTERNS is set, and WDash no longer "
                      "reads it", said[0])

    def test_the_harness_clears_exactly_the_names_the_application_refuses(self):
        """`tests/__init__.py` pops them before anything is imported, so a
        developer's shell cannot put this ERROR under every app the suite
        builds. Two lists, held to each other."""
        refused = {name for names, *_ in RETIRED_VARIABLES for name in names}
        self.assertEqual(set(RETIRED), refused)

    def test_config_carries_none_of_them(self):
        """Read into nothing: no attribute, no default, no fallback."""
        for name in RETIRED:
            with self.subTest(variable=name):
                self.assertFalse(hasattr(Config, name),
                                 f"Config still reads {name}")


class AtStartUpTest(unittest.TestCase):
    """What an installation that still sets one is told, and not given."""

    def test_it_is_said_as_an_error_naming_the_variables(self):
        _, errors = started_with(ELASTICSEARCH_URL="http://127.0.0.1:1",
                                 ELASTICSEARCH_VERIFY_CERTS="false")
        said = [line for line in errors if "no longer reads" in line]
        self.assertEqual(len(said), 1, errors)
        self.assertIn("ELASTICSEARCH_URL and ELASTICSEARCH_VERIFY_CERTS are "
                      "set", said[0])
        self.assertIn("under Sources", said[0])

    def test_nothing_is_read_from_them(self):
        """The cluster the variable names is not registered, under any name:
        the installation has what is stored and nothing else."""
        app, _ = started_with(ELASTICSEARCH_URL="http://127.0.0.1:1",
                              TRACE_INDEX_PATTERNS="*traces*",
                              MONITOR_INDEX_PATTERNS="heartbeat-*")
        self.assertEqual(app.hub.log_sources, [])
        self.assertEqual(app.hub.trace_sources, [])
        self.assertEqual([s.name for s in app.hub.monitor_sources],
                         ["wdash-agents"])

    def test_nothing_is_imported_into_the_store(self):
        """An implicit one-shot import is the mechanism being removed. The
        variables are named in the log, not written anywhere."""
        app, _ = started_with(ELASTICSEARCH_URL="http://127.0.0.1:1",
                              ELASTICSEARCH_USERNAME="elastic",
                              ELASTICSEARCH_PASSWORD="hunter2")
        self.assertEqual(app.store.sources.all(), [])

    def test_with_none_set_nothing_is_said(self):
        _, errors = started_with()
        self.assertEqual([line for line in errors if "no longer reads" in line],
                         [])


#: What a person reads before setting a variable, and so what must not tell
#: them to set one of these. README.md is not here: its upgrade note names
#: them on purpose, to say they are no longer read. `src/wdash/app.py` is not
#: here either: it holds the list itself.
DOCUMENTS = ("templates", "kubernetes", "docs", ".env.example", "run.sh",
             "docker-compose.yml", "Dockerfile", "CONTRIBUTING.md",
             "SECURITY.md", "ROADMAP.md", "lab/README.md", "lab/lab.sh",
             os.path.join(".github", "workflows"))


def _files_under(path):
    full = os.path.join(ROOT, path)
    if os.path.isfile(full):
        yield full
        return
    for directory, subdirectories, files in os.walk(full):
        subdirectories[:] = [d for d in subdirectories
                             if d not in ("__pycache__", "logo", "themes")]
        for filename in files:
            if filename.endswith((".py", ".html", ".md", ".yaml", ".yml",
                                  ".sh", ".txt", ".example", ".js")):
                yield os.path.join(directory, filename)


class NoDocumentTellsAnybodyToSetOneTest(unittest.TestCase):
    """Every sentence that told somebody to set one of these is replaced by
    the sentence that says where it is configured now. A document that
    still names one sends the reader to a variable nothing reads."""

    def test_the_source_looks_at_them_only_in_the_list(self):
        for directory, subdirectories, files in os.walk(os.path.join(ROOT, "src")):
            subdirectories[:] = [d for d in subdirectories if d != "__pycache__"]
            for filename in files:
                if not filename.endswith(".py") or filename == "app.py":
                    continue
                path = os.path.join(directory, filename)
                with open(path, encoding="utf-8") as handle:
                    text = handle.read()
                found = sorted(name for name in RETIRED if name in text)
                with self.subTest(file=os.path.relpath(path, ROOT)):
                    self.assertEqual(found, [], f"names {found}")

    def test_no_document_names_one(self):
        for document in DOCUMENTS:
            for path in _files_under(document):
                with open(path, encoding="utf-8") as handle:
                    text = handle.read()
                found = sorted(name for name in RETIRED if name in text)
                with self.subTest(file=os.path.relpath(path, ROOT)):
                    self.assertEqual(found, [], f"names {found}")


if __name__ == "__main__":
    unittest.main()
