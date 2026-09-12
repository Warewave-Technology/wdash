"""
One source, several signals.

A row used to mean a signal, so an Elasticsearch cluster holding both logs and
traces needed two entries. That is not merely untidy: it is two credentials to
rotate, two `verify_certs` settings that can drift apart, two rows in the
health check for one system, and — the one that bites — a rotation where
somebody updates one and not the other.

Two properties matter beyond the tidiness.

**Patterns are per signal.** A single index-pattern list for both means a
trace search scans the log indices, which is slow and returns bodyless
records.

**An existing row keeps working.** The old flat config and the old single
`signal` column are both still read, because a migration that changes what a
stored source means is not a migration.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.store import Store  # noqa: E402
from wdash.store.sources import SourceError, normalise_signals  # noqa: E402

ES = {"url": "http://cluster:9200", "verify_certs": True,
      "logs": {"index_patterns": ["app-*"], "exclude_patterns": ["*traces*"]},
      "traces": {"index_patterns": ["*apm*"]}}


class SignalTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = Store.open(f"sqlite:///{self.database}")

    def tearDown(self):
        self.store.engine.dispose()
        os.unlink(self.database)

    def create(self, name="cluster", signal=("logs", "traces"), kind="elasticsearch",
               config=None):
        return self.store.sources.create(
            name=name, signal=list(signal), kind=kind,
            config=dict(config if config is not None else ES))


class NormalisationTest(unittest.TestCase):
    def test_a_single_string_is_accepted(self):
        """Every caller written before this passes a string."""
        self.assertEqual(normalise_signals("loki", "logs"), ["logs"])

    def test_both_signals_are_accepted(self):
        self.assertEqual(normalise_signals("elasticsearch", ["traces", "logs"]),
                         ["logs", "traces"])

    def test_the_order_is_the_kind_s_own(self):
        """So two identical sources compare equal however the form submitted
        them."""
        self.assertEqual(normalise_signals("elasticsearch", ["traces", "logs"]),
                         normalise_signals("elasticsearch", ["logs", "traces"]))

    def test_a_signal_the_kind_cannot_serve_is_refused(self):
        with self.assertRaises(SourceError) as caught:
            normalise_signals("loki", ["logs", "traces"])
        self.assertIn("traces", str(caught.exception))

    def test_no_signal_at_all_is_refused(self):
        """A source serving nothing would register nowhere and appear to work."""
        with self.assertRaises(SourceError):
            normalise_signals("elasticsearch", [])

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(SourceError):
            normalise_signals("carrier-pigeon", ["logs"])


class StorageTest(SignalTestCase):
    def test_one_row_serves_both(self):
        row = self.create()
        self.assertEqual(row["signals"], ["logs", "traces"])

    def test_listing_by_signal_finds_it_under_each(self):
        self.create()
        self.assertEqual([r["name"] for r in self.store.sources.all("logs")],
                         ["cluster"])
        self.assertEqual([r["name"] for r in self.store.sources.all("traces")],
                         ["cluster"])

    def test_a_single_signal_source_is_not_found_under_the_other(self):
        self.create(name="loki", signal=("logs",), kind="loki",
                    config={"url": "http://loki:3100"})
        self.assertEqual(self.store.sources.all("traces"), [])

    def test_the_legacy_column_is_still_populated(self):
        """It is NOT NULL, and dropping a column is not a migration worth the
        risk. Written, never read."""
        from sqlalchemy import select

        from wdash.store.schema import sources
        self.create()
        with self.store.engine.connect() as connection:
            value = connection.execute(select(sources.c.signal)).scalar()
        self.assertEqual(value, "logs")

    def test_signals_can_be_changed_on_an_existing_row(self):
        """The merge somebody performs by hand: one row grows a second signal
        and the duplicate is deleted."""
        row = self.create(signal=("traces",),
                          config={"url": "http://cluster:9200",
                                  "traces": {"index_patterns": ["*apm*"]}})
        updated = self.store.sources.update(
            row["id"], signals=["logs", "traces"], config=ES)
        self.assertEqual(updated["signals"], ["logs", "traces"])

    def test_a_name_cannot_be_reused(self):
        self.create(name="cluster")
        with self.assertRaises(SourceError):
            self.create(name="cluster")


class OneNamePerSignalTest(SignalTestCase):
    """Two sources can share a name only while no signal is shared.

    The database can refuse a repeat of (name, legacy signal) and nothing
    more, so an Elasticsearch source called `prod` serving logs and traces
    was accepted alongside a Jaeger `prod` serving traces. Both were stored,
    both were built into adapters, and the hub keys one registry per signal
    by name — so one of them answered every trace query, the `*` fan-out
    included, and the other was never asked. Both showed as healthy.
    """

    JAEGER = {"url": "http://jaeger:16686"}
    TEMPO = {"url": "http://tempo:3200"}
    LOKI = {"url": "http://loki:3100"}

    def test_a_name_taken_in_a_shared_signal_is_refused(self):
        self.create(name="prod")
        with self.assertRaises(SourceError) as caught:
            self.store.sources.create(name="prod", signal=["traces"],
                                      kind="jaeger", config=dict(self.JAEGER))
        self.assertIn("traces", str(caught.exception))
        self.assertEqual([s["name"] for s in self.store.sources.all()],
                         ["prod"])

    def test_the_legacy_pair_is_still_allowed(self):
        """Migration 7 deliberately left one row for logs and one for traces
        sharing a name, for an operator to merge by hand. Refusing every
        repeated name would make those pairs uneditable."""
        self.create(name="eu", signal=("logs",), kind="loki",
                    config=dict(self.LOKI))
        self.store.sources.create(name="eu", signal=["traces"], kind="tempo",
                                  config=dict(self.TEMPO))
        self.assertEqual(len(self.store.sources.all()), 2)

    def test_a_rename_onto_a_shared_signal_is_refused(self):
        self.create(name="prod")
        other = self.store.sources.create(
            name="spare", signal=["traces"], kind="jaeger",
            config=dict(self.JAEGER))
        with self.assertRaises(SourceError):
            self.store.sources.update(other["id"], name="prod")
        self.assertEqual(
            sorted(s["name"] for s in self.store.sources.all()),
            ["prod", "spare"])

    def test_growing_into_a_signal_somebody_else_serves_is_refused(self):
        """The same collision arriving from the other direction: the name
        was already shared, legitimately, and one of the two reaches for the
        signal the other has."""
        self.create(name="eu", signal=("logs",))
        traces = self.create(name="eu", signal=("traces",),
                             config={"url": "http://cluster:9200",
                                     "traces": {"index_patterns": ["*apm*"]}})
        with self.assertRaises(SourceError):
            self.store.sources.update(traces["id"], signals=["logs", "traces"])
        self.assertEqual(
            self.store.sources.get(traces["id"])["signals"], ["traces"])

    def test_a_source_can_still_be_saved_under_its_own_name(self):
        """The check must not read a row as its own duplicate."""
        row = self.create(name="prod")
        saved = self.store.sources.update(row["id"], name="prod",
                                          signals=["logs", "traces"])
        self.assertEqual(saved["name"], "prod")

    def test_an_enabled_holder_is_described_as_serving_the_signal(self):
        """Held so the sentence below cannot be fixed by making both cases
        vague."""
        self.create(name="prod")
        with self.assertRaises(SourceError) as caught:
            self.store.sources.create(name="prod", signal=["traces"],
                                      kind="jaeger", config=dict(self.JAEGER))
        self.assertIn("already exists and serves traces",
                      str(caught.exception))

    def test_a_disabled_holder_is_not_said_to_serve_anything(self):
        """Refusing is right — re-enabling it would collide — but the
        refusal said the holder "already exists and serves traces", and a
        disabled source serves nothing: only enabled rows are built into
        adapters. Somebody switching a source off in order to replace it
        with a differently-kinded one of the same name was blocked by a
        sentence that was not true, and told nothing about how to proceed.
        """
        self.store.sources.create(name="prod", signal=["logs", "traces"],
                                  kind="elasticsearch", config=dict(ES),
                                  enabled=False)
        with self.assertRaises(SourceError) as caught:
            self.store.sources.create(name="prod", signal=["traces"],
                                      kind="jaeger", config=dict(self.JAEGER))
        message = str(caught.exception)
        # The words two tests in tests.test_config_page.SourceTest depend on.
        self.assertIn("already exists", message)
        self.assertIn("traces", message)
        self.assertIn("switched off", message)
        self.assertNotIn("serves traces", message)


class TheHubSaysWhenTwoSourcesShareANameTest(unittest.TestCase):
    """A store that already holds the pair `create` now refuses — made
    before this, or edited straight against the database — keeps exactly one
    of them reachable. That has to be said out loud somewhere."""

    class Fake:
        def __init__(self, name):
            self.name = name

    def test_the_collision_is_logged_and_one_source_is_kept(self):
        from wdash.hub import Hub

        hub = Hub()
        with self.assertLogs("wdash.hub", "WARNING") as caught:
            hub.reload_with(
                lambda: {"traces": [self.Fake("prod"), self.Fake("prod")]},
                lambda: 1)
        self.assertIn("prod", "\n".join(caught.output))
        self.assertEqual(len(hub.trace_sources), 1)

    def test_one_source_per_name_says_nothing(self):
        from wdash.hub import Hub

        hub = Hub()
        with self.assertNoLogs("wdash.hub", "WARNING"):
            hub.reload_with(
                lambda: {"traces": [self.Fake("prod"), self.Fake("eu")]},
                lambda: 1)
        self.assertEqual(len(hub.trace_sources), 2)


class PerSignalConfigTest(SignalTestCase):
    def test_each_signal_keeps_its_own_patterns(self):
        """One list for both means a trace search scans the log indices."""
        row = self.create()
        self.assertEqual(row["config"]["logs"]["index_patterns"], ["app-*"])
        self.assertEqual(row["config"]["traces"]["index_patterns"], ["*apm*"])

    def test_shared_settings_stay_shared(self):
        """The whole point: one URL, one credential, one TLS setting."""
        row = self.create()
        self.assertEqual(row["config"]["url"], "http://cluster:9200")
        self.assertNotIn("url", row["config"]["logs"])

    def test_a_comma_separated_string_is_split(self):
        row = self.create(config={"url": "http://cluster:9200",
                                  "logs": {"index_patterns": "app-*, infra-*"},
                                  "traces": {"index_patterns": "*apm*"}})
        self.assertEqual(row["config"]["logs"]["index_patterns"],
                         ["app-*", "infra-*"])


class AdapterBuildingTest(SignalTestCase):
    """One row has to become one adapter per signal."""

    def _build(self, row, signal):
        from wdash.hub.factory import build_source
        return build_source(row, None, catalogue=None, signal=signal)

    def test_a_row_becomes_a_log_source_and_a_trace_source(self):
        row = self.create()
        from wdash.hub.source import LogSource, TraceSource
        self.assertIsInstance(self._build(row, "logs"), LogSource)
        self.assertIsInstance(self._build(row, "traces"), TraceSource)

    def test_each_adapter_gets_its_own_patterns(self):
        row = self.create()
        self.assertEqual(self._build(row, "logs")._patterns, ("app-*",))
        self.assertEqual(self._build(row, "traces")._patterns, ("*apm*",))

    def test_a_trace_source_left_blank_reads_the_trace_indices(self):
        """The form's trace-pattern field shows `*traces*, *apm*` as its
        placeholder, and left blank the source read `*`: every index in the
        cluster was a candidate trace store. Measured on the lab: all six
        indices, the log indices among them, where the placeholder names
        two. The log side keeps its `*`."""
        for traces in ({"index_patterns": ""}, None):
            config = {"url": "http://cluster:9200",
                      "logs": {"index_patterns": ["app-*"]}}
            if traces is not None:
                config["traces"] = traces
            row = self.create(name=f"cluster-{traces is None}", config=config)
            self.assertEqual(self._build(row, "traces")._patterns,
                             ("*traces*", "*apm*"), config)
            self.assertEqual(self._build(dict(row, config={"url": "http://c:9200"}),
                                         "logs")._patterns, ("*",))

    def test_both_adapters_carry_the_source_name(self):
        """So the log picker and the trace picker say the same thing, and a
        record's badge names the source rather than the signal."""
        row = self.create()
        self.assertEqual(self._build(row, "logs").name, "cluster")
        self.assertEqual(self._build(row, "traces").name, "cluster")

    def test_a_legacy_flat_config_still_builds(self):
        """A source stored before a row could serve two signals keeps its
        patterns at the top level. A migration that changes what a stored
        source means is not a migration."""
        row = self.create(signal=("logs",),
                          config={"url": "http://cluster:9200",
                                  "index_patterns": ["legacy-*"]})
        # `validate` drops unknown top-level keys, so put it back the way an
        # untouched row from before the change looks.
        legacy = dict(row, config={"url": "http://cluster:9200",
                                   "index_patterns": ["legacy-*"]},
                      signals=["logs"])
        self.assertEqual(self._build(legacy, "logs")._patterns, ("legacy-*",))


class RegistrationTest(SignalTestCase):
    def test_a_two_signal_row_registers_twice(self):
        from wdash.hub import Hub
        from wdash.hub.factory import register_configured_sources

        self.create()
        hub = Hub()
        registered = register_configured_sources(hub, self.store)
        self.assertEqual(registered, 2)
        self.assertEqual([s.name for s in hub.log_sources], ["cluster"])
        self.assertEqual([s.name for s in hub.trace_sources], ["cluster"])

    def _register_with_one_signal_broken(self, broken):
        from wdash.hub import Hub
        from wdash.hub.factory import register_configured_sources
        import wdash.hub.factory as factory

        self.create()
        hub = Hub()
        original = factory.build_source

        def selective(record, credential, catalogue=None, signal=None):
            if signal == broken:
                raise RuntimeError("no")
            return original(record, credential, catalogue, signal)

        factory.build_source = selective
        try:
            registered = register_configured_sources(hub, self.store)
        finally:
            factory.build_source = original
        return hub, registered

    def test_a_broken_trace_side_does_not_cost_the_log_side(self):
        hub, registered = self._register_with_one_signal_broken("traces")
        self.assertEqual(registered, 1)
        self.assertEqual([s.name for s in hub.log_sources], ["cluster"])
        self.assertEqual(hub.trace_sources, [])

    def test_a_broken_log_side_does_not_cost_the_trace_side(self):
        """The other order, and the one that matters.

        `logs` is registered first, so a handler that abandons the loop rather
        than skipping the signal produces exactly the same result as skipping
        when the SECOND signal fails. Only breaking the first tells them
        apart.
        """
        hub, registered = self._register_with_one_signal_broken("logs")
        self.assertEqual(registered, 1)
        self.assertEqual(hub.log_sources, [])
        self.assertEqual([s.name for s in hub.trace_sources], ["cluster"])


if __name__ == "__main__":
    unittest.main()
