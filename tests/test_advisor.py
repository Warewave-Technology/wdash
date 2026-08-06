"""
Advisor tests.

None of these need a live Elasticsearch. Because the rules are pure functions
over a snapshot, a snapshot captured from a real cluster is used directly as a
fixture.

To refresh the fixtures:
    PYTHONPATH=src python -m wdash.advisor --save-snapshot tests/fixtures/lab-cluster.json
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.advisor import ClusterSnapshot, run_rules  # noqa: E402
from wdash.advisor.models import Finding, Rule, Severity, all_rules  # noqa: E402
from wdash.advisor import models as advisor_models  # noqa: E402
from wdash.advisor.rules._util import (  # noqa: E402
    count_fields, is_aggregatable, parse_percent, resolve_field,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
LAB = os.path.join(FIXTURES, "lab-cluster.json")
LAB_COLD_CACHE = os.path.join(FIXTURES, "lab-cache-cold.json")

# The index deliberately left broken in the lab
BAD_INDEX = "bad-logs-000001"
# Correctly configured indices — they must not appear in any mapping finding
GOOD_INDICES = ["app-logs-000001", "service-logs-000001", "infra-logs-000001"]


def findings_by_rule(report, rule_id, severity=None):
    return [f for f in report.findings
            if f.rule_id == rule_id and (severity is None or f.severity == severity)]


class UtilTest(unittest.TestCase):
    def test_parse_percent(self):
        self.assertEqual(parse_percent("85%"), 85.0)
        self.assertEqual(parse_percent("92.5%"), 92.5)
        # Byte-valued thresholds are not percentages
        self.assertIsNone(parse_percent("100gb"))
        self.assertIsNone(parse_percent(None))

    def test_count_fields_counts_objects_and_multifields(self):
        properties = {
            "level": {"type": "keyword"},
            "message": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "service": {"properties": {"name": {"type": "keyword"},
                                       "version": {"type": "keyword"}}},
        }
        # level(1) + message(1) + message.keyword(1) + service(1) + name(1) + version(1)
        self.assertEqual(count_fields(properties), 6)

    def test_count_fields_handles_empty(self):
        self.assertEqual(count_fields(None), 0)
        self.assertEqual(count_fields({}), 0)

    def test_resolve_field_dotted_path(self):
        properties = {"service": {"properties": {"name": {"type": "keyword"}}}}
        self.assertEqual(resolve_field(properties, "service.name"), {"type": "keyword"})
        self.assertIsNone(resolve_field(properties, "service.missing"))
        self.assertIsNone(resolve_field(properties, "nope"))

    def test_is_aggregatable(self):
        self.assertEqual(is_aggregatable({"type": "keyword"}), (True, False))
        self.assertEqual(is_aggregatable({"type": "text"}), (False, False))
        self.assertEqual(
            is_aggregatable({"type": "text", "fields": {"keyword": {"type": "keyword"}}}),
            (True, True))
        # A keyword with doc_values disabled cannot be aggregated
        self.assertEqual(is_aggregatable({"type": "keyword", "doc_values": False}),
                         (False, False))


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.snapshot = ClusterSnapshot.load(LAB)

    def test_roundtrip(self):
        restored = ClusterSnapshot.from_dict(self.snapshot.to_dict())
        self.assertEqual(restored.cluster_name, self.snapshot.cluster_name)
        self.assertEqual(restored.version, self.snapshot.version)
        self.assertEqual(restored.user_indices(), self.snapshot.user_indices())

    def test_version_parsing(self):
        self.assertEqual(self.snapshot.version_tuple[:1], (8,))
        self.assertEqual(self.snapshot.distribution, "elasticsearch")

    def test_user_indices_excludes_system(self):
        indices = self.snapshot.user_indices()
        self.assertIn(BAD_INDEX, indices)
        self.assertFalse([i for i in indices if i.startswith(".")])

    def test_index_setting_lookup(self):
        self.assertEqual(self.snapshot.index_setting(BAD_INDEX, "index.number_of_shards"), "5")
        self.assertIsNone(self.snapshot.index_setting(BAD_INDEX, "index.lifecycle.name"))


class LabFixtureTest(unittest.TestCase):
    """Verify every deliberate fault in the lab is caught.

    These also act as regression protection: if a rule silently breaks, it is
    caught here.
    """

    @classmethod
    def setUpClass(cls):
        cls.report = run_rules(ClusterSnapshot.load(LAB))

    def test_no_rule_crashed(self):
        self.assertEqual(self.report.errors, [], f"rule errors: {self.report.errors}")

    def test_no_collection_errors(self):
        self.assertEqual(self.report.collection_errors, {})

    # --- mapping fixtures ---

    def test_map001_detects_text_aggregation_field(self):
        """level mapped as text -> the terms aggregation fails."""
        critical = findings_by_rule(self.report, "MAP001", Severity.CRITICAL)
        self.assertEqual(len(critical), 1)
        self.assertIn(BAD_INDEX, critical[0].targets)
        self.assertIn("level", critical[0].evidence)

    def test_map001_ignores_object_fields(self):
        """The service object field (trace schema) must not yield a false positive."""
        for finding in findings_by_rule(self.report, "MAP001"):
            self.assertNotIn("apm-traces-000001", finding.targets)
            self.assertNotIn("otel-traces-000001", finding.targets)

    def test_map002_detects_dynamic_mapping_growth(self):
        findings = findings_by_rule(self.report, "MAP002")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].targets, [BAD_INDEX])

    def test_map003_detects_field_limit_pressure(self):
        findings = findings_by_rule(self.report, "MAP003")
        self.assertTrue(findings)
        self.assertIn(BAD_INDEX, findings[0].targets)

    def test_map004_detects_redundant_keyword_subfield(self):
        findings = findings_by_rule(self.report, "MAP004")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].targets, [BAD_INDEX])

    # --- shard fixtures ---

    def test_shd003_detects_over_sharding(self):
        findings = findings_by_rule(self.report, "SHD003")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].targets, [BAD_INDEX])

    def test_shd004_detects_unassignable_replicas(self):
        findings = findings_by_rule(self.report, "SHD004")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].targets, [BAD_INDEX])

    # --- cluster and security fixtures ---

    def test_clu001_detects_yellow_status(self):
        findings = findings_by_rule(self.report, "CLU001")
        self.assertEqual(len(findings), 1)
        self.assertIn("yellow", findings[0].title)

    def test_sec001_detects_disabled_security(self):
        self.assertTrue(findings_by_rule(self.report, "SEC001", Severity.CRITICAL))

    # --- false positive protection ---

    def test_good_indices_have_no_mapping_findings(self):
        """Correctly configured indices must not appear in any mapping finding."""
        for finding in self.report.findings:
            if not finding.rule_id.startswith("MAP"):
                continue
            for index in GOOD_INDICES:
                self.assertNotIn(
                    index, finding.targets,
                    f"{finding.rule_id} raised a false alarm on healthy index {index}")

    def test_good_indices_not_over_sharded(self):
        for rule_id in ("SHD002", "SHD003", "SHD004"):
            for finding in findings_by_rule(self.report, rule_id):
                for index in GOOD_INDICES:
                    self.assertNotIn(index, finding.targets)

    def test_some_rules_pass(self):
        """If every rule fires, the thresholds are set wrong."""
        self.assertGreater(len(self.report.passed), 5)


class ColdCacheFixtureTest(unittest.TestCase):
    """Is the timestamp format that breaks the cache key detected?"""

    @classmethod
    def setUpClass(cls):
        cls.report = run_rules(ClusterSnapshot.load(LAB_COLD_CACHE))

    def test_qry001_detects_cache_thrashing(self):
        findings = findings_by_rule(self.report, "QRY001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)


class RegistryTest(unittest.TestCase):
    def test_rule_ids_are_unique(self):
        ids = [r.id for r in all_rules()]
        self.assertEqual(len(ids), len(set(ids)), "rule ids must be unique")

    def test_every_rule_has_metadata(self):
        for r in all_rules():
            self.assertTrue(r.title, f"{r.id} has no title")
            self.assertTrue(r.category, f"{r.id} has no category")

    def test_every_finding_is_actionable(self):
        """Quality gate: every finding needs evidence, impact and a concrete fix.

        Advice along the lines of "review this" gains the user nothing.
        """
        report = run_rules(ClusterSnapshot.load(LAB))
        for finding in report.findings:
            self.assertTrue(finding.evidence.strip(), f"{finding.rule_id}: evidence is empty")
            self.assertTrue(finding.impact.strip(), f"{finding.rule_id}: impact is empty")
            self.assertTrue(finding.remediation.strip(), f"{finding.rule_id}: remediation is empty")
            self.assertGreater(len(finding.remediation), 30,
                               f"{finding.rule_id}: remediation is too shallow")


class RobustnessTest(unittest.TestCase):
    def test_broken_rule_does_not_break_report(self):
        """A failing rule must not bring the report down."""
        def exploding_rule(snapshot):
            raise RuntimeError("deliberately raised")

        broken = Rule(id="ZZZ999", category="test", title="exploding rule",
                      check=exploding_rule)
        advisor_models._REGISTRY.append(broken)
        try:
            report = run_rules(ClusterSnapshot.load(LAB))
            self.assertIn("ZZZ999", [rule_id for rule_id, _ in report.errors])
            # The other rules must still have run
            self.assertTrue(report.findings)
        finally:
            advisor_models._REGISTRY.remove(broken)

    def test_empty_snapshot_produces_no_crash(self):
        """No rule may fail on a completely empty snapshot."""
        report = run_rules(ClusterSnapshot(taken_at="1970-01-01T00:00:00Z"))
        self.assertEqual(report.errors, [], f"errors on an empty snapshot: {report.errors}")

    def test_report_serialises(self):
        report = run_rules(ClusterSnapshot.load(LAB))
        data = report.to_dict()
        self.assertIn("findings", data)
        self.assertIn("score", data)
        self.assertIsInstance(data["counts"], dict)


class ScoringTest(unittest.TestCase):
    def test_clean_report_scores_full(self):
        report = run_rules(ClusterSnapshot(taken_at="x"))
        self.assertEqual(report.score, 100)

    def test_score_never_negative(self):
        report = run_rules(ClusterSnapshot(taken_at="x"))
        report.findings = [
            Finding(rule_id=f"X{i}", category="c", severity=Severity.CRITICAL,
                    title="t", evidence="e", impact="i", remediation="r")
            for i in range(50)
        ]
        self.assertEqual(report.score, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ReportSourceNameTest(unittest.TestCase):
    """`Report.source` has to mean one thing.

    It is documented as the configured source this report is about. It used to
    fall back to the cluster's own name when a snapshot carried no source name
    — which is a different thing, already has its own field, and made the
    meaning depend on the backend: the WDash source name for Loki, the cluster
    name for Elasticsearch. Anything matching on it then failed for exactly
    one backend, quietly. The source picker did: it showed nothing selected
    beside an Elasticsearch report.
    """

    def _report(self):
        fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                               "lab-cluster.json")
        return run_rules(ClusterSnapshot.load(fixture))

    def test_an_elasticsearch_snapshot_carries_no_source_name(self):
        """`collect()` is handed a client and never learns what the
        configuration page calls it. Whoever knows has to say so."""
        report = self._report()
        self.assertEqual(report.source, "")

    def test_the_cluster_name_is_still_there_under_its_own_name(self):
        """Dropping the fallback must not lose it — the page reads it."""
        self.assertEqual(self._report().cluster_name, "wdash-lab")
