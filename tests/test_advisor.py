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
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.advisor import ClusterSnapshot, run_rules  # noqa: E402
from wdash.advisor.models import Finding, Rule, Severity, all_rules  # noqa: E402
from wdash.advisor import models as advisor_models  # noqa: E402
from wdash.advisor.rules._util import (  # noqa: E402
    count_fields, is_aggregatable, resolve_field,
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
    def test_parse_watermark(self):
        """A watermark is a percentage, a ratio or a byte size, the way
        Elasticsearch reads one. It used to be a percentage or nothing, and
        nothing became 85/90/95 — so '0.97' was judged at 95% and '10gb' at
        90%."""
        from wdash.advisor.rules._util import parse_watermark

        kind, ratio = parse_watermark("85%")
        self.assertEqual(kind, "ratio")
        self.assertAlmostEqual(ratio, 0.85)
        self.assertAlmostEqual(parse_watermark("92.5%")[1], 0.925)
        self.assertEqual(parse_watermark("0.97")[0], "ratio")
        self.assertAlmostEqual(parse_watermark("0.97")[1], 0.97)
        # Byte-valued thresholds are bytes, in Elasticsearch's binary units
        self.assertEqual(parse_watermark("100gb"), ("bytes", 100 * 1024 ** 3))
        self.assertEqual(parse_watermark("500MB"), ("bytes", 500 * 1024 ** 2))
        self.assertIsNone(parse_watermark(None))
        self.assertIsNone(parse_watermark("lots"))
        self.assertIsNone(parse_watermark("101%"))
        self.assertIsNone(parse_watermark("1.5"), "a ratio above one")

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


# ---------------------------------------------------------------------------
# What a failed or missing input does to a verdict
# ---------------------------------------------------------------------------

#: Every field `collect()` fills, one call each.
COLLECTED = tuple(name for name in ClusterSnapshot.__dataclass_fields__
                  if name not in ("taken_at", "errors"))

TB = 1024 ** 4
GB = 1024 ** 3


def _lab():
    return ClusterSnapshot.load(LAB)


def _failed(snapshot, *names):
    """The snapshot as `collect()` leaves it when those calls failed: the
    field empty, the error recorded."""
    for name in names:
        setattr(snapshot, name, type(getattr(snapshot, name))())
        snapshot.errors[name] = ("AuthorizationException(403, 'security_exception', "
                                 "'action is unauthorized')")
    return snapshot


def _ids(entries):
    return {entry[0] for entry in entries}


class NotCollectedTest(unittest.TestCase):
    """A rule whose input never arrived has not passed.

    It used to: `run_rules` filed every rule that yielded nothing under
    `passed`. A cluster that refused every call scored 100 with all 31 rules
    passed, and one that refused only _nodes/info moved CLU004, CLU005,
    CLU009, SEC001 and SEC003 from their findings into "passed".
    """

    def test_a_failed_call_takes_its_rules_out_of_passed(self):
        before = run_rules(_lab())
        after = run_rules(_failed(_lab(), "nodes_info"))
        self.assertEqual(_ids(after.passed) - _ids(before.passed), set(),
                         "rules passed on data that never arrived")
        for rule_id in ("CLU004", "CLU005", "CLU009", "SEC001", "SEC003"):
            self.assertIn(rule_id, _ids(after.not_evaluated), rule_id)
        reasons = {rule_id: why for rule_id, _, why in after.not_evaluated}
        self.assertIn("nodes_info", reasons["SEC001"])

    def test_the_rules_that_did_not_need_it_still_ran(self):
        """Not all or nothing: MAP001 reads mappings, not nodes."""
        after = run_rules(_failed(_lab(), "nodes_info"))
        self.assertTrue(findings_by_rule(after, "MAP001", Severity.CRITICAL))
        self.assertIn("SHD002", _ids(after.passed))

    def test_nothing_collected_is_not_a_clean_report(self):
        report = run_rules(_failed(ClusterSnapshot(taken_at="x"), *COLLECTED))
        self.assertEqual(report.passed, [],
                         "rules passed against a cluster that answered nothing")
        self.assertEqual(report.findings, [])
        self.assertEqual(len(report.not_evaluated),
                         len(all_rules("elasticsearch")))
        self.assertTrue(report.unavailable)
        self.assertFalse(report.complete)
        self.assertIsNone(report.score,
                          "a score of 100 for a cluster nobody could read")
        self.assertIsNone(report.to_dict()["score"])

    def test_a_complete_report_says_so(self):
        report = run_rules(_lab())
        self.assertEqual(report.not_evaluated, [])
        self.assertTrue(report.complete)
        self.assertFalse(report.unavailable)

    def test_a_partial_report_is_neither(self):
        report = run_rules(_failed(_lab(), "nodes_info"))
        self.assertFalse(report.complete)
        self.assertFalse(report.unavailable)
        self.assertIsNotNone(report.score)
        self.assertEqual(
            {entry["rule_id"] for entry in report.to_dict()["not_evaluated"]},
            _ids(report.not_evaluated))

    def test_a_failure_no_rule_reads_still_makes_the_report_incomplete(self):
        """Nothing depends on ILM policies today. The report still cannot
        say it saw everything."""
        report = run_rules(_failed(_lab(), "ilm_policies"))
        self.assertEqual(report.not_evaluated, [])
        self.assertFalse(report.complete)

    def test_an_answer_listing_no_nodes_says_nothing_about_backups(self):
        """No failed call, and no nodes either: the empty repository list is
        not known to be this cluster's."""
        report = run_rules(ClusterSnapshot(taken_at="x", nodes_info={"nodes": {}}))
        self.assertNotIn("SEC003", _ids(report.passed))
        self.assertNotIn("SEC003", {f.rule_id for f in report.findings})
        self.assertIn("SEC003", _ids(report.not_evaluated))

    def test_whether_ilm_applies_depends_on_the_distribution(self):
        """IDX002 is an Elasticsearch rule; which one this is comes from
        GET /. Unanswered, the distribution defaults to Elasticsearch and
        an OpenSearch cluster would be told to attach ILM."""
        report = run_rules(_failed(_lab(), "info"))
        self.assertIn("IDX002", _ids(report.not_evaluated))

    def test_every_rule_says_what_it_needs(self):
        for registered in all_rules():
            self.assertTrue(registered.needs, f"{registered.id} declares nothing")

    def test_an_elasticsearch_rule_needs_only_what_is_collected(self):
        """A misspelt need never matches an error: a check that never
        fires."""
        for registered in all_rules("elasticsearch"):
            self.assertLessEqual(set(registered.needs), set(COLLECTED),
                                 registered.id)

    #: Fields a rule reads for its wording but not for its verdict. CLU001's
    #: status comes from _cluster/health; _cat/shards only names the
    #: indices, and losing it must not hide a red cluster.
    DETAIL_ONLY = {"CLU001": {"cat_shards"}}

    def test_every_rule_declares_what_it_reads(self):
        """What a rule reads is what it needs — measured, not trusted.

        A rule that reads a field it does not declare passes when that call
        fails, which is the fault this class is about."""

        class Recording(ClusterSnapshot):
            def __getattribute__(self, name):
                if name in COLLECTED:
                    object.__getattribute__(self, "__dict__").setdefault(
                        "_reads", set()).add(name)
                return object.__getattribute__(self, name)

        # Three nodes, so the multi-node branches read what they read too.
        three = _lab()
        for part in (three.nodes_info, three.nodes_stats):
            (node_id, value), = part["nodes"].items()
            part["nodes"] = {f"{node_id}-{i}": value for i in range(3)}
        sources = [_lab(), ClusterSnapshot.load(LAB_COLD_CACHE), three]

        from wdash.advisor.models import NotEvaluated
        undeclared, read_anything = {}, 0
        for registered in all_rules("elasticsearch"):
            reads = set()
            for source in sources:
                snapshot = Recording(**source.to_dict())
                try:
                    list(registered.check(snapshot) or [])
                except NotEvaluated:
                    pass
                reads |= snapshot.__dict__.get("_reads", set())
            read_anything += bool(reads)
            extra = (reads - set(registered.needs)
                     - self.DETAIL_ONLY.get(registered.id, set()))
            if extra:
                undeclared[registered.id] = sorted(extra)
        self.assertEqual(undeclared, {}, "rules reading what they do not declare")
        # A recording that records nothing passes the line above for every
        # rule.
        self.assertEqual(read_anything, len(all_rules("elasticsearch")))


def _three_data_nodes():
    nodes = {f"n{i}": {"name": f"n{i}", "roles": ["data", "master"]}
             for i in range(3)}
    shards = [{"index": "a", "shard": str(i), "prirep": "p", "state": "STARTED"}
              for i in range(800)]
    return ClusterSnapshot(
        taken_at="x", nodes_info={"nodes": nodes}, cat_shards=shards,
        cluster_settings={"defaults": {"cluster.max_shards_per_node": "1000"}},
        index_settings={"a": {"settings": {"index.number_of_replicas": "1"}}})


class DataNodeCountTest(unittest.TestCase):
    """How many data nodes there are, when _nodes/info did not say.

    `data_node_count` answered 1. SHD004 then told a three-node cluster that
    its replicas could never be allocated, and SHD005 put it at 80% of a
    shard limit it was at 27% of.
    """

    def test_three_nodes_are_three(self):
        snapshot = _three_data_nodes()
        self.assertEqual(snapshot.data_node_count, 3)
        report = run_rules(snapshot)
        self.assertFalse([f for f in report.findings
                          if f.rule_id in ("SHD004", "SHD005")])

    def test_a_failed_nodes_call_does_not_shrink_the_cluster_to_one_node(self):
        report = run_rules(_failed(_three_data_nodes(), "nodes_info"))
        advice = [(f.rule_id, f.title) for f in report.findings
                  if f.rule_id in ("SHD004", "SHD005")]
        self.assertEqual(advice, [], "single-node advice for three nodes")
        self.assertLessEqual({"SHD004", "SHD005"}, _ids(report.not_evaluated))

    def test_the_count_is_not_guessed(self):
        self.assertEqual(ClusterSnapshot(taken_at="x").data_node_count, 0)

    def test_with_no_nodes_and_no_error_the_rules_still_do_not_guess(self):
        """An answer with no nodes in it, not a failed call: the rules have
        to refuse on their own rather than lean on `needs`."""
        snapshot = _three_data_nodes()
        snapshot.nodes_info = {}
        report = run_rules(snapshot)
        advice = [f.rule_id for f in report.findings if f.rule_id.startswith("SHD")]
        self.assertEqual(advice, [])
        self.assertEqual(report.errors, [])
        self.assertLessEqual({"SHD001", "SHD004", "SHD005"},
                             _ids(report.not_evaluated))

    def test_a_single_data_node_is_still_told_about_its_replicas(self):
        snapshot = _three_data_nodes()
        del snapshot.nodes_info["nodes"]["n1"], snapshot.nodes_info["nodes"]["n2"]
        report = run_rules(snapshot)
        self.assertEqual([f.title for f in findings_by_rule(report, "SHD004")],
                         ["Replicas requested on a single-node cluster"])


def _disk(total, free, persistent=None, defaults=None, no_headroom=False):
    """The lab fixture, with its one node's disk and the watermarks changed.

    The lab's defaults are Elasticsearch 8.19's: 85/90/95% with max_headroom
    200GB/150GB/100GB."""
    snapshot = _lab()
    for stats in snapshot.nodes_stats["nodes"].values():
        stats["fs"]["total"].update(total_in_bytes=total, available_in_bytes=free,
                                    free_in_bytes=free)
    settings = snapshot.cluster_settings
    settings["persistent"] = {**(settings.get("persistent") or {}), **(persistent or {})}
    settings["defaults"] = {key: value for key, value in settings["defaults"].items()
                            if not (no_headroom and key.endswith("max_headroom"))}
    settings["defaults"].update(defaults or {})
    return snapshot


WATERMARK = "cluster.routing.allocation.disk.watermark."


class WatermarkTest(unittest.TestCase):
    """CLU006 against Elasticsearch's own arithmetic.

    Since 8.5 a percentage watermark asks for at most max_headroom of free
    space, so on a 10TB disk the high watermark is at 98.5%, not 90%. The
    rule read only 'N%' and fell back to 85/90/95 for anything else, so a
    10TB disk with 1TB free was "past the high watermark" and one with
    400GB free was told that writes had stopped.
    """

    def verdicts(self, snapshot):
        report = run_rules(snapshot)
        return [(f.severity, f.title) for f in findings_by_rule(report, "CLU006")], report

    def test_a_large_disk_is_judged_by_its_headroom(self):
        found, _ = self.verdicts(_disk(10 * TB, 1 * TB))
        self.assertEqual(found, [], "past a watermark Elasticsearch puts at 98.5%")

    def test_writes_have_not_stopped_with_400gb_free(self):
        found, _ = self.verdicts(_disk(10 * TB, 400 * GB))
        self.assertEqual(found, [])

    def test_the_high_watermark_is_150gb_free_on_a_large_disk(self):
        found, report = self.verdicts(_disk(10 * TB, 120 * GB))
        self.assertEqual(found, [(Severity.CRITICAL, "Disk is past the high watermark")])
        evidence = findings_by_rule(report, "CLU006")[0].evidence
        self.assertIn("120.0GB free", evidence)
        self.assertIn("150.0GB", evidence)

    def test_the_flood_stage_is_100gb_free_on_a_large_disk(self):
        found, _ = self.verdicts(_disk(10 * TB, 90 * GB))
        self.assertEqual(found, [(Severity.CRITICAL, "Disk is past the flood-stage watermark")])

    def test_the_low_watermark_is_200gb_free_on_a_large_disk(self):
        found, _ = self.verdicts(_disk(10 * TB, 180 * GB))
        self.assertEqual(found, [(Severity.WARNING, "Disk is past the low watermark")])

    def test_a_small_disk_is_still_judged_by_its_percentage(self):
        """Below the headroom, 15% of 1TB is what the low mark asks for."""
        found, _ = self.verdicts(_disk(1 * TB, 150 * GB))
        self.assertEqual(found, [(Severity.WARNING, "Disk is past the low watermark")])

    def test_byte_watermarks_are_read_as_bytes(self):
        marks = {WATERMARK + "low": "50gb", WATERMARK + "high": "20gb",
                 WATERMARK + "flood_stage": "10gb"}
        self.assertEqual(self.verdicts(_disk(1 * TB, 100 * GB, marks))[0], [])
        self.assertEqual(self.verdicts(_disk(1 * TB, 40 * GB, marks))[0],
                         [(Severity.WARNING, "Disk is past the low watermark")])
        self.assertEqual(self.verdicts(_disk(1 * TB, 15 * GB, marks))[0],
                         [(Severity.CRITICAL, "Disk is past the high watermark")])
        self.assertEqual(self.verdicts(_disk(1 * TB, 5 * GB, marks))[0],
                         [(Severity.CRITICAL, "Disk is past the flood-stage watermark")])

    def test_ratio_watermarks_are_read_as_ratios(self):
        marks = {WATERMARK + "low": "0.97", WATERMARK + "high": "0.98",
                 WATERMARK + "flood_stage": "0.99"}
        self.assertEqual(self.verdicts(_disk(1 * TB, 40 * GB, marks))[0], [])
        self.assertEqual(self.verdicts(_disk(1 * TB, 25 * GB, marks))[0],
                         [(Severity.WARNING, "Disk is past the low watermark")])

    def test_a_watermark_somebody_set_has_no_default_headroom(self):
        """Elasticsearch's default max_headroom applies only while the
        watermark itself is a default: set it, and 90% means 90%."""
        marks = {WATERMARK + "high": "90%"}
        found, _ = self.verdicts(_disk(10 * TB, 900 * GB, marks))
        self.assertEqual(found, [(Severity.CRITICAL, "Disk is past the high watermark")])

    def test_so_does_one_set_in_the_node_configuration(self):
        """elasticsearch.yml values arrive in `defaults`, beside a headroom
        of 200GB that the node does not use: it only knows the watermark
        is not 85%."""
        found, _ = self.verdicts(_disk(10 * TB, 500 * GB,
                                       defaults={WATERMARK + "low": "90%"}))
        self.assertEqual(found, [(Severity.WARNING, "Disk is past the low watermark")])

    def test_a_headroom_somebody_set_applies_to_their_watermark(self):
        marks = {WATERMARK + "low": "85%", WATERMARK + "high": "90%",
                 WATERMARK + "flood_stage": "95%",
                 WATERMARK + "low.max_headroom": "300GB",
                 WATERMARK + "high.max_headroom": "250GB",
                 WATERMARK + "flood_stage.max_headroom": "200GB"}
        found, _ = self.verdicts(_disk(10 * TB, 220 * GB, marks))
        self.assertEqual(found, [(Severity.CRITICAL, "Disk is past the high watermark")])

    def test_a_cluster_without_headroom_settings_is_not_given_one(self):
        """Before 8.5 there is no max_headroom, and 90% of 10TB is 1TB."""
        found, _ = self.verdicts(_disk(10 * TB, 900 * GB, no_headroom=True))
        self.assertEqual(found, [(Severity.CRITICAL, "Disk is past the high watermark")])

    def test_an_unreadable_watermark_is_not_replaced_by_a_default(self):
        _, report = self.verdicts(_disk(1 * TB, 500 * GB, {WATERMARK + "low": "lots"}))
        self.assertNotIn("CLU006", _ids(report.passed))
        reasons = {rule_id: why for rule_id, _, why in report.not_evaluated}
        self.assertIn(WATERMARK + "low", reasons["CLU006"])

    def test_an_unreadable_headroom_is_not_ignored(self):
        _, report = self.verdicts(_disk(10 * TB, 1 * TB,
                                        defaults={WATERMARK + "high.max_headroom": "plenty"}))
        self.assertNotIn("CLU006", _ids(report.passed))
        self.assertIn("CLU006", _ids(report.not_evaluated))


class _Calls:
    def __init__(self, **calls):
        self.__dict__.update(calls)


def _cluster(slow):
    def ok(*_, **__):
        return {"ok": True}

    return _Calls(
        info=ok, cluster=_Calls(health=ok, get_settings=ok),
        nodes=_Calls(info=ok, stats=ok),
        indices=_Calls(stats=ok, get_settings=ok, get_mapping=slow,
                       get_index_template=ok),
        cat=_Calls(indices=lambda **_: [], shards=lambda **_: []),
        ilm=_Calls(get_lifecycle=ok), snapshot=_Calls(get_repository=ok))


#: Rules whose verdict is about the nodes. Each one reads the node map, and
#: each one read an empty map as "nothing wrong here".
NODE_RULES = ("CLU002", "CLU003", "CLU004", "CLU005", "CLU006", "CLU007",
              "CLU008", "CLU009", "QRY001", "QRY002", "QRY003", "SEC001",
              "SEC002")


def _said_no_nodes():
    """The lab cluster as the master describes it when the node-level
    requests failed: HTTP 200, a `_nodes` header counting the failures, and
    an empty `nodes` map."""
    snapshot = _lab()
    empty = {"_nodes": {"total": 3, "successful": 0, "failed": 3}, "nodes": {}}
    snapshot.nodes_info = dict(empty)
    snapshot.nodes_stats = dict(empty)
    return snapshot


class NodesThatSaidNothingTest(unittest.TestCase):
    """An answer that listed no nodes is not a verdict about nodes.

    No call failed — the master answered 200 — so `needs=` never fired and
    thirteen rules passed against a node map that was empty. Among them
    SEC001 "Cluster authentication", which is the critical rule on the full
    report: a cluster whose nodes said nothing was told its security was on.
    """

    def test_no_node_rule_passes_on_an_empty_node_map(self):
        report = run_rules(_said_no_nodes())
        self.assertEqual(_ids(report.passed) & set(NODE_RULES), set(),
                         "rules passed on a cluster whose nodes said nothing")

    def test_they_are_not_evaluated_rather_than_quietly_dropped(self):
        report = run_rules(_said_no_nodes())
        self.assertLessEqual(set(NODE_RULES), _ids(report.not_evaluated))
        self.assertEqual(report.errors, [], "refusing is not failing")

    def test_authentication_is_not_confirmed_by_a_cluster_that_said_nothing(self):
        report = run_rules(_said_no_nodes())
        self.assertNotIn("SEC001", _ids(report.passed))
        self.assertNotIn("SEC001", {f.rule_id for f in report.findings})

    def test_a_cluster_that_did_answer_is_still_judged(self):
        """Not a blanket refusal: every node rule still reaches a verdict on
        the lab fixture, or the guard above would be free."""
        report = run_rules(_lab())
        reached = _ids(report.passed) | {f.rule_id for f in report.findings}
        self.assertLessEqual(set(NODE_RULES), reached)

    def test_a_nodes_call_that_partly_failed_is_recorded_as_a_failure(self):
        """`_nodes: {failed: 3}` with a 200 is the master saying it could not
        reach its nodes. Kept as a success, it is an empty node map nobody
        can tell from a cluster with nothing to report."""
        from wdash.advisor.snapshot import collect

        def ok(*_, **__):
            return {"ok": True}

        def partly_failed(*_, **__):
            return {"_nodes": {"total": 3, "successful": 1, "failed": 2},
                    "nodes": {"n0": {"name": "n0", "roles": ["data"]}}}

        snapshot = collect(_Calls(
            info=ok, cluster=_Calls(health=ok, get_settings=ok),
            nodes=_Calls(info=partly_failed, stats=partly_failed),
            indices=_Calls(stats=ok, get_settings=ok, get_mapping=ok,
                           get_index_template=ok),
            cat=_Calls(indices=lambda **_: [], shards=lambda **_: []),
            ilm=_Calls(get_lifecycle=ok), snapshot=_Calls(get_repository=ok)),
            timeout=5)
        self.assertIn("nodes_info", snapshot.errors)
        self.assertIn("2", snapshot.errors["nodes_info"])
        self.assertIn("nodes_stats", snapshot.errors)
        self.assertNotIn("info", snapshot.errors)

    def test_a_nodes_call_that_wholly_succeeded_is_not_an_error(self):
        from wdash.advisor.snapshot import collect

        def ok(*_, **__):
            return {"ok": True}

        def all_well(*_, **__):
            return {"_nodes": {"total": 1, "successful": 1, "failed": 0},
                    "nodes": {"n0": {"name": "n0", "roles": ["data"]}}}

        snapshot = collect(_Calls(
            info=ok, cluster=_Calls(health=ok, get_settings=ok),
            nodes=_Calls(info=all_well, stats=all_well),
            indices=_Calls(stats=ok, get_settings=ok, get_mapping=ok,
                           get_index_template=ok),
            cat=_Calls(indices=lambda **_: [], shards=lambda **_: []),
            ilm=_Calls(get_lifecycle=ok), snapshot=_Calls(get_repository=ok)),
            timeout=5)
        self.assertEqual(snapshot.errors, {})


class EveryRuleRaisedTest(unittest.TestCase):
    """A report where every rule failed to run is a report of nothing.

    `unavailable` counted collection errors and rules that could not look,
    but not rules that RAISED. So a report of 31 exceptions kept a score of
    100, and the command line exited 0 without --fail-on, although the exit
    status is documented as 2 for "nothing could be evaluated".
    """

    def _all_raised(self):
        from wdash.advisor.models import Report

        return Report(taken_at="x", cluster_name="c", version="8.19.9",
                      distribution="elasticsearch",
                      errors=[(r.id, "TypeError: boom")
                              for r in all_rules("elasticsearch")])

    def test_nothing_reached_a_verdict_so_the_report_is_unavailable(self):
        report = self._all_raised()
        self.assertEqual(report.evaluated, 0)
        self.assertTrue(report.unavailable)

    def test_it_carries_no_score(self):
        self.assertIsNone(self._all_raised().score)
        self.assertIsNone(self._all_raised().to_dict()["score"])

    def test_a_report_that_did_reach_a_verdict_is_not_unavailable(self):
        """One rule that ran is enough: this is about nothing being
        evaluated, not about any error at all."""
        from wdash.advisor.models import Report

        report = Report(taken_at="x", cluster_name="c", version="8.19.9",
                        distribution="elasticsearch",
                        passed=[("CLU001", "Cluster status")],
                        errors=[("SEC001", "TypeError: boom")])
        self.assertFalse(report.unavailable)
        self.assertEqual(report.score, 100)


class CollectTimeoutTest(unittest.TestCase):
    """One slow call costs its own field and nothing else.

    `as_completed(timeout=)` raised out of the loop, discarding every field
    already collected, and the pool's `with` then waited for the slow call
    anyway: the budget bounded nothing, and the page said "Unable to
    analyse the cluster: 1 (of 13) futures unfinished".
    """

    def test_a_slow_call_is_recorded_and_the_rest_is_kept(self):
        from wdash.advisor.snapshot import collect

        release = threading.Event()
        started = time.monotonic()
        try:
            snapshot = collect(_cluster(slow=lambda **_: release.wait(5) and {}),
                               timeout=0.5)
            elapsed = time.monotonic() - started
        finally:
            release.set()
        self.assertLess(elapsed, 2.5, "the budget did not bound the wait")
        self.assertEqual(set(snapshot.errors), {"index_mappings"})
        self.assertIn("0.5s", snapshot.errors["index_mappings"])
        self.assertEqual(snapshot.info, {"ok": True})
        self.assertEqual(snapshot.cat_shards, [])

    def test_the_mappings_rules_are_not_evaluated_rather_than_passed(self):
        from wdash.advisor.snapshot import collect

        release = threading.Event()
        try:
            snapshot = collect(_cluster(slow=lambda **_: release.wait(5) and {}),
                               timeout=0.3)
        finally:
            release.set()
        report = run_rules(snapshot)
        self.assertIn("MAP001", _ids(report.not_evaluated))
        self.assertNotIn("MAP001", _ids(report.passed))
