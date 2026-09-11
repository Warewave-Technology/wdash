"""
The Advisor, on the backends that are not Elasticsearch.

Two properties matter more than any individual rule.

**A rule must not run against a backend it does not understand.** A shard
count means nothing to Loki, and a finding about one would be advice on a
concept the operator does not have.

**A short report must not read as a clean bill of health.** Jaeger exposes
almost nothing about itself; three checks passing there is a much narrower
statement than thirty-one passing against Elasticsearch, and the report says
so rather than leaving somebody to assume.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.advisor.backends import (  # noqa: E402
    SourceSnapshot, collect_jaeger, collect_loki, collect_tempo,
    collect_victorialogs,
)
from wdash.advisor.models import Severity, all_rules, run_rules  # noqa: E402

#: Loki's `/config`, trimmed to what the rules read.
LOKI_CONFIG = """
auth_enabled: false
common:
  replication_factor: 1
compactor:
  retention_enabled: false
limits_config:
  retention_period: 0s
  reject_old_samples: true
  reject_old_samples_max_age: 1w
  ingestion_rate_mb: 4
  ingestion_burst_size_mb: 6
"""

#: Tempo prefixes the body with the request line, which is a second YAML
#: document and an error to a parser that expects one.
TEMPO_CONFIG = """GET /status/config
---
multitenancy_enabled: false
compactor:
  compaction:
    block_retention: 168h0m0s
storage:
  trace:
    backend: local
metrics_generator:
  processor:
    - service_graphs
    - span_metrics
  storage:
    remote_write: []
overrides:
  defaults:
    global:
      max_bytes_per_trace: 5000000
"""

VL_FLAGS = """-httpListenAddr=":9428"
-retentionPeriod="30d"
-storageDataPath="/victoria-logs-data"
"""

VL_METRICS = """# HELP vl_free_disk_space_bytes free space
# TYPE vl_free_disk_space_bytes gauge
vl_free_disk_space_bytes{path="/victoria-logs-data"} 1150063616000
vm_app_version{version="victoria-logs-20250210", short_version="v1.9.1"} 1
"""


class FakeResponse:
    def __init__(self, text="", payload=None, status_code=200):
        self.text = text
        self._payload = payload
        self.status_code = status_code

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHttp:
    def __init__(self, routes, explode=()):
        self.routes = routes
        self.explode = set(explode)
        self.calls = []

    def get(self, url, params=None, timeout=None, auth=None, verify=None):
        self.calls.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                if fragment in self.explode:
                    raise OSError("connection refused")
                return response
        return FakeResponse(status_code=404)


def loki_http(config=LOKI_CONFIG, **overrides):
    routes = {"/config": FakeResponse(text=config),
              "buildinfo": FakeResponse(payload={"version": "3.1.1"})}
    routes.update(overrides)
    return FakeHttp(routes)


def tempo_http(config=TEMPO_CONFIG):
    return FakeHttp({"/status/config": FakeResponse(text=config),
                     "/status/version": FakeResponse(
                         text="GET /status/version\ntempo, version 2.6.1 (…)")})


def vl_http(flags=VL_FLAGS, metrics=VL_METRICS):
    return FakeHttp({"/flags": FakeResponse(text=flags),
                     "/metrics": FakeResponse(text=metrics)})


def jaeger_http(services=("a", "b"), metrics_status=501):
    return FakeHttp({"/api/services": FakeResponse(
                         payload={"data": list(services)}),
                     "/api/metrics/calls": FakeResponse(
                         status_code=metrics_status)})


def _findings(report):
    return {finding.rule_id: finding for finding in report.findings}


def _passed(report):
    return {rule_id for rule_id, _ in report.passed}


def _not_evaluated(report):
    return {entry[0] for entry in report.not_evaluated}


class RegistryTest(unittest.TestCase):
    """A rule must not run where its concepts do not exist."""

    def test_every_backend_has_rules(self):
        for backend in ("elasticsearch", "loki", "victorialogs", "tempo",
                        "jaeger"):
            self.assertTrue(all_rules(backend), f"no rules for {backend}")

    def test_elasticsearch_rules_do_not_run_elsewhere(self):
        """A shard count is advice about a concept Loki does not have."""
        elastic = {r.id for r in all_rules("elasticsearch")}
        for backend in ("loki", "victorialogs", "tempo", "jaeger"):
            overlap = elastic & {r.id for r in all_rules(backend)}
            self.assertEqual(overlap, set(), f"{backend} inherited {overlap}")

    def test_rules_default_to_elasticsearch(self):
        """Thirty-one rules were written before there was a second backend.
        Their meaning must not change because a field gained a default, so
        every one of them is checked rather than a sample."""
        backend_ids = set()
        for backend in ("loki", "victorialogs", "tempo", "jaeger"):
            backend_ids |= {r.id for r in all_rules(backend)}

        for registered in all_rules():
            if registered.id in backend_ids:
                continue
            self.assertEqual(registered.backends, ("elasticsearch",),
                             f"{registered.id} lost its default")

    def test_a_rule_refuses_a_snapshot_from_another_backend(self):
        """Two layers, and this is the inner one.

        `run_rules` already asks for one backend's rules, so this check can
        never fire through that path — which is exactly why it needs its own
        test. Anything calling `applies_to` directly (a future report that
        runs several backends at once, a script) has to be refused here.
        """
        loki_rule = all_rules("loki")[0]
        elastic_rule = all_rules("elasticsearch")[0]
        snapshot = SourceSnapshot(backend="loki", source_name="x")

        applicable, _ = loki_rule.applies_to(snapshot)
        self.assertTrue(applicable)

        applicable, reason = elastic_rule.applies_to(snapshot)
        self.assertFalse(applicable, f"{elastic_rule.id} accepted a Loki "
                                     f"snapshot")
        self.assertIn("loki", reason)

    def test_the_default_is_narrow_rather_than_everything(self):
        """The decorator's default is what every existing rule inherits.

        Widened to every backend, each of the thirty-one Elasticsearch rules
        would run against Loki and produce advice about shards, ILM and
        mappings — concepts the operator does not have.
        """
        import inspect

        from wdash.advisor.models import rule as rule_decorator
        default = inspect.signature(rule_decorator).parameters["backends"].default
        self.assertEqual(tuple(default), ("elasticsearch",))

    def test_a_report_carries_its_source_and_backend(self):
        """A report with no name on it is unreadable once there is more than
        one: "retention is not set" is a different sentence for each."""
        report = run_rules(collect_loki("http://loki:3100", "lab-loki",
                                        session=loki_http()))
        self.assertEqual(report.source, "lab-loki")
        self.assertEqual(report.backend, "loki")

    def test_a_report_skips_nothing_from_another_backend(self):
        """Running the whole registry would bury six relevant results under
        thirty-one skipped ones."""
        report = run_rules(collect_loki("http://loki:3100", "lab-loki",
                                        session=loki_http()))
        self.assertEqual(report.skipped, [])


class LokiRuleTest(unittest.TestCase):
    def report(self, config=LOKI_CONFIG):
        return run_rules(collect_loki("http://loki:3100", "lab-loki",
                                      session=loki_http(config)))

    def test_infinite_retention_is_reported(self):
        self.assertIn("LOKI001", _findings(self.report()))

    def test_a_real_retention_passes(self):
        report = self.report(LOKI_CONFIG.replace("retention_period: 0s",
                                                 "retention_period: 744h"))
        self.assertIn("LOKI001", _passed(report))

    def test_retention_without_a_compactor_is_critical(self):
        """The setting people set is not the one that does the work, so the
        configuration says one thing and behaves like another."""
        report = self.report(LOKI_CONFIG.replace("retention_period: 0s",
                                                 "retention_period: 744h"))
        finding = _findings(report)["LOKI002"]
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_the_compactor_rule_stays_quiet_without_a_retention(self):
        """Nothing to enforce is not a misconfiguration."""
        self.assertIn("LOKI002", _passed(self.report()))

    def test_accepting_old_samples_is_reported(self):
        report = self.report(LOKI_CONFIG.replace("reject_old_samples: true",
                                                 "reject_old_samples: false"))
        self.assertIn("LOKI003", _findings(report))

    def test_a_default_ingestion_rate_is_reported(self):
        self.assertIn("LOKI004", _findings(self.report()))

    def test_a_considered_ingestion_rate_passes(self):
        report = self.report(LOKI_CONFIG.replace("ingestion_rate_mb: 4",
                                                 "ingestion_rate_mb: 32"))
        self.assertIn("LOKI004", _passed(report))

    def test_an_unreadable_duration_does_not_become_a_finding(self):
        """A format the parser does not know must skip, not be read as zero —
        that turns an unrecognised value into advice about a setting that is
        perfectly fine. Nor as a pass: "Retention is configured", about a
        value nobody could read, is the same mistake the other way round."""
        report = self.report(LOKI_CONFIG.replace("retention_period: 0s",
                                                 "retention_period: forever"))
        self.assertNotIn("LOKI001", _findings(report))
        self.assertNotIn("LOKI001", _passed(report))
        self.assertIn("LOKI001", _not_evaluated(report))
        # The compactor rule reads the same value: off, with a retention
        # nobody can read, is not "nothing to enforce".
        self.assertIn("LOKI002", _not_evaluated(report))

    def test_findings_carry_the_source_name(self):
        finding = _findings(self.report())["LOKI001"]
        self.assertEqual(finding.targets, ["lab-loki"])

    def test_a_missing_setting_produces_no_finding(self):
        """Absent is not false. A rule that cannot see a setting must not
        claim it is off — nor that it is on, which is what counting it as
        passed said: "Retention is configured", about a /config that never
        mentions retention."""
        report = self.report("auth_enabled: false\n")
        for rule_id in ("LOKI001", "LOKI002", "LOKI003", "LOKI004", "LOKI005"):
            self.assertNotIn(rule_id, _findings(report), rule_id)
            self.assertNotIn(rule_id, _passed(report), rule_id)
            self.assertIn(rule_id, _not_evaluated(report), rule_id)

    def test_loki_leaves_auth_enabled_out_when_it_is_false(self):
        """Loki writes `auth_enabled` with omitempty, so false is not written
        at all. Measured on the lab's Loki 3.1: /config goes `target`,
        `http_prefix`, `ballast_bytes` with nothing between the first two,
        and a query without X-Scope-OrgID is answered. LOKI006 passed there
        as "Multi-tenancy is on"."""
        report = self.report(LOKI_CONFIG.replace("auth_enabled: false\n", ""))
        self.assertIn("LOKI006", _findings(report))

    def test_multi_tenancy_that_is_on_passes(self):
        report = self.report(LOKI_CONFIG.replace("auth_enabled: false",
                                                 "auth_enabled: true"))
        self.assertIn("LOKI006", _passed(report))


class VictoriaLogsRuleTest(unittest.TestCase):
    def report(self, flags=VL_FLAGS, metrics=VL_METRICS):
        return run_rules(collect_victorialogs(
            "http://vl:9428", "lab-vl", session=vl_http(flags, metrics)))

    def test_flags_are_parsed(self):
        snapshot = collect_victorialogs("http://vl:9428", "lab-vl",
                                        session=vl_http())
        self.assertEqual(snapshot.settings["retentionPeriod"], "30d")
        self.assertEqual(snapshot.version, "v1.9.1")

    def test_an_explicit_retention_passes(self):
        self.assertIn("VL001", _passed(self.report()))

    def test_an_inherited_retention_is_reported(self):
        """`/flags` lists only what was SET, so absence is the finding."""
        report = self.report(flags='-httpListenAddr=":9428"\n')
        self.assertIn("VL001", _findings(report))

    def test_an_unbounded_disk_is_reported(self):
        self.assertIn("VL002", _findings(self.report()))

    def test_a_bounded_disk_passes(self):
        report = self.report(
            flags=VL_FLAGS + '-storage.maxDiskSpaceUsageBytes="500000000000"\n')
        self.assertIn("VL002", _passed(report))

    def test_a_full_volume_is_critical(self):
        metrics = VL_METRICS.replace("1150063616000", "900000000")
        finding = _findings(self.report(metrics=metrics))["VL003"]
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_a_nearly_full_volume_is_a_warning(self):
        metrics = VL_METRICS.replace("1150063616000", "5000000000")
        finding = _findings(self.report(metrics=metrics))["VL003"]
        self.assertEqual(finding.severity, Severity.WARNING)

    def test_no_authentication_on_a_public_address_is_a_warning(self):
        finding = _findings(self.report())["VL004"]
        self.assertEqual(finding.severity, Severity.WARNING)

    def test_no_authentication_on_loopback_is_only_a_note(self):
        """Reachable from the host is a different conversation from reachable
        from the network."""
        flags = VL_FLAGS.replace('-httpListenAddr=":9428"',
                                 '-httpListenAddr="127.0.0.1:9428"')
        finding = _findings(self.report(flags=flags))["VL004"]
        self.assertEqual(finding.severity, Severity.INFO)


class TempoRuleTest(unittest.TestCase):
    def report(self, config=TEMPO_CONFIG):
        return run_rules(collect_tempo("http://tempo:3200", "lab-tempo",
                                       session=tempo_http(config)))

    def test_the_config_survives_its_header_line(self):
        """Tempo answers with `GET /status/config` and then the document,
        which is two YAML documents and an error to a naive parser."""
        snapshot = collect_tempo("http://tempo:3200", "lab-tempo",
                                 session=tempo_http())
        self.assertEqual(snapshot.setting("storage.trace.backend"), "local")

    def test_the_version_is_not_read_off_the_request_line(self):
        """The body begins `GET /status/version`, so a loose match reported
        the version as "tempo,"."""
        snapshot = collect_tempo("http://tempo:3200", "lab-tempo",
                                 session=tempo_http())
        self.assertEqual(snapshot.version, "2.6.1")

    def test_local_storage_is_reported(self):
        self.assertIn("TEMPO001", _findings(self.report()))

    def test_object_storage_passes(self):
        report = self.report(TEMPO_CONFIG.replace("backend: local",
                                                  "backend: s3"))
        self.assertIn("TEMPO001", _passed(report))

    def test_infinite_retention_is_reported(self):
        report = self.report(TEMPO_CONFIG.replace("block_retention: 168h0m0s",
                                                  "block_retention: 0s"))
        self.assertIn("TEMPO002", _findings(report))

    def test_a_generator_with_nowhere_to_write_is_reported(self):
        """Configured-looking and inert: the processors are on by default and
        do nothing without a remote_write target."""
        self.assertIn("TEMPO003", _findings(self.report()))

    def test_a_generator_with_a_target_passes(self):
        report = self.report(TEMPO_CONFIG.replace(
            "remote_write: []", "remote_write:\n      - url: http://prom/api"))
        self.assertIn("TEMPO003", _passed(report))

    def test_an_unlimited_trace_size_is_reported(self):
        report = self.report(TEMPO_CONFIG.replace("max_bytes_per_trace: 5000000",
                                                  "max_bytes_per_trace: 0"))
        self.assertIn("TEMPO004", _findings(report))

    def test_a_bounded_trace_size_passes(self):
        self.assertIn("TEMPO004", _passed(self.report()))

    def test_tempo_leaves_multitenancy_out_when_it_is_false(self):
        """omitempty, as in Loki. The lab's Tempo 2.6 has no
        multitenancy_enabled in /status/config and answers a search with
        no X-Scope-OrgID; TEMPO005 passed there as "Multi-tenancy is on"."""
        report = self.report(TEMPO_CONFIG.replace("multitenancy_enabled: false\n", ""))
        self.assertIn("TEMPO005", _findings(report))

    def test_multi_tenancy_that_is_on_passes(self):
        report = self.report(TEMPO_CONFIG.replace("multitenancy_enabled: false",
                                                  "multitenancy_enabled: true"))
        self.assertIn("TEMPO005", _passed(report))

    def test_an_unreadable_retention_is_not_a_pass(self):
        report = self.report(TEMPO_CONFIG.replace("block_retention: 168h0m0s",
                                                  "block_retention: a week"))
        self.assertNotIn("TEMPO002", _passed(report))
        self.assertIn("TEMPO002", _not_evaluated(report))

    def test_a_missing_setting_is_not_a_pass(self):
        report = self.report("GET /status/config\n---\nmultitenancy_enabled: true\n")
        for rule_id in ("TEMPO001", "TEMPO002", "TEMPO003", "TEMPO004"):
            self.assertNotIn(rule_id, _findings(report), rule_id)
            self.assertNotIn(rule_id, _passed(report), rule_id)
            self.assertIn(rule_id, _not_evaluated(report), rule_id)

    def test_a_version_page_without_a_version_is_a_failed_collection(self):
        """It was stored as 'unknown' with no error, so the report named
        nothing missing."""
        session = tempo_http()
        session.routes["/status/version"] = FakeResponse(text="GET /status/version\n")
        snapshot = collect_tempo("http://tempo:3200", "lab-tempo", session=session)
        self.assertIn("version", snapshot.errors)


class JaegerRuleTest(unittest.TestCase):
    def report(self, services=("a", "b"), metrics_status=501):
        return run_rules(collect_jaeger(
            "http://jaeger:16686", "lab-jaeger",
            session=jaeger_http(services, metrics_status)))

    def test_a_normal_service_list_passes(self):
        self.assertIn("JAEGER001", _passed(self.report()))

    def test_runaway_cardinality_is_reported(self):
        """Thousands of services means an identifier that varies per request
        has been spliced into service.name."""
        report = self.report(services=[f"svc-{i}" for i in range(900)])
        self.assertIn("JAEGER001", _findings(report))

    def test_a_disabled_metrics_api_is_reported(self):
        self.assertIn("JAEGER002", _findings(self.report()))

    def test_a_working_metrics_api_passes(self):
        self.assertIn("JAEGER002", _passed(self.report(metrics_status=200)))

    def test_the_limits_of_the_check_are_always_stated(self):
        """A report with three checks and no explanation reads as "this
        backend is fine", which is not the same statement as "there are three
        things anybody can check from here"."""
        report = self.report(metrics_status=200)
        self.assertIn("JAEGER003", _findings(report))

    def test_a_refusal_is_not_a_working_metrics_api(self):
        """401, 403 or 503 is an auth proxy or a dead upstream answering,
        not Jaeger saying its metrics backend is wired up.

        Any status but 501 counted as "it works", so a Jaeger that refused
        every call reported a HIGHER score than one that answered: 100, with
        JAEGER002 under "1 rules passed", because JAEGER003's honest
        coverage finding had moved into not_evaluated.
        """
        for status in (401, 403, 500, 503):
            with self.subTest(status=status):
                report = self.report(metrics_status=status)
                self.assertNotIn("JAEGER002", _passed(report))
                self.assertIn("JAEGER002", _not_evaluated(report))
                self.assertNotIn("JAEGER002", _findings(report))

    def test_a_refused_metrics_call_is_recorded_as_a_failed_call(self):
        snapshot = collect_jaeger("http://jaeger:16686", "lab-jaeger",
                                  session=jaeger_http(metrics_status=403))
        self.assertIn("metrics", snapshot.errors)
        self.assertNotIn("metrics_api", snapshot.facts)

    def test_the_two_answers_jaeger_gives_are_still_read(self):
        """200 and 501 are Jaeger answering; neither becomes an error."""
        for status in (200, 501):
            with self.subTest(status=status):
                snapshot = collect_jaeger(
                    "http://jaeger:16686", "lab-jaeger",
                    session=jaeger_http(metrics_status=status))
                self.assertNotIn("metrics", snapshot.errors)
                self.assertEqual(snapshot.facts["metrics_api"], status)


class CollectionFailureTest(unittest.TestCase):
    """A backend that will not answer must not take the report down."""

    def test_a_failed_collection_is_recorded_rather_than_raised(self):
        session = loki_http()
        session.explode.add("/config")
        snapshot = collect_loki("http://loki:3100", "lab-loki", session=session)
        self.assertIn("config", snapshot.errors)

    def test_a_report_is_still_produced(self):
        session = loki_http()
        session.explode.add("/config")
        report = run_rules(collect_loki("http://loki:3100", "lab-loki",
                                        session=session))
        self.assertEqual(report.collection_errors.get("config") is not None,
                         True)

    def test_rules_pass_rather_than_inventing_findings_with_no_data(self):
        """With nothing collected, every rule must stay quiet. Reporting
        "retention is not set" when the config could not be read would be a
        finding about the Advisor, dressed as one about the backend."""
        session = loki_http()
        session.explode.add("/config")
        report = run_rules(collect_loki("http://loki:3100", "lab-loki",
                                        session=session))
        self.assertEqual(report.findings, [])

    def test_an_unknown_backend_collects_nothing(self):
        from wdash.advisor.backends import collect
        self.assertIsNone(collect("carrier-pigeon", "http://x", "name"))

    def test_rules_with_nothing_to_read_have_not_passed(self):
        """Quiet is not the same as passed: six Loki rules passing against a
        /config that could not be read is a clean bill for a backend nobody
        looked at."""
        session = loki_http()
        session.explode.add("/config")
        report = run_rules(collect_loki("http://loki:3100", "lab-loki",
                                        session=session))
        self.assertEqual(report.passed, [])
        self.assertEqual(_not_evaluated(report),
                         {r.id for r in all_rules("loki")})
        self.assertTrue(report.unavailable)

    def test_a_tempo_without_its_config_passes_nothing(self):
        session = tempo_http()
        session.explode.add("/status/config")
        report = run_rules(collect_tempo("http://tempo:3200", "lab-tempo",
                                         session=session))
        self.assertEqual(report.passed, [])
        self.assertEqual(report.findings, [])

    def test_a_jaeger_without_its_service_list_passes_nothing_about_it(self):
        session = jaeger_http()
        session.explode.add("/api/services")
        report = run_rules(collect_jaeger("http://jaeger:16686", "lab-jaeger",
                                          session=session))
        self.assertNotIn("JAEGER001", _passed(report))
        self.assertLessEqual({"JAEGER001", "JAEGER003"}, _not_evaluated(report))
        self.assertIn("JAEGER002", _findings(report), "the metrics call still answered")

    def test_a_jaeger_without_its_metrics_call_does_not_pass_it(self):
        session = jaeger_http(metrics_status=200)
        session.explode.add("/api/metrics/calls")
        report = run_rules(collect_jaeger("http://jaeger:16686", "lab-jaeger",
                                          session=session))
        self.assertNotIn("JAEGER002", _passed(report))
        self.assertIn("JAEGER002", _not_evaluated(report))

    def test_jaeger_facts_nobody_collected_are_not_a_pass(self):
        """A snapshot with no error recorded and nothing in it either: the
        rules have to refuse on their own."""
        report = run_rules(SourceSnapshot(backend="jaeger", source_name="x"))
        self.assertLessEqual({"JAEGER001", "JAEGER002"}, _not_evaluated(report))
        self.assertEqual({"JAEGER001", "JAEGER002"} & _passed(report), set())

    def test_a_rule_needs_only_what_its_collector_records(self):
        """A need nobody records is never missing: a check that never
        fires. Every call refused, so every name a collector can write is
        written."""
        from wdash.advisor.backends import COLLECTORS

        class Refusing:
            def get(self, *_, **__):
                raise OSError("connection refused")

        for backend, collector in COLLECTORS.items():
            recorded = set(collector("http://x", "x", session=Refusing()).errors)
            for registered in all_rules(backend):
                self.assertLessEqual(set(registered.needs), recorded,
                                     f"{registered.id} needs {registered.needs}")


class VictoriaLogsFlagsFailureTest(unittest.TestCase):
    """VictoriaLogs' rules read an absent flag as the finding, so a /flags
    that could not be read looked exactly like a VictoriaLogs started with
    nothing set: VL001, VL002 and VL004, score 89 — including "no
    authentication" from a server that had just answered 401.
    """

    def report(self, session):
        return run_rules(collect_victorialogs("http://vl:9428", "lab-vl",
                                              session=session))

    def assert_nothing_invented(self, report):
        self.assertIn("flags", report.collection_errors)
        self.assertEqual({"VL001", "VL002", "VL004"} & set(_findings(report)), set())
        self.assertLessEqual({"VL001", "VL002", "VL004"}, _not_evaluated(report))

    def test_an_unreachable_flags_page_invents_nothing(self):
        session = vl_http()
        session.explode.add("/flags")
        self.assert_nothing_invented(self.report(session))

    def test_a_refused_flags_page_is_not_read_as_no_authentication(self):
        session = vl_http()
        session.routes["/flags"] = FakeResponse(text="Unauthorized", status_code=401)
        self.assert_nothing_invented(self.report(session))

    def test_the_disk_rule_still_runs_on_the_metrics(self):
        session = vl_http()
        session.explode.add("/flags")
        self.assertIn("VL003", _passed(self.report(session)))

    def test_without_metrics_the_disk_is_not_healthy_by_default(self):
        session = vl_http()
        session.explode.add("/metrics")
        report = self.report(session)
        self.assertNotIn("VL003", _passed(report))
        self.assertIn("VL003", _not_evaluated(report))

    def test_metrics_without_the_disk_gauge_are_not_a_healthy_disk(self):
        report = self.report(vl_http(metrics='vm_app_version{short_version="v1.9.1"} 1\n'))
        self.assertNotIn("VL003", _passed(report))
        self.assertIn("VL003", _not_evaluated(report))


#: Pages that answer 200 where a backend was expected: a sign-in page, a
#: proxy's error page, an SSO front door.
PAGES = {
    "tiny": "<html><body>Sign in</body></html>",
    "nginx502": ("<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n"
                 "<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx</center>\r\n"
                 "</body>\r\n</html>\r\n"),
    "oauth2proxy": ("<!DOCTYPE html>\n<html lang=\"en\" charset=\"utf-8\">\n<head>\n"
                    "<title>Sign In</title>\n</head>\n<body>\n<section class=\"section\">\n"
                    "<form method=\"GET\" action=\"/oauth2/start\">\n"
                    "<button type=\"submit\">Sign in with OpenID Connect</button>\n"
                    "</form>\n</section>\n</body>\n</html>\n"),
}


class PageNotBackendTest(unittest.TestCase):
    """A source URL that answers 200 with a page rather than the backend.

    Every collector accepted it. Tempo recorded no error and passed all five
    rules; VictoriaLogs recorded no error and invented VL001, VL002 and
    VL004; Loki's /config filtered the page out as "not a mapping", returned
    {}, and passed six rules. A real server, answering text/html on every
    path.
    """

    def setUp(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from tests.support import serve_in_background

        page = self.page = {"body": ""}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                body = page["body"].encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = serve_in_background(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def each_page(self, collector):
        """(page, snapshot, report) for every page, collected for real."""
        out = []
        for label, body in PAGES.items():
            self.page["body"] = body
            snapshot = collector(self.url, "behind-a-proxy")
            out.append((label, snapshot, run_rules(snapshot)))
        return out

    def test_loki(self):
        for label, snapshot, report in self.each_page(collect_loki):
            with self.subTest(page=label):
                self.assertIn("config", snapshot.errors)
                self.assertEqual(report.passed, [])

    def test_tempo(self):
        for label, snapshot, report in self.each_page(collect_tempo):
            with self.subTest(page=label):
                self.assertLessEqual({"config", "version"}, set(snapshot.errors))
                self.assertEqual(report.passed, [])

    def test_victorialogs(self):
        for label, snapshot, report in self.each_page(collect_victorialogs):
            with self.subTest(page=label):
                self.assertLessEqual({"flags", "metrics"}, set(snapshot.errors))
                self.assertEqual(report.findings, [])
                self.assertEqual(report.passed, [])

    def test_jaeger(self):
        """Its metrics call records a status, and 200 read as "the metrics
        API works"."""
        for label, snapshot, report in self.each_page(collect_jaeger):
            with self.subTest(page=label):
                self.assertLessEqual({"services", "metrics"}, set(snapshot.errors))
                self.assertEqual(report.passed, [])


class PageWithoutContentTypeTest(unittest.TestCase):
    """The same pages with no Content-Type to give them away: what the body
    says has to be enough on its own."""

    def test_a_page_is_not_a_loki_configuration(self):
        for label, body in PAGES.items():
            with self.subTest(page=label):
                snapshot = collect_loki("http://loki:3100", "x",
                                        session=loki_http(config=body))
                self.assertIn("config", snapshot.errors)

    def test_a_page_is_not_a_tempo_configuration(self):
        for label, body in PAGES.items():
            with self.subTest(page=label):
                snapshot = collect_tempo("http://tempo:3200", "x",
                                         session=tempo_http(config=body))
                self.assertIn("config", snapshot.errors)

    def test_a_page_is_not_a_list_of_flags(self):
        for label, body in PAGES.items():
            with self.subTest(page=label):
                snapshot = collect_victorialogs("http://vl:9428", "x",
                                                session=vl_http(flags=body))
                self.assertIn("flags", snapshot.errors)

    def test_an_empty_flags_page_is_a_victorialogs_with_nothing_set(self):
        """/flags lists only what was set; nothing set is an empty body."""
        snapshot = collect_victorialogs("http://vl:9428", "x",
                                        session=vl_http(flags=""))
        self.assertNotIn("flags", snapshot.errors)


class SnapshotTest(unittest.TestCase):
    def test_a_missing_setting_returns_the_default(self):
        snapshot = SourceSnapshot(backend="loki", source_name="x",
                                  settings={"a": {"b": 1}})
        self.assertEqual(snapshot.setting("a.b"), 1)
        self.assertIsNone(snapshot.setting("a.c"))
        self.assertIsNone(snapshot.setting("nothing.at.all"))

    def test_a_path_through_a_non_dict_does_not_raise(self):
        snapshot = SourceSnapshot(backend="loki", source_name="x",
                                  settings={"a": 5})
        self.assertIsNone(snapshot.setting("a.b"))


if __name__ == "__main__":
    unittest.main()
