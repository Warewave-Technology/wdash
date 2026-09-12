"""
The group-by offer and the Loki split, against the running lab.

`tests/test_group_by_fields.py` and `tests/test_conformance_loki.py` hold the
code to what was measured; this file asks the real servers, and it is where
the measurements came from. Both are needed: a fake answers what it was
written to answer, and the thing being claimed here is what Elasticsearch,
Loki and VictoriaLogs actually do.

    cd lab && ./lab.sh up          # Elasticsearch, Loki, VictoriaLogs

Read-only: every request here is a query. Skipped when a backend is absent,
and REQUIRED when `WDASH_REQUIRE_LAB=1` says a job promised one — a test that
exists to measure this and passes by skipping is the fault it is looking for.
"""

import datetime as dt
import os
import sys
import unittest

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.hub import DateHistogram, LogQuery, Scope, Terms, TimeWindow  # noqa: E402

ES_URL = os.environ.get("WDASH_LAB_URL") or "http://localhost:9200"
LOKI_URL = os.environ.get("WDASH_LAB_LOKI_URL") or "http://localhost:3100"
VL_URL = os.environ.get("WDASH_LAB_VICTORIALOGS_URL") or "http://localhost:9428"
REQUIRED = os.environ.get("WDASH_REQUIRE_LAB") == "1"

#: The lab's log index. Named rather than wildcarded, so this measures the
#: mapping the numbers in the comments came from.
ES_PATTERN = "app-logs-*"


def _reachable(url, path="/"):
    try:
        return requests.get(url + path, timeout=3).status_code < 500
    except Exception:
        return False


def _window(hours=24):
    now = dt.datetime.now(dt.timezone.utc)
    return TimeWindow.exact(now - dt.timedelta(hours=hours), now)


def _query(window=None):
    return LogQuery(window=window or _window(), text="*", limit=10)


def _skip_unless(reachable, what):
    if reachable:
        return
    if REQUIRED:
        raise AssertionError(f"WDASH_REQUIRE_LAB=1 but {what} is not there")
    raise unittest.SkipTest(f"{what} is not running")


class LokiSplitLabTest(unittest.TestCase):
    """D16 against the server that decides it."""

    def setUp(self):
        _skip_unless(_reachable(LOKI_URL, "/ready"), f"Loki at {LOKI_URL}")
        from wdash.hub.adapters.loki import LokiLogSource
        self.source = LokiLogSource(LOKI_URL, name="lab-loki")

    def split(self, field, hours=24):
        result = self.source.aggregate(
            _query(_window(hours)),
            [DateHistogram(name="panel", interval="1h", min_count=0,
                           sub=(Terms(name="split", field=field, size=10),))],
            Scope.unrestricted())
        self.assertFalse(result.failed, result.warnings)
        return result

    def test_the_default_panel_is_actually_split(self):
        """Volume by Severity is the panel every board is born with.

        Before: one series, and the note "Loki does not split this series; it
        is the total". Measured on this lab at the time of writing: 8 hourly
        buckets, 598 lines, 0 series. After: the same total in 4 series —
        ERROR, INFO, UNSPECIFIED, WARN — with no JSON parser and no error
        filter in the query.
        """
        result = self.split("severity")
        rows = result.get("panel")
        self.assertTrue(rows, "Loki answered no buckets at all")

        keys = {bucket.key for row in rows for bucket in row.sub.get("split", ())}
        self.assertGreaterEqual(
            len(keys), 2, f"a split legend with one series: {keys}")
        self.assertTrue(keys <= {"TRACE", "DEBUG", "INFO", "WARN", "ERROR",
                                 "FATAL", "UNSPECIFIED"},
                        f"severity keys are not normalised: {keys}")
        self.assertEqual(result.reasons("panel"), (),
                         "a split that was made still carried a reason")

    def test_the_split_adds_up_to_the_total_it_is_drawn_under(self):
        """The whole complaint: a stack that is not the line above it."""
        for row in self.split("severity").get("panel"):
            self.assertEqual(sum(b.count for b in row.sub.get("split", ())),
                             row.count, f"bucket {row.key_text} does not add up")

    def test_the_query_needs_no_parser_stage(self):
        """The cost argument against D16 rested on `| json | __error__=""`.

        That pipeline answers HTTP 400 on this lab, because one stream holds
        a non-JSON line. A label split needs neither stage, and this is what
        holds the adapter to it.
        """
        sent = []
        original = self.source._get

        def record(path, params):
            sent.append(params.get("query", ""))
            return original(path, params)

        self.source._get = record
        self.split("severity")
        counted = [query for query in sent if "count_over_time" in query]
        self.assertTrue(counted, sent)
        for query in counted:
            self.assertNotIn("| json", query)
            self.assertNotIn("__error__", query)
            self.assertIn("sum by (", query)

    def test_a_field_that_is_not_a_label_draws_the_total_and_says_so(self):
        """`host` is one of the four names the editor offered every source."""
        result = self.split("host")
        rows = result.get("panel")
        self.assertTrue(rows)
        self.assertTrue(sum(row.count for row in rows) > 0,
                        "the total went missing with the split")
        self.assertEqual([row.sub for row in rows], [{} for _ in rows])
        self.assertIn("not a Loki label", " ".join(result.reasons("panel")))


class GroupByOfferLabTest(unittest.TestCase):
    """D12: what each backend really offers, and how they differ."""

    def loki(self):
        _skip_unless(_reachable(LOKI_URL, "/ready"), f"Loki at {LOKI_URL}")
        from wdash.hub.adapters.loki import LokiLogSource
        return LokiLogSource(LOKI_URL, name="lab-loki")

    def victorialogs(self):
        _skip_unless(_reachable(VL_URL, "/select/logsql/query?query=*&limit=1"),
                     f"VictoriaLogs at {VL_URL}")
        from wdash.hub.adapters.victorialogs import VictoriaLogsSource
        return VictoriaLogsSource(VL_URL, name="lab-vl")

    def elasticsearch(self):
        _skip_unless(_reachable(ES_URL), f"Elasticsearch at {ES_URL}")
        from elasticsearch import Elasticsearch
        from wdash.hub.adapters import ElasticsearchLogSource
        client = Elasticsearch(hosts=[ES_URL], request_timeout=10)
        return ElasticsearchLogSource(client, name="lab-es",
                                      patterns=(ES_PATTERN,))

    def test_elasticsearch_offers_more_than_the_four_hardcoded_names(self):
        """Measured: ten fields, six of which no board could ever ask for."""
        offered = self.elasticsearch().group_by_fields(Scope.unrestricted())
        self.assertIn("http_status", offered)
        self.assertIn("severity", offered)
        self.assertNotIn("message", offered)
        self.assertGreater(len(offered), 4, offered)

    def test_loki_offers_its_labels_and_not_two_names_it_answers_with_nothing(self):
        """`host` and `environment` are not labels on this lab's Loki, and a
        terms panel over either came back with no rows at all."""
        offered = self.loki().group_by_fields(Scope.unrestricted())
        self.assertIn("severity", offered)
        self.assertIn("service", offered)
        self.assertNotIn("host", offered)
        self.assertNotIn("environment", offered)

    def test_victorialogs_offers_the_name_it_actually_writes(self):
        """`env`, not `environment` — which is why a VictoriaLogs board
        grouping by `environment` drew an empty panel."""
        offered = self.victorialogs().group_by_fields(Scope.unrestricted())
        self.assertIn("env", offered)
        self.assertNotIn("environment", offered)
        self.assertNotIn("_msg", offered)

    def test_a_field_one_source_has_and_another_does_not(self):
        """`http_status` is the case the whole option is about.

        Elasticsearch maps it and answers it; Loki has no such label and
        VictoriaLogs no such field. All three have to be honest about which
        of those they are, and neither of the two may answer with an empty
        panel and nothing else.
        """
        es = self.elasticsearch()
        self.assertIn("http_status", es.group_by_fields(Scope.unrestricted()))
        counted = es.aggregate(_query(), [Terms(name="p", field="http_status",
                                                size=5)],
                               Scope.unrestricted())
        self.assertTrue(counted.get("p"), "Elasticsearch counted nothing")

        for source in (self.loki(), self.victorialogs()):
            self.assertNotIn("http_status",
                             source.group_by_fields(Scope.unrestricted()))
            refused = source.aggregate(
                _query(), [Terms(name="p", field="http_status", size=5)],
                Scope.unrestricted())
            self.assertEqual(refused.get("p"), [])
            self.assertIn("http_status",
                          " ".join(refused.reasons("p")),
                          f"{source.name} drew an empty panel with no reason")


if __name__ == "__main__":
    unittest.main()
