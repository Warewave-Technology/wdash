"""
The group-by offer and the Loki split, against the running lab.

`tests/test_group_by_fields.py` and `tests/test_conformance_loki.py` hold the
code to what was measured; this file asks the real servers, and it is where
the measurements came from. Both are needed: a fake answers what it was
written to answer, and the thing being claimed here is what Elasticsearch,
Loki and VictoriaLogs actually do.

    cd lab && ./lab.sh up          # Elasticsearch, Loki, VictoriaLogs

Read-only: every request here is a query. Skipped when a backend is absent,
and REQUIRED when `WDASH_REQUIRE_LAB` says a job promised THAT backend — a
test that exists to measure this and passes by skipping is the fault it is
looking for, and a test that fails over a backend nobody promised is the
same fault pointed the other way.
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

#: The lab's log index. Named rather than wildcarded, so this measures the
#: mapping the numbers in the comments came from.
ES_PATTERN = "app-logs-*"


from tests import lab  # noqa: E402


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


def _skip_unless(reachable, kind, what):
    if reachable:
        return
    if lab.promised(kind):
        raise AssertionError(
            f"WDASH_REQUIRE_LAB promised {kind} but {what} is not there")
    raise unittest.SkipTest(f"{what} is not running")


def _needs(kind, hours=24):
    """Reachable AND holding something over the window this file asks about.

    Reachability was the whole guard, and the two are not the same question:
    a lab that is up and a week old answers every query here with nothing,
    which reads as an adapter that has stopped working. Measured on
    2026-09-20, when it did. See tests/lab.py.

    Per BACKEND, not per run: the promise used to be one flag for the whole
    suite, so a job that started an Elasticsearch failed here over a Loki it
    had never said it would run.
    """
    _skip_unless(lab.volume(kind, hours) is not None, kind,
                 f"{kind} at {lab.BACKENDS[kind][0]}")
    reason = lab.why_not(kind, hours=hours)
    if reason:
        if lab.promised(kind):
            raise AssertionError(
                f"WDASH_REQUIRE_LAB promised {kind} but {reason}")
        raise unittest.SkipTest(reason)


class LokiSplitLabTest(unittest.TestCase):
    """D16 against the server that decides it."""

    def setUp(self):
        _needs("loki")
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

    def test_a_window_with_no_lines_says_nothing_about_the_label(self):
        """The inference needs evidence, and an empty answer is not evidence.

        `sum by (level)` over a filter nothing matches returns no series at
        all, which was read as the one unlabelled series that means "not a
        label" — so a panel over a quiet window reported that `severity` is
        not a Loki label on streams that carry it, beside a total of nothing.
        The terms path has always required an unlabelled series carrying
        lines before it says this.
        """
        for field in ("severity", "service"):
            result = self.source.aggregate(
                LogQuery(window=_window(24), text="zzz_no_such_line_F1",
                         limit=10),
                [DateHistogram(name="panel", interval="1h", min_count=0,
                               sub=(Terms(name="split", field=field, size=10),))],
                Scope.unrestricted())
            self.assertFalse(result.failed, result.warnings)
            self.assertEqual(sum(row.count for row in result.get("panel") or ()),
                             0, "the lab answered lines for a nonsense filter")
            self.assertEqual(result.reasons("panel"), (), field)
            self.assertEqual(result.warnings, (), field)

    def test_a_split_cut_to_fit_the_legend_says_how_many_it_dropped(self):
        """Measured: 24h by `service` at size 10 drew 473 of 488 lines with
        nothing said. The stack is shorter than the line above it, which is
        exactly the state the half-labelled note exists for."""
        result = self.source.aggregate(
            _query(_window(24)),
            [DateHistogram(name="panel", interval="1h", min_count=0,
                           sub=(Terms(name="split", field="service", size=2),))],
            Scope.unrestricted())
        rows = result.get("panel")
        total = sum(row.count for row in rows)
        stack = sum(b.count for row in rows for b in row.sub.get("split", ()))
        self.assertGreater(total, stack, "nothing was dropped to measure")
        reason = " ".join(result.reasons("panel"))
        self.assertIn("did not fit the legend", reason)
        self.assertIn("'service'", reason)

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
        _needs("loki")
        from wdash.hub.adapters.loki import LokiLogSource
        return LokiLogSource(LOKI_URL, name="lab-loki")

    def victorialogs(self):
        _needs("victorialogs")
        from wdash.hub.adapters.victorialogs import VictoriaLogsSource
        return VictoriaLogsSource(VL_URL, name="lab-vl")

    def elasticsearch(self):
        _needs("es-logs")
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

    def test_a_numbered_field_answers_the_aggregation_a_panel_really_sends(self):
        """The offer is only worth having if the panel built from it answers.

        `_panel_aggregations` asks for absent documents under "unknown" on
        every terms panel but severity, and Elasticsearch parses `missing` as
        the field's own type: `{"terms": {"field": "http_status", "missing":
        "unknown"}}` answered `BadRequestError(400, ... 'For input string:
        "unknown"')` on this cluster, and a 400 is the whole `_search` — the
        timeline and the severity panel of the same board went dark too, with
        no reason on any of the three. Measured with a bare `Terms`, which is
        not what a board sends, this looked fine.
        """
        es = self.elasticsearch()
        offered = es.group_by_fields(Scope.unrestricted())
        self.assertIn("http_status", offered)

        batch = [
            DateHistogram(name="timeline", interval="1h", min_count=0,
                          sub=(Terms(name="split", field="severity", size=10),)),
            Terms(name="levels", field="severity", size=10),
            Terms(name="status", field="http_status", size=10,
                  missing="unknown"),
            Terms(name="slow", field="duration_ms", size=10,
                  missing="unknown"),
            Terms(name="users", field="user_id", size=10, missing="unknown"),
        ]
        result = es.aggregate(_query(), batch, Scope.unrestricted())

        self.assertFalse(result.failed, result.warnings)
        self.assertEqual(result.warnings, ())
        for name in ("timeline", "levels", "status", "slow", "users"):
            self.assertTrue(result.get(name), f"{name} answered nothing")

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
