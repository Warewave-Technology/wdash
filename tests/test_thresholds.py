"""
Dashboard thresholds.

Not an alerting system — no notification, no schedule, no silencing. It answers
"is this outside what the owner calls normal", so that every reader does not
re-derive it from memory and disagree with the next one.

The distinction these tests protect: "no threshold configured" is not "ok".
A green badge on a dashboard nobody defined normal for is a claim we cannot
support, and once people see it they stop reading the numbers.
"""

import os
import sys
import unittest

from tests.support import change_dashboard, grant, install_dashboard

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.dashboard.thresholds import (  # noqa: E402
    ThresholdError, evaluate, normalise,
)


class NormaliseTest(unittest.TestCase):
    def test_values_are_parsed_from_form_strings(self):
        parsed = normalise({"error_rate": {"warning": "0.02", "critical": "0.05"}})
        self.assertEqual(parsed["error_rate"], {"warning": 0.02, "critical": 0.05})

    def test_blank_levels_are_dropped(self):
        parsed = normalise({"error_rate": {"warning": "0.02", "critical": ""}})
        self.assertEqual(parsed["error_rate"], {"warning": 0.02})

    def test_a_metric_with_nothing_set_disappears(self):
        self.assertEqual(normalise({"error_rate": {"warning": "", "critical": ""}}), {})

    def test_an_unknown_metric_is_refused(self):
        with self.assertRaises(ThresholdError):
            normalise({"cpu": {"warning": "1"}})

    def test_a_rate_above_one_is_refused_with_a_useful_message(self):
        """Typing 5 for 5% is the mistake this shape invites."""
        with self.assertRaises(ThresholdError) as caught:
            normalise({"error_rate": {"warning": "5"}})
        self.assertIn("0.05", str(caught.exception))

    def test_a_count_above_one_is_fine(self):
        self.assertEqual(normalise({"error_count": {"warning": "500"}}),
                         {"error_count": {"warning": 500.0}})

    def test_critical_below_warning_is_refused(self):
        """It would look configured and never be reported: critical wins first."""
        with self.assertRaises(ThresholdError):
            normalise({"error_rate": {"warning": "0.5", "critical": "0.1"}})

    def test_a_negative_threshold_is_refused(self):
        with self.assertRaises(ThresholdError):
            normalise({"error_count": {"warning": "-1"}})

    def test_nonsense_is_an_error_not_a_crash(self):
        with self.assertRaises(ThresholdError):
            normalise({"error_rate": {"warning": "quite high"}})


class EvaluateTest(unittest.TestCase):
    RATE = {"error_rate": {"warning": 0.02, "critical": 0.05}}

    def test_nothing_configured_is_none_not_ok(self):
        self.assertIsNone(evaluate({}, {"error_rate": 0.9}))
        self.assertIsNone(evaluate(None, {"error_rate": 0.9}))

    def test_inside_the_thresholds_is_ok(self):
        status = evaluate(self.RATE, {"error_rate": 0.01})
        self.assertEqual(status["level"], "ok")
        self.assertEqual(status["breaches"], [])

    def test_over_the_warning_is_a_warning(self):
        status = evaluate(self.RATE, {"error_rate": 0.03})
        self.assertEqual(status["level"], "warning")
        self.assertEqual(status["breaches"][0]["metric"], "error_rate")

    def test_over_both_is_critical_not_warning(self):
        status = evaluate(self.RATE, {"error_rate": 0.4})
        self.assertEqual(status["level"], "critical")
        self.assertEqual(len(status["breaches"]), 1, "one breach, not one per level")
        self.assertEqual(status["breaches"][0]["level"], "critical")

    def test_exactly_on_the_threshold_counts_as_breached(self):
        """'At or over' — a limit you can sit exactly on is not a limit."""
        self.assertEqual(evaluate(self.RATE, {"error_rate": 0.02})["level"], "warning")

    def test_the_worst_metric_sets_the_overall_level(self):
        thresholds = {"error_rate": {"warning": 0.02},
                      "error_count": {"critical": 100}}
        status = evaluate(thresholds, {"error_rate": 0.03, "error_count": 500})
        self.assertEqual(status["level"], "critical")
        self.assertEqual(len(status["breaches"]), 2)

    def test_a_missing_value_is_skipped_rather_than_treated_as_zero(self):
        """Zero would silently read as 'well within the threshold'."""
        status = evaluate(self.RATE, {})
        self.assertEqual(status["breaches"], [])

    def test_the_breach_text_says_what_and_by_how_much(self):
        text = evaluate(self.RATE, {"error_rate": 0.1})["breaches"][0]["text"]
        self.assertIn("10.00%", text)
        self.assertIn("5.00%", text)

    def test_a_count_breach_is_not_formatted_as_a_percentage(self):
        text = evaluate({"error_count": {"warning": 100}},
                        {"error_count": 1700})["breaches"][0]["text"]
        self.assertIn("1,700", text)
        self.assertNotIn("%", text)


class PayloadTest(unittest.TestCase):
    """The dashboard response carries the status the badge renders."""

    STORAGE = "database"

    def setUp(self):
        from wdash.app import create_app
        from wdash.config import Config
        from wdash.hub import Hub
        from wdash.hub.adapters import ElasticsearchLogSource
        from wdash.models import Dashboard
        from tests.test_dashboard_contract import FakeES

        class TestConfig(Config):
            TESTING = True
            SECRET_KEY = "thresholds"
            DASHBOARD_STORAGE = self.STORAGE

        self.app = create_app(TestConfig)
        hub = Hub()
        hub.add_logs(ElasticsearchLogSource(FakeES()))
        self.app.hub = hub

        # The fixture is 8 errors in 100 records: an 8% error rate.
        self.dashboard = install_dashboard(
            self.app,
            Dashboard("t1", "T", "", "*", "u", index_patterns=["app-*"]))

        self.client = self.app.test_client()
        grant(self.app, "u", permissions=["dashboard:view"], indices=["*"], trace_indices=["*"], services=["*"])
        with self.client.session_transaction() as session:
            session["user_data"] = {
                "id": "1", "email": "u@x", "username": "u", "groups": [],
                "role": "admin", "permissions": ["dashboard:view"],
                "allowed_indices": ["*"], "allowed_trace_indices": ["*"],
                "allowed_services": ["*"]}
            session["_user_id"] = "1"

    def status(self, thresholds):
        change_dashboard(self.app, self.dashboard, thresholds=thresholds)
        return self.client.get("/api/dashboard/t1/data").get_json()["status"]

    def test_no_thresholds_means_no_status(self):
        self.assertIsNone(self.status({}))

    def test_the_status_reflects_the_real_error_rate(self):
        self.assertEqual(self.status({"error_rate": {"warning": 0.05}})["level"],
                         "warning")
        self.assertEqual(self.status({"error_rate": {"warning": 0.5}})["level"], "ok")

    def test_a_count_threshold_uses_the_error_count(self):
        self.assertEqual(self.status({"error_count": {"critical": 5}})["level"],
                         "critical")

    def test_a_short_answer_gets_no_badge_at_all(self):
        """"Within thresholds" is a claim about numbers, and a half-answer
        is numbers nobody can vouch for.

        Elasticsearch fails a search outright only when EVERY shard fails;
        when some do it answers 200 with what the rest found and says so in
        `_shards`. Measured against the lab: `error_count` 18,609 against a
        critical threshold of 20,000 painted the badge GREEN, from a
        response carrying "5 of 9 shards failed: Fielddata is disabled" in
        the warnings of that same payload. It could have been anything above
        the threshold.
        """
        original = self.app.hub.logs().multi_aggregate

        def short(requests, scope):
            answers = original(requests, scope)
            for answer in answers:
                answer.partial = True
                answer.warnings = answer.warnings + (
                    "5 of 9 shards failed: Fielddata is disabled",)
            return answers

        self.app.hub.logs().multi_aggregate = short
        self.addCleanup(setattr, self.app.hub.logs(), "multi_aggregate",
                        original)

        # Both directions: the badge that would have been green, and the one
        # that would have been critical. Neither is a thing we can say.
        self.assertIsNone(self.status({"error_rate": {"warning": 0.5}}))
        self.assertIsNone(self.status({"error_count": {"critical": 5}}))

    def test_a_whole_answer_still_gets_one(self):
        """The control: the same board, nothing short about it."""
        self.assertEqual(self.status({"error_rate": {"warning": 0.5}})["level"],
                         "ok")



class PayloadOnTheFileStoreTest(PayloadTest):
    """The same thresholds against the JSON store, which is still supported.

    Pinned to the file store when the default moved — its fixture set
    `self.dashboard.thresholds` in place, which is a write only on the manager
    that hands out the object it stores — so the badge nobody had to configure
    was measured on the one store nobody gets.
    """

    STORAGE = "file"


if __name__ == "__main__":
    unittest.main(verbosity=2)
