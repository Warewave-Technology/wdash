"""
Alerting on a saved log search.

The fourth rule kind. A rule points at a saved search, groups its matches by
a field, and every value of that field over the threshold is its own alert —
so a rule watching twenty services is twenty alerts that fire and recover on
their own. The alternative, one alert for the whole query, hides the second
service to break behind the first and recovers when either of them does.

The state machine needs nothing new: a grouped value is a subject the way a
monitor is a subject, and everything `alerts/evaluate.py` knows about
flapping, repeating and recovering is already about subjects. So what is
tested here is the OBSERVATION — what the rule sees, and, at greater length,
every way it can fail to see.

That second part is most of this file on purpose. A rule that cannot look
observes nothing, and nothing is indistinguishable from "every group
recovered" unless something says otherwise: `complete=False` is that
something, and a pass that loses it sends a recovery for an outage that is
still happening and then forgets the failure count it was keeping. One of
these cases was found by measuring rather than by reasoning — a field the
cluster cannot group by is refused on its own while the search around it
succeeds, so nothing failed, nothing was partial, and every firing group
would have been told it was well.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.alerts.runner import (  # noqa: E402
    LOG_QUERY_GROUPS, observe,
)
from wdash.hub.aggregation import AggregationResult, Bucket  # noqa: E402

NOW = datetime(2026, 9, 23, 18, 0, tzinfo=timezone.utc)


class Search:
    """A saved search, as the store hands one over."""

    def __init__(self, name="Errors", query="level:ERROR", source=None):
        self.name, self.query, self.source = name, query, source


class Searches:
    def __init__(self, **searches):
        self._searches = searches

    def get(self, search_id):
        return self._searches.get(search_id)


class Store:
    def __init__(self, **searches):
        self.saved_searches = Searches(**searches)


class Source:
    """A log source that answers one aggregation, however it was told to."""

    def __init__(self, result=None, **counts):
        self.result = result or AggregationResult(
            buckets={"groups": [Bucket(key=name, count=count)
                                for name, count in counts.items()]})
        self.asked = []

    def aggregate(self, query, aggregations, scope):
        self.asked.append((query, aggregations, scope))
        return self.result


class Hub:
    ALL_SOURCES = "*"

    def __init__(self, source=None):
        self.source = source
        self.asked_for = []

    def logs(self, name=None):
        self.asked_for.append(name)
        return self.source


def rule(**selector):
    """A log rule whose selector says what the test is about."""
    whole = {"saved_search": "s1", "group_by": "service"}
    whole.update({k: v for k, v in selector.items() if v is not None})
    for key, value in selector.items():
        if value is None:
            whole.pop(key, None)
    return {"id": "r1", "name": "errors", "kind": "log_query",
            "selector": whole}


def seen(source, store=None, **selector):
    return observe(rule(**selector), None,
                   store or Store(s1=Search()), None, NOW, Hub(source))


class WhatALogRuleCountsTest(unittest.TestCase):
    """One observation per group, and what makes one bad."""

    def test_every_group_is_its_own_subject(self):
        out = seen(Source(billing=12, search=3, checkout=40),
                   at_least="10").observations
        self.assertEqual(sorted(o.subject for o in out),
                         ["billing", "checkout", "search"])

    def test_the_threshold_decides_which_of_them_is_bad(self):
        out = seen(Source(billing=12, search=3, checkout=40),
                   at_least="10").observations
        self.assertEqual({o.subject: o.bad for o in out},
                         {"billing": True, "search": False, "checkout": True})

    def test_a_rule_with_no_threshold_fires_on_the_first_record(self):
        """"Tell me when this search matches anything here" is the common
        case and the default. Note that no test can separate a default of 1
        from one of 0 — a terms bucket exists only where a document made it,
        so both fire on the same groups; the runner says so where the
        default is written."""
        out = seen(Source(billing=1), at_least=None).observations
        self.assertEqual([(o.subject, o.bad) for o in out], [("billing", True)])

    def test_the_threshold_is_at_least_and_not_more_than(self):
        """A rule reading "10 errors in 15 minutes" fires on the tenth.
        Off by one here is an alert that needs eleven, which nobody
        discovers until the report of the outage it missed."""
        out = seen(Source(billing=10), at_least="10").observations
        self.assertEqual([o.bad for o in out], [True])

    def test_the_detail_carries_the_count_and_what_it_was_measured_against(self):
        """It is the sentence the notification sends. A number with nothing
        beside it cannot be acted on: 40 is either nothing or an outage
        depending on a threshold the reader cannot see."""
        [out] = seen(Source(checkout=40), at_least="10",
                     window_minutes="15").observations
        self.assertEqual(out.detail,
                         "40 record(s) in 15 minute(s), against a "
                         "threshold of 10")

    def test_a_group_with_nothing_in_it_is_simply_absent(self):
        """And the state machine resolves it, which is right: a value with
        no records in the window has nothing wrong with it. This is only
        safe because every way of FAILING to count says so — see
        `WhenALogRuleCannotLookTest`."""
        out = seen(Source())
        self.assertEqual(out.observations, [])
        self.assertTrue(out.complete)

    def test_it_counts_over_the_window_the_rule_names(self):
        source = Source(billing=1)
        seen(source, window_minutes="5")
        [(query, _, _)] = source.asked
        self.assertEqual(query.window.end, NOW)
        self.assertEqual(query.window.start, NOW - timedelta(minutes=5))

    def test_the_window_is_exact_rather_than_aligned(self):
        """An aligned window is widened by up to one bucket. On a chart that
        is invisible; against a threshold it counts records from outside the
        minutes the rule names, in a sentence that says it did not."""
        source = Source(billing=1)
        seen(source, window_minutes="7")
        [(query, _, _)] = source.asked
        self.assertEqual(
            (query.window.end - query.window.start).total_seconds(), 7 * 60)

    def test_it_counts_the_saved_searchs_own_query(self):
        source = Source(billing=1)
        seen(source, store=Store(s1=Search(query="level:FATAL")))
        [(query, _, _)] = source.asked
        self.assertEqual(query.text, "level:FATAL")

    def test_it_reads_the_source_the_saved_search_was_written_against(self):
        """A search saved against one cluster must not be counted on
        another: the same query over a different store is a different
        question, and the alert would name neither."""
        hub = Hub(Source(billing=1))
        observe(rule(), None, Store(s1=Search(source="warehouse")), None,
                NOW, hub)
        self.assertEqual(hub.asked_for, ["warehouse"])

    def test_a_search_pinned_to_no_source_reads_every_one(self):
        hub = Hub(Source(billing=1))
        observe(rule(), None, Store(s1=Search(source=None)), None, NOW, hub)
        self.assertEqual(hub.asked_for, ["*"])


class WhenALogRuleCannotLookTest(unittest.TestCase):
    """Every way of not counting, and the one thing they share.

    `complete=False`. Without it the empty list of groups is read as "every
    group recovered", so the pass sends a recovery in the middle of the
    outage and then empties the state row it was counting failures in.
    """

    def refusal(self, source=None, store=None, **selector):
        out = seen(source if source is not None else Source(),
                   store, **selector)
        self.assertEqual(out.observations, [], "it observed something")
        self.assertFalse(out.complete, "an empty answer was called complete")
        self.assertTrue(out.warnings, "it declined without saying why")
        return " ".join(out.warnings)

    def test_a_rule_naming_no_saved_search(self):
        self.assertIn("names no saved search",
                      self.refusal(saved_search=None))

    def test_a_saved_search_that_was_deleted(self):
        """The commonest of these: somebody tidies their saved searches and
        the rule goes on existing."""
        self.assertIn("no saved search 'gone'",
                      self.refusal(saved_search="gone"))

    def test_a_rule_naming_no_field_to_group_by(self):
        self.assertIn("no field to group by", self.refusal(group_by=None))

    def test_a_window_that_is_not_a_number(self):
        """NOT quietly replaced by the default. A rule written to count a
        day that silently counts fifteen minutes is a rule whose threshold
        means something other than what is written on it."""
        self.assertIn("not a whole number",
                      self.refusal(window_minutes="fifteen"))

    def test_a_threshold_that_is_not_a_number(self):
        self.assertIn("not a whole number", self.refusal(at_least="lots"))

    def test_a_threshold_of_zero(self):
        """Zero would make every group bad, including the ones with no
        records, which is not a threshold but a stuck alarm."""
        self.assertIn("at least 1", self.refusal(at_least="0"))

    def test_a_selector_key_this_version_does_not_read(self):
        """A misspelled key is a setting somebody believes is in force. Read
        as a monitor label it would match nothing and say nothing."""
        self.assertIn("windo_minutes", self.refusal(windo_minutes="15"))

    def test_no_log_source_configured_at_all(self):
        """Not routed through `refusal`: that helper supplies a source, and
        the absence of one is the thing being asked about."""
        out = observe(rule(), None, Store(s1=Search()), None, NOW, Hub(None))
        self.assertEqual(out.observations, [])
        self.assertFalse(out.complete)
        self.assertIn("there is none", " ".join(out.warnings))

    def test_no_hub_at_all(self):
        """`observe` is called with the monitor source positionally and the
        hub last; a caller that has not been taught about the fourth kind
        passes no hub, and must not thereby resolve every alert."""
        out = observe(rule(), None, Store(s1=Search()), None, NOW)
        self.assertEqual(out.observations, [])
        self.assertFalse(out.complete)

    def test_a_search_that_did_not_run(self):
        """`failed` is no answer at all."""
        self.assertIn("the cluster refused", self.refusal(
            Source(AggregationResult(failed=True,
                                     warnings=("the cluster refused",)))))

    def test_an_answer_that_came_back_short(self):
        """`partial`: some shards did not reply. The groups in hand are not
        the groups there are."""
        self.assertIn("4 of 9 shards", self.refusal(
            Source(AggregationResult(partial=True,
                                     warnings=("4 of 9 shards failed",)))))

    def test_a_field_the_backend_cannot_group_by(self):
        """Found by measuring against a real cluster, grouping by `@m`: the
        search succeeds and the AGGREGATION is refused on its own, so
        nothing failed, nothing was partial, and every firing group would
        have been told it had recovered on a pass that counted nothing."""
        said = self.refusal(Source(AggregationResult(
            notes={"groups": ["'@m' cannot be aggregated on these indices"]})))
        self.assertIn("cannot be aggregated", said)

    def test_that_reason_is_not_said_twice(self):
        """A single source files its reason under both the page-level list
        and the aggregation's name. The same sentence twice in a log reads
        as the thing having happened twice."""
        reason = "'@m' cannot be aggregated on these indices"
        out = seen(Source(AggregationResult(warnings=(reason,),
                                            notes={"groups": [reason]})))
        self.assertEqual(list(out.warnings).count(reason), 1)


class Ratio:
    """A source that answers the matches first and the total second.

    `_ratio_groups` runs two searches: the saved search's own query, then
    the same window with the query replaced by everything. This answers
    them in that order, which is also the order that keeps the numerator
    from outgrowing the denominator.
    """

    def __init__(self, matched=None, total=None, results=None):
        self.results = results or [
            AggregationResult(buckets={"groups": [
                Bucket(key=k, count=v) for k, v in (matched or {}).items()]}),
            AggregationResult(buckets={"groups": [
                Bucket(key=k, count=v) for k, v in (total or {}).items()]}),
        ]
        self.asked = []

    def aggregate(self, query, aggregations, scope):
        self.asked.append((query, aggregations, scope))
        return self.results[min(len(self.asked), len(self.results)) - 1]


def share(source, **selector):
    whole = {"condition": "ratio"}
    whole.update(selector)
    return seen(source, **whole)


class WhatShareOfAGroupTest(unittest.TestCase):
    """The condition a service whose traffic moves can be asked.

    Ten errors is an outage at 3am and a rounding error at noon. A
    twentieth of the lines is the same statement at both.
    """

    def test_the_share_decides(self):
        out = share(Ratio(matched={"billing": 10, "checkout": 1},
                          total={"billing": 100, "checkout": 100}),
                    ratio_at_least="5", of_at_least="20").observations
        self.assertEqual({o.subject: o.bad for o in out},
                         {"billing": True, "checkout": False})

    def test_a_rule_with_no_share_named_uses_a_share_worth_paging_on(self):
        """Unlike the count condition's default, this one is observable and
        has to be: a default of nothing would fire on a single error in ten
        thousand lines, which is every service, all the time."""
        out = share(Ratio(matched={"billing": 1, "checkout": 20},
                          total={"billing": 100, "checkout": 100}),
                    of_at_least="20").observations
        self.assertEqual({o.subject: o.bad for o in out},
                         {"billing": False, "checkout": True})

    def test_a_rule_with_no_floor_named_will_not_read_a_handful(self):
        """Six records cannot support a percentage: one of them is sixteen
        points. Without a default floor the rule would page on it."""
        [out] = share(Ratio(matched={"billing": 3}, total={"billing": 6}),
                      ratio_at_least="5").observations
        self.assertFalse(out.known,
                         "a share was read off six records")

    def test_the_threshold_is_at_least_here_too(self):
        out = share(Ratio(matched={"billing": 5}, total={"billing": 100}),
                    ratio_at_least="5", of_at_least="20").observations
        self.assertEqual([o.bad for o in out], [True])

    def test_the_detail_shows_both_numbers_and_the_share(self):
        """A percentage with no counts behind it cannot be checked, and a
        reader woken at 4am is exactly the person who needs to see that it
        was 3 of 20 rather than 300 of 2,000."""
        [out] = share(Ratio(matched={"billing": 12}, total={"billing": 400}),
                      ratio_at_least="5", of_at_least="20",
                      window_minutes="15").observations
        self.assertEqual(out.detail,
                         "12 of 400 record(s) in 15 minute(s) — 3.0%, "
                         "against a threshold of 5%")

    def test_the_denominator_is_the_same_window_with_no_query(self):
        source = Ratio(matched={"billing": 1}, total={"billing": 10})
        share(source, ratio_at_least="5", of_at_least="1",
              window_minutes="15")
        (matching, _, _), (everything, _, _) = source.asked
        self.assertEqual(matching.text, "level:ERROR")
        self.assertEqual(everything.text, "*")
        self.assertEqual(everything.window, matching.window)

    def test_the_matches_are_counted_before_the_total(self):
        """A record written between the two searches then lands in the
        denominator rather than the numerator, so the share comes out a
        shade low — the direction that does not invent an alert."""
        source = Ratio(matched={"billing": 1}, total={"billing": 10})
        share(source, of_at_least="1")
        self.assertEqual([q.text for q, _, _ in source.asked],
                         ["level:ERROR", "*"])

    def test_a_group_whose_matches_stopped_is_reported_as_well(self):
        """It has no bucket in the numerator at all, and it is exactly the
        group whose alert has to resolve. Iterating the numerator would
        leave it firing for ever."""
        out = share(Ratio(matched={}, total={"billing": 100}),
                    ratio_at_least="5", of_at_least="20").observations
        self.assertEqual([(o.subject, o.bad, o.known) for o in out],
                         [("billing", False, True)])

    def test_a_share_over_a_hundred_is_clamped(self):
        """The numerator is a subset of the denominator by construction, so
        this is the race running the other way. A percentage over 100 in an
        alert is a number nobody can act on."""
        [out] = share(Ratio(matched={"billing": 12}, total={"billing": 10}),
                      ratio_at_least="5", of_at_least="1").observations
        self.assertIn("100.0%", out.detail)


class TooLittleToSayTest(unittest.TestCase):
    """A percentage of three records is a statement about three records.

    With N records one record IS 100/N per cent. Below the floor the
    threshold measures the sample rather than the service, and the honest
    answer is neither "firing" nor "fine".
    """

    def small(self, floor="20", **selector):
        return share(Ratio(matched={"billing": 2}, total={"billing": 3}),
                     ratio_at_least="5", of_at_least=floor,
                     **selector).observations

    def test_a_group_under_the_floor_is_not_called_bad(self):
        """Two errors in three lines is 67%, and firing on it pages
        somebody about a service nobody is using."""
        self.assertEqual([o.bad for o in self.small()], [False])

    def test_and_is_not_called_well_either(self):
        """`bad=False` alone would resolve a firing alert on a sample of
        three. `known=False` holds it instead — the state machine has meant
        this since the monitor side, and it means it here."""
        self.assertEqual([o.known for o in self.small()], [False])

    def test_it_says_how_little_there_was_and_what_it_wanted(self):
        [out] = self.small()
        self.assertEqual(out.detail,
                         "3 record(s) in 15 minute(s), too few to read a "
                         "share of — this rule wants 20")

    def test_a_floor_the_group_clears_is_judged_normally(self):
        self.assertEqual([(o.bad, o.known) for o in self.small(floor="3")],
                         [(True, True)])


class ARatioThatCannotBeReadTest(unittest.TestCase):
    """Its own refusals, and the two searches' failures folded together."""

    def refusal(self, source=None, **selector):
        out = share(source or Ratio(matched={}, total={}), **selector)
        self.assertFalse(out.complete)
        self.assertTrue(out.warnings)
        return " ".join(out.warnings)

    def test_a_condition_this_version_does_not_know(self):
        out = seen(Source(), condition="rate")
        self.assertFalse(out.complete)
        self.assertEqual(out.observations, [])
        self.assertIn("'rate' is not a condition", " ".join(out.warnings))

    def test_a_share_that_is_not_a_number(self):
        self.assertIn("not a whole number",
                      self.refusal(ratio_at_least="five percent"))

    def test_a_share_over_a_hundred_cannot_be_reached(self):
        """A rule that can never fire is a rule somebody believes is
        watching."""
        self.assertIn("cannot be reached", self.refusal(ratio_at_least="120"))

    def test_a_floor_that_is_not_a_number(self):
        self.assertIn("not a whole number", self.refusal(of_at_least="lots"))

    def test_the_total_failing_is_enough_to_stop_the_pass(self):
        """Both searches have to land. The matches alone say nothing about
        a share, and reporting on them would judge every group against a
        denominator this pass never read."""
        source = Ratio(results=[
            AggregationResult(buckets={"groups": [Bucket(key="billing",
                                                         count=5)]}),
            AggregationResult(failed=True, warnings=("the cluster refused",)),
        ])
        self.assertIn("the cluster refused", self.refusal(source))

    def test_the_matches_failing_is_too(self):
        source = Ratio(results=[
            AggregationResult(failed=True, warnings=("the cluster refused",)),
            AggregationResult(buckets={"groups": [Bucket(key="billing",
                                                         count=100)]}),
        ])
        self.assertIn("the cluster refused", self.refusal(source))

    def test_a_cut_is_never_reasoned_past_on_a_share(self):
        """The count condition can bound what is behind its cut, because
        terms are ordered by count and so is its threshold. A share is not:
        a quiet group with a terrible ratio sits wherever its VOLUME puts
        it, which may be last."""
        full = {f"service-{n}": 1_000 for n in range(LOG_QUERY_GROUPS)}
        said = self.refusal(Ratio(matched={"service-0": 1}, total=full),
                            ratio_at_least="90", of_at_least="1")
        self.assertIn("no way to tell what is behind the cut", said)


class TheGroupsItCannotSeeTest(unittest.TestCase):
    """A terms aggregation has a size, and what falls past it is invisible.

    Ordered by count, so everything below the cut counts no more than the
    last value returned. That turns the cut into a question this pass can
    ANSWER rather than a silent trim: if the smallest value in hand is still
    under the threshold, nothing hidden can be over it.
    """

    def full(self, count):
        return Source(AggregationResult(buckets={"groups": [
            Bucket(key=f"service-{n}", count=count)
            for n in range(LOG_QUERY_GROUPS)]}))

    def test_a_cut_that_hid_nothing_over_the_threshold_is_complete(self):
        self.assertTrue(seen(self.full(3), at_least="10").complete)

    def test_a_cut_that_could_be_hiding_one_is_not(self):
        out = seen(self.full(40), at_least="10")
        self.assertFalse(out.complete)
        self.assertIn("cannot see all of them", " ".join(out.warnings))

    def test_and_the_groups_it_did_see_are_still_reported(self):
        """Incomplete is not empty: the services known to be breaching
        should still fire. Withholding them would turn "I may be missing
        some" into "there are none"."""
        out = seen(self.full(40), at_least="10")
        self.assertEqual(len(out.observations), LOG_QUERY_GROUPS)
        self.assertTrue(all(o.bad for o in out.observations))

    def test_fewer_groups_than_the_cut_is_always_complete(self):
        """The cut was not reached, so nothing is behind it — whatever the
        counts are."""
        source = Source(AggregationResult(buckets={"groups": [
            Bucket(key=f"service-{n}", count=9_000)
            for n in range(LOG_QUERY_GROUPS - 1)]}))
        self.assertTrue(seen(source, at_least="10").complete)


class SavingALogRuleTest(unittest.TestCase):
    """Refused at the save, not left to the evaluator.

    The evaluator does refuse a rule with no saved search, and says so every
    pass. But a rule that exists and never evaluates reads, on the page that
    lists it, as a rule that is watching — and "I have an alert for that" is
    the belief this whole feature must not sell falsely.
    """

    def setUp(self):
        import tempfile
        from wdash.store import Store
        from wdash.store.secrets import SecretBox

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.store = Store.open(f"sqlite:///{self.database}",
                                secret_box=SecretBox(SecretBox.generate_key()))
        self.channel = self.store.channels.create(
            "hook", url="https://example.com/hook")

    def tearDown(self):
        self.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def create(self, selector):
        return self.store.rules.create(
            "errors", "log_query", self.channel["id"], selector=selector)

    def test_a_whole_rule_saves(self):
        saved = self.create({"saved_search": "s1", "group_by": "service"})
        self.assertEqual(saved["kind"], "log_query")
        self.assertEqual(saved["selector"]["group_by"], "service")

    def test_it_is_a_rule_kind_the_product_offers(self):
        from wdash.alerts.evaluate import LOG_QUERY, RULE_KINDS
        self.assertIn(LOG_QUERY, RULE_KINDS)

    def test_a_rule_with_no_saved_search_is_refused(self):
        from wdash.store.alerting import AlertingError
        with self.assertRaises(AlertingError) as refused:
            self.create({"group_by": "service"})
        self.assertIn("saved search", str(refused.exception))

    def test_a_rule_with_nothing_to_group_by_is_refused(self):
        from wdash.store.alerting import AlertingError
        with self.assertRaises(AlertingError) as refused:
            self.create({"saved_search": "s1"})
        self.assertIn("group by", str(refused.exception))

    def test_a_condition_this_version_cannot_judge_is_refused(self):
        """Read as anything but a known condition the rule falls back to
        counting, so a ratio rule saved with a misspelled one would fire on
        ten RECORDS while its form says ten per cent."""
        from wdash.store.alerting import AlertingError
        with self.assertRaises(AlertingError) as refused:
            self.create({"saved_search": "s1", "group_by": "service",
                         "condition": "rate"})
        self.assertIn("'rate' is not a way to judge", str(refused.exception))

    def test_a_ratio_rule_saves(self):
        saved = self.create({"saved_search": "s1", "group_by": "service",
                             "condition": "ratio", "ratio_at_least": "5"})
        self.assertEqual(saved["selector"]["condition"], "ratio")

    def test_an_edit_cannot_empty_it_either(self):
        """It arrives by the same form and is the same mistake. The kind is
        read from the stored row rather than taken from the caller, so an
        edit cannot dodge the check by not mentioning it."""
        from wdash.store.alerting import AlertingError
        saved = self.create({"saved_search": "s1", "group_by": "service"})
        with self.assertRaises(AlertingError):
            self.store.rules.update(saved["id"], selector={"group_by": ""})

    def test_and_an_edit_to_another_kind_is_left_alone(self):
        """A monitor rule's selector is a label selector, and an empty one
        means every monitor."""
        other = self.store.rules.create(
            "down", "monitor_down", self.channel["id"], selector={"env": "x"})
        self.assertEqual(
            self.store.rules.update(other["id"], selector={})["selector"], {})


class AWholePassTest(unittest.TestCase):
    """The runner, not just the observation.

    `observe` is given the hub as its last argument, and everything above
    calls `observe` directly — so nothing above would notice if
    `evaluate_once` stopped passing it. A log rule would then observe
    nothing on every pass, for ever, and the only sign would be a line in
    the log. This drives the real loop instead.
    """

    def setUp(self):
        import tempfile
        from wdash.store import Store
        from wdash.store.secrets import SecretBox
        from tests.test_alert_delivery import Receiver

        handle, self.database = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.database)
        self.store = Store.open(f"sqlite:///{self.database}",
                                secret_box=SecretBox(SecretBox.generate_key()))
        self.receiver = Receiver()
        self.channel = self.store.channels.create("hook",
                                                  url=self.receiver.url)
        self.search = self.store.saved_searches.create(
            "Errors", "level:ERROR", "15m", created_by="admin")
        self.rule = self.store.rules.create(
            "errors per service", "log_query", self.channel["id"],
            threshold=1,
            selector={"saved_search": self.search.id, "group_by": "service",
                      "at_least": "10", "window_minutes": "15"})
        self.source = Source(billing=12, search=3, checkout=40)

    def tearDown(self):
        self.receiver.stop()
        self.store.engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.database + suffix):
                os.unlink(self.database + suffix)

    def runner(self, source=None):
        from wdash.alerts.runner import AlertRunner

        class WholeHub(Hub):
            def monitors(self, name=None):
                return None

        return AlertRunner(self.store, WholeHub(
            self.source if source is None else source))

    def test_the_breaching_groups_fire_and_the_quiet_one_does_not(self):
        self.assertEqual(self.runner().evaluate_once(), 2)
        self.assertEqual(
            sorted(r["body"]["name"] for r in self.receiver.received),
            ["billing", "checkout"])

    def test_the_notification_says_how_many_and_against_what(self):
        self.runner().evaluate_once()
        said = " ".join(str(r["body"]) for r in self.receiver.received)
        self.assertIn("40 record(s) in 15 minute(s)", said)
        self.assertIn("threshold of 10", said)

    def test_a_group_that_drops_below_the_threshold_recovers(self):
        self.runner().evaluate_once()
        self.receiver.received.clear()
        self.runner(Source(billing=1, checkout=40)).evaluate_once()
        transitions = {r["body"]["name"]: r["body"]["transition"]
                       for r in self.receiver.received}
        self.assertEqual(transitions.get("billing"), "resolved")
        self.assertNotIn("checkout", transitions,
                         "a group still breaching was told it had recovered")

    def test_a_pass_that_could_not_look_resolves_nothing(self):
        """The whole reason `complete` travels with the observations. Here
        the search fails on the second pass, which must not read as every
        service having recovered."""
        self.runner().evaluate_once()
        self.receiver.received.clear()
        self.runner(Source(AggregationResult(
            failed=True, warnings=("the cluster refused",)))).evaluate_once()
        self.assertEqual(self.receiver.received, [],
                         "a backend outage was announced as a recovery")


class AgainstTheLabTest(unittest.TestCase):
    """The whole path over a real Elasticsearch.

    The fakes above model an aggregation result. This asks a cluster, which
    is where the two things the fakes cannot prove live: that a neutral
    field name resolves to a real mapping path, and that a field which is
    NOT groupable comes back as a refusal rather than as no groups.
    """

    INDEX = "wdash-log-alert-check"

    @classmethod
    def setUpClass(cls):
        from tests import lab
        if lab.volume("es-logs") is None:
            raise unittest.SkipTest(
                f"es-logs at {lab.BACKENDS['es-logs'][0]} is not running")
        from elasticsearch import Elasticsearch
        from wdash.hub.adapters import ElasticsearchLogSource

        cls.es = Elasticsearch(hosts=[lab.ES], request_timeout=20)
        cls.es.options(ignore_status=[404]).indices.delete(index=cls.INDEX)
        cls.es.indices.create(index=cls.INDEX, mappings={"properties": {
            "@timestamp": {"type": "date"},
            "level": {"type": "keyword"},
            "service": {"type": "keyword"},
            "message": {"type": "text"}}})
        # Three services, three counts, so one threshold can tell them apart.
        for number, (service, count) in enumerate(
                (("billing", 12), ("search", 3), ("checkout", 40))):
            for n in range(count):
                cls.es.index(index=cls.INDEX, id=f"{service}-{n}", document={
                    "@timestamp": (NOW - timedelta(minutes=1)).isoformat(),
                    "level": "ERROR", "service": service,
                    "message": "it broke"})
        cls.es.indices.refresh(index=cls.INDEX)
        cls.source = ElasticsearchLogSource(cls.es, name="lab",
                                            patterns=(cls.INDEX,))

    @classmethod
    def tearDownClass(cls):
        cls.es.options(ignore_status=[404]).indices.delete(index=cls.INDEX)

    def observe(self, **selector):
        # `NOW` is the fixture's clock, and the window ends there: a real
        # window ending at the real now would hold nothing the day after
        # this was written.
        return observe(rule(**selector), None, Store(s1=Search()), None,
                       NOW, Hub(self.source))

    def test_a_real_cluster_counts_each_service(self):
        out = self.observe(group_by="service", at_least="10",
                           window_minutes="5")
        self.assertEqual({o.subject: o.bad for o in out.observations},
                         {"billing": True, "search": False, "checkout": True})
        self.assertTrue(out.complete)

    def test_the_counts_are_the_records_that_are_there(self):
        out = self.observe(group_by="service", at_least="1",
                           window_minutes="5")
        self.assertEqual(
            {o.subject: int(o.detail.split()[0]) for o in out.observations},
            {"billing": 12, "search": 3, "checkout": 40})

    def test_a_field_this_cluster_cannot_group_by_is_a_refusal(self):
        """`message` is `text`: the search succeeds and the aggregation is
        refused on its own. The fakes assert what this proves is real."""
        out = self.observe(group_by="message", at_least="1",
                           window_minutes="5")
        self.assertEqual(out.observations, [])
        self.assertFalse(out.complete,
                         "not being able to group read as no groups")

    def ratio(self, **selector):
        whole = {"condition": "ratio", "group_by": "service",
                 "window_minutes": "5"}
        whole.update(selector)
        return observe(rule(**whole), None,
                       Store(s1=Search(query="level:ERROR")), None, NOW,
                       Hub(self.source))

    def test_a_real_cluster_answers_a_share_per_service(self):
        """The fixture is 12, 3 and 40 ERROR records and nothing else, so
        every service is 100% errors — which is the point: the denominator
        really is the same search with the query taken off, and the two
        numbers come from the same cluster in the same window."""
        out = self.ratio(ratio_at_least="50", of_at_least="1")
        self.assertEqual({o.subject: o.bad for o in out.observations},
                         {"billing": True, "search": True, "checkout": True})
        self.assertTrue(out.complete)

    def test_the_denominator_is_bigger_than_the_query_alone(self):
        """A second index of non-matching lines in the same window: the
        totals have to grow and the shares have to fall."""
        for n in range(60):
            self.es.index(index=self.INDEX, id=f"quiet-{n}", document={
                "@timestamp": (NOW - timedelta(minutes=1)).isoformat(),
                "level": "INFO", "service": "checkout",
                "message": "all well"})
        self.es.indices.refresh(index=self.INDEX)
        try:
            out = self.ratio(ratio_at_least="50", of_at_least="1")
            found = {o.subject: o.detail for o in out.observations}
            self.assertIn("40 of 100 record(s)", found["checkout"])
            self.assertIn("40.0%", found["checkout"])
            self.assertFalse(
                next(o.bad for o in out.observations
                     if o.subject == "checkout"),
                "40% fired against a threshold of 50%")
        finally:
            for n in range(60):
                self.es.options(ignore_status=[404]).delete(
                    index=self.INDEX, id=f"quiet-{n}")
            self.es.indices.refresh(index=self.INDEX)

    def test_a_service_below_the_floor_is_unknown_on_a_real_cluster(self):
        """`search` has three records. A share of three records is a
        statement about three records."""
        out = self.ratio(ratio_at_least="50", of_at_least="20")
        known = {o.subject: o.known for o in out.observations}
        self.assertFalse(known["search"])
        self.assertTrue(known["checkout"])

    def test_a_window_before_the_records_counts_nothing_and_says_so(self):
        """Complete and empty: it looked, and there was nothing. This is
        the answer every refusal above must NOT look like."""
        out = observe(rule(group_by="service", at_least="1",
                           window_minutes="5"), None, Store(s1=Search()),
                      None, NOW - timedelta(days=2), Hub(self.source))
        self.assertEqual(out.observations, [])
        self.assertTrue(out.complete)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
