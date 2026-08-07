"""
The alert state machine.

`evaluate` is a pure function so that everything which makes alerting hard can
be driven by hand. Each of these is a sequence of states over time; against a
real scheduler each would need minutes of waiting, which is why the ones that
matter never get tested and why alerting systems ship the same five bugs.

The five, all covered below:

  * firing on a single bad check, so a monitor that blips at 03:00 wakes
    somebody for a thing that fixed itself
  * a failure counter that is never reset, so the threshold means "ever"
    rather than "in a row"
  * repeating the same sentence every evaluation until the channel is muted
  * losing the recovery, so the last message anybody has says it is broken
  * a silence that swallows the recovery too
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wdash.alerts import (  # noqa: E402
    FIRING, NOTIFY_FIRING, NOTIFY_RESOLVED, OK, Observation, State, evaluate,
)

START = datetime(2026, 8, 6, 12, 0, tzinfo=timezone.utc)


class Rule:
    def __init__(self, threshold=3, repeat_minutes=0):
        self.threshold = threshold
        self.repeat_minutes = repeat_minutes


class Timeline:
    """Feed a sequence of good/bad and collect what would have been sent."""

    def __init__(self, rule, subject="m1", step_seconds=30):
        self.rule = rule
        self.subject = subject
        self.step = timedelta(seconds=step_seconds)
        self.state = {}
        self.sent = []
        self.moment = START

    def run(self, bad, silenced=(), detail="500"):
        decisions = evaluate(
            self.rule, self.state,
            [Observation(self.subject, bad, detail, "API")],
            self.moment, silenced=silenced)
        for decision in decisions:
            self.state[decision.subject] = decision.state
            if decision.notify:
                self.sent.append((self.moment, decision.notify))
        self.moment += self.step
        return decisions[0]

    def feed(self, pattern, **kwargs):
        for bad in pattern:
            self.run(bad, **kwargs)
        return self

    @property
    def notifications(self):
        return [kind for _, kind in self.sent]


class ThresholdTest(unittest.TestCase):
    def test_one_bad_check_notifies_nobody(self):
        """A blip that fixes itself must not wake anybody."""
        line = Timeline(Rule(threshold=3)).feed([True, False])
        self.assertEqual(line.notifications, [])

    def test_it_fires_on_the_threshold_and_not_before(self):
        line = Timeline(Rule(threshold=3))
        for expected in (None, None, NOTIFY_FIRING):
            self.assertEqual(line.run(True).notify, expected)

    def test_a_threshold_of_one_fires_immediately(self):
        """Somebody who wants that should be able to ask for it."""
        self.assertEqual(Timeline(Rule(threshold=1)).run(True).notify,
                         NOTIFY_FIRING)

    def test_a_good_check_resets_the_count(self):
        """Otherwise the threshold means "three failures ever", and a monitor
        that fails once a day fires on the third day for no reason anybody can
        see."""
        line = Timeline(Rule(threshold=3)).feed([True, True, False, True, True])
        self.assertEqual(line.notifications, [])

    def test_a_zero_threshold_is_treated_as_one(self):
        """Zero would mean "fire before anything has failed"."""
        self.assertEqual(Timeline(Rule(threshold=0)).run(True).notify,
                         NOTIFY_FIRING)


class RepeatTest(unittest.TestCase):
    def test_by_default_it_says_it_once(self):
        """The same sentence every thirty seconds is how a channel gets
        muted, and a muted channel is worse than none because it looks like
        coverage."""
        line = Timeline(Rule(threshold=1, repeat_minutes=0)).feed([True] * 20)
        self.assertEqual(line.notifications, [NOTIFY_FIRING])

    def test_a_repeat_interval_is_honoured(self):
        line = Timeline(Rule(threshold=1, repeat_minutes=5), step_seconds=60)
        line.feed([True] * 12)          # twelve minutes
        self.assertEqual(len(line.notifications), 3)   # 0, 5 and 10 minutes

    def test_a_repeat_does_not_restart_the_clock_early(self):
        line = Timeline(Rule(threshold=1, repeat_minutes=10), step_seconds=60)
        line.feed([True] * 9)
        self.assertEqual(len(line.notifications), 1)


class RecoveryTest(unittest.TestCase):
    def test_a_recovery_is_notified(self):
        """Without it the last message anybody has says it is broken."""
        line = Timeline(Rule(threshold=1)).feed([True, False])
        self.assertEqual(line.notifications, [NOTIFY_FIRING, NOTIFY_RESOLVED])

    def test_recovering_from_ok_notifies_nothing(self):
        """A monitor that was never firing has nothing to recover from."""
        self.assertEqual(Timeline(Rule()).feed([False, False]).notifications, [])

    def test_it_can_fire_again_after_recovering(self):
        line = Timeline(Rule(threshold=1)).feed([True, False, True])
        self.assertEqual(line.notifications,
                         [NOTIFY_FIRING, NOTIFY_RESOLVED, NOTIFY_FIRING])

    def test_the_recovery_carries_how_long_it_was_broken(self):
        line = Timeline(Rule(threshold=1), step_seconds=60)
        line.run(True)
        decision = line.run(False)
        self.assertEqual(decision.since, START)


class SilenceTest(unittest.TestCase):
    def test_a_silence_suppresses_the_notification(self):
        line = Timeline(Rule(threshold=1))
        line.run(True, silenced={"m1"})
        self.assertEqual(line.notifications, [])

    def test_but_not_the_state(self):
        """When the silence ends the thing is still recorded as broken, so the
        recovery still arrives and the history is not a lie."""
        line = Timeline(Rule(threshold=1))
        decision = line.run(True, silenced={"m1"})
        self.assertEqual(decision.state.state, FIRING)

    def test_a_recovery_is_notified_even_while_silenced(self):
        """Somebody silenced the noise of a thing being broken. Leaving them
        believing it still is, is not what they asked for."""
        line = Timeline(Rule(threshold=1))
        line.run(True, silenced={"m1"})
        line.run(False, silenced={"m1"})
        self.assertEqual(line.notifications, [NOTIFY_RESOLVED])

    def test_alerting_resumes_when_the_silence_ends(self):
        """The failure that fires afterwards is a NEW transition; a state
        machine that thinks it already fired stays quiet for ever."""
        line = Timeline(Rule(threshold=1))
        line.run(True, silenced={"m1"})
        line.run(False, silenced={"m1"})   # resolved, silenced
        line.run(True)                     # silence over
        self.assertEqual(line.notifications, [NOTIFY_RESOLVED, NOTIFY_FIRING])

    def test_a_star_silences_everything(self):
        line = Timeline(Rule(threshold=1))
        line.run(True, silenced={"*"})
        self.assertEqual(line.notifications, [])


class SubjectTest(unittest.TestCase):
    def _evaluate(self, previous, observations, silenced=()):
        return {d.subject: d for d in evaluate(
            Rule(threshold=1), previous, observations, START,
            silenced=silenced)}

    def test_subjects_are_independent(self):
        """One rule watching fifty monitors fires fifty times, not once for
        "something is wrong"."""
        decisions = self._evaluate({}, [Observation("a", True),
                                        Observation("b", False)])
        self.assertEqual(decisions["a"].notify, NOTIFY_FIRING)
        self.assertIsNone(decisions["b"].notify)

    def test_a_subject_that_disappears_while_firing_is_resolved(self):
        """A monitor deleted while down would otherwise stay firing for ever,
        and a rule complaining about something that no longer exists cannot be
        silenced except by deleting the rule."""
        previous = {"gone": State(state=FIRING, failures=5, since=START)}
        decisions = self._evaluate(previous, [Observation("a", False)])
        self.assertEqual(decisions["gone"].notify, NOTIFY_RESOLVED)
        self.assertIn("no longer", decisions["gone"].detail)

    def test_a_subject_that_disappears_while_ok_says_nothing(self):
        previous = {"gone": State(state=OK, failures=1)}
        decisions = self._evaluate(previous, [Observation("a", False)])
        self.assertNotIn("gone", decisions)


class RuleShapeTest(unittest.TestCase):
    """A rule arrives as a stored row or as an object depending on caller."""

    def test_a_mapping_works(self):
        decisions = evaluate({"threshold": 1, "repeat_minutes": 0}, {},
                             [Observation("a", True)], START)
        self.assertEqual(decisions[0].notify, NOTIFY_FIRING)

    def test_a_missing_setting_falls_back(self):
        decisions = evaluate({}, {}, [Observation("a", True)], START)
        self.assertEqual(decisions[0].notify, NOTIFY_FIRING)

    def test_a_null_setting_falls_back_rather_than_crashing(self):
        """A column with no value reads as None, and `int(None)` is a
        traceback in the evaluation loop — which stops every other rule."""
        decisions = evaluate({"threshold": None, "repeat_minutes": None}, {},
                             [Observation("a", True)], START)
        self.assertEqual(decisions[0].notify, NOTIFY_FIRING)


if __name__ == "__main__":
    unittest.main()


class UndeliveredTest(unittest.TestCase):
    """A firing state that was never successfully announced.

    Two ways to reach it, and both are an outage nobody was told about:

      * the webhook was down when it fired. The state says firing, the history
        says delivery failed, and with no repeat interval it would never try
        again.
      * it started firing while silenced, and the silence has now ended.

    The runner records a failed delivery by leaving `last_notified_at` unset,
    so both cases look the same to the state machine — which is the point.
    """

    def test_it_retries_when_nothing_was_ever_delivered(self):
        previous = {"m1": State(state=FIRING, failures=5, since=START,
                                last_notified_at=None)}
        decisions = evaluate(Rule(threshold=1, repeat_minutes=0), previous,
                             [Observation("m1", True)], START)
        self.assertEqual(decisions[0].notify, NOTIFY_FIRING)

    def test_a_delivered_one_stays_quiet(self):
        previous = {"m1": State(state=FIRING, failures=5, since=START,
                                last_notified_at=START)}
        decisions = evaluate(Rule(threshold=1, repeat_minutes=0), previous,
                             [Observation("m1", True)], START + timedelta(hours=1))
        self.assertIsNone(decisions[0].notify)

    def test_a_silence_still_holds_it_back(self):
        """The retry must not be a way around a silence."""
        previous = {"m1": State(state=FIRING, failures=5, since=START,
                                last_notified_at=None)}
        decisions = evaluate(Rule(threshold=1), previous,
                             [Observation("m1", True)], START,
                             silenced={"m1"})
        self.assertIsNone(decisions[0].notify)
