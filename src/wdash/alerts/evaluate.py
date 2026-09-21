"""
The alert state machine.

A PURE function: `(rule, stored state, observations, now) -> decisions`. No
database, no clock of its own, no network. That is deliberate, because this is
where alerting goes wrong and none of the failures are visible without being
able to drive time by hand:

  * firing on a single bad check, so a monitor that blips at 03:00 wakes
    somebody for a thing that fixed itself
  * never firing again after a recovery, because the counter was not reset
  * repeating the same sentence every fifteen seconds until the channel is
    muted — and a muted channel is worse than none, because it looks like
    coverage
  * losing the recovery, so the last message anybody has says it is broken
  * a silence that ends and never resumes alerting

Every one of those is a sequence of states over time. Tested against a real
scheduler they would each need minutes of waiting; tested here they are a
list.
"""

from datetime import timedelta

#: What a rule can watch. Three, because they are three different facts with
#: three different audiences: a target that stopped answering, a probe that
#: stopped looking, and a diary entry about a certificate.
MONITOR_DOWN = "monitor_down"
AGENT_SILENT = "agent_silent"
CERTIFICATE_EXPIRING = "certificate_expiring"
RULE_KINDS = (MONITOR_DOWN, AGENT_SILENT, CERTIFICATE_EXPIRING)

OK = "ok"
FIRING = "firing"

#: What the evaluator asks the caller to do.
NOTIFY_FIRING = "firing"
NOTIFY_RESOLVED = "resolved"


class Observation:
    """One subject as it stands right now.

    `bad` is the judgement the caller has already made — "this monitor is
    down", "this agent has gone quiet", "this certificate expires inside the
    window". The evaluator does not re-derive it, because what counts as bad
    differs per rule kind and the state machine should not know.

    `known` is whether there is a judgement to make at all. `bad=False` says
    the subject was looked at and was fine; `known=False` says nobody looked,
    which is a third thing and used to be spelled as the second. What that
    cost is written out at the top of `_one`.

    This is `Observed.complete` one subject at a time. That flag says the
    LISTING could not be read; this says one row in a listing that was read
    whole carries no reading. Both exist because a monitoring system's worst
    failure is announcing that something is fine when what happened is that
    it stopped being watched.
    """

    __slots__ = ("subject", "bad", "detail", "label", "known")

    def __init__(self, subject, bad, detail="", label="", known=True):
        self.subject = subject
        self.bad = bool(bad)
        self.detail = detail
        #: Human name, for the message. The subject is an id.
        self.label = label or subject
        self.known = bool(known)

    def __repr__(self):
        return (f"<Observation {self.subject} bad={self.bad}>" if self.known
                else f"<Observation {self.subject} no reading>")


class State:
    """What was stored about one subject last time round."""

    __slots__ = ("state", "failures", "since", "last_notified_at", "detail")

    def __init__(self, state=OK, failures=0, since=None,
                 last_notified_at=None, detail=""):
        self.state = state
        self.failures = failures
        self.since = since
        self.last_notified_at = last_notified_at
        self.detail = detail


class Decision:
    """What the caller should write, and whether to notify.

    Both together, because they must not diverge: writing the state and
    sending the notification are one transition, and a caller that can do the
    first without the second will eventually do exactly that.
    """

    __slots__ = ("subject", "label", "state", "notify", "detail", "since")

    def __init__(self, subject, label, state, notify=None, detail="",
                 since=None):
        self.subject = subject
        self.label = label
        self.state = state
        #: None, "firing" or "resolved".
        self.notify = notify
        self.detail = detail
        self.since = since

    def __repr__(self):
        return (f"<Decision {self.subject} {self.state.state} "
                f"notify={self.notify}>")


def _setting(rule, name, default):
    """A rule is a stored row (a mapping) or an object, depending on caller.

    Written out rather than inlined into a conditional expression: the first
    version mixed `or` and a ternary and its precedence was wrong in a way
    that happened to work for the values being passed.
    """
    if hasattr(rule, "get"):
        value = rule.get(name, default)
    else:
        value = getattr(rule, name, default)
    return default if value is None else value


def evaluate(rule, previous, observations, now, silenced=(), complete=True):
    """Work out what changed. Returns a list of Decision.

    `rule` needs `threshold` and `repeat_minutes`. `previous` maps subject to
    State. `silenced` is the set of subjects under a silence right now.

    `complete` says whether `observations` is the whole picture. False means a
    source could not be read, and then a subject that is absent has not gone
    away — nobody looked. Resolving it would announce a recovery in the middle
    of the outage and throw away the failure count on the way.
    """
    threshold = max(1, int(_setting(rule, "threshold", 1) or 1))
    repeat = int(_setting(rule, "repeat_minutes", 0) or 0)

    decisions = []
    for observation in observations:
        if not observation.known:
            # No reading for this subject. No decision, so the caller writes
            # nothing and sends nothing and everything stored about it stands
            # — the state, the failure count and the detail the alert is
            # carrying. See `_one` for what the alternatives cost.
            #
            # It is still an observation, so the subject is in `seen` below
            # and the disappearance sweep leaves it alone. Dropping it from
            # the list instead would resolve it by the other road.
            continue
        before = previous.get(observation.subject) or State()
        decisions.append(_one(observation, before, threshold, repeat, now,
                              observation.subject in silenced
                              or "*" in silenced))

    # Subjects that were firing and have DISAPPEARED — a monitor deleted while
    # it was down, an agent removed. Resolved rather than left firing for
    # ever: the thing being complained about no longer exists, and a rule that
    # keeps complaining about it is one nobody can silence except by deleting
    # the rule.
    #
    # Only from a listing that is COMPLETE. "Absent" and "not looked at" are
    # the same shape here and opposite facts, and reading the second as the
    # first sent a recovery for a monitor that was still down.
    if complete:
        seen = {o.subject for o in observations}
        for subject, before in previous.items():
            if subject in seen or before.state != FIRING:
                continue
            decisions.append(Decision(
                subject, subject, State(state=OK, failures=0, since=now),
                notify=NOTIFY_RESOLVED,
                detail="no longer being checked", since=before.since))
    return decisions


def _one(observation, before, threshold, repeat, now, is_silenced):
    """Only ever called for an observation that HAS a reading.

    `evaluate` filters the rest out above, and this is where the reason is
    worth writing down, because "not bad" reaching here is how the fault
    happened: a `monitor_down` alert that was firing saw its monitor go
    `unknown` — the agent stopped reporting, the check went overdue — and
    `unknown` is not `down`, so `bad` was False and `_recovered` sent
    "resolved" to Alertmanager while the target was still down. Measured
    end to end against a real runner and a real receiver: pass 1
    `firing | Payments API | could not connect: connection refused`, pass 2
    `resolved | Payments API | agent 'dublin' has not reported since 11:38`,
    and with the probe back and the target still down, pass 3 firing again —
    one outage, three notifications, the middle one a lie.

    The failure count went with it, so the threshold that means "three times
    in a row" restarted. The other direction has been guarded since the rule
    was written (`unknown` never FIRES; a restarting probe must not page
    anybody) and nothing anywhere claimed the asymmetry on purpose.
    """
    if not observation.bad:
        return _recovered(observation, before, now)

    failures = before.failures + 1
    reached = failures >= threshold

    if before.state == FIRING:
        # Already firing. Notify again only if the rule asks for repeats and
        # enough time has passed — otherwise the same sentence arrives every
        # evaluation until somebody mutes the channel.
        #
        # EXCEPT when it has never been notified successfully. That happens
        # two ways and both need saying: the webhook was down when it fired,
        # and it fired while silenced. Without this the first is an outage
        # nobody was ever told about — the state says firing, the history says
        # delivery failed, and with no repeat interval it would never try
        # again.
        notify = None
        if not is_silenced:
            last = before.last_notified_at
            if last is None:
                notify = NOTIFY_FIRING
            elif repeat and (now - last) >= timedelta(minutes=repeat):
                notify = NOTIFY_FIRING
        return Decision(
            observation.subject, observation.label,
            State(state=FIRING, failures=failures, since=before.since or now,
                  last_notified_at=(now if notify else before.last_notified_at),
                  detail=observation.detail),
            notify=notify, detail=observation.detail, since=before.since or now)

    if not reached:
        # Bad, but not for long enough. The count is kept and nothing is sent:
        # this is the whole reason a single blip does not page anybody.
        return Decision(
            observation.subject, observation.label,
            State(state=OK, failures=failures, since=before.since,
                  last_notified_at=before.last_notified_at,
                  detail=observation.detail),
            notify=None, detail=observation.detail)

    # Crossing into firing. A silence suppresses the NOTIFICATION and not the
    # state: when the silence ends the thing is still recorded as broken, so
    # the recovery still arrives and the history is not a lie.
    return Decision(
        observation.subject, observation.label,
        State(state=FIRING, failures=failures, since=now,
              last_notified_at=(None if is_silenced else now),
              detail=observation.detail),
        notify=(None if is_silenced else NOTIFY_FIRING),
        detail=observation.detail, since=now)


def _recovered(observation, before, now):
    if before.state != FIRING:
        # Was fine, still fine. The failure count resets — that is what makes
        # the threshold mean "in a row" rather than "ever".
        return Decision(
            observation.subject, observation.label,
            State(state=OK, failures=0, since=before.since,
                  last_notified_at=before.last_notified_at),
            notify=None)

    # A recovery is ALWAYS notified, silence or not. Somebody silenced the
    # noise of a thing being broken; leaving them believing it still is, is
    # not what they asked for.
    return Decision(
        observation.subject, observation.label,
        State(state=OK, failures=0, since=now, last_notified_at=now),
        notify=NOTIFY_RESOLVED,
        detail=observation.detail or "recovered", since=before.since)
