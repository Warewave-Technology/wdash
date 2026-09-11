"""
The evaluation loop.

Reads through `MonitorSource` rather than the results table, so a rule covers
Heartbeat monitors and WDash's own agent alike — a rule that only saw one of
them would be blind to half the page it is named after.

Runs as its own process. It must evaluate when NOTHING is arriving: retention
could ride on the ingest path because the endpoint that grows the table is the
one that should shrink it, but an agent going completely silent produces no
requests at all, and that is exactly the moment somebody needs telling.
"""

import logging
import threading
from datetime import datetime, timedelta, timezone

from .channels import DeliveryError, payload, send
from .evaluate import (
    AGENT_SILENT, CERTIFICATE_EXPIRING, MONITOR_DOWN, NOTIFY_FIRING,
    Observation, evaluate,
)

logger = logging.getLogger(__name__)

#: How often to evaluate. Thirty seconds: fast enough that a three-failure
#: threshold on a thirty-second monitor fires within a couple of minutes,
#: slow enough not to be a load of its own.
INTERVAL = 30

#: How far back to look for each monitor's current state. Long enough to hold
#: one run of a slow monitor; a monitor on a longer schedule than this looks
#: silent, which is what the agent_silent rule is for.
WINDOW = "1h"


def observe(rule, source, store, window, now):
    """What this rule sees right now, as a list of Observation.

    The judgement — what counts as bad — lives here rather than in the state
    machine, because it differs per rule kind and the state machine should not
    have to know.
    """
    kind = rule.get("kind")
    if kind == AGENT_SILENT:
        return _agents(store, now)

    page = source.monitors(window, _scope()) if source else None
    monitors = list(page.monitors) if page else []
    monitors = [m for m in monitors if _selected(rule, m)]

    if kind == MONITOR_DOWN:
        # `unknown` is NOT down. An agent that stopped reporting says nothing
        # about the target, and paging somebody because a probe restarted is
        # how a channel gets muted. That case has its own rule kind.
        #
        # One observation per monitor: the worst of its rows. The agents'
        # store lists a monitor once per agent, and with both rows keyed on
        # the same subject the later verdict replaced the earlier — down
        # from Dublin and up from Frankfurt counted no failure at all.
        worst = {}
        for m in monitors:
            if m.id not in worst or (m.status == "down"
                                     and worst[m.id].status != "down"):
                worst[m.id] = m
        return [Observation(m.id, m.status == "down",
                            m.error or "the check failed", m.name)
                for m in worst.values()]

    if kind == CERTIFICATE_EXPIRING:
        days = int(rule.get("days_before") or 30)
        out = []
        for monitor in monitors:
            certificate = monitor.certificate
            if certificate is None:
                continue
            remaining = certificate.days_remaining
            if remaining is None:
                continue
            out.append(Observation(
                monitor.id, remaining <= days,
                (f"expired {abs(remaining)} day(s) ago" if certificate.expired
                 else f"expires in {remaining} day(s)"),
                f"{monitor.name} ({certificate.common_name})"))
        return out

    logger.warning(f"rule '{rule.get('name')}' has an unknown kind {kind!r}")
    return []


def _agents(store, now):
    """Agents that have stopped reporting.

    A separate rule kind from monitor_down on purpose: they are different
    facts with different audiences. "The payment API is unreachable" goes to
    whoever owns payments; "the Frankfurt probe is dead" goes to whoever runs
    the probes, and telling the first audience the second thing is how both
    learn to ignore the channel.
    """
    try:
        agents = store.agents.all()
    except Exception as exc:
        logger.error(f"could not list agents: {exc}")
        return []
    return [Observation(
        a["id"], a["enabled"] and a["stale"],
        ("has never reported" if a["last_seen_at"] is None
         else f"last reported {a['last_seen_at']:%H:%M}"),
        a["name"]) for a in agents if a["enabled"]]


def _selected(rule, monitor):
    """Does this rule watch this monitor?

    An empty selector means everything — so a monitor added later is covered
    without anybody remembering to add it, which is the omission nobody
    notices until the outage.
    """
    selector = rule.get("selector") or {}
    if not selector:
        return True
    tags = dict(pair.split("=", 1) for pair in monitor.tags if "=" in pair)
    return all(tags.get(key) == value for key, value in selector.items())


def _scope():
    from ..hub.scope import Scope
    return Scope(principal="alerts", containers=("*",))


class AlertRunner:
    def __init__(self, store, hub, session=None):
        self._store = store
        self._hub = hub
        self._session = session
        self._stop = threading.Event()

    def evaluate_once(self, now=None):
        """One pass over every enabled rule. Returns how many were notified."""
        from ..hub.query import TimeWindow
        now = now or datetime.now(timezone.utc)
        window = TimeWindow.of(WINDOW)
        source = self._hub.monitors(self._hub.ALL_SOURCES) if self._hub else None
        silenced = self._store.silences.active(now)

        sent = 0
        for rule in self._store.rules.all(enabled_only=True):
            try:
                sent += self._one_rule(rule, source, window, now, silenced)
            except Exception as exc:
                # One broken rule must not stop the others. A rule that
                # references a deleted channel, a selector with a bad shape —
                # neither is a reason for every other alert to go quiet.
                logger.exception(f"rule '{rule.get('name')}' failed: {exc}")
        return sent

    def _one_rule(self, rule, source, window, now, silenced):
        observations = observe(rule, source, self._store, window, now)
        previous = self._store.alert_state.load(rule["id"])
        decisions = evaluate(rule, previous, observations, now,
                             silenced=silenced)

        sent = 0
        for decision in decisions:
            if decision.notify:
                delivered, error = self._deliver(rule, decision)
                if not delivered:
                    # Leave `last_notified_at` unset so the next pass tries
                    # again. Otherwise a webhook that was down when the alert
                    # fired means an outage nobody was ever told about.
                    decision.state.last_notified_at = None
                else:
                    sent += 1
                self._store.alert_history.record(
                    rule["id"], decision.subject, decision.notify,
                    decision.detail, delivered=delivered, error=error,
                    label=decision.label)

            self._store.alert_state.save(rule["id"], decision.subject,
                                         decision.state)
            # A resolved subject that no longer exists is forgotten, so the
            # state table does not grow a row per deleted monitor for ever.
            if (decision.state.state == "ok" and decision.state.failures == 0
                    and decision.notify == "resolved"
                    and decision.detail == "no longer being checked"):
                self._store.alert_state.forget(rule["id"], decision.subject)
        return sent

    def _deliver(self, rule, decision):
        channel = self._store.channels.get(rule["channel_id"])
        if channel is None:
            return False, "the channel this rule sends to no longer exists"
        if not channel["enabled"]:
            return False, "the channel is disabled"
        secrets = self._store.channels.credentials(channel["id"])
        body = payload(rule, decision, decision.notify)
        try:
            send(channel, secrets, body, session=self._session)
        except DeliveryError as exc:
            logger.warning(f"alert for {decision.label} was not delivered: {exc}")
            return False, str(exc)
        except Exception as exc:
            logger.exception("unexpected failure delivering an alert")
            return False, f"{type(exc).__name__}: {exc}"
        return True, None

    def run_forever(self, interval=INTERVAL):
        logger.info(f"alert runner starting, evaluating every {interval}s")
        while not self._stop.is_set():
            try:
                self.evaluate_once()
            except Exception:
                logger.exception("an evaluation pass failed entirely")
            # Housekeeping on the same loop: expired silences would otherwise
            # accumulate for ever on a screen people read.
            try:
                self._store.silences.prune()
            except Exception:
                logger.exception("could not prune expired silences")
            self._stop.wait(interval)
        logger.info("alert runner stopping")

    def stop(self):
        self._stop.set()
