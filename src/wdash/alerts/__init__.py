"""
Alerting: something has to say when a monitor goes down.

Until this, somebody had to be looking at the Monitors page — a poor way to
find out about an outage at three in the morning.

Three pieces, deliberately separate:

  * `evaluate.py` is the state machine, a PURE function. Everything that
    makes alerting hard — flapping, repeats, recoveries, silences — is a
    sequence of states over time, and testing that against a real scheduler
    would mean waiting minutes per case.
  * the channels, which deliver.
  * `python -m wdash.alerts`, which drives the loop.

The loop is a separate process rather than a thread in the web server, and
that is not only tidiness: the evaluation must run when NOTHING is arriving.
Retention could ride on the ingest path because the endpoint that grows the
table is the one that should shrink it; alerting cannot, because an agent
going completely silent produces no requests at all — and that is exactly the
moment somebody needs telling.
"""

from .evaluate import (  # noqa: F401
    AGENT_SILENT, CERTIFICATE_EXPIRING, FIRING, MONITOR_DOWN, NOTIFY_FIRING,
    NOTIFY_RESOLVED, OK, RULE_KINDS, Decision, Observation, State, evaluate,
)
