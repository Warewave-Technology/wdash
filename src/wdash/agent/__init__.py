"""
The WDash check agent.

Runs somewhere a user would be — another region, a branch office, a laptop —
pulls its configuration from WDash, runs the checks on its own schedule, and
pushes the results back. WDash never connects to it, so it works behind NAT
and needs no inbound port.

    python -m wdash.agent --server https://wdash.internal --token <token>

Three properties this is built around, each because losing it makes the whole
thing lie:

**The agent owns the schedule.** WDash schedules nothing, so restarting WDash
misses no check and two WDash replicas do not double every probe.

**Results survive the network.** A check that ran during an outage is the most
valuable check there is, and it is exactly the one that cannot be delivered at
the time. Results go to a spool on disk first and are sent from there.

**A failure to reach WDash is not a failed check.** They are different facts
about different systems, and conflating them turns a flaky uplink into a
false outage.
"""

__all__ = ["Agent", "Spool", "run_check"]

from .checks import run_check
from .runner import Agent
from .spool import Spool
