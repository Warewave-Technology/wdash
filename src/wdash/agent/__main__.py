"""
`python -m wdash.agent`

The same image as the server, a different entry point: one artifact to build,
scan and version, and it still runs wherever the checks should run from.
"""

import argparse
import logging
import os
import signal
import sys

from .runner import Agent


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m wdash.agent",
        description="Run WDash synthetic checks and report them back.")
    parser.add_argument("--server", default=os.environ.get("WDASH_SERVER"),
                        help="WDash base URL, e.g. https://wdash.internal")
    parser.add_argument("--token", default=os.environ.get("WDASH_AGENT_TOKEN"),
                        help="the agent token; prefer WDASH_AGENT_TOKEN, "
                             "because an argument is visible in `ps`")
    parser.add_argument("--spool", default=os.environ.get(
        "WDASH_AGENT_SPOOL", "agent-spool.jsonl"),
        help="where to hold results that have not been delivered")
    parser.add_argument("--insecure", action="store_true",
                        help="do not verify the server's TLS certificate")
    parser.add_argument("--once", action="store_true",
                        help="run EVERY check once and exit, ignoring the "
                             "schedule; for testing a configuration without "
                             "leaving a daemon behind")
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if arguments.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")

    if not arguments.server or not arguments.token:
        parser.error("both --server and --token are required "
                     "(or WDASH_SERVER and WDASH_AGENT_TOKEN)")

    agent = Agent(arguments.server, arguments.token,
                  spool_path=arguments.spool,
                  verify=not arguments.insecure)

    if arguments.once:
        agent.fetch_config()
        # `force`, because a fresh agent staggers its monitors over the next
        # few seconds. Without it this ran whichever single check happened to
        # be first and reported "1 check" for a configuration of fifty.
        ran = agent.run_due(force=True)
        accepted = agent.flush()
        print(f"ran {ran} check(s), {accepted} accepted, "
              f"{agent.spool.pending()} still spooled")
        return 0

    # SIGTERM is how a container is asked to stop. Without this the loop is
    # killed mid-flight and whatever it had just measured is lost — from a
    # spool that exists precisely so that does not happen.
    for received in (signal.SIGTERM, signal.SIGINT):
        signal.signal(received, lambda *_: agent.stop())

    agent.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
