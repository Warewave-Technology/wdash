"""
`python -m wdash.alerts`

The same image as the server and the agent, a third entry point. A separate
process rather than a thread in the web server, because the evaluation has to
run when nothing is arriving — an agent going completely silent produces no
requests at all, and that is exactly when somebody needs telling.

Run ONE of these. Two would evaluate the same rules and send the same alert
twice; the state table is shared, so the second would usually find the
transition already made, but "usually" is not a guarantee worth relying on.
"""

import argparse
import logging
import signal
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m wdash.alerts",
        description="Evaluate WDash alert rules and deliver notifications.")
    parser.add_argument("--interval", type=int, default=None,
                        help="seconds between evaluations (default 30)")
    parser.add_argument("--once", action="store_true",
                        help="evaluate once and exit; for testing a rule "
                             "without leaving a daemon behind")
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if arguments.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")

    # The whole application, because the runner reads monitors through the hub
    # — which is what makes a rule cover Heartbeat and WDash's own agent
    # alike. Building the sources by hand here would be a second place that
    # has to know how to configure every backend.
    from wdash.alerts.runner import INTERVAL, AlertRunner
    from wdash.app import create_app
    from wdash.config import Config

    app = create_app(Config)
    if getattr(app, "store", None) is None:
        print("No metadata store is configured, so there are no rules to run.",
              file=sys.stderr)
        return 1

    runner = AlertRunner(app.store, app.hub)

    if arguments.once:
        sent = runner.evaluate_once()
        rules = len(app.store.rules.all(enabled_only=True))
        print(f"evaluated {rules} rule(s), sent {sent} notification(s)")
        return 0

    for received in (signal.SIGTERM, signal.SIGINT):
        signal.signal(received, lambda *_: runner.stop())
    runner.run_forever(arguments.interval or INTERVAL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
