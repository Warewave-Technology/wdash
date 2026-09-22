"""
`python -m wdash.demo` — fill an unclaimed installation with something to look at.

    python -m wdash.demo                  # ask for a password, add what answers
    python -m wdash.demo --dry-run        # say what it would do
    python -m wdash.demo --password ...   # for a script; `ps` shows this

`./lab.sh demo` starts five backends and fills them with a day of data. Then
it stops, and everything after it is a sequence somebody follows: claim the
installation, add a source, add another, tick the right signals on each. That
is the difference between trying WDash and reading about it, and it is what
this closes.

What it will not do
-------------------
**It does not sign anybody in, and it does not enrol an authenticator.** The
account it creates is a normal local account: a password, no second factor
yet, and the enrolment page on first sign-in — the same path setup leaves.
A demo that handed over a signed-in administrator would need a bypass in the
one guard this project is most careful about, and a demo that shipped a
database with a known authenticator secret would be a credential in the
repository. Neither is worth a saved click.

**It will not touch an installation somebody has claimed**, unless told to
with `--into-claimed`. The first version of this file said so in these words
and did not do it: it asked `any_exist()`, skipped creating the account when
one was there, and then went on and added five sources anyway. Run against
the demo database by hand it added four — to an installation it had just
said it would not touch.

So the order is now the other way round. An account that exists ends the run
before anything is written, naming the flag; with the flag, the sources are
added and the account is left alone. The account itself is still created
through `users.create_first_admin`, which is the same guard the setup form
uses rather than a second copy of it: it claims a sentinel row in the
transaction that inserts the account, so two of these racing produce one
administrator.

**It adds only backends that answer.** A source that points at nothing shows
as a red row and an empty screen, which is what a broken WDash looks like.
Each address is probed first, the ones that answer are added, and the ones
that did not are named with the command that starts them.
"""

import argparse
import getpass
import logging
import os
import sys

logger = logging.getLogger(__name__)

#: The lab's backends, in the order they are worth looking at.
#:
#: The address of each is read from the same variables `tests/lab.py` reads,
#: so a lab on other ports is one set of exports rather than five flags.
#: `signals` is what the source will serve; `probe` is a path that answers
#: without authentication, because "is this there" must not need a credential
#: the demo does not have.
BACKENDS = (
    ("main-elasticsearch", "elasticsearch",
     ("logs", "traces", "monitors"),
     ("WDASH_LAB_URL", "WDASH_LAB_ES"), "http://localhost:9200", "/",
     "elasticsearch"),
    ("lab-loki", "loki", ("logs",),
     ("WDASH_LAB_LOKI", "WDASH_LAB_LOKI_URL"), "http://localhost:3100",
     "/ready", "loki"),
    ("lab-victorialogs", "victorialogs", ("logs",),
     ("WDASH_LAB_VICTORIALOGS", "WDASH_LAB_VICTORIALOGS_URL"),
     "http://localhost:9428", "/health", "victorialogs"),
    ("lab-tempo", "tempo", ("traces",),
     ("WDASH_LAB_TEMPO", "WDASH_LAB_TEMPO_URL"), "http://localhost:3200",
     "/ready", "tempo"),
    ("lab-jaeger", "jaeger", ("traces",),
     ("WDASH_LAB_JAEGER", "WDASH_LAB_JAEGER_URL"), "http://localhost:16686",
     "/api/services", "jaeger"),
)

#: How long to wait for a backend to say it is there. Short on purpose: this
#: is "is something listening", not "is it healthy", and a demo that pauses
#: five seconds per absent backend spends half a minute saying nothing.
PROBE_TIMEOUT = 3


def address(names, default):
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


def answers(url, path):
    """Is something serving at this address?

    A status code at all, rather than a 2xx: an Elasticsearch with security
    on answers `/` with 401, and that is a backend that is THERE and needs a
    credential — which is a different sentence from "nothing is listening",
    and the one worth telling somebody.
    """
    import requests
    try:
        requests.get(f"{url.rstrip('/')}{path}", timeout=PROBE_TIMEOUT)
        return True
    except Exception:
        return False


def config_for(kind, url):
    """The stored configuration for a lab backend of this kind.

    Every pattern field is left empty, which is what the page tells somebody
    to do and what `./lab.sh targets` prints: the defaults are the lab's, the
    seed writes `service_name` for Loki and `service` for VictoriaLogs, and a
    pattern typed here would be a second place for those to be written down.
    """
    return {"url": url, "verify_certs": False}


#: Where the lab publishes its six synthetic targets. The ports are fixed in
#: `lab/docker-compose.yml`; only the host moves, and only for somebody
#: running the lab elsewhere.
TARGETS_HOST = os.environ.get("WDASH_LAB_TARGETS", "localhost")

#: The six, and what each one is FOR. `lab/synthetics/nginx.conf` says it
#: first and says it better: "a monitoring page that only ever shows green
#: proves nothing". So the demo takes all six rather than the two that look
#: tidy — the 500 is how a `monitor_down` rule has anything to fire on, and
#: the twelve-day certificate is how a `certificate_expiring` rule does.
#:
#: `labels` are what an alert rule's selector matches, so they are the join
#: between the monitors here and the rules below.
def _monitors(host):
    return (
        {"name": "lab up", "kind": "http", "target": f"http://{host}:18080/",
         "assertions": {"status": [200]},
         "labels": {"lab": "yes", "expect": "up"}},
        {"name": "lab down", "kind": "http", "target": f"http://{host}:18081/",
         "assertions": {"status": [200]},
         "labels": {"lab": "yes", "expect": "down"}},
        {"name": "lab echo", "kind": "http",
         "target": f"http://{host}:18082/echo",
         "assertions": {"status": [200]},
         "labels": {"lab": "yes", "expect": "up"}},
        {"name": "lab port", "kind": "tcp", "target": f"{host}:18080",
         "labels": {"lab": "yes", "expect": "up"}},
        # Self-signed, so verifying against the public roots would fail for a
        # reason that says nothing about the certificate's dates. Expiry-only
        # is the setting these two exist to demonstrate, and WDash withholds
        # a check's headers and credentials before an expiry-only check
        # reaches any agent.
        {"name": "lab TLS, healthy", "kind": "http",
         "target": f"https://{host}:18443/", "tls": {"mode": "expiry_only"},
         "labels": {"lab": "yes", "expect": "up"}},
        {"name": "lab TLS, expiring", "kind": "http",
         "target": f"https://{host}:18444/", "tls": {"mode": "expiry_only"},
         "labels": {"lab": "yes", "expect": "expiring"}},
    )


#: A sign-in and a dashboard, against the two pages `lab/synthetics/journey`
#: serves. Nine verbs and no script — the failure names the step, which is
#: the whole argument for the step list.
def _journey(host):
    return (
        {"kind": "goto", "value": f"http://{host}:18083/"},
        {"kind": "fill", "selector": "#email", "value": "demo@lab.local"},
        {"kind": "fill", "selector": "#password", "value": "hunter2"},
        {"kind": "click", "selector": "#signin button"},
        {"kind": "expect_text", "value": "Signed in"},
        {"kind": "expect_selector", "selector": "#basket"},
    )


def look():
    """Which backends are there, which are not. Asks no database."""
    present, missing = [], []
    for name, kind, signals, variables, default, probe, target in BACKENDS:
        url = address(variables, default)
        (present if answers(url, probe) else missing).append(
            {"name": name, "kind": kind, "signals": list(signals),
             "url": url, "target": target})
    return present, missing


def _say_what_is_missing(missing, out):
    if not missing:
        return
    targets = " ".join(sorted({one["target"] for one in missing}))
    print("\nNot added, because nothing answered at:", file=out)
    for one in missing:
        print(f"  {one['name']:<20} {one['url']}", file=out)
    print(f"\n  cd lab && ./lab.sh up {targets} && ./lab.sh seed {targets}",
          file=out)
    print("  then run this again — it adds what is missing.", file=out)


class AlreadyClaimed(RuntimeError):
    """Somebody has an account here, so this is not an empty installation."""


def fill(store, username, password, present, out=sys.stdout,
         into_claimed=False):
    """Claim the installation and add the sources. Returns what it created.

    Raises `AlreadyClaimed` BEFORE writing anything when an account exists
    and `into_claimed` is not set. Before, and not alongside: the check used
    to be a branch that skipped the account and carried on to the sources,
    which is how a command that promised to leave a claimed installation
    alone wrote five rows into one.
    """
    if store.users.any_exist() and not into_claimed:
        raise AlreadyClaimed(
            "This installation already has an account, so it is somebody's "
            "rather than empty.")

    created = {"account": None, "sources": []}

    if not store.users.any_exist():
        store.users.create_first_admin(username, password, role="admin")
        created["account"] = username
        print(f"Created the administrator '{username}'.", file=out)
    else:
        print("An account already exists; adding sources only.", file=out)

    existing = {source["name"] for source in store.sources.all()}
    for one in present:
        if one["name"] in existing:
            print(f"  {one['name']:<20} already configured", file=out)
            continue
        store.sources.create(
            name=one["name"], signal=one["signals"], kind=one["kind"],
            config=config_for(one["kind"], one["url"]))
        created["sources"].append(one["name"])
        print(f"  {one['name']:<20} {one['url']}  "
              f"({', '.join(one['signals'])})", file=out)
    return created


def add_checks(store, username, host=None, out=sys.stdout):
    """An agent, six monitors and a journey. Returns what it created.

    The agent's token is returned and printed, once, because that is the
    only time it exists in readable form — the store keeps a SHA-256 of it.
    A demo that created an agent and swallowed its token would leave six
    monitors that nothing can ever run, which reads as WDash not working.
    """
    host = host or TARGETS_HOST
    created = {"agent": None, "token": None, "monitors": [], "journey": None}

    named = {agent["name"] for agent in store.agents.all()}
    if "lab agent" in named:
        agent = next(a for a in store.agents.all() if a["name"] == "lab agent")
        print("  lab agent            already registered, token unchanged",
              file=out)
    else:
        agent, token = store.agents.create("lab agent", labels={"lab": "yes"})
        created["agent"], created["token"] = agent["name"], token
        print(f"  lab agent            registered", file=out)

    existing = {monitor["name"] for monitor in store.monitors.all()}
    for definition in _monitors(host):
        if definition["name"] in existing:
            print(f"  {definition['name']:<20} already configured", file=out)
            continue
        store.monitors.create(
            agent_ids=[agent["id"]], created_by=username,
            interval_seconds=60, timeout_seconds=10, **definition)
        created["monitors"].append(definition["name"])
        print(f"  {definition['name']:<20} {definition['target']}", file=out)

    if "lab journey" not in existing:
        store.monitors.create(
            name="lab journey", kind="browser", target="",
            steps=list(_journey(host)), agent_ids=[agent["id"]],
            created_by=username, interval_seconds=300, timeout_seconds=60,
            labels={"lab": "yes", "expect": "browser"})
        created["journey"] = "lab journey"
        print(f"  lab journey          six steps through "
              f"http://{host}:18083/", file=out)
    return created


def add_boards(store, username, out=sys.stdout):
    """A dashboard and a saved search, so neither screen opens empty."""
    created = {"dashboards": [], "searches": []}

    names = {board.name for board in store.dashboards.get_all_dashboards()}
    if "The lab" not in names:
        store.dashboards.create_dashboard(
            name="The lab", created_by=username,
            description="Everything the lab holds, over every source that "
                        "answered. Unpinned on purpose: the stat cards name "
                        "which source gave what.",
            query="*", panels=[
                {"type": "timeseries", "title": "Volume, split by severity",
                 "split_by": "severity", "width": 12},
                {"type": "terms", "title": "Busiest services",
                 "field": "service", "size": 10, "width": 6},
                {"type": "count", "title": "Errors", "field": "severity",
                 "value": "ERROR", "width": 3},
                {"type": "alerts_undelivered", "title": "Alerts nobody got",
                 "width": 3},
                {"type": "monitors", "title": "Checks", "view": "status",
                 "width": 6},
                {"type": "monitor_certificates", "title": "Certificates",
                 "width": 6},
                {"type": "trace_services", "title": "Services by traffic",
                 "size": 10, "sort": "spans", "width": 6},
                {"type": "records", "title": "Newest records", "size": 10,
                 "width": 6},
            ])
        created["dashboards"].append("The lab")
        print("  The lab              eight panels over four signals",
              file=out)

    saved = {search.name for search in store.saved_searches.all_for(username)}
    if "Errors, everywhere" not in saved:
        store.saved_searches.create(
            name="Errors, everywhere", query="level:ERROR",
            time_range="24h", created_by=username)
        created["searches"].append("Errors, everywhere")
        print("  Errors, everywhere   level:ERROR over 24 hours", file=out)
    return created


def add_alerting(store, username, host=None, out=sys.stdout):
    """A channel and two rules, each with something real to fire on.

    The channel points at the lab's echo target, which answers 200. A demo
    whose every alert failed to deliver would be demonstrating the delivery
    failure rather than the alert — and `lab/synthetics/nginx.conf` ships an
    endpoint that exists precisely to be sent things.
    """
    host = host or TARGETS_HOST
    created = {"channels": [], "rules": []}

    channels = {channel["name"]: channel for channel in store.channels.all()}
    if "lab echo" in channels:
        channel = channels["lab echo"]
    else:
        channel = store.channels.create(
            name="lab echo", kind="webhook",
            url=f"http://{host}:18082/echo")
        created["channels"].append("lab echo")
        print(f"  lab echo             http://{host}:18082/echo", file=out)

    named = {rule["name"] for rule in store.rules.all()}
    wanted = (
        {"name": "A lab check is down", "kind": "monitor_down",
         "threshold": 2, "selector": {"lab": "yes"}},
        {"name": "A lab certificate is nearly gone",
         "kind": "certificate_expiring", "days_before": 30,
         "selector": {"lab": "yes"}},
        {"name": "The lab agent went quiet", "kind": "agent_silent",
         "selector": {"lab": "yes"}},
    )
    for rule in wanted:
        if rule["name"] in named:
            continue
        store.rules.create(channel_id=channel["id"], created_by=username,
                           **rule)
        created["rules"].append(rule["name"])
        print(f"  {rule['name']}", file=out)
    return created


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m wdash.demo",
        description="Fill an unclaimed WDash with the lab, ready to look at.")
    parser.add_argument("--database-url",
                        default=os.environ.get("DATABASE_URL"),
                        help="the metadata store to fill; DATABASE_URL "
                             "otherwise")
    parser.add_argument("--username", default="demo",
                        help="the administrator to create (default: demo)")
    parser.add_argument("--password",
                        help="for scripted use; prompts otherwise, because "
                             "an argument is visible in `ps`")
    parser.add_argument("--dry-run", action="store_true",
                        help="say what it would do and write nothing")
    parser.add_argument("--into-claimed", action="store_true",
                        help="add the sources to an installation that "
                             "already has an account, leaving the account "
                             "alone. Without this, one is a refusal")
    parser.add_argument("--targets-host", default=TARGETS_HOST,
                        help="where the lab publishes its six synthetic "
                             "targets; WDASH_LAB_TARGETS otherwise")
    arguments = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)s %(message)s")

    from wdash.store import Store
    from wdash.store.users import SetupClosed

    present, missing = look()

    if arguments.dry_run:
        # Deliberately without opening the store. `Store.open` MIGRATES, and
        # against a path that does not exist yet that means creating the file
        # and writing a schema into it — which a run that says it writes
        # nothing must not do, however harmless the file would be.
        print(f"Store: {arguments.database_url or '$DATABASE_URL'} "
              f"(not opened — a dry run writes nothing, and opening it "
              f"migrates)\n")
        print("Would add:" if present else "Would add nothing.")
        for one in present:
            print(f"  {one['name']:<20} {one['url']}  "
                  f"({', '.join(one['signals'])})")
        print("\nAlready-configured sources are not subtracted here, for the "
              "same reason.")
        _say_what_is_missing(missing, sys.stdout)
        return 0

    if not present:
        print("No lab backend answered, so there is nothing to look at yet.",
              file=sys.stderr)
        _say_what_is_missing(missing, sys.stderr)
        return 1

    # `Store.open` migrates, which is also what gives a database nobody has
    # opened yet its roles — migration 19. A demo that skipped it would
    # create an administrator holding a role that does not exist.
    store = Store.open(arguments.database_url)
    print(f"Store: {store.describe()}\n")

    password = arguments.password
    if password is None and not store.users.any_exist():
        password = getpass.getpass(
            f"A password for '{arguments.username}' (12 characters or more): ")

    try:
        fill(store, arguments.username, password, present,
             into_claimed=arguments.into_claimed)
        print("\nChecks:")
        checks = add_checks(store, arguments.username, arguments.targets_host)
        print("\nScreens:")
        add_boards(store, arguments.username)
        print("\nAlerting:")
        add_alerting(store, arguments.username, arguments.targets_host)
    except AlreadyClaimed as exc:
        print(f"\n{exc}", file=sys.stderr)
        print("Nothing was written. Point --database-url at an empty "
              "installation, or pass --into-claimed to add the lab's sources "
              "to this one and leave its account alone.", file=sys.stderr)
        return 1
    except SetupClosed as exc:
        # The race rather than the check above: another process claimed the
        # installation between `any_exist` and the insert.
        print(f"\n{exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 1

    _say_what_is_missing(missing, sys.stdout)

    if checks.get("token"):
        print(f"""
Run the agent, or every check stays `unknown` — which is what WDash says
when nobody has looked, and is not the same answer as `down`:

    WDASH_AGENT_TOKEN={checks['token']} \\
        python -m wdash.agent --server http://127.0.0.1:5001

That token is printed once because only its SHA-256 is stored. The journey
needs the browser image — `docker build --target browser .` — and reads
`unknown` until one reports, which is the same sentence for the same
reason.""")

    print("\nAnd the evaluator, for the two rules to have anything to say:"
          "\n\n    python -m wdash.alerts")
    print("\nNow sign in. The first sign-in asks for an authenticator, which "
          "is\nwhat every local account does — this one is no exception.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
