# Test package for WDash.
#
# The suite must mean the same thing on every machine. `Config` reads its
# defaults from the environment, so a developer who has sourced a deployment's
# variables into their shell runs a different suite from the one CI runs — and
# it fails in a way that reads as flakiness rather than as configuration.
#
# That is not hypothetical, twice over:
#
#   * with `WDASH_ENCRYPTION_KEY` exported, four tests covering "no key is
#     configured, so secrets are refused rather than written as plaintext"
#     quietly got a key and failed
#   * with the trace-index variable of the day exported empty — which is how
#     the lab then said "no environment trace source" — 127 tests failed,
#     because the application under test had no trace source at all
#
# The pattern is the same both times, and so is the fix: a variable whose
# value changes what a test MEANS does not get to arrive by accident.
#
# Anything a test needs, it sets on its own config class, where it is visible.
import os

#: Cleared before any test module is imported. Each of these flips behaviour
#: rather than tuning it.
#:
#: Removing the name is only enough when the DEFAULT is inert. That is the
#: whole of the distinction, and getting it wrong is invisible: the cluster
#: address was once on this list, was faithfully removed, and `Config` then
#: fell back to `http://localhost:9200` — which is the lab's own address.
#: Fourteen tests had been talking to a real cluster for as long as anybody
#: had one running, and said so only by failing on the day it was switched
#: off. The guard for this list checked that the NAME was absent, which was
#: true and meant nothing.
NEUTRALISED = (
    "WDASH_ENCRYPTION_KEY",     # set: secrets can be stored. Default: unset.
    "DASHBOARD_STORAGE",        # database vs file: a different store entirely
    "DASHBOARD_STORAGE_FILE",   # see PROTECTED_BY_THE_APP
)

#: Cleared too, for the opposite reason: nothing reads them. The application
#: looks at these only to say, as an ERROR at start-up, that they are set and
#: no longer configure anything (`RETIRED_VARIABLES` in wdash/app.py, which
#: tests/test_retired_variables.py holds to this list). Removing the name IS
#: enough here — there is no default to land on — and without it a developer
#: whose shell still exports a deployment's variables would get that ERROR
#: from every app the suite builds.
RETIRED = (
    "ELASTICSEARCH_URL", "ELASTICSEARCH_USERNAME", "ELASTICSEARCH_PASSWORD",
    "ELASTICSEARCH_TIMEOUT", "ELASTICSEARCH_VERIFY_CERTS",
    "ELASTICSEARCH_CA_CERTS", "TRACE_INDEX_PATTERNS", "MONITOR_INDEX_PATTERNS",
    "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_DISCOVERY_URL",
    "OIDC_REDIRECT_URI", "OIDC_SCOPES", "OIDC_USERNAME_CLAIM",
    "OIDC_EMAIL_CLAIM", "OIDC_GROUPS_CLAIM", "OIDC_TRUST_UNVERIFIED_EMAIL",
)

#: Forced to a value, because removing them lands on a default that points at
#: something REAL — a cluster, a database — rather than at nothing.
FORCED = {
    # No developer database. The default is `sqlite:///data/wdash.db` — local
    # accounts, their password hashes, and every source credential the
    # encryption key protects.
    #
    # `create_app` used to swap that for `:memory:` itself whenever TESTING
    # was set. It worked, and it was in the wrong place twice over: it only
    # covered apps, so anything reading `Config.DATABASE_URL` directly — the
    # alert process, the agent, the two CLIs — still landed on the real file;
    # and it only covered apps whose config REMEMBERED to set TESTING, which
    # is a thing a new test forgets silently and destructively. Forced here,
    # the guarantee holds for the whole process and needs nothing remembered.
    #
    # In-memory rather than a temporary file, because each connection pool
    # gets its own database: apps stay isolated from each other for free,
    # which a single shared path would have undone.
    "DATABASE_URL": "sqlite:///:memory:",
}

#: Points at something real, and is NOT handled here — the application itself
#: refuses it under TESTING. Each entry names the test that proves it, so that
#: deleting the protection fails a test rather than quietly widening this list.
#:
#: This is the only honest alternative to forcing a value, and it is better
#: where isolation has to be per-app rather than per-run: the dashboard file
#: store gets a fresh temporary directory per app, which one forced path would
#: have collapsed back into a single file every app shares.
PROTECTED_BY_THE_APP = {
    "DASHBOARD_STORAGE_FILE":
        "tests.test_dashboard_persistence.IsolationTest",
}

#: Points at something real and is reached by nothing, checked rather than
#: assumed. Listed so the next person does not have to re-derive it. Empty
#: since the redirect URI moved to the OpenID Connect card; the list stays
#: because the guard below reads it.
INERT = {}

def points_at_something_real(value):
    """Would a test reaching this value talk to, or write into, something?

    The judgement the guard in `test_no_elasticsearch` is made of, named so it
    can be tested on its own. The version before it was a regex over the text
    of `config.py`, and it was wrong in two ways that each hid a live value
    for months:

      * it needed a literal default on the line, so
        `os.environ.get(...) or CONSTANT` was invisible;
      * it treated a path as real only if it began with `/`, and
        `data/dashboards.json` — somebody's actual dashboards — does not.

    Relative is not the same as harmless. A relative path is resolved against
    the working directory, and the suite's working directory is the
    repository.
    """
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("sqlite:"):
        # Both an address and a path, and it is the path that matters:
        # `://` alone would call `sqlite:///:memory:` real.
        return os.path.exists(value.split("///", 1)[-1])
    return "://" in value or os.path.exists(value)


for _variable in NEUTRALISED + RETIRED:
    os.environ.pop(_variable, None)

for _variable, _value in FORCED.items():
    os.environ[_variable] = _value

# And the same values arriving through a file rather than a shell.
#
# `wdash.config` calls `load_dotenv()` at import, which puts the developer's
# `.env` into the process environment and computes `Config` from it — after
# the pops above, undoing every one of them. CI has no `.env`; a developer
# does. Set here, before anything from the package is imported, because this
# module is the first thing the discovery loader touches.
os.environ["WDASH_NO_DOTENV"] = "1"

# On Postgres, when asked. Last, because it imports the store, and nothing
# from the package may be imported before the environment above is settled.
if os.environ.get("WDASH_TEST_POSTGRES"):
    from tests import postgres_store
    postgres_store.install()
