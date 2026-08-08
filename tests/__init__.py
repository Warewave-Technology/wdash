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
#   * with `TRACE_INDEX_PATTERNS` exported empty — which is how the lab now
#     says "no environment trace source" — 127 tests failed, because the
#     application under test had no trace source at all
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
#: whole of the distinction, and getting it wrong is invisible:
#: `ELASTICSEARCH_URL` was on this list, was faithfully removed, and
#: `Config` then fell back to `http://localhost:9200` — which is the lab's own
#: address. Fourteen tests had been talking to a real cluster for as long as
#: anybody had one running, and said so only by failing on the day it was
#: switched off. The guard for this list checked that the NAME was absent,
#: which was true and meant nothing.
NEUTRALISED = (
    "WDASH_ENCRYPTION_KEY",     # set: secrets can be stored. Default: unset.
    "TRACE_INDEX_PATTERNS",     # empty: no environment trace source. Default:
                                # a list of index names, inert without a
                                # cluster to look them up in.
    "DASHBOARD_STORAGE",        # database vs file: a different store entirely
    "DASHBOARD_STORAGE_FILE",   # writes into somebody's real data directory
    # DATABASE_URL has the same flaw as ELASTICSEARCH_URL and is NOT fixed
    # here: its default is `sqlite:///data/wdash.db`, the developer's own
    # database. Forcing it at a path that does not exist breaks 414 tests,
    # because a great many of them reach Config before they build their own
    # app. That is a real hazard and a separate piece of work; it is written
    # down rather than left to be rediscovered.
    "DATABASE_URL",
)

#: Forced to a value, because removing them lands on a default that points at
#: something REAL — a cluster, a database — rather than at nothing.
FORCED = {
    # No Elasticsearch. A test that needs one registers a source on its own
    # app, where the dependency is visible and does not vary by what happens
    # to be listening on 9200.
    "ELASTICSEARCH_URL": "",
}

for _variable in NEUTRALISED:
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
