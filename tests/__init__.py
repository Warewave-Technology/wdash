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
#: rather than tuning it: empty means "off" for two of them, and the other
#: three redirect storage somewhere a test would then quietly write to.
NEUTRALISED = (
    "WDASH_ENCRYPTION_KEY",     # set: secrets can be stored
    "TRACE_INDEX_PATTERNS",     # empty: no environment trace source
    "ELASTICSEARCH_URL",        # empty: no Elasticsearch at all
    "DASHBOARD_STORAGE",        # database vs file: a different store entirely
    "DASHBOARD_STORAGE_FILE",   # writes into somebody's real data directory
    "DATABASE_URL",             # same, for the metadata store
)

for _variable in NEUTRALISED:
    os.environ.pop(_variable, None)

# And the same values arriving through a file rather than a shell.
#
# `wdash.config` calls `load_dotenv()` at import, which puts the developer's
# `.env` into the process environment and computes `Config` from it — after
# the pops above, undoing every one of them. CI has no `.env`; a developer
# does. Set here, before anything from the package is imported, because this
# module is the first thing the discovery loader touches.
os.environ["WDASH_NO_DOTENV"] = "1"
