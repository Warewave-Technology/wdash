# Contributing

Two things about this repository are unusual enough to say before anything
else, because they will fail a pull request that is otherwise fine.

**1. A dependency has to pass a licence rule.** No proprietary or
source-available work — SSPL, the Elastic Licence, BUSL, anything commercial.
Copyleft is not banned: `ldap3` and `psycopg` are LGPL v3, used as libraries
over their published interfaces, which is what the LGPL is for. Speaking HTTP
to an AGPL server, as WDash does to Loki and Tempo, binds nothing.
`tests/test_dependency_licences.py` enforces it, and it reads the Dockerfile
as well as `requirements.txt` — a dependency added to a build stage is still
in a published image.

**2. A dependency also has to be used.** The same file fails on anything
declared and imported nowhere. `redis` sat in every published image for the
life of the project, with a 165-line Kubernetes manifest, for something no
line of code ever read. If a dependency genuinely cannot be imported —
`gunicorn` runs the process, `psycopg` is loaded by SQLAlchemy from a URL
scheme — say so in the list, with the reason.

## Running things

```bash
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
npm ci                                    # for the front-end suites

./venv/bin/python -m tests.run            # on every core; the quick way
./venv/bin/python -m unittest discover -s tests -t .   # one after another, as CI does
npm test
```

On Postgres as well, for anything that touches the store: `./lab.sh up
postgres`, then the same command with
`WDASH_TEST_POSTGRES=postgresql://wdash:wdash-lab@localhost:55432/wdash`.
A test about SQLite itself says so with `sqlite_only` from
`tests/postgres_store.py`, and skips there.

Python 3.11 or newer. Node is needed because part of the Python suite shells
out to it — without node those checks skip themselves and say nothing.

The lab gives you real backends rather than mocks:

```bash
cd lab && ./lab.sh up && ./lab.sh seed
```

Some tests only run when something real is there — a browser, a cluster —
and they name what is missing when they skip. CI closes all of them; see
[.github/workflows/tests.yml](.github/workflows/tests.yml).

**Seed it, and seed it again.** The lab-backed tests ask about the last
twenty-four hours, because that is the window every screen opens on, so a
lab left running for a week holds plenty and answers nothing. They skip
rather than fail there, and the skip names the command — `./lab.sh seed
<target>`. `./lab.sh targets` says what each backend holds right now.
`tests/lab.py` is the guard; `WDASH_REQUIRE_LAB=1` turns those skips into
failures, which is what CI sets, because a job that promised a lab must not
keep the promise by skipping.

## What a change is expected to come with

### A test that would have failed before it

Not coverage. The suite is largely a record of specific mistakes, and each
test says which one in its docstring. That is the format: what went wrong,
why nothing caught it, and what this now catches.

### Evidence that the test can fail

The habit here is to break the code on purpose and check the test notices —
change the condition, delete the line, invert the comparison. It is
surprisingly often that a test passes for a reason unrelated to what it
claims. Several tests in this repository were found that way *after* being
written, and their docstrings say so.

Two traps worth knowing:

* a test that skips is a test that passed. Anything that can skip should
  say why, and where a job exists to run it, it should fail instead;
* Python caches bytecode by `(mtime, size)`. Restoring a same-length edit can
  leave the mutant running, so purge `__pycache__` between steps or you will
  get a confident wrong answer.

### Measurement rather than recollection

Numbers in this repository are measured: image sizes, contrast ratios, the
row count where SQLite stops being quick, the shape of an Elasticsearch
document. Document shapes especially — the browser-journey adapter was held
back for a phase because guessing one produces a screen that looks complete
and is wrong. If you cannot measure it, say that instead.

## Guards you will meet

They are not style rules; each exists because something went wrong once.

| Guard | It fails when |
|---|---|
| `test_contrast.py` | a colour is written outside the palette, a template names a theme, or any theme's text falls below WCAG AA |
| `test_dependency_licences.py` | a dependency arrives under an unreviewed licence, or is declared and never imported |
| `test_version.py` | the version in the package, `package.json`, the lockfile or the Kubernetes manifests disagree |
| `test_release_files.py` | the changelog has no entry for the version being shipped, the third-party notices are stale, or `RELEASING.md` names a command that is not there |
| `test_csrf.py` | a state-changing route or a POST form escapes the CSRF check |
| `test_lab_targets.py` | `lab.sh` and the compose file stop describing the same lab |
| `test_lab_data.py` | the lab-backed tests would measure an empty backend, or a job that promised a lab keeps the promise by skipping |
| `test_first_run.py` | `docker compose up` or `cp .env.example .env` stops giving a running WDash |
| `test_ci.py` | the workflow stops running what it claims, or the Python matrix and the packaging classifiers drift apart |
| `test_no_elasticsearch.py` | the suite can reach a cluster or a database nobody declared |
| `test_frontend_integrity.py` | `wdash.min.js` is stale, a bundle references a method that does not exist, or a static asset is asked for without a version |
| `test_kubernetes_manifests.py` | the shipped manifests stop describing this application — a setting that never reaches the process, a mount of a volume the pod does not declare, a workload that does not exist |

If one of them blocks something reasonable, that is worth a conversation
rather than an exemption — but every exemption list in this repository
carries a reason per entry, and a test that fails when an exemption outlives
the thing it excused.

## Style

Match the file you are in. The prose in comments and docstrings is doing real
work here: it records *why*, and the why is usually a fault that is no longer
visible in the code. A comment restating the code is worse than none; a
comment explaining a decision somebody would otherwise undo is the point.

Commit messages are written the same way — what changed, what it fixes, and
what was measured to know it works.

## Reporting a vulnerability

Not here. See [SECURITY.md](SECURITY.md).
