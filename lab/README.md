# WDash Lab

A self-contained development and test environment. It serves two purposes:

1. **Development data** — realistic log and trace documents, multiple index
   patterns (so RBAC can be exercised), multi-line stack traces and JSON
   messages.
2. **Advisor fixtures** — deliberately misconfigured indices. On a clean
   cluster most Advisor rules never fire; these indices let us verify both that
   the rules trigger and that they stay quiet on healthy indices.

## Quick start

```bash
cd lab
./lab.sh up          # Elasticsearch
./lab.sh seed        # ~50k logs, 2k traces
./lab.sh status      # health check
```

To point the application at the lab, add it on the configuration page —
**Configuration → Sources → Add source**: an Elasticsearch at
`http://localhost:9200` serving logs, traces and monitors. The traces are in
`*traces*` and `*apm*` and Heartbeat's checks in `heartbeat-*` and
`synthetics-*`, which are the defaults the form offers. Nothing about a
source is read from `.env`.

## Commands

| Command | Description |
|---|---|
| `./lab.sh up [profile...]` | Start the stack |
| `./lab.sh seed [args]` | Load data into every running backend. Arguments go to `seed.py`; Loki and VictoriaLogs are seeded too when their profiles are up, with different service names so a merged search visibly draws from all three |
| `./lab.sh status` | Cluster health and index list |
| `./lab.sh logs [service]` | Container logs |
| `./lab.sh down` | Stop, keeping data |
| `./lab.sh reset` | Stop and delete all data |

### Profiles

```bash
./lab.sh up kibana            # Kibana on 5601, for comparison
./lab.sh up cluster           # a second data node, for shard/allocation rules
./lab.sh up kibana cluster
```

Both are off by default because they cost memory.

### Seed options

```bash
./lab.sh seed --reset                 # drop existing indices first
./lab.sh seed --logs 200000           # larger volume
./lab.sh seed --days 30               # wider time range
./lab.sh seed --only traces
./lab.sh seed --seed 42               # reproducible data
```

## Generated indices

| Index | Purpose |
|---|---|
| `app-logs-000001` | Correctly configured log index |
| `service-logs-000001` | Same, different pattern (RBAC testing) |
| `infra-logs-000001` | Same, a pattern the `viewer` role cannot reach |
| `bad-logs-000001` | **Advisor fixture** — deliberately broken |
| `otel-traces-000001` | OpenTelemetry semantic conventions schema |
| `apm-traces-000001` | Elastic APM / ECS schema |

Both trace indices carry the *same* traces on purpose: that lets us test the
hub's adapter layer without standing up a second backend. A share of the log
records is linked to real trace ids from that same set, so log-to-trace
correlation can be exercised end to end.

The APM index is deliberately **not** named `traces-apm-*`: Elasticsearch's
built-in `traces-apm@template` owns that pattern and only permits data streams.
What matters for the adapter is the document schema, not the index type.

RBAC works out of the box against the built-in roles — `viewer` sees only
`app-*`, `developer` sees `app-*` and `service-*`, and `infra-*` is admin only.

## Deliberate misconfigurations

These are not mistakes; they are the input for the Advisor rules.

| Where | What | Rule it triggers |
|---|---|---|
| `bad-logs` mapping | `level` mapped as `text` | Aggregated field is not a keyword |
| `bad-logs` mapping | `dynamic: true`, ~600 fields | Mapping explosion / approaching field limit |
| `bad-logs` mapping | `message` as both text and keyword | Redundant double storage |
| `bad-logs` settings | 5 shards on a single node | Oversharding |
| `bad-logs` settings | `replicas: 1` on a single node | Unassignable shard, yellow cluster |
| `bad-logs` settings | `refresh_interval: 1s` | Wrong for a write-heavy index |
| compose | `xpack.security.enabled=false` | Security disabled |
| compose | `bootstrap.memory_lock=false` | Swap risk |
| all indices | No ILM policy | Unbounded growth |

A **yellow** cluster status caused by `bad-logs-000001` is expected: it
represents the unassignable replica shard.

The `level` field being `text` matters especially: a `{"terms": {"field":
"level"}}` aggregation fails on that index. The lab therefore reproduces a real
failure mode rather than just describing it.

## Licence note

Compose sets `xpack.license.self_generated.type=basic`, which stops a trial
licence activating itself. That way we never accidentally build a dependency on
Platinum features such as document- or field-level security — all RBAC has to
stay in the application layer.

## Synthetic targets

`./lab.sh up synthetics` starts nginx with six endpoints, each of which exists
to produce a specific document. A monitoring page that only ever shows green
proves nothing.

| Port | What it is |
|------|------------|
| 18080 | a plain 200 |
| 18081 | a 500, so `monitor.status: down` and `error.*` appear |
| 18082 | echoes headers, cookies and auth back as JSON |
| 18083 | a sign-in form and a dashboard, for browser journeys |
| 18443 | TLS with a certificate valid for a year |
| 18444 | TLS with a certificate valid for twelve days |

The expiring certificate is the point of a TLS monitor: waiting a year to see
the warning is not a test.

The journey site on 18083 is static, and the "authentication" happens in the
page — `hunter2` signs in, anything else stays on the form and shows the error
banner. That is enough, because a journey drives a BROWSER: what it has to
exercise is a form, a submit, a navigation, and a page that says something
different afterwards. A real session would add a backend to the lab and prove
nothing extra about the thing under test.

A journey against it needs an agent with a browser:

```bash
docker build -t wdash-browser --target browser ..
docker run --rm --add-host=host.docker.internal:host-gateway wdash-browser \
    --server http://host.docker.internal:5000 --token <the agent token>
```

Heartbeat drives the same two pages as well — `lab-journey-up` signs in and
adds to the basket, `lab-journey-down` uses the wrong password and fails at
its second step. They are what the ELASTIC side of browser monitoring was
measured against, and they write somewhere the HTTP monitors do not:

```
synthetics-browser-default              journey and step documents
synthetics-browser.network-default      one per request the page made
synthetics-browser.screenshot-default   screenshots, in pieces — see below
```

### How a screenshot is stored, measured

Elastic does not store a screenshot. `tests/test_synthetics_lab.py` asks this
lab the question and holds the answer:

* one `step/screenshot_ref` per step, carrying the size of the picture and a
  list of **blocks** — 64 of them for 1280x720, each 160x90, each named by a
  content **hash** and placed by `top`/`left`;
* one `screenshot/block` per distinct hash, whose `_id` IS the hash and whose
  `synthetics.blob` is a base64 JPEG of that tile.

Three things follow, and all three shaped the code that reads them:

* **Blocks are shared.** In this lab 125 references pointed at 30 stored
  blocks, and a screenshot taken this morning was built almost entirely out
  of blocks written two days earlier by different runs of a *different*
  monitor. So they are looked up by hash, never by check group.
* **Whatever prunes the data stream punches holes in newer screenshots.**
  WDash counts the missing tiles and says so, rather than drawing the gap and
  letting somebody read it as a blank part of the page.
* **A skipped step has no screenshot at all.** It writes a `step/end`
  document like every other step, and nothing else — the step never ran, so
  there was nothing on screen. WDash offers no camera button for one.

Two things about running them, both learned the hard way:

* **Heartbeat must not run as root.** It refuses a browser monitor with
  "script monitors cannot be run as root" — and refuses it per monitor, so
  the HTTP checks carry on and the journeys report `down` with a zero
  duration. The compose service therefore runs as `heartbeat`.
* **The browser is in the image already.** `docker.elastic.co/beats/heartbeat`
  ships `@elastic/synthetics` and its own Chromium, which is most of why it is
  2.58GB.

## Identity

`./lab.sh up identity` starts a directory and an OIDC provider in front of it,
so both of WDash's sign-in paths can be exercised against something real
rather than mocked.

| | |
|---|---|
| OpenLDAP | `ldap://localhost:1389`, base `dc=lab,dc=local` |
| Dex | `http://localhost:5556/dex` |

Four people, all with the password `hunter2`:

| Who | Group | Role they land on |
|---|---|---|
| `alice` | `wdash-admins` | admin |
| `bob` | `wdash-developers` | developer |
| `carol` | `wdash-viewers` | viewer |
| `dave` | none | the default role |

Dave is there on purpose. What a directory returns for somebody who
authenticates and is entitled to nothing is a different path through the code
from a refused password, and it is the one that tends to be wrong.

Point WDash at both, on the configuration page under **Authentication** —
the only place a directory is configured:

```
# The LDAP card
Server            ldap://localhost:1389
Base DN           dc=lab,dc=local
Bind DN           cn=admin,dc=lab,dc=local
Bind password     hunter2

# The OpenID Connect card
Discovery URL     http://localhost:5556/dex/.well-known/openid-configuration
Client ID         wdash
Client secret     wdash-lab-secret
Redirect URI      http://127.0.0.1:5001/auth/callback  (or blank: it is
                  derived from the address the browser used)
```

Dex reads the same directory rather than carrying its own users, which is
what a real deployment does and is also the only way it can issue a `groups`
claim at all — its static passwords cannot. So the lab has one source of
identity truth and two paths to it: alice through LDAP and alice through OIDC
should reach the same role, and if they do not, one of the two paths is
wrong.

**WDash itself uses one of those paths at a time.** Both cards can be saved
— that is what makes the lab useful for testing the rule — but only one
signs people in: enabling the second is refused, and with both enabled the
card saved most recently is in force and the other is shadowed, reported in
the log, in an audit row and on `/admin/config`. To try the other path,
turn the first off on the page and save, then enable the other, or run
`python -m wdash.store.recover --use-directory oidc`.

And measured here: this Dex sends no `preferred_username`, so alice arrives as
`alice` through LDAP and as `alice@lab.local` through Dex — two different
names in one namespace. Switching the lab's directory therefore does NOT carry
her dashboards, which makes it a good place to see the inheritance sentence
tell the truth about a site where the names do not line up.

### Three things this lab found

Worth reading before adding to it, because each cost an hour:

* **The image already installs the memberOf overlay.** A second one added
  from a bootstrap LDIF fails the whole startup with `status 50`, and the
  seed never runs — so the directory comes up empty and healthy-looking.
* **That overlay is configured for `groupOfUniqueNames` / `uniqueMember`.** A
  `groupOfNames` group adds cleanly, lists its members correctly, and is
  invisible to the overlay: every user in it has no `memberOf` at all, which
  reaches WDash as "authenticated, belongs to nothing".
* **WDash was not asking for the `groups` scope.** Dex gates the claim behind
  it, so every OIDC identity signed in perfectly and landed on the default
  role — no error, no log line, and an administrator who could not see the
  configuration page. Fixed in `auth.py`; the Scopes field on the OpenID
  Connect card overrides it for a provider that refuses the scope.

### The group names are namespaced on purpose

`wdash-admins` rather than `admins`, in the lab and in the product's
defaults. A real directory almost certainly has a group called `admins`, it
usually means domain administrators, and a default that maps it to
`system:admin` hands WDash's highest privilege to everyone in it.

There used to be two sets of defaults — `config/rbac.yaml` and
`store/roles.py` — and they disagreed about this, and about whether the middle
role was called `developer` or `editor`. There is one now, `DEFAULT_ROLES` in
`store/roles.py`, and `tests/test_store.py` holds a new installation to it.

## Postgres

`./lab.sh up postgres` starts the metadata store the way a deployment with
more than one replica runs it, at
`postgresql+psycopg://wdash:wdash-lab@localhost:55432/wdash` — not 5432, so a
Postgres already on the machine is left alone.

Nothing had ever started WDash against one: the first migration aborted its
own transaction on an empty database, so no installation could get past its
first start. `WDASH_TEST_POSTGRES` with that URL runs the whole suite on it
(tests/postgres_store.py).

## Port conflicts

The project-root `docker-compose.yml` also contains Elasticsearch and
Kibana on the same ports. **Do not run both at once.** Use this lab for
development; the root compose file should eventually be reduced to just the
application.

## Not here yet

- **An OpenTelemetry Collector profile.** The OTLP-to-Elasticsearch pipeline
  via `elasticsearchexporter` will be added when real OTel integration starts;
  for now the seed script writes the OTel schema directly.
- **ILM policies.** Deliberately absent so the Advisor's "no ILM" rule has
  something to find. A well-configured example will be added once that rule is
  settled.
