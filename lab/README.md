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
./lab.sh up          # Elasticsearch + Redis
./lab.sh seed        # ~50k logs, 2k traces
./lab.sh status      # health check
```

To point the application at the lab, use this in the project root `.env`:

```
ELASTICSEARCH_URL=http://localhost:9200
REDIS_URL=redis://localhost:6379/0
```

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

RBAC works out of the box against `config/rbac.yaml` — `viewer` sees only
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
synthetics-browser.screenshot-default   screenshots — several documents per
                                        run, and how they assemble into an
                                        image has not been measured
```

Two things about running them, both learned the hard way:

* **Heartbeat must not run as root.** It refuses a browser monitor with
  "script monitors cannot be run as root" — and refuses it per monitor, so
  the HTTP checks carry on and the journeys report `down` with a zero
  duration. The compose service therefore runs as `heartbeat`.
* **The browser is in the image already.** `docker.elastic.co/beats/heartbeat`
  ships `@elastic/synthetics` and its own Chromium, which is most of why it is
  2.58GB.

## Port conflicts

The project-root `docker-compose.yml` also contains Elasticsearch, Redis and
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
