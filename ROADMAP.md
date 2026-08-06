# Roadmap

What is here, what is coming, and what is deliberately absent. The last of
those is the part worth reading: a feature that is missing by accident and one
that is missing on purpose look identical from outside, and only one of them
is worth asking about.

## Here now

**Logs and traces across several backends.** Elasticsearch (logs, and APM or
OpenTelemetry traces), Loki, VictoriaLogs, Jaeger and Tempo, behind one neutral
model. A search fans out across all of them and merges the results, reporting
which source could not answer rather than letting a failure look like an empty
page.

**Dashboards, saved searches, RBAC, OIDC and LDAP sign-in, an audit trail.**
All of it in a metadata database — SQLite or Postgres — rather than in
Elasticsearch, which is a data source here and not a dependency. WDash starts
and works with no Elasticsearch at all.

**A cluster advisor.** Rules over a snapshot of a backend's configuration, per
backend, saying what is wrong and why it matters rather than listing settings.

**Synthetic monitors, two ways.** WDash reads what Elastic Heartbeat and the
Synthetics integration write; and it runs its own checks through an agent that
pulls configuration and pushes results back. Both appear on one page, with
response-time history, per-monitor detail and the TLS certificates the checks
saw.

## Phase 3

### Alerting

Nothing tells anybody when a monitor goes down. Somebody has to be looking at
the page, which is a poor way to find out about an outage at three in the
morning. This is probably the most valuable single addition the product can
make.

The shape to follow already exists: `src/wdash/store/forwarding.py` sends the
audit trail to Splunk or Elasticsearch through a `Sink` interface, and an
alert destination is the same problem.

Two things it must get right, both of which the model already supports:

* **Read sources, not tables.** An alert rule that queries
  `wdash_monitor_results` directly works for WDash's own agent and is blind to
  every Heartbeat monitor on the same page. `MonitorSource` is what both go
  through.
* **`unknown` is not `down`.** A silent agent and a failing target are
  different facts, and the source layer already tells them apart. Paging
  somebody because an agent restarted is how a monitoring system gets muted,
  and a muted monitoring system is worse than none — it is the same blindness
  with a false sense of coverage.

### Browser checks

Multi-step journeys through a real browser: sign in, add to basket, check out.
The single-request checks WDash runs today cannot say that a login form stopped
submitting.

Playwright is the obvious tool and is Apache-2.0, so it satisfies the licensing
rule below. It is a separate phase rather than a third entry in
`MONITOR_KINDS` for two reasons:

* it brings hundreds of megabytes of browser, which is a different deployment
  question from an agent that is one Python process;
* a journey is not a request with a duration. It is a script with steps, each
  timed and each capable of failing on its own, and the neutral model would
  have to grow a shape for that. Bolting it onto `Monitor` would produce a
  page that shows a journey as one number.

The Elasticsearch adapter already lists `monitor.type: browser` documents with
their summary status, which is real. The per-step detail is what is missing,
and it is missing because that document shape has never been measured against
a running Synthetics service — guessing it would produce a screen that looks
complete and is wrong.

## Deliberately absent

**ICMP checks.** A ping needs a raw socket, which needs `NET_RAW`, which needs
a privileged container. That is a trade worth making in some deployments and
worth arguing about explicitly in all of them — not a type that quietly
appears in a dropdown.

**WDash in the data path.** Applications write to a collector, the collector
writes to storage, WDash reads storage. That is why WDash cannot lose
telemetry, and it is why the check agent is a separate process that WDash
never connects to rather than a thread inside the web server.

**Proprietary and source-available dependencies.** SSPL, the Elastic Licence,
anything commercial. Copyleft is not banned — `ldap3` and `psycopg` are LGPL
v3, used as libraries over their published interfaces — and
`tests/test_dependency_licences.py` enforces the distinction so that a new one
has to be argued about rather than arriving with a `pip install`. Speaking
HTTP to an AGPL server, as WDash does to Loki and Tempo, binds nothing.

## Known limits, measured

**SQLite and the monitor results table.** Measured on this schema, thirty days
of history, a 24-hour page:

| Monitors | Interval | Rows | File | Page |
|---|---|---|---|---|
| 10 | 60s | 432,000 | 228 MB | 99 ms |
| 50 | 60s | 2,160,000 | 1.2 GB | 508 ms |
| 50 | 15s | 8,640,000 | 4.8 GB | 2,274 ms |

Two million rows is where the page stops feeling instant and eight million is
where it stops being usable. Past the threshold WDash says so, on `/health` and
on the page — a page that is slow without explaining why sends somebody to look
at the network. The answer at that scale is Postgres, not another index.

**One report cache per process.** The advisor caches its report in memory, so
each gunicorn worker holds its own. Acceptable while the report is advisory
and the TTL is short; it should move to shared storage alongside the rest of
the metadata.

**No metrics signal.** Logs, traces and synthetic monitors. Metrics are a
fourth signal with a genuinely different query model, and adding a screen that
renders Prometheus badly would be worse than not having one.
