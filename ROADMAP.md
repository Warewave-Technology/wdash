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

**Browser journeys.** Multi-step checks through real Chromium: sign in, add to
basket, check out. A journey is a step list rather than a script, every step is
timed on its own, and a failure names the step and keeps a screenshot of the
page as it was. The browser rides in its own image so nobody pulls it to run
uptime checks.

**Alerting.** Rules over monitors, webhook delivery, silences, and a history
that records what was NOT delivered as well as what was. Evaluation is its own
process, because an agent going silent produces no requests to piggyback on
and that is the moment somebody needs telling.

## Phase 3 — done

### Alerting

Rules, channels, silences and delivery. Evaluation runs as its own process
(`python -m wdash.alerts`) because it has to evaluate when NOTHING is
arriving — an agent going completely silent produces no requests at all, and
that is exactly the moment somebody needs telling.

The two things it had to get right, and did:

* **It reads sources, not tables.** A rule that queried
  `wdash_monitor_results` would work for WDash's own agent and be blind to
  every Heartbeat monitor on the same page. Everything goes through
  `MonitorSource`.
* **`unknown` is not `down`.** A silent agent and a failing target are
  different facts with different audiences, so they are different rule kinds.
  Paging somebody because an agent restarted is how a monitoring system gets
  muted, and a muted one is worse than none.

### Browser checks

Multi-step journeys through a real browser: sign in, add to basket, check out.
Playwright, which is Apache-2.0.

Both of the reasons this was held back turned out to be right, and both were
answered rather than dodged:

* **The browser is a deployment question.** It is a separate image —
  `--target browser`, measured at 1.77GB against the server's 265MB. Anybody
  running a probe for uptime checks does not pull it. Where no browser agent
  is assigned, a journey reports as unknown rather than pretending.
* **A journey is not a request with a duration.** It is a sequence, and the
  model grew `JourneyRun` and `StepResult` to say so. Every step is timed on
  its own, and the first failure stops the run — the steps after it are
  `skipped`, not `failed`, because step 5 could not find the basket button
  when step 4's sign-in failed.

A journey is a step list, not a script. Nine verbs, rendered from the same
dictionary the server validates against. That is a real limit and it bought
three things: a journey that can be shown as rows rather than as one number, a
failure that names the step, and an edit form that is not remote code
execution on every probe host.

What is still missing is the per-step detail from ELASTIC's browser monitors.
The adapter lists `monitor.type: browser` documents with their summary status,
which is real; the steps inside one have never been measured against a running
Synthetics service, and guessing that document shape would produce a screen
that looks complete and is wrong.

## Phase 4 — candidates

Nothing is committed. The strongest three, in the order they would help:

* **Journeys from more than one place.** A journey already runs on every agent
  assigned to it, but the page shows one status. "Slow from Frankfurt, fine
  from Dublin" is a different question from "is it up".
* **More alert destinations.** Webhook reaches Slack, Teams, PagerDuty,
  Opsgenie and Alertmanager, which is most of it. Email is the obvious gap and
  brings an SMTP configuration screen with it.
* **Per-step history.** "Which step got slower this week" is answerable from
  what is already stored, and would need a chart per step rather than per
  journey.

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
