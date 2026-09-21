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

**And from more than one place.** A check watched by two probes gets a row per
location — availability, median, p95 and failures each — and every run says
where it ran. The summary above them is still the whole check, which is the
number to page on; the rows are what it hides. Where a check ran from is the
agent that reported it, or `observer.geo.name` on an Elastic document.

**Browser journeys.** Multi-step checks through real Chromium: sign in, add to
basket, check out. A journey is a step list rather than a script, every step is
timed on its own, and a failure names the step and keeps a screenshot of the
page as it was. The browser rides in its own image so nobody pulls it to run
uptime checks. Elastic's own browser monitors are read down to the step too,
onto the same screen — measured against a running Heartbeat rather than
transcribed from the reference.

**Themes.** Gruvbox dark, Gruvbox light, or follow the system, chosen from
the navbar and remembered by the browser rather than by the account — the same
operator on a bright wall display and a dark laptop wants two different
answers. Dark stays the default. Both are Gruvbox at its medium contrast with
orange as the accent; where one of its colours falls short of AA on a surface
it lands on, it is moved the least distance that clears it, and
[docs/themes](docs/themes/) lists each move. The charts follow a switch too,
rather than keeping the colours they were first drawn in.

Underneath it, every colour in the product now comes from one palette, and
`tests/test_contrast.py` measures every theme rather than whichever one was
written first. That was the expensive half: 24 Bootstrap classes naming a
theme in six templates and three scripts, and about a hundred colours written
outside the palette — including the chart gridlines, which were a shade of a
dark background and would have been invisible on a light page.

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

  That sentence was only half done for most of this line's life: `unknown`
  did not fire, and it RESOLVED — so a probe dying in the middle of an
  outage sent "resolved" while the target was still down. It is neither
  now. A subject with no reading holds everything stored about it and
  produces no notification in either direction.

### Browser checks

Multi-step journeys through a real browser: sign in, add to basket, check out.
Playwright, which is Apache-2.0.

Both of the reasons this was held back turned out to be right, and both were
answered rather than dodged:

* **The browser is a deployment question.** It is a separate image —
  `--target browser`, measured at 1.77GB against the server's 260MB. Anybody
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

Elastic's own browser monitors now show their steps too, on the same screen
and through the same model. That was held back for a phase because the
document shape had never been measured, and it turned out not to be what
reading a summary would suggest:

* a browser monitor writes nothing at all into `heartbeat-*` — it goes to the
  `synthetics-browser-*` data stream, with network requests and screenshots
  in two more beside it;
* one check is six documents, tied together by `monitor.check_group`;
* Elastic's three step outcomes are `succeeded`, `failed` and `skipped`, and
  the third means what WDash's own `skipped` means: the step never ran because
  an earlier one stopped the journey.

One thing is deliberately not read: `synthetics.payload.source`, which is the
step's own code and arrives with whatever literal the author typed into it.
The lab's failing journey has a password in it, and so would a real one.

## Phase 4 — done

Five candidates, all of them shipped. Every one changed on contact with a
running lab, and the changes are the interesting part of the list below: what
the page turned out to be doing was in three cases worse than the sentence
that proposed fixing it.

Email as an alert destination was on this list and is not in it — see
**Deliberately absent**.

### Capability

* ~~**Journeys from more than one place.**~~ Done, and the gap was worse than
  this said. The detail page did not show one probe's status; it averaged
  them. Measured on two agents watching one endpoint — one slow and failing a
  quarter of its runs, one healthy — the page reported 87.5% available and a
  response time true of neither. There is a row per location now, worst
  first, and each run says where it ran. A check carries `location`: the
  agent that reported it, or the `observer.geo.name` Elastic stamps on it —
  which a self-managed Heartbeat writes only once somebody configures it, so
  the lab now does.
* ~~**Per-step history.**~~ Done. A journey's detail page carries a row per
  step over the window — its share of a typical run, median, p95, failures,
  and the second half of the window against the first, so "which step got
  slower" is a column rather than an investigation. Computed from the history
  the page already reads, so it costs no query; the sparkline is one mark per
  RUN, because bucketed by time it drew nothing at all.

### The screen itself

Grounded in what is there rather than in a redesign. Each of these is a thing
somebody can point at today.

* ~~**There is one palette, and it is dark.**~~ Done — see
  **Themes** under "Here now". The measurement that started it is in
  [docs/themes](docs/themes/), including the part that mattered: the palette
  was a third of the work.

* ~~**A failed journey does not name its step until you click.**~~ Done. The
  run row names it — `step 5 · Expect URL "/dashboard"` — with the error kept
  underneath, because the step says where and only the error says what. The
  model already knew which step was to blame; the serializer between it and
  the page was dropping the answer.
* ~~**Elastic's journey screenshots are not shown.**~~ Done. Every step that
  ran offers the page as the browser saw it. Elastic stores no screenshot: it
  stores a reference to 64 tiles and the tiles themselves, deduplicated by
  content hash across every run of every monitor, so they are assembled — in
  the browser, on a canvas, rather than by adding an imaging library to
  compose JPEG on the server. What that measurement found is in
  [lab/README.md](lab/README.md#how-a-screenshot-is-stored-measured), and
  `tests/test_synthetics_lab.py` asks a running Heartbeat the same questions
  so the fixture cannot quietly stop matching reality.

## Phase 5 — candidates

Nothing is committed except the first, which is done. The list is ordered by
what it would change for somebody using WDash, not by what is interesting to
build.

* ~~**A source configured on the page needs a restart.**~~ Done. The screen
  whose entire job is configuring the application used to say "Restart WDash
  for it to be used for queries". A source is now in use in the worker that
  saved it before the page redraws, and in every other worker within five
  seconds — a stamp in the store that each one reads on a clock, because the
  administrator's form only ever reached one of them. The environment's own
  sources are held apart and never rebuilt, so an edit cannot disturb the
  connections a running query is using. Measured: 0.33 µs to read the sources,
  49 µs for the stamp once per five seconds, 627 µs for a rebuild that only
  happens when something changed.

### Capability

* **Alert on a log query.** The three rule kinds are all about monitoring —
  `monitor_down`, `agent_silent`, `certificate_expiring`. The thing most often
  wanted from a log tool is "tell me when `level:ERROR` crosses a threshold",
  and everything it needs already exists: an evaluator in its own process,
  channels, silences, a history that records what was not delivered, and a
  neutral `LogSource` so one rule would work against all five backends. The
  hard parts are honest ones — every evaluation is a real query, so the
  schedule has a cost; and "crossed a threshold" needs a definition that does
  not page somebody twice for one incident. Binding a rule to a SAVED SEARCH
  rather than to a query string keeps the query language from being
  implemented a second time.
* ~~**A monitor panel on a dashboard.**~~ Done, and wider than this said:
  the board carries checks (status and availability), TLS certificates,
  records, a trace list, a count and the alert store beside the log panels.
  A certificate row is a CERTIFICATE, with the checks that saw it — an
  endpoint watched by WDash's own agent and by Heartbeat had been two rows
  on a card that answers "what renews next".
* **API tokens for people.** Agents have tokens, hashed and rotatable, and
  every use is audited. A person has no way to reach WDash without a browser,
  so anything scripted has to borrow an agent's token or a session cookie.
* **Retention and rollup for monitor results.** The SQLite cliff below is
  measured and its only answer is "move to Postgres". Folding results older
  than a few days into hourly summaries would make the cliff something the
  product handles rather than something it documents.

### Reach

* **A demo that runs out of the box.** Half done. `docker compose up -d`
  now starts WDash itself rather than an Elasticsearch and a Kibana with the
  product commented out, and `./lab.sh targets` says what every backend
  holds and what to type into the page to read it. What is still manual is
  the rest: monitors, journeys, dashboards and alert rules are a sequence of
  steps somebody follows. One `./lab.sh demo` is the difference between
  trying WDash and reading about it.
* ~~**A release line behind the tag.**~~ Done as far as this repository can
  take it: `CHANGELOG.md` written from the operator's side, `RELEASING.md`
  with the commands and with what it deliberately does not do,
  `THIRD-PARTY-NOTICES.md` generated from installed metadata, and
  `tests/test_release_files.py` holding all three to the version. What is
  still missing is outside the repository — there is no remote, so the five
  CI jobs have never run, and no image has been published.

### Honesty

* **Paging a merged search.** It is first-page only, and the reason is good —
  a cursor that silently skips records is worse than no paging. Either the
  merged cursor gets written, or the limit is said louder on the screen than
  it is in this file.

## Deliberately absent

**Email as an alert destination.** Webhook already reaches Slack, Teams,
PagerDuty, Opsgenie and Alertmanager, and every one of them sends email better
than WDash would: an SMTP screen means credentials, a queue, retries and
bounce handling for a delivery path that ends in somebody's spam folder. Named
here so it stops being proposed.

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
