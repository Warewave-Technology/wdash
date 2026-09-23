# Changelog

What changed, for the person running it.

Entries are written from the operator's side: what is different on your
installation, and what you have to do about it. An entry that only makes
sense with the diff open does not belong here — that is what the commit
messages are for, and this project's commit messages are long on purpose.

Three rules the sections encode:

- **Needs action comes first.** Anything that stops working, changes what a
  setting means, or has to be done before the upgrade is at the top, because
  that is the part somebody is reading this for.
- **Security changes say what they change, not that they are security.**
  "CSRF protection is on" is useful; "hardening improvements" is not.
- **Nothing is listed because it was work.** A refactor that changes no
  answer is not here at all.

Versions follow semantic versioning. The one number lives in
`src/wdash/__init__.py`; `/health` reports it on a running instance. A
heading carries the date its tag was made, which is the one date that is
recorded rather than remembered — `git log -1 --format=%ai v3.0.0`.

## 3.1.3 — unreleased

### Needs action

- **Nothing.** The log sidebar chooses its ten fields differently; if you
  picked fields in 3.1.2, yours are untouched.

### Fixed

- **Serilog levels still read `UNSPECIFIED` where the shipper drops `@t`.**
  3.1.2 reads an absent `@l` as Information, which is the format's rule —
  but it only recognised the format on a document carrying `@t`, and
  fluent-bit's JSON parser CONSUMES its time key into the record's
  timestamp and removes it unless `Time_Keep On` is set. `Off` is the
  default, so the commonest way to ship these logs is the one where the
  rule never ran. Two of the format's own keys are enough now — `@m`
  beside `@i` is a naming scheme, not a coincidence.

### Changed

- **The log sidebar shows the ten fields that account for most of what you
  are looking at**, instead of the first ten field names alphabetically.
  Sorting is not ranking: on a cluster whose fields begin with `@` it gave
  a panel of `@i`, `@l`, `@sp`, `@tr` and an application's own counter —
  four of the ten holding one value per record, which says their values are
  unique and nothing about the hour — while the container name never
  appeared. The sidebar now asks about thirty fields and shows the ten
  whose values cover the most records.

  The level, the service, the host and the environment are always shown
  when the cluster has them, whatever they score: an hour in which every
  record shares a service must not take the service row away.

  And they are found by their NEUTRAL names now. The list that puts them
  first was spelled `level`, `service`, `host`, `environment` — one shape's
  spelling, which matched nothing on a cluster calling them `@l` and
  `kubernetes.container_name`. That is also why those fields now survive
  the picker's own list on a cluster with hundreds of them.

  Fields you chose yourself are shown exactly as chosen, all of them, in
  the order you get them.

## 3.1.2 — 2026-09-22

Both of these came from the same screenshot of a real cluster, a day
after 3.1.1 fixed what the one before it showed.

### Needs action

- **Pull the image if your services are .NET.** Until you do, every
  informational line from them reads `UNSPECIFIED` and shows a line of JSON
  instead of its message.

### Fixed

- **Serilog's compact format was shown as its own envelope, with no
  level.** Rows read

      {"@t":"…","@m":"Sayfa bulunamadı (NotFound): KZIAQV","@l":"Warning"}

  at `UNSPECIFIED`, beside a field sidebar counting `@l` — Warning 3,204,
  Error 15. The level was in the cluster, mapped and aggregatable, and the
  page was showing the packaging. `@m` is the message now, `@mt` the
  template behind it, `@l` the level, and `@tr`/`@sp` the trace and span a
  line belongs to, which is what makes the link to its trace appear. The
  raw line stays on the record, so what the shipper received is still
  there.

  **An absent `@l` means Information**, which is the format's rule and not
  a guess: it omits the key for that level and only for that level, which
  is why the sidebar counted Warning and Error and nothing else.

- **`Information` was not a level WDash knew**, so even a level it could
  read would have shown as nothing. That is Serilog's spelling and also
  `Microsoft.Extensions.Logging`'s. Three standards turned out to be half
  covered — syslog had `crit` and `notice` but not `emerg` or `alert`;
  java.util.logging had `severe` and `fine` but not `finer`, `finest` or
  `config` — and all three are finished. A filter for INFO now matches the
  lines spelled `Information` too.

### Added

- **The log sidebar's fields can be chosen**, per source, by an
  administrator. It showed the first ten field names a mapping offers,
  sorted — which on a cluster whose fields begin with `@` is ten nobody
  asked for, with three of them holding a single value seen once and the
  container name never reaching the list. Choose from everything the
  source maps; the filter box searches the whole mapping rather than the
  page. Nothing chosen keeps the old behaviour exactly, and a chosen field
  a mapping later loses is named rather than quietly dropped.

## 3.1.1 — 2026-09-22

Both of these were found by running 3.1.0 against a real Kubernetes
cluster, on the screen where a fault looks most like an answer.

### Needs action

- **Pull the image if your logs come from fluent-bit, fluentd or Docker's
  json-file driver.** Until you do, every record on the logs page reads
  empty.

### Fixed

- **Container logs read as empty.** A cluster of 710 indices searched
  correctly — 177,511 results — and every row of them showed no message,
  no service and a severity of `UNSPECIFIED`. WDash knew two document
  shapes, the OpenTelemetry Collector's and a flat one, and the Kubernetes
  log shippers write neither: the line is in `log`, the pod and container
  are in a `kubernetes` object, and there is no `service` field at all.
  Matching nothing, a document fell through to the flat shape, which looks
  for `message` and `level` and found neither.

  There is now a third shape. The line, the container name, the pod, the
  namespace and the host are read; `stream`, `tag` and the shipper's own
  metadata stay on the record; a filter or a chart that names `service`,
  `pod` or `namespace` is looked for where a shipper puts it.

  **The severity stays `UNSPECIFIED`**, and that is the honest answer
  rather than a gap: these documents carry no level unless your shipper
  parses one out, in which case it is read. A level guessed from the text
  would find one in the lines that happen to start `E0922` and leave the
  rest, so a filter for errors would return some of them and look like it
  had returned all of them.

- **Field statistics still failed on a cluster with a few hundred
  indices**, with the same `too_long_http_line_exception` 3.1.0 fixed for
  searches. Searches could move the index names into a request body;
  reading mappings cannot — there, the index list IS the URL — so that one
  call went on failing, and the sidebar beside a full page of results read
  as an error. It is split into as many requests as the line length allows
  now: 710 names, 21,205 characters, seven requests, one merged answer.

## 3.1.0 — 2026-09-22

Two things added and three faults fixed, all five of them found by
running 3.0.0 somewhere that was not the machine it was built on.

### Needs action

- **Nothing, unless you want the new retention behaviour.** Migration 23
  adds an empty table and nothing reads it until you set
  `monitoring.rollup_after_days`. That default is 0 — off — on purpose:
  folding results DELETES the rows behind them, and an upgrade that threw
  away three weeks of your raw history to save disk would be deciding that
  for you.

- **Pull the image.** Three of the fixes below are in it and not in
  `3.0.0`: a cluster with a few hundred indices could not search at all.

### Fixed

- **A search over more than a few hundred indices failed outright**, with
  `too_long_http_line_exception` and nothing a reader could act on. The
  index names go in the URL path and Elasticsearch's request line stops at
  4kb; measured on a cluster with 563 of them, that line came to 19,039
  characters and every search on the page failed. Past 3,500 characters the
  same search now goes as a one-request `_msearch`, which carries the list
  in the body. One round trip either way, and the role's own index list is
  still what is searched — not a wildcard standing in for it.

- **Behind an ingress with no certificate the browser accepts, every form
  was refused** — the sign-in form included — and the page blamed a stale
  session, which is not what had happened. The session cookie is marked
  `Secure`, a browser will not send one over `http`, and a session that has
  merely expired still SENDS its cookie. No cookie at all is a different
  thing, and the page now says which it is and what to do about it.

- **`Strict-Transport-Security` was sent on plain-`http` responses**,
  carrying a year and `includeSubDomains`. It is withheld now where a
  trusted `X-Forwarded-Proto` says the request arrived over `http` — and
  only there: a proxy that terminates TLS and sets no such header is a
  normal configuration, and reading its silence as insecure would take the
  header away from a deployment that has it right.

### Added

- **`python -m wdash.demo`** — one command that puts the lab into an
  unclaimed installation: five sources, an agent, seven checks including
  one that is deliberately down and a certificate with days left on it, a
  board over all four signals, a saved search, a channel and three rules.
  It does not sign anybody in and does not enrol an authenticator: the
  account it creates has the enrolment page waiting, like any other. It
  refuses an installation that already has an account rather than writing
  into somebody's; `--into-claimed` is how you say you meant it.

- **Hourly summaries for monitor results**, behind
  `monitoring.rollup_after_days`. The results table is comfortable at two
  million rows and unusable at eight, and fifty checks at fifteen seconds
  reach the second in a month; retention's only answer was to delete.
  Measured on ten checks at sixty seconds over thirty days, folded at two:
  432,000 rows and 250 MB became 28,810 rows plus 6,730 summaries and
  13 MB, and a thirty-day availability figure went from 20 ms to 2 ms with
  the same answer to the check.

  Availability stays exact for ever, because counts add. **Response-time
  percentiles do not**: an hour of checks has no median, so they narrow to
  the window that still has rows and the page says from when. The charts
  lose nothing — a count, a mean and a worst all survive an hourly
  summary, and no chart here draws a percentile.

### Changed

- The documentation gains the Kubernetes install: the two secrets and what
  an empty one of each does, the three containers, the three probes and why
  none of them is `/health`, and the four steps to more than one replica in
  the order they have to happen.

## 3.0.0 — 2026-09-22

The first release of this line, and a major one: a deployment that
configured its cluster or its identity provider through environment
variables has to do something before it upgrades.

### Needs action

- **A cluster declared in the environment is no longer read.**
  `ELASTICSEARCH_URL` and the seven variables around it — the credentials,
  the timeout, the certificate switch, the CA bundle, and the trace and
  monitor index patterns — configure nothing now. Sources live in the
  metadata database and are added on **Configuration → Sources**, where they
  are in use the moment they are saved.

  Add your cluster there BEFORE upgrading. Without it the logs, traces and
  monitors pages answer from whatever other sources are stored, or say they
  have none. A process that still has any of those variables set says so at
  start-up, as an ERROR naming them and the page, and imports nothing from
  them: a one-shot import at start-up is the mechanism being removed.

- **The same for OpenID Connect.** `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
  `OIDC_DISCOVERY_URL` and the six around them are not read. Save the
  provider on the OpenID Connect card before upgrading, or nobody signs in
  through it until somebody does.

- **`config/rbac.yaml` and `RBAC_CONFIG_FILE` are gone.** Roles are rows in
  the metadata database. An installation that has none gets `admin`,
  `developer` and `viewer` — mapped from the groups `wdash-admins`,
  `wdash-developers` and `wdash-viewers` — written once by a schema
  migration. An installation that already has roles keeps exactly those,
  including ones imported from an `rbac.yaml` by an earlier version.

  Check the `developer` role after upgrading if you deployed the Kubernetes
  manifests. The ConfigMap that used to ship in them granted it
  `services: ["*"]` where the repository's own `config/rbac.yaml` — and the
  default a migration writes today — list six application services. A
  migration does not change a role that exists, so that installation still
  has the wide one until somebody edits it on **Roles & access**.

- **Every local account needs an authenticator.** A password alone no longer
  signs anybody in: the first sign-in after the upgrade shows a QR code and
  asks for a code from it. `WDASH_ENCRYPTION_KEY` must be set BEFORE that
  happens — the shared secret is sealed with it, and WDash refuses to write
  a secret as text. `python -m wdash.store.recover --reset-totp <username>`
  is the way back for a lost phone.

- **Dashboards and saved searches live in the database.**
  `DASHBOARD_STORAGE=database` is the default, so an installation that never
  set the variable moves with the upgrade. Nothing is deleted, and the
  start-up log and the pages themselves name both files and the command
  until it is run:

  ```bash
  PYTHONPATH=src python -m wdash.store.migrate_cli --dry-run
  PYTHONPATH=src python -m wdash.store.migrate_cli
  ```

  `DASHBOARD_STORAGE=file` keeps reading the JSON, with one worker.

- **A search or a board that names no source now reads every source.** It
  read whichever was stored first. On a mixed installation that is a
  different number: measured on a five-source demo, an unpinned board went
  from 1,115 records to 15,431, and a bare `/api/search` from 5 to 14,353.
  Pin the boards that should read one source; the rest say on screen which
  sources answered.

- **The panel editor no longer offers a count field the save refuses.** The
  "Count by" select was filled from the same list as the group-by ones, but
  a count panel may only be saved with one of the four names most sources
  hold — and a refused save re-renders from the stored panel list, so one
  unusable option cost the author every panel they had just built.

- **Clicking the `unknown` slice of a panel opens the records it counted.**
  `unknown` is the label for records with no value for the field, and it was
  looked up as though somebody had logged it: measured against the lab, a
  bucket of 43,636 whose click returned nothing. The new `other` band on a
  split is not clickable at all — it is not a value.

- **A failed search or a failed dashboard load no longer leaves the last one
  on screen.** A refused search kept the previous search's volume chart,
  source breakdown, warnings and field statistics under a red box about a
  search that never ran; a dashboard whose reload failed kept a green
  "Within thresholds", its error rate, both deltas and the window they came
  from. Both pages already had a method that sweeps all of it, and both now
  call it.

- **Saved searches that could not be read say so.** The list read the
  response body and never the status, so a 503 and a 403 both drew "No saved
  searches yet" — and the sentence the server composes for exactly this
  reached nobody.

- **The span and log counters on the trace pages clear with their lists.**
  Each was written only when there was something to list, so switching to a
  quiet window left the previous window's number beside "No spans in this
  time range."

- **"Would this lock me out?" is asked about the account, not the cookie.**
  The lockout invariants read the role that was written into the session at
  sign-in, which is never rewritten — so an account whose role had changed
  since signing in was checked against the role it used to have, while its
  actual permissions had already moved. The account is read now, the way
  every other authorization decision on the request already does.

- **Test connection no longer reports success after probing without the
  password.** When a stored password could not be decrypted — a rotated
  `WDASH_ENCRYPTION_KEY` — the button probed anonymously and reported the
  far end's answer, so one page could show the red "not in use" badge and a
  working connection test for the same source. It says what happened and
  what to do instead.

- **A source save or connection test refused by the validator is audited.**
  Including the refusal of the cloud metadata address, which was the one
  refusal on this page that left no row anywhere.

- **A dashboard's threshold badge is withheld when the answer is short.**
  Elasticsearch fails a search outright only when *every* shard fails; when
  some fail it answers 200 with what the rest found. The board painted a
  green "Within thresholds" from those counts while the same response
  carried "5 of 9 shards failed" in its warnings. No badge now, for the same
  reason a board with no thresholds has none: it is a claim about numbers,
  and these are numbers nobody can vouch for. The same applies when one
  source of several did not answer.

- **"Alerts nobody received" is out of a number it is part of.** The card
  counted one per rule and subject and divided it by every history row, so a
  board where every delivery had failed read "1 of the 12 alerts in this
  window reached nobody" beside a table of twelve, all marked undelivered.
  Both halves count the same thing now, so that board reads 12 of 12.

- **A time chart split by a field adds up to the traffic again.** The split
  names the ten commonest values, and the chart stacked only those — so a
  board split by a high-cardinality field drew a fraction of its own volume
  with nothing saying so: measured, a bar of 14 over a window holding 304
  records. Records with no value for the field get the `unknown` band the
  other panels already give them, and everything past the tenth value is one
  `other` band.

- **A check result with an impossible duration no longer loses the batch it
  came in.** On Postgres, `duration_us` is a four-byte column and the guard
  checked incoming numbers against an eight-byte one, so a value between the
  two passed the guard and failed at the insert — taking every other result
  in the same batch with it, answering the agent 500, and being retried for
  ever. Such a field is dropped now, with a line saying so, and the rest of
  the result is kept. SQLite installations were never affected.

- **Two administrators deleting accounts at the same moment cannot empty the
  table.** "This is the last local account" was a count followed by a
  delete, and nothing held between them: measured with two processes, 15 of
  20 trials ended with no local account at all and both deletions reporting
  success — an installation nobody can sign in to if the directory is also
  down, and the fix involves the database.

- **A monitor cannot be pinned to an agent that no longer exists.** Saving
  an edit form that was opened before an agent was deleted wrote an
  assignment naming it, and a monitor with an assignment is not run by
  anybody else — so it sat on the page, enabled, checked by nobody. The save
  is refused now and names the agent.

- **A directory outage no longer says which names are local accounts.** A
  local name skipped the directory and was refused 401 while every other
  name got the directory's 503, so the pair of status codes sorted a list of
  candidates into "has an account here" and "does not" — with no session, no
  valid name, no correct password and no rate limiting. Both answer with the
  outage page now, decided by a probe that carries neither the name nor the
  password. A wrong password for a local account is still counted, so
  guessing at the break-glass account still locks it.

- **The volume chart is back on a board or a search that reads more than one
  source.** The merged page was built without a histogram at all, and the
  Logs page hides the chart when the list is empty — so configuring a second
  log source made the chart disappear. A member that cannot count over time
  is now named on the page rather than silently left out of the bars.

- **A merged "top 5" draws five bars.** Reading several sources at once,
  every value every source returned was drawn: measured against three lab
  sources, a panel asking for the top 5 drew nine. Each source is also asked
  for a longer list than the panel wants, so a value that sits outside one
  source's own top N is no longer counted short — and when a source really
  did hand back everything it was asked for, the panel says its smallest
  counts are a floor.

  One consequence worth knowing: a **number panel** on a board that merges
  sources can now say it cannot answer for a rare value where it used to
  give a count. It was answering off the extra values the bug returned. It
  still never reports such a value as zero.

- **Every Loki time chart was drawn one interval late.** `count_over_time`
  evaluated at *t* counts the lines before *t*, and the adapter used *t* as
  the bucket's label — so each bar sat one whole interval to the right of the
  records it counted, and the first bar counted records from before the
  window entirely. Measured on a nine-hour window at hourly resolution: the
  bucket labelled 12:00 held exactly the 79 lines of 11:00–12:00, while
  12:00–13:00 really held 85. **Screenshots and saved comparisons of Loki
  charts from before this version are off by one bar.** Elasticsearch and
  VictoriaLogs charts are unaffected.

- **A certificate alert is no longer closed by the endpoint going quiet.**
  A firing `certificate_expiring` alert resolved as "no longer being
  checked" and forgot its state the moment the check stopped returning a
  certificate — a refused connection is enough — so it re-fired from scratch
  when the endpoint answered again, about a certificate that had not moved.
  Such a subject now holds, the way a `monitor_down` one does.

  A recovery for a subject that really has been deleted now carries the name
  the subject had, not its id. Alerts about deleted checks used to name a
  uuid, because the name is the one thing that cannot be looked up once the
  check is gone.

- **An alert channel's stored host no longer carries its credential.** A
  webhook saved as `https://user:password@hooks.example.com/...` kept the
  whole `user:password@host` in the clear part of the row, so the password
  was on disk unencrypted, on the configuration page under the words "the
  full URL is encrypted and not shown", in the `channel added` audit row and
  in the log. The upgrade repairs every stored channel — the complete URL
  was already in the sealed column, so nothing changes about where alerts go
  — and names each one it repaired.

  **Rotate any webhook credential you wrote into a URL.** Taking it off disk
  does not unsay the screens and audit rows it was already on, and those are
  not rewritten: an append-only trail is the point of one.

- **`/health` asks monitor backends too, and a source cannot take over one
  of the report's own fields.** It probed the log and trace registries only,
  so an installation whose uptime backend was down answered `healthy` with
  nothing named. And the report is one flat object: a source called `store`
  landed on the metadata store's own line — measured, a dead store with a
  healthy source called `store` answered 200 `healthy` — while one called
  `status` or `version` was dropped without a word. Such a source is
  reported under `source:<name>` now. **If you have a source with one of
  those names, an alert keyed on it needs the new key.**

- **A trace panel on a dashboard needs `traces:read`.** It filled for any
  role that could open the board, so a shared dashboard handed out the
  service inventory — names, span counts, error counts and error rates — to
  roles the Traces screen and `/api/traces/services` both refuse. The panel
  now says so and leaves the rest of the board alone, and a role with no
  trace stores assigned gets that sentence instead of an empty list.

  **Give `traces:read` to any role that should keep seeing those panels.**
  Monitor and certificate panels have wanted `monitors:read` all along and
  are unchanged.

- **A `monitor_down` alert no longer resolves when the probe goes quiet.**
  It used to send `resolved` to your channel the moment the monitor went
  `unknown` — an agent five minutes silent, a check running late, a rotated
  token — while the target was still down, and then fire again when the
  probe came back. One outage, three notifications, the middle one wrong.
  Such a subject now holds: the alert stays firing with the detail and the
  failure count it had, and nothing is sent until there is a real reading
  again. `unknown` still does not fire; that half was always right.

  If you have dashboards or runbooks counting alert transitions, they will
  see fewer of them.

- **A source that holds a credential must verify the certificate.** Over
  `https`, saving a source with a password and certificate checks off is
  refused — including when the password is typed again, which used to be
  the way through. Install a private authority in the trust store of the
  host WDash runs on, or tick **Forget the stored password**.

- **A password written into a source's address is refused.**
  `https://reader:secret@es:9200` used to save. The address is stored as it
  was typed, so that password sat in the database in clear text — beside the
  sealed column, not in it — was printed twice on the configuration page,
  and was invisible to both of the rules that protect a stored one: that
  source could be repointed at another host with the password box blank, and
  saved with certificate checks off.

  **If you have one, re-save that source before you trust this fix.** Only
  you can move it: sealing needs the encryption key, and migrations run
  before WDash has one, so the upgrade can name the row and not rewrite it.
  It names it in the log and in the audit trail, masked, as **source
  password in the address**; the page now masks the value too, and the save
  refuses until the credential is in the username and password boxes.

- **An LDAP user is named by the directory, not by what they typed.** A
  directory matches `uid` loosely, so `alice`, `Alice` and `ALICE` all
  signed in and became three different people here — three roles, three sets
  of dashboards, three threads through the audit trail. The username now
  comes from the attribute the user filter looks people up by. Somebody who
  has been signing in as `Alice` against a directory that holds them as
  `alice` becomes `alice`, which is a different name from the one that owns
  their dashboards; nothing moves them, and a direct mapping written against
  the old spelling should be rewritten.

- **A directory sign-in that resolves to a local account's name is
  refused.** Falls out of the change above and is the reason it matters: a
  user filter that matches more than one attribute — `(|(uid={username})
  (mail={username}))`, the ordinary "username or email" configuration — let
  a directory principal type their mail address and be handed the local
  account's name, its role mapping, its dashboards and its rows in the audit
  trail, while typing the name itself was refused. Such a sign-in now gets
  401 and an audited refusal. If a directory principal legitimately shares a
  name with a local account, rename one of them.

### Changed

- **A resolved alert says "recovered", not "the check failed".** The detail on
  a `monitor_down` recovery was a fallback meant for a monitor that IS down,
  and a healthy monitor has no error text either — so both halves of the pair
  claimed a failure and only the transition field told them apart. (This one
  landed separately; it is here because the sentence reaching Alertmanager
  changed.)

- **Screenshot retention no longer stops when result retention is switched
  off.** They are documented as two clocks and were one: the early return for
  "retention off" sat above the screenshot pass, and nothing else prunes a
  journey screenshot. The results clock is a **ceiling** on the screenshot one
  — a screenshot whose result row has gone is an image no screen can reach —
  so thirty days of screenshots under seven days of results is seven, and that
  is now written down.

- **Unticking every Serves box on an existing source is refused.** It changed
  nothing and was reported as saved: the store reads "no signals" as "leave
  them alone". The create path has always refused it.

- **Deleting a source no longer says it is "in use now".** The sentence is
  composed for a save, and a delete fell through to it.

- **An OpenID Connect sign-in is welcomed with the role it resolved to.** It
  said "Role: None" — the object holding the message is built before the
  resolver runs, and the role it carries is the one `User.__init__` sets.

- **A saved search that cannot be deleted says so.** A refusal did nothing at
  all: no message, no change, the row still in the list.

- **Two start-up lines now reach the log.** Which database this process opened
  and how many sources it built were written at INFO, below the level Flask's
  default handler listens at — present on a developer laptop and absent on
  every deployment.

- **"Slowest" over Jaeger or Tempo says what it ranked.** Neither search
  endpoint takes a sort parameter, so the ranking happens in WDash over
  whatever page the backend returned — which used to be the page you asked
  for. It now pulls a pool of five times that (100 to 500 rows) and, when
  that pool comes back full, says in a line of its own that these are the
  slowest of the pool rather than of the window. Elasticsearch ranks
  server-side and is unchanged.

- **A record in the second cluster of a kind gets its raw document and its
  neighbours.** Both were routed by backend TYPE and answered from the first
  source of that type, so with two Elasticsearch sources a record held by the
  second had neither — while the record itself opened fine, which made it look
  like the feature was simply absent.

- **`DASHBOARD_STORAGE_FILE` may be a bare filename again.** With no directory
  in the path, every saved-search *write* was a 500 while the read answered
  200 with an empty list.

- **A CSRF refusal names the client, not the proxy.** It logged
  `request.remote_addr`, which behind an ingress is the ingress: one address
  for every refusal on the whole installation, on the one rule an
  unauthenticated stranger can produce at will.

- **A merged search says the MERGE cannot page**, not that "this source
  cannot page further" — which sent somebody to look at a backend that is
  fine.

### Added

- **`./lab.sh demo`** — one command: start every backend that holds data,
  wait for each to be ready, seed it, and print what to type into WDash.
  `up` then `seed` is two commands with a wait between them that nobody was
  told about, and seeding a backend that is up but not ready fails in a way
  that reads as a broken seeder.
- **A documentation page**, in `site/`. Install step by step, one section
  per backend with what it can and cannot answer, the query language, every
  panel kind, the three role boundaries and the pattern language, the three
  ways somebody signs in, monitoring, alerting, a reference for every
  variable the process reads, a table of everything WDash refuses, and
  thirteen named failures with what each one means, at
  <https://wdash.warewave.tech/docs/>.
- **CSRF protection**, on every state-changing request, with the token in a
  hidden field for a form and in `X-CSRF-Token` for a `fetch`. The agent API
  is exempt: it authenticates with a bearer token and no cookie.
- **Local accounts on the configuration page** — create, change a role,
  disable, reset a password, delete, and reset an authenticator. The
  break-glass account used to be the one account no screen could show.
- **A second factor on every local account**: RFC 6238, implemented out of
  the standard library, checked against the RFC's own vectors.
- **One directory at a time.** LDAP or OpenID Connect, never both; the page
  refuses the second one and says how to switch, and the switch says what
  the names it hands over already own.
- **Monitors, certificates, records, traces, counts and alerts as dashboard
  panels**, beside the log ones. A certificate row is a certificate, with
  the checks that saw it — an endpoint watched by an agent and by Heartbeat
  used to be two rows.
- **Per-monitor TLS trust**: paste the certificate a private endpoint
  presents, or ask for its expiry only — which verifies nothing and
  therefore sends nothing.
- **Synthetic checks from more than one place**, with a row per location.
- **Browser journeys** through real Chromium, as a step list rather than a
  script, with a screenshot per step.
- **Alerting** as its own process, with silences and a history that records
  what was NOT delivered.
- **Gruvbox dark, Gruvbox light, or follow the system**, chosen from the
  navbar.

### Changed

- The root `docker-compose.yml` runs WDash. It ran an Elasticsearch and a
  Kibana and had the application commented out. It publishes **5001**,
  because macOS answers 5000 with its own AirPlay receiver.
- `.env.example` carries `WDASH_ENCRYPTION_KEY=` as a line to fill in rather
  than as a comment.
- `two directories configured` is audited once for the installation rather
  than once per worker per restart.
- The lab starts and seeds one backend at a time — `./lab.sh up loki`,
  `./lab.sh seed loki` — and `./lab.sh targets` says what each one holds
  over the last 24 hours and what to type into WDash to read it.

### Removed

- Flask-WTF, which was installed and never initialised, and the
  `WTF_CSRF_ENABLED` flag that read as "off for tests, on in production"
  about something that was never on.
- The development sign-in door (`/auth/dev-login`).
- Redis, which was configured, deployed and read by no line of code.
