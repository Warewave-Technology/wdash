# WDash

A small observability front-end for logs and traces, with role-based access
control that lives in the application rather than in the data store.

WDash sits in front of Elasticsearch and gives you log search, dashboards,
distributed traces, and a cluster configuration advisor — without requiring a
commercial licence for the features that matter.

## Why it exists

Elasticsearch's free tier has no document-level or field-level security. If you
need "this team sees `app-*` logs and only their own services' traces", you
either buy a licence or enforce it in front of the cluster. WDash does the
latter: it is designed to be the only path to Elasticsearch, and every query it
issues carries an explicit authorization scope.

## Features

- **Log search** — Lucene-style query syntax, a volume histogram split by
  severity (click a bar to zoom), cursor pagination, field statistics sidebar,
  surrounding-record context, multi-line and JSON message rendering.
- **Distributed traces** — browse services, list their traces (most recent or
  slowest, errors only), and open a trace on its own page: a waterfall with
  span ids and self-time, a per-service breakdown of where the time went, span
  attributes, and the log records that carry the same trace id. Reads both
  OpenTelemetry and Elastic APM schemas.
- **Dashboards** — a panel list you choose: volume over time (optionally split
  by a field), top values of a field, and services from the trace store. Every
  count is compared against the preceding window of the same length, and every
  chart and stat card opens the log records behind it — inside the dashboard's
  own index patterns and the store it reads from, and, for a severity card,
  every level that number counted, so the drill-down narrows what is on screen
  rather than widening it or trimming it. Log panels are answered
  in a single backend round trip however many there are. Optional thresholds
  say whether the dashboard is outside what its owner calls normal.
  A dashboard link carries its time range and filter, so what you share is the
  view rather than the page.
- **More than one source** — Elasticsearch, Grafana Loki and VictoriaLogs for
  logs; Elasticsearch, Jaeger and Grafana Tempo for traces. **None of them is required**: set
  `ELASTICSEARCH_URL` to nothing and WDash runs on the others. Search one or
  all of them; a merged page says which source answered each record, and says
  so when a backend is down rather than quietly returning less. A trace split
  across two backends — a request crossing services that export to different
  stores — is reassembled into one waterfall rather than shown as two halves
  with holes in them.
- **Access control** — three independent boundaries per role (log containers,
  trace stores, services), resolved on every request so a change takes effect
  without anyone signing out. Fails closed throughout.
- **Gruvbox dark, Gruvbox light, or follow the system** — chosen from the
  navbar and kept in the browser, because a theme belongs to the screen
  somebody is sitting at rather than to the account they sign in with. Dark
  is what you get if you never choose. Where Gruvbox's own colours fall short
  of AA they are moved the least distance that clears it, and
  [docs/themes](docs/themes/) lists every one.
- **Configuration in the browser** — sources, identity providers and roles, with
  a connection test before you save a source and an "what would this reach?"
  preview before you save a role. **One source serves every signal it holds**:
  an Elasticsearch cluster with logs and traces is one entry with one
  credential, not two rows that drift apart on the next rotation.
- **Advisor** — read-only checks over every configured source, with concrete
  remediation steps: 31 for Elasticsearch (sharding, mappings, caching,
  security), and a smaller set for each of the others covering retention,
  capacity and exposure. How much a backend can be checked differs a great
  deal, so each report says which source it is about and how many checks could
  run against it — a clean report for Jaeger is a much narrower statement than
  a clean one for Elasticsearch, and hiding that would be the misleading
  version.
- **Synthetic monitors, two ways** — WDash reads what Elastic Heartbeat and the
  Synthetics integration write, AND runs its own checks through an agent that
  pulls configuration and pushes results back. Both appear on one page with
  response-time history, per-monitor detail and the TLS certificates the checks
  saw. A silent agent leaves its monitors `unknown` rather than `down`: a probe
  that stopped looking is not a site that stopped answering. A check behind a
  private certificate may name the certificate to trust — pasted, trusted
  instead of the public roots, and only for that check's own origin — or say
  "expiry only", which does not verify at all and therefore sends no headers,
  no cookies and no authentication. The page says which, and never guesses:
  a source that cannot report whether a handshake was verified says nothing
  rather than claiming either.
- **Browser journeys** — multi-step checks through real Chromium: sign in, add
  to basket, check out. A journey is a step list rather than a script, so it
  can be shown as rows, every step is timed on its own, and a failure names the
  step and keeps a screenshot of the page as it was. Passwords are encrypted
  and referred to as `{{ secret.name }}`, never typed into a step. The browser
  ships in its own image so nobody pulls it to run uptime checks.
- **Alerting** — rules over monitors, agents and expiring certificates, sent to
  a webhook, with silences and a history that records what was NOT delivered as
  well as what was. Evaluation runs as its own process, because an agent going
  completely silent produces no requests to piggyback on and that is exactly
  when somebody needs telling.
- **Sign-in** — OIDC *or* LDAP — one directory at a time, never both — and a
  local break-glass account created at first
  run that keeps working when the identity provider does not. Repeated failures
  are throttled per account, per address and per pair. The account-wide limit
  counts only guesses, so an address knocking on a locked door cannot lock the
  owner out from everywhere else.
- **Audit trail** — every configuration change with its resulting state, every
  sign-in, sign-out and lockout, each with the address it came from. Read-only
  from the application, filterable, exportable as JSON lines, and forwardable
  to Splunk or Elasticsearch — including everything recorded before forwarding
  was switched on. The recorded state travels to Elasticsearch as JSON text,
  so an index mapping cannot be broken by whatever one change happened to
  contain; Splunk gets the object. **Upgrading:** an audit index written by
  an earlier release mapped `state` as an object, and such an index refuses
  every row that has one — `document_parsing_exception`, on every sweep, for
  ever. Roll the index over or reindex it before turning forwarding back on;
  a new index picks up the new shape by itself. The refusal is loud (the
  forwarding error and the queue depth on the audit page), never silent.

## Quick start

The repository ships a self-contained lab environment. You do not need an
existing Elasticsearch cluster to try it.

```bash
# 1. Start Elasticsearch and load sample data
cd lab
./lab.sh up
./lab.sh seed          # ~50k logs, 2k traces across two schemas

# 2. Run the application
cd ..
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp .env.example .env   # defaults already point at the lab
./venv/bin/python main.py
```

Open <http://127.0.0.1:5001>. The installation has no accounts yet, so every
route leads to `/setup`, where you create the administrator.

> ### ⚠️ The first account is a local one
>
> **The account you create at `/setup` is stored in WDash's own database with
> an Argon2 password hash. It is NOT an identity-provider account, and it keeps
> working when the identity provider does not.**
>
> **That is the point — it is the way back in after a bad OIDC change, which
> also makes it a permanent credential to the whole system. Protect it like
> one, and do not share it.**
>
> Setup closes the instant that account exists, and cannot be reopened from the
> UI. There is no static password and no environment-variable-gated door: the
> old `/auth/dev-login` has been removed, because a guard that is one
> environment variable deep is the guard people forget.
>
> Minimum password length is 12 characters. There are no composition rules —
> length is what actually costs an attacker time.

### How setup closes

The check is against the database on every request rather than a flag cached at
startup, so a second worker sees the first worker's administrator immediately.
The account is created under a uniqueness constraint, so two people submitting
the form at the same moment produce one administrator and one clear error
rather than two owners.

## Configuration

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Flask session signing key | `dev-secret-key-change-in-production` |
| `FLASK_DEBUG` | `true` turns on Flask's debugger and reloader | `False` |
| `TRACE_INDEX_PATTERNS` | Indices holding traces; excluded from log search | `*traces*,*apm*` |
| `ELASTICSEARCH_URL` | Cluster endpoint. **Set it to nothing to run without Elasticsearch at all** — unset still means the local default | `http://localhost:9200` |
| `ELASTICSEARCH_USERNAME` | Optional basic auth user | — |
| `ELASTICSEARCH_PASSWORD` | Optional basic auth password | — |
| `ELASTICSEARCH_TIMEOUT` | Request timeout, seconds | `30` |
| `ELASTICSEARCH_VERIFY_CERTS` | Verify the cluster's TLS certificate. **Off by default so no existing deployment loses its cluster on upgrade — turn it on for anything but a loopback address** | `False` |
| `ELASTICSEARCH_CA_CERTS` | CA bundle for a cluster behind a private authority | — |
| `OIDC_CLIENT_ID` | OIDC client id | — |
| `OIDC_CLIENT_SECRET` | OIDC client secret | — |
| `OIDC_DISCOVERY_URL` | Provider discovery document | — |
| `OIDC_REDIRECT_URI` | Callback URL | `http://127.0.0.1:5001/auth/callback` |
| `OIDC_USERNAME_CLAIM` / `OIDC_EMAIL_CLAIM` / `OIDC_GROUPS_CLAIM` | Which claims name a person. Unset falls back to rbac.yaml's `claim_mappings`, then `preferred_username` / `email` / `groups` | — |
| `OIDC_TRUST_UNVERIFIED_EMAIL` | Use an email the provider has not marked verified. Only for a provider that never sends `email_verified` and lets nobody edit the address | `false` |
| `OIDC_SCOPES` | What to ask the provider for. `groups` is included because roles are mapped from groups, and a provider that gates that claim behind a scope sends nothing without it | `openid email profile groups` |
| `RBAC_CONFIG_FILE` | Roles imported **once** into the database on a fresh installation, then ignored | `config/rbac.yaml` |
| `LOGS_PER_PAGE` | Records per page in the log list | `50` |
| `SESSION_COOKIE_SECURE` | Send the session cookie over HTTPS only. Also enables HSTS | `False` |
| `TRUSTED_PROXY_COUNT` | How many reverse proxies sit in front of WDash. `0` ignores `X-Forwarded-For` entirely — trusting it without knowing the depth lets a client name its own address and step around the per-address rate limit | `0` |
| `DASHBOARD_STORAGE_FILE` | Dashboard persistence file (file store only) | `data/dashboards.json` |
| `DATABASE_URL` | Metadata store: `postgresql://…` or `sqlite:///…` | `sqlite:///data/wdash.db` |
| `WDASH_ENCRYPTION_KEY` | Encrypts secrets held in the metadata store. Without it, secrets cannot be saved at all | — |
| `DASHBOARD_STORAGE` | Where dashboards **and saved searches** live: `database` or `file` (default). Run the migration before switching &mdash; flipping it without one presents an empty list as though nothing had ever been saved | `file` |
| `DASHBOARD_INDEX` | Kept out of log search. The Elasticsearch dashboard store has been removed, but an installation that used it still has the index sitting in the cluster, and without this a search over `*` returns dashboards as bodyless records | `wdash-dashboards` |
| `MAX_SEARCH_RESULTS` | Upper bound on page size | `1000` |

### Identity providers

OIDC and LDAP are configured on `/admin/config` and take effect immediately —
the client is built per request, which is what lets an administrator repair a
broken provider and try again without a restart.

Where two places configure the same provider, the stored settings win over the
environment: otherwise the config page would save successfully and change
nothing. A provider switched off is off, with no fall back to the environment —
or the switch would do nothing on a deployment that has both. Saving the OIDC
card with **Enabled** unchecked is therefore also how a provider configured in
the environment is turned off from the page, with no restart.

**At most one directory.** Either LDAP or OIDC signs people in, never both.
Ownership here is the username — a dashboard belongs to `created_by`, a role
mapping is written against a name — with no provider attached to it, so with
two directories open a principal at one who can choose `preferred_username`
signs in as somebody at the other and gets their dashboards and their role.
Which one is in force is decided in one place, from configuration and not from
usability:

1. a directory configured in the store beats one configured only in the
   environment;
2. both stored and enabled: the row saved most recently wins, ties to LDAP, so
   the answer never depends on row order;
3. neither: no directory, and local accounts are unaffected.

Enabling the second one is refused on the page, in words that say how to
switch: turn the first one off and save, then enable the other. That second
save is the confirmation, and it says what those names already own — how many
dashboards and role mappings belong to names that are not local accounts, a
few of them by name, and that whoever signs in as one of them through the new
directory inherits them. Nothing is migrated and nothing is scoped by
provider: a name keeping what it owns is exactly what makes a deliberate
switch work.

A directory that is configured and not in use is said rather than hidden — one
neutral line on the sign-in page, so somebody whose usual door has gone is not
told "Invalid username or password" for a reason that is not theirs — and a
directory in force whose settings cannot be read (a rotated encryption key, a
half-filled row) closes the door rather than handing the installation to the
other one. An installation that already has both gets a warning in the log at
startup, a `two directories configured` audit row, and a banner on
`/admin/config`; a resolution that changes while WDash is running is audited
as `directory in force changed`. Turning off the directory you arrived through
is refused when no enabled local account can administer and no other directory
would take over — a handover to one that is configured and works is the switch
itself, and on an installation with both it is the only direction the page
has, since enabling the second one is refused. Where it does refuse,
`python -m wdash.store.recover --use-directory <ldap|oidc|none>`,
`--enable <username>` and `--grant-admin <username>` are the way back from
outside the application.

LDAP authentication binds **as the user** with the password they typed. Finding
their entry with the service account proves the account exists, not that the
password is right; treating the search as the check is a complete bypass that
looks like working code. `ldap3` is LGPL v3 — as is `psycopg`, which is needed
only when `DATABASE_URL` points at Postgres — and it is kept behind
`src/wdash/auth/ldap_auth.py` so it can be replaced in one file. Both are used
as libraries over their published interfaces, which is what the LGPL is for;
neither pulls WDash's own licence with it. `tests/test_dependency_licences.py`
refuses anything proprietary or source-available.

`ldaps://` certificates are checked against the system's CAs, or a CA file
named on the page. The bind carries the password a person typed, so a
directory whose certificate is not checked hands that password to anything
that answers in its place. Turning the check off is a switch somebody has to
choose, and it is logged on every sign-in. `ldap://` sends passwords in clear
text, and the page says so. A directory that cannot answer — unreachable, its
certificate refused, the service account refused, a search that fails — is
reported as that and answered with a 503. It is not recorded as a wrong
password, so an outage cannot lock anybody out. A local account's name is never
asked of the directory, so an outage cannot stop its wrong guesses being
counted either. The user's own bind refused for the account — locked by a
password policy, inactivated — is a wrong password, not an outage. An
`ldaps://` server may be named by address when its certificate carries that
address, and a CA file that cannot be read is refused when it is saved.

**What a provider may assert about a person.** An OIDC email counts only when
the provider sends `email_verified: true`: roles can be mapped to an address,
and a provider that lets people set their own address would otherwise let them
take somebody else's mapping. A provider that never sends the claim has to be
trusted explicitly. The username, email and groups claims are chosen on the
page, in rbac.yaml's `claim_mappings` or with `OIDC_USERNAME_CLAIM`,
`OIDC_EMAIL_CLAIM` and `OIDC_GROUPS_CLAIM`. A dotted name reaches into an
object (`realm_access.roles`). `email_verified` speaks for the `email` claim
only: another email claim is used only if unverified addresses are trusted.
Ownership and name mappings trust the username claim, so choose one your users
cannot edit. Without a username, the fallback is the verified email, then
`sub` — unless the provider sent an address it did not verify, as ADFS and
Entra v1 tokens do: that sign-in is refused, with a message naming the setting,
rather than signing the person in as an opaque id that owns none of their
dashboards. No provider, OIDC or directory, may sign somebody in under the
name of a local account: that name owns the break-glass administrator's
dashboards. Such a sign-in is refused and audited. `claim_mappings` in
rbac.yaml is imported the first time a start finds none stored, on an existing
installation as on a new one.

### The configuration page

`/admin/config` (requires `system:admin`) holds data sources, the identity
provider settings, and roles.

Three rules run through it:

- **Secrets are written, never rendered.** The form shows whether a password is
  set and offers to replace it; it cannot show it. A settings page that renders
  stored credentials is an exfiltration endpoint for anyone who reaches an
  administrator session, which is a much lower bar than reaching the database.
- **A blank credential field means "keep", not "delete".** Otherwise saving the
  page without retyping the password silently breaks the connection.
- **Every change is logged with who made it.** This is the screen that decides
  who can see what.

Source URLs are checked before the server will fetch them: only `http` and
`https`, and never a link-local address — `169.254.169.254` is where cloud
instance metadata lives, and it hands out credentials to anything that asks.
Private and loopback addresses stay allowed, because that is where these
backends actually live.

`config/rbac.yaml` is imported once into the database on a fresh installation
and ignored afterwards, so an edit made here is never overwritten by a restart.

## Access control

Three independent boundaries per role, and **a boundary that is not declared
grants nothing** — access is granted explicitly or not at all.

| Boundary | Unit | Blank means |
|---|---|---|
| log containers | index / stream | nothing |
| trace stores | index; Tempo and Jaeger by source name | nothing |
| services | service name | **every service** |

Services is the one exception, and the form says so. The granularity differs by
signal on purpose: for logs the meaningful unit is the index, for traces it is
the service. A role given every trace store but restricted to application
services sees no infrastructure spans at all.

Tempo and Jaeger have no index to grant, so each is one trace store matched by
its source's name: `*`, `lab-tempo`, `lab-*` or `lab-tempo:*` open it, and
`-lab-tempo` beside `*` keeps it closed. In 2.4.0 and earlier they asked only
whether a role had any log container, so a role granted nothing but
Elasticsearch trace indices (`otel-traces-*`) read every trace in Tempo and
Jaeger; such a role now needs the store's name added. The shipped roles use `*`
and are unaffected.

Patterns support `*`, `prefix*`, `*suffix` and `*middle*` — the same four in
every boundary, services included. A bare pattern applies to **every configured
source**, so adding a source widens what existing roles reach; write
`source-name:pattern` to hold one to a single source.

The colon qualifies a rule **only when a source has that name**. Names have
colons — OpenTelemetry's default service name is `unknown_service:java` — and
a colon that names no source is part of the name, so `unknown_service:java`
grants that service and `-unknown_service:*` hides every one of them. The role
preview says when a rule's colon names no source. A source's name cannot
contain a colon, and a source cannot be created or renamed with a name that
roles already write before a colon: that would turn their names into rules for
it.

A pattern prefixed with `-` is an exclusion, and **an exclusion beats every
inclusion** regardless of the order they are written in — a role is a set, not
a program, and a rule whose meaning depends on typing order is not reviewable
in any list that displays it. So `app-*` together with `-*-pii-*` means "the
app family, never the sensitive ones", and keeps meaning that as new indices
appear. Exclusions can be source-qualified too, with the `-` on either side
(`-primary:secret-*` and `primary:-secret-*` are the same rule). An exclusion
on its own grants nothing: `-secret-*` is a role with no access, not a role
with all of it. The same holds for services: `*` with `-payments` hides every
payments span, in every trace store, and a trace that lost spans that way says
so. A trace list chooses traces only by what the role may see: "errors only"
means an error in a visible service, and a trace whose entry point is hidden is
still listed, told through its visible services and timed by them.

A check made without knowing the source fails closed both ways: a qualified
grant does not apply, and a qualified exclusion does. And because a qualifier
is a source's name, a source cannot be renamed while some role's patterns
name either the old name or the new one — renaming `primary` would otherwise
turn `-primary:secret-*` into an exclusion of nothing, and renaming a source
to `staging` would hand `staging:*` everything in it. The same goes for a Tempo
or Jaeger source whose name a role's trace stores match differently than they
would match the new one.

A role that reaches nothing in a source is told how many containers exist
there, not their names; only an administrator is shown the names.

When a role is edited, the configuration page reports what the change *does* —
which containers it starts and stops reaching, which permissions it adds and
removes, and whether the net effect widens access. An end state is easy to read
and impossible to review: `app-*` and `ap-*` both look deliberate and both
produce a plausible count.

### Permissions

Every permission lives in one catalogue (`src/wdash/permissions.py`), which is
what lets the configuration page offer a checked list rather than a text box. A
name the catalogue does not know is refused rather than stored: a permission
that grants nothing while looking configured is worse than one that was
rejected.

| Permission | Grants |
|---|---|
| `logs:read` | Open the Logs screen, search it, read a record with its context |
| `traces:read` | Open the Traces screen, search it, open a waterfall |
| `dashboard:view` | See and open dashboards |
| `dashboard:create` / `dashboard:edit` / `dashboard:delete` | Manage your own dashboards |
| `system:admin` | The configuration page, the Cluster Advisor, debug endpoints, and editing others' dashboards |

**`system:admin` is not a superuser.** It grants no access to logs or traces on
its own. That has a consequence worth knowing: nothing else can recover from
losing it, so three invariants refuse any change that would leave nobody able
to administer — editing a role's permissions or its groups, deleting a role,
and reassigning yourself through the mappings table. "Would this lock me out?"
is answered by the resolver's own rule, groups and all, applied to the picture
after the change. A refused attempt is recorded alongside the successful ones.

A role something still points at cannot be deleted: the default role, a role a
mapping names, or one a local account holds. Deleting the default role used to
succeed, and the page then showed its first role — `admin` — as the default,
so the next "Save mappings" made everybody unmapped an administrator.

If it happens anyway, `python -m wdash.store.recover --status` says who can
administer and `--grant-admin <username>` puts one account back. The recovery
role grants no data access; it exists to reach the configuration page.
`--set-role <username> <role>` moves a local account to a role that exists —
which is how a role a local account holds is freed to be deleted, since the
page has no control for a local account's role. `--enable <username>` undoes a
disabled account, which `--grant-admin` never did: a disabled account is
refused before its password is checked, so granting it a role was a way back
that could not be taken. `--use-directory <ldap|oidc|none>` writes the
directories' enabled flags, for the one case the page cannot reach — an
installation that had two directories enabled at once, where the losing one
held every administrator. It refuses a directory that cannot be used as it
stands, naming the field that is blank or the secret that cannot be
decrypted, rather than putting it in force and turning off the one that
worked; and a stored row holding nothing but `enabled: false` is read as the
off-switch it is, not as a configuration, so choosing OIDC again restores a
provider configured in the environment.

### Authorization is resolved per request

The session carries identity only — who you are and which groups the provider
asserted. What you may do is read from the metadata store on every request,
cached for a few seconds per worker.

Permissions used to be written into the session cookie at sign-in, which meant
revoking a role saved successfully and changed nothing until the person
happened to sign out: an administrator shown a revocation that did not happen.
A role change now reaches every worker within about ten seconds, with no
coordination between them.

Users are mapped to roles by email, username or identity-provider group, and
anyone unmapped falls back to the default role. A local account's role is
stored with the account and beats every mapping, which is what makes it the way
back in.

### Before you save a role

Boundary fields stay free text, and that is a decision. Containers rotate: a
role granted `app-logs-000001` by name silently loses access the day `-000002`
appears, which is a worse failure than a typo and a much quieter one. Patterns
are what survive rotation, so patterns stay.

The danger was never typing — it was typing blind. So **every field shows what
it matches as you type**, against the containers this installation actually
has, and flags the two outcomes worth flagging:

- **matches nothing** — a valid choice, and also exactly what a typo looks like
- **matches everything** — the dangerous direction. `*` where `app-*` was meant
  saves cleanly and grants the whole cluster, and nothing used to say so.

**browse…** beside each field lists what exists, offering a rotation-proof
pattern first and the exact name as the deliberate alternative.

The matching runs on the server. Reimplementing the pattern language in the
browser would give the product two of them under one name, which is a bug this
codebase has already had once.

Permissions are checkboxes and mapped roles are chosen from a list, for the
same reason: a name that does not exist grants nothing while looking
configured.

Every change to roles, mappings and identity settings is written to
`wdash_audit` with the resulting state, so "what could this role see last
Tuesday" has an answer.

`config/rbac.yaml` is imported once into the database on a fresh installation
and ignored afterwards, so an edit made in the UI is never overwritten by a
restart.

### Who can see which dashboard

**You can see a dashboard if you could see its data.** A dashboard resolving to
no container you may reach is one you could never have used, so hiding it costs
nothing and stops the list advertising what exists — a name like
`payment-fraud-investigation` over `fraud-*` is information whether or not you
can read the index.

That rule needs no new concept and cannot drift out of step with the data
boundary, because it *is* the data boundary. What it cannot express is intent,
so a dashboard can also be marked **private**: the author and administrators
only, even among colleagues with the same access.

Two exceptions, both deliberate. Authors always see their own — otherwise a
dashboard over an index that does not exist yet is invisible to the person who
just wrote it, which reads as "it did not save". And `system:admin` sees every
dashboard, because editing or deleting somebody else's already requires it.

The rule is applied to the list page **and** every dashboard endpoint. Applied
to the list alone it would not be a boundary, only a speed bump. An endpoint
answers 404 rather than 403 for a dashboard you may not see, so the URL is not
a way to find out which ones exist.

The list says how many are hidden rather than leaving a gap — including when
that number is all of them, which is the case where an empty page saying
"create your first dashboard" would be actively misleading.

Dashboards stored before this existed default to shared, so nothing disappears
on upgrade; the boundary rule now applies to them, which is the change.

## Query syntax

```
*                            everything
severity:ERROR               field equals value
body:"connection refused"    exact phrase
service:payment*             prefix
duration_ms:[100 TO 500]     range
_exists_:trace_id            field is present
a AND b   a OR b   a b       combination (whitespace means AND)
NOT a     -a                 negation
(a OR b) AND c               grouping
free text                    searched in the message body
```

Elasticsearch field names are accepted as aliases, so `level:ERROR` and
`severity:ERROR` are equivalent. Queries are parsed into a backend-neutral tree
before execution — syntax errors are reported with a position, before the query
reaches the cluster.

On Loki and VictoriaLogs a level matches however the source wrote it, and
wherever it was written: `level:WARN` finds `warn`, `warning` and `WARN` alike,
in Loki's `level`, `severity` or `detected_level` and in VictoriaLogs' `level`,
`severity`, `log.level` or `severity_text` — the same fields, read in the same
order, that a record's own level is read from.

## Sources and signals

WDash reads from whatever sources are configured. It never collects.

### Searching across sources

The Logs screen offers a source picker once more than one is configured, with
**All sources** fanning out across every one of them in parallel and merging by
time.

The merge is the easy part. What matters is that a backend being down is
*visible*: the page renders from the sources that answered, marks itself
incomplete, and names the one that failed — because fewer rows looks exactly
like less data. And a merged total is reported as a lower bound whenever any
source could not count, since Elasticsearch reports a real match count and Loki
does not.

### Which source answered

Every record carries the name of the configured source that produced it, and
the Logs screen shows it as a badge — but only when more than one source is
configured. A badge repeated on every row that always says the same thing is
noise, and noise is how people stop reading the row footer at all.

A dashboard may name the source it reads from — a **Log source** field on the
create and edit forms, shown once more than one is configured, and stored in
whichever dashboard store is in use. Leaving it on the default is what every
dashboard written before there was a choice means. One naming a source that is
no longer configured reports that plainly instead of falling back to the
default: quietly answering from a different store is how somebody concludes
their data has disappeared. An edit that does not carry the field leaves the
stored source alone, for the same reason — on an installation with one source
the field is not even drawn.

A drill-down from a dashboard that names a source is answered from that
source, and the Logs screen names it in the scope badge and moves its own
source picker to match. The picker was left on its first option while the
server answered from the dashboard's, so the control on screen and the records
under it disagreed.

### OpenTelemetry

WDash reads OpenTelemetry data and does not collect it: an ingest path would
put it in the data path, where being down means losing telemetry rather than
losing a dashboard. The lab runs a real collector
(`./lab.sh up otel`) so the OTel path is exercised rather than assumed — which
is how it was discovered that the schemas had been written against a fixture
that had itself been written from an assumption. See
[docs/opentelemetry.md](docs/opentelemetry.md).

## Cluster Advisor

`/advisor` (requires `system:admin`) inspects the connected cluster read-only
and reports misconfigurations with concrete fixes. It covers shard sizing and
density, mapping problems, cache effectiveness, index lifecycle, JVM and disk
pressure, and security settings.

It can also run headless, which makes it usable in CI:

```bash
PYTHONPATH=src python -m wdash.advisor --url http://localhost:9200
PYTHONPATH=src python -m wdash.advisor --fail-on critical   # exit 1 on findings
```

With `--fail-on` it exits 2 when it could not look at everything, and it
exits 2 in any case when nothing could be evaluated. The cluster's
certificate is checked, against `ELASTICSEARCH_CA_CERTS` when that is set
and the URL is `https://`; `ELASTICSEARCH_VERIFY_CERTS=false` (or `0`, `no`,
`off`) or `--insecure` turns the check off. Any other spelling keeps the
check and says so.

Two checks are specific to how WDash queries data:

- **MAP001** flags fields that WDash aggregates on but that are mapped as
  analysed text — the cause of dashboard panels that render empty.
- **QRY001** flags a near-zero shard request cache hit rate, which usually
  means query time bounds are generated at sub-second precision and every
  request produces a unique cache key.

See [`docs/advisor.md`](docs/advisor.md) for the full rule catalogue and how to
add rules.

## API

Responses use a backend-neutral shape: log records expose `body`, `severity`,
`resource` and `attributes` rather than Elasticsearch's `_source`. A record's
`ref` is a handle (`backend:container:id`); the web client takes the container
and the id from it for the record views below, and sends the record's
`source` as `?source=`.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/search` | Search log records |
| `GET` | `/api/log/<container>/<id>` | Single record, all fields. `?source=` names the source it came from — every record says which — and without it the default source is asked |
| `GET` | `/api/log/<container>/<id>/context` | Surrounding records, from a source that declares the capability; `?source=` as above |
| `GET` | `/api/log/<container>/<id>/raw` | The stored document, backend-shaped (diagnostic); `?source=` as above |
| `GET` | `/api/field-stats` | Field value distributions |
| `GET` | `/api/indices` | Accessible containers |
| `GET` | `/api/saved-searches` | List saved searches |
| `POST` | `/api/saved-searches` | Save a search |
| `DELETE` | `/api/saved-searches/<id>` | Delete a saved search |
| `GET` | `/api/traces` | List traces, optionally by service |
| `GET` | `/api/traces/<trace_id>` | Trace with spans, waterfall and service breakdown |
| `GET` | `/api/traces/<trace_id>/logs` | Log records carrying this trace id |
| `GET` | `/api/traces/services` | Services with span and error counts |
| `GET` | `/api/traces/capabilities` | What the trace backend supports |
| `GET` | `/api/dashboard/<id>/data` | All dashboard panels plus the previous-period comparison, one round trip |
| `GET` | `/api/advisor/report` | Advisor findings |
| `GET` | `/api/advisor/rules` | The rule catalogue |
| `GET` | `/livez` | Whether the process answers; asks nothing else. The liveness and startup probes read it |
| `GET` | `/readyz` | Whether the metadata store answers, which decides whether anybody can be served. The readiness probe reads it |
| `GET` | `/health` | Every backend's reachability and the running version, asked at once and answered within two seconds, then reused for ten. For alerts and people, not probes |

Per-panel dashboard endpoints (`/stats`, `/timeline`, `/log-levels`,
`/services`, `/heatmap`) remain available for API compatibility, but the UI
uses the combined `/data` endpoint.

`/data` also accepts nothing beyond `time_range`; the baseline window is
derived from it (same length, immediately before) and batched into the same
`_msearch`. If that sub-query fails, `previous_period` is `null` — it is never
reported as a real zero, which would render as "-100%, traffic has stopped".

The Logs screen reads `query`, `time_range`, and `start`/`end` from the query
string, which is what makes every chart elsewhere a link into it:

    /logs?query=level:ERROR AND service:"payment-service"&time_range=24h

## Architecture

Backend access goes through a **hub** layer that keeps Elasticsearch specifics
in one place:

```
routes  →  hub (neutral model, neutral query language, Scope)  →  adapters  →  Elasticsearch
```

Three rules hold this together:

1. **The internal model belongs to no backend.** It follows OpenTelemetry
   semantic conventions. Adapters translate on read.
2. **`Scope` is a required argument on every source method.** Because
   authorization lives entirely in the application, forgetting it must be a
   call error rather than a silent data leak.
3. **Capabilities are explicit.** Sources declare what they support; the UI
   does not offer features the backend cannot serve.

[`docs/hub.md`](docs/hub.md) explains the reasoning, the migration history and
what is still outstanding.

## What runs before a merge

`.github/workflows/tests.yml`, in four jobs, because the suite means
different things depending on what is installed beside it:

| Job | What it adds | What it closes |
|---|---|---|
| `suite` | Python 3.11–3.14, node | the whole suite, on every supported version, from a clean checkout |
| `browser` | Playwright and Chromium | the journey and rendered-page tests that otherwise skip |
| `live-schema` | a seeded Elasticsearch | the tests that read both trace schemas |
| `postgres` | Postgres | the whole suite again, every store a Postgres schema, and a SQLite file moved into Postgres |
| `image` | Docker | that the Dockerfile still builds |

The last two refuse to pass by skipping — `WDASH_REQUIRE_LAB=1` turns "no
cluster" from a skip into a failure, and the browser job exits non-zero if
anything was skipped at all. A job that exists to run a test and goes green
because it did not is worse than no job.

`tests/test_ci.py` holds the workflow to what it claims: the version matrix
against the packaging classifiers, the Playwright pin against the image, the
Elasticsearch service against the lab's version.

## Local development

```bash
cd lab && ./lab.sh up && ./lab.sh seed     # sample cluster
python -m tests.run                        # the suite, on every core
python -m unittest discover -s tests -t .  # the same, one after another, as CI runs it
```

`python -m tests.run` runs each test module in a process of its own, as many
at once as there are cores, and learns from each run which modules and
classes to split: about a quarter of a minute on an 18-core machine, against
a minute and a half one after another. `-j N` sets how many at once; module
names narrow it (`python -m tests.run test_store test_identity`).

The same suite on Postgres, with every store it opens a schema of its own in
a database made for the run and dropped after it:

```bash
cd lab && ./lab.sh up postgres
WDASH_TEST_POSTGRES=postgresql://wdash:wdash-lab@localhost:55432/wdash \
    python -m unittest discover -s tests -t .
```

Tests never talk to Elasticsearch. The hub and advisor operate on plain data,
so fixtures are captured cluster snapshots and fake clients. A handful of
integration tests run against the lab when it is up and skip when it is not.

To refresh advisor fixtures after changing the sample data:

```bash
PYTHONPATH=src python -m wdash.advisor --save-snapshot tests/fixtures/lab-cluster.json
```

### The browser bundle

`static/js/wdash.js` is minified to `wdash.min.js`, and **that** is the file
pages load. Editing the source without rebuilding ships nothing:

```bash
npm run build      # or: npx terser static/js/wdash.js -o static/js/wdash.min.js --compress --mangle
```

A stale bundle used to be invisible — the Python suite never loads the
JavaScript, so a completely dead front end passed every test. `tests/
test_frontend_integrity.py` now checks the bundle is current, that every
`this._method()` exists, and that every element id the JS looks up is defined
in some template.

Behaviour is covered by a jsdom suite that opens the log detail modal against
a fake DOM. `package.json` carries the dev tooling — it is not needed to run
WDash, only to work on `static/js`:

```bash
npm install        # jsdom + terser
npm run check      # rebuild the bundle, then run the smoke suite
```

The Python suite runs the smoke suite too, and skips it when jsdom is absent,
so contributors who never touch the front end need no npm at all. It exists
because three faults reached the working tree that no Python test could see and
no parser could catch: a method called three times and never defined, an
undeclared variable, and a JSON highlighter that rewrote `09:30:12` as
`09: 30: 12` while colouring it.

## Project layout

```
src/wdash/
├── app.py              application factory
├── permissions.py      the permission catalogue
├── hub/                backend-neutral READ layer
│   ├── models.py       LogRecord, Span, Trace, Bucket …
│   ├── query.py        LogQuery, TimeWindow (cache-friendly alignment)
│   ├── query_language.py  neutral query parser
│   ├── scope.py        authorization boundary
│   ├── patterns.py     one pattern language, shared by scope and adapters
│   ├── source.py       LogSource / TraceSource interfaces + Capability
│   ├── fanout.py       every source behind one, for merged search
│   ├── factory.py      stored source definitions -> live adapters
│   ├── probe.py        "is this reachable?" for the config page
│   └── adapters/       Elasticsearch (logs + OTel/APM traces), Loki (logs)
├── store/              WDash's own STATE — deliberately not a data source
│   ├── schema.py       users, roles, sources, settings, dashboards, audit
│   ├── rbac.py         resolves a principal to a role, per request
│   ├── secrets.py      encryption at rest; no key means no secret, ever
│   ├── recover.py      getting back in when nobody can administer
│   └── migrate_cli.py  move the JSON files into the database
├── advisor/            cluster configuration checks
│   ├── snapshot.py     read-only collection
│   └── rules/          pure functions over a snapshot
├── api/                HTTP blueprints, including the configuration page
├── auth/               OIDC, LDAP, local accounts, first-run setup
├── dashboard/          panels, thresholds, visibility, system invariants
└── utils/timerange.py  time-range parsing and alignment

kubernetes/             manifests, kustomization, and kubernetes/README.md
lab/                    docker-compose environment, data generator, collector
docs/                   hub, advisor and OpenTelemetry documentation
tests/                  unit tests, adapter conformance suite, fixtures
```

The split that matters: **`hub/` reads observability data, `store/` holds
WDash's own state.** Coupling them is what made dashboards-in-Elasticsearch look
correct right up until Elasticsearch became one source among several.

## Roles and directory groups

A fresh installation has three roles — `admin`, `developer`, `viewer` — mapped
from the directory or OIDC groups `wdash-admins`, `wdash-developers` and
`wdash-viewers`.

The prefix is deliberate. A directory almost certainly has a group called
`admins` already, it usually means domain administrators, and a default that
mapped it to `system:admin` would hand WDash's highest privilege to everyone
in it.

The seeding runs **once**, on an empty installation, importing
`config/rbac.yaml` if it is there. After that the file is ignored and roles
are edited in the UI — an edit made there is never overwritten on the next
restart.

## Versioning

One number, in `src/wdash/__init__.py`. `setup.py` reads it, `package.json`
and the Kubernetes manifests are held to it by `tests/test_version.py`, and
`/health` reports it — so a running instance can be asked which build it is
rather than guessed at.

It had been four numbers that disagreed: the package said `1.0.0` while the
published images had reached `2.2.4`, and the manifests in this repository
deployed `wdash-elastic-dashboard:1.0.0` — five minor versions behind
whatever anybody thought they were running.

Semantic versioning. The Python floor moving from 3.8 to 3.11 is not counted
as a break, because `>=3.8` was never installable: `psycopg` has required
3.10 for as long as it has been pinned here.

## Production notes

- **Set `WDASH_ENCRYPTION_KEY`.** Without it WDash refuses to store secrets at
  all, so the configuration page cannot save OIDC or LDAP credentials. It
  refuses rather than writing them as text, which is the right failure — but it
  is a failure you want to meet before you need the page.
- **Use `DASHBOARD_STORAGE=database` with more than one worker**, and run the
  migration first. The JSON file store reads the whole file, mutates it and
  writes it back, so two workers editing different dashboards lose one of the
  edits — silently, because both writes succeed.
- **Protect the local administrator account.** It is a permanent credential
  that keeps working when the identity provider does not, which is exactly what
  makes it worth stealing.
- Put WDash on the only network path to Elasticsearch. Application-level
  authorization is worthless if the cluster is directly reachable — the
  Advisor's `SEC001` check exists to remind you.
- **Set a real `SECRET_KEY`** and serve over HTTPS with
  `SESSION_COOKIE_SECURE=true`. WDash refuses to start if those two disagree —
  the built-in development key, and every placeholder key this repository has
  ever shipped in `.env.example` or `kubernetes/secrets.yaml`, is printed here
  and signs the administrator's session cookie, so an instance served over TLS
  may not use any of them. `.env.example` now ships the key empty; a `.env`
  copied from an older one still carries the old placeholder and is refused
  the same way. Generate one with
  `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- Enable Elasticsearch security and give WDash a dedicated user.
- Run the Advisor against your cluster before going live.

### Kubernetes

`kubernetes/` installs the server, its database on a volume, the alert
evaluator beside it and a plain `networking.k8s.io/v1` Ingress:

```bash
kubectl apply -k kubernetes/
```

Read [kubernetes/README.md](kubernetes/README.md) first — three values have to
change before that command, and nothing starts until they do. The two secrets
ship empty on purpose, and WDash refuses to start on its built-in development
key while `SESSION_COOKIE_SECURE` is true, so an unfilled Secret fails with a
message instead of quietly signing every session cookie with a string printed
in this repository.

`replicas: 1` and `strategy: Recreate` are the SQLite file, not caution. The
page above says what to change to scale out, and in which order.

### Probes

An agent runs the checks. It pulls its configuration and pushes results back,
so it works behind NAT and restarting WDash misses no check.

```bash
docker build -t wdash .                                  # server, 260MB
docker build -t wdash-browser --target browser .         # + Chromium, 1.77GB

docker run -d wdash-browser \
    --server https://wdash.example.com --token <the agent token>
```

- **Two images, and the small one is the default.** The browser is most of the
  second one and nothing in the first needs it. Anybody running a probe for
  http and tcp checks should use `wdash`.
- **A journey needs a browser agent.** Assign the journey to one. An agent
  with no browser reports nothing for it and says so in its own log, so the
  journey reads `unknown` — "no agent has reported a result for this check" —
  rather than down. A probe that cannot look is not evidence that a checkout
  is broken.
- **Two journeys run at a time per agent.** A Chromium is a few hundred
  megabytes of resident memory, and the agent's normal limit of sixteen
  concurrent checks would be five gigabytes on a host sized for a Python
  process. Http checks keep the wider limit — sockets and memory are bounded
  by different things, and dropping the shared limit to two would make an
  agent with two hundred http monitors a hundred times slower round them.
- **Failure screenshots are kept for a week**, results for thirty days.
  `monitoring.screenshot_retention_days` changes it. "Step 4 failed" a month
  later is still a data point; the picture of a login page from a month ago is
  a megabyte nobody will open.

## Current limitations

Stated plainly, because they affect whether this fits your deployment:

- **The metadata store is new and not yet the default.** Dashboards and saved
  searches still default to the JSON file until an existing deployment has run
  the migration; flipping it silently would leave every stored dashboard
  behind. Migrate with:

  ```bash
  PYTHONPATH=src python -m wdash.store.migrate_cli --dry-run
  PYTHONPATH=src python -m wdash.store.migrate_cli
  # then set DASHBOARD_STORAGE=database
  ```

  With no paths given it reads the file the application itself reads —
  `DASHBOARD_STORAGE_FILE` — and the saved searches beside it, prints both
  absolute paths, and stops with a non-zero exit if a file it is about to
  read is not there rather than reporting "0 moved". Pass
  `--allow-missing-dashboards`, `--allow-missing-searches` or
  `--allow-missing` for both, for a deployment that really has none.

  A saved-searches file nobody named is not required: the application writes
  it on the first save, so its absence means nobody has saved a search, and
  the run says so and carries on. Neither JSON file is required with
  `--from-elasticsearch`, which reads neither.

  The JSON files are left untouched, so the move is reversible.
- **A source saved in the UI is used within a few seconds.** The worker that
  handled the save uses it immediately; the others notice on their next check,
  which is at most five seconds later. Sources from `ELASTICSEARCH_URL` are
  built once and never rebuilt, so a configuration edit never disturbs the
  connections a running query is using.
- **A merged search is first-page only.** Paging a time-ordered merge needs
  every source's cursor advanced together, and each backend's cursor means
  something different — a cursor that silently skips records is worse than no
  paging.
- **A bare container pattern applies to every source.** A role granted `app-*`
  reaches `app-*` in each configured source, so adding a source widens what
  existing roles can see. Writing `source-name:pattern` or excluding with
  `-pattern` avoids it, but the default is the wide one.
- **Tempo returns ids two ways.** Its search endpoint gives hex; its trace
  endpoint gives OTLP JSON, where ids are protobuf `bytes` and therefore
  base64. Both are handled — read as hex, the base64 form produces dangling
  parents and a flat waterfall that looks like missing instrumentation. Like
  Jaeger it reports no per-service volume without a metrics backend, and a
  TraceQL query it cannot parse is surfaced rather than swallowed into an
  empty result.
- **Jaeger cannot answer "every trace".** `GET /api/traces` without a service
  is an HTTP 400, so an unfiltered search is fanned across the service list and
  bounded at 20. It also has no volume aggregation unless a separate metrics
  backend is wired up, so its service list carries names without span counts —
  zero rather than a number derived from a sample of fetched traces.
- **VictoriaLogs serves logs only**, but with more than Loki: it can count
  matches and list field values, so a page total is a real count and the
  field-statistics sidebar is served by the backend. No context view and no raw
  document — `_stream_id` names a stream rather than a line, and returning the
  wrong record is worse than returning none.
- **Loki serves logs only, with fewer capabilities.** No field statistics, no
  context view, no single-record fetch — Loki has neither field mappings nor
  document ids. Those are declared absent rather than returning something
  thinner than the name. Capabilities intersect across a merged search, so
  configuring Loki removes the field-statistics panel from "All sources". The
  source breakdown beside it does not come from a capability and stays. A
  negated group such as `NOT (a b)` is refused with a warning — a chain of line
  filters cannot say OR — and a panel counted by a field that is not a Loki
  label says so rather than drawing an empty chart.
- **WDash does not collect telemetry**, deliberately. Run an OpenTelemetry
  Collector and point WDash at the storage behind it — see
  [docs/opentelemetry.md](docs/opentelemetry.md).
- **A role change takes up to ten seconds to reach every worker.** Each
  process caches the resolved roles briefly. That is a bounded window with no
  coordination between workers, and it replaces the previous unbounded one.
- **Thresholds are not alerting.** They colour the dashboard; there is no
  notification, schedule, silencing or history.
- **Sessions live in the cookie.** Signed, carrying identity only;
  authorization is read from the database on every request. There is no
  session store, and nothing here is waiting for one — a Redis was configured,
  deployed and never read by a line of code, and it has been removed rather
  than left looking like a plan.
- **No CSRF protection.** State-changing endpoints rely on `SameSite=Lax`
  cookies only. Flask-WTF was installed and never initialised — no
  `CSRFProtect(app)` anywhere — while five test configurations set
  `WTF_CSRF_ENABLED = False`, which reads as "switched off for tests" and
  therefore as "on in production". It was never on. The library and the flag
  have been removed so the sentence above is the only thing left saying
  anything about CSRF.
- **Query language is a subset.** Fuzzy matching, boosting and regular
  expressions are not supported; unsupported syntax is rejected rather than
  silently misinterpreted.
- **No metrics signal.** Logs, traces and synthetic monitors. Metrics have a
  genuinely different query model, and a screen that renders Prometheus badly
  would be worse than not having one.
- **A journey is a step list, not a script.** Nine verbs — go to, click, type
  into, expect text, expect URL and so on — rather than arbitrary Playwright
  code. That is a real limit: a journey that needs to compute something cannot
  be written. It buys a journey that can be shown as rows rather than as one
  number, a failure that names the step, and an edit form that is not remote
  code execution on every probe host.
- **An Elastic screenshot is reassembled, and can arrive incomplete.**
  A `monitor.type: browser` check from Heartbeat or the Synthetics
  integration is read down to the individual step — name, outcome, duration,
  the error on the one that broke, and the page as the browser saw it. That
  last one is not a stored image: Elastic writes a reference to 64 tiles and
  the tiles themselves, addressed by content hash and shared across every run
  of every monitor, so WDash fetches the tiles and the browser draws them.
  Two consequences worth knowing before relying on it. Whatever prunes
  `synthetics-browser.screenshot-*` removes tiles that NEWER screenshots
  still point at, and the screen says how many are gone rather than drawing
  the gap. And a step that never ran has no screenshot at all — nothing was
  on screen — so no button is offered for one.

What is planned, and what is missing on purpose, is in
[ROADMAP.md](ROADMAP.md).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) — how to run the suite, what a change is
expected to come with, and the two rules that will fail an otherwise fine
pull request: a dependency has to pass a licence check, and it has to be
imported by something.

## Reporting a vulnerability

[SECURITY.md](SECURITY.md), not a public issue. It also says which
weaknesses are documented trades rather than bugs, so a report can be about
something new.

## Licence

MIT. See `LICENSE`.
