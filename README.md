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
  logs; Elasticsearch, Jaeger and Grafana Tempo for traces. **None of them is
  required**: declare the ones you have on the configuration page, and only
  those. Search one or
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
- **Sign-in** — OIDC *or* LDAP — one directory at a time, never both — and
  local break-glass accounts that keep working when the identity provider does
  not. Every local account needs an authenticator code as well as a password,
  set up at its first sign-in and not optional; directory accounts get their
  second factor at the provider. Repeated failures are throttled per account,
  per address and per pair, and a wrong code is a failure like a wrong
  password. The account-wide limit counts only guesses, so an address knocking
  on a locked door cannot lock the owner out from everywhere else.
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
cp .env.example .env   # then fill in the two keys it asks for
./venv/bin/python main.py
```

Open <http://127.0.0.1:5001>. The installation has no accounts yet, so every
route leads to `/setup`, where you create the administrator.

In a container instead, with the same two keys in the same `.env`:

```bash
cp .env.example .env   # SECRET_KEY and WDASH_ENCRYPTION_KEY
docker compose up -d   # WDash on 5001, and an Elasticsearch to point it at
```

Both keys are refused rather than defaulted: with neither, WDash comes up
and no local account can finish signing in, so `docker compose up` stops
and names the line to fill in. It publishes **5001**, not the 5000 the
container serves on, because macOS answers 5000 with its own AirPlay
receiver — measured here as a `403` from `Server: AirTunes` on a machine
where the container was answering 200.

Then give it the lab: **Configuration → Sources → Add source**, an
Elasticsearch at `http://localhost:9200` serving logs, traces and monitors.
The lab's traces are in `*traces*` and `*apm*` and its synthetic checks in
`heartbeat-*` and `synthetics-*`, which are the defaults the form offers. It
is in use the moment it is saved; nothing about a source is read from the
environment or from `.env`.

The lab holds four more backends — a Loki, a VictoriaLogs, a Jaeger and a
Tempo — and each can be started, filled and added on its own:

```bash
./lab.sh up loki       # that one and nothing else
./lab.sh seed loki     # 2,000 lines over the last 24 hours
./lab.sh targets       # every target: up or not, what is in it, what to type
```

`./lab.sh targets` is the sheet to add sources from. It reports what each one
holds **over the last 24 hours**, which is the window every page opens on: a
lab seeded last week is healthy, full of documents, and blank on screen.

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
>
> **You will be asked to set up an authenticator before you are signed in.**
> Every local account needs one: scan the QR with any TOTP application, or
> type the key it shows beside it, and enter the code. Nothing is stored until
> that code proves you have the key. Set `WDASH_ENCRYPTION_KEY` BEFORE you do
> this — the shared secret is sealed with it, WDash refuses to write a secret
> as plain text, and without a key no local account can finish signing in.

### Two factors, for local accounts only

A password alone is a shared secret that travels: it is typed on other
people's machines, reused, and phished. The local account is also the one that
keeps working when the identity provider does not, which is precisely what
makes it worth stealing — so it takes a code as well.

- **At the first sign-in** the enrolment page shows a QR code, the same secret
  in groups you can type, and the whole `otpauth://` link. An authenticator on
  the same device cannot scan the screen it is on, which is why all three are
  there. The secret does NOT reach the database until a code proves you hold
  it: an unconfirmed secret on an account is a half-enrolled account somebody
  who saw the QR may be able to sign in as.
- **At every sign-in after**, the code page. A step either side of now is
  accepted for clock drift, and a step that has already been used is refused —
  a replayed code is one somebody read over a shoulder or off a screen share.
- **A correct password starts nothing.** It puts the sign-in on hold for a few
  minutes, and the hold opens those two pages and nothing else.
- **A wrong code is a failure** through the same guard that throttles password
  guessing, so the lockout, the backoff and the audit trail cover it too.
- **RFC 6238**, SHA-1, six digits, a thirty-second step: what authenticator
  applications implement. It is implemented in `src/wdash/auth/totp.py` out of
  the standard library — about sixty lines — and checked against the RFC's own
  published vectors in `tests/test_totp.py`.
- **Lost your phone?** An administrator resets it from Authentication → Local
  accounts, and you enrol again at your next sign-in. When nobody can open
  that page, `python -m wdash.store.recover --reset-totp <username>` does the
  same from the command line. Both are audited, and both say what it costs:
  until that account enrols again, its password alone signs it in.
- **Directory accounts are untouched.** WDash never sees an LDAP or OIDC
  password and keeps no row for those principals, so a second factor for them
  belongs at the provider that authenticates them.

`WDASH_ENCRYPTION_KEY` is now required for local sign-in, not just for stored
credentials. The authenticator's shared secret is sealed with it like every
other secret at rest, and with no key the enrolment page refuses and says so
rather than storing it as text. Rotating or losing that key makes every local
account's authenticator unreadable — the way back is `--reset-totp`.

### How setup closes

The check is against the database on every request rather than a flag cached at
startup, so a second worker sees the first worker's administrator immediately.
The account is created under a uniqueness constraint, so two people submitting
the form at the same moment produce one administrator and one clear error
rather than two owners.

Setup does not sign the first administrator in. It used to, which with a
mandatory second factor would have made the account that matters most the one
account that never enrolled — and the bypass would have been one POST away
from anybody who reached an unclaimed installation. It leaves the same hold a
correct password leaves, and the enrolment page is the only thing that hold
opens.

## Configuration

Data sources and identity providers are not environment variables. Every
source — Elasticsearch, Loki, VictoriaLogs, Jaeger, Tempo — is declared on
the configuration page and stored in the metadata database, with its own
credentials and index patterns, and is in use the moment it is saved; so
are OpenID Connect and LDAP, under Authentication. The variables below
configure the process itself.

**A source that holds a credential verifies the certificate.** Over `https`,
turning that switch off means the source is talking to whatever answered,
and WDash would send that credential there on every query — so the save is
refused, and it is refused whether or not the password is typed again.
Retyping used to be the way through, which confused consent with
protection. The remedies are on the page: leave verification on — a private
authority goes in the trust store of the host WDash runs on, which is where
every other client on it will find it too — or tick **Forget the stored
password**. A source with no credential may verify or not as you like, and
a plain `http` source is not what the rule is about, because there is no
certificate in it to check. A synthetic check has had the same rule since
its TLS support was written; it carries its own pasted certificate because
the agent that makes ITS connection runs on somebody else's host.

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Flask session signing key | `dev-secret-key-change-in-production` |
| `FLASK_DEBUG` | `true` turns on Flask's debugger and reloader | `False` |
| `LOGS_PER_PAGE` | Records per page in the log list | `50` |
| `SESSION_COOKIE_SECURE` | Send the session cookie over HTTPS only. Also enables HSTS | `False` |
| `TRUSTED_PROXY_COUNT` | How many reverse proxies sit in front of WDash. `0` ignores `X-Forwarded-For` entirely — trusting it without knowing the depth lets a client name its own address and step around the per-address rate limit | `0` |
| `DASHBOARD_STORAGE_FILE` | The JSON dashboard file: where `DASHBOARD_STORAGE=file` keeps dashboards, where the saved searches sit beside them, and the path the start-up check reads to tell an unmigrated installation what it still has | `data/dashboards.json` |
| `DATABASE_URL` | Metadata store: `postgresql://…` or `sqlite:///…` | `sqlite:///data/wdash.db` |
| `WDASH_ENCRYPTION_KEY` | Encrypts secrets held in the metadata store, including every local account's authenticator. Without it, secrets cannot be saved at all and no local account can sign in | — |
| `DASHBOARD_STORAGE` | Where dashboards **and saved searches** live: `database` (default) or `file`. An installation with JSON files it has not migrated is told at start-up and on the pages themselves, naming both files and the command &mdash; rather than being shown an empty list as though nothing had ever been saved | `database` |
| `MAX_SEARCH_RESULTS` | Upper bound on page size | `1000` |

### Identity providers

OIDC and LDAP are configured on `/admin/config`, under **Authentication**,
and take effect immediately — the client is built per request, which is what
lets an administrator repair a broken provider and try again without a
restart. That page is the only place either is configured: nothing about a
provider is read from the environment, and a provider switched off is off,
even with its settings still filled in.

**Switching one on takes a card that can sign somebody in.** OpenID Connect
needs a client ID, a discovery URL and a client secret; LDAP needs a server
and a base DN, plus a bind password wherever a bind DN names a service
account to bind as. A card missing any of those is refused with the fields
named, on the server and in the browser, and nothing is saved. A card that
is switched OFF may be half-filled — that is a draft somebody is coming back
to — but what IS filled in has to be usable either way: a server address
without `ldap://` or `ldaps://`, or a discovery URL that is not http(s) or
that resolves to a link-local address, is refused whether or not the switch
is on. An empty card with nothing stored behind it is not saved at all; a
card that exists may be blanked, which is how a provider is removed.

Before this, an empty card saved, switched on, reported itself as "in force
now", and refused the other directory as a second one — while every sign-in
through it was declined out of sight, in a log line.

The OpenID Connect card asks the provider for `openid email profile groups`
unless its **Scopes** field says otherwise — `groups` because roles are
mapped from groups, and a provider that gates that claim behind a scope
sends nothing without it; a provider that refuses a scope it does not know
needs the list changed there. A blank **Redirect URI** means this WDash's
own `/auth/callback` as the browser reached it, which is right on a laptop;
behind a proxy that terminates TLS, type the `https://` address and register
the same one at the provider.

**At most one directory.** Either LDAP or OIDC signs people in, never both.
Ownership here is the username — a dashboard belongs to `created_by`, a role
mapping is written against a name — with no provider attached to it, so with
two directories open a principal at one who can choose `preferred_username`
signs in as somebody at the other and gets their dashboards and their role.
Which one is in force is decided in one place, from configuration and not from
usability:

1. both stored and enabled: the row saved most recently wins, ties to LDAP, so
   the answer never depends on row order;
2. one: that one;
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
startup, one `two directories configured` audit row — one for the
installation, not one per worker, and none at all on the restarts
after it while nothing has changed. Measured with four worker
processes, which is what the shipped image runs: four rows before
the write lock was taken ahead of the read, one after, on SQLite
and on Postgres. And a banner on `/admin/config`; a resolution that changes while WDash is running is audited
as `directory in force changed`. Turning off the directory you arrived through
is refused when no enabled local account can administer and no other directory
would take over — a handover to one that is configured and works is the switch
itself, and on an installation with both it is the only direction the page
has, since enabling the second one is refused. Where it does refuse,
`python -m wdash.store.recover --use-directory <ldap|oidc|none>`,
`--enable <username>` and `--grant-admin <username>` are the way back from
outside the application.

**The directory names the person, not the keyboard.** A directory matches
`uid` with caseIgnoreMatch, so `alice`, `Alice` and `ALICE` all sign in.
WDash used to keep whatever was typed, and each of those was a different
person: a different role, because a mapping is compared exactly; different
dashboards, because ownership is `created_by`; and a separate thread
through the audit trail. Measured against OpenLDAP with `alice` mapped to
admin, typing `Alice` landed on the default role, silently. The username is
now read from the attribute the user filter looks people up by — `uid`, or
`sAMAccountName`, or whatever that filter names — and a directory that
returns nothing for it leaves the typed name alone. OpenID Connect never
had this: there the username is a claim the provider sends.

**Upgrading:** somebody who has been signing in as `Alice` against a
directory that holds them as `alice` becomes `alice` on their next
sign-in. That is a different name from the one that owns their dashboards
and saved searches, and nothing moves them: merging two names is a
decision about people rather than about data. A direct mapping written
against the old spelling stops applying and should be rewritten — which is
the same fix as before, since it was not applying to the other spelling
either.

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
OpenID Connect card. A dotted name reaches into an
object (`realm_access.roles`). `email_verified` speaks for the `email` claim
only: another email claim is used only if unverified addresses are trusted.
Ownership and name mappings trust the username claim, so choose one your users
cannot edit. Without a username, the fallback is the verified email, then
`sub` — unless the provider sent an address it did not verify, as ADFS and
Entra v1 tokens do: that sign-in is refused, with a message naming the setting,
rather than signing the person in as an opaque id that owns none of their
dashboards. No provider, OIDC or directory, may sign somebody in under the
name of a local account: that name owns the break-glass administrator's
dashboards. Such a sign-in is refused and audited — checked against the
name the DIRECTORY answers with as well as against the one that was typed,
because a filter matching more than one attribute makes those two different
strings and the second one is the one the session gets. Named nowhere, the claims
are `preferred_username`, `email` and `groups` — unless the installation
imported other names from an rbac.yaml's `claim_mappings` at an earlier
version, which it keeps and goes on using.

### The configuration page

`/admin/config` (requires `system:admin`) holds data sources, the identity
provider settings, local accounts, and roles.

Three rules run through it:

- **Secrets are written, never rendered.** The form shows whether a password is
  set and offers to replace it; it cannot show it. A settings page that renders
  stored credentials is an exfiltration endpoint for anyone who reaches an
  administrator session, which is a much lower bar than reaching the database.

  Which is why a password written into the address — `https://reader:secret@es:9200`
  — is refused. It is a credential arriving through the one box that is stored
  as typed and shown as typed, and it was stored in clear text, printed on this
  page, and exempt from both rules below. Put the user in the username box and
  the password in the password box.
- **A blank credential field means "keep", not "delete".** Otherwise saving the
  page without retyping the password silently breaks the connection.
- **Every change is logged with who made it.** This is the screen that decides
  who can see what.

Source URLs are checked before the server will fetch them: only `http` and
`https`, and never a link-local address — `169.254.169.254` is where cloud
instance metadata lives, and it hands out credentials to anything that asks.
Private and loopback addresses stay allowed, because that is where these
backends actually live.

Roles live in the database, and this page is where they are edited. An
installation with none is given the built-in ones — see "Roles and directory
groups" below — and nothing overwrites an edit made here: not a restart, and
not an upgrade.

#### Local accounts

**Authentication → Local accounts** lists every local account with its role,
whether it is enabled, when it was created and when it last signed in, and can
create one, change its role, disable and re-enable it, reset its password and
delete it. It sits on that tab because that tab is the page's one answer to
"how do people get in"; a role is not a person, which is what Roles & access
is about. Until it existed an account could only be made by first-run setup or
by `python -m wdash.store.recover`, so the break-glass path was the one door
with no window: nobody could see who held an account or that a contractor's
was still enabled.

A password is written and never rendered back — not on the page and not in the
audit trail, which is exported from this same screen. Deleting an account takes
the confirmation every other destructive control here takes.

Each act has its own control, and that is a rule rather than a layout: the
role has a Save, and enabling, disabling, resetting a password, resetting an
authenticator and deleting are each their own button and their own route. The
enabled switch used to be a checkbox on the role form, read as "ticked or
not" — and an unticked checkbox is indistinguishable from an absent one on the
wire, so a submission that never mentioned the switch disabled the account,
flashed "saved", and signed that person out on their next request. A route
that cannot change the enabled state cannot be made to by any request at all,
which a hidden marker beside the checkbox would not have given. The flash and
the audit row name which act it was — `account role changed`, `account
disabled`, `account enabled` — rather than all reading "saved".

The installation refuses to be left without a local account that is enabled and
can administer, and an administrator cannot do it to themselves by demoting,
disabling or deleting their own account. Both are refused with a sentence
naming what would break, an audit row, and nothing saved.

Where a name also has a row under "Direct mappings", each table says so and
says the account's own role wins — because it does, and the two can disagree
with nothing on either page to explain why.

Directory accounts are not listed and cannot be managed here. LDAP and OIDC
principals are authenticated at the provider and have no row in this database
at all; storing a shadow copy would give "what may this person do" two answers
and guarantee they drift apart.

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
| `traces:read` | Open the Traces screen, search it, open a waterfall, and fill a trace panel on a dashboard |
| `monitors:read` | Open the Monitors screen, and fill a monitor or certificate panel on a dashboard |
| `dashboard:view` | See and open dashboards |
| `dashboard:create` / `dashboard:edit` / `dashboard:delete` | Manage your own dashboards |
| `system:admin` | The configuration page, the Cluster Advisor, debug endpoints, and editing others' dashboards |

**A dashboard panel is checked against the same permission its screen is.**
`dashboard:view` opens the board; each panel is filled — or refused with a
sentence, leaving the rest of the board alone — under the permission for the
data it holds. Otherwise a shared dashboard is a way around every one of
them, which a trace panel was: it filled for a role without `traces:read`
while the trace list beside it on the same board said no.

**`system:admin` is not a superuser.** It grants no access to logs or traces on
its own. That has a consequence worth knowing: nothing else can recover from
losing it, so four invariants refuse any change that would leave nobody able
to administer — editing a role's permissions or its groups, deleting a role,
reassigning yourself through the mappings table, and demoting, disabling or
deleting a local account on the accounts card. "Would this lock me out?"
is answered by the resolver's own rule, groups and all, applied to the picture
after the change. A refused attempt is recorded alongside the successful ones.

A role something still points at cannot be deleted: the default role, a role a
mapping names, or one a local account holds. Deleting the default role used to
succeed, and the page then showed its first role — `admin` — as the default,
so the next save made everybody unmapped an administrator.

If it happens anyway, `python -m wdash.store.recover --status` says who can
administer and `--grant-admin <username>` puts one account back. The recovery
role grants no data access; it exists to reach the configuration page.
`--set-role <username> <role>` moves a local account to a role that exists —
the same thing the accounts card does, for the case where nobody can open it.
`--enable <username>` undoes a
disabled account, which `--grant-admin` never did: a disabled account is
refused before its password is checked, so granting it a role was a way back
that could not be taken. `--use-directory <ldap|oidc|none>` writes the
directories' enabled flags, for the one case the page cannot reach — an
installation that had two directories enabled at once, where the losing one
held every administrator. It refuses a directory that cannot be used as it
stands, naming the field that is blank or the secret that cannot be
decrypted, rather than putting it in force and turning off the one that
worked; and a stored row holding nothing but `enabled: false` — which an
earlier version wrote to switch off a provider read from the environment —
is read as the off-switch it is, not as a configuration to put in force.

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
back in — and it is read from the store on every request, like everything else.
It used to be written into the session cookie at sign-in and never read again,
which made the one role that wins the order the one thing still frozen there:
demoting or disabling a local account changed nothing until that person
happened to sign out. An account that is disabled or deleted now stops being
able to do anything on its next request, not at its next sign-in.

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

A dashboard reads **every source** unless it is pinned to one — the same
question the Logs screen asks on its first search — and says which sources
answered: the four stat cards print how much each log source gave, and every
trace and monitor panel names the stores its rows came from, so two stored
rows over one cluster are two names under one number rather than a number
that is quietly double. There is no default source: a search or a board that
names none asks all of them.

A board may be pinned — a **Source** field on the create and edit forms,
offered when there is something to choose, with **All sources** first and
what a new board gets. A pin is the source for *every signal it serves*:
pinned to a cluster that serves logs, traces and monitors, a board reads all
three from that cluster; pinned to a Loki, its logs from the Loki and its
traces and monitors from every source, because the Loki serves neither. The
board's header says which. The pin is stored as the name, and "All sources"
as nothing (the form's empty value; `*`, the search API's spelling of the
same choice, is stored the same way), so a board has one value for it.

One pinned to a source that is no longer configured reports that plainly, on
every panel, instead of falling back to the rest: quietly answering from a
different store is how somebody concludes their data has disappeared. An
edit that does not carry the field leaves the stored source alone, for the
same reason — on an installation with nothing to choose the field is not
even drawn.

What a refresh costs depends on the sources it reads, and the forms say so
where the source is chosen: Elasticsearch answers a whole board in one
request whatever the panel count; Loki and VictoriaLogs are asked once per
log panel plus twice for the stat cards. Measured on the lab, an eight-panel
board over 24 hours is 1 request to Elasticsearch, 10 to Loki and 10 to
VictoriaLogs — 21 per refresh over all three, and only its own source's
share when pinned.

A drill-down from a dashboard is answered from the dashboard's source — the
one it is pinned to, or every source — and the Logs screen names it in the
scope badge and moves its own source picker to match. The picker was left
on its first option while the server answered from the dashboard's, so the
control on screen and the records under it disagreed.

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
PYTHONPATH=src python -m wdash.advisor --url https://es.example:9200 \
    --username wdash --password-file /run/secrets/es --ca-certs /etc/ssl/ca.pem \
    --fail-on critical                                   # exit 1 on findings
```

Everything it needs is on the command line and nothing is read from the
environment: `--url` names the cluster, `--username` with `--password-file`
(a path, or `-` for standard input — never an argument, which `ps` shows)
the credentials, and `--ca-certs` the authority for an `https://` cluster.
With `--fail-on` it exits 2 when it could not look at everything, and it
exits 2 in any case when nothing could be evaluated. The cluster's
certificate is always checked; `--insecure` turns the check off, and the
credentials then go to whoever answers.

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
| `GET` | `/api/log/<container>/<id>` | Single record, all fields. `?source=` names the source it came from — every record says which. Without it the one source there is answers; with several configured the request is refused, as `?source=*` is, because one record lives in one place |
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

Every backend means logs, traces **and** monitors, each asked once however
many signals it serves. The report is one flat object keyed by source name,
so a source whose name is one the report already uses — `store`, `status`,
`version`, `degraded`, `detail` — is reported under `source:<name>` instead,
and two different sources sharing a name get one line between them. Only the
metadata store decides the status code.

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

They are written by a schema migration, version 19, into an installation that
has no roles and into no other — once, under the lock every worker takes at
start-up. An edit made on the configuration page is not overwritten by a
restart or an upgrade, and an installation that already has roles — including
one that imported them from an `rbac.yaml` at an earlier version — keeps
exactly those.

There is no file for bringing roles of your own. Other roles, and other
groups mapped onto them, are made on the configuration page under **Roles &
access**. When nobody can reach that page, `python -m wdash.store.recover`
puts a local account on a role that exists (`--set-role`) or on one that
administers (`--grant-admin`).

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

- **Set `WDASH_ENCRYPTION_KEY` before anybody signs in.** Without it WDash
  refuses to store secrets at all, so the configuration page cannot save OIDC
  or LDAP credentials — and no local account can finish signing in, because
  the authenticator every one of them needs has nowhere safe to live. It
  refuses rather than writing a secret as text, which is the right failure,
  and it is one you want to meet before it is the only door you have. Keep the
  key: rotating or losing it means re-entering every stored credential and
  resetting every authenticator with
  `python -m wdash.store.recover --reset-totp <username>`.
- **Run the migration before upgrading an installation that has JSON files.**
  `DASHBOARD_STORAGE=database` is the default now, so a deployment that never
  set the variable moves with the upgrade. Nothing is deleted and the start-up
  log names both files, but until the migration is run those dashboards and
  saved searches are not on the pages. `DASHBOARD_STORAGE=file` goes on
  reading them, with one worker: the JSON file store reads the whole file,
  mutates it and writes it back, so two workers editing different dashboards
  lose one of the edits — silently, because both writes succeed.
- **Protect the local administrator account.** It is a permanent credential
  that keeps working when the identity provider does not, which is exactly what
  makes it worth stealing.
- **Upgrading: a board or a search that names no source reads every source.**
  It used to read one — whichever was stored first — and on a mixed
  installation that is a different number. Measured on the demo's five
  stored sources over a rolling 24 hours: an unpinned board read 1,115
  records from the Loki alone and now reads 15,431 (13,245 from the
  cluster, 1,066 from the Loki, 1,120 from VictoriaLogs, twenty minutes
  later); its trace list for `api-gateway` was empty, because the oldest
  trace source was a Tempo with no such service, and lists ten traces from
  the cluster now; a bare `/api/search` answered 5 records from the Loki
  and answers 14,353 across all three, with the breakdown. A board
  pinned to a source keeps reading that source, for every signal it serves:
  the demo's board pinned to its cluster drew its trace list from the Tempo
  before and draws it from the cluster now. The cost moves with it — an
  unpinned eight-panel board was 10 requests to the Loki per refresh and is
  1 to the cluster, 10 to the Loki and 10 to VictoriaLogs — and the refresh
  interval and the Source field say so. Pin the boards that should read one
  source; the rest say on screen which sources answered.
- **Upgrading a deployment that declared its cluster in the environment.**
  2.5 and earlier registered an Elasticsearch from `ELASTICSEARCH_URL` and the
  seven variables around it (the credentials, timeout, certificate switch and
  bundle, and the trace and monitor index patterns). Nothing reads them now.
  Before upgrading, add that cluster under **Configuration → Sources** with
  the same index patterns. Without it, the logs, traces and monitors pages
  answer from whatever other sources are stored — or say they have none —
  and a search or a board that names no source reads every stored source,
  so its numbers are every other backend's without the cluster's. A process
  that still has any of the variables
  set says so at start-up, as an ERROR naming them and the page, and reads
  nothing from them — it does not import them, because a one-shot import at
  start-up is the mechanism that was removed. The same goes for the OpenID
  Connect provider, which 2.5 and earlier also read from `OIDC_CLIENT_ID`,
  `OIDC_CLIENT_SECRET`, `OIDC_DISCOVERY_URL` and the six variables around
  them: save the provider on the OpenID Connect card before upgrading, or
  nobody signs in through it until somebody does. Local accounts are
  unaffected either way.
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
- **A TLS setting needs an agent new enough to read it.** "Trust this
  certificate" and "do not verify — expiry only" are sent to every agent
  assigned to the check, and an agent older than this release ignores the
  setting: it verifies against the public roots, so the check stays down with
  the OpenSSL message and no sentence about the box that would answer it.
  Nothing leaks that way — WDash withholds an expiry-only check's headers,
  cookies and credentials before they reach any agent, whatever its version —
  but the setting does nothing until the probe is upgraded. Nothing on the
  Checks table says so yet; the agent's own row reports its version.
- **Failure screenshots are kept for a week**, results for thirty days.
  `monitoring.screenshot_retention_days` changes it. "Step 4 failed" a month
  later is still a data point; the picture of a login page from a month ago is
  a megabyte nobody will open.

  The results clock is a **ceiling** on the screenshot one: a screenshot
  whose result row has been pruned is an image no screen can reach, so
  asking for thirty days of screenshots under seven days of results gets
  seven. Switching result retention off removes the ceiling rather than the
  clock — screenshots are still pruned at their own week.

## Current limitations

Stated plainly, because they affect whether this fits your deployment:

- **Upgrading from the JSON files takes one command.** Dashboards and saved
  searches are kept in the metadata database by default. An installation
  that was running before that — it has a `data/dashboards.json`, and
  perhaps a `data/saved_searches.json` beside it — has not lost anything,
  but nothing is reading those files any more. WDash says so at start-up,
  naming both files, how many records in each the database does not have,
  and the command below; it says nothing when there is no file, when the
  file is empty, or once the records are in.

  The pages say it too, which is where somebody is actually looking: the
  dashboards page carries the count instead of "Create your first dashboard
  to get started", and the saved-search list says how many are in the file
  instead of "No saved searches yet". Both give the path and the command to
  an administrator only, and both go quiet the moment the migration
  finishes, without a restart. Migrate with:

  ```bash
  PYTHONPATH=src python -m wdash.store.migrate_cli --dry-run
  PYTHONPATH=src python -m wdash.store.migrate_cli
  ```

  `DASHBOARD_STORAGE=file` keeps the JSON files, unchanged and supported,
  for a deployment that wants to stay on them. One worker only: the file
  store reads the whole document, changes it and writes it back, so two
  workers editing different dashboards lose one of the edits.

  With no paths given it reads the file the application itself reads —
  `DASHBOARD_STORAGE_FILE` — and the saved searches beside it, prints both
  absolute paths, and stops with a non-zero exit if a file it is about to
  read is not there rather than reporting "0 moved". Pass
  `--allow-missing-dashboards`, `--allow-missing-searches` or
  `--allow-missing` for both, for a deployment that really has none.

  The metadata database it writes into is `DATABASE_URL`, read the way the
  application reads it — `.env` included, which is where `cp .env.example
  .env` leaves it. `--database-url` overrides that; the start-up warning
  deliberately does not print one, because on Postgres that address carries
  a password and the warning goes to the log.

  A saved-searches file nobody named is not required: the application writes
  it on the first save, so its absence means nobody has saved a search, and
  the run says so and carries on. Neither JSON file is required with
  `--from-elasticsearch`, which reads neither.

  The JSON files are left untouched, so the move is reversible.
- **A source saved in the UI is used within a few seconds.** The worker that
  handled the save uses it immediately; the others notice on their next check,
  which is at most five seconds later. The stored sources are swapped as a
  unit and the adapters a running query holds are not closed under it, so a
  configuration edit never disturbs the connections that query is using.
- **A merged search is first-page only.** Paging a time-ordered merge needs
  every source's cursor advanced together, and each backend's cursor means
  something different — a cursor that silently skips records is worse than no
  paging.
- **A bare container pattern applies to every source.** A role granted `app-*`
  reaches `app-*` in each configured source, so adding a source widens what
  existing roles can see. Writing `source-name:pattern` or excluding with
  `-pattern` avoids it, but the default is the wide one.
- **"Slowest" is the slowest of a sample on Jaeger and Tempo.** Neither
  search endpoint takes a sort parameter — both answer newest-first — so the
  ranking happens in WDash, over a pool it asks for (five times the page,
  between 100 and 500 rows). When that pool comes back full there were more
  traces behind it, and the list says so in a line of its own. Elasticsearch
  ranks server-side, so "Slowest" there is the slowest in the window.
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
- **CSRF protection is on, and the suite does not switch it off.** Every
  state-changing request — POST, PUT, PATCH, DELETE — carries a token tied
  to the session, in a hidden field for a form and in `X-CSRF-Token` for a
  `fetch`; without it the request is refused with a 400 and a page that says
  what to do. The guard is over the METHOD rather than over a list of
  routes, so a route written next year is protected before anybody
  remembers it exists, and the one exemption is the agent API, which sends
  a bearer token and no cookie and therefore has no ambient authority to
  borrow. `tests/test_csrf.py` enumerates every state-changing route and
  every POST form in every template.

  This replaces `SameSite=Lax` cookies as the only defence. The history is
  worth keeping: Flask-WTF had been installed and never initialised — no
  `CSRFProtect(app)` anywhere — while five test configurations set
  `WTF_CSRF_ENABLED = False`, which reads as "switched off for tests" and
  therefore as "on in production". It was never on. What is here now is
  WDash's own, about sixty lines in `src/wdash/security.py`, and the suite
  runs with it ON: the test client carries the token the way a browser
  does, so the protection is exercised by four thousand tests rather than
  by the handful that are about it.
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
