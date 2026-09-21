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
`src/wdash/__init__.py`; `/health` reports it on a running instance.

## 3.0.0 — unreleased

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

### Added

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
