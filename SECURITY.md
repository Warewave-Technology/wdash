# Security

WDash exists to enforce authorization that the data store underneath it does
not. That makes a bypass in WDash the whole product failing, rather than one
feature of it — so this file is specific about what is a vulnerability here,
what is a documented limitation, and what would only be a finding if the
deployment were built wrong.

## Reporting

**Do not open a public issue for a suspected vulnerability.**

Use GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on this repository. It creates a private thread with the
maintainers and needs no prior contact.

> Maintainers: if you would rather take reports by email, put the address
> here and delete this note. An unanswered channel is worse than one channel.

What helps, in rough order of how much:

* the version — `GET /health` reports it, and it is in
  `src/wdash/__init__.py`;
* which backends are configured, since most of the interesting surface is
  the boundary between WDash and a data source;
* whether the account used was local, OIDC or LDAP;
* a request that shows it. A curl line is worth a page of description.

Expect an acknowledgement within a week. If a report is a vulnerability, the
fix and the advisory go out together; if it is one of the documented
limitations below, you will be told which one and why.

## Supported versions

| Version | Supported |
|---|---|
| 3.0.x | yes |
| < 3.0 | no |

There is one maintained line. A fix is released as a patch version on it.

## The security model, in one paragraph

WDash is designed to be **the only network path to the data stores it reads**.
Every query it issues carries an explicit `Scope` — index patterns for logs,
services for traces — resolved from the signed-in principal's role on every
request. Elasticsearch's free tier has no document- or field-level security,
so that scope is the only thing separating one team's logs from another's. If
the cluster is reachable directly, WDash is a convenience and not a control,
and none of this holds. The Advisor's `SEC001` check exists to say so out
loud.

## In scope

These are vulnerabilities. Report them.

* **Authorization bypass** — any request that returns records outside the
  principal's scope: a container pattern, a service, or a signal (`logs:read`
  vs `traces:read` vs `monitors:read`) that was not granted. This includes
  reaching another source by naming it, and it includes a merged search
  returning what a single-source search would refuse.
* **Authentication bypass** — reaching a `@login_required` route unsigned-in,
  taking another principal's session, or getting the sign-in throttle to
  count somebody else's failures.
* **Escalation** — a role editing itself or another role beyond
  `system:admin`, or a non-admin reaching the configuration page, the audit
  trail or the agent API.
* **Secret exposure** — a source credential, an OIDC client secret, an LDAP
  bind password, an agent token or a journey secret appearing in a response,
  a log line, an error message, an audit row or a screenshot. Secrets are
  encrypted at rest with Fernet and redacted on the way out; a path that
  skips either is a bug.
* **SSRF** — WDash fetches from URLs an administrator configures, and the
  agent fetches from URLs a monitor names. A path that lets a *non-admin*
  cause a fetch to an address they chose is in scope.
* **Injection** — stored XSS through a log record, a trace attribute, a
  monitor name or a journey step. WDash renders other systems' data; a record
  is untrusted input.
* **Audit evasion** — a configuration change, sign-in or lockout that leaves
  no row, or a row that can be edited or deleted from the application.
* **A state-changing request accepted without its CSRF token** — a route, a
  verb or a content type that gets past the check in
  `src/wdash/security.py`.
* **Anything in the agent protocol** — an agent token that reaches
  configuration it was not assigned, or a result that can be attributed to a
  monitor the agent does not own.

## Documented limitations, not vulnerabilities

Each of these is stated in the README already. A report will be closed with a
pointer to it — which is not a dismissal, it is that the trade was made
deliberately and written down.

* **The local administrator is a permanent credential.** It is created at
  first run and keeps working when the identity provider does not, which is
  the point and also what makes it worth stealing. It takes a password AND an
  authenticator code, which is what that is worth.
* **A second factor for a directory account is the directory's job.** WDash
  never sees an LDAP or OIDC password and keeps no row for those principals.
  A TOTP secret it could not tie to anything it authenticates would be a
  second factor in name only.
* **`WDASH_ENCRYPTION_KEY` is required for local sign-in.** The
  authenticator's shared secret is sealed with it, and with no key enrolment
  refuses rather than storing the secret as text — so a deployment with no
  key has directory sign-in and nothing else. Rotating or losing the key
  makes every local account's authenticator unreadable; the way back is
  `python -m wdash.store.recover --reset-totp <username>`.
* **There are no backup codes.** A printed list of one-time codes is a second
  password, kept in the place people keep passwords. The recovery path is an
  administrator, or the recovery tool with database access — which is the
  same bar every other recovery here is held to.
* **Sessions live in the signed cookie**, carrying identity only.
  Authorization is read from the database per request, so a role change takes
  effect at once — but a stolen cookie is valid until it expires. There is no
  server-side session store to revoke.
* **A role change takes up to ten seconds to reach every worker.** Each
  process caches resolved roles briefly; the window is bounded and has no
  cross-worker coordination.
* **A bare container pattern applies to every source.** A role granted
  `app-*` reaches `app-*` in each configured source, so adding a source
  widens what existing roles can see. `source-name:pattern` scopes it.
* **Defaults are development defaults.** `SECRET_KEY` has a placeholder value
  and `SESSION_COOKIE_SECURE` is off until set. Running a deployment on them
  is a deployment fault, not a product one — the README's production notes
  list what has to be set. One case is refused rather than left to the
  operator: any key this repository has printed — the development fallback
  and the placeholders `.env.example` and `kubernetes/secrets.yaml` used to
  ship — with `SESSION_COOKIE_SECURE=true` stops the application from
  starting, because that combination is a TLS deployment signing the
  administrator's session cookie with a string published here.

## What is already in place

So that a report can say what it got past:

* every query carries a `Scope`, resolved per request, failing closed;
* a per-session CSRF token on every state-changing request — a hidden field
  on a form, `X-CSRF-Token` on a `fetch` — refused when it is missing or
  wrong. The check is over the METHOD rather than over a list of routes, so
  it covers a route the day it is written; the one exemption is the agent
  API, which authenticates with a bearer token and no cookie and so has no
  ambient authority for another site to borrow. `tests/test_csrf.py`
  enumerates every state-changing route and every POST form in every
  template, and the suite runs with the protection ON rather than disabling
  it for tests — which is what the Flask-WTF flag that used to sit here did;
* Argon2 for local passwords, SHA-256 for agent tokens, Fernet for stored
  secrets — and a refusal to store a secret at all when no encryption key is
  configured, rather than writing it as text;
* a second factor on every local account, not optional and not a setting:
  RFC 6238 TOTP, implemented out of the standard library in
  `src/wdash/auth/totp.py` and checked against the RFC's own published
  vectors. A correct password starts no session — it holds the sign-in for a
  few minutes, and the hold opens the enrolment page and the code page and
  nothing else, which `tests/test_totp.py` proves by asking every route in
  the url map for it. The shared secret is sealed with the store's SecretBox
  like a source password, is written only once a code has proved it, and is
  never rendered back. A used step is recorded and refused, so a code read
  over a shoulder or off a screen share cannot be replayed. A wrong code is a
  failure through the guard that already throttles password guessing, so one
  set of limits covers both. First-run setup enrols like everybody else: it
  no longer signs the first administrator in;
* local accounts managed from the product, under Authentication on the
  configuration page: an administrator can see who holds one, when it was last
  used, create one, change its role, disable it, reset its password and delete
  it. A password set here is never rendered back and never reaches an audit
  row. The account's role and its enabled flag are read from the store on
  every request rather than from the session cookie, so disabling or demoting
  one takes effect on that person's next request rather than at their next
  sign-in. The installation refuses to be left with no enabled local account
  that can administer, and an administrator cannot demote, disable or delete
  their own;
* sign-in throttling per account, per address and per pair, applied before
  the password is checked so a lockout also stops the guessing — the
  account-wide limit counting guesses only, so an address knocking on a
  locked door cannot lock the owner out everywhere, a directory outage
  counting as no guess at all, and a local account's name never asked of the
  directory, so an outage cannot hide guesses at it;
* an OIDC email trusted only when the provider marks it verified, and only
  for the claim the mark is about; the claims that name a person
  configurable; no provider allowed to sign anybody in under a local
  account's name, nor under an opaque id when the address it sent was not
  verified;
* at most ONE directory signing people in — LDAP or OIDC, never both.
  Ownership here is the username, with no provider attached to it, so with two
  directories open a principal at one who can choose `preferred_username`
  takes a name that belongs to somebody at the other, with its dashboards and
  its role mapping. Enabling the second is refused and audited, an
  installation that already has both is logged, audited (`two directories
  configured`) and banners the configuration page, a resolution that changes
  is audited where it changes, and the sign-in page says in one neutral line
  that another method is configured and not in use. A directory in force whose
  settings cannot be read closes the door rather than handing it to the other
  one. Local accounts are not a directory and none of this touches them;
* `ldaps://` certificates checked, against the system's CAs or a named CA
  file, with turning the check off an explicit and logged choice;
* an append-only audit trail, not deletable from the UI, recording refused
  changes as well as accepted ones;
* a Content-Security-Policy where `script-src` is `'self'` and a
  per-request nonce — no `unsafe-inline`, and no host: a CDN that serves
  whatever anybody publishes, listed there, let one HTML injection load code
  of the attacker's choosing through an iframe's `srcdoc`. `connect-src` is
  `'self'` so an exfiltration attempt has nowhere to send anything, and
  `frame-ancestors` is `'none'`.
  `style-src` DOES allow `'unsafe-inline'`, because a style attribute cannot
  carry a nonce — said plainly here rather than left for a reporter to
  discover;
* Subresource Integrity on every third-party asset, so a substituted CDN
  fails closed rather than serving attacker code under a valid nonce;
* values from logs, traces, monitor documents, agents and backends reach
  the page as text: escaped for the context they land in — an attribute
  needs its quotes escaped, which text escaping does not do — and numbers
  a backend computes are read as numbers or reported as a failed answer;
* failure screenshots kept and served only as the image their bytes say
  they are, whatever type the agent sent, with a policy of their own;
* `X-Frame-Options: DENY`, and HSTS when served over TLS;
* `X-Forwarded-For` ignored unless `TRUSTED_PROXY_COUNT` says how many
  proxies to count in from the right — an unconfigured deployment cannot be
  told its own client's address by that client.
