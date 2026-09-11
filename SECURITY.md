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
| 2.4.x | yes |
| < 2.4 | no |

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
* **Anything in the agent protocol** — an agent token that reaches
  configuration it was not assigned, or a result that can be attributed to a
  monitor the agent does not own.

## Documented limitations, not vulnerabilities

Each of these is stated in the README already. A report will be closed with a
pointer to it — which is not a dismissal, it is that the trade was made
deliberately and written down.

* **No CSRF protection.** State-changing endpoints rely on `SameSite=Lax`
  cookies. There is no CSRF library installed and no flag pretending
  otherwise.
* **The local administrator is a permanent credential.** It is created at
  first run and keeps working when the identity provider does not, which is
  the point and also what makes it worth stealing.
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
* Argon2 for local passwords, SHA-256 for agent tokens, Fernet for stored
  secrets — and a refusal to store a secret at all when no encryption key is
  configured, rather than writing it as text;
* sign-in throttling per account, per address and per pair, applied before
  the password is checked so a lockout also stops the guessing;
* an append-only audit trail, not deletable from the UI, recording refused
  changes as well as accepted ones;
* a Content-Security-Policy where `script-src` carries a per-request nonce
  and no `unsafe-inline`, `connect-src` is `'self'` so an exfiltration
  attempt has nowhere to send anything, and `frame-ancestors` is `'none'`.
  `style-src` DOES allow `'unsafe-inline'`, because a style attribute cannot
  carry a nonce — said plainly here rather than left for a reporter to
  discover;
* Subresource Integrity on every third-party asset, so a substituted CDN
  fails closed rather than serving attacker code under a valid nonce;
* `X-Frame-Options: DENY`, and HSTS when served over TLS;
* `X-Forwarded-For` ignored unless `TRUSTED_PROXY_COUNT` says how many
  proxies to count in from the right — an unconfigured deployment cannot be
  told its own client's address by that client.
