"""
Response headers, and the reasoning behind each one.

None of these were set. A browser given no instructions makes the permissive
choice every time, so the absence of a header is a decision — just not one
anybody made on purpose.

The Content-Security-Policy is the one worth reading carefully, because its
value depends entirely on what it does NOT allow.

Scripts are nonce-based. Every `<script>` in this application carries a
per-response nonce, so an injected `<script>` — which cannot know the nonce —
does not run. That is the protection; a policy with `'unsafe-inline'` for
scripts would list the same directives and stop nothing.

Styles are not. 121 `style="…"` attributes are spread through the templates,
and a nonce cannot cover a style attribute at all — only `'unsafe-inline'`
does. So `style-src` is honest about being permissive rather than pretending
otherwise. The residual risk is defacement and data exfiltration through CSS
selectors, not script execution, which is why this is the compromise to take
rather than the other one.

`frame-ancestors 'none'` is what stops the configuration page being framed by
another site and clicked through invisibly. `base-uri 'self'` stops an injected
`<base>` tag redirecting every relative URL on the page, which is a way to turn
a single HTML injection into a full script hijack even under a nonce policy.
"""

import secrets

#: Hosts scripts may load from beyond the nonce: none. It listed
#: cdn.jsdelivr.net, which serves any npm package or GitHub file anybody
#: publishes, and a host in script-src stays in force beside a nonce. So one
#: HTML injection was one `<iframe srcdoc>` away from running code of the
#: attacker's choosing on WDash's origin — measured in Chromium. The CDN
#: scripts WDash does load carry the nonce, which admits them wherever they
#: come from, and their integrity hashes, which admit only their bytes.
SCRIPT_SOURCES = ()
STYLE_SOURCES = ("https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com")
FONT_SOURCES = ("https://cdnjs.cloudflare.com", "data:")


def _policy(nonce):
    return "; ".join((
        "default-src 'self'",
        " ".join(("script-src", "'self'", f"'nonce-{nonce}'") + SCRIPT_SOURCES),
        # See the module docstring: style attributes cannot carry a nonce.
        "style-src 'self' 'unsafe-inline' " + " ".join(STYLE_SOURCES),
        "font-src 'self' " + " ".join(FONT_SOURCES),
        # data: for the charts, which draw to a canvas and export images.
        "img-src 'self' data:",
        # The front end talks to this origin only. An exfiltration attempt has
        # nowhere to send anything.
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ))


def nonce():
    """This request's script nonce, created on first use.

    Deliberately not a `before_request` hook. Flask stops running those the
    moment one returns a response, and this application has hooks that do —
    the first-run setup guard redirects every route to `/setup`. Registered as
    a hook, the nonce was never issued for exactly those responses, so the
    policy silently vanished from every redirect and every error page.

    16 bytes: it only has to be unguessable within one response.
    """
    from flask import g
    value = getattr(g, "csp_nonce", None)
    if value is None:
        value = secrets.token_urlsafe(16)
        g.csp_nonce = value
    return value


#: What a state-changing request must carry a token for. GET is not here:
#: a route that changes something on a GET is a bug of its own, and pinning
#: the list to the verbs is what makes a new POST route protected before
#: anybody remembers it exists.
GUARDED_METHODS = ("POST", "PUT", "PATCH", "DELETE")

#: Blueprints exempt by NAME, and the only one there is.
#:
#: An agent sends a bearer token and no cookie, so there is no ambient
#: authority for another site to borrow — which is the whole of what this
#: protects. It also has no session to put a token in, and no browser to
#: read one back out of a page.
EXEMPT_BLUEPRINTS = ("agent",)

#: Endpoints exempt by name. Empty, and a list rather than nothing so the
#: test that enumerates every route has something to hold: an exemption is
#: a decision somebody writes down here, next to the reason.
EXEMPT_ENDPOINTS = ()

#: Where the browser sends it back. The form field for a form, the header
#: for `fetch`.
FIELD = "csrf_token"
HEADER = "X-CSRF-Token"


def token():
    """This session's CSRF token, created on first use.

    In the signed session cookie, which is where this application keeps
    identity — so it travels with the session, cannot be read by another
    origin, and is invalidated by the same sign-out.

    Nothing rotates it explicitly, and there is no `rotate()` here to call:
    `session.clear()` is what sign-in, the authenticator hold and sign-out
    already do, and it takes this with it. A second mechanism beside that
    one would be a thing to keep in step with it.

    32 bytes: it has to survive being guessed at for the life of a session
    rather than for one response, which is why it is not the CSP nonce.
    """
    from flask import session
    value = session.get(FIELD)
    if not value:
        value = secrets.token_urlsafe(32)
        session[FIELD] = value
        # The session is only written when Flask sees it change; assigning
        # to it is that change, and `modified` says so for the cases where
        # the object is mutated rather than replaced.
        session.modified = True
    return value


def submitted(request):
    """The token this request carries, from wherever it put it."""
    return (request.form.get(FIELD)
            or request.headers.get(HEADER)
            or "")


def _exempt(request):
    blueprint = (request.blueprint or "").split(".")[0]
    return (blueprint in EXEMPT_BLUEPRINTS
            or request.endpoint in EXEMPT_ENDPOINTS)


def install_csrf(app):
    """Refuse a state-changing request that does not carry the token.

    Deny by default, over the METHOD rather than over a list of routes:
    there are forty-one POST routes here and a list of them is a list
    somebody forgets to add to. An exemption is written into the two tuples
    above, where it is visible and where a test enumerates it.

    Nothing was here at all. The application relied on `SameSite=Lax`
    cookies, which is a real defence and a single one: it is a browser
    default a deployment can lose (a proxy that rewrites the cookie, an
    older browser, a `GET`-shaped state change), and it protects nothing
    against a same-site subdomain. The README said so plainly rather than
    claiming otherwise, which is how this came to be the next thing to fix
    rather than a surprise.
    """

    @app.context_processor
    def _expose_token():
        return {"csrf_token": token}

    @app.before_request
    def _check():
        from flask import jsonify, render_template, request

        if request.method not in GUARDED_METHODS or _exempt(request):
            return None

        expected = request.cookies and token()
        given = submitted(request)
        if expected and given and secrets.compare_digest(str(expected),
                                                         str(given)):
            return None

        # Logged, not audited. An audit row is a write, and this is the one
        # refusal an unauthenticated stranger can produce at will — a rule
        # that hands them a row per request is a way to fill the table.
        from .store.signin import client_address
        # The CLIENT's address, through the proxy count this deployment is
        # configured with — the same helper the sign-in throttle, the audit
        # trail and every other log line here use. `request.remote_addr` is
        # the last hop, which behind an ingress is the ingress: one address
        # for every refusal, on the one rule an unauthenticated stranger can
        # produce at will. The comment above argues for the stranger being
        # identifiable; this was the line that stripped them out.
        app.logger.warning(
            f"CSRF token missing or wrong for {request.method} {request.path}"
            f" from {client_address(request, app.config.get('TRUSTED_PROXY_COUNT', 0))}")
        if request.accept_mimetypes.best == "application/json" or (
                request.path.startswith("/api/")):
            return jsonify({"error": "This request did not carry a valid "
                                     "security token. Reload the page and "
                                     "try again."}), 400
        return render_template("csrf.html"), 400


def install(app):
    """Add the headers, and make the nonce available to templates."""

    @app.context_processor
    def _expose_nonce():
        return {"csp_nonce": nonce()}

    @app.after_request
    def _headers(response):
        response.headers.setdefault("Content-Security-Policy", _policy(nonce()))

        # Redundant with frame-ancestors for current browsers, and the reason
        # to keep it is the browsers that are not current.
        response.headers.setdefault("X-Frame-Options", "DENY")
        # Stops a response being reinterpreted as a script or a stylesheet
        # because its bytes happen to look like one.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        # A log query can contain a customer identifier, an account name or a
        # token somebody pasted in to find it. Full URLs must not travel to
        # another origin in a Referer header.
        response.headers.setdefault("Referrer-Policy",
                                    "strict-origin-when-cross-origin")
        # Nothing here uses any of these, so refuse them rather than leaving
        # the decision to whatever a future embedded page asks for.
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()")

        # Only when the deployment says it is behind TLS. Sent otherwise, it
        # would lock a plain-HTTP installation out of its own hostname.
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains")

        return response
