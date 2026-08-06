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

#: Where the front end's third-party code comes from. Listing them explicitly
#: is the point: anything not on this list cannot load, including a CDN that
#: gets substituted for another one somewhere down the line.
SCRIPT_SOURCES = ("https://cdn.jsdelivr.net",)
STYLE_SOURCES = ("https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com")
FONT_SOURCES = ("https://cdnjs.cloudflare.com", "data:")


def _policy(nonce):
    return "; ".join((
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}' " + " ".join(SCRIPT_SOURCES),
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
