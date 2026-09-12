"""
What a check actually does.

Two kinds, deliberately. ICMP needs a raw socket and therefore a privileged
container; a browser check needs a browser. Both are real and both are a
decision to make on purpose rather than a type that quietly appears in a
dropdown.

Everything here returns a result rather than raising. A check that cannot run
is a check that failed — that IS the measurement — and an exception escaping
to the scheduler would take the other monitors down with it.
"""

import logging
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

#: Response body read before giving up on a `body_contains` assertion. A
#: monitor is not a downloader: a target streaming a gigabyte should fail the
#: assertion, not fill the agent's memory.
MAX_BODY = 512 * 1024

USER_AGENT = "wdash-agent"

#: The two TLS decisions a monitor can carry. Spelled here rather than
#: imported from the store: the agent runs on its own image, against a server
#: it only talks JSON to, and an unfamiliar value means the same as no value —
#: verify.
VERIFY, EXPIRY_ONLY = "verify", "expiry_only"


def _mode(tls):
    mode = ((tls or {}).get("mode") or VERIFY)
    return mode if mode in (VERIFY, EXPIRY_ONLY) else VERIFY


def _now():
    return datetime.now(timezone.utc)


def _result(monitor, started, status, error="", duration_us=None, **extra):
    return {
        "monitor_id": monitor["id"],
        "started_at": started.isoformat(),
        "status": status,
        "duration_us": duration_us,
        "error": error or "",
        **extra,
    }


def run_check(monitor, session=None):
    """Run one monitor and return a result dictionary.

    `session` lets an http check reuse a connection pool. Not shared between
    monitors on purpose: a pool shared across targets makes one slow host
    hold connections another is waiting for.
    """
    problem = monitor.get("config_error")
    if problem:
        # WDash could not assemble this check — almost always an encryption
        # key that changed, so the credential could not be unsealed. Sending
        # the request anyway measures the missing credential: the target
        # answers 401 and a server that is perfectly healthy is reported
        # broken, for a reason nobody looking at it can act on.
        return _result(monitor, _now(), "down", str(problem))

    kind = (monitor.get("kind") or "").lower()
    if kind == "http":
        return _http(monitor, session)
    if kind == "tcp":
        return _tcp(monitor)
    if kind == "browser":
        # Imported here, not at module scope: the plain agent image has no
        # Playwright, and an import at the top would stop it from running http
        # checks at all.
        from .browser import run_journey
        return run_journey(monitor, secrets=monitor.get("secrets"))
    return _result(monitor, _now(), "down",
                   f"unknown check type '{kind}'")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _http(monitor, session=None):
    import requests

    if session is not None:
        return _http_with(session, monitor)
    # A session of its own for the one check, as `requests.get` would have
    # made: it is what keeps a cookie set during a redirect for the next hop.
    with requests.Session() as client:
        return _http_with(client, monitor)


def _http_with(client, monitor):
    started = _now()
    clock = time.monotonic()
    timeout = monitor.get("timeout_seconds") or 10
    assertions = monitor.get("assertions") or {}
    tls = monitor.get("tls") or {}
    # The address and any credential written into it, separated before
    # anything else looks at either: `requests` keeps `user:password@` in the
    # prepared URL, so a mount prefix built without it never matches and a
    # request given `auth=None` sends it anyway. See `_split_userinfo`.
    target, address_auth = _split_userinfo(monitor.get("target") or "")
    secure = target.lower().startswith("https://")
    # Mounted on this monitor's own origin and nowhere else, so a hop anywhere
    # else gets the session's default adapter and the public roots — the same
    # rule `_at_home` applies to what the check was given to send.
    if secure and _mode(tls) == VERIFY and tls.get("certificate"):
        _trust(client, target, tls)
    # The waiver, likewise bounded to its own origin: "do not verify" was
    # chosen about THIS endpoint, and a redirect somewhere else is asked for
    # as a stranger would ask.
    waive = secure and _mode(tls) == EXPIRY_ONLY

    # The monitor's timeout bounds the whole exchange, not each socket read.
    # What `requests` is given is the wait for the NEXT byte, so a target that
    # sends one inside every window never times out: measured against a server
    # trickling five bytes every 0.2s, a check with `timeout_seconds=1` was
    # still running after 6s and ended only when the server stopped, at 20.2s,
    # reporting `up`. Behind it the agent's round, and with it the heartbeat,
    # waited the same 20s.
    deadline = clock + timeout

    request = monitor.get("request") or {}
    headers = {"User-Agent": USER_AGENT}
    headers.update(request.get("headers") or {})

    auth = request.get("auth") or {}
    credentials = None
    if auth.get("type") == "basic":
        credentials = (auth.get("username") or "", auth.get("password") or "")
    elif auth.get("type") == "bearer" and auth.get("token"):
        headers["Authorization"] = f"Bearer {auth['token']}"
    if credentials is None and address_auth and not waive:
        # What `requests` used to do for itself off the URL, done here so
        # that it is bounded like the rest: the configured boxes win when
        # both are filled, which is the order `prepare_auth` already used,
        # and a check that does not verify sends neither. The store refuses
        # to save that last combination, so a row holding it was hand-edited
        # or written by an older build.
        credentials = address_auth

    # What this check's OWN handshake did, recorded on its own whether or not
    # a certificate could be read afterwards — an http:// target, an agent
    # behind a proxy and an endpoint that closes the second connection all
    # produce no certificate, and those are exactly the runs where the verdict
    # still has to be written. None means "no handshake to make"; False means
    # "not a verified one", which covers the failure path and the waiver.
    verified = False if secure else None
    try:
        response = _get_following(client, target, headers,
                                  credentials, request.get("cookies") or None,
                                  deadline, waive)
    except _Overran as exc:
        # The hops themselves ran the budget out. Named separately from a
        # slow body, because "the response did not finish" about a check that
        # never got a response sends somebody to look at the wrong thing.
        hops = exc.args[0] if exc.args else 0
        return _result(monitor, started, "down",
                       f"the redirects did not finish within {timeout}s "
                       f"({hops} hop(s) followed)",
                       duration_us=int((time.monotonic() - clock) * 1_000_000),
                       tls=_certificate(target, timeout),
                       handshake_verified=verified)
    except Exception as exc:
        elapsed = int((time.monotonic() - clock) * 1_000_000)
        # The certificate is read even though the request failed, and
        # especially then. An EXPIRED certificate makes verification fail —
        # which means the single most important thing the TLS screen has to
        # show is the one case where the check never got far enough to look.
        # A monitor that goes down for a certificate and cannot say which
        # certificate is a monitor that has told you nothing.
        return _result(monitor, started, "down",
                       _redact(_reason(exc, tls), request),
                       duration_us=elapsed,
                       tls=_certificate(target, timeout),
                       handshake_verified=verified)
    if secure:
        # The exchange completed. In verify mode that means a verified
        # handshake with this endpoint; in expiry-only mode it means the
        # opposite, and the point of the whole package is that the two are
        # told apart on the page.
        verified = _mode(tls) == VERIFY

    # The body is read either way. Kept only when something is asserted about
    # it, but always consumed: the timing would otherwise measure the headers
    # alone, and a server that answers instantly and then stalls would look
    # fast.
    keeping = bool(assertions.get("body_contains"))
    body = b""
    read = 0
    overran = late = False
    try:
        for chunk in response.iter_content(8192):
            read += len(chunk)
            if keeping:
                body += chunk
                if len(body) >= MAX_BODY:
                    break
            if time.monotonic() > deadline:
                # Told apart before either is reported: a body that arrived
                # complete and late is a different fact from one that stopped
                # half way, and the second sentence sends somebody looking
                # for a stall that never happened.
                overran = not _all_of_it(response, read)
                late = not overran
                break
    except Exception as exc:
        elapsed = int((time.monotonic() - clock) * 1_000_000)
        return _result(monitor, started, "down",
                       _redact(f"reading the response failed: "
                               f"{_reason(exc, tls)}", request),
                       duration_us=elapsed, http_status=response.status_code,
                       handshake_verified=verified)
    finally:
        response.close()

    elapsed = int((time.monotonic() - clock) * 1_000_000)
    # A body that ended by itself, past the deadline: the loop never had to
    # cut it off, and it is still over the budget the monitor was given.
    late = late or (not overran and time.monotonic() > deadline)
    if overran or late:
        # Down, and named for what happened: the target answered and then
        # either did not finish or finished too late. The certificate is read
        # here as it is on every other down path — `_to_monitor` takes the
        # TLS column from the LATEST result, so leaving it out empties the
        # certificate screen for as long as the target keeps overrunning, and
        # "down, and we cannot tell you which certificate" says nothing.
        return _result(monitor, started, "down",
                       (f"the response did not finish within {timeout}s"
                        if overran else
                        f"the response took {elapsed / 1000:.0f} ms, over the "
                        f"{timeout}s timeout"),
                       duration_us=elapsed,
                       http_status=response.status_code,
                       tls=_certificate(target, timeout),
                       handshake_verified=verified)
    certificate = _certificate(target, timeout)
    failure = _assert_http(response, body, elapsed, assertions)
    return _result(monitor, started, "down" if failure else "up", failure,
                   duration_us=elapsed, http_status=response.status_code,
                   tls=certificate, handshake_verified=verified)


#: Hops a check follows before it calls the target down.
MAX_REDIRECTS = 10
_REDIRECTS = (301, 302, 303, 307, 308)


class _Overran(Exception):
    """The monitor's whole budget went before there was an answer to read.

    Carries the number of hops that were followed, for the message.
    """


def _all_of_it(response, read):
    """Whether the body that arrived is the whole body.

    Only `Content-Length` can settle it. A chunked answer cannot be settled
    without pulling again, which is the one thing there is no budget left for,
    so that one is reported as unfinished — which is what it looks like from
    here.

    Asked at all because a complete answer whose last byte landed a
    millisecond after the deadline used to be reported as "the response did
    not finish within 1s", about a response that finished.
    """
    declared = response.headers.get("Content-Length")
    if declared is None:
        return False
    try:
        return read >= int(declared)
    except (TypeError, ValueError):
        return False


def _origin(url):
    """(scheme, host, port), with the port a scheme implies filled in."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    return scheme, (parts.hostname or "").lower(), (
        parts.port or {"http": 80, "https": 443}.get(scheme))


def _origin_prefixes(url):
    """The mount prefixes that match this target as `requests` prepares it.

    BOTH forms, and that is the whole point. `PreparedRequest.prepare_url`
    does not add the port a scheme implies, so a prefix built from the
    port-filled origin — `https://payments.internal:443/` — never matches the
    ordinary `https://payments.internal/`, and an adapter mounted on it is
    silently never used: the check stays down with the same OpenSSL message
    and the setting the administrator chose does nothing. Measured against
    requests 2.32.5, `Session.get_adapter('https://payments.internal/')`
    returns the DEFAULT adapter for that prefix and the mounted one for
    `https://payments.internal:8443/health` — which is why every port in
    every measurement behind this package was a non-default one until this
    was looked at.

    The written form covers the default port; the port-filled form covers a
    target somebody typed `:443` into. Neither matches another host, another
    port or the other scheme, which is what bounds both settings to the
    monitor's own origin.
    """
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    # Userinfo is NOT stripped by `prepare_url` — measured, `get_adapter` is
    # given `https://svc:P4SS@host/` and matches its prefixes against that.
    # So it is taken out HERE and taken out of the request too
    # (`_split_userinfo`, called before any of this): a prefix carrying a
    # password would match, and put the password in a dictionary key.
    netloc = (parts.netloc or "").lower().rpartition("@")[2]
    if not scheme or not netloc:
        return ()
    prefixes = {f"{scheme}://{netloc}/"}
    if not parts.port:
        implied = {"http": 80, "https": 443}.get(scheme)
        if implied:
            prefixes.add(f"{scheme}://{netloc}:{implied}/")
    return tuple(sorted(prefixes))


def _split_userinfo(url):
    """(the URL with no `user:password@`, (user, password) or None).

    Split at the source, because `requests` treats the userinfo form as a
    place to keep a credential rather than as part of the address, and two
    things follow from that. It has no way to say "no authentication":
    passing `auth=None` makes `PreparedRequest.prepare_auth` fall back to
    `get_auth_from_url`, so a target written `https://svc:P4SS@host/` put a
    real `Authorization: Basic` header on the wire over a connection an
    expiry-only check had deliberately not verified — measured, the listener
    logged `Basic c3ZjOlA0U1NXMFJE`. And `prepare_url` KEEPS the userinfo in
    the prepared URL, so `Session.get_adapter` matches against
    `https://svc:P4SS@host/`: a certificate mounted on the address without
    it was silently never used, which is the same silent-ignore shape as the
    port prefix below.

    Both stop being possible once the address and the credential are two
    things: the URL that goes on the wire never carries one, and the
    credential travels as an argument, through the same `_at_home` gate as
    every other thing this check was given to send.
    """
    from urllib.parse import urlsplit, urlunsplit
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return url, None
    if "@" not in (parts.netloc or ""):
        return url, None
    from urllib.parse import unquote
    return (urlunsplit(parts._replace(
        netloc=parts.netloc.rsplit("@", 1)[-1])),
        (unquote(parts.username or ""), unquote(parts.password or "")))


def _without_userinfo(url):
    """The address alone. What "this check sends nothing" means for a URL."""
    return _split_userinfo(url)[0]


def _trust(client, target, tls):
    """Mount an adapter that trusts the pasted certificate, and only it.

    Trusted EXCLUSIVELY: a certificate is pasted because the endpoint is not
    public, and adding the public roots beside it would let a mis-pasted or
    simply wrong certificate pass through a path nobody meant — the check
    would look like it was working. Measured,
    `ssl.create_default_context(cadata=…)` holds exactly the pasted
    certificates and no public root, PROVIDED `cert_verify` is overridden:
    the stock one loads the system bundle into our context on every request.

    Mounted rather than passed per request because `assert_hostname` is a
    connection-pool argument; a session that has no `mount` — a fake in a
    test, a caller's own object — is left exactly as it was.
    """
    import ssl

    mount = getattr(client, "mount", None)
    if mount is None:
        return False
    import requests.adapters

    pem = tls.get("certificate") or ""
    expected = tls.get("expected_name") or ""

    class Trusting(requests.adapters.HTTPAdapter):
        def cert_verify(self, conn, url, verify, cert):
            # Deliberately nothing. The stock implementation resolves
            # `verify` to the system CA bundle and loads it into the pool's
            # context, so a pasted authority ended up ONE of the trusted
            # roots rather than the only one: measured, a public host still
            # verified through this adapter until this override was added.
            return

        def init_poolmanager(self, *args, **kwargs):
            context = ssl.create_default_context(cadata=pem)
            if expected:
                # urllib3 re-checks the name itself whatever the context
                # says, so turning `check_hostname` off is not enough on its
                # own: measured, a cadata context with check_hostname False
                # still raised "hostname 'localhost' doesn't match". The
                # pool argument is what asserts the name the certificate
                # actually carries. SNI is unchanged — the server still
                # chooses what it would choose for a real client.
                context.check_hostname = False
                kwargs["assert_hostname"] = expected
            kwargs["ssl_context"] = context
            return super().init_poolmanager(*args, **kwargs)

    adapter = Trusting()
    for prefix in _origin_prefixes(target):
        mount(prefix, adapter)
    return True


def _at_home(home, url):
    """Whether a hop to `url` may carry what the monitor was given to send.

    Its own origin may, and so may the one hop nearly every site makes: from
    http:// to https:// on the same host, where the secrets go on encrypted.
    The other way, or to any other host or port, they may not.
    """
    here = _origin(url)
    if here == home:
        return True
    return (home[0], home[2]) == ("http", 80) and here == ("https", home[1], 443)


def _waived(client, url, **kwargs):
    """One hop with verification off, and without silencing the process.

    `verify=False` is the documented way to say this and it does everything a
    CERT_NONE adapter does: measured on this session, the next hop to another
    host still failed with `self-signed certificate`, so the waiver does not
    travel. urllib3 warns once per request, which for a setting somebody
    chose on purpose is a line per check per interval, so the warning is
    filtered HERE — around this call — rather than disabled for the process:
    the agent's own link to WDash has its own `verify` switch, and a
    process-wide `disable_warnings` would silence the one line that says that
    link is unverified.

    `catch_warnings` restores the global filter state on exit, and the agent
    runs checks on threads, so another thread's InsecureRequestWarning could
    be swallowed for the width of this call. A missed log line is the smaller
    cost; the alternative silences that line for ever.
    """
    import warnings

    import urllib3

    with warnings.catch_warnings():
        warnings.simplefilter(
            "ignore", urllib3.exceptions.InsecureRequestWarning)
        return client.get(url, verify=False, **kwargs)


def _get_following(client, url, headers, credentials, cookies, deadline,
                   waive=False):
    """GET `url`, following redirects by hand, inside one deadline.

    Every hop is given what is LEFT of the check's budget rather than the
    whole of it. Handing each one the full timeout made the timeout a
    per-hop figure: measured against a server that redirected ten times,
    sleeping 0.8s before each answer, a check with `timeout_seconds=1`
    returned after 8.9s — and a target that writes its own Location headers
    chooses that multiplier itself.

    Redirects are followed, because a monitor that reports 301 as a failure
    reports every site that moved to https as down. But `requests` follows
    them with the request's own headers and cookies, and on a change of host
    strips only `Authorization`: a target that redirected elsewhere — a
    sign-in page on another domain, a CDN, an open redirect — was handed the
    monitor's sealed X-Api-Key, X-Auth-Token and cookie.

    So what the monitor was given to send goes to its own origin and nowhere
    else (see `_at_home`); a hop anywhere else is asked for as a stranger
    would ask. Cookies a site sets on the way are kept by the session, which
    scopes them to the host that set them.

    `waive` — the monitor's "expiry only" — is bounded by the same rule and
    for the same reason: not verifying was chosen about THIS endpoint, and a
    redirect to a sign-in page on another host is asked for with the public
    roots like anybody else's.
    """
    import requests
    from urllib.parse import urljoin

    home = _origin(url)
    current = url
    for hop in range(MAX_REDIRECTS + 1):
        left = deadline - time.monotonic()
        if left <= 0:
            raise _Overran(hop)
        own = _at_home(home, current)
        if waive and own:
            # The one hop this check does not verify carries NOTHING, and a
            # password in the address is the channel no `auth=None` can
            # close: `requests` reads it back off the URL. Taken out of the
            # URL itself, which is the only place it can be taken out of.
            current = _without_userinfo(current)
        options = dict(
            # Never zero: a timeout of 0 is "no timeout" to `requests`, which
            # is the opposite of what a spent budget means.
            timeout=max(0.1, left), stream=True, allow_redirects=False,
            headers=headers if own else {"User-Agent": USER_AGENT},
            auth=credentials if own else None,
            cookies=cookies if own else None)
        response = (_waived(client, current, **options) if (waive and own)
                    else client.get(current, **options))
        location = response.headers.get("location")
        if response.status_code not in _REDIRECTS or not location:
            return response
        response.close()
        current = urljoin(current, location)
    raise requests.exceptions.TooManyRedirects(
        f"more than {MAX_REDIRECTS} redirects")


def _assert_http(response, body, elapsed_us, assertions):
    """The first thing that is wrong, or "" when nothing is.

    Returns the reason rather than a boolean: "down" without a reason sends
    somebody to look at a target that may be answering perfectly.
    """
    expected = assertions.get("status") or [200]
    if isinstance(expected, int):
        expected = [expected]
    if response.status_code not in expected:
        return (f"received status code {response.status_code}, "
                f"expected {', '.join(str(s) for s in expected)}")

    needle = assertions.get("body_contains")
    if needle:
        try:
            text = body.decode(response.encoding or "utf-8", "replace")
        except Exception:
            text = str(body)
        if needle not in text:
            return f"the response body does not contain {needle!r}"

    # Response headers. Two checks, because they answer different questions:
    # "did the proxy add a request id at all" and "is this JSON".
    for name in (assertions.get("headers_present") or ()):
        if name not in response.headers:
            return f"the response has no {name} header"

    for name, expected in (assertions.get("headers_match") or {}).items():
        actual = response.headers.get(name)
        if actual is None:
            return f"the response has no {name} header"
        # Substring, not equality. `Content-Type: application/json` arrives as
        # `application/json; charset=utf-8` from half the servers in the
        # world, and a monitor that calls that a failure is a monitor somebody
        # turns off.
        if str(expected) not in actual:
            return (f"{name} is {actual!r}, which does not contain "
                    f"{str(expected)!r}")

    ceiling = assertions.get("max_duration_ms")
    if ceiling and elapsed_us > int(ceiling) * 1000:
        return (f"answered in {elapsed_us / 1000:.0f} ms, "
                f"over the {ceiling} ms limit")
    return ""


#: Header names whose value must never reach a stored error message. A check
#: that fails against an authenticated endpoint puts its exception on a page
#: any reader of the Monitors screen can see.
_SECRET_IN_MESSAGES = ("authorization", "proxy-authorization", "cookie",
                       "x-api-key", "x-auth-token", "api-key", "set-cookie")


def _redact(text, request=None):
    """Remove anything that came out of the request's credentials.

    urllib3 puts the failing request into some of its exceptions, and
    `requests` will happily render a header dictionary into one. The error is
    shown on the Monitors page and stored in the results table, so a leak here
    is a credential in a table people read.
    """
    text = str(text)
    for value in _credential_values(request):
        if value and len(value) > 3:
            text = text.replace(value, "***")
    return text


def _credential_values(request):
    request = request or {}
    for name, value in (request.get("headers") or {}).items():
        if name.lower() in _SECRET_IN_MESSAGES:
            yield str(value)
    for value in (request.get("cookies") or {}).values():
        yield str(value)
    auth = request.get("auth") or {}
    for key in ("password", "token"):
        if auth.get(key):
            yield str(auth[key])


#: What OpenSSL says when nothing the check trusts vouches for the chain.
#: Both spellings: OpenSSL 3 hyphenates, 1.1 does not.
_UNTRUSTED = ("self-signed certificate", "self signed certificate",
              "unable to get local issuer certificate")

#: And when the chain is fine but the name is not. The third is urllib3's own
#: wording from `assert_hostname`, which is not an OpenSSL message at all.
_MISNAMED = ("hostname mismatch", "ip address mismatch", "doesn't match")


def _tls_advice(reason, tls):
    """The one sentence that names the setting THIS failure is answered by.

    Appended only to the reasons it actually answers. Measured, the four
    common TLS failures are distinguishable from the message:

        unable to get local issuer certificate   nothing local vouches for it
        self-signed certificate                  the same, for one certificate
        Hostname/IP address mismatch             trusted, wrong name
        certificate has expired                  the expiry IS the finding

    An expired certificate gets NOTHING appended. "Set the check to expiry
    only" against `certificate has expired` is advice to switch verification
    off in order to stop seeing an expiry — the one thing the TLS screen
    exists to show.
    """
    if _mode(tls) != VERIFY:
        # It was not verifying; whatever went wrong, the setting is not it.
        return ""
    text = (reason or "").lower()
    pasted = bool((tls or {}).get("certificate"))
    if any(marker in text for marker in _UNTRUSTED):
        if not pasted:
            return (" — this check verifies the certificate, and nothing it "
                    "trusts vouches for this one. Name the certificate to "
                    "trust (the endpoint's own, or the authority that signed "
                    "it), or set the check to expiry only.")
        return (" — the certificate this check was told to trust did not "
                "sign the one this endpoint presented.")
    if any(marker in text for marker in _MISNAMED) and pasted:
        if not (tls or {}).get("expected_name"):
            return (" — the certificate is trusted and does not name this "
                    "address. Type the name it carries into 'Expected "
                    "certificate name'.")
    return ""


def _reason(exception, tls=None):
    """A short sentence rather than a repr.

    This ends up on a page as "why is it down", and
    `ConnectionError(MaxRetryError(...))` is not an answer anybody reads.

    `tls` is the monitor's own TLS setting, so a handshake failure can say
    which setting would answer it — the moment somebody needs to know the
    setting exists is the moment it has just failed, not a form they were not
    looking at.
    """
    import requests

    if isinstance(exception, requests.exceptions.SSLError):
        inner = _innermost(exception)
        return f"TLS handshake failed: {inner}{_tls_advice(inner, tls)}"
    if isinstance(exception, requests.exceptions.ConnectTimeout):
        return "timed out connecting"
    if isinstance(exception, requests.exceptions.ReadTimeout):
        return "timed out waiting for a response"
    if isinstance(exception, requests.exceptions.ConnectionError):
        return f"could not connect: {_innermost(exception)}"
    if isinstance(exception, requests.exceptions.TooManyRedirects):
        return "too many redirects"
    return f"{type(exception).__name__}: {exception}"


#: How much of the innermost error is kept. Long enough for every OpenSSL
#: reason; short enough that a page is not a wall of urllib3.
_REASON_LIMIT = 160


def _innermost(exception):
    """urllib3 wraps its errors three deep; only the last one says anything.

    Ends on a whole word and never on half a bracket, because a sentence is
    appended to this. Two ways it used not to. The wrapper strip takes the
    closing parenthesis of `(_ssl.c:1081)` with the brackets urllib3 nested
    around it, and the 160-character cap lands mid-token on the longer
    messages — measured, both produced

        ...self-signed certificate (_ssl.c:1081 — this check verifies the
        certificate, and nothing it trusts vouches for this one.

    where the advice reads as a continuation of a half-written line number.
    The line number is OpenSSL's own source file and answers nothing, so
    what is left is the sentence and then the advice.
    """
    text = str(exception)
    for marker in ("Caused by ", "NewConnectionError(", "SSLError("):
        if marker in text:
            text = text.split(marker, 1)[1]
    text = text.lstrip("('\" ")
    # The brackets urllib3 nested around the message, and NOT the ones the
    # message itself uses: a plain strip took the `)` of `(_ssl.c:1081)` with
    # them and left the reason ending on half a bracket. A closing bracket
    # that has an opening one to belong to stays.
    while text and text[-1] in ")'\" ":
        if text[-1] == ")" and text.count(")") <= text.count("("):
            break
        text = text[:-1]
    if len(text) > _REASON_LIMIT:
        cut = text[:_REASON_LIMIT]
        # Back to the last space, and no further: a single unbroken token
        # longer than the limit has no boundary to find, and returning ""
        # for it would turn a long reason into no reason at all. This is
        # also what drops `(_ssl.c:1028` — one token, no spaces in it —
        # rather than leaving the advice to read as its continuation.
        text = cut.rsplit(" ", 1)[0] if " " in cut else cut
    return text.rstrip(" ,;:-—")


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def _certificate(url, timeout):
    """The certificate on the wire, in the neutral shape.

    Fetched with a second connection rather than read off the request, because
    `requests` does not expose the peer certificate through its public API and
    reaching into the adapter's socket breaks on every release.

    Returns None on any failure. A certificate that cannot be read is not a
    reason to fail the check — the check already answered the question it was
    asked, and reporting a TLS read error as a downtime would be reporting the
    agent's limitation as the target's.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None

    host = parsed.hostname
    port = parsed.port or 443
    try:
        # Verification off ON PURPOSE, and only here: the point is to read
        # what the endpoint presents, including a certificate that is expired
        # or self-signed. Those are exactly the ones worth reporting, and a
        # verifying connection would refuse to show them. Whether the
        # certificate is TRUSTED is a separate question the http check above
        # already answered by connecting.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                # ONLY the binary form. `getpeercert()` returns an EMPTY
                # dictionary when verify_mode is CERT_NONE — Python parses the
                # certificate for the caller only when it verified it. Reading
                # the parsed form here produced a certificate with no common
                # name and no expiry, which is worse than none at all: the TLS
                # tab would show a row that says nothing.
                binary = tls.getpeercert(binary_form=True)
    except Exception as exc:
        logger.debug(f"could not read the certificate for {url}: {exc}")
        return None

    return _describe(binary)


def _describe(binary):
    """Parse the DER into the neutral Certificate shape.

    Parsed here rather than taken from `getpeercert()`, which is empty without
    verification — and verification is off on purpose, because an expired or
    self-signed certificate is exactly the one worth reporting.

    `cryptography` is already a dependency (Fernet, in the secret box), so
    this adds nothing to install.
    """
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if not binary:
        return None
    try:
        certificate = x509.load_der_x509_certificate(binary)
    except Exception as exc:
        logger.debug(f"could not parse the certificate: {exc}")
        return None

    def name(value, attribute):
        try:
            found = value.get_attributes_for_oid(attribute)
        except Exception:
            return ""
        return found[0].value if found else ""

    key = certificate.public_key()
    algorithm, size, curve = "", 0, ""
    if isinstance(key, rsa.RSAPublicKey):
        algorithm, size = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        # ECDSA carries a curve and no size. Reporting the missing size as 0
        # rendered "ECDSA-0" on the certificate screen, which is not a key —
        # the same trap the Heartbeat adapter fell into.
        algorithm, curve = "ECDSA", key.curve.name
    else:
        algorithm = type(key).__name__.replace("PublicKey", "")

    return {
        "common_name": name(certificate.subject, x509.oid.NameOID.COMMON_NAME),
        "issuer": (name(certificate.issuer, x509.oid.NameOID.COMMON_NAME)
                   or name(certificate.issuer,
                           x509.oid.NameOID.ORGANIZATION_NAME)),
        "not_before": _utc(certificate).get("before"),
        "not_after": _utc(certificate).get("after"),
        "fingerprint": hashlib.sha256(binary).hexdigest(),
        "serial_number": str(certificate.serial_number),
        "key_algorithm": algorithm,
        "key_size": size,
        "key_curve": curve,
        "signature_algorithm": (certificate.signature_algorithm_oid._name
                                if certificate.signature_algorithm_oid else ""),
    }


def _utc(certificate):
    """`not_valid_before/after` in UTC, whichever property this version has.

    cryptography 42 deprecated the naive properties in favour of `_utc` ones
    and warns on the old names. Both are read so the agent works either side
    of that release rather than filling the log with warnings on one of them.
    """
    def read(new_name, old_name):
        value = getattr(certificate, new_name, None)
        if value is None:
            value = getattr(certificate, old_name, None)
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    return {"before": read("not_valid_before_utc", "not_valid_before"),
            "after": read("not_valid_after_utc", "not_valid_after")}


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

def _tcp(monitor):
    host, _, port = monitor["target"].rpartition(":")
    started = _now()
    clock = time.monotonic()
    try:
        with socket.create_connection(
                (host, int(port)), timeout=monitor.get("timeout_seconds") or 10):
            elapsed = int((time.monotonic() - clock) * 1_000_000)
    except socket.timeout:
        return _result(monitor, started, "down", "timed out connecting",
                       duration_us=int((time.monotonic() - clock) * 1_000_000))
    except Exception as exc:
        return _result(monitor, started, "down",
                       f"could not connect: {exc}",
                       duration_us=int((time.monotonic() - clock) * 1_000_000))

    ceiling = (monitor.get("assertions") or {}).get("max_duration_ms")
    if ceiling and elapsed > int(ceiling) * 1000:
        return _result(monitor, started, "down",
                       f"connected in {elapsed / 1000:.0f} ms, "
                       f"over the {ceiling} ms limit", duration_us=elapsed)
    return _result(monitor, started, "up", duration_us=elapsed)
