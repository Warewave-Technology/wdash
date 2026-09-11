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

    try:
        response = _get_following(client, monitor["target"], timeout, headers,
                                  credentials, request.get("cookies") or None)
    except Exception as exc:
        elapsed = int((time.monotonic() - clock) * 1_000_000)
        # The certificate is read even though the request failed, and
        # especially then. An EXPIRED certificate makes verification fail —
        # which means the single most important thing the TLS screen has to
        # show is the one case where the check never got far enough to look.
        # A monitor that goes down for a certificate and cannot say which
        # certificate is a monitor that has told you nothing.
        return _result(monitor, started, "down",
                       _redact(_reason(exc), request),
                       duration_us=elapsed,
                       tls=_certificate(monitor["target"], timeout))

    body = b""
    overran = False
    try:
        if assertions.get("body_contains"):
            for chunk in response.iter_content(8192):
                body += chunk
                if time.monotonic() > deadline:
                    overran = True
                    break
                if len(body) >= MAX_BODY:
                    break
        else:
            # Nothing is asserted about the body, but the response still has
            # to be consumed or the timing measures the headers alone — and a
            # server that answers instantly then stalls would look fast.
            for _ in response.iter_content(8192):
                if time.monotonic() > deadline:
                    overran = True
                    break
    except Exception as exc:
        elapsed = int((time.monotonic() - clock) * 1_000_000)
        return _result(monitor, started, "down",
                       _redact(f"reading the response failed: {_reason(exc)}",
                               request),
                       duration_us=elapsed, http_status=response.status_code)
    finally:
        response.close()

    elapsed = int((time.monotonic() - clock) * 1_000_000)
    if overran:
        # Down, and named for what happened: the target answered and then did
        # not finish. No second connection for the certificate — the budget is
        # already spent, and a slow body says nothing about the certificate.
        return _result(monitor, started, "down",
                       f"the response did not finish within {timeout}s",
                       duration_us=elapsed,
                       http_status=response.status_code)
    certificate = _certificate(monitor["target"], timeout)
    failure = _assert_http(response, body, elapsed, assertions)
    return _result(monitor, started, "down" if failure else "up", failure,
                   duration_us=elapsed, http_status=response.status_code,
                   tls=certificate)


#: Hops a check follows before it calls the target down.
MAX_REDIRECTS = 10
_REDIRECTS = (301, 302, 303, 307, 308)


def _origin(url):
    """(scheme, host, port), with the port a scheme implies filled in."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    return scheme, (parts.hostname or "").lower(), (
        parts.port or {"http": 80, "https": 443}.get(scheme))


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


def _get_following(client, url, timeout, headers, credentials, cookies):
    """GET `url`, following redirects by hand.

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
    """
    import requests
    from urllib.parse import urljoin

    home = _origin(url)
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        own = _at_home(home, current)
        response = client.get(
            current, timeout=timeout, stream=True, allow_redirects=False,
            headers=headers if own else {"User-Agent": USER_AGENT},
            auth=credentials if own else None,
            cookies=cookies if own else None)
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


def _reason(exception):
    """A short sentence rather than a repr.

    This ends up on a page as "why is it down", and
    `ConnectionError(MaxRetryError(...))` is not an answer anybody reads.
    """
    import requests

    if isinstance(exception, requests.exceptions.SSLError):
        return f"TLS handshake failed: {_innermost(exception)}"
    if isinstance(exception, requests.exceptions.ConnectTimeout):
        return "timed out connecting"
    if isinstance(exception, requests.exceptions.ReadTimeout):
        return "timed out waiting for a response"
    if isinstance(exception, requests.exceptions.ConnectionError):
        return f"could not connect: {_innermost(exception)}"
    if isinstance(exception, requests.exceptions.TooManyRedirects):
        return "too many redirects"
    return f"{type(exception).__name__}: {exception}"


def _innermost(exception):
    """urllib3 wraps its errors three deep; only the last one says anything."""
    text = str(exception)
    for marker in ("Caused by ", "NewConnectionError(", "SSLError("):
        if marker in text:
            text = text.split(marker, 1)[1]
    return text.strip("()'\" ")[:160]


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
