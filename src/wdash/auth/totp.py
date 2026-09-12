"""
Time-based one-time passwords, RFC 6238.

Written out rather than taken from a library, and it is about sixty lines:
HMAC-SHA-1 over a counter, the dynamic truncation of RFC 4226, modulo ten to
the sixth. The standard library has every piece. A dependency here would be a
third party in the authentication path for an algorithm whose whole
specification fits on two pages — and one whose correctness is checkable
against published vectors, which `tests/test_totp.py` does. An implementation
with no vectors behind it is a guess.

SHA-1, six digits, a thirty-second step. Not a preference: it is what
authenticator applications implement, and an otpauth:// URI naming anything
else is scanned happily by some of them and silently produces codes that never
match. RFC 6238 defines SHA-256 and SHA-512 variants; there is nowhere to use
them until the applications do.

Two things this refuses that a naive version accepts:

  * a code from a step that has already been used. A replayed code is a code
    somebody read over a shoulder, off a screen share, or out of a phishing
    page thirty seconds ago. `after` is the last step an account accepted, and
    nothing at or below it is accepted again.
  * a code from the wrong shape of input. Length and digits are checked before
    any comparison, so "123456 " and "12345" cannot reach the HMAC at all.

Clock drift is allowed one step either way, which is the RFC's own
recommendation: thirty seconds of skew is ordinary on a phone, and refusing it
produces a second factor that works for most people most of the time.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

#: What every authenticator application implements. See the module docstring.
DIGITS = 6
STEP = 30
ALGORITHM = "SHA1"

#: How many steps either side of now are accepted, for clock drift.
DRIFT = 1

#: 160 bits, which is what RFC 4226 requires as a minimum and what the shared
#: secret in its own test vectors is.
SECRET_BYTES = 20

#: What the authenticator shows above the code.
ISSUER = "WDash"


def generate_secret():
    """A new shared secret, base32 without padding.

    Base32 because that is what an otpauth:// URI carries and what somebody
    types into an application by hand when the QR cannot be scanned. Unpadded
    because the `=` at the end of a padded 160-bit secret is dropped by some
    applications and kept by others, and a secret that differs by its padding
    is a secret that produces different codes.
    """
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode(
        "ascii").rstrip("=")


def _key(secret):
    """The raw bytes of a base32 secret, however it was typed.

    Spaces and lower case are accepted: the enrolment page shows the secret in
    groups of four so a person can type it, and an application that hands it
    back lower-cased is not wrong.
    """
    cleaned = "".join((secret or "").split()).upper()
    padding = "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned + padding)


def code_at(secret, counter, digits=DIGITS):
    """HOTP, RFC 4226 section 5.3: one code for one counter value."""
    digest = hmac.new(_key(secret), struct.pack(">Q", counter),
                      hashlib.sha1).digest()
    # Dynamic truncation: the low nibble of the last byte picks where to read
    # four bytes from, and the top bit is masked off so the result does not
    # depend on whether the platform's integers are signed.
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def step_at(at=None, step=STEP):
    """Which time step a moment falls in. RFC 6238's T."""
    return int(at if at is not None else time.time()) // step


def code(secret, at=None, step=STEP, digits=DIGITS):
    """The code for a moment. Used by the tests and by nothing in the app —
    WDash checks codes, it never shows one."""
    return code_at(secret, step_at(at, step), digits)


def verify(secret, submitted, at=None, drift=DRIFT, step=STEP, digits=DIGITS,
           after=None):
    """The step a code is valid for, or None.

    Returns the STEP rather than True so the caller can record it and refuse
    it next time: "was this code right" and "has this code been used" are two
    questions, and an account that only answers the first accepts a code an
    attacker watched being typed.
    """
    submitted = "".join((submitted or "").split())
    if len(submitted) != digits or not submitted.isdigit():
        return None

    current = step_at(at, step)
    for candidate in range(current - drift, current + drift + 1):
        if candidate < 0:
            continue
        if after is not None and candidate <= after:
            continue
        if hmac.compare_digest(code_at(secret, candidate, digits), submitted):
            return candidate
    return None


def provisioning_uri(secret, username, issuer=ISSUER):
    """The otpauth:// URI an authenticator scans or is given.

    Every parameter is written out, including the ones that are the default.
    An application that assumes a different default — and they differ — enrols
    happily and then produces codes that never match, which reads as a broken
    second factor rather than as a disagreement about `algorithm`.
    """
    label = quote(f"{issuer}:{username}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={quote(issuer, safe='')}"
            f"&algorithm={ALGORITHM}&digits={DIGITS}&period={STEP}")


def readable(secret, group=4):
    """The secret in groups somebody can type without losing their place.

    An authenticator on the same device cannot scan the screen it is on, so
    the secret has to be typeable — and thirty-two unbroken characters is not.
    """
    cleaned = "".join((secret or "").split()).upper()
    return " ".join(cleaned[index:index + group]
                    for index in range(0, len(cleaned), group))


def qr_svg(uri):
    """The URI as an inline SVG, for embedding straight into the page.

    Inline rather than an <img>: the Content-Security-Policy admits no
    external image and no CDN, and a data: URI would be a second encoding of
    the same bytes for no gain. `segno` (BSD 3-clause, pure Python, no
    dependencies of its own) draws it; writing a QR encoder by hand is a
    different project from writing a TOTP one.

    Drawn dark-on-light whatever the page's theme is, and given its own white
    quiet zone in the template. A camera reading a screen wants the contrast
    the specification assumes; inverting it to match a dark theme is a
    decoration that some scanners refuse.
    """
    import io

    import segno

    buffer = io.BytesIO()
    segno.make(uri, error="m").save(
        buffer, kind="svg", xmldecl=False, svgns=True, scale=4, border=2,
        svgclass=None, lineclass=None, dark="#000000", light="#ffffff")
    return buffer.getvalue().decode("utf-8")
