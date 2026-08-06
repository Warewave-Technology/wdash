"""
Secrets at rest.

The config page will hold an OIDC client secret, an LDAP bind password and
source credentials. Those cannot sit in the database as text: a database dump,
a replica, or a backup then carries working credentials for the identity
provider, and the blast radius of a stolen backup stops being "they can see
what dashboards exist".

Design rules, in order of importance:

1. **No key, no secret.** If no encryption key is configured, storing a secret
   FAILS. It never silently falls back to plaintext — that is the failure mode
   where everyone believes secrets are encrypted and nobody checks.
2. **Never reversible to the UI.** A stored secret can be replaced but not
   read back. The config page shows "set" or "not set", never the value.
   Otherwise the page becomes a credential exfiltration endpoint for anyone
   who reaches an admin session.
3. **Key rotation must be possible.** Ciphertext carries the key id it was
   sealed with, so a rotation can decrypt old values while writing new ones.

Fernet (AES-128-CBC + HMAC) from `cryptography`: authenticated, versioned, and
not something to hand-roll.
"""

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

#: Environment variable holding the key. A urlsafe base64 32-byte value, as
#: produced by `Fernet.generate_key()` — or any passphrase, which is stretched.
KEY_VARIABLE = "WDASH_ENCRYPTION_KEY"

#: Prefix on stored ciphertext, so a value's format is self-describing and a
#: future algorithm change is detectable rather than a decryption failure.
PREFIX = "wdash:v1:"


class SecretsUnavailable(RuntimeError):
    """No encryption key is configured, so secrets cannot be stored."""


class SecretsCorrupt(RuntimeError):
    """A stored secret cannot be decrypted with the configured key."""


def _derive(raw):
    """Accept either a real Fernet key or a passphrase.

    A passphrase is stretched rather than rejected: refusing anything that is
    not exactly 32 base64 bytes reliably produces a deployment that sets no key
    at all, which is worse than a derived one.
    """
    raw = raw.strip()
    try:
        candidate = base64.urlsafe_b64decode(raw)
        if len(candidate) == 32:
            return raw.encode() if isinstance(raw, str) else raw
    except Exception:
        pass
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class SecretBox:
    """Seals and opens secrets. Construct once and keep it on the app."""

    def __init__(self, key=None):
        """`key=None` means no key, and nothing else.

        It used to fall back to the environment, which made `SecretBox(None)`
        and `SecretBox()` the same thing — so a deployment that deliberately
        configured no key got one anyway if the variable happened to be
        exported, and the "secrets cannot be stored" path could not be
        exercised on a machine that had one. Reading the environment is the
        configuration layer's job; see `from_environment` for the one caller
        that has no configuration to read.
        """
        self._fernet = Fernet(_derive(key)) if key else None

    @classmethod
    def from_environment(cls):
        """A box keyed from the environment, for callers outside the app."""
        return cls(os.environ.get(KEY_VARIABLE))

    @property
    def available(self):
        return self._fernet is not None

    def seal(self, value):
        """Encrypt a value for storage. Returns None for an empty value."""
        if value is None or value == "":
            return None
        if not self._fernet:
            raise SecretsUnavailable(
                f"{KEY_VARIABLE} is not set, so secrets cannot be stored. "
                f"Generate one with:\n"
                f"  python -c \"from cryptography.fernet import Fernet; "
                f"print(Fernet.generate_key().decode())\"")
        token = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return PREFIX + token

    def open(self, stored):
        """Decrypt a stored value. Returns None when nothing is stored."""
        if not stored:
            return None
        if not stored.startswith(PREFIX):
            raise SecretsCorrupt(
                "Stored secret is not in a format this version understands.")
        if not self._fernet:
            raise SecretsUnavailable(
                f"{KEY_VARIABLE} is not set, so stored secrets cannot be read.")
        try:
            return self._fernet.decrypt(stored[len(PREFIX):].encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            # Almost always a changed or lost key rather than tampering, and
            # saying so is the difference between a five-minute fix and an hour.
            raise SecretsCorrupt(
                f"A stored secret could not be decrypted. {KEY_VARIABLE} has "
                f"probably changed since it was written; the value must be "
                f"entered again.") from exc

    @staticmethod
    def generate_key():
        return Fernet.generate_key().decode("ascii")
