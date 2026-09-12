"""
Local accounts.

Only local accounts. OIDC and LDAP users are authenticated elsewhere and their
role is resolved per request — storing a shadow copy of them here would create
two answers to "what may this person do" and guarantee they drift apart.

What lives here is the break-glass admin created at first run. Its whole
purpose is to work when the identity provider does not, which is also why it
must be protected like the thing it is: a permanent credential to the system.
"""

import logging
import secrets
import uuid
from datetime import datetime, timezone

from argon2 import PasswordHasher
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .schema import settings, users

#: Fixed key claimed by whoever completes first-run setup.
SETUP_SENTINEL = "setup.completed"

logger = logging.getLogger(__name__)

#: Argon2id with the library defaults, which track current guidance. Chosen
#: over bcrypt for its memory-hardness: the threat here is an offline attack on
#: a stolen dump, and that is exactly what memory cost raises the price of.
_hasher = PasswordHasher()

MIN_PASSWORD_LENGTH = 12


class SetupClosed(RuntimeError):
    """First-run setup was attempted after an account already existed."""


class WeakPassword(ValueError):
    """The chosen password is not acceptable."""


def check_password_strength(password):
    """Length only, deliberately.

    Composition rules ("one capital, one symbol") push people towards
    Passw0rd! and add nothing an attacker notices. Length is the property that
    actually costs a cracker time.
    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(
            f"The password must be at least {MIN_PASSWORD_LENGTH} characters.")


def hash_password(password):
    return _hasher.hash(password)


def _public(row):
    """One account as anything outside this module may see it.

    The sealed TOTP secret is dropped and replaced by whether there is one.
    It is a credential, and the only caller that needs the value is the code
    check — which asks for it by name, through `totp_secret()`. Everything
    else here feeds a page, an audit row or an invariant, and a secret that
    travels with them is a secret waiting to be rendered.
    """
    account = dict(row)
    account["totp_enrolled"] = bool(account.get("totp_confirmed_at"))
    account.pop("totp_secret", None)
    return account


class UserRepository:
    def __init__(self, engine, secret_box=None):
        self._engine = engine
        #: For sealing the TOTP secret. `None` means no key, and nothing else:
        #: sealing then raises rather than storing the secret as text. See
        #: store/secrets.py, rule 1.
        self._secrets = secret_box

    # ---------- reading ----------

    def count(self):
        with self._engine.connect() as connection:
            return connection.execute(
                select(func.count()).select_from(users)).scalar() or 0

    def any_exist(self):
        """Whether setup has already been completed.

        The question the setup route asks on every request, so it must stay a
        single cheap query rather than a cached flag: a second worker must see
        the first worker's admin immediately.
        """
        return self.count() > 0

    def by_username(self, username):
        """One local account, or None.

        `local` is set on the way out. Callers use it to decide whether the
        stored role applies — a directory principal has no stored role, and
        its role comes from the groups the directory asserted. Without the
        flag the sign-in path treated a local account as a directory one and
        dropped its role on the floor, so the break-glass administrator was an
        administrator until the first time they signed out.
        """
        if not username:
            return None
        with self._engine.connect() as connection:
            row = connection.execute(
                select(users).where(users.c.username == username.strip().lower())
            ).mappings().first()
        return dict(_public(row), local=True) if row else None

    def all(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(users).order_by(users.c.created_at)).mappings().all()
        return [_public(row) for row in rows]

    def totp_secret(self, username):
        """The account's shared secret, opened. None when it has not enrolled.

        The one path that reads it, named so that a reader can find every
        caller. Raises `SecretsCorrupt` when the key has changed since it was
        sealed, rather than answering "not enrolled" — an account whose secret
        cannot be opened must not quietly fall back to enrolling again, which
        is a second factor that a lost key removes.
        """
        with self._engine.connect() as connection:
            sealed = connection.execute(
                select(users.c.totp_secret)
                .where(users.c.username == (username or "").strip().lower())
            ).scalar()
        return self._box().open(sealed) if sealed else None

    def _box(self):
        if self._secrets is None:
            from .secrets import SecretBox
            # A repository built without one. Not a fallback to plaintext:
            # an empty box refuses to seal, which is the whole rule.
            return SecretBox(None)
        return self._secrets

    # ---------- writing ----------

    def create(self, username, password, role, email=None):
        """Create an account. Raises if the username is taken.

        Usernames are folded to lower case before storage so that Admin and
        admin cannot both exist — a distinction nobody intends and everybody
        eventually trips over.
        """
        check_password_strength(password)
        username = (username or "").strip().lower()
        if not username:
            raise ValueError("A username is required.")

        record = {
            "id": str(uuid.uuid4()),
            "username": username,
            "email": (email or "").strip() or None,
            "password_hash": hash_password(password),
            "role": role,
            "disabled": False,
            "created_at": datetime.now(timezone.utc),
            "last_login_at": None,
        }
        try:
            with self._engine.begin() as connection:
                connection.execute(users.insert().values(**record))
        except IntegrityError as exc:
            raise ValueError(f"The username '{username}' is already taken.") from exc
        return record

    def create_first_admin(self, username, password, role="admin", email=None):
        """Create the bootstrap account, and only ever the first one.

        Guarded by inserting a sentinel row with a fixed primary key in the
        SAME transaction. The primary key constraint is what makes this atomic:
        the loser of the race violates it, the transaction rolls back, and no
        account is created.

        The obvious alternatives are both wrong. Counting rows and then
        inserting leaves a window where two workers processing two submissions
        of the setup form each see an empty table. Locking the count with
        `SELECT count(*) ... FOR UPDATE` is worse than useless — PostgreSQL
        rejects FOR UPDATE alongside an aggregate, so that version would not
        have guarded the race, it would have crashed setup outright.
        """
        check_password_strength(password)
        username = (username or "").strip().lower()
        if not username:
            raise ValueError("A username is required.")

        record = {
            "id": str(uuid.uuid4()),
            "username": username,
            "email": (email or "").strip() or None,
            "password_hash": hash_password(password),
            "role": role,
            "disabled": False,
            "created_at": datetime.now(timezone.utc),
            "last_login_at": None,
        }
        try:
            with self._engine.begin() as connection:
                # Claim the sentinel first. Whoever inserts it owns setup.
                connection.execute(settings.insert().values(
                    key=SETUP_SENTINEL,
                    value={"completed_by": username},
                    updated_at=record["created_at"],
                    updated_by=username))
                connection.execute(users.insert().values(**record))
        except IntegrityError as exc:
            raise SetupClosed(
                "Setup has already been completed on this installation.") from exc
        logger.warning(
            f"First-run setup completed: local administrator '{username}' created")
        return record

    def verify(self, username, password):
        """Check a password. Returns the account, or None.

        Always performs a hash comparison, even when the user does not exist,
        so that response time does not reveal which usernames are real.

        A password is now half of a sign-in, not all of it: the second factor
        is checked after this, and `last_login_at` moved to `record_sign_in`
        so that "last sign-in" on the accounts page is not set by somebody who
        typed the right password and never produced a code.
        """
        account = self.by_username(username)
        stored = account["password_hash"] if account else _DUMMY_HASH

        try:
            _hasher.verify(stored, password or "")
        except Exception:
            # Deliberately broad: a mismatch, a corrupt hash and an unexpected
            # library error must all mean "not authenticated". Narrowing this
            # risks a new argon2 exception type becoming an accidental 500 on
            # the login path, which is a worse outcome than a lost log line.
            return None

        if not account or account["disabled"]:
            return None

        # Rehash when the parameters have moved on, which happens for free on
        # the next successful sign-in rather than needing a migration.
        if _hasher.check_needs_rehash(account["password_hash"]):
            self.set_password(account["username"], password)

        return account

    def record_sign_in(self, username):
        """Mark an account as having signed in, now.

        Called when the WHOLE sign-in has succeeded — the password and the
        second factor — rather than when the password was accepted. The
        difference is the column the accounts page labels "Last sign-in", and
        an attacker who has the password but not the phone should not be able
        to write to it.
        """
        with self._engine.begin() as connection:
            result = connection.execute(
                users.update()
                .where(users.c.username == (username or "").strip().lower())
                .values(last_login_at=datetime.now(timezone.utc)))
        return result.rowcount > 0

    # ---------- the second factor ----------

    def confirm_totp(self, username, secret, step):
        """Store a secret a code has just proved, and the step it used.

        Written in ONE statement with its confirmation time and first used
        step, because a secret stored before it is proved is a half-enrolled
        account: the person cannot sign in, and whoever else holds the secret
        — a shoulder, a screenshot of the QR in a chat — can.

        Sealing happens here rather than in the caller so that there is one
        place where a TOTP secret meets the database, and it is a place that
        cannot write plaintext: with no encryption key, `seal` raises.
        """
        sealed = self._box().seal(secret)
        with self._engine.begin() as connection:
            result = connection.execute(
                users.update()
                .where(users.c.username == (username or "").strip().lower())
                .values(totp_secret=sealed,
                        totp_confirmed_at=datetime.now(timezone.utc),
                        totp_last_step=step))
        return result.rowcount > 0

    def record_totp_step(self, username, step):
        """Remember the step a code was accepted for, so it cannot be reused."""
        with self._engine.begin() as connection:
            result = connection.execute(
                users.update()
                .where(users.c.username == (username or "").strip().lower())
                .values(totp_last_step=step))
        return result.rowcount > 0

    def clear_totp(self, username):
        """Forget an account's second factor, so it enrols again.

        All three columns together: a confirmation time or a used step left
        behind an absent secret describes an account that does not exist.
        """
        with self._engine.begin() as connection:
            result = connection.execute(
                users.update()
                .where(users.c.username == (username or "").strip().lower())
                .values(totp_secret=None, totp_confirmed_at=None,
                        totp_last_step=None))
        return result.rowcount > 0

    def set_password(self, username, password):
        check_password_strength(password)
        with self._engine.begin() as connection:
            result = connection.execute(
                users.update()
                .where(users.c.username == (username or "").strip().lower())
                .values(password_hash=hash_password(password)))
        return result.rowcount > 0

    def set_role(self, username, role):
        """Move an account to a role. Returns whether a row was touched.

        The role is NOT validated here, and deliberately: the recovery tool
        creates the role it grants, and this repository has no opinion about
        which names exist. Whoever offers a choice — the accounts card, the
        CLI — checks the name against `roles.all()` first, because a role
        that does not exist grants nothing, silently.
        """
        with self._engine.begin() as connection:
            result = connection.execute(
                users.update()
                .where(users.c.username == (username or "").strip().lower())
                .values(role=role))
        return result.rowcount > 0

    def set_disabled(self, username, disabled):
        with self._engine.begin() as connection:
            result = connection.execute(
                users.update()
                .where(users.c.username == (username or "").strip().lower())
                .values(disabled=bool(disabled)))
        return result.rowcount > 0

    def delete(self, username):
        """Remove an account, refusing to remove the last one.

        An installation with no local account and a broken identity provider
        is unreachable, and the fix involves the database.
        """
        username = (username or "").strip().lower()
        with self._engine.begin() as connection:
            remaining = connection.execute(
                select(func.count()).select_from(users)
                .where(users.c.username != username)).scalar() or 0
            if remaining == 0:
                raise ValueError(
                    "This is the last local account. Removing it would leave "
                    "no way in if the identity provider is unavailable.")
            result = connection.execute(
                users.delete().where(users.c.username == username))
        return result.rowcount > 0


#: A real Argon2 hash of a random value, used to keep the verify path constant
#: time when the username does not exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))
