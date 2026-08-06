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


class UserRepository:
    def __init__(self, engine):
        self._engine = engine

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
        return dict(row, local=True) if row else None

    def all(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(users).order_by(users.c.created_at)).mappings().all()
        return [dict(row) for row in rows]

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

        with self._engine.begin() as connection:
            connection.execute(users.update()
                               .where(users.c.id == account["id"])
                               .values(last_login_at=datetime.now(timezone.utc)))
        return account

    def set_password(self, username, password):
        check_password_strength(password)
        with self._engine.begin() as connection:
            result = connection.execute(
                users.update()
                .where(users.c.username == (username or "").strip().lower())
                .values(password_hash=hash_password(password)))
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
