"""
Sign-in throttling.

A password form with no limit is an offline attack conducted online: the only
thing standing between an attacker and the break-glass administrator is how
fast they can send requests, and that is not a security control.

Three limits, because one is either too loose to help or tight enough to be a
weapon:

    pair      username + address, 5 failures in 15 minutes
    address   any username from one address, 20 failures in 15 minutes
    username  one account from anywhere, 50 failures in an hour

The pair limit is the one that normally fires — somebody mistyping their own
password from their own machine — and it backs off gently, a minute at a time.
The address limit catches one host working through a list of names. The
username limit catches a spray from many hosts against one account, and its
threshold is deliberately high: a low one hands anybody who knows the
administrator's username a way to lock them out on purpose. None of the three
is permanent, for the same reason.

**Locking out is not the same as denying.** A locked attempt is refused before
the password is checked, so a lockout also protects the Argon2 hashing cost
from being used as a CPU amplifier.

What this cannot do is stop a distributed attack that stays under every
threshold. That needs a second factor, which is a different piece of work.
"""

import datetime as dt
import logging
from datetime import datetime, timezone

from sqlalchemy import delete, func, select

from .schema import signin_attempts

logger = logging.getLogger(__name__)

SUCCESS, FAILURE, LOCKED = "success", "failure", "locked"
#: An attempt that was not a guess: the directory could not answer, or the
#: name belongs to a local account and a provider asserted it. Recorded, so
#: the trail shows it, and counted by no limit — neither says anything about
#: whether somebody is guessing a password.
UNAVAILABLE, REFUSED = "unavailable", "refused"


class Limit:
    """One rule: how many failures, over how long, and the resulting wait."""

    def __init__(self, name, threshold, window, base_wait, max_wait):
        self.name = name
        self.threshold = threshold
        self.window = window
        self.base_wait = base_wait
        self.max_wait = max_wait

    def wait_for(self, failures):
        """How long to refuse, given this many failures in the window.

        Doubling per failure past the threshold, capped. The cap matters more
        than the curve: an uncapped backoff is a permanent lockout wearing a
        different name, and the account it locks out permanently is whichever
        one somebody chose to attack.
        """
        over = max(0, failures - self.threshold)
        seconds = self.base_wait.total_seconds() * (2 ** min(over, 10))
        return min(dt.timedelta(seconds=seconds), self.max_wait)


#: Tuned for an internal deployment of tens of users, not a public sign-up
#: page. Overridable through configuration; see `Store.signin`.
DEFAULT_LIMITS = (
    Limit("pair", threshold=5, window=dt.timedelta(minutes=15),
          base_wait=dt.timedelta(minutes=1), max_wait=dt.timedelta(minutes=15)),
    Limit("address", threshold=20, window=dt.timedelta(minutes=15),
          base_wait=dt.timedelta(minutes=5), max_wait=dt.timedelta(minutes=30)),
    Limit("username", threshold=50, window=dt.timedelta(hours=1),
          base_wait=dt.timedelta(minutes=5), max_wait=dt.timedelta(minutes=15)),
)

#: How long attempts are kept. Long enough to answer "when did this start",
#: short enough that the table does not grow without bound.
RETENTION = dt.timedelta(days=30)


class Lockout:
    """A refusal, and when it lifts."""

    def __init__(self, limit, until, failures):
        self.limit = limit
        self.until = until
        self.failures = failures

    @property
    def seconds_remaining(self):
        return max(0, int((self.until - datetime.now(timezone.utc))
                          .total_seconds()))

    def __repr__(self):
        return (f"<Lockout {self.limit} for {self.seconds_remaining}s "
                f"after {self.failures} failures>")


class SignInGuard:
    """Decides whether an attempt may proceed, and remembers what happened."""

    def __init__(self, engine, limits=DEFAULT_LIMITS):
        self._engine = engine
        self._limits = tuple(limits)
        self._writes = 0

    # ---------- deciding ----------

    def check(self, username, address):
        """Returns a `Lockout`, or None when the attempt may proceed.

        On a database failure this returns None — it lets the attempt through.
        That is deliberate and narrow: local passwords, roles and directory
        group mappings all live in the same database, so an installation that
        cannot read this table cannot authorise anybody either. Failing closed
        here would trade a rate limit for a total outage without protecting
        anything that is still reachable.
        """
        username = _normalise(username)
        address = address or "unknown"
        try:
            for limit in self._limits:
                lockout = self._evaluate(limit, username, address)
                if lockout is not None:
                    return lockout
        except Exception as exc:
            logger.error(f"Sign-in guard could not read its own history: {exc}")
        return None

    def _evaluate(self, limit, username, address):
        since = datetime.now(timezone.utc) - limit.window

        if limit.name == "pair":
            # The counter resets when this pair succeeds — but by counting
            # from the success, not by deleting what came before it. Deleting
            # was the first attempt, and it meant an attacker who eventually
            # guessed the password erased their own failed attempts on the way
            # in. "When did this account start failing" is the question the
            # table exists to answer, and a success is not permission to
            # forget the answer.
            last_success = self._last_success(username, address)
            if last_success is not None:
                since = max(since, last_success)

        # The account-wide limit counts guesses only. It counted refused
        # attempts too — the ones this guard turned away before any password
        # was checked — so one address that kept knocking locked the account
        # out from every other address, the owner's included, and each of the
        # owner's own refused attempts pushed the end further away. Fifty
        # requests from anywhere was a lockout of the break-glass
        # administrator. The pair and address limits keep counting refusals:
        # those only ever hold back the address sending them.
        outcomes = ((FAILURE,) if limit.name == "username"
                    else (FAILURE, LOCKED))
        query = (select(func.count(), func.max(signin_attempts.c.at))
                 .where(signin_attempts.c.at >= since)
                 .where(signin_attempts.c.outcome.in_(outcomes)))

        if limit.name == "pair":
            query = query.where(signin_attempts.c.username == username)
            query = query.where(signin_attempts.c.address == address)
        elif limit.name == "address":
            # Deliberately NOT reset by a success: one person signing in from
            # a shared address says nothing about twenty failures against
            # twenty other usernames from the same place.
            query = query.where(signin_attempts.c.address == address)
        else:
            query = query.where(signin_attempts.c.username == username)

        with self._engine.connect() as connection:
            failures, latest = connection.execute(query).first()

        failures = failures or 0
        if failures < limit.threshold or latest is None:
            return None

        # Measured from the last failure, not the first: otherwise the wait is
        # spent while the attacker is still going, and expires the moment they
        # pause.
        until = _aware(latest) + limit.wait_for(failures)
        if until <= datetime.now(timezone.utc):
            return None
        return Lockout(limit.name, until, failures)

    # ---------- remembering ----------

    def record(self, username, address, outcome):
        """Write one attempt. Never raises — see `AuditLog.record`."""
        try:
            with self._engine.begin() as connection:
                connection.execute(signin_attempts.insert().values(
                    at=datetime.now(timezone.utc),
                    username=_normalise(username),
                    address=address or "unknown",
                    outcome=outcome))
        except Exception as exc:
            logger.error(f"Could not record a sign-in attempt: {exc}")
            return

        # Pruning on a fraction of writes rather than on a schedule: there is
        # no scheduler here, and a sweep on every attempt would put a delete on
        # the login path.
        self._writes += 1
        if self._writes % 100 == 0:
            self.prune()

    def _last_success(self, username, address):
        """When this pair last got in, or None."""
        query = (select(func.max(signin_attempts.c.at))
                 .where(signin_attempts.c.username == username)
                 .where(signin_attempts.c.address == address)
                 .where(signin_attempts.c.outcome == SUCCESS))
        with self._engine.connect() as connection:
            moment = connection.execute(query).scalar()
        return _aware(moment) if moment is not None else None

    def prune(self, retention=RETENTION):
        try:
            with self._engine.begin() as connection:
                connection.execute(
                    delete(signin_attempts).where(
                        signin_attempts.c.at
                        < datetime.now(timezone.utc) - retention))
        except Exception as exc:
            logger.error(f"Could not prune sign-in attempts: {exc}")

    # ---------- reading ----------

    def recent(self, limit=100, username=None, outcome=None):
        """Attempt history, newest first. For the audit screen."""
        try:
            query = (select(signin_attempts)
                     .order_by(signin_attempts.c.at.desc()).limit(limit))
            if username:
                query = query.where(
                    signin_attempts.c.username == _normalise(username))
            if outcome:
                query = query.where(signin_attempts.c.outcome == outcome)
            with self._engine.connect() as connection:
                return [dict(row) for row
                        in connection.execute(query).mappings().all()]
        except Exception as exc:
            logger.error(f"Could not read sign-in attempts: {exc}")
            return []


def _normalise(username):
    return (username or "").strip().lower()[:255]


def _aware(moment):
    """SQLite hands back naive datetimes; comparisons need one kind."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def client_address(request, trusted_proxies=0):
    """The client's address, as far as it can be trusted.

    `X-Forwarded-For` is written by whatever spoke to the proxy, so the value
    is only meaningful if you know how many proxies are in front of you and
    count in from the right. Reading the leftmost entry — the usual mistake —
    lets a client name its own address and walk straight through a per-address
    limit by changing a header.

    With no proxies configured, the socket address is the only thing anybody
    can be held to, so that is what is used.
    """
    if trusted_proxies > 0:
        forwarded = request.headers.get("X-Forwarded-For", "")
        chain = [part.strip() for part in forwarded.split(",") if part.strip()]
        if len(chain) >= trusted_proxies:
            return chain[-trusted_proxies][:64]
    return (request.remote_addr or "unknown")[:64]
