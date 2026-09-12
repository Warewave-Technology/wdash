import secrets
import uuid
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint, current_app, flash, redirect, render_template, request, session, url_for,
)
from flask_login import current_user, login_user, logout_user, login_required
from authlib.integrations.flask_client import OAuth
from markupsafe import Markup

from ..models import User
from ..store.signin import (
    FAILURE, LOCKED, REFUSED, SUCCESS, UNAVAILABLE, client_address)
from . import totp
from .ldap_auth import DirectoryUnavailable
from .providers import ldap_settings, oidc_settings, shadow_notice

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

#: Where a half-finished sign-in lives. Its own key, never `user_data`: the
#: principal is rebuilt from `user_data` and nothing else, so a session holding
#: only this is not signed in to anything. `tests/test_totp.py` proves that by
#: asking every route in the url map, rather than by reading the code.
PENDING = 'pending_totp'

#: How long the hold is good for. Long enough to unlock a phone and read a
#: code; short enough that a browser left open on a shared machine between the
#: password and the code is not a way in.
PENDING_MINUTES = 5

def init_oauth(app, settings=None):
    """Build the OIDC client from whatever settings are currently in force.

    Constructed per request rather than once at startup. That is what lets an
    administrator repair a broken provider from the config page and try again
    immediately — the moment you most want not to be told to restart.
    """
    settings = settings or oidc_settings(app)
    if settings is None:
        return None, None

    oauth = OAuth(app)
    oidc = oauth.register(
        name='oidc',
        client_id=settings['client_id'],
        client_secret=settings['client_secret'],
        server_metadata_url=settings['discovery_url'],
        # `groups` is in the default because this product maps groups to
        # roles — the callback reads the groups claim (`groups_claim`,
        # rbac.yaml's `claim_mappings` or the configuration page) — and a
        # provider that gates the claim behind a scope sends nothing
        # without it. Dex does; so do Keycloak and Okta with the
        # usual configuration.
        #
        # Measured in the lab: without this every OIDC identity signed in
        # perfectly and landed on the DEFAULT role, whatever directory groups
        # it held. Nothing failed, nothing logged, and the only symptom was
        # an administrator who could not see the configuration page.
        #
        # Configurable because an authorization server MAY refuse a scope it
        # does not recognise, and a deployment that meets one needs a way out
        # that is not a fork.
        client_kwargs={'scope': current_app.config.get(
            'OIDC_SCOPES', 'openid email profile groups')},
    )
    return oauth, oidc

def _resolver():
    store = getattr(current_app, 'store', None)
    return store.rbac if store else None


def _start_session(user, local_role=None, provider=None):
    """Store IDENTITY in the session and sign the user in.

    Only identity: who this is, which groups the provider asserted, and which
    door they came through. What they may do is resolved from the store on
    every request instead.

    `provider` is identity too, and it is what stops the one-directory rule
    telling somebody something untrue: a session survives a change of
    directory, so "you are not local, therefore you arrived through the
    directory you are turning off" is a guess. An administrator who arrived
    through the OTHER directory is the person who should be allowed to turn
    this one off, and she is exactly who that guess blocks.

    Permissions used to be written here. That froze them for the lifetime of
    the cookie, so revoking access in the config page would save successfully
    and change nothing until the person happened to sign out — an
    administrator being shown a revocation that did not happen.
    """
    # Everything the pre-authentication session held is dropped. Flask's
    # session is a signed cookie rather than a server-side record, so this is
    # not the classic fixation fix — it is the one that matters here: anything
    # planted before sign-in (a flash, a stale `user_data`, a key some future
    # code decides to trust) must not survive into an authenticated session.
    session.clear()
    session['user_data'] = {
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'groups': user.groups,
        # Set for local accounts, whose role is stored with the account rather
        # than derived from provider groups.
        'local_role': local_role,
        # 'local account', 'directory', 'oidc' — the same words the audit
        # trail records. Absent in a session written before this existed,
        # which reads as "unknown" and is never claimed to be either door.
        'provider': provider,
    }
    login_user(user)


def _store():
    return getattr(current_app, 'store', None)


# ---------------------------------------------------------------------------
# The second factor
#
# A correct password for a local account does not start a session. It puts the
# sign-in ON HOLD: the account it is for, when it was issued, when it expires,
# and — while enrolling — the candidate secret that is not in the database yet.
# The hold grants nothing. `load_user_from_session` reads `user_data`, which a
# held sign-in does not have, so every `@login_required` route turns it away
# exactly as it turns away a browser that has never signed in.
#
# Directory accounts are untouched. LDAP and OIDC principals go straight to a
# session, because a second factor belongs at the provider that authenticates
# them: WDash never sees their password and has nowhere to put a secret for
# them — `wdash_users` holds local accounts and deliberately nothing else.
# ---------------------------------------------------------------------------

def _hold(username, secret=None):
    """Put a sign-in on hold between the password and the code.

    `session.clear()` first, for the same reason `_start_session` does it:
    whatever the pre-authentication session held must not survive into the
    next stage, and a hold is the thing an attacker would most like to plant.

    `secret` is the candidate for an enrolment. It lives in the signed cookie
    rather than in the database, because a secret stored before a code proves
    it is a half-enrolled account: one that cannot sign in, and that whoever
    else saw the QR can. The cookie is signed and not encrypted, so the
    candidate is readable by the browser holding it — which is the browser
    being shown the same secret on screen, so nothing is disclosed that the
    page is not already disclosing to the same person.
    """
    session.clear()
    now = datetime.now(timezone.utc)
    session[PENDING] = {
        'username': username,
        'issued_at': now.isoformat(),
        'expires_at': (now + timedelta(minutes=PENDING_MINUTES)).isoformat(),
        'secret': secret,
    }


def _pending():
    """The held sign-in, or None when there is none or it has expired.

    An expired hold is dropped rather than left to be read again: a cookie
    that says "this password was right" is worth exactly as much as the window
    it names, and one nobody clears keeps saying it.
    """
    held = session.get(PENDING)
    if not isinstance(held, dict):
        return None
    try:
        expires = datetime.fromisoformat(held['expires_at'])
    except (KeyError, TypeError, ValueError):
        session.pop(PENDING, None)
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc) or not held.get('username'):
        session.pop(PENDING, None)
        return None
    return held


def _held_account(store):
    """(held, account) for a hold that is still good, or (None, None).

    The account is read NOW rather than trusted from the hold: it can be
    disabled, deleted, or have its second factor reset by an administrator
    between the password and the code, and each of those has to take effect
    before the code is accepted rather than after.
    """
    held = _pending()
    if store is None or held is None:
        return None, None
    account = store.users.by_username(held['username'])
    if account is None or account['disabled']:
        session.pop(PENDING, None)
        return None, None
    return held, account


def _start_again(message='Your sign-in timed out. Please start again.'):
    session.pop(PENDING, None)
    flash(message, 'error')
    return redirect(url_for('auth.login'))


def _completed(store, account, address, method='local account',
               second_factor='totp'):
    """Finish a sign-in that has passed both halves.

    SUCCESS is recorded HERE and nowhere earlier. The pair limit counts from
    the last success, so recording one when the password was accepted would
    reset the counter before the code was ever checked — handing anybody who
    had the password an unlimited number of guesses at the second factor,
    which is the one thing the second factor exists to stop.
    """
    store.signin.record(account['username'], address, SUCCESS)
    store.users.record_sign_in(account['username'])
    user = User(user_id=account['id'], email=account['email'] or '',
                username=account['username'], groups=[])
    # Clears the session, the hold included.
    _start_session(user, local_role=account['role'], provider=method)
    store.audit.record(account['username'], "sign-in",
                       subject=f"user:{account['username']}", address=address,
                       state={"method": method, "second_factor": second_factor})
    current_app.logger.info(
        f"Sign-in: {account['username']} via {method} with {second_factor}")
    return redirect(url_for('index'))


def _wrong_code(store, address, template, page):
    """A wrong code is a FAILURE, through the guard that already exists.

    Not a counter of its own: the lockout, the backoff and the audit trail
    that cover password guessing cover code guessing for free, and a second
    counter would be a second set of thresholds to keep in agreement.

    `page` is passed as a dict rather than keywords because it carries a
    `username` of its own, and a template context that collides with a
    parameter name is a TypeError raised on the sign-in path.
    """
    who = page['username']
    store.signin.record(who, address, FAILURE)
    current_app.logger.warning(
        f"Failed second factor for {who!r} from {address}")
    flash('That code was not accepted. Check your authenticator and try '
          'the current code.', 'error')
    return render_template(template, **page), 401


def _locked(store, address, lockout, template, page):
    who = page['username']
    store.signin.record(who, address, LOCKED)
    store.audit.record(who, "sign-in blocked", subject=f"user:{who}",
                       address=address,
                       state={"limit": lockout.limit,
                              "failures": lockout.failures,
                              "stage": "second factor"})
    flash(f'Too many sign-in attempts. Try again in '
          f'{_describe_wait(lockout.seconds_remaining)}.', 'error')
    return render_template(template, **page), 429


@auth_bp.route('/totp/enrol', methods=['GET', 'POST'])
def totp_enrol():
    """Set up an authenticator, and finish signing in with it.

    Reachable only with a held sign-in, which means only after a correct
    password. The secret shown here is NOT in the database: it is written, in
    one statement with its confirmation time, when a code proves the person
    holds it.
    """
    store = _store()
    held, account = _held_account(store)
    if held is None:
        return _start_again()
    if account['totp_enrolled']:
        # Finished in another tab, or set up elsewhere while this form was
        # open. The code page is where they belong.
        return redirect(url_for('auth.totp_code'))

    # A secret that cannot be sealed must not be enrolled: storing it as text
    # would mean a database dump carries a working second factor, which is
    # the one thing store/secrets.py exists to refuse.
    if not store.secrets.available:
        return render_template('totp_enrol.html', username=account['username'],
                               secrets_available=False), 503

    secret = held.get('secret')
    if not secret:
        secret = totp.generate_secret()
        session[PENDING] = {**held, 'secret': secret}

    address = client_address(
        request, current_app.config.get('TRUSTED_PROXY_COUNT', 0))
    uri = totp.provisioning_uri(secret, account['username'])
    # Marked safe HERE rather than with `|safe` in the template. A template
    # that switches autoescape off is a template somebody later puts a
    # username in, so the whole project refuses the filter
    # (tests/test_security_headers.py) — and the decision belongs beside the
    # code that generated the markup anyway. This is segno's own output for a
    # URI this function built; nothing from a request reaches it unencoded.
    page = {'username': account['username'], 'secrets_available': True,
            'qr': Markup(totp.qr_svg(uri)), 'uri': uri,
            'secret_groups': totp.readable(secret),
            'digits': totp.DIGITS, 'step_seconds': totp.STEP}

    if request.method == 'GET':
        return render_template('totp_enrol.html', **page)

    lockout = store.signin.check(account['username'], address)
    if lockout is not None:
        return _locked(store, address, lockout, 'totp_enrol.html', page)

    step = totp.verify(secret, request.form.get('code', ''))
    if step is None:
        return _wrong_code(store, address, 'totp_enrol.html', page)

    store.users.confirm_totp(account['username'], secret, step)
    store.audit.record(account['username'], "totp enrolled",
                       subject=f"user:{account['username']}", address=address,
                       state={"username": account['username']})
    current_app.logger.warning(
        f"Second factor enrolled for local account '{account['username']}'")
    flash('Your authenticator is set up. It will ask for a code every time '
          'you sign in.', 'success')
    return _completed(store, account, address)


@auth_bp.route('/totp', methods=['GET', 'POST'])
def totp_code():
    """Ask for the code, for an account that has already enrolled."""
    store = _store()
    held, account = _held_account(store)
    if held is None:
        return _start_again()
    if not account['totp_enrolled']:
        # An administrator reset it while this form was open, or the account
        # never had one. Either way the answer is to enrol.
        return redirect(url_for('auth.totp_enrol'))

    page = {'username': account['username'], 'digits': totp.DIGITS}
    if request.method == 'GET':
        return render_template('totp.html', **page)

    address = client_address(
        request, current_app.config.get('TRUSTED_PROXY_COUNT', 0))
    lockout = store.signin.check(account['username'], address)
    if lockout is not None:
        return _locked(store, address, lockout, 'totp.html', page)

    try:
        secret = store.users.totp_secret(account['username'])
    except Exception as exc:
        # The key has changed since the secret was sealed, or there is none.
        # Said plainly: this is not a wrong code, and telling somebody their
        # code is wrong when the server cannot read the secret sends them to
        # re-install an application that was never the problem.
        current_app.logger.error(
            f"Could not open the stored second factor for "
            f"{account['username']!r}: {exc}")
        flash('Your second factor could not be read on this server, so the '
              'code could not be checked. An administrator has to reset it: '
              'python -m wdash.store.recover --reset-totp '
              f"{account['username']}", 'error')
        return render_template('totp.html', **page), 503

    # `after` is what refuses a replay: a code that was already accepted is a
    # code somebody may have read over a shoulder or off a screen share.
    # Submitting the same one twice — a double click included — is a FAILURE,
    # which is the right answer to "this code has been used".
    step = totp.verify(secret, request.form.get('code', ''),
                       after=account['totp_last_step'])
    if step is None:
        return _wrong_code(store, address, 'totp.html', page)

    store.users.record_totp_step(account['username'], step)
    return _completed(store, account, address)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Sign in with a local account, or hand off to the identity provider.

    Both are offered when both are available. The local account is the
    break-glass path: it exists precisely so that a broken or misconfigured
    identity provider does not lock everyone out of the screen that fixes it,
    which means it must never be hidden just because OIDC is configured.

    This replaces the development-only login that used to live here. Two doors
    are worse than one, and a door whose only guard is an environment variable
    is the one that gets left open.
    """
    store = _store()
    # At most one of these is ever a directory: both read the same resolution
    # in providers.py, so the page cannot offer two doors even if two are
    # configured. The third is the sentence for whoever used the other one —
    # without it their sign-in fails as "Invalid username or password", which
    # is a failure that looks like their own mistake.
    oidc_available = oidc_settings(current_app) is not None
    directory = ldap_settings(current_app)
    notice = shadow_notice(current_app)

    if request.method == 'GET':
        if store is not None and store.needs_setup:
            return redirect(url_for('setup.first_run'))
        return render_template('login.html', oidc_available=oidc_available,
                               ldap_available=directory is not None,
                               local_available=store is not None,
                               directory_notice=notice)

    if store is None:
        flash('Local sign-in is unavailable: no metadata store is configured.',
              'error')
        return redirect(url_for('auth.login'))

    username = request.form.get('username', '')
    password = request.form.get('password', '')
    address = client_address(
        request, current_app.config.get('TRUSTED_PROXY_COUNT', 0))

    # Refused before the password is checked, so a lockout also stops the
    # Argon2 cost being used as a CPU amplifier.
    lockout = store.signin.check(username, address)
    if lockout is not None:
        store.signin.record(username, address, LOCKED)
        store.audit.record(username or "unknown", "sign-in blocked",
                           subject=f"user:{username}", address=address,
                           state={"limit": lockout.limit,
                                  "failures": lockout.failures})
        current_app.logger.warning(
            f"Sign-in blocked for {username!r} from {address} "
            f"({lockout.limit} limit, {lockout.failures} failures)")
        flash(f'Too many sign-in attempts. Try again in '
              f'{_describe_wait(lockout.seconds_remaining)}.', 'error')
        return render_template('login.html', oidc_available=oidc_available,
                               ldap_available=directory is not None,
                               local_available=True,
                               directory_notice=notice,
                               username=username), 429

    # Local accounts first. The break-glass administrator has to work when the
    # directory is unreachable, which is the situation it exists for — and
    # asking a directory that is down would make sign-in hang before ever
    # trying the account that would have worked.
    account = store.users.verify(username, password)

    # A local name is not asked of the directory. Whatever the directory said
    # about it would be refused below — the name is the local account's —
    # and asking gave every wrong guess at the break-glass password a way
    # out of the count: a directory that could not answer made each one an
    # outage, which no limit counts. Measured: 60 wrong guesses at `owner`
    # with the directory unreachable were 60 × 503, the right one was let
    # in, and nothing ever locked; before the directory was asked, the
    # sixth guess was a 429.
    if (account is None and directory is not None
            and store.users.by_username(username) is None):
        try:
            account = _authenticate_directory(directory, username, password)
        except DirectoryUnavailable as exc:
            # Not a wrong password, and not recorded as one: counted as a
            # guess, an outage locked people out of accounts that were fine,
            # and the page told them their password was wrong.
            store.signin.record(username, address, UNAVAILABLE)
            current_app.logger.error(f"LDAP could not answer: {exc}")
            flash('The directory could not be reached, so the password could '
                  'not be checked. Try again shortly, or sign in with a local '
                  'account.', 'error')
            return render_template('login.html', oidc_available=oidc_available,
                                   ldap_available=True, local_available=True,
                                   directory_notice=notice,
                                   username=username), 503

    if not account:
        # One message for every failure. Saying which half was wrong tells an
        # attacker which usernames exist.
        store.signin.record(username, address, FAILURE)
        current_app.logger.warning(
            f"Failed sign-in for {username!r} from {address}")
        flash('Invalid username or password', 'error')
        return render_template('login.html', oidc_available=oidc_available,
                               ldap_available=directory is not None,
                               local_available=True,
                               directory_notice=notice,
                               username=username), 401

    if account.get('local'):
        # Half a sign-in. No session, no SUCCESS recorded — see `_completed`
        # for why the success has to wait for the second half — and nothing
        # in the hold that any route will accept.
        _hold(account['username'],
              secret=None if account['totp_enrolled']
              else totp.generate_secret())
        return redirect(url_for('auth.totp_code' if account['totp_enrolled']
                                else 'auth.totp_enrol'))

    # Recorded, not cleared. The success itself is what resets this pair's
    # counter — see SignInGuard._evaluate. Deleting the failures would let
    # somebody who eventually guessed the password erase the attempts that
    # got them there.
    store.signin.record(account['username'], address, SUCCESS)

    user = User(user_id=account['id'], email=account['email'] or '',
                username=account['username'], groups=account.get('groups') or [])
    # A directory account has no stored role: its role is resolved from the
    # groups the directory asserted, exactly like an OIDC principal. Its
    # second factor belongs at the directory too — WDash never sees its
    # password and has nowhere to keep a secret for it.
    _start_session(user, local_role=None, provider='directory')
    store.audit.record(account['username'], "sign-in",
                       subject=f"user:{account['username']}", address=address,
                       state={"method": 'directory'})
    current_app.logger.info(f"Sign-in: {account['username']} via directory")
    return redirect(url_for('index'))


def _describe_wait(seconds):
    """A wait somebody can act on. "in 900 seconds" is not one."""
    if seconds < 60:
        return "a few seconds" if seconds < 15 else f"{seconds} seconds"
    minutes = (seconds + 59) // 60
    return "a minute" if minutes == 1 else f"{minutes} minutes"


def _local_name_taken(store, username, email, method, address):
    """True, having refused and said so, when a provider asserts a name that
    belongs to a local account.

    Ownership here is the username: dashboards, saved searches and a
    mapping written against a name all follow it. So an identity provider
    that let somebody call themselves `owner` — preferred_username is
    whatever the provider allows a user to edit — handed them the
    break-glass administrator's private dashboards and whatever the name was
    mapped to. A local name is the local account's; a provider may not
    claim it.
    """
    if store.users.by_username(username) is None:
        return False
    store.signin.record(username, address, REFUSED)
    store.audit.record(username, "sign-in refused", subject=f"user:{username}",
                       address=address,
                       state={"method": method, "email": email or None,
                              "reason": "the name belongs to a local account"})
    current_app.logger.warning(
        f"Refused a {method} sign-in as {username!r}: that name is a local "
        f"account")
    flash(f'"{username}" is the name of a local account here, so it cannot '
          f'be used to sign in through {method}. Ask an administrator.',
          'error')
    return True


def _authenticate_directory(settings, username, password):
    """Check credentials against LDAP. Returns an account-shaped dict, or None.

    Raises DirectoryUnavailable when the directory could not answer — any
    failure of its own counts as that, never as a wrong password.
    """
    from .ldap_auth import authenticate

    try:
        result = authenticate(settings, username, password)
    except DirectoryUnavailable:
        raise
    except Exception as exc:
        # A directory outage must not surface as a stack trace on a login form.
        raise DirectoryUnavailable(str(exc)) from exc

    if result is None:
        return None
    return {"id": f"ldap:{result['username']}", "username": result["username"],
            "email": result.get("email"), "groups": result.get("groups") or [],
            "local": False}


def _no_provider():
    """Refuse a single sign-on route, saying which of the two things is true.

    "No identity provider is configured" is not true on an installation where
    one IS configured and is not the directory in force, and a person sent
    away with an untrue sentence goes looking for the wrong thing.
    """
    flash(shadow_notice(current_app) or 'No identity provider is configured.',
          'error')
    return redirect(url_for('auth.login'))


@auth_bp.route('/oidc')
def oidc_login():
    settings = oidc_settings(current_app)
    if settings is None:
        return _no_provider()

    oauth, oidc = init_oauth(current_app, settings)

    # A nonce binds the id_token to THIS sign-in attempt. Without one, a token
    # captured from another session for the same client is replayable: the
    # signature is valid, the audience is right, and nothing in it says which
    # request asked for it. Authlib only generates and checks a nonce when it
    # is given one.
    nonce = secrets.token_urlsafe(24)
    session['oidc_nonce'] = nonce
    return oidc.authorize_redirect(settings['redirect_uri'], nonce=nonce)


@auth_bp.route('/callback')
def callback():
    settings = oidc_settings(current_app)
    if settings is None:
        return _no_provider()

    oauth, oidc = init_oauth(current_app, settings)

    # Popped, not read: a nonce that outlives its one use is not a nonce, and
    # leaving it in the session would let a second callback reuse it.
    nonce = session.pop('oidc_nonce', None)
    if nonce is None:
        # No nonce means this callback did not follow a sign-in this browser
        # started — a stray link, a replayed URL, or a forged one.
        current_app.logger.warning(
            "OIDC callback without a nonce; the sign-in did not start here")
        flash('Sign-in could not be completed. Please try again.', 'error')
        return redirect(url_for('auth.login'))

    try:
        token = oidc.authorize_access_token()
        user_info = token.get('userinfo')

        if not user_info:
            user_info = oidc.parse_id_token(token, nonce=nonce)
        
        address = client_address(
            request, current_app.config.get('TRUSTED_PROXY_COUNT', 0))
        store = _store()
        try:
            email, username, groups = _identity(user_info, settings)
        except UnvouchedIdentity as refusal:
            return _unvouched(store, refusal, address)
        if not email and _claim(user_info, settings.get("email_claim") or "email"):
            # Said, because what it changes is silent: a mapping written
            # against this person's address no longer matches, and they land
            # on the default role with nothing on any page to say why.
            current_app.logger.warning(
                f"OIDC: the address sent for {username!r} was not used — the "
                f"provider did not mark it verified. A provider that never "
                f"sends email_verified has to be trusted on the configuration "
                f"page.")
        if store is not None and _local_name_taken(store, username, email,
                                                   'oidc', address):
            return redirect(url_for('auth.login'))

        # Create user object
        user = User(
            user_id=str(uuid.uuid4()),
            email=email,
            username=username,
            groups=groups
        )
        
        # Role and boundaries come from the store, resolved on every request
        # from here on; nothing is frozen into the session.
        _start_session(user, provider='oidc')
        if store is not None:
            # What the provider said, not whether an address was used: with
            # unverified addresses trusted, `bool(email)` recorded one the
            # provider had called unverified as verified.
            said = user_info.get("email_verified")
            store.audit.record(
                username, "sign-in", subject=f"user:{username}",
                address=address,
                state={"method": "oidc", "email": email or None,
                       "email_verified": said is True
                       or str(said).lower() == "true",
                       "unverified_email_trusted": bool(
                           email and settings.get("trust_unverified_email"))})
        current_app.logger.info(f"Sign-in: {username} via oidc")
        flash(f'Welcome {username}! Role: {user.role}', 'success')

        return redirect(url_for('index'))

    except Exception as exc:
        # The detail goes to the log, not to the page. An exception raised
        # while exchanging a code carries request URLs and provider responses,
        # and this page is reachable without signing in.
        current_app.logger.error(f"OIDC sign-in failed: {exc}")
        flash('Sign-in failed. Please try again, or contact your '
              'administrator if this continues.', 'error')
        return redirect(url_for('auth.login'))

class UnvouchedIdentity(Exception):
    """The provider named nobody this installation can trust by that name."""

    def __init__(self, reason, name):
        super().__init__(reason)
        self.name = name


def _claim(info, name):
    """A claim by name, a dotted name reaching into an object: Keycloak puts
    realm roles at `realm_access.roles`."""
    value = info
    for part in (name or "").split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _identity(info, settings):
    """(email, username, groups) from the provider's claims.

    The email is used only when the provider says it is verified. It was used
    as sent, and mappings and roles are written against it: somebody who
    could set their own address at the provider — an account console,
    self-registration, a multi-tenant provider — set it to one mapped to
    admin and was admin. A provider that never sends `email_verified` has to
    be trusted explicitly, on the configuration page.

    The username falls back to the verified email, then to `sub`, which the
    provider promises is unique and stable. It fell back to the email as
    sent, unverified, which was the same hole a second time.
    """
    verified = info.get("email_verified")
    verified = verified is True or str(verified).lower() == "true"
    # And only for the claim it is about. `email_verified` attests `email`:
    # read against another claim — `work_email`, `upn` — it vouched for an
    # address the provider never checked, one a user could often edit.
    claim = settings.get("email_claim") or "email"
    verified = verified and claim == "email"
    email = _claim(info, claim)
    email = str(email).strip() if email and (
        verified or settings.get("trust_unverified_email")) else ""

    username_claim = settings.get("username_claim") or "preferred_username"
    username = _claim(info, username_claim)
    username = (str(username).strip() if username else "") or email
    if not username:
        sent = _claim(info, claim)
        if sent:
            # A token shaped like ADFS or Entra v1: no preferred_username,
            # and an address with no email_verified. The name used to be that
            # address; falling back to `sub` would sign the person in as an
            # opaque id, and every dashboard they own and every mapping
            # written against their name would be gone without a word.
            raise UnvouchedIdentity(
                f"the provider sent no '{username_claim}' claim, and the "
                f"address it sent ({sent}) is not marked verified",
                name=str(sent).strip())
        username = str(info.get("sub") or "")

    groups = _claim(info, settings.get("groups_claim") or "groups") or []
    if isinstance(groups, str):
        groups = [groups]
    groups = [str(group) for group in groups if group is not None]
    return email, username, groups


def _unvouched(store, refusal, address):
    """Refuse a sign-in the provider did not name anybody for, and say what
    would fix it — to the person, and to whoever reads the log."""
    if store is not None:
        store.signin.record(refusal.name, address, REFUSED)
        store.audit.record(refusal.name, "sign-in refused",
                           subject=f"user:{refusal.name}", address=address,
                           state={"method": "oidc", "reason": str(refusal)})
    current_app.logger.warning(
        f"Refused an OIDC sign-in: {refusal}. Name the claim that holds the "
        f"username (username_claim, for example upn) or trust unverified "
        f"addresses, on the configuration page.")
    flash('Your identity provider did not send a name WDash can trust, so '
          'you were not signed in. Ask an administrator: the provider '
          'settings need a username claim.', 'error')
    return redirect(url_for('auth.login'))


@auth_bp.route('/logout')
@login_required
def logout():
    # Recorded before the session goes: afterwards there is nobody to name.
    # A trail with sign-ins and no sign-outs cannot answer "was that session
    # still open when this happened".
    store = _store()
    username = getattr(current_user, 'username', None)
    if store is not None and username:
        store.audit.record(
            username, "sign-out", subject=f"user:{username}",
            address=client_address(
                request, current_app.config.get('TRUSTED_PROXY_COUNT', 0)))

    logout_user()
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

def load_user_from_session():
    """Rebuild the principal from the session, resolving authorization now.

    The session says who; the store says what they may do. That split is what
    makes a role change take effect within seconds instead of never.
    """
    user_data = session.get('user_data')
    if not user_data:
        return None

    user = User(
        user_data['id'],
        user_data['email'],
        user_data['username'],
        user_data.get('groups') or []
    )

    explicit = user_data.get('local_role')
    store = _store()
    if store is not None and user_data.get('provider') == 'local account':
        # Read now, not taken from the cookie. `local_role` was written at
        # sign-in and never looked at again, which is the same frozen
        # authorization that moving permissions out of the session was for:
        # demoting a local account changed nothing until that person happened
        # to sign out, and the refusal that says "this would lock you out
        # immediately" was not true of the only role that wins.
        #
        # An account that has been deleted or disabled ends the session here
        # rather than at its next sign-in. Disabling an account that stays
        # signed in is half a switch, and it is the half somebody reaches for
        # when an account is being abused.
        account = store.users.by_username(user.username)
        if account is None or account['disabled']:
            return None
        explicit = account['role']

    resolver = _resolver()
    if resolver is not None:
        return user.apply(resolver.resolve(
            email=user.email, username=user.username, groups=user.groups,
            explicit=explicit))

    # No store: a deployment still on the YAML file. Not a fallback to
    # something permissive — the same file the resolver replaced.
    user.load_rbac_config(current_app.config['RBAC_CONFIG_FILE'])

    return user