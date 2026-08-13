import secrets
import uuid

from flask import (
    Blueprint, current_app, flash, redirect, render_template, request, session, url_for,
)
from flask_login import current_user, login_user, logout_user, login_required
from authlib.integrations.flask_client import OAuth

from ..models import User
from ..store.signin import FAILURE, LOCKED, SUCCESS, client_address
from .providers import ldap_settings, oidc_settings

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

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
        # roles — `rbac.yaml` has a `groups_claim` and the callback below
        # reads it — and a provider that gates the claim behind a scope sends
        # nothing without it. Dex does; so do Keycloak and Okta with the
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


def _start_session(user, local_role=None):
    """Store IDENTITY in the session and sign the user in.

    Only identity: who this is and which groups the provider asserted. What
    they may do is resolved from the store on every request instead.

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
    }
    login_user(user)


def _store():
    return getattr(current_app, 'store', None)


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
    oidc_available = oidc_settings(current_app) is not None
    directory = ldap_settings(current_app)

    if request.method == 'GET':
        if store is not None and store.needs_setup:
            return redirect(url_for('setup.first_run'))
        return render_template('login.html', oidc_available=oidc_available,
                               ldap_available=directory is not None,
                               local_available=store is not None)

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
                               username=username), 429

    # Local accounts first. The break-glass administrator has to work when the
    # directory is unreachable, which is the situation it exists for — and
    # asking a directory that is down would make sign-in hang before ever
    # trying the account that would have worked.
    account = store.users.verify(username, password)

    if account is None and directory is not None:
        account = _authenticate_directory(directory, username, password)

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
                               username=username), 401

    # Recorded, not cleared. The success itself is what resets this pair's
    # counter — see SignInGuard._evaluate. Deleting the failures would let
    # somebody who eventually guessed the password erase the attempts that
    # got them there.
    store.signin.record(account['username'], address, SUCCESS)

    user = User(user_id=account['id'], email=account['email'] or '',
                username=account['username'], groups=account.get('groups') or [])
    # A directory account has no stored role: its role is resolved from the
    # groups the directory asserted, exactly like an OIDC principal.
    _start_session(user, local_role=account.get('role') if account.get('local')
                   else None)
    method = 'local account' if account.get('local') else 'directory'
    store.audit.record(account['username'], "sign-in",
                       subject=f"user:{account['username']}", address=address,
                       state={"method": method})
    current_app.logger.info(f"Sign-in: {account['username']} via {method}")
    return redirect(url_for('index'))


def _describe_wait(seconds):
    """A wait somebody can act on. "in 900 seconds" is not one."""
    if seconds < 60:
        return "a few seconds" if seconds < 15 else f"{seconds} seconds"
    minutes = (seconds + 59) // 60
    return "a minute" if minutes == 1 else f"{minutes} minutes"


def _authenticate_directory(settings, username, password):
    """Check credentials against LDAP. Returns an account-shaped dict, or None."""
    from .ldap_auth import authenticate

    try:
        result = authenticate(settings, username, password)
    except Exception as exc:
        # A directory outage must not surface as a stack trace on a login form.
        current_app.logger.error(f"LDAP authentication failed: {exc}")
        return None

    if result is None:
        return None
    return {"id": f"ldap:{result['username']}", "username": result["username"],
            "email": result.get("email"), "groups": result.get("groups") or [],
            "local": False}


@auth_bp.route('/oidc')
def oidc_login():
    settings = oidc_settings(current_app)
    if settings is None:
        flash('No identity provider is configured.', 'error')
        return redirect(url_for('auth.login'))

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
        flash('No identity provider is configured.', 'error')
        return redirect(url_for('auth.login'))

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
        
        # Extract user information
        email = user_info.get('email', '')
        username = user_info.get('preferred_username', email)
        groups = user_info.get('groups', [])
        
        # Create user object
        user = User(
            user_id=str(uuid.uuid4()),
            email=email,
            username=username,
            groups=groups
        )
        
        # Role and boundaries come from the store, resolved on every request
        # from here on; nothing is frozen into the session.
        _start_session(user)
        store = _store()
        if store is not None:
            store.audit.record(
                username, "sign-in", subject=f"user:{username}",
                address=client_address(
                    request, current_app.config.get('TRUSTED_PROXY_COUNT', 0)),
                state={"method": "oidc"})
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

    resolver = _resolver()
    if resolver is not None:
        return user.apply(resolver.resolve(
            email=user.email, username=user.username, groups=user.groups,
            explicit=user_data.get('local_role')))

    # No store: a deployment still on the YAML file. Not a fallback to
    # something permissive — the same file the resolver replaced.
    user.load_rbac_config(current_app.config['RBAC_CONFIG_FILE'])

    return user