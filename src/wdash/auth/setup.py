"""
First-run setup.

An installation with no accounts has nobody who can configure it, so the very
first thing it must do is let one person claim it. Until that happens every
route redirects here — an unclaimed installation is not a usable one, and
leaving the rest of the UI reachable would mean serving pages whose
authorization has no owner.

Two properties make this safe rather than an open door:

  * it closes the instant an account exists, checked per request against the
    database rather than a cached flag, so a second worker sees the first
    worker's administrator immediately
  * the account is created under a uniqueness constraint, so two submissions
    racing produce one account and one error, not two administrators

This replaces the development-only login. That door was guarded by an
environment variable, which is the guard people forget.
"""

from flask import (
    Blueprint, current_app, flash, redirect, render_template, request, url_for,
)

from ..models import User
from ..store import SetupClosed, WeakPassword
from .auth import _start_session

setup_bp = Blueprint('setup', __name__)

#: Reachable before an account exists. Everything else redirects to setup.
OPEN_ENDPOINTS = {'setup.first_run', 'static', 'health'}


def _store():
    return getattr(current_app, 'store', None)


def register_setup_gate(app):
    """Send every request to setup until the installation has an owner."""

    @app.before_request
    def _require_setup():
        store = _store()
        if store is None or request.endpoint in OPEN_ENDPOINTS:
            return None
        # A live check, not a flag cached at startup: the worker that did not
        # process the setup form must still see that setup is done.
        if not store.needs_setup:
            return None
        return redirect(url_for('setup.first_run'))


@setup_bp.route('/setup', methods=['GET', 'POST'])
def first_run():
    store = _store()
    if store is None:
        flash('No metadata store is configured, so setup cannot run.', 'error')
        return redirect(url_for('index'))

    if not store.needs_setup:
        # Not an error page: somebody following a stale link should simply end
        # up at the sign-in screen.
        return redirect(url_for('auth.login'))

    if request.method == 'GET':
        return render_template('setup.html',
                               secrets_available=store.secrets.available)

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    confirm = request.form.get('confirm') or ''
    email = (request.form.get('email') or '').strip()

    def again(message):
        flash(message, 'error')
        return render_template('setup.html', username=username, email=email,
                               secrets_available=store.secrets.available), 400

    if not username:
        return again('Choose a username for the administrator account.')
    if password != confirm:
        return again('The two passwords do not match.')

    try:
        account = store.users.create_first_admin(username, password, email=email)
    except WeakPassword as exc:
        return again(str(exc))
    except SetupClosed:
        # Somebody else completed setup while this form was open. Say so
        # plainly rather than reporting a generic failure.
        flash('This installation has just been set up by someone else. '
              'Sign in with that account.', 'warning')
        return redirect(url_for('auth.login'))
    except Exception as exc:
        current_app.logger.error(f"Setup failed: {exc}")
        return again('The account could not be created. Check the server logs.')

    user = User(user_id=account['id'], email=account['email'] or '',
                username=account['username'], groups=[])
    _start_session(user, local_role=account['role'])
    current_app.logger.warning(
        f"First-run setup completed by '{account['username']}'")
    flash(f"Welcome. You are signed in as {account['username']}.", 'success')
    return redirect(url_for('index'))
