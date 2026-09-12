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

from ..store import SetupClosed, WeakPassword
from ..store.users import check_password_strength
from .auth import _hold


def _administering_role(store):
    """A role that can administer, for the account setup creates.

    It was always `admin`. An installation whose rbac.yaml calls its
    administrator role something else — or has none — got a break-glass
    account that fell through to the default role: it could sign in and
    could not open the page that would fix anything.
    """
    from ..permissions import PERMISSIONS

    roles = {role["name"]: role for role in store.roles.all()}
    administering = sorted(name for name, role in roles.items()
                           if "system:admin" in (role.get("permissions") or []))
    if "admin" in administering:
        return "admin"
    if administering:
        return administering[0]
    # Not `admin`, and no name anything already points at. A mapping left
    # behind by a rename — `bob: admin` with no role called that — grants
    # nothing; a role created under that name at setup would have made bob
    # an administrator of every container. The recovery CLI keeps to its
    # own name for the same reason.
    mapped = set((store.settings.get("rbac.user_roles") or {}).values())
    mapped.add(store.settings.get("rbac.default_role") or "")
    name, suffix = "setup-admin", 1
    while name in roles or name in mapped:
        suffix += 1
        name = f"setup-admin-{suffix}"
    store.roles.upsert(
        name, permissions=list(PERMISSIONS), containers=["*"],
        trace_containers=["*"], services=None,
        description="Created at setup: no role in rbac.yaml could administer.")
    return name

setup_bp = Blueprint('setup', __name__)

#: Reachable before an account exists. Everything else redirects to setup.
OPEN_ENDPOINTS = {'setup.first_run', 'static', 'health', 'livez', 'readyz'}

#: Blueprints that must never be redirected anywhere.
#:
#: An agent has no browser. A 302 to an HTML setup form is not something a
#: daemon can act on — it parses the body as JSON, fails, and reports itself
#: broken while WDash is merely waiting for somebody to create an account. It
#: has a bearer token and its own 401; that is the answer it can use.
OPEN_BLUEPRINTS = {'agent'}


def _is_open(endpoint):
    if endpoint in OPEN_ENDPOINTS:
        return True
    return bool(endpoint) and endpoint.split('.')[0] in OPEN_BLUEPRINTS


def _store():
    return getattr(current_app, 'store', None)


def register_setup_gate(app):
    """Send every request to setup until the installation has an owner."""

    @app.before_request
    def _require_setup():
        store = _store()
        if store is None or _is_open(request.endpoint):
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
        # Checked before a role is made for the account: a refused password
        # left the role behind.
        check_password_strength(password)
        account = store.users.create_first_admin(
            username, password, role=_administering_role(store), email=email)
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

    # NOT a session. Setup used to sign the first administrator straight in,
    # which with a mandatory second factor would have made the account that
    # matters most the one account that never enrolled — and the bypass would
    # be one POST away from anybody who reached an unclaimed installation.
    # The hold grants nothing; the enrolment page is the only thing it opens.
    _hold(account['username'])
    current_app.logger.warning(
        f"First-run setup completed by '{account['username']}'")
    flash(f"Welcome, {account['username']}. Set up an authenticator to "
          f"finish signing in.", 'success')
    return redirect(url_for('auth.totp_enrol'))
