"""
WDash - Main Application
A minimal Kibana alternative with RBAC and OIDC support
"""

import contextlib
import os
import sys
import json
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_required, current_user
from sqlalchemy import select

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wdash import __version__
from wdash.config import (
    Config, DEFAULT_DASHBOARD_FILE, PUBLISHED_SECRET_KEYS)
from wdash.auth import auth_bp, load_user_from_session
from wdash.auth.setup import register_setup_gate, setup_bp
from wdash.dashboard import DashboardManager
from wdash.store import SecretBox, Store
from wdash.models import SavedSearch
from wdash.utils import timerange
from wdash.api.advisor_routes import advisor_bp
from wdash.api.agent_routes import agent_bp
from wdash.api.alert_routes import alert_bp
from wdash.api.monitor_routes import monitor_bp
from wdash.api.trace_routes import trace_bp
from wdash.api.log_routes import log_bp
from wdash.api.config_routes import config_bp
from wdash.api.dashboard_routes import dashboard_bp
from wdash.hub import Hub
from wdash.hub.factory import build_configured_sources
from datetime import datetime, timedelta
import time
import uuid

try:                                    # POSIX only; Linux and macOS have it.
    import fcntl
except ImportError:                     # pragma: no cover - not our platforms
    fcntl = None


class SavedSearchesUnavailable(RuntimeError):
    """The saved-search file is there and could not be read.

    Kept apart from "there is no file yet", which is an empty list and a
    perfectly good answer. Reading them as the same thing turned an
    unreadable file into "you have no saved searches", and then the next
    create wrote that emptiness over everybody's.
    """


def saved_searches_beside(dashboards_file):
    """Where the JSON saved searches live, given the dashboards file.

    One function rather than two identical `os.path.join` calls, because the
    start-up check and the store that actually reads them have to name the
    same file. They did not have to before: the check did not exist.
    """
    return os.path.join(os.path.dirname(dashboards_file),
                        'saved_searches.json')


def _json_rows(path):
    """The records a JSON store holds — or None when it cannot be read.

    Three answers, not two, and for the reason `SavedSearchesUnavailable`
    exists: no file is nothing left behind, an empty file is nothing left
    behind, and a file that cannot be parsed is NOT nothing. Counting it as
    zero is how a failure comes to look like emptiness.
    """
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            rows = json.load(handle)
    except Exception:
        return None
    return rows if isinstance(rows, list) else None


def _left_behind(rows, already_there):
    """Of `rows`, the ones the database has no record of.

    Matched by id, which is what the migration matches on — it skips an
    object already present — so a deployment that has run the migration and
    kept its JSON files (the migration leaves them, deliberately, so it is
    reversible) is told nothing. A warning that cannot be silenced except by
    deleting data is a warning people learn to scroll past.
    """
    if rows is None:
        return None
    return [row for row in rows
            if not isinstance(row, dict) or row.get('id') not in already_there]


def _stored_ids(store):
    """The dashboard and saved-search ids already in the metadata database."""
    from .store.schema import dashboards as dashboards_table
    from .store.schema import saved_searches as searches_table

    with store.engine.connect() as connection:
        return ({row[0] for row in
                 connection.execute(select(dashboards_table.c.id))},
                {row[0] for row in
                 connection.execute(select(searches_table.c.id))})


class LeftBehind:
    """Records a JSON file holds that the metadata database has no copy of.

    One set of facts, two readers. The start-up log line is one of them; the
    other is the page somebody is actually looking at, which used to say
    "Create your first dashboard to get started" over a file holding three of
    theirs. A log line four gunicorn workers each wrote once, hours ago, is
    not a substitute for the one place the question gets asked.

    `dashboards` and `searches` are a count, or None for a file that could
    not be read — the same three answers `_json_rows` gives, carried this far
    rather than flattened into "nothing", because a failure must not arrive
    looking like emptiness on the screen either.
    """

    def __init__(self, dashboards, searches, dashboards_file, searches_file,
                 command):
        self.dashboards = dashboards
        self.searches = searches
        self.dashboards_file = dashboards_file
        self.searches_file = searches_file
        #: What to run, exactly as the operator should type it.
        self.command = command

    @staticmethod
    def _notice(count, one, many):
        if count is None:
            return (f"A JSON file that may hold {many} cannot be read, so "
                    f"whether it holds any nobody can see is unknown")
        if not count:
            return None
        return (f"{count} {one if count == 1 else many} "
                f"{'is' if count == 1 else 'are'} in a JSON file that "
                f"nothing is reading")

    @property
    def dashboards_notice(self):
        """One line for the dashboards page, or None with nothing to say."""
        return self._notice(self.dashboards, "dashboard", "dashboards")

    @property
    def searches_notice(self):
        """One line for the saved-search list, or None."""
        return self._notice(self.searches, "saved search", "saved searches")


def left_behind_report(store, dashboards_file):
    """What JSON files nothing is reading still hold, or None.

    DASHBOARD_STORAGE decides where dashboards AND saved searches live —
    one setting, two files — so an installation that upgrades into the
    'database' default without having migrated loses sight of both. The
    saved searches are the half that is easy to miss: they are not on the
    dashboards page, so nobody goes looking for them until a shift when the
    query they always run is gone.

    None for a deployment that has no file, an empty file, or one whose
    records are all in the database already. A file that cannot be read is
    reported as unreadable rather than skipped, because "nothing to migrate"
    and "could not tell" are different sentences.
    """
    searches_file = saved_searches_beside(dashboards_file)

    # The files are read before the database is, and the ids only when there
    # is something to compare them against. Every worker runs this at every
    # start, and the ordinary answer — a database installation with no JSON
    # files at all — is now two `os.path.exists` calls rather than two full
    # id columns off a store that may hold thousands of rows. `[]` and only
    # `[]` is "nothing here": None is a file that could not be read, and that
    # one still has to be reported.
    rows = {path: _json_rows(path) for path in (dashboards_file, searches_file)}
    if all(found == [] for found in rows.values()):
        return None

    dashboard_ids, search_ids = _stored_ids(store)

    counted = []
    for path, present in ((dashboards_file, dashboard_ids),
                          (searches_file, search_ids)):
        outstanding = _left_behind(rows[path], present)
        counted.append(None if outstanding is None else len(outstanding))

    if not any(count is None or count for count in counted):
        return None

    # Only the files that are there are named on the command line: the
    # migration refuses a path it was told to read and cannot find, so a
    # command that names an absent file is a command that exits 1. An
    # unnamed searches file is derived from the dashboards one, which is
    # this same path, and its absence is the ordinary "nobody has saved one".
    #
    # Absolute, because the sentence beside it is. The two halves named
    # different files: the sentence said
    # /srv/wdash/data/dashboards.json and the command said
    # `--dashboards data/dashboards.json`, which is that file only if the
    # operator happens to run it from the application's working directory.
    # It failed safe when they did not — the migration refuses a path it
    # cannot find — but "one message, one path" costs nothing.
    dashboards_file = os.path.abspath(dashboards_file)
    searches_file = os.path.abspath(searches_file)
    arguments = ["--dashboards", dashboards_file]
    if not os.path.exists(dashboards_file):
        arguments.append("--allow-missing-dashboards")
    if os.path.exists(searches_file):
        arguments += ["--saved-searches", searches_file]

    return LeftBehind(
        dashboards=counted[0], searches=counted[1],
        dashboards_file=dashboards_file, searches_file=searches_file,
        command="PYTHONPATH=src python -m wdash.store.migrate_cli "
                + " ".join(arguments))


def left_behind_sentence(report):
    """The start-up log line for a `LeftBehind`, or None for None.

    The log's reader is an operator with a shell, so this one names the files
    in full and carries the command. The page's reader may be neither, which
    is why the page renders the same report differently rather than printing
    this string into HTML.
    """
    if report is None:
        return None

    lines = []
    for path, count, one, many in (
            (report.dashboards_file, report.dashboards,
             "dashboard", "dashboards"),
            (report.searches_file, report.searches,
             "saved search", "saved searches")):
        if count is None:
            lines.append(f"{path} cannot be read, so "
                         f"whether it holds {many} nobody can see is unknown")
        elif count:
            lines.append(f"{path} holds {count} "
                         f"{one if count == 1 else many} that the metadata "
                         f"database does not")

    return (
        "DASHBOARD_STORAGE is 'database', and " + "; ".join(lines) + ". "
        "Nothing has been deleted and nothing is being read from these "
        "files. Move them in with:\n"
        "  " + report.command + "\n"
        "or set DASHBOARD_STORAGE=file to go on reading them, which is "
        "still supported.")


def files_left_behind(store, dashboards_file):
    """What to say at start-up about JSON files nothing is reading, or None."""
    return left_behind_sentence(left_behind_report(store, dashboards_file))


#: Variables an earlier version configured a whole subsystem from, and where
#: that subsystem is configured now. Each group is (the names, what they
#: configured, the tab of the configuration page, what an installation
#: without that configuration is missing).
#:
#: NOTHING IS READ FROM THEM. They are looked at only to say so: an
#: installation upgrading with one of these still set would otherwise come up
#: with no log source, or no single sign-on, and a page saying "No log source
#: is configured" over a cluster that was answering yesterday reads as an
#: outage rather than as a variable. Nor are they imported into the store —
#: a one-shot import at start-up is exactly the mechanism being removed.
#:
#: Spelled as a list read in a loop, never as `os.environ.get("NAME")`:
#: tests/test_kubernetes_manifests.py reads the source for variables the
#: application looks up by name, and a ConfigMap that still carries one of
#: these has to FAIL that check, not pass it because the name was seen here.
RETIRED_VARIABLES = (
    (("ELASTICSEARCH_URL", "ELASTICSEARCH_USERNAME", "ELASTICSEARCH_PASSWORD",
      "ELASTICSEARCH_TIMEOUT", "ELASTICSEARCH_VERIFY_CERTS",
      "ELASTICSEARCH_CA_CERTS", "TRACE_INDEX_PATTERNS",
      "MONITOR_INDEX_PATTERNS"),
     "the Elasticsearch cluster and its index patterns are",
     "Sources",
     "until the cluster is added there, the logs, traces and monitors pages "
     "have no source"),
    (("OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_DISCOVERY_URL",
      "OIDC_REDIRECT_URI", "OIDC_SCOPES", "OIDC_USERNAME_CLAIM",
      "OIDC_EMAIL_CLAIM", "OIDC_GROUPS_CLAIM", "OIDC_TRUST_UNVERIFIED_EMAIL"),
     "the OpenID Connect provider is",
     "Authentication → OpenID Connect",
     "until the provider is saved there, nobody signs in through it"),
)


def _listed(names):
    """`A`, `A and B`, `A, B and C`."""
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " and " + names[-1]


def variables_left_behind(environ):
    """What to say at start-up about variables nothing reads any more.

    One sentence per group of `RETIRED_VARIABLES` that has a value in
    `environ`, naming every variable of the group that is set and the tab of
    the configuration page where the same thing is configured now; an empty
    list when none is set. An empty value does not count: it configured
    nothing before either.
    """
    said = []
    for names, what, tab, cost in RETIRED_VARIABLES:
        found = [name for name in names if (environ.get(name) or "").strip()]
        if not found:
            continue
        many = len(found) > 1
        said.append(
            f"{_listed(found)} {'are' if many else 'is'} set, and WDash no "
            f"longer reads {'them' if many else 'it'}: {what} configured on "
            f"the configuration page, under {tab}, and stored in the "
            f"metadata database. Nothing was read from "
            f"{'these variables' if many else 'this variable'} — {cost}. "
            f"Configure it on that page, then unset "
            f"{'them' if many else 'it'}.")
    return said


def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__, 
                template_folder='../../templates',
                static_folder='../../static')
    app.config.from_object(config_class)

    # The development session key must not reach a deployment serving real
    # people.
    #
    # `SECRET_KEY` falls back to a literal printed in this repository. That is
    # right for `python main.py` on a laptop and catastrophic anywhere else:
    # it signs the session cookie, so anybody who has read the source can mint
    # the administrator's session.
    #
    # This exists because of what happened when the shipped Kubernetes Secret
    # stopped carrying a working key. It used to publish a real, decodable
    # `secret-key`, and a comment asking for it to be changed — so an
    # unedited `kubectl apply` ran on a key everybody can read. Emptying it
    # fixes that only if the empty value is LOUD: an empty environment
    # variable lands right back on this fallback, and the deployment would
    # have been just as forgeable and no longer obvious.
    #
    # SESSION_COOKIE_SECURE is the signal. Nobody turns it on except to serve
    # over TLS to real people, and every other reading of "is this
    # production?" — DEBUG, TESTING, a hostname — is either wrong on a laptop
    # or wrong in a cluster. Refuse there; warn everywhere else.
    #
    # Empty counts as well as the literal. An empty environment variable is
    # what an unfilled Secret produces, and `Config` turns that back into the
    # development key one line later — so the two are the same deployment, and
    # a check that knew only about the literal would be a check that passes on
    # the exact file being shipped.
    #
    # And "the literal" is every literal this repository has printed, not the
    # one `Config` falls back to. `.env.example` carried its own, the quick
    # start copies that file into `.env`, and so a deployment built from the
    # README signed the administrator's cookie with a published string while
    # this check, which knew one spelling, said nothing at all.
    key = app.config.get('SECRET_KEY')
    if not key or key in PUBLISHED_SECRET_KEYS:
        if app.config.get('SESSION_COOKIE_SECURE'):
            raise RuntimeError(
                "SECRET_KEY is unset, empty, or a key printed in this "
                "repository — and SESSION_COOKIE_SECURE says this instance "
                "is served over TLS to real people. A published key signs "
                "every session cookie, including the administrator's, so "
                "anybody who has read the source can mint one. Set a real "
                "one:\n"
                "  python -c \"import secrets; print(secrets.token_urlsafe(48))\"\n"
                "In Kubernetes it is `secret-key` in kubernetes/secrets.yaml.")
        app.logger.warning(
            "SECRET_KEY is unset or a key printed in this repository. "
            "Sessions signed with it can be forged by anyone who has read "
            "the source.")

    # What `?v=` on a static URL is for.
    #
    # The three templates that load this application's own CSS and JavaScript
    # appended `?v={{ range(1000,9999) | random }}` — a NEW number on every
    # page load. So wdash.css and wdash.min.js were re-downloaded on every
    # single view, and the nginx sidecar's `expires 1y, immutable` never
    # applied to the two files it was written for.
    #
    # The favicon and the mark got the opposite treatment: no version at all,
    # so they WERE pinned for a year — and the release that changed the mark
    # would have gone on showing the old one to everybody who had ever loaded
    # a page.
    #
    # The version is the honest stamp: it changes exactly when the files can.
    # Under debug it is the process start instead, because editing a
    # stylesheet locally must not need a version bump to be visible — and the
    # reloader restarts on the edit, so the number moves with it.
    asset_version = (str(int(time.time())) if app.config.get('DEBUG')
                     else __version__)

    @app.context_processor
    def _asset_version():
        return {'asset_version': asset_version}

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        return load_user_from_session()
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(setup_bp)
    app.register_blueprint(config_bp)
    app.register_blueprint(advisor_bp)
    app.register_blueprint(trace_bp)
    app.register_blueprint(monitor_bp)
    # No session login on this one: an agent has no browser and no cookie.
    app.register_blueprint(agent_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(log_bp)
    app.register_blueprint(dashboard_bp)
    
    # Variables an earlier version configured a source or a provider from.
    # Said as an ERROR, once per group, naming what is set and the page it
    # moved to — and read for nothing else. See RETIRED_VARIABLES.
    for left_behind in variables_left_behind(os.environ):
        app.logger.error(left_behind)

    # WDash's own state, separate from every data source. Always present: roles
    # and local accounts live here regardless of which backends are configured,
    # and a Loki-only deployment has no Elasticsearch to fall back on.
    #
    # Whatever the configuration says, with no TESTING branch. There was one:
    # under TESTING the default URL was swapped for `:memory:`, so a test run
    # could not write into the repository's data directory. It held for apps
    # and only for apps — the alert process, the agent and the two CLIs read
    # `Config.DATABASE_URL` and got the developer's real database — and it
    # held only for a config that remembered to set TESTING. That guarantee
    # belongs to the harness, which can make it for the whole process:
    # `tests/__init__.py` forces DATABASE_URL, and a test there fails if it
    # ever stops.
    store = Store.open(
        app.config.get('DATABASE_URL'),
        secret_box=SecretBox(app.config.get('ENCRYPTION_KEY')))
    app.store = store
    # Until somebody claims this installation, every route leads to setup.
    register_setup_gate(app)
    app.logger.info(f"Metadata store: {store.describe()}")
    if store.needs_setup:
        app.logger.warning(
            "No local account exists yet — first-run setup is open at /setup")
    if not store.secrets.available:
        app.logger.warning(
            "WDASH_ENCRYPTION_KEY is not set: secrets cannot be stored, so "
            "OIDC and LDAP credentials cannot be saved from the config page, "
            "no alert channel can be defined or delivered to, and no check "
            "can carry credentials")
        # Said as its own line, because it is the one consequence that stops
        # the installation being usable rather than merely limited: a local
        # account needs an authenticator, its shared secret is sealed with
        # this key, and WDash refuses to write a secret as plain text. Only a
        # directory sign-in works until a key is set.
        app.logger.error(
            "WDASH_ENCRYPTION_KEY is not set, so NO LOCAL ACCOUNT CAN SIGN "
            "IN: the authenticator every local account needs cannot be "
            "stored. Generate one with: python -c \"from cryptography.fernet "
            "import Fernet; print(Fernet.generate_key().decode())\"")

    # Where dashboards and saved searches live. 'database' is the default:
    # the metadata database is opened and migrated a few lines above whatever
    # this says, so 'file' does not avoid a database, it adds a second store
    # beside one that is always there.
    #
    # 'file' stays supported and unchanged. What the default flip cost is an
    # installation that had JSON files and never set the variable, and that
    # is what the warning below is for — by name, both files, with the
    # command, instead of an empty list that says "Create your first".
    #
    # The file path is resolved once, before the branch, because both halves
    # need it: the file store writes to it, and the database store reads it
    # to see what an unmigrated installation still has. Same isolation the
    # metadata store gets, and for the same reason it needed it: a test run
    # must not touch the repository's data directory. It did — 3,000 fixture
    # dashboards accumulated in `data/dashboards.json` across runs, and the
    # saved searches from test runs went to `data/saved_searches.json`
    # beside them, because that path was derived from the un-isolated
    # setting. Nor should a test run be WARNED about the repository's files.
    #
    # Compared against the literal default so an explicitly configured path
    # is never discarded.
    #
    # A path, not a directory. `mkdtemp` here made one per test app and left
    # it there — 1,225 per suite run, against the 26 apps that actually use
    # the file store, on a machine already holding a quarter of a million of
    # them. Only the half that WRITES needs the directory to exist, and it
    # says so in its own branch below; the check only reads, and a path whose
    # directory is not there reads as "no file", which is the truth about a
    # test run.
    storage_file = app.config['DASHBOARD_STORAGE_FILE']
    isolated = bool(app.config.get('TESTING')) and \
        storage_file == DEFAULT_DASHBOARD_FILE
    if isolated:
        import tempfile
        from uuid import uuid4
        storage_file = os.path.join(tempfile.gettempdir(),
                                    f"wdash-test-{uuid4().hex}",
                                    "dashboards.json")

    # `or`, not a default argument: a config object that carries the key with
    # nothing in it means "not set", which is exactly what Config makes of an
    # empty environment variable. Stripped for the same reason — only the
    # environment path stripped before, so 'database ' off a config object
    # was a different store from 'database'.
    storage = str(app.config.get('DASHBOARD_STORAGE') or 'database')
    storage = storage.strip().lower()

    def json_stores_left_behind():
        """The `LeftBehind` report, or None — and never an exception.

        Two callers with the same requirement and different consequences:
        `create_app` must not fail to start over a check, and a page must not
        answer 500 over one. Both are told at ERROR and carry on, and a file
        store is told nothing at all because its files ARE being read.
        """
        if storage != 'database':
            return None
        try:
            return left_behind_report(store, storage_file)
        except Exception as exc:        # never at the cost of starting
            app.logger.error(f"Could not check for JSON stores left "
                             f"behind: {exc}")
            return None

    # The function, not its result. A context processor runs for every
    # template this application renders and only two of them ask, so a value
    # here would put two `os.path.exists` calls — and, for an installation
    # that really does have files left behind, two id columns — on the render
    # of every page in the product. It is also the reason the page goes quiet
    # the moment the migration finishes rather than at the next restart: the
    # answer is read when the question is asked.
    app.context_processor(
        lambda: {"json_stores_left_behind": json_stores_left_behind})

    if storage == 'database':
        dashboard_manager = store.dashboards
        left_behind = left_behind_sentence(json_stores_left_behind())
        if left_behind:
            app.logger.warning(left_behind)
    elif storage == 'elasticsearch':
        # Removed. Refused rather than quietly falling through to the file
        # store, which would present an empty list as though every dashboard
        # had been deleted — and the person would go looking for a deletion
        # that never happened.
        raise RuntimeError(
            "DASHBOARD_STORAGE=elasticsearch has been removed. Move the data "
            "into the metadata database first:\n"
            "  PYTHONPATH=src python -m wdash.store.migrate_cli \\\n"
            "      --from-elasticsearch <the cluster's url>\n"
            "then unset DASHBOARD_STORAGE — 'database' is the default.")
    elif storage == 'file':
        # The only branch that writes to the path, so the only one that needs
        # the directory to be there. Made here, and only when this run
        # redirected the path itself: `save_dashboards` treats a missing
        # directory as the failure it is, and a deployment that names a
        # directory it did not create should hear that rather than have one
        # made behind it.
        if isolated:
            os.makedirs(os.path.dirname(storage_file), exist_ok=True)
        dashboard_manager = DashboardManager(storage_file)
    else:
        # A value nobody recognises used to fall through to the JSON file
        # store without a word. That was survivable while 'file' was the
        # default and held the data; now the data is in the database, so one
        # transposed letter showed an empty dashboard list AND an empty
        # saved-search list with nothing logged — "there is nothing" and "we
        # looked somewhere else" made indistinguishable, which is the whole
        # reason this package exists. Refused the way 'elasticsearch' above
        # is refused, and for the same reason.
        raise RuntimeError(
            f"DASHBOARD_STORAGE={app.config.get('DASHBOARD_STORAGE')!r} is "
            f"not a value WDash knows. It is 'database' — the default, where "
            f"dashboards and saved searches live — or 'file', the JSON store, "
            f"which is still supported. Refused rather than falling through "
            f"to the file store: that would have shown an empty dashboard "
            f"list and an empty saved-search list for data that is in the "
            f"database, and nothing would have said why.")

    # Store services in app context
    app.dashboard_manager = dashboard_manager

    # The hub is the backend-neutral access layer. Every route works through
    # it; nothing Elasticsearch-specific reaches the HTTP layer.
    #
    # Every log and trace source, and every monitor source but one, comes
    # from the configuration page. There used to be a set registered from the
    # environment ahead of them — an Elasticsearch declared by variable,
    # answering as `elasticsearch-logs`, `elasticsearch-traces` and
    # `elasticsearch-monitors` — so that a deployment older than the page
    # kept its cluster. Gone: a cluster is a stored source now, and an
    # installation that still sets the variables is told so above.
    hub = Hub()

    # The checks WDash runs itself. Registered unconditionally and cheap when
    # unused: with no agents and no monitors it reports an empty list, which
    # is the truth rather than an absence the page has to explain.
    #
    # The one BASE source: it reads the metadata store this process already
    # holds, so there is nothing about it that a configuration edit could
    # change, and it is built once.
    if store is not None:
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        hub.add_monitors(StoreMonitorSource(store))

    # Sources added through the config page. A broken one is logged and
    # skipped; it must not stop startup.
    #
    # Handed to the hub as a recipe rather than a result, so an administrator
    # saving the form does not have to restart WDash to use what they just
    # configured. The page used to say so out loud, which made the
    # configuration screen the one screen that could not configure anything.
    if store is not None:
        # What the base registry already answers to. Asked at save time, so
        # `wdash-agents` typed into the form is a sentence about the name
        # rather than a row that is stored, listed, and reachable by nothing
        # because the source WDash registers itself keeps the name.
        store.sources.reserved_names = hub.base_source_names

        hub.reload_with(
            build=lambda: build_configured_sources(store),
            # A lambda rather than the bound method: it is looked up on
            # the repository each time, so a store that swaps one in is
            # honoured rather than shadowed by what was captured here.
            stamp=lambda: store.sources.stamp())
        if hub.configured_count:
            app.logger.info(
                f"{hub.configured_count} source(s) from configuration")

    # Which directory signs people in, and what is being shadowed to make that
    # true. An installation that has had both live loses one door the moment
    # it upgrades — nobody presses anything — so it is made loud rather than
    # quiet: here, on the configuration page, in the audit trail, and in one
    # neutral line on the sign-in page for the people whose usual door has
    # gone. Recomputed on demand for the same reason the duplicate warning is.
    from .auth.providers import directory as _directory
    app.directory_conflict = lambda: _directory(app)["reason"]
    _resolution = _directory(app)
    if _resolution["reason"]:
        app.logger.warning(_resolution["reason"])
    if store is not None and _resolution["shadowed"]:
        try:
            store.audit.record(
                "system", "two directories configured", subject="auth",
                state={"in_force": _resolution["in_force"],
                       "shadowed": _resolution["shadowed"],
                       "sources": _resolution["sources"],
                       "reason": _resolution["reason"]})
        except Exception as exc:
            app.logger.error(f"Directory conflict could not be audited: {exc}")

    app.hub = hub


    # Response headers. Installed before the routes so every response
    # carries them, including error pages and redirects.
    from .security import install as install_security
    install_security(app)

    # Routes
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('logs.logs_page'))
        return render_template('index.html')
    
    # --- Saved Searches ---
    #
    # Backed by the same setting dashboards use. They were left on the JSON
    # file when dashboards moved, which made the migration a half-truth: it
    # copied searches into the database, printed "Done", and nothing ever read
    # them from there. The database copy was dead weight and the file remained
    # the real one.
    #
    # The file path also inherits the DASHBOARD_STORAGE_FILE directory, so a
    # deployment that pointed dashboards elsewhere moved its searches too
    # without being told.
    #
    # `storage` above, not a second read of the setting with its own default:
    # the two defaults disagreed the moment one of them moved, and a
    # deployment whose config object simply has no DASHBOARD_STORAGE would
    # have read its dashboards from the database and its searches from a file.
    #
    # `storage_file` above, not the raw setting, for the same reason: derived
    # from the setting, a TESTING app that named no path wrote its saved
    # searches into the repository's `data/` directory while its dashboards
    # went to a temporary one.
    searches_in_database = storage == 'database'
    SAVED_SEARCHES_FILE = saved_searches_beside(storage_file)

    @contextlib.contextmanager
    def _saved_search_lock():
        """Hold the saved searches across a read-modify-write.

        Create and delete read the whole list, change it and write it back.
        Two workers doing that at the same moment — four gunicorn workers is
        the packaged default — both read the old list, and the second write
        drops whatever the first added. The lock lives on a file BESIDE the
        list rather than on the list itself, because the write replaces the
        file and a lock held on an unlinked inode guards nothing.
        """
        if fcntl is None:               # pragma: no cover - not our platforms
            yield
            return
        os.makedirs(os.path.dirname(SAVED_SEARCHES_FILE), exist_ok=True)
        handle = open(f"{SAVED_SEARCHES_FILE}.lock", "a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            handle.close()              # releases the lock

    def _saved_search_rows():
        """The file's rows, exactly as stored. File store only.

        Three answers, not two. No file is an empty list. A file that cannot
        be parsed at all raises, because the caller must not write over
        something it could not read. A row that cannot be understood is left
        where it is — see `_load_saved_searches`.
        """
        if not os.path.exists(SAVED_SEARCHES_FILE):
            return []
        try:
            with open(SAVED_SEARCHES_FILE, 'r') as f:
                rows = json.load(f)
        except (OSError, ValueError) as exc:
            raise SavedSearchesUnavailable(str(exc)) from exc
        if not isinstance(rows, list):
            raise SavedSearchesUnavailable(
                "the file does not hold a list of searches")
        return rows

    def _load_saved_searches():
        """Every stored search that can be read.

        One row that cannot be used to empty the list for everybody: the
        parse ran over the whole file, so a single entry written before
        `time_range` existed raised a KeyError and three people's searches
        became `[]`. A bad row is skipped and logged now, and left in the
        file, so it comes back when whatever wrote it is fixed.
        """
        searches = []
        for row in _saved_search_rows():
            try:
                searches.append(SavedSearch.from_dict(row))
            except Exception as exc:
                app.logger.error(
                    f"Skipping a saved search that could not be read: {exc}")
        return searches

    def _save_saved_search_rows(rows):
        """Replace the file, atomically. Call inside `_saved_search_lock`.

        It opened the real file with 'w', which truncates before it writes:
        another worker reading at that instant saw an empty or half-written
        file, and a crash mid-write left one behind.
        """
        os.makedirs(os.path.dirname(SAVED_SEARCHES_FILE), exist_ok=True)
        temp_path = (f"{SAVED_SEARCHES_FILE}.tmp."
                     f"{os.getpid()}.{threading.get_ident()}")
        try:
            with open(temp_path, 'w') as f:
                json.dump(rows, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, SAVED_SEARCHES_FILE)
        except Exception:
            with contextlib.suppress(OSError):
                os.remove(temp_path)
            raise

    def _searches_unreadable(exc, consequence):
        app.logger.error(f"Saved searches could not be read: {exc}")
        return jsonify({
            'error': f"Your saved searches could not be read, so {consequence}. "
                     f"Check the server logs.",
            'error_type': 'saved_searches_unavailable'}), 503

    @app.route('/api/saved-searches')
    @login_required
    def api_list_saved_searches():
        # A saved search holds a query. Everything else that touches log
        # queries is gated; leaving this open was an inconsistency rather than
        # a hole, since ownership was always enforced.
        if not current_user.has_permission('logs:read'):
            return jsonify({'error': 'Access denied',
                            'error_type': 'permission_denied'}), 403
        if searches_in_database:
            return jsonify([search.to_dict() for search
                            in store.saved_searches.all_for(
                                current_user.username)])
        try:
            searches = _load_saved_searches()
        except SavedSearchesUnavailable as exc:
            # Not an empty list: "you have none" and "they could not be read"
            # are different answers and need different actions.
            return _searches_unreadable(exc, "none can be listed")
        user_searches = [s.to_dict() for s in searches
                         if s.created_by == current_user.username]
        return jsonify(user_searches)

    @app.route('/api/saved-searches', methods=['POST'])
    @login_required
    def api_create_saved_search():
        if not current_user.has_permission('logs:read'):
            return jsonify({'error': 'Access denied',
                            'error_type': 'permission_denied'}), 403
        data = request.get_json()
        if not data or not data.get('name') or not data.get('query'):
            return jsonify({'error': 'Name and query are required'}), 400

        if searches_in_database:
            search = store.saved_searches.create(
                name=data['name'], query=data['query'],
                time_range=data.get('time_range', '1h'),
                created_by=current_user.username)
            return jsonify(search.to_dict()), 201

        search = SavedSearch(
            search_id=str(uuid.uuid4()),
            name=data['name'],
            query=data['query'],
            time_range=data.get('time_range', '1h'),
            created_by=current_user.username
        )
        # The whole read-modify-write under one lock, so a second worker
        # cannot read the list between this read and this write.
        with _saved_search_lock():
            try:
                rows = _saved_search_rows()
            except SavedSearchesUnavailable as exc:
                return _searches_unreadable(exc, "this one was not saved")
            rows.append(search.to_dict())
            try:
                _save_saved_search_rows(rows)
            except OSError as exc:
                app.logger.error(f"Saved searches could not be written: {exc}")
                return jsonify({
                    'error': "This search could not be saved. Check the "
                             "server logs.",
                    'error_type': 'saved_searches_unavailable'}), 503
        return jsonify(search.to_dict()), 201

    @app.route('/api/saved-searches/<search_id>', methods=['DELETE'])
    @login_required
    def api_delete_saved_search(search_id):
        if not current_user.has_permission('logs:read'):
            return jsonify({'error': 'Access denied',
                            'error_type': 'permission_denied'}), 403
        if searches_in_database:
            # Ownership is part of the delete, not a read followed by a check:
            # the two-step version has a window, and this endpoint gets called
            # with somebody else's id.
            if not store.saved_searches.delete(search_id,
                                               current_user.username):
                return jsonify({'error': 'Not found or not owned by you'}), 404
            return jsonify({'success': True})

        with _saved_search_lock():
            try:
                rows = _saved_search_rows()
            except SavedSearchesUnavailable as exc:
                # Answering 404 here would say "it is already gone", which is
                # the one thing nobody can tell from an unreadable file.
                return _searches_unreadable(exc, "this one was not deleted")
            def is_the_one(row):
                # `isinstance` first, and not because a dict is likely: the
                # loader already skips a row it cannot understand and the
                # create path already steps over one, so a file holding
                # something that is not an object at all reads and appends
                # fine and then made THIS verb an AttributeError and a 500.
                # One file, three verbs, one answer.
                return (isinstance(row, dict)
                        and row.get('id') == search_id
                        and row.get('created_by') == current_user.username)

            kept = [row for row in rows if not is_the_one(row)]
            if len(kept) == len(rows):
                return jsonify({'error': 'Not found or not owned by you'}), 404
            try:
                _save_saved_search_rows(kept)
            except OSError as exc:
                app.logger.error(f"Saved searches could not be written: {exc}")
                return jsonify({
                    'error': "This search could not be deleted; it is still "
                             "there. Check the server logs.",
                    'error_type': 'saved_searches_unavailable'}), 503
        return jsonify({'success': True})

    @app.route('/livez')
    def livez():
        """Is this process serving requests? Nothing else.

        The liveness and startup probes read this. A restart can only fix
        the process, so nothing outside it — no backend, not even the
        metadata store — may decide it: a thirty-second Loki outage, or a
        database failover, used to have the kubelet restart a container that
        was fine.
        """
        return jsonify({'status': 'alive', 'version': __version__})

    @app.route('/readyz')
    def readyz():
        """Should this instance be sent traffic? The metadata store decides.

        Accounts and roles live there, so without it nothing can be served;
        with it, sign-in, the configuration page and every reachable source
        work, whatever else is down. Only the store is asked, so the answer
        comes back in the time one small query takes.
        """
        try:
            store.users.count()
        except Exception as exc:
            app.logger.warning(f"readyz: metadata store: {exc}")
            return jsonify({'status': 'unavailable',
                            'store': 'unreachable'}), 503
        return jsonify({'status': 'ready', 'store': 'connected'})

    #: The newest /health report and when it was made. Per worker, which is
    #: enough: what it bounds is how often one worker asks the backends.
    health_cache = {}

    @app.route('/health')
    def health():
        """Is this instance able to answer?

        Three things were wrong here, and each one made an unhealthy instance
        report as healthy — which is worse than having no probe at all, because
        an orchestrator keeps sending it traffic.

        `ping()` RETURNS False for an unreachable cluster; it does not raise.
        Only the exception was handled, so a dead cluster answered "connected".

        It also covered nothing but the environment-configured Elasticsearch.
        A deployment whose Loki is down, or whose metadata store is gone, was
        entirely healthy by this measure while half its screens were empty.

        And the failure branch returned `str(exc)` to an unauthenticated
        caller, which is where connection strings live. Detail is logged;
        callers get a name.

        WHAT COUNTS AS UNHEALTHY is the fourth. It used to be "anything at
        all", and both Kubernetes probes point here, so an unreachable data
        source did two things nobody asked for:

          * readiness failed, the pod left the Service, and the one screen
            that could have fixed the problem — the configuration page —
            became unreachable. On a first deployment, where the cluster
            address then defaulted to a localhost that was not there, the
            pod never became ready at all;
          * liveness failed, so the kubelet RESTARTED the container. A Loki
            outage of thirty seconds put WDash into a restart loop.

        An unreachable log backend is a degraded instance, not a dead one: it
        still serves sign-in, RBAC, dashboards, the configuration page and
        every other source. The metadata store is the only thing WDash cannot
        work without — accounts and roles live there — so that alone decides
        the status code. Everything else is reported and named, which is what
        an alert should be reading anyway.

        AND HOW LONG IT TOOK was the fifth. The checks ran one after another
        inside the request: the environment cluster pinged twice (once as
        itself, once as `elasticsearch-traces`), each with a ten-second client
        timeout, then five seconds for every Loki, Tempo and VictoriaLogs.
        Measured: one Loki waiting out its timeout made this answer in 5.0s,
        past both probe timeouts, and a cluster that accepted and never
        replied made it 20.0s. The kubelet read a slow answer as a dead one
        and restarted a container that was fine. So the probes no longer
        come here (see /livez and /readyz); the checks run at once, the
        whole report answers within HEALTH_BUDGET_SECONDS, whatever has not
        answered by then is named as unreachable, and the report is reused
        for HEALTH_CACHE_SECONDS so a poller cannot hold every worker on a
        backend that hangs.
        """
        cached = health_cache.get('report')
        ttl = float(app.config['HEALTH_CACHE_SECONDS'])
        if cached and time.monotonic() - cached[0] < ttl:
            return jsonify(cached[1]), cached[2]

        checks = {}
        try:
            store.users.count()
            checks['store'] = 'connected'
        except Exception as exc:
            app.logger.warning(f"health: metadata store: {exc}")
            checks['store'] = 'unreachable'

        # Keyed by name, so one stored source serving logs AND traces — two
        # adapters over one client — is asked once and reported once.
        probes = {}
        for source in list(app.hub.log_sources) + list(app.hub.trace_sources):
            probes[source.name] = source.health
        checks.update(_ask_at_once(probes,
                                   float(app.config['HEALTH_BUDGET_SECONDS'])))

        degraded = sorted(name for name, state in checks.items()
                          if state != 'connected')
        # The store is the only hard dependency, so it is the only one that
        # may take the instance out of service.
        serving = checks['store'] == 'connected'

        status = 'healthy' if not degraded else (
            'degraded' if serving else 'unhealthy')
        # The version, because "which build is this?" was a question a
        # running instance could not answer. It was written down in four
        # places that disagreed — the package said 1.0.0 while the published
        # images had reached 2.2.4 — and in none of them could an operator
        # reach it without shelling into the container.
        payload = dict(checks, status=status, version=__version__)
        if degraded:
            # Named, so an alert can say WHICH backend is down without having
            # to diff two payloads.
            payload['degraded'] = degraded
        code = 200 if serving else 503
        health_cache['report'] = (time.monotonic(), payload, code)
        return jsonify(payload), code

    def _ask_at_once(probes, budget):
        """{name: 'connected' | 'unreachable'}, every probe at once, the lot
        within `budget` seconds. A probe still running when it is up is
        unreachable, and is left to finish on its own thread: its answer is
        no longer wanted, and waiting for it is what made this slow."""
        from concurrent.futures import ThreadPoolExecutor, wait
        if not probes:
            return {}
        pool = ThreadPoolExecutor(max_workers=len(probes),
                                  thread_name_prefix="health")
        futures = {name: pool.submit(probe) for name, probe in probes.items()}
        wait(futures.values(), timeout=budget)
        pool.shutdown(wait=False)
        out = {}
        for name, future in futures.items():
            if not future.done():
                app.logger.warning(f"health: {name}: no answer within {budget:g}s")
                out[name] = 'unreachable'
                continue
            try:
                healthy, detail = future.result()
            except Exception as exc:
                healthy, detail = False, str(exc)
            out[name] = 'connected' if healthy else 'unreachable'
            if not healthy:
                app.logger.warning(f"health: {name}: {detail}")
        return out

    @app.route('/api/debug/dashboard-manager')
    @login_required
    def debug_dashboard_manager():
        """Debug endpoint for dashboard manager (admin only)"""
        if not current_user.has_permission('system:admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            stats = dashboard_manager.get_stats()
            dashboard_list = [
                {
                    'id': d.id,
                    'name': d.name,
                    'created_by': d.created_by,
                    'created_at': d.created_at.isoformat(),
                    'index_patterns': d.index_patterns
                }
                for d in dashboard_manager.get_all_dashboards()
            ]
            
            return jsonify({
                'manager_stats': stats,
                'dashboards': dashboard_list,
                'total_count': len(dashboard_list)
            })
        except Exception as exc:
            # Detail to the log, a name to the caller — the same rule /health
            # follows, for the same reason: exception text is where
            # connection strings live.
            app.logger.error(f"debug dashboard-manager: {exc}")
            return jsonify({'error': 'Debug info could not be collected.'}), 500
    
    @app.route('/api/debug/refresh-dashboards', methods=['POST'])
    @login_required
    def refresh_dashboards():
        """Force refresh dashboard cache (admin only)"""
        if not current_user.has_permission('system:admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        try:
            dashboard_manager.refresh_cache()
            stats = dashboard_manager.get_stats()
            return jsonify({
                'message': 'Dashboard cache refreshed',
                'stats': stats
            })
        except Exception as exc:
            app.logger.error(f"debug refresh-dashboards: {exc}")
            return jsonify({'error': 'Refresh failed.'}), 500
    
    return app


if __name__ == '__main__':
    # Kept in step with main.py, which is the entry point people actually
    # use: 127.0.0.1 by default, because `debug=True` serves an interactive
    # console on any traceback.
    app = create_app()
    app.run(debug=True,
            host=os.environ.get('WDASH_DEV_HOST', '127.0.0.1'),
            port=int(os.environ.get('WDASH_DEV_PORT', 5000)))
