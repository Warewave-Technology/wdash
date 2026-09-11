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

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wdash import __version__
from wdash.config import (
    Config, DEFAULT_DASHBOARD_FILE, DEFAULT_TRACE_PATTERNS,
    PUBLISHED_SECRET_KEYS)
from wdash.auth import auth_bp, load_user_from_session
from wdash.auth.setup import register_setup_gate, setup_bp
from wdash.logs import ElasticsearchClient
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
from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource
from wdash.hub.adapters.elasticsearch import _IndexCatalogue
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
    
    # Elasticsearch, if there is one.
    #
    # `ELASTICSEARCH_URL` set to nothing means "no Elasticsearch here" — a
    # deployment reading logs from Loki or VictoriaLogs should not have to run
    # a cluster it never queries. The default is still the local URL, so
    # nothing changes for a deployment that has always had one.
    #
    # Every consumer of `app.es_client` has to cope with None. The screens that
    # genuinely need a cluster say so; the ones that do not carry on.
    es_url = (app.config.get('ELASTICSEARCH_URL') or '').strip()
    es_client = ElasticsearchClient(app.config) if es_url else None
    if es_client is None:
        app.logger.info(
            "No ELASTICSEARCH_URL is set: Elasticsearch features are off")

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
        rbac_file=app.config.get('RBAC_CONFIG_FILE'),
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

    # Where dashboards live. 'database' is the destination; 'file' remains the
    # default until an existing deployment has run the migration, because
    # flipping it silently would leave every stored dashboard behind.
    storage = str(app.config.get('DASHBOARD_STORAGE', 'file')).lower()
    if storage == 'database':
        dashboard_manager = store.dashboards
    elif storage == 'elasticsearch':
        # Removed. Refused rather than quietly falling through to the file
        # store, which would present an empty list as though every dashboard
        # had been deleted — and the person would go looking for a deletion
        # that never happened.
        raise RuntimeError(
            "DASHBOARD_STORAGE=elasticsearch has been removed. Move the data "
            "into the metadata database first:\n"
            "  PYTHONPATH=src python -m wdash.store.migrate_cli \\\n"
            "      --from-elasticsearch $ELASTICSEARCH_URL\n"
            "then set DASHBOARD_STORAGE=database.")
    else:
        # Same isolation the metadata store gets, and for the same reason it
        # needed it: a test run must not write into the repository's data
        # directory. It did — 3,000 fixture dashboards accumulated in
        # `data/dashboards.json` across runs, and the dashboards page rendered
        # every one of them into a seven-megabyte response.
        #
        # Compared against the literal default so an explicitly configured
        # path is never discarded.
        storage_file = app.config['DASHBOARD_STORAGE_FILE']
        if app.config.get('TESTING') and storage_file == DEFAULT_DASHBOARD_FILE:
            import tempfile
            storage_file = os.path.join(tempfile.mkdtemp(prefix="wdash-test-"),
                                        "dashboards.json")
        dashboard_manager = DashboardManager(storage_file)
    
    # Store services in app context
    app.es_client = es_client
    app.dashboard_manager = dashboard_manager

    # The hub is the backend-neutral access layer. Every route works through
    # it; nothing Elasticsearch-specific reaches the HTTP layer.
    hub = Hub()
    # One index catalogue shared by both sources: the cluster's index list is
    # the same for logs and traces, so there is no reason to fetch it twice.
    catalogue = None
    trace_patterns = app.config.get("TRACE_INDEX_PATTERNS", ("*traces*", "*apm*"))
    if es_client is not None:
        catalogue = _IndexCatalogue(es_client.es)

        # Kept after the Elasticsearch dashboard store was removed: an
        # installation that used it still has the index sitting in the
        # cluster, and without this a log search over `*` returns dashboards
        # as bodyless records.
        own_indices = (app.config.get('DASHBOARD_INDEX', 'wdash-dashboards'),)

        # The exclusion does NOT follow the trace source being switched off.
        #
        # `TRACE_INDEX_PATTERNS` does two jobs: it says which indices hold
        # traces, and — emptied — it says "do not register an environment
        # trace source". Emptying it took the log-side exclusion with it, so
        # a deployment that moved its trace source to the configuration page
        # found its log search scanning the span indices and returning
        # bodyless records. Those are different statements, and only one of
        # them is about the log source.
        excluded_from_logs = tuple(trace_patterns) or DEFAULT_TRACE_PATTERNS
        # Heartbeat's too, which the monitor source below reads. Heartbeat 8
        # writes data streams, and once the catalogue listed streams by name
        # its checks would have come back from a log search over `*` as
        # records with no body — the reason the trace indices are left out.
        from wdash.hub.adapters.es_monitors import DEFAULT_PATTERNS as HEARTBEAT
        heartbeat = tuple(app.config.get("MONITOR_INDEX_PATTERNS") or HEARTBEAT)
        hub.add_logs(ElasticsearchLogSource(
            es_client.es, name="elasticsearch-logs",
            exclude=excluded_from_logs + own_indices + heartbeat,
            catalogue=catalogue))
        # No patterns means no environment trace source. A deployment that
        # declares its trace backends on the configuration page — APM on one
        # cluster, OpenTelemetry on another — does not want a third source
        # reading both of them, which would count every span twice.
        if trace_patterns:
            hub.add_traces(ElasticsearchTraceSource(
                es_client.es, name="elasticsearch-traces",
                patterns=trace_patterns, catalogue=catalogue))
        else:
            app.logger.info(
                "TRACE_INDEX_PATTERNS is empty: no environment trace source")

        # Synthetic monitors from the same cluster. Registered unconditionally
        # because the index names are Heartbeat's own — `heartbeat-*` and
        # `synthetics-*` — and a cluster without them simply reports no
        # monitors. There is nothing to overlap with the way the trace and log
        # patterns can overlap with each other.
        from wdash.hub.adapters.es_monitors import (
            DEFAULT_PATTERNS as MONITOR_PATTERNS, ElasticsearchMonitorSource,
        )
        monitor_patterns = app.config.get("MONITOR_INDEX_PATTERNS") or MONITOR_PATTERNS
        hub.add_monitors(ElasticsearchMonitorSource(
            es_client.es, name="elasticsearch-monitors",
            patterns=monitor_patterns, catalogue=catalogue))

    # The checks WDash runs itself. Registered unconditionally and cheap when
    # unused: with no agents and no monitors it reports an empty list, which
    # is the truth rather than an absence the page has to explain.
    #
    # Part of the BASE set, with the environment's sources: it reads the
    # metadata store this process already holds, so there is nothing about it
    # that a configuration edit could change.
    if store is not None:
        from wdash.hub.adapters.store_monitors import StoreMonitorSource
        hub.add_monitors(StoreMonitorSource(store))

    # Sources added through the config page. Loaded AFTER the environment ones
    # so a deployment that has always worked keeps its default, and an
    # operator adding a source does not silently take over the queries that
    # name no source. A broken one is logged and skipped; it must not stop
    # startup.
    #
    # Handed to the hub as a recipe rather than a result, so an administrator
    # saving the form does not have to restart WDash to use what they just
    # configured. The page used to say so out loud, which made the
    # configuration screen the one screen that could not configure anything.
    if store is not None:
        # What the base registry already answers to. Asked at save time, so
        # `elasticsearch-logs` typed into the form is a sentence about the
        # name rather than a row that is stored, listed, and reachable by
        # nothing because the environment's source keeps the name.
        store.sources.reserved_names = hub.base_source_names

        hub.reload_with(
            build=lambda: build_configured_sources(store, catalogue),
            # A lambda rather than the bound method: it is looked up on
            # the repository each time, so a store that swaps one in is
            # honoured rather than shadowed by what was captured here.
            stamp=lambda: store.sources.stamp())
        if hub.configured_count:
            app.logger.info(
                f"{hub.configured_count} source(s) from configuration")

    # Recomputed on demand rather than at startup, because the sources it
    # compares are now live: a duplicate added on the configuration page has
    # to be reported by the configuration page, not by the next restart.
    app.duplicate_sources = lambda: _same_backend_twice(app, store)
    for warning in app.duplicate_sources():
        app.logger.warning(warning)

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
    searches_in_database = str(
        app.config.get('DASHBOARD_STORAGE', 'file')).lower() == 'database'
    SAVED_SEARCHES_FILE = os.path.join(
        os.path.dirname(app.config['DASHBOARD_STORAGE_FILE']),
        'saved_searches.json')

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
            became unreachable. On a first deployment, where the default
            ELASTICSEARCH_URL points at a localhost that is not there, the
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

        probes = {}
        if es_client is not None:
            probes['elasticsearch'] = lambda: (
                (True, 'ok') if es_client.es.ping()
                else (False, 'ping failed: no response from the cluster'))
        for source in list(app.hub.log_sources) + list(app.hub.trace_sources):
            if es_client is not None and source.name in (
                    'elasticsearch-logs', 'elasticsearch-traces'):
                continue          # the same cluster, already reported above
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

def _normalise_url(value):
    """Compare cluster addresses, not the strings people typed."""
    return (value or "").strip().rstrip("/")


def _same_backend_twice(app, store):
    """Warn when two registered sources read the same system.

    The environment Elasticsearch predates the configuration page, and both
    still register. Point a configured source at the same cluster — which is
    what an operator does when they move to the configuration page and forget
    to unset `ELASTICSEARCH_URL` — and every matching log line is counted
    twice in a merged search, silently. The totals simply look bigger.

    Reported rather than resolved: which one to drop is the operator's
    decision, and picking for them could take away the source their saved
    links name.
    """
    # Both sides normalised: `http://host:9200/` and `http://host:9200` are
    # one cluster, and a comparison that misses that reports nothing on the
    # commonest way of typing it.
    url = _normalise_url(app.config.get("ELASTICSEARCH_URL"))
    # Short circuit, not a check: `validate` refuses a source without a url,
    # so an empty environment url cannot match a stored one either way.
    if not url or store is None:
        return []

    try:
        rows = store.sources.all(enabled_only=True)
    except Exception:
        # Returning [] here would state "no duplicates", which is not what
        # "could not look" means. Say which one happened.
        app.logger.exception("Could not check for duplicate sources")
        return []

    clashes = []
    for row in rows:
        if row["kind"] != "elasticsearch":
            continue
        if _normalise_url(row["config"].get("url")) != url:
            continue
        clashes.append(
            f"Source '{row['name']}' points at the same Elasticsearch as "
            f"ELASTICSEARCH_URL ({url}). Both are registered, so a merged "
            f"search counts every matching record twice. Unset "
            f"ELASTICSEARCH_URL to keep only the configured source, or "
            f"delete the configured one.")
    return clashes
