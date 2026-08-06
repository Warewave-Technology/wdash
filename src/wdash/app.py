"""
WDash - Main Application
A minimal Kibana alternative with RBAC and OIDC support
"""

import os
import sys
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_required, current_user

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wdash.config import (
    Config, DEFAULT_DASHBOARD_FILE, DEFAULT_DATABASE_URL,
    DEFAULT_TRACE_PATTERNS)
from wdash.auth import auth_bp, load_user_from_session
from wdash.auth.setup import register_setup_gate, setup_bp
from wdash.logs import ElasticsearchClient
from wdash.dashboard import DashboardManager
from wdash.store import SecretBox, Store
from wdash.models import SavedSearch
from wdash.utils import timerange
from wdash.api.advisor_routes import advisor_bp
from wdash.api.trace_routes import trace_bp
from wdash.api.log_routes import log_bp
from wdash.api.config_routes import config_bp
from wdash.api.dashboard_routes import dashboard_bp
from wdash.hub import Hub
from wdash.hub.adapters import ElasticsearchLogSource, ElasticsearchTraceSource
from wdash.hub.adapters.elasticsearch import _IndexCatalogue
from wdash.hub.factory import register_configured_sources
from datetime import datetime, timedelta
import uuid


def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__, 
                template_folder='../../templates',
                static_folder='../../static')
    app.config.from_object(config_class)
    
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
    # A test run must not write into the repository's data directory: a
    # database that survives between runs makes tests order-dependent and
    # eventually makes one of them fail for reasons nobody can reproduce.
    #
    # Compared against the literal default, not against Config.DATABASE_URL —
    # that attribute already reflects DATABASE_URL from the environment, so
    # comparing to it discarded an explicitly configured database as well.
    database_url = app.config.get('DATABASE_URL')
    if app.config.get('TESTING') and database_url == DEFAULT_DATABASE_URL:
        database_url = 'sqlite:///:memory:'

    store = Store.open(
        database_url,
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
            "OIDC and LDAP credentials cannot be saved from the config page")

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
        hub.add_logs(ElasticsearchLogSource(
            es_client.es, name="elasticsearch-logs",
            exclude=excluded_from_logs + own_indices, catalogue=catalogue))
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

    # Sources added through the config page. Registered AFTER the
    # environment-configured ones so a deployment that has always worked keeps
    # its default, and an operator adding a source does not silently take it
    # over. A broken one is logged and skipped; it must not stop startup.
    configured = register_configured_sources(hub, store, catalogue)
    if configured:
        app.logger.info(f"{configured} source(s) registered from configuration")

    app.duplicate_sources = _same_backend_twice(app, store)
    for warning in app.duplicate_sources:
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

    def _load_saved_searches():
        """Every stored search. File store only — the database never reads
        them all, because it can ask for one person's."""
        if not os.path.exists(SAVED_SEARCHES_FILE):
            return []
        try:
            with open(SAVED_SEARCHES_FILE, 'r') as f:
                return [SavedSearch.from_dict(d) for d in json.load(f)]
        except Exception:
            return []

    def _save_saved_searches(searches):
        # Read-modify-write over one file: two people saving a search at the
        # same moment lose one of the two, invisibly, because both writes
        # succeed. The database store does not have this problem, which is
        # the argument for moving.
        os.makedirs(os.path.dirname(SAVED_SEARCHES_FILE), exist_ok=True)
        with open(SAVED_SEARCHES_FILE, 'w') as f:
            json.dump([s.to_dict() for s in searches], f, indent=2)

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
        searches = _load_saved_searches()
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

        searches = _load_saved_searches()
        search = SavedSearch(
            search_id=str(uuid.uuid4()),
            name=data['name'],
            query=data['query'],
            time_range=data.get('time_range', '1h'),
            created_by=current_user.username
        )
        searches.append(search)
        _save_saved_searches(searches)
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

        searches = _load_saved_searches()
        original_len = len(searches)
        searches = [s for s in searches
                    if not (s.id == search_id
                            and s.created_by == current_user.username)]
        if len(searches) == original_len:
            return jsonify({'error': 'Not found or not owned by you'}), 404
        _save_saved_searches(searches)
        return jsonify({'success': True})

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
        """
        checks = {}

        if es_client is not None:
            try:
                checks['elasticsearch'] = (
                    'connected' if es_client.es.ping() else 'unreachable')
            except Exception as exc:
                app.logger.warning(f"health: elasticsearch: {exc}")
                checks['elasticsearch'] = 'unreachable'

        try:
            store.users.count()
            checks['store'] = 'connected'
        except Exception as exc:
            app.logger.warning(f"health: metadata store: {exc}")
            checks['store'] = 'unreachable'

        for source in list(app.hub.log_sources) + list(app.hub.trace_sources):
            if source.name == 'elasticsearch-logs':
                continue          # the same cluster, already reported above
            try:
                healthy, detail = source.health()
            except Exception as exc:
                healthy, detail = False, str(exc)
            checks[source.name] = 'connected' if healthy else 'unreachable'
            if not healthy:
                app.logger.warning(f"health: {source.name}: {detail}")

        degraded = sorted(name for name, state in checks.items()
                          if state != 'connected')
        # The store is the only hard dependency, so it is the only one that
        # may take the instance out of service.
        serving = checks['store'] == 'connected'

        status = 'healthy' if not degraded else (
            'degraded' if serving else 'unhealthy')
        payload = dict(checks, status=status)
        if degraded:
            # Named, so an alert can say WHICH backend is down without having
            # to diff two payloads.
            payload['degraded'] = degraded
        return jsonify(payload), (200 if serving else 503)
    
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
