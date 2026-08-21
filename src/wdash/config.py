import os
from dotenv import load_dotenv

#: A test run must not read the developer's `.env`.
#:
#: `load_dotenv()` at import puts that file's values into the process
#: environment, and `Config`'s attributes are computed from it on the next
#: line — so the suite meant one thing on a machine with a `.env` and another
#: on CI, which has none. That is the same divergence the environment
#: variables caused, arriving through a file instead of a shell.
#:
#: Set by `tests/__init__.py` before anything from this package is imported.
if os.environ.get("WDASH_NO_DOTENV") != "1":
    load_dotenv()

#: Where the metadata store lives when nothing is configured: local accounts,
#: their password hashes, and every credential the encryption key protects.
#: Named because a test has to be able to say "not THAT one" about it.
DEFAULT_DATABASE_URL = 'sqlite:///data/wdash.db'

#: The packaged dashboard file. Named so the app factory can tell
#: "nobody configured this" from "somebody configured this path" —
#: the same comparison the database URL needs, and for the same reason.
DEFAULT_DASHBOARD_FILE = 'data/dashboards.json'

#: The session key when nobody sets one. Named, rather than written inline,
#: because `create_app` has to be able to say "not THAT one" about it: the
#: string is printed in this repository, it signs session cookies, and anybody
#: holding it can mint the administrator's. Right for `python main.py` on a
#: laptop, and nowhere else.
DEV_SECRET_KEY = 'dev-secret-key-change-in-production'

#: What holds traces when nobody says otherwise. Named so the log
#: source can keep excluding spans even when the environment trace
#: source is switched off — those are different statements.
DEFAULT_TRACE_PATTERNS = ('*traces*', '*apm*')


class Config:
    """Application configuration"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or DEV_SECRET_KEY
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    # Elasticsearch Configuration
    #: `or` rather than a default was the whole reason Elasticsearch could not
    #: be switched off: an explicitly empty value fell straight back to the
    #: local URL, so "no cluster here" was unsayable. Unset still means the
    #: local default; set-and-empty now means none.
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL',
                                       'http://localhost:9200')
    ELASTICSEARCH_USERNAME = os.environ.get('ELASTICSEARCH_USERNAME')
    ELASTICSEARCH_PASSWORD = os.environ.get('ELASTICSEARCH_PASSWORD')
    ELASTICSEARCH_TIMEOUT = int(os.environ.get('ELASTICSEARCH_TIMEOUT', 30))
    # Certificate verification for the environment-configured cluster. Sources
    # added on the config page have carried this switch for a while; the one
    # every deployment uses had it wired off in code with no way to turn it on.
    #
    # The default stays off so no existing deployment loses its cluster on
    # upgrade. It should be on wherever WDash talks to Elasticsearch over
    # anything but a loopback address.
    ELASTICSEARCH_VERIFY_CERTS = (
        os.environ.get('ELASTICSEARCH_VERIFY_CERTS', 'False').lower() == 'true')
    #: Path to a CA bundle, for a cluster behind a private authority.
    #: Verification without this trusts the system store only.
    ELASTICSEARCH_CA_CERTS = os.environ.get('ELASTICSEARCH_CA_CERTS') or None
    
    # OIDC Configuration
    OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID')
    OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET')
    OIDC_DISCOVERY_URL = os.environ.get('OIDC_DISCOVERY_URL')
    OIDC_REDIRECT_URI = os.environ.get('OIDC_REDIRECT_URI') or 'http://127.0.0.1:5001/auth/callback'
    #: What to ask the provider for. `groups` is included because roles are
    #: mapped from groups, and a provider that gates that claim behind a
    #: scope sends nothing without it — which reaches WDash as "this person
    #: belongs to nothing" and lands them on the default role.
    OIDC_SCOPES = (os.environ.get('OIDC_SCOPES')
                   or 'openid email profile groups')
    
    # ------------------------------------------------------------------
    # METADATA DATABASE
    #
    # WDash's own state: local accounts, roles, source definitions, settings,
    # dashboards and saved searches. Deliberately NOT Elasticsearch — that is
    # a data source, and it may not even be present once other backends are
    # configured. A search index is also the wrong home for a password hash.
    #
    #   postgresql://user:pass@host/wdash   more than one process
    #   sqlite:///data/wdash.db             single node and the lab
    # ------------------------------------------------------------------
    DATABASE_URL = os.environ.get('DATABASE_URL') or DEFAULT_DATABASE_URL

    # Encrypts secrets held in that database (OIDC client secret, LDAP bind
    # password, source credentials). Without it those cannot be stored at all —
    # WDash refuses rather than writing them as text.
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    ENCRYPTION_KEY = os.environ.get('WDASH_ENCRYPTION_KEY')

    
    # Which indices hold which signal. Logs and traces live in the same
    # cluster, and a log search that also scans the trace store returns spans
    # as bodyless records — confusing and slow.
    #: Read with a default rather than `or`, so an explicitly empty value
    #: means empty. The same mistake as ELASTICSEARCH_URL: `or` turns
    #: "configured as nothing" back into the default, so "this deployment has
    #: no environment trace source, the config page declares them" was
    #: unsayable — and the environment source read the same indices as the
    #: configured ones, counting every span twice.
    TRACE_INDEX_PATTERNS = tuple(
        p.strip() for p in
        os.environ.get('TRACE_INDEX_PATTERNS',
                       ','.join(DEFAULT_TRACE_PATTERNS)).split(',')
        if p.strip())

    # RBAC Configuration
    RBAC_CONFIG_FILE = os.environ.get('RBAC_CONFIG_FILE') or 'config/rbac.yaml'
    
    # Application Settings
    LOGS_PER_PAGE = int(os.environ.get('LOGS_PER_PAGE', 50))
    MAX_SEARCH_RESULTS = int(os.environ.get('MAX_SEARCH_RESULTS', 1000))
    DASHBOARD_STORAGE_FILE = (os.environ.get('DASHBOARD_STORAGE_FILE')
                              or DEFAULT_DASHBOARD_FILE)

    # Where dashboards are persisted: 'file' (default) or 'elasticsearch'.
    #
    # The file store keeps everything in one JSON document, so two workers
    # editing different dashboards at the same moment lose one of the edits —
    # silently, since both writes succeed. Anything running more than one
    # replica should use 'elasticsearch', which stores one document per
    # dashboard and rejects a genuinely conflicting write instead.
    DASHBOARD_STORAGE = (os.environ.get('DASHBOARD_STORAGE') or 'file').strip().lower()
    DASHBOARD_INDEX = os.environ.get('DASHBOARD_INDEX') or 'wdash-dashboards'
    
    # Security Settings
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    #: How many reverse proxies sit in front of WDash.
    #:
    #: Zero — the default — means the socket address is used and
    #: `X-Forwarded-For` is ignored entirely. That header is written by
    #: whatever spoke to the proxy, so trusting it without knowing the depth
    #: lets a client name its own address and step around a per-address rate
    #: limit by changing a header. Set this to the real number, and the
    #: address is counted in from the right.
    #: Where synthetic monitors are stored. Heartbeat and the Fleet Synthetics
    #: integration write to these by default; a deployment that renamed them
    #: says so here.
    MONITOR_INDEX_PATTERNS = tuple(
        p.strip() for p in
        (os.environ.get('MONITOR_INDEX_PATTERNS') or '').split(',') if p.strip())

    TRUSTED_PROXY_COUNT = int(os.environ.get('TRUSTED_PROXY_COUNT', 0))
