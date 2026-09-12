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

#: Every session key this repository has ever printed, and so every key
#: anybody who has read it can sign a cookie with.
#:
#: Knowing only `DEV_SECRET_KEY` was a check with a hole the size of the
#: quick start: README says `cp .env.example .env`, and `.env.example`
#: carried a different literal, which therefore arrived in every deployment
#: built from the README and passed the check without so much as a warning.
#: Removing a literal from the file does not remove it from the `.env` files
#: already copied from it, so the old spellings stay on this list for good.
PUBLISHED_SECRET_KEYS = frozenset({
    DEV_SECRET_KEY,
    # .env.example, from the initial import until it shipped empty.
    'your-secret-key-here-change-in-production',
    # kubernetes/secrets.yaml, base64-encoded, before it shipped empty.
    'your-super-secret-key-change-in-production',
})

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
    # Which claims name a person. Unset falls back to rbac.yaml's
    # claim_mappings, then to preferred_username / email / groups.
    OIDC_USERNAME_CLAIM = os.environ.get('OIDC_USERNAME_CLAIM')
    OIDC_EMAIL_CLAIM = os.environ.get('OIDC_EMAIL_CLAIM')
    OIDC_GROUPS_CLAIM = os.environ.get('OIDC_GROUPS_CLAIM')
    # An email is used only when the provider says it is verified. A provider
    # that never sends email_verified needs this to be trusted at all.
    OIDC_TRUST_UNVERIFIED_EMAIL = (os.environ.get('OIDC_TRUST_UNVERIFIED_EMAIL', '')
                                   .lower() in ('1', 'true', 'yes'))
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

    # Where dashboards are persisted — and saved searches with them, because
    # one setting covers both: 'database' (default) or 'file'. Leaving the
    # searches on the JSON file when dashboards moved made the migration a
    # half-truth once already.
    #
    # The file store keeps everything in one JSON document, so two workers
    # editing different dashboards at the same moment lose one of the edits —
    # silently, since both writes succeed. Measured here, three trials each:
    # 4 processes x 8 creates reported 32 successes and left 9 rows in the
    # file, every trial; the same 32 into SQLite reported 32 and left 32,
    # every trial. The metadata database is opened and migrated
    # before this setting is read, so 'file' does not avoid a database, it
    # adds a second store beside one that is always there.
    #
    # 'file' remains supported and behaves exactly as it always has. An
    # installation that has JSON files and never set this is told at
    # start-up, by name and with the command to run — see
    # `_files_left_behind` in app.py — rather than shown an empty list.
    # Move the existing files in with `python -m wdash.store.migrate_cli`.
    #
    # 'elasticsearch' was a third option and has been removed; app.py refuses
    # it at start-up rather than falling through to the file store. This
    # comment recommended it for exactly the deployment it no longer works
    # for, which is how an operator ends up following it into a refusal.
    DASHBOARD_STORAGE = (os.environ.get('DASHBOARD_STORAGE')
                         or 'database').strip().lower()
    DASHBOARD_INDEX = os.environ.get('DASHBOARD_INDEX') or 'wdash-dashboards'
    
    # Security Settings
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    #: The largest request body accepted, in bytes. There was no limit: any
    #: caller, signed in or not, could send a body of any size and a worker
    #: would read it. 16 MiB is what the proxy in the Kubernetes manifests
    #: accepts, and the agent keeps each delivery well under it.
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    #: /health asks every backend at once and answers within this many
    #: seconds; one that has not answered by then is reported unreachable.
    HEALTH_BUDGET_SECONDS = 2
    #: How long a /health report is reused, so a poller cannot hold a worker
    #: per poll on a backend that hangs.
    HEALTH_CACHE_SECONDS = 10

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
