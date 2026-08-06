"""
Which identity provider settings are actually in force.

Two places can configure a provider: the environment (how it has always
worked) and the configuration page (how it works now). Both have to keep
working, so the rule is stated once here rather than guessed at each call site:

    a provider configured in the store wins; otherwise the environment is used

The store wins because it is the thing an administrator just edited. If the
environment took precedence, the config page would save successfully and change
nothing — the same illusion that made permissions-in-the-cookie a bug.

`enabled` is honoured separately from completeness. Turning a provider off must
disable it even though its settings are still filled in, or the switch is
decoration.

Read on the request that needs them rather than cached at startup: sign-in is
rare, a database round trip is nothing next to an OIDC redirect, and it means
an administrator can fix a broken provider without a restart — which is exactly
the situation in which nobody wants to be told to restart.
"""

import logging

logger = logging.getLogger(__name__)

OIDC_KEY = "auth.oidc"
LDAP_KEY = "auth.ldap"


def _store(app):
    return getattr(app, "store", None)


def oidc_settings(app):
    """Effective OIDC settings, or None when no provider is usable.

    Returns a dict with client_id / client_secret / discovery_url /
    redirect_uri. The secret is decrypted here and must not be logged or put
    into a template.
    """
    store = _store(app)
    if store is not None:
        stored = store.settings.get(OIDC_KEY)
        if stored and stored.get("enabled"):
            try:
                secret = store.settings.secret(OIDC_KEY)
            except Exception as exc:
                # A key that has changed since the secret was written. Say so:
                # falling back to the environment here would sign people in
                # against a provider the administrator thought they had
                # replaced.
                logger.error(f"OIDC client secret could not be read: {exc}")
                return None
            if stored.get("client_id") and stored.get("discovery_url"):
                return {
                    "client_id": stored["client_id"],
                    "client_secret": secret or "",
                    "discovery_url": stored["discovery_url"],
                    "redirect_uri": stored.get("redirect_uri")
                    or app.config.get("OIDC_REDIRECT_URI"),
                    "source": "configuration",
                }
            logger.warning(
                "OIDC is enabled but incomplete (client id and discovery URL "
                "are both required); it will not be offered")
            return None
        if stored is not None and not stored.get("enabled"):
            # Explicitly turned off. Do NOT fall back to the environment —
            # that would make the switch do nothing on a deployment that has
            # both, which is every deployment that has just migrated.
            return None

    if app.config.get("OIDC_CLIENT_ID") and app.config.get("OIDC_DISCOVERY_URL"):
        return {
            "client_id": app.config["OIDC_CLIENT_ID"],
            "client_secret": app.config.get("OIDC_CLIENT_SECRET") or "",
            "discovery_url": app.config["OIDC_DISCOVERY_URL"],
            "redirect_uri": app.config.get("OIDC_REDIRECT_URI"),
            "source": "environment",
        }
    return None


def ldap_settings(app):
    """Effective LDAP settings, or None when no directory is usable."""
    store = _store(app)
    if store is None:
        return None

    stored = store.settings.get(LDAP_KEY)
    if not stored or not stored.get("enabled"):
        return None
    if not stored.get("server") or not stored.get("base_dn"):
        logger.warning(
            "LDAP is enabled but incomplete (server and base DN are both "
            "required); it will not be offered")
        return None

    try:
        password = store.settings.secret(LDAP_KEY)
    except Exception as exc:
        logger.error(f"LDAP bind password could not be read: {exc}")
        return None

    return {
        "server": stored["server"],
        "bind_dn": stored.get("bind_dn") or "",
        "bind_password": password or "",
        "base_dn": stored["base_dn"],
        "user_filter": stored.get("user_filter") or "(uid={username})",
        "group_attribute": stored.get("group_attribute") or "memberOf",
    }
