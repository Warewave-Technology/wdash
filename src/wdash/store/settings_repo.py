"""
Application settings.

One row per key, so a concurrent edit to the OIDC block cannot clobber an edit
to the LDAP block — the same lesson as one row per dashboard, applied to
config.

Secrets are a separate column and a separate method. Reading a setting never
returns a secret by accident: `get` gives you the public part, and the secret
has to be asked for explicitly, which is what keeps a client secret out of a
debug page somebody adds later.
"""

from datetime import datetime, timezone

from sqlalchemy import select

from .schema import settings

#: Keys WDash itself uses. Not a whitelist — an operator may store anything —
#: but naming them here keeps the config page and the resolver in step.
DEFAULT_ROLE = "rbac.default_role"
USER_ROLES = "rbac.user_roles"
OIDC = "auth.oidc"
LDAP = "auth.ldap"
#: Where the audit trail is shipped, if anywhere. The credential (an HEC token
#: or a cluster password) is the setting's secret half, so it is encrypted with
#: everything else rather than living in the JSON.
AUDIT_FORWARDING = "audit.forwarding"


class SettingsRepository:
    def __init__(self, engine, secret_box=None):
        self._engine = engine
        self._secrets = secret_box

    def get(self, key, default=None):
        """The public part of a setting."""
        with self._engine.connect() as connection:
            row = connection.execute(
                select(settings.c.value).where(settings.c.key == key)
            ).first()
        return row[0] if row and row[0] is not None else default

    def all(self, prefix=None):
        with self._engine.connect() as connection:
            query = select(settings.c.key, settings.c.value,
                           settings.c.secret_value, settings.c.updated_at,
                           settings.c.updated_by)
            rows = connection.execute(query).mappings().all()
        return {
            row["key"]: {
                "value": row["value"],
                # Never the secret itself: whether one is set is all a caller
                # needs, and returning more turns any settings view into an
                # exfiltration endpoint.
                "has_secret": bool(row["secret_value"]),
                "updated_at": row["updated_at"],
                "updated_by": row["updated_by"],
            }
            for row in rows
            if prefix is None or row["key"].startswith(prefix)
        }

    def secret(self, key):
        """Decrypt and return a stored secret. Raises if the key is wrong."""
        with self._engine.connect() as connection:
            row = connection.execute(
                select(settings.c.secret_value).where(settings.c.key == key)
            ).first()
        if not row or not row[0]:
            return None
        if self._secrets is None:
            raise RuntimeError("No secret box configured for this store.")
        return self._secrets.open(row[0])

    def set(self, key, value=None, secret=None, updated_by=None,
            keep_secret=True):
        """Write a setting.

        `keep_secret` exists for the config form: a blank secret field means
        "leave it alone", not "delete it". Treating blank as deletion means
        anyone who saves the OIDC page without retyping the client secret
        silently breaks single sign-on.
        """
        record = {
            "value": value,
            "updated_at": datetime.now(timezone.utc),
            "updated_by": updated_by,
        }
        if secret is not None:
            if self._secrets is None:
                raise RuntimeError("No secret box configured for this store.")
            record["secret_value"] = self._secrets.seal(secret)
        elif not keep_secret:
            record["secret_value"] = None

        with self._engine.begin() as connection:
            existing = connection.execute(
                select(settings.c.key).where(settings.c.key == key)).first()
            if existing:
                connection.execute(
                    settings.update().where(settings.c.key == key).values(**record))
            else:
                connection.execute(settings.insert().values(key=key, **record))

    def delete(self, key):
        with self._engine.begin() as connection:
            result = connection.execute(
                settings.delete().where(settings.c.key == key))
        return result.rowcount > 0
