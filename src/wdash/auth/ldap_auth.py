"""
Authenticating against a directory.

The library choice is confined to this file on purpose: `ldap3` is LGPL v3,
which is fine for a library imported at runtime but is the one dependency in
this project that is not permissively licensed. Keeping it behind a single
function means swapping it costs one file, not an audit.

How a sign-in works
-------------------
1. bind as the service account and search for the user, or build their DN
   directly from the filter if no service account is configured
2. bind AS THE USER with the password they typed — this is the actual check;
   a successful search proves the account exists, not that the password is right
3. read the group attribute and hand the groups back for role resolution

Step 2 is the one people get wrong. Searching with a service account and
treating "found" as "authenticated" is a complete authentication bypass, and it
looks like working code.

A wrong password and a directory that could not answer are different outcomes.
The second raises `DirectoryUnavailable`: it was returned as "no such user", so
an outage — or a service account whose password had changed — was recorded as
a failed guess against every name that tried, and five tries locked people out
of an account that was fine.
"""

import logging
import re

logger = logging.getLogger(__name__)

TIMEOUT = 10

#: LDAP result code for a bind with the wrong password (RFC 4511).
INVALID_CREDENTIALS = 49


class DirectoryUnavailable(RuntimeError):
    """The directory could not answer: unreachable, its certificate refused,
    the service account refused, or a search that failed."""

#: Characters that would change the meaning of an LDAP filter. A username is
#: interpolated into one, so it is escaped the way RFC 4515 requires — the
#: injection here is the directory equivalent of SQL injection, and `*` alone
#: turns a filter into "any user".
_ESCAPES = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00",
            "/": r"\2f"}


def escape_filter(value):
    return "".join(_ESCAPES.get(char, char) for char in value or "")


def _tls(settings):
    """How ldaps:// is checked: the certificate and the name on it.

    ldap3's own default is CERT_NONE, and the password a person types is sent
    in the bind that follows — so anybody between WDash and the directory
    could present any certificate and read it. The system's CAs are used
    unless a CA file is given; turning the check off is a setting somebody
    has to choose, and it is logged every time.
    """
    import ssl
    from ldap3 import Tls

    if settings.get("verify_certs", True) is False:
        logger.warning("LDAP: certificate verification is OFF for "
                       f"{settings.get('server')}; a password can be read by "
                       f"anything that answers in the directory's place")
        return Tls(validate=ssl.CERT_NONE)
    return Tls(validate=ssl.CERT_REQUIRED,
               ca_certs_file=settings.get("ca_certs") or None)


def _connection(settings, user=None, password=None, receive_timeout=TIMEOUT):
    from ldap3 import ALL, Connection, Server

    server_uri = settings["server"]
    use_ssl = server_uri.lower().startswith("ldaps://")
    server = Server(server_uri, get_info=ALL, connect_timeout=receive_timeout,
                    use_ssl=use_ssl, tls=_tls(settings) if use_ssl else None)
    return Connection(server, user=user, password=password,
                      auto_bind=False, receive_timeout=receive_timeout)


def _bind(connection, who):
    """True on success, False on a wrong password, raising otherwise."""
    from ldap3.core.exceptions import LDAPException
    try:
        if connection.bind():
            return True
    except LDAPException as exc:
        raise DirectoryUnavailable(f"{who} could not bind: {exc}") from exc
    code = (connection.result or {}).get("result")
    if code == INVALID_CREDENTIALS:
        return False
    raise DirectoryUnavailable(
        f"{who} could not bind: {(connection.result or {}).get('description')}")


def authenticate(settings, username, password):
    """Returns {username, email, groups} on success, None on failure.

    An empty password is refused outright. Most directories treat a bind with
    an empty password as an ANONYMOUS bind and return success, which would
    authenticate anyone who submits a blank field.
    """
    username = (username or "").strip()
    if not username or not password:
        return None

    filter_template = settings.get("user_filter") or "(uid={username})"
    user_filter = filter_template.replace("{username}", escape_filter(username))

    # Find the user's DN. With a service account this is a search; without one
    # the filter has to be enough to construct the DN.
    user_dn, attributes = _find_user(settings, user_filter)
    if user_dn is None:
        logger.info(f"LDAP: no directory entry matched {username!r}")
        return None

    # THE actual check: bind as that user with the password they typed.
    connection = _connection(settings, user=user_dn, password=password)
    try:
        if not _bind(connection, "the user"):
            logger.info(f"LDAP: bind rejected for {username!r}")
            return None
    finally:
        try:
            connection.unbind()
        except Exception:
            pass

    group_attribute = settings.get("group_attribute") or "memberOf"
    return {
        "username": username,
        "email": _first(attributes.get("mail")),
        "groups": _group_names(attributes.get(group_attribute)),
    }


def _find_user(settings, user_filter):
    """Locate the user entry, returning (dn, attributes).

    Raises DirectoryUnavailable when the directory cannot say: a service
    account that cannot bind is a configuration fault, not an unknown user,
    and so is a search that fails — a base DN that does not exist answered
    exactly like a name that does not.
    """
    from ldap3 import SUBTREE
    from ldap3.core.exceptions import LDAPException

    bind_dn = settings.get("bind_dn") or None
    connection = _connection(settings, user=bind_dn,
                             password=settings.get("bind_password") or None)
    try:
        if not _bind(connection, "the service account"):
            raise DirectoryUnavailable("the service account could not bind: "
                                       "its password was refused")

        group_attribute = settings.get("group_attribute") or "memberOf"
        try:
            found = connection.search(
                search_base=settings["base_dn"], search_filter=user_filter,
                search_scope=SUBTREE, attributes=["mail", "cn", group_attribute],
                size_limit=2)
        except LDAPException as exc:
            raise DirectoryUnavailable(f"the search failed: {exc}") from exc

        code = (connection.result or {}).get("result")
        # 0 is success and 4 is sizeLimitExceeded, which size_limit=2 asks
        # for when the filter matches several; anything else is the search
        # failing, not the user being absent.
        if not found and code not in (0, 4):
            raise DirectoryUnavailable(
                f"the search failed: {(connection.result or {}).get('description')}")
        if not connection.entries:
            return None, {}
        if len(connection.entries) > 1:
            # An ambiguous filter must not silently pick the first match: which
            # account someone signed in as would depend on directory ordering.
            logger.error(
                f"LDAP: {len(connection.entries)} entries matched; the user "
                f"filter is not specific enough")
            return None, {}

        entry = connection.entries[0]
        attributes = {name: entry[name].values for name in entry.entry_attributes}
        return entry.entry_dn, attributes
    finally:
        try:
            connection.unbind()
        except Exception:
            pass


def _first(values):
    if not values:
        return None
    return values[0] if isinstance(values, (list, tuple)) else values


def _group_names(values):
    """Turn group DNs into names.

    `memberOf` yields full DNs (`cn=admins,ou=groups,dc=example,dc=com`), while
    role mappings are written in terms of names. Both forms are returned so an
    administrator can map either without having to know which one their
    directory emits.
    """
    if not values:
        return []
    if not isinstance(values, (list, tuple)):
        values = [values]

    names = []
    for value in values:
        value = str(value)
        names.append(value)
        match = re.match(r"^cn=([^,]+)", value, re.IGNORECASE)
        if match:
            names.append(match.group(1))
    return names
