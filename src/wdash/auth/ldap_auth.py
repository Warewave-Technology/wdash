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

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

TIMEOUT = 10

#: LDAP result code for a bind with the wrong password (RFC 4511).
INVALID_CREDENTIALS = 49

#: Result codes that are the directory failing, not an answer about the
#: person binding (RFC 4511): operationsError, protocolError,
#: timeLimitExceeded, authMethodNotSupported, strongerAuthRequired,
#: adminLimitExceeded, confidentialityRequired, busy, unavailable, other.
DIRECTORY_FAULTS = frozenset({1, 2, 3, 7, 8, 11, 13, 51, 52, 80})


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

    _match_addresses()
    if settings.get("verify_certs", True) is False:
        logger.warning("LDAP: certificate verification is OFF for "
                       f"{settings.get('server')}; a password can be read by "
                       f"anything that answers in the directory's place")
        return Tls(validate=ssl.CERT_NONE)
    return Tls(validate=ssl.CERT_REQUIRED,
               ca_certs_file=settings.get("ca_certs") or None)


def _match_addresses():
    """Let ldap3's name check match an IP address.

    ldap3 checks the name on the certificate itself, and on Python 3.12 and
    later — where the standard library's match_hostname is gone — with a
    backport that knows no IP addresses. ldaps://10.0.0.5, with that address
    in the certificate and its CA given, was refused on every sign-in, and
    the only way out was to turn the check off. Addresses are matched here,
    against the certificate's IP entries; names are left to ldap3.
    """
    from ldap3.core import tls
    if getattr(tls.match_hostname, "wdash", False):
        return
    by_name = tls.match_hostname

    def match_hostname(certificate, hostname):
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            return by_name(certificate, hostname)
        for kind, value in (certificate or {}).get("subjectAltName", ()):
            if kind != "IP Address":
                continue
            try:
                if ipaddress.ip_address(value.strip()) == address:
                    return None
            except ValueError:
                continue
        raise tls.CertificateError(
            f"{hostname} is not among the certificate's addresses")

    match_hostname.wdash = True
    tls.match_hostname = match_hostname


def _connection(settings, user=None, password=None, receive_timeout=TIMEOUT):
    from ldap3 import ALL, Connection, Server

    server_uri = settings["server"]
    use_ssl = server_uri.lower().startswith("ldaps://")
    server = Server(server_uri, get_info=ALL, connect_timeout=receive_timeout,
                    use_ssl=use_ssl, tls=_tls(settings) if use_ssl else None)
    return Connection(server, user=user, password=password,
                      auto_bind=False, receive_timeout=receive_timeout)


def _bind(connection, who, the_person=False):
    """True on success, False on a refusal, raising when the directory failed.

    A wrong password is a refusal for anybody. For the person signing in, so
    is every other answer about them: an account a password policy has
    locked (19), one 389-ds or FreeIPA has inactivated (53). Those were
    reported as the directory being down — a 503 that said "try again
    shortly", an ERROR in the log that read as an outage, and an attempt
    no limit counted. For the service account any refusal means the
    configuration is wrong, which is the directory not being able to answer.
    """
    from ldap3.core.exceptions import LDAPException
    try:
        if connection.bind():
            return True
    except LDAPException as exc:
        raise DirectoryUnavailable(f"{who} could not bind: {exc}") from exc
    code = (connection.result or {}).get("result")
    if code == INVALID_CREDENTIALS or (
            the_person and code is not None and code not in DIRECTORY_FAULTS):
        return False
    raise DirectoryUnavailable(
        f"{who} could not bind: {(connection.result or {}).get('description')}")


#: The attribute a user filter looks the typed name up by. `(uid={username})`
#: means uid; `(sAMAccountName={username})` means sAMAccountName; and it is
#: found inside a longer filter too, since a real one is usually
#: `(&(objectClass=person)(uid={username}))`.
_LOOKED_UP_BY = re.compile(r"([A-Za-z][\w.;-]*)\s*=\s*\{username\}")


def naming_attribute(filter_template):
    """Which attribute the filter identifies somebody by, or None."""
    found = _LOOKED_UP_BY.search(filter_template or "")
    return found.group(1) if found else None


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
        if not _bind(connection, "the user", the_person=True):
            logger.info(f"LDAP: bind rejected for {username!r}")
            return None
    finally:
        try:
            connection.unbind()
        except Exception:
            pass

    group_attribute = settings.get("group_attribute") or "memberOf"
    return {
        "username": _as_the_directory_has_it(filter_template, attributes,
                                             username),
        "email": _first(attributes.get("mail")),
        "groups": _group_names(attributes.get(group_attribute)),
    }


def _as_the_directory_has_it(filter_template, attributes, typed):
    """The name the DIRECTORY holds, falling back to what was typed.

    It was the typed string, always. A directory matches `uid` with
    caseIgnoreMatch, so alice, Alice and ALICE all sign in — and each became
    a different person here: a different role, because a mapping is compared
    exactly; different dashboards, because ownership is `created_by`; and a
    separate thread in the audit trail. Measured against the lab's OpenLDAP,
    with `alice` mapped to admin: typing `alice` landed on admin and typing
    `Alice` on the default role, silently.

    OpenID Connect never had this — the username is a claim the provider
    sends — so this is the LDAP side arriving at the same rule: the
    directory names the person, not the keyboard.

    The attribute is whichever one the filter looks people up by, so an
    installation searching `sAMAccountName` gets that. Where the directory
    returns nothing for it, the typed name stands: a person signing in is
    not the moment to refuse over a missing attribute.
    """
    attribute = naming_attribute(filter_template)
    held = _first(attributes.get(attribute)) if attribute else None
    held = (str(held).strip() if held is not None else "")
    if not held:
        return typed
    if held != typed:
        logger.info(f"LDAP: {typed!r} signed in; the directory has this "
                    f"entry as {held!r}, which is the name WDash uses")
    return held


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
        # The attribute the filter matched on comes back too: it is the name
        # the directory holds for this person, and what WDash calls them.
        wanted = ["mail", "cn", group_attribute]
        naming = naming_attribute(settings.get("user_filter")
                                  or "(uid={username})")
        if naming and naming not in wanted:
            wanted.append(naming)
        try:
            found = connection.search(
                search_base=settings["base_dn"], search_filter=user_filter,
                search_scope=SUBTREE, attributes=wanted,
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
