"""
The scope a request is answered under.

Three route modules built it the same way, and now it needs something only the
application knows: which names are sources. A rule's colon qualifies it only
when the part before it names one (see hub.patterns.parse), so a scope built
without the names reads `unknown_service:java` as a rule for a source that
does not exist.
"""

from flask import current_app
from flask_login import current_user

from ..hub import Scope


def source_names():
    """Every name a role's rule can be qualified by.

    What the hub has registered, for every signal, WDash's own monitor source
    included; and what is configured but switched off. A rule written for a
    source that is switched off is still that source's rule. Read as a plain
    name, it could match something in another source.
    """
    names = set()
    hub = getattr(current_app, "hub", None)
    if hub is not None:
        for source in hub.log_sources + hub.trace_sources + hub.monitor_sources:
            names.add(source.name)
    store = getattr(current_app, "store", None)
    if store is not None:
        try:
            names.update(record["name"] for record in store.sources.all())
        except Exception:
            # The registered names still stand; a store that cannot be read
            # here has already been reported where the hub reloads.
            pass
    return frozenset(names)


def request_scope():
    return Scope.from_user(current_user, sources=source_names())
