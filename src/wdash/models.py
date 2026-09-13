from flask_login import UserMixin
from datetime import datetime
import json

class User(UserMixin):
    def __init__(self, user_id, email, username, groups=None):
        self.id = user_id
        self.email = email
        self.username = username
        self.groups = groups or []
        self.role = None
        self.permissions = []
        # Log side: the unit of granularity is the index
        self.allowed_indices = []
        # Trace side: which stores are visible and which services within them
        self.allowed_trace_indices = []
        self.allowed_services = []

    def apply(self, resolved):
        """Take role and boundaries from the resolver.

        The User object no longer decides what it may do; it is told, on every
        request. Keeping that decision here was how permissions ended up frozen
        in a session cookie.
        """
        self.role = resolved.get("role")
        self.permissions = list(resolved.get("permissions") or [])
        self.allowed_indices = list(resolved.get("containers") or [])
        self.allowed_trace_indices = list(resolved.get("trace_containers") or [])
        services = resolved.get("services")
        # None means unrestricted on the trace side, [] means nothing. Collapsing
        # the two would either open every service or close them all.
        self.allowed_services = list(services) if services is not None else None
        return self

    def has_permission(self, permission):
        """Check if user has specific permission"""
        return permission in self.permissions
    

#: The name the search API gives "every source". A board never stores it:
#: see `pinned_source`.
EVERY_SOURCE = "*"


def pinned_source(value):
    """The one stored spelling of a board's source.

    A name pins the board to that source. Nothing — None, the empty string
    the form sends for "All sources", or `*`, which is how the search API
    spells the same choice — is stored as None, so "every source" has ONE
    value in every store and every reader of a row asks one question of it.
    A board that held `*` beside boards that held nothing would be two
    spellings of one meaning, and the day one reader learns only one of them
    is the day a board quietly reads a different set of sources.
    """
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", EVERY_SOURCE) else text


class Dashboard:
    def __init__(self, dashboard_id, name, description, query, created_by,
                 created_at=None, index_patterns=None, panels=None,
                 thresholds=None, visibility=None, source=None):
        self.id = dashboard_id
        self.name = name
        self.description = description
        self.query = query
        self.created_by = created_by
        self.created_at = created_at or datetime.utcnow()
        self.index_patterns = index_patterns or ['*']  # Default to all indices
        #: What this dashboard asks. None means "the standard set" — dashboards
        #: created before panels existed have no list stored, and must keep
        #: rendering exactly as they did.
        self.panels = panels
        #: What "normal" looks like for this dashboard. Empty means it is
        #: never alarming, which is different from "everything is fine".
        self.thresholds = thresholds or {}
        #: Which configured source this dashboard reads from, for every
        #: signal that source serves. None means every source, which is what
        #: every dashboard written before there was a choice means. It lives
        #: on the model rather than only on the database row because the
        #: FILE store had nowhere to put it: the README said a dashboard may
        #: name its source, the forms had no field for it, and the default
        #: store could not have held one if they had.
        self.source = pinned_source(source)
        #: Who may see that this dashboard exists. See dashboard/visibility.py;
        #: the data boundary applies regardless.
        from .dashboard.visibility import normalise as _normalise_visibility
        self.visibility = _normalise_visibility(visibility)

    def get_panels(self):
        """The panel list, falling back to the default set."""
        from .dashboard.panels import default_panels, normalise_all
        if not self.panels:
            return default_panels()
        return normalise_all(self.panels)

    def to_dict(self):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'query': self.query,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'index_patterns': self.index_patterns
        }
        # Only written once customised, so an untouched dashboard keeps
        # following the default set rather than freezing today's version of it.
        if self.panels:
            data['panels'] = self.panels
        if self.thresholds:
            data['thresholds'] = self.thresholds
        # Written only when one was chosen: a board over every source holds
        # nothing, and stays over every source however the set changes.
        if self.source:
            data['source'] = self.source
        data['visibility'] = self.visibility
        return data

    @classmethod
    def from_dict(cls, data):
        dashboard = cls(
            data['id'],
            data['name'],
            data['description'],
            data['query'],
            data['created_by'],
            index_patterns=data.get('index_patterns', ['*']),  # Backward compatibility
            panels=data.get('panels'),
            thresholds=data.get('thresholds'),
            visibility=data.get('visibility'),
            source=data.get('source'),
        )
        if 'created_at' in data:
            dashboard.created_at = datetime.fromisoformat(data['created_at'])
        return dashboard
    
    def get_resolved_indices(self, available_indices):
        """Resolve this dashboard's patterns to actual containers.

        Uses the same matcher as every access boundary. It used to have its
        own — trailing wildcards only — so `*logs*` worked in a role and
        matched nothing in a dashboard, with nothing to say why.
        """
        from .hub.patterns import matches_any

        if not self.index_patterns:
            return list(available_indices)
        return [name for name in available_indices
                if matches_any(self.index_patterns, name)]


class SavedSearch:
    def __init__(self, search_id, name, query, time_range, created_by, created_at=None):
        self.id = search_id
        self.name = name
        self.query = query
        self.time_range = time_range
        self.created_by = created_by
        self.created_at = created_at or datetime.utcnow()

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'query': self.query,
            'time_range': self.time_range,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data):
        # `time_range` arrived after the first saved searches were written, so
        # an entry from before it exists and has none. Reading that as a
        # KeyError made one old row throw away the whole file, because the
        # loader parsed the list inside a single try. An hour is what the
        # search form offers when nobody has chosen.
        s = cls(data['id'], data['name'], data['query'],
                data.get('time_range') or '1h', data['created_by'])
        if 'created_at' in data:
            s.created_at = datetime.fromisoformat(data['created_at'])
        return s
