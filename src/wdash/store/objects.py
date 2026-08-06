"""
Dashboards and saved searches.

Both are user-authored objects with the same concurrency story, so they share
one pattern: a `revision` column that must match on write. Two people editing
the same dashboard is the case where last-write-wins destroys work somebody is
actively doing, and the answer is to refuse and say so rather than to pick a
winner silently.

Two people editing DIFFERENT dashboards do not conflict at all — that is a
property of storing one row per object, and it is the actual fix for the lost
update the JSON file had.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select

from ..dashboard.dashboard_manager import DashboardStorageError
from ..dashboard.visibility import normalise as _visibility
from ..models import Dashboard, SavedSearch
from .schema import dashboards, saved_searches


class ObjectConflict(DashboardStorageError):
    """The stored object changed while it was being edited."""


def _now():
    return datetime.now(timezone.utc)


class DashboardRepository:
    """The interface the routes already call, backed by a table.

    Method names match the file-based manager exactly so swapping the two is a
    configuration change rather than a rewrite of every call site.
    """

    def __init__(self, engine):
        self._engine = engine

    # ---------- translation ----------

    @staticmethod
    def _to_model(row):
        dashboard = Dashboard(
            dashboard_id=row["id"], name=row["name"],
            description=row["description"] or "", query=row["query"],
            created_by=row["created_by"], created_at=row["created_at"],
            index_patterns=row["containers"] or ["*"],
            panels=row["panels"], thresholds=row["thresholds"] or {},
            visibility=row["visibility"])
        # Carried so a caller can pass it back for an optimistic update; not
        # part of the model's own vocabulary.
        dashboard.revision = row["revision"]
        dashboard.source = row["source"]
        return dashboard

    # ---------- reading ----------

    def get_dashboard(self, dashboard_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(dashboards).where(dashboards.c.id == dashboard_id)
            ).mappings().first()
        return self._to_model(row) if row else None

    def get_all_dashboards(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(dashboards).order_by(dashboards.c.created_at.desc())
            ).mappings().all()
        return [self._to_model(row) for row in rows]

    def get_user_dashboards(self, username):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(dashboards).where(dashboards.c.created_by == username)
                .order_by(dashboards.c.created_at.desc())).mappings().all()
        return [self._to_model(row) for row in rows]

    # ---------- writing ----------

    def create_dashboard(self, name, description, query, created_by,
                         index_patterns=None, panels=None, thresholds=None,
                         source=None, visibility=None, dashboard_id=None,
                         created_at=None):
        """`dashboard_id` and `created_at` exist for migration only.

        Importing must preserve identity: a dashboard that changes id on the
        way in breaks every link somebody has pasted, and makes the import
        impossible to run twice safely.
        """
        record = {
            "id": dashboard_id or str(uuid.uuid4()), "name": name,
            "description": description or "", "query": query,
            "created_by": created_by, "created_at": created_at or _now(),
            "updated_at": _now(),
            "containers": list(index_patterns or ["*"]),
            "panels": panels, "thresholds": thresholds or {},
            "source": source, "visibility": _visibility(visibility),
            "revision": 1,
        }
        try:
            with self._engine.begin() as connection:
                connection.execute(dashboards.insert().values(**record))
        except Exception as exc:
            raise DashboardStorageError(str(exc)) from exc
        return self._to_model(record)

    def update_dashboard(self, dashboard_id, name=None, description=None,
                         query=None, index_patterns=None, panels=None,
                         thresholds=None, source=None, visibility=None,
                         revision=None):
        """Apply changes, refusing a write against a stale revision.

        `revision` is optional: a caller that does not track it gets
        last-write-wins, which is what a script wants. The edit form passes it,
        which is what a person wants.
        """
        changes = {"updated_at": _now()}
        if visibility is not None:
            changes["visibility"] = _visibility(visibility)
        for column, value in (("name", name), ("description", description),
                              ("query", query), ("panels", panels),
                              ("thresholds", thresholds), ("source", source)):
            if value is not None:
                changes[column] = value
        if index_patterns is not None:
            changes["containers"] = list(index_patterns)

        with self._engine.begin() as connection:
            current = connection.execute(
                select(dashboards.c.revision)
                .where(dashboards.c.id == dashboard_id)).scalar()
            if current is None:
                return None
            if revision is not None and int(revision) != current:
                raise ObjectConflict(
                    "This dashboard was changed by someone else. Reload it and "
                    "reapply your changes.")

            changes["revision"] = current + 1
            connection.execute(dashboards.update()
                               .where(dashboards.c.id == dashboard_id)
                               .values(**changes))
        return self.get_dashboard(dashboard_id)

    def delete_dashboard(self, dashboard_id):
        with self._engine.begin() as connection:
            result = connection.execute(
                dashboards.delete().where(dashboards.c.id == dashboard_id))
        return result.rowcount > 0

    # ---------- parity with the file manager ----------

    def refresh_cache(self):
        """Nothing is cached; every read already goes to the database."""

    def get_stats(self):
        with self._engine.connect() as connection:
            total = connection.execute(
                select(func.count()).select_from(dashboards)).scalar() or 0
        return {"backend": "database", "total_dashboards": total}


class SavedSearchRepository:
    def __init__(self, engine):
        self._engine = engine

    @staticmethod
    def _to_model(row):
        search = SavedSearch(
            search_id=row["id"], name=row["name"], query=row["query"],
            time_range=row["time_range"], created_by=row["created_by"],
            created_at=row["created_at"])
        search.source = row["source"]
        return search

    def all_for(self, username):
        """A user's saved searches.

        Scoped to the author because a saved search carries somebody's working
        context, not shared configuration. Sharing is a feature to add
        deliberately, not a default to fall into.
        """
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(saved_searches)
                .where(saved_searches.c.created_by == username)
                .order_by(saved_searches.c.created_at.desc())).mappings().all()
        return [self._to_model(row) for row in rows]

    def get(self, search_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(saved_searches).where(saved_searches.c.id == search_id)
            ).mappings().first()
        return self._to_model(row) if row else None

    def create(self, name, query, time_range, created_by, source=None,
               search_id=None, created_at=None):
        """`search_id` and `created_at` exist for migration only."""
        record = {
            "id": search_id or str(uuid.uuid4()), "name": name, "query": query,
            "time_range": time_range, "created_by": created_by,
            "created_at": created_at or _now(), "source": source, "revision": 1,
        }
        try:
            with self._engine.begin() as connection:
                connection.execute(saved_searches.insert().values(**record))
        except Exception as exc:
            raise DashboardStorageError(str(exc)) from exc
        return self._to_model(record)

    def delete(self, search_id, username):
        """Delete, but only the caller's own.

        The ownership check is part of the query rather than a read followed by
        a check: the two-step version has a window, and this is the kind of
        endpoint that gets called with somebody else's id.
        """
        with self._engine.begin() as connection:
            result = connection.execute(
                saved_searches.delete()
                .where(saved_searches.c.id == search_id)
                .where(saved_searches.c.created_by == username))
        return result.rowcount > 0
