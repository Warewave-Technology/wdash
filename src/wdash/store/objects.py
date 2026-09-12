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


#: The keys every dashboard store answers from `get_stats()`, and the whole of
#: what the two /api/debug endpoints promise.
#:
#: The two stores answer different shapes and always have: the JSON manager
#: adds storage_path, file_exists, loaded_signature, disk_signature and
#: should_reload, which describe a file and mean nothing where there is no
#: file. Both endpoints jsonify the dict straight through, so moving the
#: default from 'file' to 'database' silently changed what an installation
#: that set nothing gets back from them.
#:
#: Inventing the file keys for the database — storage_path: null, file_exists:
#: false — would answer the question with a lie, so the agreement is the
#: honest intersection plus `backend`, which is the key that says WHICH shape
#: is being looked at. The file manager kept its extra keys, so nothing
#: scripted against a file installation lost anything; `backend` is how such a
#: script now tells the two apart instead of inferring it from a missing key.
DASHBOARD_STATS = ("backend", "total_dashboards")


def _now():
    return datetime.now(timezone.utc)


_CONFLICT = ("This dashboard was changed by someone else. Reload it and "
             "reapply your changes.")

#: Tries a revision-less update gets before it gives up. Each one loses only
#: to a writer that committed inside its own read-to-write window, so several
#: in a row means a dashboard being rewritten continuously — which is worth
#: saying rather than looping over.
_UPDATE_ATTEMPTS = 5


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
            visibility=row["visibility"], source=row["source"])
        # Carried so a caller can pass it back for an optimistic update; not
        # part of the model's own vocabulary.
        dashboard.revision = row["revision"]
        return dashboard

    # ---------- reading ----------

    def get_dashboard(self, dashboard_id):
        with self._engine.connect() as connection:
            row = connection.execute(
                select(dashboards).where(dashboards.c.id == dashboard_id)
            ).mappings().first()
        return self._to_model(row) if row else None

    #: Newest first, and then by id so the answer does not move.
    #:
    #: A bulk migration out of the JSON file preserves `created_at`, which the
    #: file store wrote to the second — so a deployment that moves in arrives
    #: with whole runs of dashboards sharing one timestamp. `created_at DESC`
    #: alone puts those in whatever order the database felt like returning,
    #: and the dashboards page then reshuffles between loads for no reason
    #: anybody can see. The id breaks the tie: arbitrary, but the same
    #: arbitrary every time.
    _NEWEST_FIRST = (dashboards.c.created_at.desc(), dashboards.c.id.asc())

    def get_all_dashboards(self):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(dashboards).order_by(*self._NEWEST_FIRST)
            ).mappings().all()
        return [self._to_model(row) for row in rows]

    def get_user_dashboards(self, username):
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(dashboards).where(dashboards.c.created_by == username)
                .order_by(*self._NEWEST_FIRST)).mappings().all()
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
            "source": source or None, "visibility": _visibility(visibility),
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

        The revision is checked BY the write, not before it. Reading it in
        Python and then updating `WHERE id = :id` left the whole distance
        between the two statements open: two forms rendered at revision 1 and
        saved together both read 1, both passed the check, and both wrote —
        measured on SQLite as 57 of 80 barrier-aligned calls reporting
        success, with more than one winner in 18 of 20 trials. On Postgres the
        second UPDATE waits for the row lock and then re-checks a WHERE clause
        that only mentions the id, so it applies for the same reason. With the
        revision in the WHERE clause there is nothing between the decision and
        the write: the loser matches no row and is told.
        """
        changes = {"updated_at": _now()}
        if visibility is not None:
            changes["visibility"] = _visibility(visibility)
        if source is not None:
            # "" is the form saying "the default source", which is a choice
            # and not an absence; None means "leave it as it is".
            changes["source"] = source or None
        for column, value in (("name", name), ("description", description),
                              ("query", query), ("panels", panels),
                              ("thresholds", thresholds)):
            if value is not None:
                changes[column] = value
        if index_patterns is not None:
            changes["containers"] = list(index_patterns)

        for _ in range(_UPDATE_ATTEMPTS):
            with self._engine.begin() as connection:
                current = connection.execute(
                    select(dashboards.c.revision)
                    .where(dashboards.c.id == dashboard_id)).scalar()
                if current is None:
                    return None
                if revision is not None and int(revision) != current:
                    raise ObjectConflict(_CONFLICT)

                changes["revision"] = current + 1
                applied = connection.execute(
                    dashboards.update()
                    .where(dashboards.c.id == dashboard_id)
                    .where(dashboards.c.revision == current)
                    .values(**changes)).rowcount
            if applied:
                return self.get_dashboard(dashboard_id)
            # Somebody committed between the read and the write.
            if revision is not None:
                # They hold what this caller was shown, so this IS the stale
                # write the revision exists to refuse.
                raise ObjectConflict(_CONFLICT)
            # No revision was submitted, so last-write-wins was asked for:
            # read the new one and write again, rather than reporting a
            # conflict to a caller that never claimed a version.
        raise ObjectConflict(
            "This dashboard is being changed faster than it can be written. "
            "Try again.")

    def delete_dashboard(self, dashboard_id):
        with self._engine.begin() as connection:
            result = connection.execute(
                dashboards.delete().where(dashboards.c.id == dashboard_id))
        return result.rowcount > 0

    # ---------- parity with the file manager ----------

    def refresh_cache(self):
        """Nothing is cached; every read already goes to the database."""

    def get_stats(self):
        """What /api/debug/dashboard-manager answers about this store.

        `backend` and `total_dashboards` are the two keys BOTH stores answer,
        and they are the agreement: see `DASHBOARD_STATS` for why the rest of
        the file manager's keys are not invented here.
        """
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
