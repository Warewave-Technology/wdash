import json
import logging
import os
import uuid
import threading
from ..models import Dashboard

logger = logging.getLogger(__name__)


class DashboardStorageError(Exception):
    """A dashboard could not be persisted.

    Raised rather than logged-and-swallowed: a save that quietly fails while
    the route reports "created successfully" is silent data loss, and the user
    only discovers it when the dashboard is gone.
    """


class DashboardManager:
    def __init__(self, storage_path="dashboards.json"):
        self.storage_path = storage_path
        self.dashboards = {}
        self._lock = threading.RLock()  # Reentrant lock for nested operations
        self._file_lock = threading.Lock()  # Separate lock for file operations
        #: Signature of the file contents currently in memory, or None.
        self._loaded_signature = None
        self.load_dashboards()

    def _signature(self):
        """Identify the file version on disk, or None if it is not there.

        Size as well as modification time: comparing a wall-clock mtime against
        a wall-clock "when we last loaded" misses a write that lands in the
        same clock tick, and then the stale copy is served forever because the
        timestamp never moves again. A signature only has to CHANGE, not to be
        newer, so an equal-mtime write with different content is still caught.
        """
        try:
            stat = os.stat(self.storage_path)
        except OSError:
            return None
        return (stat.st_mtime_ns, stat.st_size)

    def _should_reload(self):
        """True when the file on disk differs from what we loaded."""
        if not os.path.exists(self.storage_path):
            return False
        return self._signature() != self._loaded_signature
    
    def load_dashboards(self, force=False):
        """Load dashboards from storage with thread safety"""
        with self._lock:
            # Check if we need to reload
            if not force and not self._should_reload():
                return
            
            if not os.path.exists(self.storage_path):
                self.dashboards = {}
                self._loaded_signature = None
                return

            signature = self._signature()
            try:
                with self._file_lock:
                    with open(self.storage_path, 'r') as f:
                        data = json.load(f)

                    # Clear existing dashboards and reload
                    new_dashboards = {}
                    for dashboard_data in data:
                        dashboard = Dashboard.from_dict(dashboard_data)
                        new_dashboards[dashboard.id] = dashboard

                    self.dashboards = new_dashboards
                    self._loaded_signature = signature

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                # Keep what is already in memory: serving the last good copy
                # beats emptying the list, which reads as "your dashboards are
                # gone" when the file is merely half-written.
                logger.error(f"Dashboard file is corrupt, keeping the loaded "
                             f"copy: {e}")
            except OSError as e:
                logger.error(f"Could not read the dashboard file: {e}")

    def save_dashboards(self):
        """Persist every dashboard, atomically.

        Raises DashboardStorageError if the write fails. The caller must not
        report success it did not get — this used to log and return normally,
        so a full disk or a missing directory produced "created successfully"
        and nothing on disk.
        """
        with self._lock:
            temp_path = (f"{self.storage_path}.tmp."
                         f"{os.getpid()}.{threading.get_ident()}")
            try:
                data = [dashboard.to_dict() for dashboard in self.dashboards.values()]

                with self._file_lock:
                    with open(temp_path, 'w') as f:
                        json.dump(data, f, indent=2)
                        # Flush to the platter before the rename: without this
                        # a crash can leave the renamed file present but empty.
                        f.flush()
                        os.fsync(f.fileno())

                    if os.name == 'nt' and os.path.exists(self.storage_path):
                        os.remove(self.storage_path)
                    os.rename(temp_path, self.storage_path)
                    self._loaded_signature = self._signature()

            except Exception as e:
                logger.error(f"Failed to save dashboards: {e}")
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except OSError:
                    pass
                raise DashboardStorageError(str(e)) from e
    
    def _snapshot(self):
        """The in-memory dashboards, copied deeply enough to restore from."""
        return {key: Dashboard.from_dict(value.to_dict())
                for key, value in self.dashboards.items()}

    def _save_or_restore(self, snapshot):
        """Persist; on failure put memory back the way it was, and re-raise.

        The routes tell the reader "has NOT been created", "your changes were
        NOT applied" and "it is still there" when the save raises. That was
        true of the disk and false of this worker: the change stayed in
        `self.dashboards`, `_loaded_signature` still matched the untouched
        file so `load_dashboards()` never reloaded, and every later read in
        this process served the change the user had just been told did not
        happen. The next save that DID succeed then wrote it out.
        """
        try:
            self.save_dashboards()
        except DashboardStorageError:
            self.dashboards = snapshot
            raise

    def create_dashboard(self, name, description, query, created_by,
                         index_patterns=None, panels=None,
                         thresholds=None, visibility=None, source=None):
        """Create a new dashboard with thread safety"""
        with self._lock:
            # Reload to ensure we have latest data
            self.load_dashboards()
            
            dashboard_id = str(uuid.uuid4())
            
            # Ensure unique ID (very unlikely collision, but be safe)
            while dashboard_id in self.dashboards:
                dashboard_id = str(uuid.uuid4())
            
            dashboard = Dashboard(
                dashboard_id=dashboard_id,
                name=name,
                description=description,
                query=query,
                created_by=created_by,
                index_patterns=index_patterns or ['*'],
                panels=panels,
                thresholds=thresholds,
                visibility=visibility,
                source=source
            )
            
            snapshot = self._snapshot()
            self.dashboards[dashboard_id] = dashboard
            self._save_or_restore(snapshot)
            return dashboard
    
    def get_dashboard(self, dashboard_id):
        """Get dashboard by ID with thread safety and cache refresh"""
        with self._lock:
            # Check if we should reload from disk
            self.load_dashboards()
            return self.dashboards.get(dashboard_id)
    
    def get_all_dashboards(self):
        """Get all dashboards with thread safety"""
        with self._lock:
            # Check if we should reload from disk
            self.load_dashboards()
            return list(self.dashboards.values())
    
    def update_dashboard(self, dashboard_id, name=None, description=None,
                         query=None, index_patterns=None, panels=None,
                         thresholds=None, visibility=None, source=None):
        """Update existing dashboard with thread safety"""
        with self._lock:
            # Reload to ensure we have latest data
            self.load_dashboards()
            
            dashboard = self.dashboards.get(dashboard_id)
            if not dashboard:
                return None

            snapshot = self._snapshot()
            if name is not None:
                dashboard.name = name
            if description is not None:
                dashboard.description = description
            if query is not None:
                dashboard.query = query
            if index_patterns is not None:
                dashboard.index_patterns = index_patterns
            if panels is not None:
                dashboard.panels = panels
            if thresholds is not None:
                dashboard.thresholds = thresholds
            if visibility is not None:
                dashboard.visibility = visibility
            if source is not None:
                # "" is how the form says "the default source", which is a
                # choice and not an absence: `None` means "leave it alone".
                dashboard.source = source or None

            self._save_or_restore(snapshot)
            return dashboard
    
    def delete_dashboard(self, dashboard_id):
        """Delete dashboard with thread safety"""
        with self._lock:
            # Reload to ensure we have latest data
            self.load_dashboards()
            
            if dashboard_id in self.dashboards:
                snapshot = self._snapshot()
                del self.dashboards[dashboard_id]
                self._save_or_restore(snapshot)
                return True
            return False
    
    def get_user_dashboards(self, username):
        """Get dashboards created by specific user with thread safety"""
        with self._lock:
            # Check if we should reload from disk
            self.load_dashboards()
            return [
                dashboard for dashboard in self.dashboards.values()
                if dashboard.created_by == username
            ]
    
    def refresh_cache(self):
        """Manually refresh the dashboard cache"""
        with self._lock:
            self.load_dashboards(force=True)
    
    def get_stats(self):
        """Get dashboard manager statistics for debugging"""
        with self._lock:
            return {
                'total_dashboards': len(self.dashboards),
                'storage_path': self.storage_path,
                'file_exists': os.path.exists(self.storage_path),
                'loaded_signature': self._loaded_signature,
                'disk_signature': self._signature(),
                'should_reload': self._should_reload()
            }