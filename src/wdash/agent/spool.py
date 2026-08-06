"""
Results on disk, waiting to be sent.

A check that ran during an outage is the most valuable check there is, and it
is exactly the one that cannot be delivered at the time. Holding results in
memory means an agent restart — or the crash that the outage caused — throws
away the evidence of the thing being investigated.

JSON lines in a file, appended and truncated. Not SQLite: the agent should
carry as little as possible, the access pattern is append-then-drain, and a
file that can be read with `tail` is one an operator can inspect when the
agent is the thing that is broken.
"""

import json
import logging
import os
import tempfile
import threading

logger = logging.getLogger(__name__)

#: How many results to keep when the server has been unreachable for a long
#: time. At one check every fifteen seconds this is about two days for a
#: single monitor, and it bounds the file rather than the time — an agent with
#: fifty monitors fills it fifty times faster, and the disk should not be the
#: thing that discovers that.
MAX_SPOOLED = 10000


class Spool:
    """An append-only queue of results that survives a restart."""

    def __init__(self, path, limit=MAX_SPOOLED):
        self.path = path
        self.limit = limit
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)

    def add(self, results):
        """Append. Returns how many are now waiting."""
        if not results:
            return self.pending()
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                for result in results:
                    handle.write(json.dumps(result, default=str) + "\n")
                # Flushed and fsynced: the point of the spool is to survive
                # the crash that the outage caused, and a buffered write does
                # not.
                handle.flush()
                os.fsync(handle.fileno())
            return self._trim_locked()

    def take(self, count):
        """The oldest `count` results, still spooled until `drop` is called.

        Read rather than removed, so a send that fails leaves them where they
        were. Removing first and re-adding on failure loses them if the agent
        dies in between — which is the moment it is most likely to.
        """
        with self._lock:
            return self._read_locked()[:count]

    def drop(self, count):
        """Forget the oldest `count` results. Called after a successful send."""
        with self._lock:
            remaining = self._read_locked()[count:]
            self._write_locked(remaining)
            return len(remaining)

    def pending(self):
        with self._lock:
            return len(self._read_locked())

    # ---------- internals ----------

    def _read_locked(self):
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    # A half-written line from a kill mid-append. Dropping the
                    # one line and keeping the rest beats discarding the file,
                    # which is the whole backlog.
                    logger.warning(
                        f"{self.path}: line {number} is not readable, skipping")
        return out

    def _write_locked(self, results):
        """Replace the file atomically.

        Written to a temporary file and renamed, so a crash during the rewrite
        leaves the old file rather than a truncated one. The results in it have
        already been delivered, so a duplicate is the worst case — and a
        duplicate is a repeated data point, while a truncated file is a lost
        backlog.
        """
        directory = os.path.dirname(os.path.abspath(self.path))
        handle, temporary = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                for result in results:
                    out.write(json.dumps(result, default=str) + "\n")
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.path)
        except Exception:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise

    def _trim_locked(self):
        results = self._read_locked()
        if len(results) <= self.limit:
            return len(results)
        # The OLDEST go. A backlog that has overflowed is one where the recent
        # results matter more — and dropping the newest would mean the agent
        # reports nothing at all until the backlog clears.
        dropped = len(results) - self.limit
        logger.warning(
            f"spool is full: dropping the {dropped} oldest result(s)")
        self._write_locked(results[-self.limit:])
        return self.limit
