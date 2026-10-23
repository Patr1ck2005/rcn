"""Cooperative background IO: real foreground work wins, capacity waits do not.

No worker, timer or new database. Cross-process writers are already represented
by VolumeBudget claims. Same-process reads use a small admission counter.
"""
from contextlib import closing, contextmanager
import sqlite3
import threading
import time


class BackgroundDeferred(ValueError):
    reason_code = "storage_background_deferred"


class IoPriority:
    def __init__(self):
        self.lock = threading.Lock()
        self.readers = 0
        self.quiet_until = 0.0

    @contextmanager
    def foreground(self, *, quiet_after=0.0):
        with self.lock:
            self.readers += 1
        try:
            yield
        finally:
            with self.lock:
                self.readers -= 1
                if quiet_after:
                    self.quiet_until = max(self.quiet_until, time.monotonic()+quiet_after)

    def checkpoint(self):
        with self.lock:
            if self.readers or time.monotonic() < self.quiet_until:
                raise BackgroundDeferred("normal collection or requested download is active")


io_priority = IoPriority()
BACKGROUND_CHUNK_BYTES = 4 * 1024


class BackgroundBudget:
    """Bound metadata sampling; uncertain ledger state also defers background IO."""
    def __init__(self, database, *, clock=time.monotonic, ignore_token=None):
        self.database, self.clock = database, clock
        self.ignore_token = ignore_token
        self.next_check = 0.0

    def checkpoint(self):
        io_priority.checkpoint()
        now = self.clock()
        if now < self.next_check:
            return
        self.next_check = now + .05
        try:
            # sqlite3's connection context commits/rolls back; it does not close.
            # Release metadata handles here instead of in a later GC pause.
            with closing(sqlite3.connect(self.database, timeout=0)) as db:
                exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='storage_volume_claims'").fetchone()
                sql = "SELECT 1 FROM storage_volume_claims WHERE state='active'"
                args = ()
                if self.ignore_token is not None:
                    sql += " AND token<>?"
                    args = (self.ignore_token,)
                if exists and db.execute(sql+" LIMIT 1", args).fetchone():
                    raise BackgroundDeferred("an admitted foreground write is active")
        except sqlite3.Error as exc:
            raise BackgroundDeferred("foreground ledger is busy") from exc
