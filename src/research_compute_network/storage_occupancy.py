"""Bounded metadata-only probes of exact registered paths, never a tree walker."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import time
from datetime import datetime, timezone
from functools import lru_cache

from .origin_transfer import managed_path
from .storage_io import BackgroundBudget, BackgroundDeferred, io_priority
from .storage_projection import execute


def ensure_schema(db):
    for sql in (
        """CREATE TABLE IF NOT EXISTS storage_occupancy_observations (
          file_id INTEGER PRIMARY KEY,project_id TEXT NOT NULL,role TEXT NOT NULL,location TEXT NOT NULL,
          object_key TEXT,logical_bytes INTEGER,observed_at TEXT NOT NULL,state TEXT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS storage_occupancy_object_refs ON storage_occupancy_observations(object_key,file_id)",
        "CREATE INDEX IF NOT EXISTS storage_occupancy_project_time ON storage_occupancy_observations(project_id,role,location,observed_at)",
        """CREATE TABLE IF NOT EXISTS storage_occupancy_objects (
          object_key TEXT PRIMARY KEY,owner_file_id INTEGER NOT NULL,project_id TEXT NOT NULL,
          role TEXT NOT NULL,location TEXT NOT NULL,allocated_bytes INTEGER NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS storage_occupancy_totals (
          project_id TEXT NOT NULL,role TEXT NOT NULL,location TEXT NOT NULL,
          measured_files INTEGER NOT NULL DEFAULT 0,observed_logical_bytes INTEGER NOT NULL DEFAULT 0,
          allocated_bytes INTEGER NOT NULL DEFAULT 0,oldest_observed_at TEXT,
          PRIMARY KEY(project_id,role,location))""",
    ):
        execute(db, sql)


def _delta(db, scope, *, files=0, logical=0, allocated=0):
    execute(db, """INSERT INTO storage_occupancy_totals
      (project_id,role,location,measured_files,observed_logical_bytes,allocated_bytes) VALUES(?,?,?,?,?,?)
      ON CONFLICT(project_id,role,location) DO UPDATE SET measured_files=measured_files+excluded.measured_files,
      observed_logical_bytes=observed_logical_bytes+excluded.observed_logical_bytes,allocated_bytes=allocated_bytes+excluded.allocated_bytes""",
      (*scope, files, logical, allocated))


def _oldest(db, scope):
    row = execute(db, "SELECT observed_at FROM storage_occupancy_observations WHERE project_id=? AND role=? AND location=? ORDER BY observed_at LIMIT 1", scope).fetchone()
    execute(db, "UPDATE storage_occupancy_totals SET oldest_observed_at=? WHERE project_id=? AND role=? AND location=?",
            (row[0] if row else None, *scope))


def _object(db, key, allocated=None):
    old = execute(db, "SELECT * FROM storage_occupancy_objects WHERE object_key=?", (key,)).fetchone()
    owner = execute(db, "SELECT file_id,project_id,role,location FROM storage_occupancy_observations WHERE object_key=? ORDER BY file_id LIMIT 1", (key,)).fetchone()
    if old:
        _delta(db, tuple(old[2:5]), allocated=-old[5])
        execute(db, "DELETE FROM storage_occupancy_objects WHERE object_key=?", (key,))
    if owner:
        amount = allocated if allocated is not None else old[5]
        execute(db, "INSERT INTO storage_occupancy_objects VALUES(?,?,?,?,?,?)", (key, *owner, amount))
        _delta(db, tuple(owner[1:4]), allocated=amount)


def forget_observation(db, file_id):
    old = execute(db, "SELECT * FROM storage_occupancy_observations WHERE file_id=?", (file_id,)).fetchone()
    if old is None:
        return
    scope = tuple(old[1:4])
    if old[4]:
        _delta(db, scope, files=-1, logical=-old[5])
    execute(db, "DELETE FROM storage_occupancy_observations WHERE file_id=?", (file_id,))
    if old[4]:
        _object(db, old[4])
    _oldest(db, scope)


def record_observation(db, row, measured, *, now):
    forget_observation(db, row["file_id"])
    scope = (row["project_id"], row["role"], row["location"])
    key = measured.get("object_key")
    execute(db, "INSERT INTO storage_occupancy_observations VALUES(?,?,?,?,?,?,?,?)",
            (row["file_id"], *scope, key, measured.get("logical_bytes"), now.isoformat(), measured["state"]))
    if key:
        _delta(db, scope, files=1, logical=measured["logical_bytes"])
        _object(db, key, measured["allocated_bytes"])
    _oldest(db, scope)


@lru_cache(maxsize=1)
def _windows_allocation_api():
    """Reuse immutable FFI definitions; never cache a file handle or observation."""
    import ctypes
    from ctypes import wintypes
    class Standard(ctypes.Structure):
        _fields_ = [("allocation", ctypes.c_longlong), ("size", ctypes.c_longlong),
                    ("links", wintypes.DWORD), ("delete_pending", ctypes.c_ubyte), ("directory", ctypes.c_ubyte)]
    class Identity(ctypes.Structure):
        _fields_ = [("volume", ctypes.c_ulonglong), ("file_id", ctypes.c_ubyte*16)]
    class Attributes(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    return ctypes, kernel, Standard, Identity, Attributes


def native_allocation(path):
    """No payload read: one native handle's allocation, volume and file identity."""
    io_priority.checkpoint()
    if os.name != "nt":
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not hasattr(info, "st_blocks"):
            raise ValueError("allocated_size_unsupported")
        return {"object_key": f"{info.st_dev}:{info.st_ino}", "allocated_bytes": info.st_blocks*512,
                "logical_bytes": info.st_size, "state": "measured_posix_blocks"}
    ctypes, kernel, Standard, Identity, Attributes = _windows_allocation_api()
    handle = kernel.CreateFileW(str(path), 0x80, 7, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        io_priority.checkpoint()
        standard, identity, attributes = Standard(), Identity(), Attributes()
        for kind, info in ((1, standard), (18, identity), (9, attributes)):
            io_priority.checkpoint()
            if not kernel.GetFileInformationByHandleEx(handle, kind, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
        io_priority.checkpoint()
        if standard.directory or attributes.attributes & 0x400:
            raise ValueError("reparse_or_nonfile")
        # Compression/sparse allocation semantics vary by filesystem. Keep those
        # explicitly unknown until its provider supplies a verified allocation API.
        if attributes.attributes & (0x800 | 0x200):
            raise ValueError("compressed_or_sparse_allocation_unknown")
        return {"object_key": f"{identity.volume}:{bytes(identity.file_id).hex()}",
                "allocated_bytes": standard.allocation, "logical_bytes": standard.size,
                "state": "measured_windows_file_standard_info"}
    finally:
        kernel.CloseHandle(handle)


class OccupancyInventory:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def advance(self, *, max_files=8, time_budget_ms=10, clock=time.perf_counter, probe=native_allocation):
        if not 1 <= max_files <= 256 or not 0 < time_budget_ms <= 1000:
            raise ValueError("invalid occupancy inventory budget")
        started = clock()
        budget = BackgroundBudget(self.lifecycle.database)
        budget.checkpoint()
        with self.lifecycle._connect() as db:
            state = db.execute("SELECT value FROM storage_inventory_state WHERE key='occupancy_cursor'").fetchone()
            cursor = int(state[0]) if state else 0
            rows = db.execute("SELECT rowid AS file_id,* FROM storage_inventory_files WHERE resident=1 AND rowid>? ORDER BY rowid LIMIT ?",
                              (cursor, max_files)).fetchall()
        roots, processed = {}, 0
        for row in rows:
            # Metadata admission can itself exhaust the slice. Allow one file
            # after the foreground checkpoints so repeated slow setup cannot
            # starve this cursor; the time budget prevents additional work.
            if processed and (clock()-started)*1000 >= time_budget_ms:
                break
            budget.checkpoint()
            measured = {"state": "unregistered_path"}
            try:
                locator = json.loads(row["locator"]) if row["locator"] else None
                if locator and row["location"] == "center":
                    if "center" not in roots:
                        roots["center"] = self.lifecycle._root()
                    path = managed_path(roots["center"], locator["origin_submitter_id"], "incoming",
                                        row["job_id"], row["unit_id"], row["attempt_id"], row["path"])
                elif locator:
                    if row["location"] not in roots:
                        with self.lifecycle._connect() as db:
                            store = db.execute("SELECT payload FROM storage_restore_stores WHERE store_id=? AND generation=?",
                                (locator["store_id"], locator["generation"])).fetchone()
                        if store is None:
                            raise ValueError("registration_unavailable")
                        from .restore_sources import RegisteredResultSources
                        payload = json.loads(store[0])
                        resolver = RegisteredResultSources(self.lifecycle, allowed_kind=payload["kind"])
                        roots[row["location"]] = resolver._validate_store(payload)
                    path = managed_path(roots[row["location"]], locator["relative_path"])
                else:
                    path = None
                if path is not None:
                    measured = probe(path)
                    measured["object_key"] = self.lifecycle.process_host.casefold()+':'+measured["object_key"]
            except BackgroundDeferred:
                raise
            except (OSError, ValueError) as exc:
                measured = {"state": "unavailable_or_unsupported", "reason": type(exc).__name__}
            # A foreground admission during the OS probe must also win over the
            # following metadata write. Leave the cursor unchanged for a retry.
            budget.checkpoint()
            now = datetime.now(timezone.utc)
            with self.lifecycle._transaction() as db:
                current = db.execute("SELECT size_bytes,sha256,resident,locator FROM storage_inventory_files WHERE rowid=?", (row["file_id"],)).fetchone()
                if current and tuple(current) == (row["size_bytes"], row["sha256"], 1, row["locator"]):
                    record_observation(db, row, measured, now=now)
                cursor = row["file_id"]
                db.execute("INSERT INTO storage_inventory_state VALUES('occupancy_cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(cursor),))
            processed += 1
        complete = processed == len(rows) and len(rows) < max_files
        if complete:
            budget.checkpoint()
            with self.lifecycle._transaction() as db:
                for key, value in (("occupancy_cursor", "0"), ("occupancy_pass_completed_at", datetime.now(timezone.utc).isoformat())):
                    db.execute("INSERT INTO storage_inventory_state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        return {"processed": processed, "pass_complete": complete, "cursor": 0 if complete else cursor,
                "elapsed_ms": (clock()-started)*1000}
