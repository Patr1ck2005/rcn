"""Persistent, conservative write reservations in the original metadata DB.

Claims are keyed by actual host and filesystem device, not by directory. Each
holds the whole expected write until its exact writer has ended. Nothing expires
by age: an orphan needs explicit process-identity and writer-tree evidence.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

import psutil

from .storage_roots import current_host_id, reject_reparse_path


HARD_RESERVE_BYTES = 10 * 1024**3
MAX_ADMISSION_RETRIES = 8
LEDGER_BUSY_TIMEOUT_SECONDS = 1.0
MAX_LEDGER_BUSY_RETRIES = 8
LEDGER_BUSY_RETRY_DELAY_SECONDS = 0.1


class VolumeBudgetError(RuntimeError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class VolumeCapacityUnavailable(VolumeBudgetError):
    def __init__(self, *, required_bytes: int, free_bytes: int, reserved_bytes: int,
                 reserve_bytes: int = HARD_RESERVE_BYTES):
        super().__init__("storage_capacity_unavailable", "shared volume budget cannot admit the full write")
        self.required_bytes = required_bytes
        self.free_bytes = free_bytes
        self.reserved_bytes = reserved_bytes
        self.reserve_bytes = reserve_bytes


class VolumeHolderBusy(VolumeBudgetError):
    def __init__(self, *, required_bytes: int, free_bytes: int | None, reserved_bytes: int | None):
        super().__init__("storage_holder_busy", "an exact transfer holder or its bounded stream limit is active")
        self.required_bytes = required_bytes
        self.free_bytes = free_bytes
        self.reserved_bytes = reserved_bytes
        self.reserve_bytes = HARD_RESERVE_BYTES


class VolumeBudgetBusy(VolumeHolderBusy):
    """Concurrent holder changes require a fresh probe and bounded deferral."""

    def __init__(self, *, required_bytes: int):
        super().__init__(required_bytes=required_bytes, free_bytes=None, reserved_bytes=None)
        VolumeBudgetError.__init__(self, "storage_budget_busy", "shared volume claims kept changing during admission")


class VolumeLedgerBusy(VolumeHolderBusy):
    """A bounded metadata-lock wait ended; defer without replaying the writer."""

    def __init__(self, *, required_bytes: int, operation: str):
        super().__init__(required_bytes=required_bytes, free_bytes=None, reserved_bytes=None)
        VolumeBudgetError.__init__(self, "storage_ledger_busy", "capacity ledger is temporarily locked")
        self.operation = operation


def _is_sqlite_busy(exc: sqlite3.Error) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        return code & 0xff in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
    # Older Python/SQLite combinations may provide only the canonical message.
    message = str(exc).strip().casefold()
    return any(message == prefix or message.startswith(prefix + ":") for prefix in (
        "database is locked", "database table is locked", "database schema is locked",
    ))


def volume_for_destination(destination: Path) -> tuple[Path, str]:
    selected = Path(destination).absolute()
    ancestor = selected
    while not ancestor.exists():
        if ancestor == ancestor.parent:
            raise VolumeBudgetError("storage_volume_unavailable", "write destination has no existing volume")
        ancestor = ancestor.parent
    reject_reparse_path(ancestor)
    if not ancestor.is_dir():
        raise VolumeBudgetError("storage_volume_unavailable", "write destination ancestor is not a directory")
    return ancestor, "st_dev:" + str(ancestor.stat().st_dev)


@dataclass(frozen=True)
class VolumeClaim:
    token: str
    host_id: str
    volume_id: str
    required_bytes: int
    holder_kind: str
    holder_key: str
    owner_pid: int
    owner_started_at: float


# Transports can be reconstructed for every collection attempt. Keep exact
# completion proof across those instances, but never across an owner process,
# metadata database or host identity. Process exit leaves ordinary orphan
# claims requiring the existing independent writer-tree recovery proof.
_PENDING_RELEASES_BY_OWNER: dict[tuple[str, str, int, float], dict[str, tuple[VolumeClaim, str]]] = {}
_PENDING_RELEASE_LOCK = threading.Lock()


class VolumeBudget:
    def __init__(self, database: str | Path, *, host_id: str | None = None,
                 volume_probe: Callable[[Path], tuple[Path, str]] | None = None,
                 free_bytes: Callable[[Path], int] | None = None):
        if not str(database) or str(database) == ":memory:":
            raise VolumeBudgetError("storage_budget_unavailable", "shared capacity needs the original file-backed metadata database")
        self.database = Path(database).absolute()
        self.host_id = (host_id if host_id is not None else current_host_id()).casefold()
        self.volume_probe = volume_probe or volume_for_destination
        self.free_bytes = free_bytes or (lambda path: shutil.disk_usage(path).free)
        self.owner_pid = os.getpid()
        self.owner_started_at = psutil.Process(self.owner_pid).create_time()
        if not self.database.parent.is_dir():
            raise VolumeBudgetError("storage_budget_unavailable", "metadata database parent is unavailable")
        reject_reparse_path(self.database, must_exist=False)
        owner_key = (os.path.normcase(str(self.database.resolve())), self.host_id,
                     self.owner_pid, self.owner_started_at)
        self._pending_release_lock = _PENDING_RELEASE_LOCK
        with self._pending_release_lock:
            self._pending_releases = _PENDING_RELEASES_BY_OWNER.setdefault(owner_key, {})
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS storage_volume_claims (
                token TEXT PRIMARY KEY, host_id TEXT NOT NULL, volume_id TEXT NOT NULL,
                required_bytes INTEGER NOT NULL CHECK(required_bytes > 0),
                holder_kind TEXT NOT NULL, holder_key TEXT NOT NULL,
                owner_pid INTEGER NOT NULL, owner_started_at REAL NOT NULL,
                created_at REAL NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','released')),
                released_at REAL, release_evidence TEXT, destination TEXT NOT NULL)""")
            db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS storage_volume_active_holder
                ON storage_volume_claims(host_id, volume_id, holder_kind, holder_key) WHERE state='active'""")
            db.execute("""CREATE INDEX IF NOT EXISTS storage_volume_active_budget
                ON storage_volume_claims(host_id, volume_id, state)""")
            db.execute("""CREATE TABLE IF NOT EXISTS storage_volume_revisions (
                host_id TEXT NOT NULL, volume_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 0), PRIMARY KEY(host_id, volume_id))""")

    @staticmethod
    def _retry_sqlite(operation: Callable[[], object], *, required_bytes: int, stage: str):
        for attempt in range(MAX_LEDGER_BUSY_RETRIES):
            try:
                return operation()
            except sqlite3.Error as exc:
                if not _is_sqlite_busy(exc):
                    raise
                if attempt + 1 == MAX_LEDGER_BUSY_RETRIES:
                    raise VolumeLedgerBusy(required_bytes=required_bytes, operation=stage) from exc
                time.sleep(LEDGER_BUSY_RETRY_DELAY_SECONDS)

    @contextmanager
    def _transaction(self, *, required_bytes: int = 0) -> Iterator[sqlite3.Connection]:
        reject_reparse_path(self.database, must_exist=False)
        try:
            db = sqlite3.connect(str(self.database), timeout=LEDGER_BUSY_TIMEOUT_SECONDS, isolation_level=None)
        except sqlite3.Error as exc:
            raise VolumeBudgetError("storage_budget_unavailable", "capacity ledger cannot be opened") from exc
        db.row_factory = sqlite3.Row
        try:
            db.execute(f"PRAGMA busy_timeout={int(LEDGER_BUSY_TIMEOUT_SECONDS * 1000)}")
            self._retry_sqlite(lambda: db.execute("PRAGMA synchronous=FULL"),
                               required_bytes=required_bytes, stage="configure")
            self._retry_sqlite(lambda: db.execute("BEGIN IMMEDIATE"),
                               required_bytes=required_bytes, stage="begin")
            # Yield exactly once: retries never repeat caller work or external I/O.
            yield db
            self._retry_sqlite(lambda: db.execute("COMMIT"),
                               required_bytes=required_bytes, stage="commit")
        except sqlite3.Error as exc:
            if db.in_transaction:
                try:
                    db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass  # Preserve the original failure; close also rolls back.
            if _is_sqlite_busy(exc):
                raise VolumeLedgerBusy(required_bytes=required_bytes, operation="statement") from exc
            raise VolumeBudgetError("storage_budget_unavailable", "capacity ledger transaction failed") from exc
        except Exception:
            if db.in_transaction:
                try:
                    db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        finally:
            db.close()

    @staticmethod
    def _revision(db: sqlite3.Connection, host_id: str, volume_id: str) -> int:
        row = db.execute("SELECT revision FROM storage_volume_revisions WHERE host_id=? AND volume_id=?",
                         (host_id, volume_id)).fetchone()
        return row[0] if row is not None else 0

    def _read_revision(self, volume_id: str, *, required_bytes: int = 0) -> int:
        # A short autocommit read ends before any potentially slow data-volume
        # probe. It acquires no write transaction on the shared metadata DB.
        reject_reparse_path(self.database)
        try:
            db = sqlite3.connect(str(self.database), timeout=LEDGER_BUSY_TIMEOUT_SECONDS, isolation_level=None)
            try:
                return self._retry_sqlite(lambda: self._revision(db, self.host_id, volume_id),
                                          required_bytes=required_bytes, stage="read")
            finally:
                db.close()
        except sqlite3.Error as exc:
            raise VolumeBudgetError("storage_budget_unavailable", "capacity revision cannot be read") from exc

    @staticmethod
    def _advance_revision(db: sqlite3.Connection, host_id: str, volume_id: str) -> None:
        db.execute("""INSERT INTO storage_volume_revisions(host_id, volume_id, revision) VALUES(?,?,1)
            ON CONFLICT(host_id, volume_id) DO UPDATE SET revision=revision+1""", (host_id, volume_id))

    def reserve(self, destination: str | Path, required_bytes: int, *, holder_kind: str,
                holder_key: str, max_kind_claims: int | None = None,
                expected_volume_id: str | None = None) -> VolumeClaim:
        if type(required_bytes) is not int or not 0 < required_bytes <= 2**63 - 1:
            raise VolumeBudgetError("storage_size_invalid", "complete write size must be a positive bounded integer")
        if not holder_kind or len(holder_kind) > 64 or not holder_key or len(holder_key) > 2048:
            raise VolumeBudgetError("storage_holder_invalid", "capacity requires a bounded exact holder identity")
        self._flush_pending_releases()
        destination = Path(destination).absolute()
        ancestor, volume_id = self.volume_probe(destination)
        if expected_volume_id is not None and volume_id != expected_volume_id:
            raise VolumeBudgetError("storage_volume_mismatch", "write volume differs from the expected binding")
        claim = VolumeClaim(uuid.uuid4().hex, self.host_id, volume_id, required_bytes,
                            holder_kind, holder_key, self.owner_pid, self.owner_started_at)
        for attempt in range(MAX_ADMISSION_RETRIES):
            if attempt:
                ancestor, observed_volume = self.volume_probe(destination)
                if observed_volume != volume_id:
                    raise VolumeBudgetError("storage_volume_mismatch", "write volume changed while reserving capacity")
            revision = self._read_revision(volume_id, required_bytes=required_bytes)
            free = self.free_bytes(ancestor)
            if type(free) is not int or free < 0:
                raise VolumeBudgetError("storage_capacity_unknown", "actual volume free space is unknown")
            if self.volume_probe(destination)[1] != volume_id:
                raise VolumeBudgetError("storage_volume_mismatch", "write volume changed while reserving capacity")
            with self._transaction(required_bytes=required_bytes) as db:
                if self._revision(db, self.host_id, volume_id) != revision:
                    # A writer may have finished after the free-space sample,
                    # leaving fewer free bytes and removing its full claim.
                    # End this transaction and re-probe without holding it.
                    continue
                active = db.execute("SELECT required_bytes, holder_kind, holder_key FROM storage_volume_claims "
                                    "WHERE host_id=? AND volume_id=? AND state='active'", (self.host_id, volume_id)).fetchall()
                reserved = sum(row["required_bytes"] for row in active)
                same_kind = [row for row in active if row["holder_kind"] == holder_kind]
                if any(row["holder_key"] == holder_key for row in same_kind) or (
                    max_kind_claims is not None and len(same_kind) >= max_kind_claims
                ):
                    raise VolumeHolderBusy(required_bytes=required_bytes, free_bytes=free, reserved_bytes=reserved)
                if free < required_bytes + reserved + HARD_RESERVE_BYTES:
                    raise VolumeCapacityUnavailable(required_bytes=required_bytes, free_bytes=free,
                                                     reserved_bytes=reserved)
                db.execute("INSERT INTO storage_volume_claims VALUES (?,?,?,?,?,?,?,?,?,'active',NULL,NULL,?)",
                           (claim.token, claim.host_id, claim.volume_id, claim.required_bytes,
                            claim.holder_kind, claim.holder_key, claim.owner_pid, claim.owner_started_at,
                            time.time(), str(destination)))
                self._advance_revision(db, self.host_id, volume_id)
                return claim
        raise VolumeBudgetBusy(required_bytes=required_bytes)

    def release(self, claim: VolumeClaim, *, writer_stopped: bool, evidence: str) -> None:
        if writer_stopped is not True or not evidence:
            raise VolumeBudgetError("storage_writer_unproven", "capacity stays reserved until the exact writer has ended")
        if (claim.host_id, claim.owner_pid, claim.owner_started_at) != (
            self.host_id, os.getpid(), psutil.Process(os.getpid()).create_time()
        ):
            raise VolumeBudgetError("storage_owner_mismatch", "only the original live owner can release its claim")
        try:
            self._release_claim(claim, evidence=evidence)
        except VolumeLedgerBusy:
            # Retain only explicit exact-writer completion proof in this owner.
            # A subsequent admission retries this local, idempotent SQL before
            # it probes space. No active writer is released by age or PID alone.
            with self._pending_release_lock:
                self._pending_releases.setdefault(claim.token, (claim, evidence[:2048]))
            raise
        with self._pending_release_lock:
            self._pending_releases.pop(claim.token, None)

    def _release_claim(self, claim: VolumeClaim, *, evidence: str) -> None:
        with self._transaction(required_bytes=claim.required_bytes) as db:
            row = db.execute("SELECT * FROM storage_volume_claims WHERE token=?", (claim.token,)).fetchone()
            if row is None or any(row[key] != value for key, value in claim.__dict__.items()):
                raise VolumeBudgetError("storage_claim_mismatch", "capacity claim does not match its durable identity")
            if row["state"] == "active":
                db.execute("UPDATE storage_volume_claims SET state='released', released_at=?, release_evidence=? "
                           "WHERE token=? AND state='active'", (time.time(), evidence[:2048], claim.token))
                self._advance_revision(db, claim.host_id, claim.volume_id)

    def _flush_pending_releases(self) -> None:
        with self._pending_release_lock:
            pending = list(self._pending_releases.values())
        for claim, evidence in pending:
            self.release(claim, writer_stopped=True, evidence=evidence)

    @staticmethod
    def _owner_alive(pid: int, started_at: float) -> bool | None:
        try:
            process = psutil.Process(pid)
            return process.create_time() == started_at and process.is_running()
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            return None

    def reconcile_orphan(self, token: str, *, expected_owner_pid: int,
                         expected_owner_started_at: float, writer_tree_exited: bool,
                         evidence: str) -> None:
        """Explicit operator recovery, never a TTL or automatic PID-only release."""
        if writer_tree_exited is not True or not evidence:
            raise VolumeBudgetError("storage_writer_unproven", "orphan recovery requires explicit writer-tree exit evidence")
        # Process identity probing also precedes the shared writer lock. A
        # missing exact PID/birth pair cannot later become that same owner.
        owner_alive = self._owner_alive(expected_owner_pid, expected_owner_started_at)
        with self._transaction() as db:
            row = db.execute("SELECT * FROM storage_volume_claims WHERE token=?", (token,)).fetchone()
            if row is None or row["host_id"] != self.host_id or (
                row["owner_pid"], row["owner_started_at"]
            ) != (expected_owner_pid, expected_owner_started_at):
                raise VolumeBudgetError("storage_claim_mismatch", "orphan proof does not identify the original claim owner")
            if owner_alive is not False:
                raise VolumeBudgetError("storage_owner_active_or_unknown", "original owner is alive or cannot be proven absent")
            if row["state"] == "active":
                db.execute("UPDATE storage_volume_claims SET state='released', released_at=?, release_evidence=? "
                           "WHERE token=? AND state='active'",
                           (time.time(), json.dumps({"operator_writer_tree_exit": evidence[:1600],
                                                    "owner_pid": expected_owner_pid,
                                                    "owner_started_at": expected_owner_started_at}), token))
                self._advance_revision(db, row["host_id"], row["volume_id"])

    def active_claims(self) -> list[dict]:
        with self._transaction() as db:
            return [dict(row) for row in db.execute("SELECT * FROM storage_volume_claims WHERE host_id=? "
                                                    "AND state='active' ORDER BY created_at, token", (self.host_id,))]
