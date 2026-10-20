"""Durable admission gate and bounded local release/shutdown contracts.

This journal belongs to the control root, not the scientific metadata database.
Admission and maintenance intent share one SQLite write transaction, including
across service processes. Tokens must be retained until response/file close.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Callable
import uuid

import psutil
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .auth import require_role
from .models import UserRole


class TransferAdmissionClosed(RuntimeError):
    reason_code = "release_maintenance_active"


class MaintenanceConflict(ValueError):
    pass


def _operation_id(value: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("release maintenance requires a UUID") from exc


@dataclass(frozen=True)
class TransferToken:
    token_id: str


class TransferAdmissionGate:
    def __init__(self, control_root: str | Path):
        self.root = Path(control_root).resolve()
        self.path = self.root / "startup" / "release-maintenance.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (operation_id TEXT PRIMARY KEY, "
                       "contract TEXT NOT NULL, actor_id TEXT NOT NULL, state TEXT NOT NULL, "
                       "created_at REAL NOT NULL, released_at REAL)")
            db.execute("CREATE TABLE IF NOT EXISTS transfers (token_id TEXT PRIMARY KEY, "
                       "pid INTEGER NOT NULL, process_created REAL NOT NULL, entered_at REAL NOT NULL)")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_active_maintenance "
                       "ON operations ((1)) WHERE state = 'draining'")

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def _prune_exited(db):
        # A service death closes every local response. Only proven dead process
        # identities may be removed; denied/unknown process queries stay active.
        for token, pid, created in db.execute("SELECT token_id,pid,process_created FROM transfers").fetchall():
            try:
                process = psutil.Process(pid)
                exited = process.create_time() != created or not process.is_running() or process.status() == psutil.STATUS_ZOMBIE
            except psutil.NoSuchProcess:
                exited = True
            except (psutil.AccessDenied, OSError):
                exited = False
            if exited:
                db.execute("DELETE FROM transfers WHERE token_id=?", (token,))

    def enter(self) -> TransferToken:
        token = TransferToken(str(uuid.uuid4()))
        created = psutil.Process(os.getpid()).create_time()
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM operations WHERE state='draining'").fetchone():
                raise TransferAdmissionClosed("new transfers are deferred during release maintenance")
            db.execute("INSERT INTO transfers VALUES (?,?,?,?)", (token.token_id, os.getpid(), created, time.time()))
        return token

    def admission_closed(self) -> bool:
        """Short read-only probe for SSE/idle sweepers; no token/prune writes."""
        db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.25)
        try:
            return db.execute("SELECT 1 FROM operations WHERE state='draining' LIMIT 1").fetchone() is not None
        finally:
            db.close()

    def leave(self, token: TransferToken | str) -> None:
        value = token.token_id if isinstance(token, TransferToken) else str(token)
        with self._transaction() as db:
            db.execute("DELETE FROM transfers WHERE token_id=?", (value,))

    def begin(self, operation_id: str, contract: dict, *, actor_id: str) -> dict:
        operation_id = _operation_id(operation_id)
        canonical = json.dumps(contract, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._transaction() as db:
            row = db.execute("SELECT contract,actor_id FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row:
                if row != (canonical, actor_id):
                    raise MaintenanceConflict("UUID already belongs to a different maintenance contract or actor")
            else:
                if db.execute("SELECT 1 FROM operations WHERE state='draining'").fetchone():
                    raise MaintenanceConflict("another release maintenance operation is active")
                db.execute("INSERT INTO operations VALUES (?,?,?,'draining',?,NULL)",
                           (operation_id, canonical, actor_id, time.time()))
            return self._snapshot(db, operation_id)

    def _snapshot(self, db, operation_id: str) -> dict:
        row = db.execute("SELECT contract,actor_id,state,created_at,released_at FROM operations WHERE operation_id=?",
                         (operation_id,)).fetchone()
        if row is None:
            raise KeyError(operation_id)
        self._prune_exited(db)
        count = db.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
        return {"operation_id": operation_id, "contract": json.loads(row[0]), "actor_id": row[1],
                "state": "released" if row[2] == "released" else ("drained" if count == 0 else "draining"),
                "admission_closed": row[2] == "draining", "active_transfers": count,
                "created_at": row[3], "released_at": row[4], "gate_protocol": "durable-transfer-gate-v1"}

    def snapshot(self, operation_id: str) -> dict:
        with self._transaction() as db:
            return self._snapshot(db, _operation_id(operation_id))

    def release(self, operation_id: str) -> dict:
        with self._transaction() as db:
            operation_id = _operation_id(operation_id)
            if db.execute("SELECT 1 FROM operations WHERE operation_id=?", (operation_id,)).fetchone() is None:
                raise KeyError(operation_id)
            db.execute("UPDATE operations SET state='released',released_at=COALESCE(released_at,?) WHERE operation_id=?",
                       (time.time(), operation_id))
            return self._snapshot(db, operation_id)


_gates: dict[str, TransferAdmissionGate] = {}
_gates_lock = threading.Lock()


def get_transfer_gate(control_root: str | Path) -> TransferAdmissionGate:
    key = os.path.normcase(str(Path(control_root).resolve()))
    with _gates_lock:
        if key not in _gates:
            _gates[key] = TransferAdmissionGate(control_root)
        return _gates[key]


class MaintenanceContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transaction_id: str = Field(min_length=1, max_length=200)
    candidate_deployment_id: str = Field(min_length=1, max_length=200)
    drain_timeout_s: float = Field(default=300, ge=0, le=86400, allow_inf_nan=False)


def build_release_maintenance_router(control_root: str | Path, auth) -> APIRouter:
    router = APIRouter()
    gate = get_transfer_gate(control_root)

    def invoke(context, method, *args, **kwargs):
        require_role(context, UserRole.ADMIN)
        try:
            return method(*args, **kwargs)
        except KeyError as exc:
            raise HTTPException(404, "release maintenance operation not found") from exc
        except MaintenanceConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.put("/v1/admin/release-maintenance/{operation_id}")
    def begin(operation_id: str, contract: MaintenanceContract, context=Depends(auth.actor)):
        return invoke(context, gate.begin, operation_id, contract.model_dump(), actor_id=context.actor_id)

    @router.get("/v1/admin/release-maintenance/{operation_id}")
    def status(operation_id: str, context=Depends(auth.actor)):
        return invoke(context, gate.snapshot, operation_id)

    @router.post("/v1/admin/release-maintenance/{operation_id}/release")
    def release(operation_id: str, context=Depends(auth.actor)):
        return invoke(context, gate.release, operation_id)

    return router


def shutdown_request_path(control_root: str | Path) -> Path:
    return Path(control_root).resolve() / "startup" / "cooperative-shutdown.json"


def cooperative_service_shutdown(control_root: str | Path, *, timeout: float = 30) -> None:
    """Stop the exact hook-bearing service, including legacy GUI launchers."""
    capability_path = Path(control_root).resolve() / "startup" / "cooperative-service.json"
    try:
        capability = json.loads(capability_path.read_text(encoding="utf-8"))
        if capability["protocol"] != "cooperative-shutdown-v1":
            raise ValueError("unknown shutdown protocol")
        pid, created = int(capability["pid"]), float(capability["process_created"])
        try:
            process = psutil.Process(pid)
            if process.create_time() != created:
                return  # the recorded service exited; never signal a reused PID
        except psutil.NoSuchProcess:
            return  # recover a shutdown whose completion receipt was lost
    except (OSError, ValueError, KeyError, TypeError, psutil.Error) as exc:
        raise RuntimeError("cooperative shutdown unavailable; bootstrap the managed shutdown contract before release") from exc
    request_cooperative_shutdown(control_root, child_pid=pid, process_created=created,
                                 operation_id=str(uuid.uuid4()))
    deadline = time.monotonic() + max(0, timeout)
    while True:
        try:
            if not process.is_running() or process.create_time() != created or process.status() == psutil.STATUS_ZOMBIE:
                return
        except psutil.NoSuchProcess:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("cooperative API shutdown deferred; original service was preserved")
        time.sleep(0.1)


def request_cooperative_shutdown(control_root: str | Path, *, child_pid: int, process_created: float,
                                 operation_id: str, generation: str | None = None) -> None:
    """Protected-root IPC: fixed shutdown verb and exact process incarnation."""
    target = shutdown_request_path(control_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(".shutdown-" + uuid.uuid4().hex + ".partial")
    try:
        with partial.open("w", encoding="utf-8") as stream:
            payload = {"action": "shutdown", "pid": child_pid, "process_created": process_created,
                       "operation_id": _operation_id(operation_id)}
            if generation is not None:
                payload["generation"] = _operation_id(generation)
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)


def install_cooperative_shutdown(control_root: str | Path, request_shutdown: Callable[[], None]):
    """Start a local listener; return a stop callback for the server's finally."""
    target = shutdown_request_path(control_root)
    pid, created = os.getpid(), psutil.Process(os.getpid()).create_time()
    generation = os.environ.get("RCN_COORDINATOR_GENERATION")
    capability_path = target.with_name("cooperative-service.json")
    capability_path.parent.mkdir(parents=True, exist_ok=True)
    capability = {"protocol": "cooperative-shutdown-v1", "pid": pid, "process_created": created}
    if generation:
        capability["coordinator_generation"] = generation
    partial = capability_path.with_name(".cooperative-service-" + uuid.uuid4().hex + ".partial")
    try:
        with partial.open("w", encoding="utf-8") as stream:
            json.dump(capability, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(partial, capability_path)
    finally:
        partial.unlink(missing_ok=True)
    stopped = threading.Event()

    def listen():
        while not stopped.wait(0.1):
            try:
                value = json.loads(target.read_text(encoding="utf-8"))
                exact_process = value.get("pid") == pid and value.get("process_created") == created
                exact_generation = generation and value.get("generation") == generation
                if (set(value) in ({"action", "pid", "process_created", "operation_id"},
                                   {"action", "pid", "process_created", "operation_id", "generation"})
                        and value["action"] == "shutdown" and (exact_process or exact_generation)):
                    _operation_id(value["operation_id"])
                    request_shutdown()
                    return
            except (FileNotFoundError, OSError, ValueError, TypeError):
                continue

    thread = threading.Thread(target=listen, name="rcn-cooperative-shutdown", daemon=True)
    thread.start()

    def close():
        stopped.set()
        thread.join(timeout=2)
    return close
