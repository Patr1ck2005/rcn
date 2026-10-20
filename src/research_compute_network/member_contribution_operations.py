"""Owner-private, transactional contribution state and original-result receipts.

Native setup and center writes are external effects. A durable claim precedes
them; an interrupted claim can be queried but is never automatically replayed.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from uuid import UUID

from fastapi import HTTPException

from . import member_registration as storage


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def operation_uuid(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(400, "invalid contribution operation ID") from None
    return value


def _owner_alive(pid):
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return ctypes.get_last_error() != 87  # Access denial remains conservative.
    try:
        code = wintypes.DWORD()
        return not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == 259
    finally:
        kernel.CloseHandle(handle)


class ContributionStore:
    def __init__(self, root, *, initial):
        self.root = Path(root)
        self.path = self.root / "contribution.sqlite3"
        self.legacy = self.root / "setup.json"
        self.initial = initial
        self.active = ContextVar("member_contribution_operation", default=None)

    @contextmanager
    def transaction(self):
        storage._unlinked(self.path)
        existed = self.path.exists()
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        if not existed:
            os.chmod(self.path, 0o600)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS contribution_state (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, payload TEXT NOT NULL)")
            connection.execute("""CREATE TABLE IF NOT EXISTS contribution_operations (
                operation_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, center_url TEXT NOT NULL,
                kind TEXT NOT NULL, machine_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
                expected_revision INTEGER NOT NULL, intent TEXT NOT NULL, remote_intent TEXT, owner_pid INTEGER NOT NULL,
                status TEXT NOT NULL, result TEXT, error TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
            connection.execute("CREATE TABLE IF NOT EXISTS contribution_audit (sequence INTEGER PRIMARY KEY, operation_id TEXT, event TEXT NOT NULL, revision INTEGER NOT NULL, at TEXT NOT NULL)")
            if connection.execute("SELECT 1 FROM contribution_state WHERE id=1").fetchone() is None:
                if self.legacy.exists():
                    from .member_client import _read_json
                    value = _read_json(self.legacy)
                else:
                    value = self.initial()
                value = {key: item for key, item in value.items() if key != "revision"}
                connection.execute("INSERT INTO contribution_state VALUES (1,0,?)", (canonical(value),))
                self._audit(connection, None, "legacy-import" if self.legacy.exists() else "initialized", 0)
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _audit(connection, operation, event, revision):
        connection.execute("INSERT INTO contribution_audit(operation_id,event,revision,at) VALUES (?,?,?,?)",
                           (operation, event, revision, datetime.now(timezone.utc).isoformat()))

    @staticmethod
    def _state(connection):
        row = connection.execute("SELECT revision,payload FROM contribution_state WHERE id=1").fetchone()
        return {**json.loads(row["payload"]), "revision": row["revision"]}

    def read(self):
        with self.transaction() as connection:
            return self._state(connection)

    def save(self, previous, *, preserve_operation_markers=False, **updates):
        with self.transaction() as connection:
            current = self._state(connection)
            if current["revision"] != previous["revision"]:
                raise HTTPException(409, "contribution state changed; read the original result before another edit")
            value = {**previous, **updates}
            if self.active.get() and not preserve_operation_markers:
                value["last_operation_id"] = self.active.get()
                if updates.get("phase") == "configured":
                    value["completed_operation_id"] = self.active.get()
            revision = value.pop("revision") + 1
            connection.execute("UPDATE contribution_state SET revision=?,payload=? WHERE id=1", (revision, canonical(value)))
            self._audit(connection, self.active.get(), "state-updated", revision)
            return {**value, "revision": revision}

    @staticmethod
    def _receipt(row):
        if row is None:
            raise HTTPException(404, {"reason_code": "contribution_operation_not_found", "message": "contribution operation not found"})
        result = json.loads(row["result"]) if row["result"] else None
        operation = {key: row[key] for key in ("operation_id", "actor_id", "center_url", "kind", "machine_id",
                    "payload_sha256", "expected_revision", "status", "created_at", "updated_at")}
        operation["error"] = json.loads(row["error"]) if row["error"] and row["error"].startswith("{") else row["error"]
        if operation["status"] == "executing" and not _owner_alive(row["owner_pid"]):
            operation["status"] = "unknown"
            operation["error"] = "original_process_interrupted"
        return {**(result or {}), "operation": operation, "result": result}

    @staticmethod
    def _scope(row, actor_id, center_url):
        if row["actor_id"] != actor_id or row["center_url"] != center_url:
            raise HTTPException(403, "contribution operation belongs to another identity or center")

    def get(self, identifier, *, actor_id, center_url):
        operation_uuid(identifier)
        with self.transaction() as connection:
            row = connection.execute("SELECT * FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone()
            if row is None:
                raise HTTPException(404, {"reason_code": "contribution_operation_not_found", "message": "contribution operation not found"})
            self._scope(row, actor_id, center_url)
            return self._receipt(row)

    def claim(self, identifier, *, actor_id, center_url, kind, machine_id, payload, expected_revision):
        operation_uuid(identifier)
        if type(expected_revision) is not int or expected_revision < 0:
            raise HTTPException(422, "contribution expected_revision is required")
        digest = hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()
        binding = (actor_id, center_url, kind, machine_id, digest, expected_revision)
        with self.transaction() as connection:
            row = connection.execute("SELECT * FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone()
            if row:
                self._scope(row, actor_id, center_url)
                if tuple(row[key] for key in ("actor_id", "center_url", "kind", "machine_id", "payload_sha256", "expected_revision")) != binding:
                    raise HTTPException(409, "original contribution request changed")
                return False, self._receipt(row)
            state = self._state(connection)
            safety_pause = kind == "preferences" and payload == {"paused": True}
            pending = connection.execute("SELECT operation_id FROM contribution_operations WHERE status IN ('executing','unknown') LIMIT 1").fetchone()
            if pending and not safety_pause:
                raise HTTPException(409, "an original contribution operation still needs recovery")
            if state["revision"] != expected_revision and not safety_pause:
                raise HTTPException(409, "contribution state revision changed")
            now = datetime.now(timezone.utc).isoformat()
            intent = {key: value for key, value in payload.items() if key != "invite"}
            connection.execute("INSERT INTO contribution_operations VALUES (?,?,?,?,?,?,?,?,NULL,?,'executing',NULL,NULL,?,?)",
                               (identifier, *binding, canonical(intent), os.getpid(), now, now))
            self._audit(connection, identifier, "claimed", state["revision"])
            return True, None

    def intent(self, identifier):
        with self.transaction() as connection:
            row = connection.execute("SELECT intent,remote_intent FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone()
            return json.loads(row["intent"]), json.loads(row["remote_intent"]) if row["remote_intent"] else None

    def remote(self, identifier, policy, generation, *, request_id, revision_hash):
        with self.transaction() as connection:
            row = connection.execute("SELECT remote_intent FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone()
            previous = json.loads(row["remote_intent"]) if row["remote_intent"] else None
            attempts = previous.get("attempts", []) if previous else []
            if len(attempts) >= 2 or previous and previous.get("status") != "rejected":
                raise HTTPException(409, "original center request cannot be replaced while its result is unknown")
            attempt = {"request_id": request_id, "revision_hash": revision_hash, "policy": policy, "status": "sent"}
            connection.execute("UPDATE contribution_operations SET remote_intent=? WHERE operation_id=? AND status='executing'",
                               (canonical({**attempt, "pause_generation": generation, "attempts": [*attempts, attempt]}), identifier))
            self._audit(connection, identifier, "center-policy-intent", self._state(connection)["revision"])

    def remote_rejected(self, identifier, request_id):
        with self.transaction() as connection:
            row = connection.execute("SELECT remote_intent FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone()
            remote = json.loads(row["remote_intent"])
            if remote["request_id"] != request_id:
                raise HTTPException(409, "original center request changed")
            remote["status"] = "rejected"
            remote["attempts"][-1]["status"] = "rejected"
            connection.execute("UPDATE contribution_operations SET remote_intent=? WHERE operation_id=?", (canonical(remote), identifier))
            self._audit(connection, identifier, "center-policy-cas-rejected", self._state(connection)["revision"])

    def pause_intent(self, explicit):
        with self.transaction() as connection:
            state = self._state(connection)
            generation = state.get("pause_generation", 0)
            if explicit:
                generation += 1
                revision = state.pop("revision") + 1
                state["pause_generation"] = generation
                connection.execute("UPDATE contribution_state SET revision=?,payload=? WHERE id=1", (revision, canonical(state)))
                self._audit(connection, self.active.get(), "pause-intent", revision)
            return generation

    def resume_if_current(self, generation, action):
        # The reviewed local owner-control update is serialized with new pause
        # intents across broker processes. No network request runs under this lock.
        with self.transaction() as connection:
            if self._state(connection).get("pause_generation", 0) == generation:
                action()

    @contextmanager
    def executing(self, identifier):
        token = self.active.set(identifier)
        try:
            yield
        finally:
            self.active.reset(token)

    def complete(self, identifier, result, *, recovered=False):
        with self.transaction() as connection:
            existing = connection.execute("SELECT * FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone()
            if existing["status"] in {"completed", "failed"}:
                return self._receipt(existing)
            state = self._state(connection)
            # The authoritative state and exact safe receipt share this commit.
            if result.get("revision") != state["revision"]:
                raise HTTPException(409, "contribution changed before its receipt could be committed")
            now = datetime.now(timezone.utc).isoformat()
            connection.execute("UPDATE contribution_operations SET status='completed',result=?,error=NULL,updated_at=? WHERE operation_id=? AND status IN ('executing','unknown')",
                               (canonical(result), now, identifier))
            self._audit(connection, identifier, "recovered-completed" if recovered else "completed", state["revision"])
            return self._receipt(connection.execute("SELECT * FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone())

    def unknown(self, identifier, *, result=None):
        with self.transaction() as connection:
            changed = connection.execute("UPDATE contribution_operations SET status='unknown',result=COALESCE(?,result),error='original_effect_requires_recovery',updated_at=? WHERE operation_id=? AND status='executing'",
                                         (canonical(result) if result is not None else None, datetime.now(timezone.utc).isoformat(), identifier)).rowcount
            if changed:
                self._audit(connection, identifier, "outcome-unknown", self._state(connection)["revision"])

    def failed(self, identifier, result):
        with self.transaction() as connection:
            existing = connection.execute("SELECT * FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone()
            if existing["status"] in {"completed", "failed"}:
                return self._receipt(existing)
            error = {"reason_code": "machine_policy_revision_conflict", "message": "中心策略已变更，原请求未应用；本机暂停状态已保留。请核对最新状态后明确发起新修改。"}
            connection.execute("UPDATE contribution_operations SET status='failed',result=?,error=?,updated_at=? WHERE operation_id=? AND status IN ('executing','unknown')",
                (canonical(result), canonical(error), datetime.now(timezone.utc).isoformat(), identifier))
            self._audit(connection, identifier, "center-policy-conflict-failed", self._state(connection)["revision"])
            return self._receipt(connection.execute("SELECT * FROM contribution_operations WHERE operation_id=?", (identifier,)).fetchone())

    def pending(self, *, actor_id, center_url):
        with self.transaction() as connection:
            return [self._receipt(row)["operation"] for row in connection.execute(
                "SELECT * FROM contribution_operations WHERE actor_id=? AND center_url=? AND status IN ('executing','unknown') ORDER BY created_at",
                (actor_id, center_url))]
