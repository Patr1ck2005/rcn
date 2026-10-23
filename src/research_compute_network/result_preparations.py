"""Bounded, persistent identities for verified result handles.

Only metadata survives a process. A ready ticket always belongs to this process
and owns one exact verified handle, its reader pin and its drain admission.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex

from fastapi import HTTPException


VERIFY_CHUNK_BYTES = 1024 * 1024
IDLE_SECONDS = 120
DRAIN_READY_GRACE_SECONDS = 5
TERMINAL_CACHE_LIMIT = 128


class PreparationCancelled(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class VerificationSlots:
    """Count real verification IO, including blocked OS reads, until it ends."""

    def __init__(self):
        self.condition = threading.Condition()
        self.volumes = set()
        self.active = 0

    def acquire(self, volume, cancelled=lambda: False):
        with self.condition:
            while self.active >= 2 or volume in self.volumes:
                if cancelled():
                    raise PreparationCancelled()
                self.condition.wait(0.1)
            if cancelled():
                raise PreparationCancelled()
            self.active += 1
            self.volumes.add(volume)

    def release(self, volume):
        with self.condition:
            self.active -= 1
            self.volumes.remove(volume)
            self.condition.notify_all()


verification_slots = VerificationSlots()


class TransferActivity:
    def __init__(self, gate):
        self.gate = gate
        try:
            self.token = gate.enter()
        except Exception as exc:
            from .release_maintenance import TransferAdmissionClosed
            if isinstance(exc, TransferAdmissionClosed):
                raise HTTPException(503, {"reason_code": "release_draining"}, headers={"Retry-After": "5"}) from exc
            raise

    def release(self):
        if self.token is not None:
            self.gate.leave(self.token)
            self.token = None


@dataclass
class Ticket:
    document: dict
    resource: object = None
    admission: object = None
    cancel: threading.Event = field(default_factory=threading.Event)
    serving: bool = False
    last_active: float = field(default_factory=time.monotonic)
    saved_at: float = 0
    worker: threading.Thread | None = None
    ready_at: float = 0


class PreparationIndex:
    """Exact durable operation lookup without loading historical ticket bodies."""

    def __init__(self, directory):
        self.directory = directory
        self.legacy = None
        self.legacy_complete = directory is None
        if directory is None:
            self.database = None
            return
        directory.mkdir(parents=True, exist_ok=True)
        self.database = directory / "index.sqlite3"
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS preparations (ticket_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, "
                       "operation_id TEXT NOT NULL, document TEXT NOT NULL, UNIQUE(actor_id,operation_id))")
            db.execute("CREATE TABLE IF NOT EXISTS preparation_index_state (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            self.legacy_complete = db.execute("SELECT 1 FROM preparation_index_state WHERE key='legacy_complete'").fetchone() is not None

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.database, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def save(self, document):
        if self.database is None:
            return
        with self._connect() as db:
            db.execute("INSERT INTO preparations VALUES (?,?,?,?) ON CONFLICT(ticket_id) DO UPDATE SET document=excluded.document",
                (document["ticket_id"], document["actor_id"], document["operation_id"], json.dumps(document, sort_keys=True)))

    def _read(self, field, values):
        if self.database is None:
            return None
        with self._connect() as db:
            row = db.execute("SELECT document FROM preparations WHERE " + field, values).fetchone()
        return json.loads(row[0]) if row is not None else None

    def _import_legacy(self, path):
        document = json.loads(path.read_text(encoding="utf-8"))
        current = self._read("ticket_id=?", (document["ticket_id"],))
        if current is None:
            self.save(document)
            return document
        return current

    def by_ticket(self, ticket_id):
        document = self._read("ticket_id=?", (ticket_id,))
        if (document is None and self.directory is not None and
                re.fullmatch(r"[A-Za-z0-9._-]{1,128}", ticket_id) and ticket_id not in {".", ".."}):
            path = self.directory / (ticket_id + ".json")
            if path.is_file():
                document = self._import_legacy(path)
        return document

    def by_operation(self, actor_id, operation_id):
        document = self._read("actor_id=? AND operation_id=?", (actor_id, operation_id))
        if document is not None or self.legacy_complete:
            return document
        # First-version JSON identities are migrated lazily, once. Startup does
        # not enumerate them; a miss must finish indexing before admitting a new
        # identity, because an unindexed historical operation could conflict.
        if self.legacy is None:
            self.legacy = self.directory.glob("*.json")
        for path in self.legacy:
            item = self._import_legacy(path)
            if (item["actor_id"], item["operation_id"]) == (actor_id, operation_id):
                return item
        self.legacy_complete = True
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO preparation_index_state VALUES ('legacy_complete','1')")
        return None


class ResultPreparations:
    def __init__(self, control_root: Path | None, *, gate=None, idle_seconds=IDLE_SECONDS,
                 terminal_cache_limit=TERMINAL_CACHE_LIMIT, drain_ready_grace_seconds=DRAIN_READY_GRACE_SECONDS):
        if type(terminal_cache_limit) is not int or terminal_cache_limit < 1:
            raise ValueError("terminal ticket cache must retain at least one entry")
        self.directory = Path(control_root) / "result-preparations" if control_root is not None else None
        self.gate = gate
        self.idle_seconds = idle_seconds
        self.lock = threading.RLock()
        self.body_ended = threading.Condition(self.lock)
        self.tickets = OrderedDict()
        self.operations = {}
        self.terminal_cache_limit = terminal_cache_limit
        self.drain_ready_grace_seconds = drain_ready_grace_seconds
        self.process_id = token_hex(16)
        self.index = PreparationIndex(self.directory)
        self.stopped = threading.Event()
        self.draining = False
        self.sweeper = None

    def _save(self, ticket):
        ticket.document["_process_id"] = self.process_id
        self.index.save(ticket.document)
        ticket.saved_at = time.monotonic()
        self._trim_cache()

    def _trim_cache(self):
        terminal = [key for key, item in self.tickets.items() if item.resource is None and item.admission is None
                    and not item.serving and (item.document["state"] not in {"queued", "verifying", "restore_pending", "ready", "cancelling"}
                                             or self._deferred(item))]
        for key in terminal[:max(0, len(terminal) - self.terminal_cache_limit)]:
            item = self.tickets.pop(key)
            self.operations.pop((item.document["actor_id"], item.document["operation_id"]), None)

    @staticmethod
    def _deferred(ticket):
        return (ticket.document.get("state") == "restore_pending"
                and ticket.document.get("reason_code") in {"storage_background_deferred", "restore_source_unavailable"}
                and ticket.resource is None and ticket.admission is None and not ticket.serving)

    def _remember(self, document):
        if document is None:
            return None
        ticket = Ticket(document)
        self.tickets[document["ticket_id"]] = ticket
        self.operations[(document["actor_id"], document["operation_id"])] = ticket
        if document["state"] in {"queued", "verifying", "restore_pending", "ready", "cancelling"}:
            document.update(state="reprepare_required", reason_code="preparation_process_restarted")
            self._save(ticket)
        self._trim_cache()
        return ticket

    def _operation(self, actor_id, operation_id):
        ticket = self.operations.get((actor_id, operation_id))
        if ticket is None:
            ticket = self._remember(self.index.by_operation(actor_id, operation_id))
        if ticket is not None and ticket.document["ticket_id"] in self.tickets:
            self.tickets.move_to_end(ticket.document["ticket_id"])
        return ticket

    def _view(self, ticket):
        result = {key: value for key, value in ticket.document.items() if key != "actor_id" and not key.startswith("_")}
        base = f"/v1/jobs/{result['job_id']}/origin-result-preparations/{result['ticket_id']}"
        result.update(status_url=base, content_url=base + "/content", etag='"' + result["sha256"] + '"', retry_after=2)
        return result

    def _owned(self, ticket_id, actor_id, job_id):
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            ticket = self._remember(self.index.by_ticket(ticket_id))
        if ticket is None or (ticket.document["actor_id"], ticket.document["job_id"]) != (actor_id, job_id):
            raise HTTPException(404, {"reason_code": "preparation_not_found"})
        if ticket_id in self.tickets:
            self.tickets.move_to_end(ticket_id)
        return ticket

    def _release(self, ticket):
        # Caller holds the lock; no body or verification thread may own this IO.
        resource = ticket.resource
        if resource is not None:
            resource.opened_file.close()
            if resource.reader_pin is not None:
                resource.reader_pin.release()
            ticket.resource = None
        # A failed close/release keeps admission owned; maintenance must not
        # report drained while a handle or reader pin could still be active.
        if ticket.admission is not None:
            ticket.admission.release()
            ticket.admission = None

    def check_identity(self, actor_id, identity):
        with self.lock:
            ticket = self._operation(actor_id, identity["operation_id"])
            if ticket is not None and any(ticket.document.get(name) != value for name, value in identity.items()):
                raise HTTPException(409, {"reason_code": "operation_id_conflict"})

    def prepare(self, actor_id, identity, factory):
        with self.lock:
            key = actor_id, identity["operation_id"]
            ticket = self._operation(*key)
            if ticket is not None:
                if any(ticket.document.get(name) != value for name, value in identity.items()):
                    raise HTTPException(409, {"reason_code": "operation_id_conflict"})
                self._expire(ticket)
                if ticket.document["state"] in {"queued", "verifying", "restore_pending", "ready", "cancelling"} and not self._deferred(ticket):
                    return self._view(ticket)
            if self.stopped.is_set() or (self.draining and self.gate is None):
                raise HTTPException(503, {"reason_code": "release_draining"}, headers={"Retry-After": "5"})
            admission = TransferActivity(self.gate) if self.gate is not None else None
            if admission is not None:
                self.draining = False
            active = [item for item in self.tickets.values() if not self._deferred(item) and (item.admission is not None or
                      item.document["state"] in {"queued", "verifying", "restore_pending", "ready", "cancelling"})]
            if len(active) >= 8 or sum(item.document["actor_id"] == actor_id for item in active) >= 2:
                if admission is not None:
                    admission.release()
                raise HTTPException(429, {"reason_code": "preparation_capacity"}, headers={"Retry-After": "5"})
            if ticket is None:
                ticket = Ticket(dict(identity, ticket_id=token_hex(24), actor_id=actor_id, created_at=utc_now()))
                self.tickets[ticket.document["ticket_id"]] = ticket
                self.operations[key] = ticket
            ticket.document.update(state="queued", checked_bytes=0, total_bytes=identity["size_bytes"],
                                   last_progress_at=utc_now(), reason_code=None)
            ticket.document.pop("http_status", None)
            ticket.cancel.clear()
            ticket.admission = admission
            ticket.last_active = time.monotonic()
            try:
                self._save(ticket)
                if self.sweeper is None:
                    self.sweeper = threading.Thread(target=self._sweep, name="result-preparation-expiry", daemon=True)
                    self.sweeper.start()
                ticket.worker = threading.Thread(target=self._verify, args=(ticket, factory), daemon=True,
                                                 name="result-verify-" + ticket.document["ticket_id"][:8])
                ticket.worker.start()
            except BaseException:
                self._release(ticket)
                ticket.document.update(state="failed", reason_code="preparation_start_failed")
                raise
            return self._view(ticket)

    def _verify(self, ticket, factory):
        def progress(checked, total, *, state="verifying"):
            with self.lock:
                ticket.document.update(state="cancelling" if ticket.cancel.is_set() else state,
                                       checked_bytes=checked, total_bytes=total, last_progress_at=utc_now())
                if state == "restore_pending" or time.monotonic() - ticket.saved_at >= 1:
                    self._save(ticket)

        resource = None
        try:
            resource = factory(progress, ticket.cancel.is_set)
            with self.lock:
                ticket.resource = resource
                resource = None
                if ticket.cancel.is_set() or self.stopped.is_set():
                    self._release(ticket)
                    ticket.document.update(state="cancelled", reason_code="preparation_cancelled")
                else:
                    ticket.document.update(state="ready", checked_bytes=ticket.document["size_bytes"],
                                           last_progress_at=utc_now(), reason_code=None)
                    ticket.last_active = time.monotonic()
                    ticket.ready_at = ticket.last_active
                self._save(ticket)
        except BaseException as exc:
            with self.lock:
                # A factory failure must close its own partial resource first.
                if resource is not None:
                    ticket.resource = resource
                self._release(ticket)
                detail = getattr(exc, "detail", {})
                reason = detail.get("reason_code") if isinstance(detail, dict) else None
                deferred = (reason or getattr(exc, "reason_code", None)) in {"storage_background_deferred", "restore_source_unavailable"}
                ticket.document.update(state="cancelled" if ticket.cancel.is_set() or isinstance(exc, PreparationCancelled) else "restore_pending" if deferred else "failed",
                    reason_code="preparation_cancelled" if ticket.cancel.is_set() or isinstance(exc, PreparationCancelled)
                    else reason or getattr(exc, "reason_code", "result_unavailable_or_integrity_failed"),
                    http_status=getattr(exc, "status_code", 409))
                self._save(ticket)

    def status(self, ticket_id, actor_id, job_id):
        with self.lock:
            ticket = self._owned(ticket_id, actor_id, job_id)
            self._expire(ticket)
            return self._view(ticket)

    def cancel_ticket(self, ticket_id, actor_id, job_id):
        with self.lock:
            ticket = self._owned(ticket_id, actor_id, job_id)
            ticket.cancel.set()
            if ticket.serving or (ticket.document["state"] in {"queued", "verifying", "restore_pending", "cancelling"} and not self._deferred(ticket)):
                ticket.document.update(state="cancelling", reason_code="preparation_cancelled")
            else:
                self._release(ticket)
                ticket.document.update(state="cancelled", reason_code="preparation_cancelled")
            self._save(ticket)
            return self._view(ticket)

    def begin_body(self, ticket_id, actor_id, job_id):
        with self.lock:
            ticket = self._owned(ticket_id, actor_id, job_id)
            self._expire(ticket)
            if ticket.document["state"] != "ready" or ticket.resource is None:
                reason = ticket.document.get("reason_code") or "preparation_not_ready"
                # A release may expire an idle handle after the client's last
                # ready poll. This is maintenance deferral, just like a new
                # preparation admission, and must not become a permanent
                # identity/integrity conflict in the existing client.
                maintenance = reason in {"release_draining", "storage_background_deferred", "restore_source_unavailable",
                    "preparation_expired", "preparation_process_restarted", "preparation_process_stopped"}
                raise HTTPException(503 if maintenance else 409,
                    {"reason_code": reason, "state": ticket.document["state"]},
                    headers={"Retry-After": "5"} if maintenance else None)
            if ticket.serving:
                raise HTTPException(409, {"reason_code": "preparation_body_busy"}, headers={"Retry-After": "1"})
            ticket.serving = True
            ticket.last_active = time.monotonic()
            return ticket

    def defer_body(self, ticket, reason="storage_background_deferred"):
        """Called after its last joined read ended; free scarce ready ownership."""
        with self.lock:
            ticket.serving = False
            self.body_ended.notify_all()
            self._release(ticket)
            ticket.document.update(state="restore_pending", reason_code=reason, http_status=503)
            self._save(ticket)

    def end_body(self, ticket):
        with self.lock:
            ticket.serving = False
            self.body_ended.notify_all()
            ticket.last_active = time.monotonic()
            if ticket.cancel.is_set():
                self._release(ticket)
                ticket.document.update(state="cancelled", reason_code="preparation_cancelled")
                self._save(ticket)
            elif self.draining or self.stopped.is_set():
                self._release(ticket)
                ticket.document.update(state="expired", reason_code="release_draining" if self.draining else "preparation_process_stopped")
                self._save(ticket)

    def _expire(self, ticket):
        if (ticket.document["state"] == "ready" and not ticket.serving and
                time.monotonic() - ticket.last_active >= self.idle_seconds):
            self._release(ticket)
            ticket.document.update(state="expired", reason_code="preparation_expired")
            self._save(ticket)

    def drain_idle(self):
        with self.lock:
            self.draining = True
            for ticket in list(self.tickets.values()):
                if ticket.serving:
                    continue
                if ticket.document["state"] == "ready" and ticket.resource is not None:
                    if time.monotonic() < ticket.ready_at + self.drain_ready_grace_seconds:
                        continue
                    self._release(ticket)
                    ticket.document.update(state="expired", reason_code="release_draining")
                else:
                    continue
                self._save(ticket)

    def _sweep(self):
        while not self.stopped.wait(1):
            try:
                with self.lock:
                    active = any(not self._deferred(ticket) and (ticket.admission is not None or ticket.resource is not None or ticket.serving
                                 or ticket.document["state"] in {"queued", "verifying", "restore_pending", "cancelling"}
                                 ) for ticket in self.tickets.values())
                    if not active:
                        self.sweeper = None
                        return
                if self.gate is not None and (self.draining or active):
                    if self._gate_closed():
                        self.drain_idle()
                    else:
                        with self.lock:
                            self.draining = False
                with self.lock:
                    for ticket in list(self.tickets.values()):
                        self._expire(ticket)
            except Exception as exc:
                # Keep every uncertain owner counted and retry the metadata
                # operation; a busy ledger must not kill expiry permanently.
                logging.getLogger(__name__).warning("result_preparations.sweep_deferred type=%s", type(exc).__name__)

    def _gate_closed(self):
        if hasattr(self.gate, "admission_closed"):
            return self.gate.admission_closed()
        # The minimal gate contract is enter/leave. An immediate, empty
        # admission probe is also serialized against cross-process maintenance.
        try:
            activity = TransferActivity(self.gate)
        except HTTPException as exc:
            if exc.status_code == 503:
                return True
            raise
        activity.release()
        return False

    def close(self):
        self.stopped.set()
        sweeper = self.sweeper
        if sweeper is not None:
            sweeper.join()
        with self.lock:
            for ticket in list(self.tickets.values()):
                if ticket.serving:
                    continue
                if ticket.document["state"] in {"queued", "verifying", "restore_pending", "cancelling"}:
                    ticket.cancel.set()
                elif ticket.resource is not None:
                    self._release(ticket)
                    ticket.document.update(state="expired", reason_code="preparation_process_stopped")
                    self._save(ticket)
        # Joining is honest: a blocked OS read remains owned until it returns.
        for ticket in list(self.tickets.values()):
            if ticket.worker is not None:
                ticket.worker.join()
        with self.body_ended:
            while any(ticket.serving for ticket in self.tickets.values()):
                self.body_ended.wait(0.1)
