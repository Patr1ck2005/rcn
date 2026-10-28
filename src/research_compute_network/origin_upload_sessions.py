"""Durable sequential uploads; one in-place partial, no staging concatenation.

Idle sessions own bytes, not writers. Each admitted writer reserves only its
remaining allocation in the existing volume ledger, and releases after closing
its handles. Recovery requires both an OS-exclusive target lock and proof that
the previous exact process incarnation exited; timestamps never release claims.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import JSON, String
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Mapped, Session, mapped_column

from .hashing import sha256_value
from .origin import MAX_BUNDLE_BYTES
from .origin_transfer import managed_path
from .result_preparations import ResultPreparations, PreparationCancelled, verification_slots, utc_now
from .repository import Base

UPLOAD_CHUNK_BYTES = 8 * 1024**2


class UploadSessionRow(Base):
    """Upload metadata lives in the existing control-plane repository."""
    __tablename__ = "origin_upload_sessions"
    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)


class UploadSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: Literal["bundle", "asset"]
    target_id: str = Field(min_length=1, max_length=192)
    size_bytes: int = Field(ge=0, le=MAX_BUNDLE_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # Identity is intentional: directly resume the canonical asset, avoiding
    # both a persistent gzip copy and a second server-side decoded partial.
    encoding: Literal["identity"] = "identity"


class TargetLock:
    """Kernel-released lock, including across processes and process crashes."""
    def __init__(self, path):
        self.stream = path.open("a+b")
        try:
            if self.stream.seek(0, os.SEEK_END) == 0:
                self.stream.write(b"\0")
                self.stream.flush()
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            raise HTTPException(409, {"reason_code": "upload_writer_busy"}, headers={"Retry-After": "1"}) from exc

    def close(self):
        if self.stream.closed:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_UN)
        finally:
            self.stream.close()


class UploadVerifications(ResultPreparations):
    """Reuse the preparation scheduler/admission limits without ready handles."""
    def _verify(self, ticket, factory):
        def progress(checked, total, **_):
            with self.lock:
                ticket.document.update(state="verifying", checked_bytes=checked, total_bytes=total)
        try:
            factory(progress, ticket.cancel.is_set)
            state, reason = "completed", None
        except BaseException as exc:
            state = "cancelled" if isinstance(exc, PreparationCancelled) else "failed"
            reason = "upload_verification_interrupted" if state == "cancelled" else "upload_verification_failed"
        with self.lock:
            # Hold the scheduler lock while ending the target writer, so a
            # same-session retry cannot see its previous worker still active.
            factory.cleanup()
            self._release(ticket)
            ticket.document.update(state=state, reason_code=reason)
            self._save(ticket)


class UploadWriter:
    def __init__(self, manager, document, lock):
        self.manager, self.document, self.lock = manager, document, lock
        self.reserved = False

    @property
    def partial(self):
        return self.manager.partial(self.document)

    def reserve(self, remaining):
        self.manager.reserve(self.document, max(1, remaining))
        self.reserved = True

    def release_reservation(self):
        if self.reserved:
            self.manager.store.release(self.document["_holder_key"])
            self.reserved = False

    def close(self):
        try:
            self.release_reservation()
        finally:
            self.lock.close()


class UploadSessions:
    def __init__(self, store, control_root=None, *, repository, gate=None):
        self.store = store
        self.repository = repository
        self.directory = managed_path(Path(control_root) if control_root is not None else store.root,
                                      "origin-upload-sessions")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.locks = managed_path(self.directory, "locks")
        self.locks.mkdir(exist_ok=True)
        UploadSessionRow.__table__.create(repository.engine, checkfirst=True)
        # Share the existing preparation index, not another upload-owned DB.
        self.verifications = UploadVerifications(control_root, gate=gate, max_active=4, max_actor_active=4)

    @contextmanager
    def connection(self, *, durable=False):
        with self.repository.engine.connect() as connection:
            synchronous = None
            try:
                if durable and connection.dialect.name == "sqlite":
                    # Offset acknowledgements follow file fsync with a FULL
                    # metadata commit. Restore this pooled connection's setting
                    # afterwards; ordinary repository policy remains unchanged.
                    synchronous = connection.exec_driver_sql("PRAGMA synchronous").scalar_one()
                    connection.exec_driver_sql("PRAGMA synchronous=FULL")
                    connection.commit()
                with Session(connection, expire_on_commit=False) as db:
                    yield db
                    db.commit()
            except OperationalError as exc:
                connection.rollback()
                if "locked" in str(exc).lower():
                    raise HTTPException(503, {"reason_code": "storage_metadata_busy"}, headers={"Retry-After": "1"}) from exc
                raise
            finally:
                if synchronous is not None:
                    connection.rollback()
                    connection.exec_driver_sql(f"PRAGMA synchronous={int(synchronous)}")
                    connection.commit()

    def save(self, document):
        with self.connection(durable=True) as db:
            db.merge(UploadSessionRow(session_id=document["session_id"], document=dict(document)))

    def read(self, session_id, actor_id, job_id):
        with self.connection() as db:
            row = db.get(UploadSessionRow, session_id)
        document = dict(row.document) if row else None
        if document is None or (document["actor_id"], document["job_id"]) != (actor_id, job_id):
            raise HTTPException(404, {"reason_code": "upload_session_not_found"})
        return document

    @staticmethod
    def view(document):
        result = {k: v for k, v in document.items() if not k.startswith("_") and k != "actor_id"}
        result.update(chunk_bytes=UPLOAD_CHUNK_BYTES, ready=document["state"] == "completed", retry_after=1,
                      verification_required=bool(document.get("_validation_only")))
        return result

    def partial(self, document):
        return managed_path(self.store.root, document["_partial"])

    def lock(self, holder_key):
        return TargetLock(managed_path(self.locks, hashlib.sha256(holder_key.encode()).hexdigest() + ".lock"))

    def reserve(self, document, remaining):
        self.reconcile_claims(document)
        self.store.reserve(document["_holder_key"], remaining)

    def reconcile_claims(self, document):
        key = document["_holder_key"]
        budget = self.store.volume_budget
        if budget is not None:
            for claim in budget.active_claims():
                if claim["holder_kind"] != "http-upload" or claim["holder_key"] != key:
                    continue
                if budget._owner_alive(claim["owner_pid"], claim["owner_started_at"]) is False:
                    # This path holds the exact kernel target lock. Upload IO is
                    # joined threads only: there is no child process writer.
                    budget.reconcile_orphan(claim["token"], expected_owner_pid=claim["owner_pid"],
                        expected_owner_started_at=claim["owner_started_at"], writer_tree_exited=True,
                        evidence="resumable upload target OS lock held; exact process exited; upload IO has no subprocess writers")

    def initialize(self, actor_id, job_id, body, *, target, holder_key, binding):
        identity = dict(body.model_dump(), actor_id=actor_id, job_id=job_id, binding=binding)
        session_id = sha256_value({k: identity[k] for k in ("actor_id", "job_id", "kind", "target_id")})
        try:
            lock = self.lock(holder_key)
        except HTTPException:
            current = self.read(session_id, actor_id, job_id)
            if any(current.get(k) != v for k, v in identity.items()):
                raise HTTPException(409, {"reason_code": "upload_identity_conflict"})
            return self.view(current)
        writer = None
        try:
            try:
                document = self.read(session_id, actor_id, job_id)
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
                document = dict(identity, session_id=session_id, offset=0, state="uploading", checked_bytes=0,
                    created_at=utc_now(), _holder_key=holder_key,
                    _target=target.relative_to(self.store.root).as_posix(),
                    _partial=(target.parent / (".upload-" + session_id + ".partial")).relative_to(self.store.root).as_posix())
                if target.exists():
                    # An existing shared asset/legacy bundle is checked by the
                    # same bounded verifier before claiming it ready. Its bytes
                    # need neither another persistent partial nor retransmission.
                    document.update(offset=body.size_bytes, _validation_only=True)
            if any(document.get(k) != v for k, v in identity.items()):
                raise HTTPException(409, {"reason_code": "upload_identity_conflict"})
            if document["state"] == "cancelled":
                raise HTTPException(410, {"reason_code": "upload_session_cancelled"})
            if document["state"] == "completed":
                return self.view(document)
            writer = UploadWriter(self, document, lock)
            writer.reserve(document["size_bytes"] - document["offset"])
            if not document.get("_validation_only"):
                self.recover(writer)
            self.save(document)
            return self.view(document)
        finally:
            writer.close() if writer else lock.close()

    def recover(self, writer):
        document, partial = writer.document, writer.partial
        self.store.check_write()
        partial.parent.mkdir(parents=True, exist_ok=True)
        if not partial.exists():
            if document["offset"]:
                raise HTTPException(409, {"reason_code": "upload_partial_missing"})
            with partial.open("xb") as output:
                output.flush()
                os.fsync(output.fileno())
        with partial.open("r+b") as output:
            if output.seek(0, os.SEEK_END) < document["offset"]:
                raise HTTPException(409, {"reason_code": "upload_partial_truncated"})
            output.truncate(document["offset"])
            output.flush()
            os.fsync(output.fileno())
        if document["state"] == "verifying":
            document.update(state="uploading", reason_code="upload_verification_restarted")

    def begin(self, session_id, actor_id, job_id):
        document = self.read(session_id, actor_id, job_id)
        lock = self.lock(document["_holder_key"])
        try:
            document = self.read(session_id, actor_id, job_id)
            return UploadWriter(self, document, lock)
        except BaseException:
            lock.close()
            raise

    def begin_chunk(self, session_id, actor_id, job_id, offset, length):
        writer = self.begin(session_id, actor_id, job_id)
        try:
            d = writer.document
            if d["state"] in {"completed", "cancelled", "failed"}:
                raise HTTPException(409, {"reason_code": "upload_not_writable"})
            if d.get("_validation_only"):
                raise HTTPException(409, {"reason_code": "upload_verification_required"})
            if (offset < 0 or offset % UPLOAD_CHUNK_BYTES or offset > d["offset"]
                or length != min(UPLOAD_CHUNK_BYTES, d["size_bytes"] - offset) or length <= 0
                or (offset < d["offset"] and offset + length > d["offset"])):
                raise HTTPException(409, {"reason_code": "upload_offset_conflict", "offset": d["offset"]})
            writer.reserve(d["size_bytes"] - d["offset"])
            self.recover(writer)
            return writer
        except BaseException:
            writer.close()
            raise

    def append(self, writer, offset, content, digest, validate):
        d = writer.document
        if hashlib.sha256(content).hexdigest() != digest:
            raise HTTPException(422, {"reason_code": "upload_chunk_hash_mismatch"})
        validate(d)
        self.store.check_write()
        with writer.partial.open("r+b") as output:
            output.seek(offset)
            if offset < d["offset"]:
                if output.read(len(content)) != content:
                    raise HTTPException(409, {"reason_code": "upload_chunk_replay_conflict"})
                return self.view(d)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        validate(d)
        d.update(offset=offset + len(content), state="uploading", reason_code=None)
        self.save(d)
        return self.view(d)

    def finalize(self, session_id, actor_id, job_id, validate, publish, *, verify_existing=None):
        try:
            writer = self.begin(session_id, actor_id, job_id)
        except HTTPException as exc:
            current = self.read(session_id, actor_id, job_id)
            if current["state"] == "verifying" and exc.status_code == 409:
                validate(current)
                return self.view(current)
            raise
        scheduled = False
        try:
            d = writer.document
            validate(d)
            if d["state"] == "completed" and verify_existing is None:
                return self.view(d)
            if d["state"] in {"cancelled", "failed"}:
                raise HTTPException(409, {"reason_code": "upload_not_writable"})
            if d["offset"] != d["size_bytes"]:
                raise HTTPException(409, {"reason_code": "upload_incomplete", "offset": d["offset"]})
            writer.reserve(1)
            existing = (d["state"] == "completed" or d.get("_validation_only")) and verify_existing is not None
            if not existing:
                self.recover(writer)
            d["_validation_only"] = bool(existing)
            d.update(state="verifying", reason_code=None, checked_bytes=0)
            self.save(d)

            def factory(progress, cancelled):
                acquired = False
                try:
                    volume = os.stat(writer.partial.parent).st_dev
                    verification_slots.acquire(volume, cancelled)
                    acquired = True
                    def recheck():
                        if cancelled():
                            raise PreparationCancelled()
                        return validate(d)
                    recheck()
                    if existing:
                        receipt = verify_existing(d)
                        checked = d["size_bytes"]
                        recheck()
                    else:
                        checksum, checked = hashlib.sha256(), 0
                        with writer.partial.open("rb") as incoming:
                            while chunk := incoming.read(UPLOAD_CHUNK_BYTES):
                                recheck()
                                checksum.update(chunk)
                                checked += len(chunk)
                                progress(checked, d["size_bytes"])
                        if checked != d["size_bytes"] or checksum.hexdigest() != d["sha256"]:
                            raise HTTPException(422, {"reason_code": "upload_file_hash_mismatch"})
                        recheck()
                        receipt = publish(d, writer.partial, recheck)
                    # Persist canonical recovery before removing the partial:
                    # a restart during cleanup must revalidate published bytes,
                    # without requiring either retransmission or a second copy.
                    d.update(_validation_only=True, checked_bytes=checked, receipt=receipt, reason_code=None)
                    self.save(d)
                    writer.partial.unlink(missing_ok=True)
                    writer.release_reservation()
                    # Keep the target OS lock until this commit. Completed is
                    # observable only after all owned data and claims are gone.
                    d.update(state="completed")
                    self.save(d)
                except BaseException as exc:
                    # Shutdown/deferred storage can restart verification from
                    # the same complete partial. Integrity failures stay failed.
                    detail = getattr(exc, "detail", {})
                    reason = detail.get("reason_code") if isinstance(detail, dict) else None
                    retryable = isinstance(exc, (PreparationCancelled, OSError)) or getattr(exc, "status_code", 0) in {503, 507}
                    d.update(state="uploading" if retryable else "failed",
                             reason_code=reason or ("upload_verification_interrupted" if retryable else "upload_verification_failed"))
                    self.save(d)
                    raise
                finally:
                    if acquired:
                        verification_slots.release(volume)

            factory.cleanup = writer.close

            pending = self.view(d)
            self.verifications.prepare(actor_id, dict(operation_id="upload-" + session_id, job_id=job_id,
                size_bytes=d["size_bytes"], sha256=d["sha256"]), factory)
            scheduled = True
            return pending
        finally:
            if not scheduled:
                writer.close()

    def cancel(self, session_id, actor_id, job_id):
        writer = self.begin(session_id, actor_id, job_id)
        try:
            d = writer.document
            if d["state"] == "completed":
                return self.view(d)
            self.store.check_write()
            # Cancellation allocates no data; low space must not prevent
            # removing this exact idle session's owned partial.
            self.reconcile_claims(d)
            writer.partial.unlink(missing_ok=True)
            d.update(state="cancelled", reason_code="upload_session_cancelled")
            self.save(d)
            return self.view(d)
        finally:
            writer.close()

    def status(self, session_id, actor_id, job_id):
        document = self.read(session_id, actor_id, job_id)
        if document["state"] == "verifying":
            try:
                lock = self.lock(document["_holder_key"])
            except HTTPException as exc:
                if exc.status_code != 409:
                    raise
            else:
                try:
                    document = self.read(session_id, actor_id, job_id)
                    if document["state"] == "verifying":
                        document.update(state="uploading", reason_code="upload_verification_restarted")
                        self.save(document)
                finally:
                    lock.close()
        return self.view(document)

    def close(self):
        self.verifications.close()
