"""Durable Unit custody and exact-file retirement in the original metadata DB.

Custody is an authenticated adapter's assertion about bytes it actually read at
origin. It is deliberately separate from the v1 Job dataset-import receipt.
There is no remote filesystem access here and no age-based science-data GC.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

import psutil
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .hashing import canonical_json_bytes, sha256_value
from .models import FileRecord
from .origin_transfer import CHUNK_BYTES, identifier, managed_path, portable_parts


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LifecycleError(ValueError):
    def __init__(self, reason_code: str, message: str = ""):
        self.reason_code = reason_code
        super().__init__(message or reason_code)


# One bounded metadata retry budget; caller work is yielded exactly once.
METADATA_BUSY_WAIT_SECONDS = 12.0
METADATA_BUSY_SLICE_MS = 250
METADATA_BUSY_RETRY_DELAY_SECONDS = 0.05


class StorageMetadataBusy(RuntimeError):
    # Deliberately NOT LifecycleError: recovery gates catch that policy error.
    reason_code = "storage_metadata_busy"

    def __init__(self, operation: str):
        self.operation = operation
        super().__init__("storage metadata is temporarily locked")


def _is_metadata_busy(exc: sqlite3.Error) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        return code & 0xff in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
    message = str(exc).strip().casefold()
    return any(message == prefix or message.startswith(prefix + ":") for prefix in (
        "database is locked", "database table is locked", "database schema is locked",
    ))


def _retry_metadata_busy(operation, *, deadline: float, stage: str):
    while True:
        try:
            return operation()
        except sqlite3.Error as exc:
            if not _is_metadata_busy(exc):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StorageMetadataBusy(stage) from exc
            time.sleep(min(METADATA_BUSY_RETRY_DELAY_SECONDS, remaining))


class CustodyLocation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    host_id: str = Field(min_length=1, max_length=192)
    store_id: str = Field(min_length=1, max_length=192)
    volume_id: str = Field(min_length=1, max_length=512)
    generation: str = Field(min_length=1, max_length=192)
    physical_device_id: str = Field(min_length=1, max_length=512)

    @field_validator("host_id", "store_id", "volume_id", "generation", "physical_device_id")
    @classmethod
    def meaningful_identity(cls, value):
        if value != value.strip() or value.casefold() in {"unknown", "unregistered", "none"}:
            raise ValueError("custody requires an explicit physical storage identity")
        return value

    @field_validator("generation", mode="before")
    @classmethod
    def registered_generation(cls, value):
        # RCN's registered roots use positive integer generations; adapters may
        # have their own immutable generation IDs. Normalize integers exactly.
        if type(value) is int and value >= 1:
            return str(value)
        return value

    def physical_key(self) -> str:
        # Physical hardware identity, not the client that read it. The same
        # disk exposed through two hosts/shares is still only one copy.
        return self.physical_device_id.casefold()


class ProjectCustodyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str
    required_independent_copies: int = Field(default=2, ge=1, le=16, strict=True)
    automatic_retirement: bool = False
    protected_relative_paths: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("project_id")
    @classmethod
    def project_identity(cls, value):
        return identifier(value)

    @field_validator("protected_relative_paths")
    @classmethod
    def protected_paths(cls, values):
        for value in values:
            portable_parts(value)
        if len({v.casefold() for v in values}) != len(values):
            raise ValueError("protected paths must be unique")
        return sorted(values)


def inventory_payload(files: list[FileRecord]) -> list[dict]:
    """The full byte inventory, independent of order and media-type metadata."""
    names = [file.relative_path.casefold() for file in files]
    if not files or len(names) != len(set(names)):
        raise LifecycleError("ambiguous_inventory")
    for file in files:
        portable_parts(file.relative_path)
    return [{"relative_path": file.relative_path, "size_bytes": file.size_bytes,
             "sha256": file.sha256}
            for file in sorted(files, key=lambda item: item.relative_path)]


def inventory_sha256(files: list[FileRecord]) -> str:
    return sha256_value(inventory_payload(files))


class UnitCustodyReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    idempotency_key: str = Field(min_length=1, max_length=192)
    project_id: str
    job_id: str
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    work_unit_id: str
    producer_attempt_id: str
    producer_external_id: str
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: list[FileRecord] = Field(min_length=1, max_length=100000)
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target: CustodyLocation
    target_kind: Literal["origin_staging", "origin_dataset", "independent_archive"]
    verified_by: str
    adapter_id: str
    adapter_version: str = Field(min_length=1, max_length=192)
    adapter_build_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_at: datetime
    verification_method: Literal["sha256_full_read"]
    actual_bytes_verified: Literal[True]
    durable_publication: Literal[True]
    restore_ref: str = Field(min_length=1, max_length=2048)

    @field_validator("idempotency_key", "project_id", "job_id", "work_unit_id",
                     "producer_attempt_id", "adapter_id", "verified_by")
    @classmethod
    def safe_identity(cls, value):
        return identifier(value)

    @field_validator("verified_at")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verification time must include a timezone")
        if value > datetime.now(timezone.utc):
            raise ValueError("verification time cannot be in the future")
        return value

    @model_validator(mode="after")
    def check_inventory(self):
        if inventory_sha256(self.files) != self.inventory_sha256:
            raise ValueError("inventory digest does not match the full file list")
        if not self.producer_external_id.strip():
            raise ValueError("producer external identity is required")
        return self


class ReaderPin:
    """Explicit lifetime handle: keep it until streaming/restore has finished."""
    def __init__(self, lifecycle, pin_id):
        self.lifecycle, self.pin_id = lifecycle, pin_id

    def release(self):
        self.lifecycle.release_reader(self.pin_id)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.release()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_lifecycle_policies (
  project_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL,
  actor_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS storage_lifecycle_receipts (
  receipt_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
  job_id TEXT NOT NULL, unit_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL, payload TEXT NOT NULL, recorded_at TEXT NOT NULL,
  revoked_at TEXT, revoked_by TEXT, revoke_reason TEXT);
CREATE INDEX IF NOT EXISTS storage_lifecycle_receipt_unit
  ON storage_lifecycle_receipts(job_id, unit_id, attempt_id);
CREATE TABLE IF NOT EXISTS storage_lifecycle_intents (
  intent_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
  job_id TEXT NOT NULL, unit_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL,
  created_at TEXT NOT NULL, completed_at TEXT, last_reason TEXT);
CREATE TABLE IF NOT EXISTS storage_lifecycle_deletions (
  intent_id TEXT NOT NULL, relative_path TEXT NOT NULL, state TEXT NOT NULL,
  updated_at TEXT NOT NULL, PRIMARY KEY(intent_id, relative_path));
CREATE TABLE IF NOT EXISTS storage_lifecycle_readers (
  pin_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, unit_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL, relative_path TEXT NOT NULL, process_host TEXT NOT NULL,
  process_id INTEGER NOT NULL, process_started REAL NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS storage_lifecycle_reader_unit
  ON storage_lifecycle_readers(job_id, unit_id, attempt_id);
CREATE TABLE IF NOT EXISTS storage_lifecycle_audit (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
  actor_id TEXT NOT NULL, subject_id TEXT NOT NULL, created_at TEXT NOT NULL,
  details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS storage_lifecycle_gc_checks (
  job_id TEXT NOT NULL, unit_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  checked_at TEXT NOT NULL, PRIMARY KEY(job_id, unit_id, attempt_id));
CREATE TABLE IF NOT EXISTS storage_lifecycle_gc_gate (
  lock_key TEXT PRIMARY KEY, owner_token TEXT NOT NULL, process_host TEXT NOT NULL,
  process_id INTEGER NOT NULL, process_started REAL NOT NULL, acquired_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS storage_lifecycle_writer_permits (
  intent_id TEXT NOT NULL, relative_path TEXT NOT NULL, owner_token TEXT NOT NULL,
  process_host TEXT NOT NULL, process_id INTEGER NOT NULL, process_started REAL NOT NULL,
  authorized_at TEXT NOT NULL, PRIMARY KEY(intent_id, relative_path));
"""


class StorageLifecycle:
    def __init__(self, repository, center_root: Path, *, center_binding=None,
                 validate_center: Callable[[], Path] | None = None,
                 validate_retirement: Callable[[], Path] | None = None):
        self.repository = repository
        url = repository.engine.url
        if url.get_backend_name() != "sqlite" or url.database in {None, "", ":memory:"}:
            raise LifecycleError("durable_metadata_database_required")
        self.database = Path(url.database).expanduser().absolute()
        self.center_root = Path(center_root).absolute()
        self.validate_center = validate_center
        self.validate_retirement = validate_retirement
        if center_binding is not None and not isinstance(center_binding, CustodyLocation):
            volume = center_binding.volume_identity
            center_binding = CustodyLocation(host_id=center_binding.host_id,
                store_id=center_binding.store_id, generation=center_binding.generation,
                volume_id=volume.volume_id, physical_device_id=volume.physical_device_id)
        self.center_binding: CustodyLocation | None = center_binding
        self.process_host = socket.gethostname()
        self.process_started = psutil.Process(os.getpid()).create_time()
        with self._connect() as db:
            db.executescript(_SCHEMA)
            # Preserve every legacy intent, while giving solved-model expiry a
            # separate identity from whole relay-copy retirement.
            columns = {r[1] for r in db.execute("PRAGMA table_info(storage_lifecycle_intents)")}
            if "operation_kind" not in columns:
                db.execute("ALTER TABLE storage_lifecycle_intents ADD COLUMN operation_kind TEXT NOT NULL DEFAULT 'relay_copy'")
            db.execute("DROP INDEX IF EXISTS storage_lifecycle_intent_unit")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS storage_lifecycle_intent_operation "
                       "ON storage_lifecycle_intents(job_id,unit_id,attempt_id,operation_kind)")
        from .scientific_retention import ScientificRetention
        self.scientific = ScientificRetention(self)
        from .origin_retirement import OriginRetirement
        self.origin_retirement = OriginRetirement(self)
        from .derived_input_retention import DerivedInputRetention
        self.derived_inputs = DerivedInputRetention(self)

    def _open_connection(self, *, busy_timeout_ms=5000):
        db = sqlite3.connect(self.database, timeout=busy_timeout_ms / 1000, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            return db
        except BaseException:
            db.close()
            raise

    @contextmanager
    def _connect(self):
        db = self._open_connection()
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self):
        deadline = time.monotonic() + METADATA_BUSY_WAIT_SECONDS
        db = None
        try:
            db = _retry_metadata_busy(
                lambda: self._open_connection(busy_timeout_ms=METADATA_BUSY_SLICE_MS),
                deadline=deadline, stage="configure")
            _retry_metadata_busy(lambda: db.execute("BEGIN IMMEDIATE"),
                                 deadline=deadline, stage="begin")
            # No retry surrounds yield: never replay caller work or external IO.
            yield db
            # SQLite COMMIT busy keeps this exact transaction active.
            _retry_metadata_busy(db.commit, deadline=deadline, stage="commit")
        except BaseException as exc:
            if db is not None and db.in_transaction:
                try:
                    db.rollback()
                except sqlite3.Error:
                    pass  # Preserve the original failure; close also rolls back.
            if isinstance(exc, sqlite3.Error) and _is_metadata_busy(exc):
                raise StorageMetadataBusy("statement") from exc
            raise
        finally:
            if db is not None:
                db.close()

    def _audit(self, db, event_type, actor_id, subject_id, **details):
        db.execute("INSERT INTO storage_lifecycle_audit"
                   "(event_type, actor_id, subject_id, created_at, details) VALUES(?,?,?,?,?)",
                   (event_type, actor_id, subject_id, _now(), self._json(details)))

    @staticmethod
    def _json(value):
        return canonical_json_bytes(value).decode("utf-8")

    def _binding(self, job_id, unit_id, attempt_id, *, require_custody=True):
        for value in (job_id, unit_id, attempt_id):
            identifier(value)
        job = self.repository.get_origin_transfer_job(job_id, unit_id)
        if job is None:
            raise LifecycleError("job_not_found")
        unit = next((u for u in job.work_units if u.work_unit_id == unit_id), None)
        if unit is None:
            raise LifecycleError("unit_not_found")
        get_unit_manifest = getattr(self.repository, "get_artifact_manifest", None)
        if callable(get_unit_manifest):
            # Unit IDs are the artifact table's primary key. Revalidating one
            # file permit must not decode every Unit in a large campaign.
            exact = get_unit_manifest(unit_id)
            manifests = [exact] if exact is not None and exact.work_unit_id == unit_id else []
        else:
            manifests = [m for m in self.repository.list_artifact_manifests(job_id)
                         if m.work_unit_id == unit_id]
        if len(manifests) != 1:
            raise LifecycleError("verified_manifest_unavailable")
        manifest = manifests[0]
        inventory_payload(manifest.files)
        attempt = next((a for a in unit.attempts if a.attempt_id == attempt_id), None)
        if manifest.job_id != job_id or attempt is None or attempt.state != "completed":
            raise LifecycleError("producer_binding_mismatch")
        if require_custody:
            if (manifest.producer.get("attempt_id") != attempt_id or not attempt.external_run_id
                or attempt.collected_at is None):
                raise LifecycleError("producer_binding_mismatch")
            external = manifest.producer.get("external_run_id")
            if external is not None and external != attempt.external_run_id:
                raise LifecycleError("producer_binding_mismatch")
        return job, manifest, attempt

    def _root(self):
        root = self.center_root
        if self.validate_center is not None:
            root = Path(self.validate_center()).absolute()
        if root != self.center_root:
            raise LifecycleError("center_binding_changed")
        managed_path(root, ".lifecycle-check")
        return root

    def _directory(self, job, unit_id, attempt_id):
        return managed_path(self._root(), identifier(job.origin_submitter_id), "incoming",
                            identifier(job.job_id), identifier(unit_id), identifier(attempt_id))

    def _matches(self, receipt, job, manifest, attempt):
        return (receipt.project_id == job.project_id and receipt.job_id == job.job_id
                and receipt.request_hash == job.request_hash
                and receipt.work_unit_id == manifest.work_unit_id
                and receipt.producer_attempt_id == attempt.attempt_id
                and receipt.producer_external_id == attempt.external_run_id
                and receipt.manifest_sha256 == sha256_value(manifest.model_dump(mode="json"))
                and inventory_payload(receipt.files) == inventory_payload(manifest.files))

    def register_policy(self, policy: ProjectCustodyPolicy, *, actor_id: str):
        if self.repository.get_project_grant(policy.project_id) is None:
            raise LifecycleError("project_unregistered")
        with self._transaction() as db:
            db.execute("INSERT INTO storage_lifecycle_policies VALUES(?,?,?,?) "
                       "ON CONFLICT(project_id) DO UPDATE SET payload=excluded.payload, "
                       "updated_at=excluded.updated_at, actor_id=excluded.actor_id",
                       (policy.project_id, self._json(policy.model_dump(mode="json")), _now(), actor_id))
            self._audit(db, "storage.policy_registered", actor_id, policy.project_id,
                        policy=policy.model_dump(mode="json"))
        return policy

    def get_policy(self, project_id):
        with self._connect() as db:
            row = db.execute("SELECT payload FROM storage_lifecycle_policies WHERE project_id=?",
                             (project_id,)).fetchone()
        return ProjectCustodyPolicy.model_validate_json(row[0]) if row else None

    def record_receipt(self, receipt: UnitCustodyReceipt, *, actor_id: str):
        if receipt.verified_by != actor_id:
            raise LifecycleError("authenticated_adapter_actor_mismatch")
        if inventory_sha256(receipt.files) != receipt.inventory_sha256:
            raise LifecycleError("inventory_digest_mismatch")
        payload = receipt.model_dump(mode="json")
        fingerprint = sha256_value(payload)
        # An acknowledged immutable receipt remains acknowledged when a store
        # is offline. A retry never renews or changes its physical-byte proof.
        with self._connect() as db:
            existing = db.execute("SELECT * FROM storage_lifecycle_receipts WHERE idempotency_key=?",
                                  (receipt.idempotency_key,)).fetchone()
            if existing:
                if existing["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                return {"receipt_id": existing["receipt_id"], "receipt": json.loads(existing["payload"]),
                        "revoked": existing["revoked_at"] is not None, "already_present": True}
        # Probe registered center storage before accepting a receipt against its
        # current manifest. This does not read or pretend to verify origin bytes.
        self._root()
        job, manifest, attempt = self._binding(receipt.job_id, receipt.work_unit_id,
                                              receipt.producer_attempt_id)
        grant = self.repository.get_project_grant(job.project_id)
        actors = {job.user_id}
        if grant is not None:
            actors.update({grant.owner_user_id, *grant.authorized_user_ids})
        if receipt.verified_by != actor_id or actor_id not in actors:
            raise LifecycleError("authenticated_adapter_actor_mismatch")
        with self._connect() as db:
            adapter_id = db.execute("SELECT json_extract(payload, '$.origin_adapter_id') "
                                    "FROM jobs WHERE job_id=?", (job.job_id,)).fetchone()[0] or "workbench"
        adapter = self.repository.get_origin_adapter(receipt.adapter_id)
        if (receipt.adapter_id != adapter_id or adapter is None or not adapter.active
            or receipt.adapter_version != adapter.version
            or job.execution_profile_id not in adapter.allowed_profile_ids):
            raise LifecycleError("origin_adapter_binding_mismatch")
        if not self._matches(receipt, job, manifest, attempt):
            raise LifecycleError("custody_binding_mismatch")
        receipt_id = "custody-" + sha256_value(receipt.idempotency_key)[:32]
        with self._transaction() as db:
            row = db.execute("SELECT * FROM storage_lifecycle_receipts WHERE idempotency_key=?",
                             (receipt.idempotency_key,)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                return {"receipt_id": row["receipt_id"], "receipt": json.loads(row["payload"]),
                        "revoked": row["revoked_at"] is not None, "already_present": True}
            current_job, current_manifest, current_attempt = self._binding(
                receipt.job_id, receipt.work_unit_id, receipt.producer_attempt_id)
            if not self._matches(receipt, current_job, current_manifest, current_attempt):
                raise LifecycleError("custody_binding_mismatch")
            db.execute("INSERT INTO storage_lifecycle_receipts"
                       "(receipt_id,idempotency_key,job_id,unit_id,attempt_id,fingerprint,payload,recorded_at) "
                       "VALUES(?,?,?,?,?,?,?,?)", (receipt_id, receipt.idempotency_key, job.job_id,
                       manifest.work_unit_id, attempt.attempt_id, fingerprint, self._json(payload), _now()))
            self._audit(db, "storage.custody_recorded", actor_id, receipt_id,
                        job_id=job.job_id, work_unit_id=manifest.work_unit_id,
                        evidence_kind="authenticated_origin_adapter_assertion",
                        manifest_sha256=receipt.manifest_sha256,
                        inventory_sha256=receipt.inventory_sha256)
        return {"receipt_id": receipt_id, "receipt": payload, "revoked": False,
                "already_present": False}

    def revoke_receipt(self, receipt_id, *, actor_id: str, reason: str):
        if not reason.strip():
            raise LifecycleError("reason_required")
        with self._transaction() as db:
            row = db.execute("SELECT revoked_at FROM storage_lifecycle_receipts WHERE receipt_id=?",
                             (receipt_id,)).fetchone()
            if row is None:
                raise LifecycleError("receipt_not_found")
            if row[0] is None:
                db.execute("UPDATE storage_lifecycle_receipts SET revoked_at=?,revoked_by=?,revoke_reason=? "
                           "WHERE receipt_id=?", (_now(), actor_id, reason, receipt_id))
                self._audit(db, "storage.custody_revoked", actor_id, receipt_id, reason=reason)

    def list_receipts(self, job_id, unit_id, attempt_id):
        with self._connect() as db:
            return [{"receipt_id": r["receipt_id"], "receipt": json.loads(r["payload"]),
                     "revoked": r["revoked_at"] is not None}
                    for r in db.execute("SELECT * FROM storage_lifecycle_receipts "
                        "WHERE job_id=? AND unit_id=? AND attempt_id=? ORDER BY recorded_at, receipt_id",
                        (job_id, unit_id, attempt_id))]

    @staticmethod
    def _protected(path, policy):
        name = Path(path).name.casefold()
        # Runtime evidence stays physically present; all original manifest and
        # producer metadata also remains in the DB intent even after retirement.
        return (path.casefold() in {p.casefold() for p in policy.protected_relative_paths}
                or name in {"artifact-manifest.json", "manifest.json", "provenance.json",
                    "request.json", "descriptor.json", "status.json", "environment.json",
                    "run.json", "solver-receipt.json"}
                or name.endswith((".log", ".manifest.json", ".provenance.json")))

    def _evidence(self, db, job, manifest, attempt, *, receipt_ids=None):
        row = db.execute("SELECT payload FROM storage_lifecycle_policies WHERE project_id=?",
                         (job.project_id,)).fetchone()
        if not row:
            raise LifecycleError("project_policy_unregistered")
        policy = ProjectCustodyPolicy.model_validate_json(row[0])
        if not policy.automatic_retirement:
            raise LifecycleError("automatic_retirement_disabled")
        if self.center_binding is None:
            raise LifecycleError("center_identity_unregistered")
        rows = db.execute("SELECT * FROM storage_lifecycle_receipts "
                          "WHERE job_id=? AND unit_id=? AND attempt_id=? AND revoked_at IS NULL",
                          (job.job_id, manifest.work_unit_id, attempt.attempt_id)).fetchall()
        valid, devices = [], set()
        for row in rows:
            if receipt_ids is not None and row["receipt_id"] not in receipt_ids:
                continue
            receipt = UnitCustodyReceipt.model_validate_json(row["payload"])
            if self._matches(receipt, job, manifest, attempt):
                valid.append(row["receipt_id"])
                device = receipt.target.physical_key()
                if device != self.center_binding.physical_key():
                    devices.add(device)
        if receipt_ids is not None and set(valid) != set(receipt_ids):
            raise LifecycleError("custody_evidence_revoked_or_changed")
        if len(devices) < policy.required_independent_copies:
            raise LifecycleError("independent_copies_missing")
        return policy, valid, len(devices)

    def preview_retirement(self, job_id, unit_id, attempt_id):
        try:
            job, manifest, attempt = self._binding(job_id, unit_id, attempt_id)
            self._root()
            with self._connect() as db:
                if db.execute("SELECT 1 FROM storage_lifecycle_intents WHERE job_id=? AND unit_id=? AND attempt_id=? "
                              "AND (operation_kind='solved_model' OR operation_kind LIKE 'solved_model:%' OR operation_kind LIKE 'solved_model_origin:%' "
                              "OR operation_kind LIKE 'solved_model_worker:%' OR operation_kind LIKE 'origin_duplicate:%')", (job_id, unit_id, attempt_id)).fetchone():
                    # Legacy custody still describes the immutable full
                    # inventory. It cannot authorize a new science-copy exit
                    # after a partial model retirement changed physical bytes.
                    raise LifecycleError("scientific_inventory_requires_separate_relay_policy")
                policy, receipts, copies = self._evidence(db, job, manifest, attempt)
                readers = db.execute("SELECT COUNT(*) FROM storage_lifecycle_readers "
                                     "WHERE job_id=? AND unit_id=? AND attempt_id=?",
                                     (job_id, unit_id, attempt_id)).fetchone()[0]
                if readers:
                    raise LifecycleError("live_readers")
            files = [f for f in inventory_payload(manifest.files)
                     if not self._protected(f["relative_path"], policy)]
            if not files:
                raise LifecycleError("no_retirable_files")
            return {"eligible": True, "reason_code": "custody_policy_satisfied",
                    "job_id": job_id, "work_unit_id": unit_id, "producer_attempt_id": attempt_id,
                    "manifest_sha256": sha256_value(manifest.model_dump(mode="json")),
                    "inventory_sha256": inventory_sha256(manifest.files), "files": files,
                    "receipt_ids": receipts, "independent_copies": copies,
                    "size_bytes": sum(f["size_bytes"] for f in files)}
        except (LifecycleError, OSError, ValueError) as exc:
            return {"eligible": False, "reason_code": getattr(exc, "reason_code", "storage_unavailable"),
                    "job_id": job_id, "work_unit_id": unit_id, "producer_attempt_id": attempt_id}

    def create_retirement(self, job_id, unit_id, attempt_id, *, idempotency_key, actor_id,
                          verify_sources=True):
        identifier(idempotency_key)
        operation = {"job_id": job_id, "work_unit_id": unit_id, "producer_attempt_id": attempt_id}
        fingerprint = sha256_value(operation)
        with self._connect() as db:
            row = db.execute("SELECT * FROM storage_lifecycle_intents WHERE idempotency_key=?",
                             (idempotency_key,)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                return self.get_intent(row["intent_id"])
        candidate = self.preview_retirement(job_id, unit_id, attempt_id)
        if not candidate["eligible"]:
            raise LifecycleError(candidate["reason_code"])
        job, manifest, attempt = self._binding(job_id, unit_id, attempt_id)
        identities = {}
        if verify_sources:
            directory = self._directory(job, unit_id, attempt_id)
            for record in candidate["files"]:
                path = managed_path(directory, record["relative_path"])
                before = self._file_identity(path)
                self._verify_source(path, record)
                if self._file_identity(path) != before:
                    raise LifecycleError("source_file_changed")
                identities[record["relative_path"]] = before
        payload = {**candidate, "original_manifest": manifest.model_dump(mode="json"),
                   "center_binding": self.center_binding.model_dump(mode="json"),
                   "file_identities": identities}
        intent_id = "retire-" + sha256_value(idempotency_key)[:32]
        # FULL commit is the durable authorization boundary before any unlink.
        with self._transaction() as db:
            current_job, current_manifest, current_attempt = self._binding(job_id, unit_id, attempt_id)
            if (sha256_value(current_manifest.model_dump(mode="json")) != candidate["manifest_sha256"]
                or current_job.request_hash != job.request_hash
                or current_attempt.external_run_id != attempt.external_run_id):
                raise LifecycleError("retirement_binding_changed")
            self._evidence(db, job, manifest, attempt, receipt_ids=candidate["receipt_ids"])
            if db.execute("SELECT 1 FROM storage_lifecycle_readers WHERE job_id=? AND unit_id=? "
                          "AND attempt_id=?", (job_id, unit_id, attempt_id)).fetchone():
                raise LifecycleError("live_readers")
            existing = db.execute("SELECT * FROM storage_lifecycle_intents WHERE idempotency_key=?",
                                  (idempotency_key,)).fetchone()
            if existing:
                if existing["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                intent_id = existing["intent_id"]
            else:
                previous = db.execute("SELECT intent_id FROM storage_lifecycle_intents WHERE job_id=? "
                    "AND unit_id=? AND attempt_id=? AND operation_kind='relay_copy'", (job_id, unit_id, attempt_id)).fetchone()
                if previous:
                    raise LifecycleError("retirement_already_has_original_key")
                db.execute("INSERT INTO storage_lifecycle_intents"
                    "(intent_id,idempotency_key,job_id,unit_id,attempt_id,fingerprint,payload,state,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?)", (intent_id, idempotency_key, job_id, unit_id, attempt_id,
                    fingerprint, self._json(payload), "pending", _now()))
                for record in candidate["files"]:
                    db.execute("INSERT INTO storage_lifecycle_deletions VALUES(?,?,?,?)",
                               (intent_id, record["relative_path"], "pending", _now()))
                self._audit(db, "storage.retirement_intent_committed", actor_id, intent_id,
                    **operation, manifest_sha256=candidate["manifest_sha256"], files=candidate["files"])
        return self.get_intent(intent_id)

    @staticmethod
    def _file_identity(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise LifecycleError("managed_file_not_regular")
        return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]

    @staticmethod
    def _check_stop(stop_event):
        if stop_event is not None and stop_event.is_set():
            raise LifecycleError("gc_stop_requested")

    @classmethod
    def _verify_source(cls, path, record, *, stop_event=None):
        """Read every actual byte, with cancellation between bounded chunks."""
        cls._check_stop(stop_event)
        if not path.is_file() or path.stat().st_size != record["size_bytes"]:
            raise LifecycleError("source_file_integrity_failed")
        checksum, received = hashlib.sha256(), 0
        with path.open("rb") as stream:
            while True:
                cls._check_stop(stop_event)
                chunk = stream.read(CHUNK_BYTES)
                cls._check_stop(stop_event)
                if not chunk:
                    break
                received += len(chunk)
                if received > record["size_bytes"]:
                    raise LifecycleError("source_file_integrity_failed")
                checksum.update(chunk)
        if received != record["size_bytes"] or checksum.hexdigest() != record["sha256"]:
            raise LifecycleError("source_file_integrity_failed")

    def _reconcile_dead_writer(self, db, permit):
        if permit["process_host"] != self.process_host or self._process_alive(
            permit["process_id"], permit["process_started"]):
            return False
        db.execute("DELETE FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=? "
                   "AND owner_token=?", (permit["intent_id"], permit["relative_path"], permit["owner_token"]))
        self._audit(db, "storage.dead_writer_reconciled", "storage-gc", permit["intent_id"],
                    relative_path=permit["relative_path"], process_id=permit["process_id"],
                    process_started=permit["process_started"])
        return True

    def reconcile_dead_writer_permits(self):
        released = 0
        with self._transaction() as db:
            rows = db.execute("SELECT * FROM storage_lifecycle_writer_permits WHERE process_host=?",
                              (self.process_host,)).fetchall()
            for permit in rows:
                released += self._reconcile_dead_writer(db, permit)
        return released

    def _claim_writer_permit(self, db, intent_id, relative_path):
        current = db.execute("SELECT job_id,unit_id,attempt_id FROM storage_lifecycle_intents WHERE intent_id=?",
                             (intent_id,)).fetchone()
        if current is None:
            raise LifecycleError("intent_not_found")
        others = db.execute("SELECT p.* FROM storage_lifecycle_writer_permits p JOIN storage_lifecycle_intents i "
            "ON i.intent_id=p.intent_id WHERE i.job_id=? AND i.unit_id=? AND i.attempt_id=? "
            "AND p.relative_path=? AND p.intent_id<>?", (*current, relative_path, intent_id)).fetchall()
        for other in others:
            if not self._reconcile_dead_writer(db, other):
                raise LifecycleError("file_retirement_in_progress")
        permit = db.execute("SELECT * FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=?",
                            (intent_id, relative_path)).fetchone()
        if permit is not None and not self._reconcile_dead_writer(db, permit):
            raise LifecycleError("file_retirement_in_progress")
        token = uuid.uuid4().hex
        db.execute("INSERT INTO storage_lifecycle_writer_permits VALUES(?,?,?,?,?,?,?)",
            (intent_id, relative_path, token, self.process_host, os.getpid(), self.process_started, _now()))
        return token

    def _release_writer_permit(self, intent_id, relative_path, token):
        with self._transaction() as db:
            db.execute("DELETE FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=? "
                       "AND owner_token=?", (intent_id, relative_path, token))

    def get_intent(self, intent_id):
        with self._connect() as db:
            row = db.execute("SELECT * FROM storage_lifecycle_intents WHERE intent_id=?",
                             (intent_id,)).fetchone()
            if row is None:
                raise LifecycleError("intent_not_found")
            results = {r["relative_path"]: r["state"] for r in db.execute(
                "SELECT * FROM storage_lifecycle_deletions WHERE intent_id=?", (intent_id,))}
        return {"intent_id": intent_id, "idempotency_key": row["idempotency_key"],
                "operation_kind": ("solved_model" if row["operation_kind"].startswith("solved_model:") else row["operation_kind"]),
                "state": row["state"], "last_reason": row["last_reason"],
                "candidate": json.loads(row["payload"]), "files": results}

    def _check_intent(self, db, payload):
        if payload.get("operation_kind") == "solved_model":
            return self.scientific.check_intent(db, payload)
        if db.execute("SELECT 1 FROM storage_lifecycle_intents WHERE job_id=? AND unit_id=? AND attempt_id=? "
                      "AND (operation_kind='solved_model' OR operation_kind LIKE 'solved_model:%' OR operation_kind LIKE 'solved_model_origin:%' "
                      "OR operation_kind LIKE 'solved_model_worker:%' OR operation_kind LIKE 'origin_duplicate:%')", (payload["job_id"], payload["work_unit_id"],
                      payload["producer_attempt_id"])).fetchone():
            raise LifecycleError("scientific_inventory_requires_separate_relay_policy")
        job, manifest, attempt = self._binding(payload["job_id"], payload["work_unit_id"],
                                              payload["producer_attempt_id"])
        if (sha256_value(manifest.model_dump(mode="json")) != payload["manifest_sha256"]
            or self.center_binding is None
            or self.center_binding.model_dump(mode="json") != payload["center_binding"]):
            raise LifecycleError("retirement_binding_changed")
        policy, _, _ = self._evidence(db, job, manifest, attempt, receipt_ids=payload["receipt_ids"])
        if any(self._protected(f["relative_path"], policy) for f in payload["files"]):
            raise LifecycleError("retirement_policy_changed")
        if db.execute("SELECT 1 FROM storage_lifecycle_readers WHERE job_id=? AND unit_id=? "
                      "AND attempt_id=?", (job.job_id, manifest.work_unit_id, attempt.attempt_id)).fetchone():
            raise LifecycleError("live_readers")
        return job

    def run_retirement(self, intent_id, *, max_files=16, actor_id="storage-gc", stop_event=None):
        if not 1 <= max_files <= 1024:
            raise ValueError("max_files must be between 1 and 1024")
        intent = self.get_intent(intent_id)
        if intent["candidate"].get("operation_kind") in {"solved_model_origin", "solved_model_worker", "origin_duplicate", "derived_dependency_input"}:
            raise LifecycleError("origin_adapter_execution_required")
        if intent["state"] == "completed":
            return intent
        payload = intent["candidate"]
        selected = [f for f in payload["files"] if intent["files"][f["relative_path"]] == "pending"][:max_files]
        try:
            for record in selected:
                if self.validate_retirement is not None:
                    self.validate_retirement()
                self._check_stop(stop_event)
                # Hash outside the global SQLite writer lock. An exact writer
                # permit closes the reader gate throughout the later syscall.
                with self._connect() as db:
                    job = self._check_intent(db, payload)
                directory = self._directory(job, payload["work_unit_id"], payload["producer_attempt_id"])
                path = managed_path(directory, record["relative_path"])
                identity = None
                if path.exists():
                    before = self._file_identity(path)
                    expected_identity = payload.get("file_identities", {}).get(record["relative_path"])
                    if expected_identity is not None and before != expected_identity:
                        raise LifecycleError("source_file_changed")
                    self._verify_source(path, record, stop_event=stop_event)
                    identity = self._file_identity(path)
                    if identity != before:
                        raise LifecycleError("source_file_changed")
                else:
                    # Only a previously FULL-committed exact-file syscall
                    # authorization explains a crash between unlink and its
                    # result commit. A new unexplained absence is corruption,
                    # not evidence that this policy retired the source.
                    with self._connect() as db:
                        authorized = db.execute("SELECT event_type FROM storage_lifecycle_audit WHERE subject_id=? "
                            "AND event_type IN ('storage.file_retirement_authorized','storage.file_authorization_aborted') "
                            "AND json_extract(details,'$.relative_path')=? ORDER BY sequence DESC LIMIT 1",
                            (intent_id, record["relative_path"])).fetchone()
                    if authorized is None or authorized[0] != "storage.file_retirement_authorized":
                        raise LifecycleError("source_file_unexpectedly_missing")
                # Physical USB probes stay outside the global DB writer lock.
                current = managed_path(self._directory(job, payload["work_unit_id"],
                    payload["producer_attempt_id"]), record["relative_path"])
                self._check_stop(stop_event)
                if self.validate_retirement is not None:
                    self.validate_retirement()
                with self._transaction() as db:
                    self._check_intent(db, payload)
                    saved = db.execute("SELECT state FROM storage_lifecycle_deletions WHERE intent_id=? "
                        "AND relative_path=?", (intent_id, record["relative_path"])).fetchone()[0]
                    if saved != "pending":
                        continue
                    token = self._claim_writer_permit(db, intent_id, record["relative_path"])
                    self._audit(db, "storage.file_retirement_authorized", actor_id, intent_id,
                                relative_path=record["relative_path"], size_bytes=record["size_bytes"],
                                sha256=record["sha256"], owner_token=token)
                # FULL authorization and its exact-file writer permit are now
                # durable. Revocation stops new permits and permits recovery
                # readers only after this owned syscall has finished. USB IO
                # never holds the control-plane SQLite writer transaction.
                syscall_started, completed = False, False
                try:
                    self._check_stop(stop_event)
                    if self.validate_retirement is not None:
                        self.validate_retirement()
                    if identity is not None:
                        if self._file_identity(current) != identity:
                            raise LifecycleError("source_file_changed")
                        syscall_started = True
                        current.unlink()
                        result = "deleted"
                    elif current.exists():
                        raise LifecycleError("source_file_changed")
                    else:
                        result = "already_absent"
                    with self._transaction() as db:
                        db.execute("UPDATE storage_lifecycle_deletions SET state=?,updated_at=? "
                            "WHERE intent_id=? AND relative_path=?", (result, _now(), intent_id, record["relative_path"]))
                        self._audit(db, "storage.file_retired", actor_id, intent_id,
                                    relative_path=record["relative_path"], result=result,
                                    size_bytes=record["size_bytes"], sha256=record["sha256"])
                    completed = True
                finally:
                    # A killed process skips finally; only its exact exited
                    # incarnation may have this persisted permit reconciled.
                    if not syscall_started and not completed:
                        with self._transaction() as db:
                            self._audit(db, "storage.file_authorization_aborted", actor_id, intent_id,
                                        relative_path=record["relative_path"], owner_token=token,
                                        reason="known_abort_before_unlink")
                    self._release_writer_permit(intent_id, record["relative_path"], token)
            with self._transaction() as db:
                pending = db.execute("SELECT 1 FROM storage_lifecycle_deletions WHERE intent_id=? "
                                     "AND state='pending' LIMIT 1", (intent_id,)).fetchone()
                db.execute("UPDATE storage_lifecycle_intents SET state=?,completed_at=?,last_reason=NULL "
                    "WHERE intent_id=?", ("pending" if pending else "completed", None if pending else _now(), intent_id))
        except (OSError, ValueError) as exc:
            reason = getattr(exc, "reason_code", "storage_unavailable_or_integrity_failed")
            with self._transaction() as db:
                db.execute("UPDATE storage_lifecycle_intents SET last_reason=? WHERE intent_id=?", (reason, intent_id))
        return self.get_intent(intent_id)

    def pin_reader(self, job_id, unit_id, attempt_id, relative_path):
        portable_parts(relative_path)
        self._root()
        job, manifest, attempt = self._binding(job_id, unit_id, attempt_id, require_custody=False)
        if relative_path not in {f.relative_path for f in manifest.files}:
            raise LifecycleError("file_not_in_manifest")
        pin_id = "reader-" + uuid.uuid4().hex
        with self._transaction() as db:
            permits = db.execute("SELECT p.* FROM storage_lifecycle_writer_permits p "
                "JOIN storage_lifecycle_intents i ON i.intent_id=p.intent_id "
                "WHERE i.job_id=? AND i.unit_id=? AND i.attempt_id=? AND p.relative_path=?",
                (job_id, unit_id, attempt_id, relative_path)).fetchall()
            for permit in permits:
                if not self._reconcile_dead_writer(db, permit):
                    raise LifecycleError("file_retirement_in_progress")
            rows = db.execute("SELECT payload FROM storage_lifecycle_intents WHERE job_id=? "
                              "AND unit_id=? AND attempt_id=?", (job_id, unit_id, attempt_id)).fetchall()
            for row in rows:
                payload = json.loads(row[0])
                # Origin-owned retirement cannot delete this center directory.
                # Its active permits are still checked above to serialize reads.
                if payload.get("operation_kind") in {"solved_model_origin", "solved_model_worker", "origin_duplicate", "derived_dependency_input"}:
                    continue
                if payload.get("operation_kind") == "solved_model":
                    self.scientific.reader_gate(db, payload, relative_path)
                    continue
                if relative_path not in {f["relative_path"] for f in payload["files"]}:
                    continue
                # Revoked/missing custody must not trap the remaining recovery
                # copy behind an old intent. Pinning and authorization serialize;
                # a restored policy cannot delete while this pin is held.
                try:
                    policy, _, _ = self._evidence(db, job, manifest, attempt,
                                                receipt_ids=payload["receipt_ids"])
                except LifecycleError as exc:
                    if exc.reason_code not in {"project_policy_unregistered", "automatic_retirement_disabled",
                        "custody_evidence_revoked_or_changed", "independent_copies_missing"}:
                        raise
                else:
                    if not self._protected(relative_path, policy):
                        raise LifecycleError("result_retirement_pending_or_completed")
            db.execute("INSERT INTO storage_lifecycle_readers VALUES(?,?,?,?,?,?,?,?,?)",
                (pin_id, job_id, unit_id, attempt_id, relative_path, self.process_host,
                 os.getpid(), self.process_started, _now()))
        return ReaderPin(self, pin_id)

    def release_reader(self, pin_id):
        with self._transaction() as db:
            db.execute("DELETE FROM storage_lifecycle_readers WHERE pin_id=?", (pin_id,))

    def reconcile_dead_readers(self):
        """Release only same-host pins whose exact process incarnation exited."""
        released = 0
        with self._transaction() as db:
            for row in db.execute("SELECT * FROM storage_lifecycle_readers WHERE process_host=?",
                                  (self.process_host,)).fetchall():
                try:
                    alive = psutil.Process(row["process_id"]).create_time() == row["process_started"]
                except psutil.NoSuchProcess:
                    alive = False
                except psutil.AccessDenied:
                    continue
                if not alive:
                    db.execute("DELETE FROM storage_lifecycle_readers WHERE pin_id=?", (row["pin_id"],))
                    self._audit(db, "storage.dead_reader_reconciled", "storage-gc", row["pin_id"],
                                process_id=row["process_id"], process_started=row["process_started"])
                    released += 1
        return released

    def state(self, job_id, unit_id, attempt_id):
        job, manifest, _ = self._binding(job_id, unit_id, attempt_id, require_custody=False)
        with self._connect() as db:
            row = db.execute("SELECT intent_id,state FROM storage_lifecycle_intents WHERE job_id=? "
                "AND unit_id=? AND attempt_id=? AND operation_kind='relay_copy'", (job_id, unit_id, attempt_id)).fetchone()
        status = "available"
        if row is not None:
            status = "retired_with_restore_ref" if row["state"] == "completed" else "retirement_pending"
        else:
            try:
                directory = self._directory(job, unit_id, attempt_id)
                if not all(managed_path(directory, f.relative_path).is_file()
                           and managed_path(directory, f.relative_path).stat().st_size == f.size_bytes
                           for f in manifest.files):
                    status = "temporarily_unavailable"
            except (OSError, ValueError):
                status = "temporarily_unavailable"
        receipts = self.list_receipts(job_id, unit_id, attempt_id)
        scientific = self.scientific.state(job_id, unit_id, attempt_id)
        if row is None and status == "temporarily_unavailable":
            retired = {name for intent in scientific["model_retirements"]
                       if intent["candidate"].get("operation_kind") == "solved_model"
                       for name, result in intent["files"].items() if result in {"deleted", "already_absent"}}
            if retired:
                try:
                    directory = self._directory(job, unit_id, attempt_id)
                    remaining = [f for f in manifest.files if f.relative_path not in retired]
                    if all(managed_path(directory, f.relative_path).is_file()
                           and managed_path(directory, f.relative_path).stat().st_size == f.size_bytes for f in remaining):
                        status = "models_retired_scientific_exports_available"
                except (OSError, ValueError):
                    pass
        return {"state": status, "bytes_available": status == "available", "custody_receipts": receipts,
                "restore_refs": [r["receipt"]["restore_ref"] for r in receipts if not r["revoked"]],
                "intent_id": row["intent_id"] if row else None,
                "scientific_retention": scientific}

    def run_gc_batch(self, *, max_units=4, max_files=16, stop_event=None):
        """Finite automatic work; callers schedule this off the dispatcher loop."""
        if not 1 <= max_units <= 64 or not 1 <= max_files <= 1024:
            raise ValueError("GC batch limits are outside the supported bounds")
        if stop_event is not None and stop_event.is_set():
            return [{"eligible": False, "reason_code": "gc_stop_requested"}]
        with self._gc_gate() as acquired:
            if not acquired:
                return [{"eligible": False, "reason_code": "gc_already_running"}]
            models = self.scientific.run_gc_batch(max_units=max_units, max_files=max_files, stop_event=stop_event)
            # Each loop is independently finite. Scientific data-copy GC keeps
            # its original surviving-device policy and authorization path.
            return models + self._run_gc_batch(max_units=max_units, max_files=max_files, stop_event=stop_event)

    @staticmethod
    def _process_alive(process_id, process_started):
        try:
            return psutil.Process(process_id).create_time() == process_started
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            return True

    @contextmanager
    def _gc_gate(self):
        token = uuid.uuid4().hex
        acquired = False
        with self._transaction() as db:
            previous = db.execute("SELECT * FROM storage_lifecycle_gc_gate WHERE lock_key='automatic-gc'").fetchone()
            if previous is not None and (previous["process_host"] != self.process_host
                or self._process_alive(previous["process_id"], previous["process_started"])):
                pass
            else:
                db.execute("INSERT INTO storage_lifecycle_gc_gate VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(lock_key) DO UPDATE SET owner_token=excluded.owner_token, "
                    "process_host=excluded.process_host,process_id=excluded.process_id, "
                    "process_started=excluded.process_started,acquired_at=excluded.acquired_at",
                    ("automatic-gc", token, self.process_host, os.getpid(), self.process_started, _now()))
                acquired = True
        try:
            yield acquired
        finally:
            if acquired:
                with self._transaction() as db:
                    db.execute("DELETE FROM storage_lifecycle_gc_gate WHERE lock_key='automatic-gc' AND owner_token=?", (token,))

    def _run_gc_batch(self, *, max_units, max_files, stop_event=None):
        self.reconcile_dead_readers()
        self.reconcile_dead_writer_permits()
        with self._connect() as db:
            # Persist fair scan progress: a missing policy or permanently
            # revoked pending intent must not starve other intact Units.
            units = db.execute("WITH candidates AS ("
                "SELECT job_id,unit_id,attempt_id,intent_id,created_at AS observed_at "
                "FROM storage_lifecycle_intents WHERE state='pending' AND operation_kind='relay_copy' UNION ALL "
                "SELECT r.job_id,r.unit_id,r.attempt_id,NULL,MIN(r.recorded_at) "
                "FROM storage_lifecycle_receipts r LEFT JOIN storage_lifecycle_intents i "
                "ON i.job_id=r.job_id AND i.unit_id=r.unit_id AND i.attempt_id=r.attempt_id AND i.operation_kind='relay_copy' "
                "WHERE r.revoked_at IS NULL AND i.intent_id IS NULL GROUP BY r.job_id,r.unit_id,r.attempt_id) "
                "SELECT u.job_id,u.unit_id,u.attempt_id,u.intent_id FROM candidates u "
                "LEFT JOIN storage_lifecycle_gc_checks c ON c.job_id=u.job_id AND c.unit_id=u.unit_id "
                "AND c.attempt_id=u.attempt_id ORDER BY COALESCE(c.checked_at,''),u.observed_at LIMIT ?",
                (max_units,)).fetchall()
        results, remaining = [], max_files
        for row in units:
            if remaining <= 0:
                break
            if stop_event is not None and stop_event.is_set():
                results.append({"eligible": False, "reason_code": "gc_stop_requested"})
                break
            with self._transaction() as db:
                db.execute("INSERT INTO storage_lifecycle_gc_checks VALUES(?,?,?,?) "
                    "ON CONFLICT(job_id,unit_id,attempt_id) DO UPDATE SET checked_at=excluded.checked_at",
                    (*row[:3], _now()))
            try:
                if row["intent_id"] is not None:
                    intent = self.get_intent(row["intent_id"])
                else:
                    candidate = self.preview_retirement(*row[:3])
                    if not candidate["eligible"]:
                        results.append(candidate)
                        continue
                    key = "automatic-" + sha256_value(list(row[:3]))[:32]
                    intent = self.create_retirement(*row[:3], idempotency_key=key, actor_id="storage-gc",
                                                    verify_sources=False)
                scheduled = min(remaining, sum(s == "pending" for s in intent["files"].values()))
                results.append(self.run_retirement(intent["intent_id"], max_files=max(1, scheduled),
                                                   stop_event=stop_event))
                remaining -= scheduled
            except (OSError, ValueError) as exc:
                results.append({"eligible": False, "reason_code": getattr(exc, "reason_code", "storage_unavailable")})
        return results
