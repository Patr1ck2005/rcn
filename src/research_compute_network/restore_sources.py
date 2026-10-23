"""Fixed, local restore locations bound to existing immutable custody evidence.

Only trusted adapters register paths. Network callers supply the original result
identity, never a path or URL. Metadata lives in the original lifecycle database.
"""
from __future__ import annotations

import json
import errno
import os
import sqlite3
import uuid
from pathlib import Path
from contextlib import closing

from .origin_transfer import managed_path, portable_parts
from .storage_lifecycle import CustodyLocation, LifecycleError
from .storage_roots import StorageRootError, current_host_id, probe_volume_identity, reject_reparse_path


def source_unavailable(exc):
    """Only missing/offline bytes may choose another registered copy."""
    if isinstance(exc, PermissionError) or isinstance(exc.__cause__, PermissionError):
        return False
    return (isinstance(exc, OSError) and (exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.ENODEV, errno.ENXIO}
            or getattr(exc, "winerror", None) in {2, 3, 21, 55, 1167})) or (
        isinstance(exc, StorageRootError) and exc.reason_code in {"storage_root_unavailable", "storage_volume_unavailable"})


def requester_sources_from_existing_home():
    """Resolve only an already registered local source at explicit download time.

    Status/browser reads never call this. Do not create a database just because a
    member client is installed; an origin adapter must already have registered it.
    """
    from .paths import ControlPlanePaths, default_rcn_home
    database = default_rcn_home() / "control-plane.db"
    if not database.is_file():
        return None
    with closing(sqlite3.connect(database.as_uri()+"?mode=ro", uri=True)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='storage_restore_stores'").fetchone():
            return None
        if not db.execute("SELECT 1 FROM storage_restore_stores WHERE active=1 AND json_extract(payload,'$.kind')='requester_local' LIMIT 1").fetchone():
            return None
    from .repository import MetadataRepository
    from .storage_lifecycle import StorageLifecycle
    paths = ControlPlanePaths.from_root(database.parent)
    lifecycle = StorageLifecycle(MetadataRepository("sqlite:///"+database.as_posix()), paths.origin_spool)
    return RegisteredResultSources(lifecycle, allowed_kind="requester_local")


class RestorePin:
    def __init__(self, sources, token):
        self.sources, self.token = sources, token

    def release(self):
        with self.sources.lifecycle._transaction() as db:
            db.execute("DELETE FROM storage_restore_readers WHERE token=?", (self.token,))


class RegisteredResultSources:
    def __init__(self, lifecycle, *, allowed_kind="wkr_archive", host_id=None, probe=None):
        if allowed_kind not in {"wkr_archive", "requester_local"}:
            raise ValueError("unsupported restore source kind")
        self.lifecycle = lifecycle
        self.allowed_kind = allowed_kind
        self.host_id = (host_id or current_host_id()).casefold()
        self.probe = probe or probe_volume_identity
        with lifecycle._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS storage_restore_stores (
                  store_id TEXT PRIMARY KEY, generation TEXT NOT NULL, payload TEXT NOT NULL,
                  active INTEGER NOT NULL, actor_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS storage_restore_files (
                  receipt_id TEXT NOT NULL, file TEXT NOT NULL, source_path TEXT NOT NULL,
                  store_id TEXT NOT NULL, generation TEXT NOT NULL,
                  PRIMARY KEY(receipt_id,file));
                CREATE INDEX IF NOT EXISTS storage_restore_by_store ON storage_restore_files(store_id);
                CREATE TABLE IF NOT EXISTS storage_restore_readers (
                  token TEXT PRIMARY KEY, receipt_id TEXT NOT NULL, file TEXT NOT NULL,
                  process_host TEXT NOT NULL, process_id INTEGER NOT NULL, process_started REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS scientific_restore_acceptance ON scientific_export_custody(acceptance_id);
                CREATE VIEW IF NOT EXISTS storage_restore_receipt_evidence AS
                  SELECT receipt_id,payload,job_id,unit_id,attempt_id,revoked_at FROM storage_lifecycle_receipts
                  UNION ALL
                  SELECT c.receipt_id,json_patch(c.payload,json_object(
                    'project_id',json_extract(a.payload,'$.project_id'),
                    'job_id',a.job_id,'work_unit_id',a.unit_id,'producer_attempt_id',a.attempt_id,
                    'manifest_sha256',json_extract(a.payload,'$.manifest_sha256'))),
                    a.job_id,a.unit_id,a.attempt_id,COALESCE(c.revoked_at,a.revoked_at)
                  FROM scientific_export_custody c JOIN scientific_export_acceptances a ON a.acceptance_id=c.acceptance_id;
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(storage_restore_files)")}
            if "active" not in columns:
                db.execute("ALTER TABLE storage_restore_files ADD COLUMN active INTEGER NOT NULL DEFAULT 1")

    def _validate_store(self, payload):
        location = CustodyLocation.model_validate(payload["location"])
        if location.host_id.casefold() != self.host_id or payload["kind"] != self.allowed_kind:
            raise LifecycleError("restore_source_host_or_kind_mismatch")
        root = Path(payload["root"])
        reject_reparse_path(root)
        actual = self.probe(root)
        if (actual.volume_id, actual.physical_device_id) != (location.volume_id, location.physical_device_id):
            raise LifecycleError("restore_source_volume_changed")
        return root

    def register_store(self, root, location, *, kind, actor_id):
        location = CustodyLocation.model_validate(location)
        root = Path(root).absolute()
        payload = {"root": str(root), "location": location.model_dump(mode="json"), "kind": kind}
        self._validate_store(payload)
        if not actor_id:
            raise ValueError("registration requires an authenticated adapter actor")
        encoded = json.dumps(payload, sort_keys=True)
        with self.lifecycle._transaction() as db:
            row = db.execute("SELECT payload FROM storage_restore_stores WHERE store_id=?", (location.store_id,)).fetchone()
            if row is not None and row[0] != encoded:
                raise LifecycleError("restore_store_binding_changed")
            db.execute("INSERT OR IGNORE INTO storage_restore_stores VALUES(?,?,?,1,?)",
                       (location.store_id, location.generation, encoded, actor_id))
            db.execute("INSERT OR IGNORE INTO storage_inventory_locations VALUES(?,?)",
                       (location.store_id + ':' + location.generation, json.dumps(location.model_dump(mode="json"), sort_keys=True)))
        return location.store_id

    def register_receipt_files(self, receipt_id, paths, *, actor_id):
        if not paths or len(paths) > 100000:
            raise ValueError("restore registration requires bounded exact files")
        with self.lifecycle._transaction() as db:
            row = db.execute("SELECT payload,revoked_at FROM storage_restore_receipt_evidence WHERE receipt_id=?", (receipt_id,)).fetchone()
            if row is None or row["revoked_at"]:
                raise LifecycleError("restore_custody_unavailable")
            receipt = json.loads(row["payload"])
            if receipt["verified_by"] != actor_id:
                raise LifecycleError("authenticated_adapter_actor_mismatch")
            location = receipt["target"]
            store = db.execute("SELECT payload,active FROM storage_restore_stores WHERE store_id=? AND generation=?",
                               (location["store_id"], str(location["generation"]))).fetchone()
            if store is None or not store["active"] or json.loads(store["payload"])["location"] != location:
                raise LifecycleError("restore_store_binding_changed")
            files = {f["relative_path"]: f for f in receipt["files"]}
            from .storage_projection import record_file
            for name, path in paths.items():
                portable_parts(name)
                portable_parts(path)
                if name not in files:
                    raise LifecycleError("file_not_in_manifest")
                existing = db.execute("SELECT source_path FROM storage_restore_files WHERE receipt_id=? AND file=?", (receipt_id, name)).fetchone()
                if existing is not None and existing[0] != path:
                    raise LifecycleError("restore_file_binding_changed")
                db.execute("INSERT OR IGNORE INTO storage_restore_files(receipt_id,file,source_path,store_id,generation) VALUES(?,?,?,?,?)",
                           (receipt_id, name, path, location["store_id"], str(location["generation"])))
                record_file(db, project_id=receipt["project_id"], role=receipt["target_kind"],
                    location=location["store_id"] + ':' + str(location["generation"]),
                    job_id=receipt["job_id"], unit_id=receipt["work_unit_id"], attempt_id=receipt["producer_attempt_id"],
                    record=files[name], baseline=True,
                    locator={"store_id": location["store_id"], "generation": str(location["generation"]), "relative_path": path})

    def resolve(self, job_id, unit_id, attempt_id, manifest_sha256, record):
        candidates = self.candidates(job_id, unit_id, attempt_id, manifest_sha256, record)
        if candidates:
            return candidates[0]
        raise LifecycleError("restore_source_unavailable")

    def candidates(self, job_id, unit_id, attempt_id, manifest_sha256, record):
        # Indexed metadata only until an explicit download calls validate/open.
        with self.lifecycle._connect() as db:
            rows = db.execute("""SELECT r.receipt_id,r.payload AS receipt,f.source_path,s.payload AS store
                FROM storage_restore_receipt_evidence r JOIN storage_restore_files f ON f.receipt_id=r.receipt_id
                JOIN storage_restore_stores s ON s.store_id=f.store_id AND s.generation=f.generation
                WHERE r.job_id=? AND r.unit_id=? AND r.attempt_id=? AND r.revoked_at IS NULL
                AND f.file=? AND s.active=1 AND f.active=1
                AND json_extract(s.payload,'$.kind')=? AND json_extract(r.payload,'$.manifest_sha256')=?
                ORDER BY r.receipt_id LIMIT 8""",
                (job_id, unit_id, attempt_id, record.relative_path, self.allowed_kind, manifest_sha256)).fetchall()
            if not rows and db.execute("""SELECT 1 FROM storage_restore_receipt_evidence r
                JOIN storage_restore_files f ON f.receipt_id=r.receipt_id
                JOIN storage_restore_stores s ON s.store_id=f.store_id AND s.generation=f.generation
                WHERE r.job_id=? AND r.unit_id=? AND r.attempt_id=? AND f.file=?
                AND json_extract(s.payload,'$.kind')=?
                AND (r.revoked_at IS NOT NULL OR s.active=0 OR f.active=0) LIMIT 1""",
                (job_id, unit_id, attempt_id, record.relative_path, self.allowed_kind)).fetchone():
                raise LifecycleError("restore_custody_revoked_or_changed")
        candidates = []
        for row in rows:
            receipt, store = json.loads(row["receipt"]), json.loads(row["store"])
            if store["kind"] != self.allowed_kind or receipt["manifest_sha256"] != manifest_sha256:
                continue
            expected = next((f for f in receipt["files"] if f["relative_path"] == record.relative_path), None)
            if expected is None or (expected["size_bytes"], expected["sha256"]) != (record.size_bytes, record.sha256):
                continue
            candidates.append(ResolvedSource(self, dict(row), record))
        return candidates

    def open_verified(self, job_id, unit_id, attempt_id, manifest_sha256, record, *, opener, checkpoint=lambda: None):
        """Explicit download only: at most eight fixed candidates, one open handle.

        Return the original guarded stream; no staging cache and no blind retry
        for permission, changed identity, revocation, cancellation or bad SHA.
        """
        candidates = self.candidates(job_id, unit_id, attempt_id, manifest_sha256, record)
        if not candidates:
            # No registered recovery route is an operator conflict, not an
            # offline source whose same immutable operation can retry later.
            raise LifecycleError("restore_source_unregistered")
        for source in candidates:
            pin, stream = None, None
            try:
                checkpoint()
                pin = source.pin()
                checkpoint()
                target = source.validate()
                stream, file_stat = opener(target)
                checkpoint()
                source.validate()
                return source, pin, target, stream, file_stat
            except BaseException as exc:
                try:
                    if stream is not None:
                        stream.close()
                finally:
                    if pin is not None:
                        pin.release()
                if not source_unavailable(exc):
                    raise
        raise LifecycleError("restore_source_unavailable")

    def revoke_store(self, store_id, *, actor_id):
        with self.lifecycle._transaction() as db:
            db.execute("UPDATE storage_restore_stores SET active=0,actor_id=? WHERE store_id=?", (actor_id, store_id))

    def begin_retirement(self, receipt_id, *, actor_id):
        """Durably close new admissions, then drain before an adapter may unlink.

        A count alone is not a deletion permit. Closed registrations cannot reopen
        by replaying register_receipt_files; normal retirement consent still applies.
        """
        if not actor_id:
            raise ValueError("retirement requires an authenticated adapter actor")
        self.active_readers(receipt_id)  # Reconcile only proven exited owners.
        with self.lifecycle._transaction() as db:
            db.execute("UPDATE storage_restore_files SET active=0 WHERE receipt_id=?", (receipt_id,))
            readers = db.execute("SELECT COUNT(*) FROM storage_restore_readers WHERE receipt_id=?", (receipt_id,)).fetchone()[0]
            self.lifecycle._audit(db, "storage.restore_source_closed", actor_id, receipt_id, active_readers=readers)
        return {"receipt_id": receipt_id, "closed": True, "active_readers": readers, "drained": readers == 0}

    def active_readers(self, receipt_id):
        # Exact same-host process incarnation only; ambiguous owners stay pinned.
        with self.lifecycle._transaction() as db:
            for row in db.execute("SELECT token,process_id,process_started FROM storage_restore_readers WHERE process_host=?",
                                  (self.lifecycle.process_host,)).fetchall():
                if not self.lifecycle._process_alive(row[1], row[2]):
                    db.execute("DELETE FROM storage_restore_readers WHERE token=?", (row[0],))
        with self.lifecycle._connect() as db:
            return db.execute("SELECT COUNT(*) FROM storage_restore_readers WHERE receipt_id=?", (receipt_id,)).fetchone()[0]


class ResolvedSource:
    def __init__(self, sources, row, record):
        self.sources, self.row, self.record = sources, row, record
        self.store = json.loads(row["store"])

    def validate(self):
        with self.sources.lifecycle._connect() as db:
            row = db.execute("""SELECT r.revoked_at,s.active,s.payload,f.active FROM storage_restore_receipt_evidence r
                JOIN storage_restore_files f ON f.receipt_id=r.receipt_id
                JOIN storage_restore_stores s ON s.store_id=f.store_id AND s.generation=f.generation
                WHERE r.receipt_id=? AND f.file=?""", (self.row["receipt_id"], self.record.relative_path)).fetchone()
        if row is None or row[0] or not row[1] or row[2] != self.row["store"] or not row[3]:
            raise LifecycleError("restore_custody_revoked_or_changed")
        root = self.sources._validate_store(self.store)
        return managed_path(root, self.row["source_path"])

    def pin(self):
        self.validate()
        lifecycle = self.sources.lifecycle
        token = uuid.uuid4().hex
        with lifecycle._transaction() as db:
            # Evidence is rechecked under the same metadata lock as revocation.
            row = db.execute("""SELECT r.revoked_at,s.active,s.payload,f.active FROM storage_restore_receipt_evidence r
                JOIN storage_restore_files f ON f.receipt_id=r.receipt_id
                JOIN storage_restore_stores s ON s.store_id=f.store_id AND s.generation=f.generation
                WHERE r.receipt_id=? AND f.file=?""", (self.row["receipt_id"], self.record.relative_path)).fetchone()
            if row is None or row[0] or not row[1] or row[2] != self.row["store"] or not row[3]:
                raise LifecycleError("restore_custody_revoked_or_changed")
            receipt = json.loads(self.row["receipt"])
            if db.execute("SELECT 1 FROM storage_lifecycle_writer_permits p JOIN storage_lifecycle_intents i "
                "ON i.intent_id=p.intent_id WHERE i.job_id=? AND i.unit_id=? AND i.attempt_id=? AND p.relative_path=?",
                (receipt["job_id"], receipt["work_unit_id"], receipt["producer_attempt_id"], self.record.relative_path)).fetchone():
                raise LifecycleError("file_retirement_in_progress")
            db.execute("INSERT INTO storage_restore_readers VALUES(?,?,?,?,?,?)", (token,
                self.row["receipt_id"], self.record.relative_path, lifecycle.process_host, os.getpid(), lifecycle.process_started))
        return RestorePin(self.sources, token)
