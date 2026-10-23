from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from research_compute_network.auth import PilotAuthenticator
from research_compute_network.hashing import sha256_file, sha256_value
from research_compute_network.models import (
    ApiTokenRecord, ArtifactManifest, FileRecord, JobStatus, OriginAdapterRegistration, ProjectGrant,
    UserAccount, UserRole, WorkUnitAttempt, WorkUnitStatus,
)
from research_compute_network.origin import build_project_worker_job
from research_compute_network.repository import MetadataRepository
from research_compute_network.storage_lifecycle import (
    CustodyLocation, LifecycleError, ProjectCustodyPolicy, StorageLifecycle,
    UnitCustodyReceipt, inventory_sha256,
)
from research_compute_network.storage_lifecycle_api import build_storage_lifecycle_router


@pytest.fixture
def custody(tmp_path):
    database = tmp_path / "control-plane.db"
    repo = MetadataRepository(f"sqlite:///{database.as_posix()}")
    repo.init_schema()
    repo.put_project_grant(ProjectGrant(project_id="fixture", owner_user_id="alice", approved=True))
    repo.put_origin_adapter(OriginAdapterRegistration(adapter_id="workbench", version="test-v1",
        allowed_profile_ids={"project-worker-v1"}, registered_by="admin"))
    source = tmp_path / "source"
    source.mkdir()
    (source / "worker.py").write_text("pass", encoding="utf-8")
    job = build_project_worker_job(project_root=source, entrypoint="worker.py", project_files=[],
        arguments={}, origin_submitter_id="fixture-origin", user_id="alice", project_id="fixture")
    unit = job.work_units[0]
    unit.status = WorkUnitStatus.COMPLETED
    unit.attempts = [WorkUnitAttempt(attempt_id="attempt-original", external_run_id="run-original",
        state="completed", collected_at=datetime.now(timezone.utc))]
    # Unit custody is valid while other Units are still running.
    other = unit.model_copy(deep=True, update={"work_unit_id": "unit-still-running", "ordinal": 1,
        "status": WorkUnitStatus.RUNNING, "attempts": []})
    job.work_units.append(other)
    job.status = JobStatus.RUNNING
    repo.put_job(job)
    root = tmp_path / "origin-spool"
    directory = root / job.origin_submitter_id / "incoming" / job.job_id / unit.work_unit_id / "attempt-original"
    directory.mkdir(parents=True)
    records = []
    for name, raw in [("models/result.mph", b"fixture model"), ("metrics.csv", b"frequency,Q\n1,2\n"),
                      ("artifact-manifest.json", b"fixture provenance")]:
        path = directory / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
        records.append(FileRecord(relative_path=name, size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    (directory / "unlisted-evidence.json").write_text("preserved", encoding="utf-8")
    manifest = ArtifactManifest(job_id=job.job_id, work_unit_id=unit.work_unit_id, files=records,
        output_schema="fixture", producer={"attempt_id": "attempt-original", "external_run_id": "run-original"})
    repo.put_artifact_manifest(manifest)
    binding = CustodyLocation(host_id="center-host", store_id="center-store", volume_id="center-volume",
        generation="center-generation", physical_device_id="center-physical")
    state = {"available": True}
    def validate():
        if not state["available"]:
            raise LifecycleError("storage_volume_identity_mismatch")
        return root
    lifecycle = StorageLifecycle(repo, root, center_binding=binding, validate_center=validate)
    h = SimpleNamespace(repo=repo, database=database, job=job, unit=unit, manifest=manifest,
        root=root, directory=directory, binding=binding, lifecycle=lifecycle, state=state)
    yield h
    repo.engine.dispose()


def selection(h):
    return h.job.job_id, h.unit.work_unit_id, "attempt-original"


def receipt(h, number=1, *, physical=None, host=None):
    return UnitCustodyReceipt(idempotency_key=f"origin-copy-{number}", project_id=h.job.project_id,
        job_id=h.job.job_id, request_hash=h.job.request_hash, work_unit_id=h.unit.work_unit_id,
        producer_attempt_id="attempt-original", producer_external_id="run-original",
        manifest_sha256=sha256_value(h.manifest.model_dump(mode="json")), files=h.manifest.files,
        inventory_sha256=inventory_sha256(h.manifest.files), target=CustodyLocation(
            host_id=host or "origin-host", store_id=f"source-store-{number}",
            volume_id=f"source-volume-{number}", generation=f"source-generation-{number}",
            physical_device_id=physical or f"source-physical-{number}"),
        target_kind="origin_dataset", verified_by="alice", adapter_id="workbench", adapter_version="test-v1",
        adapter_build_sha256="a" * 64, verified_at=datetime.now(timezone.utc),
        verification_method="sha256_full_read", actual_bytes_verified=True,
        durable_publication=True, restore_ref=f"fixture:dataset/copy-{number}")


def ready(h, copies=2):
    h.lifecycle.register_policy(ProjectCustodyPolicy(project_id="fixture", automatic_retirement=True,
        reason="Explicit synthetic test policy"), actor_id="admin")
    return [h.lifecycle.record_receipt(receipt(h, i), actor_id="alice") for i in range(1, copies + 1)]


def intent(h, key="retirement-original"):
    return h.lifecycle.create_retirement(*selection(h), idempotency_key=key, actor_id="admin")


def test_ledger_is_original_database_and_full_connection(custody):
    h = custody
    assert h.lifecycle.database == h.database
    with h.lifecycle._connect() as db:
        assert db.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
    memory = MetadataRepository("sqlite:///:memory:")
    memory.init_schema()
    with pytest.raises(LifecycleError, match="durable_metadata_database_required"):
        StorageLifecycle(memory, h.root)
    memory.engine.dispose()


def test_receipt_is_unit_scoped_immutable_and_idempotent(custody):
    h = custody
    request = receipt(h)
    first = h.lifecycle.record_receipt(request, actor_id="alice")
    again = h.lifecycle.record_receipt(request, actor_id="alice")
    assert first["receipt_id"] == again["receipt_id"]
    assert again["already_present"]
    assert h.repo.get_job(h.job.job_id).status == JobStatus.RUNNING
    assert h.repo.get_origin_import_receipt(h.job.job_id) is None
    with pytest.raises(LifecycleError, match="idempotency_key_conflict"):
        h.lifecycle.record_receipt(request.model_copy(update={"restore_ref": "fixture:changed"}), actor_id="alice")
    restarted = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    assert restarted.list_receipts(*selection(h))[0]["receipt_id"] == first["receipt_id"]


def test_acknowledged_receipt_remains_idempotent_when_center_offline(custody):
    h = custody
    request = receipt(h)
    first = h.lifecycle.record_receipt(request, actor_id="alice")
    h.state["available"] = False
    assert h.lifecycle.record_receipt(request, actor_id="alice")["receipt_id"] == first["receipt_id"]
    with pytest.raises(LifecycleError, match="storage_volume_identity_mismatch"):
        h.lifecycle.record_receipt(receipt(h, 2), actor_id="alice")


@pytest.mark.parametrize("field,value,reason", [
    ("verified_by", "bob", "authenticated_adapter_actor_mismatch"),
    ("request_hash", "0" * 64, "custody_binding_mismatch"),
    ("manifest_sha256", "0" * 64, "custody_binding_mismatch"),
    ("producer_external_id", "run-other", "custody_binding_mismatch"),
    ("adapter_version", "test-v2", "origin_adapter_binding_mismatch"),
    ("adapter_id", "unregistered", "origin_adapter_binding_mismatch"),
])
def test_authenticated_receipt_rejects_wrong_binding(custody, field, value, reason):
    h = custody
    with pytest.raises(LifecycleError, match=reason):
        h.lifecycle.record_receipt(receipt(h).model_copy(update={field: value}), actor_id="alice")
    assert not h.lifecycle.list_receipts(*selection(h))


def test_receipt_requires_exact_complete_inventory(custody):
    h = custody
    reduced = h.manifest.files[:-1]
    request = receipt(h).model_copy(update={"files": reduced, "inventory_sha256": inventory_sha256(reduced)})
    with pytest.raises(LifecycleError, match="custody_binding_mismatch"):
        h.lifecycle.record_receipt(request, actor_id="alice")
    request = receipt(h).model_copy(update={"files": [h.manifest.files[0], h.manifest.files[0]]})
    with pytest.raises(LifecycleError, match="ambiguous_inventory"):
        h.lifecycle.record_receipt(request, actor_id="alice")


def test_legacy_manifest_and_collected_flag_are_not_custody(custody):
    h = custody
    h.manifest.producer = {}
    h.repo.put_artifact_manifest(h.manifest)
    with pytest.raises(LifecycleError, match="producer_binding_mismatch"):
        h.lifecycle.record_receipt(receipt(h), actor_id="alice")
    assert h.lifecycle.preview_retirement(*selection(h))["reason_code"] == "producer_binding_mismatch"


def test_no_default_project_policy_or_age_gc(custody):
    h = custody
    h.lifecycle.record_receipt(receipt(h), actor_id="alice")
    assert h.lifecycle.preview_retirement(*selection(h))["reason_code"] == "project_policy_unregistered"
    h.lifecycle.run_gc_batch()
    assert (h.directory / "models/result.mph").exists()
    h.lifecycle.register_policy(ProjectCustodyPolicy(project_id="fixture", reason="Registered but disabled"), actor_id="admin")
    assert h.lifecycle.preview_retirement(*selection(h))["reason_code"] == "automatic_retirement_disabled"


def test_independent_physical_copies_not_partition_count(custody):
    h = custody
    ready(h, copies=0)
    h.lifecycle.record_receipt(receipt(h, 1, physical="same-disk"), actor_id="alice")
    h.lifecycle.record_receipt(receipt(h, 2, physical="same-disk", host="second-reader-host"), actor_id="alice")
    assert h.lifecycle.preview_retirement(*selection(h))["reason_code"] == "independent_copies_missing"
    h.lifecycle.record_receipt(receipt(h, 3), actor_id="alice")
    assert h.lifecycle.preview_retirement(*selection(h))["independent_copies"] == 2


def test_center_device_does_not_count_after_retirement(custody):
    h = custody
    ready(h, copies=1)
    h.lifecycle.record_receipt(receipt(h, 2, physical=h.binding.physical_device_id,
                                     host=h.binding.host_id), actor_id="alice")
    assert h.lifecycle.preview_retirement(*selection(h))["reason_code"] == "independent_copies_missing"
    h.lifecycle.center_binding = None
    assert h.lifecycle.preview_retirement(*selection(h))["reason_code"] == "center_identity_unregistered"


def test_registered_integer_store_generation_is_normalized(custody):
    h = custody
    registered = SimpleNamespace(host_id="center-host", store_id="center-store", generation=2,
        volume_identity=SimpleNamespace(volume_id="center-volume", physical_device_id="center-physical"))
    lifecycle = StorageLifecycle(h.repo, h.root, center_binding=registered)
    assert lifecycle.center_binding.generation == "2"


def test_bounded_gc_preserves_provenance_and_restarts_same_intent(custody):
    h = custody
    ready(h)
    original_manifest = h.manifest.model_dump(mode="json")
    created = intent(h)
    assert all(state == "pending" for state in created["files"].values())
    assert created["candidate"]["original_manifest"] == original_manifest
    step = h.lifecycle.run_retirement(created["intent_id"], max_files=1)
    assert step["state"] == "pending"
    assert list(step["files"].values()).count("deleted") == 1
    assert intent(h)["intent_id"] == created["intent_id"]
    restarted = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    complete = restarted.run_retirement(created["intent_id"], max_files=1)
    assert complete["state"] == "completed"
    assert (h.directory / "artifact-manifest.json").read_bytes() == b"fixture provenance"
    assert (h.directory / "unlisted-evidence.json").read_text() == "preserved"
    assert h.repo.list_artifact_manifests(h.job.job_id)[0].model_dump(mode="json") == original_manifest
    assert h.repo.get_job(h.job.job_id).status == JobStatus.RUNNING
    assert restarted.state(*selection(h))["state"] == "retired_with_restore_ref"


def test_intent_full_commit_precedes_unlink_and_crash_reconciles(custody, monkeypatch):
    h = custody
    ready(h)
    created = intent(h)
    original_unlink = Path.unlink
    observed = []
    permits = []
    def checked_unlink(path, *args, **kwargs):
        with sqlite3.connect(h.database) as db:
            observed.append(db.execute("SELECT state FROM storage_lifecycle_intents WHERE intent_id=?",
                                      (created["intent_id"],)).fetchone()[0])
            permits.append(db.execute("SELECT COUNT(*) FROM storage_lifecycle_writer_permits "
                "WHERE intent_id=? AND relative_path=?", (created["intent_id"], path.name)).fetchone()[0])
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", checked_unlink)
    audit = h.lifecycle._audit
    def crash(db, event_type, *args, **kwargs):
        if event_type == "storage.file_retired":
            raise SystemExit("synthetic crash after unlink before result commit")
        return audit(db, event_type, *args, **kwargs)
    monkeypatch.setattr(h.lifecycle, "_audit", crash)
    with pytest.raises(SystemExit):
        h.lifecycle.run_retirement(created["intent_id"], max_files=1)
    assert observed == ["pending"]
    assert permits == [1]
    with h.lifecycle._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM storage_lifecycle_writer_permits").fetchone()[0] == 0
    assert h.lifecycle.get_intent(created["intent_id"])["files"]["metrics.csv"] == "pending"
    restarted = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    finished = restarted.run_retirement(created["intent_id"])
    assert finished["state"] == "completed"
    assert finished["files"]["metrics.csv"] == "already_absent"


def test_changed_source_after_intent_preserved(custody):
    h = custody
    ready(h)
    created = intent(h)
    (h.directory / "metrics.csv").write_bytes(b"changed bytes")
    result = h.lifecycle.run_retirement(created["intent_id"])
    assert result["last_reason"] == "source_file_changed"
    assert (h.directory / "metrics.csv").read_bytes() == b"changed bytes"
    assert (h.directory / "models/result.mph").exists()


def test_receipt_revocation_and_policy_change_stop_pending_retirement(custody):
    h = custody
    receipts = ready(h)
    created = intent(h)
    h.lifecycle.revoke_receipt(receipts[0]["receipt_id"], actor_id="admin", reason="Source proof withdrawn")
    assert h.lifecycle.run_retirement(created["intent_id"])["last_reason"] == "custody_evidence_revoked_or_changed"
    assert (h.directory / "metrics.csv").exists()


def test_policy_added_protected_file_rechecks_original_intent(custody):
    h = custody
    ready(h)
    created = intent(h)
    h.lifecycle.register_policy(ProjectCustodyPolicy(project_id="fixture", automatic_retirement=True,
        protected_relative_paths=["models/result.mph"], reason="Model now required by originating project"), actor_id="admin")
    assert h.lifecycle.run_retirement(created["intent_id"])["last_reason"] == "retirement_policy_changed"
    assert (h.directory / "metrics.csv").exists()


def test_root_swap_and_manifest_change_stop_exact_candidate(custody):
    h = custody
    ready(h)
    created = intent(h)
    h.state["available"] = False
    assert h.lifecycle.run_retirement(created["intent_id"])["last_reason"] == "storage_volume_identity_mismatch"
    assert (h.directory / "metrics.csv").exists()
    h.state["available"] = True
    h.manifest.producer["runtime_version"] = "different-provenance"
    h.repo.put_artifact_manifest(h.manifest)
    assert h.lifecycle.run_retirement(created["intent_id"])["last_reason"] == "retirement_binding_changed"
    assert (h.directory / "metrics.csv").exists()


def test_live_reader_gate_is_shared_across_instances(custody):
    h = custody
    ready(h)
    other = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    pin = h.lifecycle.pin_reader(*selection(h), "models/result.mph")
    assert other.preview_retirement(*selection(h))["reason_code"] == "live_readers"
    with pytest.raises(LifecycleError, match="live_readers"):
        intent(h)
    assert other.reconcile_dead_readers() == 0
    pin.release()
    created = intent(h)
    with pytest.raises(LifecycleError, match="result_retirement_pending_or_completed"):
        other.pin_reader(*selection(h), "models/result.mph")
    # Protected provenance remains accessible through the same gate.
    with other.pin_reader(*selection(h), "artifact-manifest.json"):
        assert h.lifecycle.run_retirement(created["intent_id"])["last_reason"] == "live_readers"
    assert other.run_retirement(created["intent_id"])["state"] == "completed"


@pytest.mark.parametrize("changed", ["custody_revoked", "policy_disabled"])
def test_invalidated_intent_allows_intact_recovery_reader(custody, changed):
    h = custody
    receipts = ready(h)
    intent(h)
    if changed == "custody_revoked":
        h.lifecycle.revoke_receipt(receipts[0]["receipt_id"], actor_id="admin", reason="Source copy unavailable")
    else:
        h.lifecycle.register_policy(ProjectCustodyPolicy(project_id="fixture", reason="Stop automatic retirement"), actor_id="admin")
    with h.lifecycle.pin_reader(*selection(h), "models/result.mph"):
        assert (h.directory / "models/result.mph").read_bytes() == b"fixture model"


def test_active_unlink_permit_blocks_reader_after_revocation_without_db_writer_lock(custody, monkeypatch):
    h = custody
    receipts = ready(h)
    created = intent(h)
    other = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    started, proceed = threading.Event(), threading.Event()
    outcomes, failures = [], []
    original_unlink = Path.unlink
    def blocked_unlink(path, *args, **kwargs):
        if path == h.directory / "metrics.csv":
            started.set()
            assert proceed.wait(10), "test did not release its synthetic blocked unlink"
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", blocked_unlink)
    def retire():
        try:
            outcomes.append(h.lifecycle.run_retirement(created["intent_id"], max_files=1))
        except BaseException as exc:
            failures.append(exc)
    thread = threading.Thread(target=retire, daemon=True)
    thread.start()
    try:
        assert started.wait(5)
        # A deliberately short independent SQLite write proves USB unlink is
        # outside the global writer transaction, rather than merely being fast.
        with sqlite3.connect(h.database, timeout=0.1) as db:
            db.execute("BEGIN IMMEDIATE")
            assert db.execute("SELECT COUNT(*) FROM storage_lifecycle_writer_permits").fetchone()[0] == 1
        assert other.reconcile_dead_writer_permits() == 0
        other.revoke_receipt(receipts[0]["receipt_id"], actor_id="admin", reason="Revoked while unlink is in flight")
        with pytest.raises(LifecycleError, match="file_retirement_in_progress"):
            other.pin_reader(*selection(h), "metrics.csv")
    finally:
        proceed.set()
        thread.join(5)
    assert not thread.is_alive() and not failures
    assert outcomes[0]["files"]["metrics.csv"] == "deleted"
    assert (h.directory / "models/result.mph").exists()
    with other.pin_reader(*selection(h), "models/result.mph"):
        assert (h.directory / "models/result.mph").read_bytes() == b"fixture model"


def test_active_permit_serializes_two_manual_retirements(custody, monkeypatch):
    h = custody
    ready(h)
    created = intent(h)
    other = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    started, proceed = threading.Event(), threading.Event()
    original_unlink = Path.unlink
    def blocked_unlink(path, *args, **kwargs):
        if path == h.directory / "metrics.csv":
            started.set()
            assert proceed.wait(10)
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", blocked_unlink)
    thread = threading.Thread(target=lambda: h.lifecycle.run_retirement(created["intent_id"], max_files=1), daemon=True)
    thread.start()
    try:
        assert started.wait(5)
        second = other.run_retirement(created["intent_id"], max_files=1)
        assert second["last_reason"] == "file_retirement_in_progress"
        assert second["files"]["metrics.csv"] == "pending"
    finally:
        proceed.set()
        thread.join(5)
    assert not thread.is_alive()
    assert other.get_intent(created["intent_id"])["files"]["metrics.csv"] == "deleted"


def test_orphan_permit_requires_same_host_exact_process_exit(custody):
    h = custody
    receipts = ready(h)
    created = intent(h)
    with h.lifecycle._transaction() as db:
        h.lifecycle._claim_writer_permit(db, created["intent_id"], "metrics.csv")
    h.lifecycle.revoke_receipt(receipts[0]["receipt_id"], actor_id="admin", reason="Protect remaining recovery source")
    assert h.lifecycle.reconcile_dead_writer_permits() == 0
    with pytest.raises(LifecycleError, match="file_retirement_in_progress"):
        h.lifecycle.pin_reader(*selection(h), "metrics.csv")
    with h.lifecycle._transaction() as db:
        db.execute("UPDATE storage_lifecycle_writer_permits SET process_host='unreachable-other-host',process_started=process_started-1000")
    assert h.lifecycle.reconcile_dead_writer_permits() == 0
    with h.lifecycle._transaction() as db:
        db.execute("UPDATE storage_lifecycle_writer_permits SET process_host=?", (h.lifecycle.process_host,))
    assert h.lifecycle.reconcile_dead_writer_permits() == 1
    with h.lifecycle.pin_reader(*selection(h), "metrics.csv"):
        assert (h.directory / "metrics.csv").exists()


def test_legacy_completed_results_keep_reader_pins_without_claiming_custody(custody):
    h = custody
    h.manifest.producer = {}
    h.repo.put_artifact_manifest(h.manifest)
    with h.lifecycle.pin_reader(*selection(h), "metrics.csv"):
        assert h.lifecycle.state(*selection(h))["state"] == "available"
    assert h.lifecycle.preview_retirement(*selection(h))["reason_code"] == "producer_binding_mismatch"


def test_dead_readers_require_exact_process_exit_evidence(custody):
    h = custody
    pin = h.lifecycle.pin_reader(*selection(h), "metrics.csv")
    with h.lifecycle._transaction() as db:
        db.execute("UPDATE storage_lifecycle_readers SET process_started=process_started-1000 WHERE pin_id=?",
                   (pin.pin_id,))
    assert h.lifecycle.reconcile_dead_readers() == 1


def test_automatic_gc_has_finite_batch_and_same_original_identity(custody):
    h = custody
    ready(h)
    first = h.lifecycle.run_gc_batch(max_units=1, max_files=1)
    assert len(first) == 1
    original = first[0]["intent_id"]
    assert first[0]["state"] == "pending"
    second = h.lifecycle.run_gc_batch(max_units=1, max_files=1)
    assert second[0]["intent_id"] == original
    assert second[0]["state"] == "completed"
    assert h.lifecycle.run_gc_batch(max_units=1, max_files=1) == []


def test_automatic_gc_hashes_only_selected_files_before_deletion(custody, monkeypatch):
    h = custody
    ready(h)
    calls = []
    original_verify = h.lifecycle._verify_source
    def verify(path, record, **kwargs):
        calls.append(record["relative_path"])
        return original_verify(path, record, **kwargs)
    monkeypatch.setattr(h.lifecycle, "_verify_source", verify)
    result = h.lifecycle.run_gc_batch(max_units=1, max_files=1)[0]
    assert calls == ["metrics.csv"]
    assert result["candidate"]["file_identities"] == {}
    assert result["files"]["metrics.csv"] == "deleted"
    assert result["files"]["models/result.mph"] == "pending"


def test_deferred_source_verification_rejects_actual_changed_bytes(custody):
    h = custody
    ready(h)
    altered = h.directory / "metrics.csv"
    altered.write_bytes(b"x" * altered.stat().st_size)
    result = h.lifecycle.run_gc_batch(max_units=1, max_files=1)[0]
    assert result["last_reason"] == "source_file_integrity_failed"
    assert all(state == "pending" for state in result["files"].values())
    assert altered.exists()


def test_gc_chunk_cancellation_deletes_nothing_and_releases_gate(custody, monkeypatch):
    h = custody
    path = h.directory / "metrics.csv"
    raw = b"large synthetic result\n" * (400000)
    path.write_bytes(raw)
    replacement = FileRecord(relative_path="metrics.csv", size_bytes=len(raw), sha256=sha256_file(path))
    h.manifest.files = [replacement if f.relative_path == "metrics.csv" else f for f in h.manifest.files]
    h.repo.put_artifact_manifest(h.manifest)
    ready(h)
    stop = threading.Event()
    original_open = Path.open
    reads = []
    class InterruptedReader:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            self.stream.__enter__()
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def read(self, size):
            chunk = self.stream.read(size)
            reads.append(size)
            stop.set()
            return chunk
    def interrupted_open(selected, mode="r", *args, **kwargs):
        stream = original_open(selected, mode, *args, **kwargs)
        return InterruptedReader(stream) if selected == path and mode == "rb" else stream
    monkeypatch.setattr(Path, "open", interrupted_open)
    result = h.lifecycle.run_gc_batch(max_units=1, max_files=1, stop_event=stop)[0]
    from research_compute_network.storage_io import BACKGROUND_CHUNK_BYTES
    assert reads == [BACKGROUND_CHUNK_BYTES]
    assert result["last_reason"] == "gc_stop_requested"
    assert all(state == "pending" for state in result["files"].values())
    assert path.exists() and (h.directory / "models/result.mph").exists()
    with h.lifecycle._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM storage_lifecycle_gc_gate").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM storage_lifecycle_writer_permits").fetchone()[0] == 0
    # The automatic stop token must never poison a later explicit manual run.
    monkeypatch.setattr(Path, "open", original_open)
    resumed = h.lifecycle.run_retirement(result["intent_id"], max_files=1)
    assert resumed["files"]["metrics.csv"] == "deleted"


def test_stop_after_durable_permit_before_unlink_releases_exact_permit(custody, monkeypatch):
    h = custody
    ready(h)
    created = intent(h)
    stop = threading.Event()
    audit = h.lifecycle._audit
    def stop_after_authorization(db, event_type, *args, **kwargs):
        result = audit(db, event_type, *args, **kwargs)
        if event_type == "storage.file_retirement_authorized":
            stop.set()
        return result
    monkeypatch.setattr(h.lifecycle, "_audit", stop_after_authorization)
    result = h.lifecycle.run_retirement(created["intent_id"], max_files=1, stop_event=stop)
    assert result["last_reason"] == "gc_stop_requested"
    assert all(state == "pending" for state in result["files"].values())
    assert (h.directory / "metrics.csv").exists()
    with h.lifecycle._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM storage_lifecycle_writer_permits").fetchone()[0] == 0


def test_automatic_gc_single_instance_gate_requires_process_exit(custody):
    h = custody
    other = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    with h.lifecycle._gc_gate() as acquired:
        assert acquired
        assert other.run_gc_batch() == [{"eligible": False, "reason_code": "gc_already_running"}]
        # Exact process-start mismatch is proof this is no longer its holder.
        with h.lifecycle._transaction() as db:
            db.execute("UPDATE storage_lifecycle_gc_gate SET process_started=process_started-1000")
        assert other.run_gc_batch() == []
    assert other.run_gc_batch() == []


def test_blocked_original_intent_does_not_starve_other_unit(custody):
    h = custody
    copies = ready(h)
    created = intent(h)
    h.lifecycle.revoke_receipt(copies[0]["receipt_id"], actor_id="admin", reason="Synthetic withdrawn proof")
    other_unit = h.job.work_units[1]
    other_unit.status = WorkUnitStatus.COMPLETED
    other_unit.attempts = [h.unit.attempts[0].model_copy(deep=True)]
    h.repo.put_job(h.job)
    other_manifest = h.manifest.model_copy(deep=True, update={"work_unit_id": other_unit.work_unit_id})
    h.repo.put_artifact_manifest(other_manifest)
    other_directory = h.root / h.job.origin_submitter_id / "incoming" / h.job.job_id / other_unit.work_unit_id / "attempt-original"
    for record in other_manifest.files:
        path = other_directory / record.relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((h.directory / record.relative_path).read_bytes())
    other_h = SimpleNamespace(**{**vars(h), "unit": other_unit, "manifest": other_manifest,
                                 "directory": other_directory})
    h.lifecycle.record_receipt(receipt(other_h, 10), actor_id="alice")
    h.lifecycle.record_receipt(receipt(other_h, 11), actor_id="alice")
    first = h.lifecycle.run_gc_batch(max_units=1)
    assert first[0]["intent_id"] == created["intent_id"]
    assert first[0]["last_reason"] == "custody_evidence_revoked_or_changed"
    second = h.lifecycle.run_gc_batch(max_units=1)
    assert second[0]["state"] == "completed"
    assert (h.directory / "models/result.mph").exists()
    assert not (other_directory / "models/result.mph").exists()


def test_operator_and_origin_routes_authenticate_scope(custody):
    h = custody
    # Use the production authenticator; tokens are fixture-only and never sent
    # to any network service.
    tokens = {}
    for user, roles in [("alice", {UserRole.MEMBER}), ("bob", {UserRole.MEMBER}), ("admin", {UserRole.ADMIN})]:
        raw = secrets.token_hex(24)
        tokens[user] = raw
        h.repo.put_user(UserAccount(user_id=user, display_name=user, roles=roles))
        h.repo.put_token(ApiTokenRecord(user_id=user, token_hash=hashlib.sha256(raw.encode()).hexdigest(), scopes={"api"}))
    app = FastAPI()
    def owner(job, context):
        if context.actor_id != job.user_id:
            raise HTTPException(403, "origin owner required")
    app.include_router(build_storage_lifecycle_router(lifecycle=h.lifecycle,
        auth=PilotAuthenticator(h.repo, allow_local_trusted=False), require_owner=owner))
    client = TestClient(app)
    url = f"/v1/jobs/{h.job.job_id}/units/{h.unit.work_unit_id}/custody"
    payload = receipt(h).model_dump(mode="json")
    assert client.post(url, json=payload).status_code == 401
    assert client.post(url, json=payload, headers={"Authorization": "Bearer " + tokens["bob"]}).status_code == 403
    result = client.post(url, json=payload, headers={"Authorization": "Bearer " + tokens["alice"]})
    assert result.status_code == 200, result.text
    policy_url = "/v1/admin/storage/projects/fixture/policy"
    policy = {"project_id": "fixture", "automatic_retirement": True, "reason": "Fixture explicit policy"}
    assert client.put(policy_url, json=policy, headers={"Authorization": "Bearer " + tokens["alice"]}).status_code == 403
    assert client.put(policy_url, json=policy, headers={"Authorization": "Bearer " + tokens["admin"]}).status_code == 200
