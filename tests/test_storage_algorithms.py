from __future__ import annotations

import json
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from research_compute_network.auth import AuthContext
from research_compute_network.hashing import sha256_value
from research_compute_network.models import UserRole
from research_compute_network.origin_transfer_api import build_origin_transfer_router
from research_compute_network.restore_sources import RegisteredResultSources
from research_compute_network.storage_lifecycle import LifecycleError
from research_compute_network.storage_io import BackgroundBudget, BackgroundDeferred, io_priority
from research_compute_network.storage_projection import record_manifest, retire_file
from research_compute_network.transfer_queue import TransferQueue
from research_compute_network.volume_budget import VolumeBudget
from test_storage_lifecycle import custody, ready, intent, selection
from test_member_client_collection_recovery import broker, operation


def registered(h, tmp_path, kind="wkr_archive"):
    receipts = ready(h)
    source = receipts[0]["receipt"]
    root = tmp_path / "registered-archive"
    root.mkdir()
    for record in h.manifest.files:
        path = root / record.relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(h.directory / record.relative_path, path)
    location = source["target"]
    resolver = RegisteredResultSources(h.lifecycle, allowed_kind=kind,
        host_id=location["host_id"], probe=lambda _: SimpleNamespace(**location))
    resolver.register_store(root, location, kind=kind, actor_id="alice")
    resolver.register_receipt_files(receipts[0]["receipt_id"],
        {f.relative_path: f.relative_path for f in h.manifest.files}, actor_id="alice")
    return resolver, receipts[0], root


def archive_app(h, resolver, tmp_path):
    app = FastAPI()
    class Auth:
        def actor(self):
            return AuthContext("alice", frozenset({UserRole.MEMBER}), frozenset())
    router = build_origin_transfer_router(repository=h.repo, auth=Auth(), root=h.root,
        require_owner=lambda *_: None, enabled=True, lifecycle=h.lifecycle,
        control_root=tmp_path / "api-control", restore_sources=resolver)
    app.include_router(router)
    return app, router.result_preparations


def test_registered_archive_streams_original_ranges_and_revocation_is_rechecked(custody, tmp_path):
    h = custody
    resolver, receipt, root = registered(h, tmp_path)
    retirement = intent(h)
    h.lifecycle.run_retirement(retirement["intent_id"])
    assert not (h.directory / "metrics.csv").exists()
    app, preparations = archive_app(h, resolver, tmp_path)
    record = h.manifest.files[0]
    body = {"operation_id": "same-original-file", "work_unit_id": h.unit.work_unit_id,
        "attempt_id": "attempt-original", "file": record.relative_path, "manifest_sha256": sha256_value(h.manifest.model_dump(mode="json")),
        "size_bytes": record.size_bytes, "sha256": record.sha256}
    try:
        client = TestClient(app)
        response = client.post(f"/v1/jobs/{h.job.job_id}/origin-result-preparations", json=body)
        assert response.status_code == 202, response.text
        ticket = response.json()
        preparations.tickets[ticket["ticket_id"]].worker.join(5)
        assert client.get(ticket["status_url"]).json()["state"] == "ready", client.get(ticket["status_url"]).json()
        for _ in range(3):
            streamed = client.get(ticket["content_url"], headers={"Range": "bytes=2-"})
            assert streamed.status_code == 206, streamed.text
            assert streamed.content == (root / record.relative_path).read_bytes()[2:]
        assert resolver.active_readers(receipt["receipt_id"]) == 1
        assert not (h.directory / "metrics.csv").exists()  # No center restore cache.
        h.lifecycle.revoke_receipt(receipt["receipt_id"], actor_id="alice", reason="fixture revoke")
        revoked = client.get(ticket["content_url"], headers={"Range": "bytes=2-"})
        assert revoked.status_code == 409 and revoked.json()["detail"]["reason_code"] == "restore_custody_revoked_or_changed"
    finally:
        preparations.close()
    assert resolver.active_readers(receipt["receipt_id"]) == 0


def test_source_registry_rejects_arbitrary_paths_generations_and_producers(custody, tmp_path):
    h = custody
    resolver, receipt, root = registered(h, tmp_path)
    with pytest.raises(ValueError):
        resolver.register_receipt_files(receipt["receipt_id"], {"metrics.csv": "../outside"}, actor_id="alice")
    with pytest.raises(LifecycleError, match="binding_changed"):
        resolver.register_store(root, {**receipt["receipt"]["target"], "generation": "new"}, kind="wkr_archive", actor_id="alice")
    with pytest.raises(LifecycleError, match="unavailable"):
        resolver.resolve(h.job.job_id, h.unit.work_unit_id, "different-attempt", "a"*64, h.manifest.files[0])
    with pytest.raises(LifecycleError, match="actor_mismatch"):
        resolver.register_receipt_files(receipt["receipt_id"], {"metrics.csv": "metrics.csv"}, actor_id="bob")


def test_inventory_is_incremental_idempotent_and_query_never_reads_data(custody, monkeypatch):
    h = custody
    assert h.lifecycle.inventory.backfill(limit=1)["processed"] == 1
    h.lifecycle.inventory.backfill(limit=1)
    expected = sum(f.size_bytes for f in h.manifest.files)
    with h.lifecycle._transaction() as db:
        record_manifest(db, h.manifest.model_dump(mode="json"), h.job.project_id)
        record_manifest(db, h.manifest.model_dump(mode="json"), h.job.project_id)
    def forbidden(*_a, **_kw):
        pytest.fail("ordinary inventory touched a data path")
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "iterdir", forbidden)
    monkeypatch.setattr(Path, "rglob", forbidden)
    monkeypatch.setattr(shutil, "disk_usage", forbidden)
    first = h.lifecycle.inventory.snapshot()
    assert first["backfill_complete"] and sum(r["bytes"] for r in first["projects"]) == expected
    with h.lifecycle._transaction() as db:
        for _ in range(2):
            retire_file(db, *selection(h), h.manifest.files[0].relative_path)
    second = h.lifecycle.inventory.snapshot()
    assert sum(r["bytes"] for r in second["projects"]) == expected-h.manifest.files[0].size_bytes
    assert second["growth_24h"][0]["removed_bytes"] == h.manifest.files[0].size_bytes


def test_foreground_io_and_real_write_claims_defer_background_but_capacity_wait_does_not(custody, monkeypatch):
    h = custody
    with io_priority.foreground():
        with pytest.raises(BackgroundDeferred):
            BackgroundBudget(h.database).checkpoint()
    budget = VolumeBudget(h.database, free_bytes=lambda _: 100*1024**3)
    claim = budget.reserve(h.root, 10, holder_kind="origin_collection", holder_key="original")
    with pytest.raises(BackgroundDeferred):
        BackgroundBudget(h.database).checkpoint()
    budget.release(claim, writer_stopped=True, evidence="fixture writer ended")
    from research_compute_network.volume_budget import VolumeCapacityUnavailable
    budget.free_bytes = lambda _: 0
    with pytest.raises(VolumeCapacityUnavailable):
        budget.reserve(h.root, 10, holder_kind="origin_collection", holder_key="capacity-wait")
    BackgroundBudget(h.database).checkpoint()


def test_transfer_queue_has_no_timer_for_waiters_and_one_deadline_timer():
    created, clock, wakes = [], [0.0], []
    class Timer:
        def __init__(self, delay, function):
            self.delay, self.function, self.cancelled = delay, function, False
            created.append(self)
        def start(self): pass
        def cancel(self): self.cancelled = True
    queue = TransferQueue(lambda: wakes.append(1), clock=lambda: clock[0], timer_factory=Timer)
    for _ in range(3):
        for i in range(100):
            queue.enqueue(str(i))
    assert len(queue.ready) == 100 and not created
    assert [queue.take() for _ in range(100)] == [str(i) for i in range(100)]
    for i in range(100):
        queue.retry(str(i), 10+i)
    assert sum(not t.cancelled for t in created) == 1
    clock[0] = 10
    created[0].function()
    assert wakes == [1] and queue.take() == "0"
    queue.close()


def test_same_target_members_attach_and_other_jobs_wait_without_polling(broker, monkeypatch):
    first, duplicate, other = operation(broker), operation(broker), operation(broker)
    broker.update(other, job_id="different-job")
    submitted = []
    monkeypatch.setattr(broker.executor, "submit", lambda f, *args: submitted.append(args))
    broker.start_transfer(first, collect=True)
    broker.start_transfer(duplicate, collect=True)
    for _ in range(10):
        broker.start_transfer(other, collect=True)
    assert submitted == [(first, True)]
    assert broker.read_operation(duplicate)["collection_control"]["canonical_operation_id"] == first
    assert list(broker.collection_queue.ready) == [other]
    assert broker.collection_queue.timer is None
    broker.busy.clear()
    broker.collection_active = None
    broker._drain_collections()
    assert submitted[-1] == (other, True)


def test_local_registered_restore_writes_only_requester_destination(custody, tmp_path, monkeypatch):
    from io import BytesIO
    from research_compute_network.collection import CollectionRunner
    h = custody
    resolver, receipt, archive = registered(h, tmp_path, "requester_local")
    monkeypatch.setenv("RCN_COLLECTION_STATE_HOME", str(tmp_path / "collection-state"))
    index = {"job_id": h.job.job_id, "units": [{"work_unit_id": h.unit.work_unit_id,
        "attempt_id": "attempt-original", "manifest_sha256": sha256_value(h.manifest.model_dump(mode="json")),
        "bytes_available": False}]}
    class Transfer:
        def require_available(self): return {}
        def _open(self, path, **kwargs):
            assert path == f'/v1/jobs/{h.job.job_id}/origin-results'
            return BytesIO(json.dumps(index).encode())
        def _read_json(self, response): return json.loads(response.read())
    runner = CollectionRunner(Transfer(), h.job.model_dump(mode="json"), [h.manifest.model_dump(mode="json")],
                              tmp_path / "requested-data", local_sources=resolver)
    runner.run()
    assert runner.status()["phase"] == "finalized"
    for _entry, record, target, _key in runner._targets():
        assert target.read_bytes() == (archive / record.relative_path).read_bytes()
    assert resolver.active_readers(receipt["receipt_id"]) == 0


def test_dispatch_reads_each_person_policy_once(service, monkeypatch):
    from conftest import simple_job
    from research_compute_network import personal_runtime
    calls = []
    store = SimpleNamespace(get_policy=lambda user: calls.append(user))
    monkeypatch.setattr(personal_runtime, "policy_store", lambda _: store)
    jobs = [simple_job(user_id='user-' + str(i % 3), request_hash=f'{i:064x}') for i in range(18)]
    service._sort_dispatch_jobs(jobs, datetime.now(timezone.utc))
    assert sorted(calls) == ['user-0', 'user-1', 'user-2']


def test_projection_rebuild_replays_exact_retired_and_registered_copies(custody, tmp_path):
    h = custody
    resolver, receipt, _root = registered(h, tmp_path)
    h.lifecycle.run_retirement(intent(h)["intent_id"])
    expected = h.lifecycle.inventory.snapshot()["projects"]
    h.lifecycle.inventory.request_rebuild()
    pages = []
    for _ in range(20):
        page = h.lifecycle.inventory.backfill(limit=1)
        pages.append(page)
        assert page["processed"] <= 1 and page["source_files_processed"] <= 1
        if page["complete"]:
            break
    assert pages[-1]["complete"]
    assert h.lifecycle.inventory.snapshot()["projects"] == expected


def test_volume_forecast_requires_fresh_spanning_samples_and_never_crosses_generation(custody, monkeypatch):
    h = custody
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    usage = SimpleNamespace(free=50*1024**3, total=100*1024**3)
    monkeypatch.setattr(shutil, "disk_usage", lambda _: usage)
    h.lifecycle.inventory.backfill()
    from research_compute_network.storage_projection import record_file
    with h.lifecycle._transaction() as db:
        for hours in (5, 2):
            record_file(db, project_id=h.job.project_id, role="origin_spool", location="center",
                job_id=h.job.job_id, unit_id=h.unit.work_unit_id, attempt_id="attempt-original",
                record={"relative_path": f"normal-{hours}", "size_bytes": 1024**3, "sha256": "a"*64},
                now=now-timedelta(hours=hours))
    for hours in (6, 3, 0):
        usage.free -= 1024**3
        h.lifecycle.inventory.sample_volume(h.root, now=now-timedelta(hours=hours))
    value = h.lifecycle.inventory.snapshot(now=now)
    assert value["volumes"][0]["growth_bytes_per_day"] == 8*1024**3
    assert value["volumes"][0]["days_to_reserve"] > 0
    assert value["volumes"][0]["forecast_basis"] == "registered_logical_file_events"
    assert h.lifecycle.inventory.snapshot(now=now+timedelta(seconds=121))["volumes"][0]["days_to_reserve"] is None
    h.lifecycle.center_binding = h.lifecycle.center_binding.model_copy(update={"generation": "new"})
    h.lifecycle.inventory.sample_volume(h.root, now=now+timedelta(seconds=1))
    volume = h.lifecycle.inventory.snapshot(now=now+timedelta(seconds=1))["volumes"][0]
    assert volume["sample_count"] == 1 and volume["days_to_reserve"] is None


def test_volume_migration_and_backfill_never_become_natural_growth(custody, monkeypatch):
    h = custody
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    usage = SimpleNamespace(free=80*1024**3, total=100*1024**3)
    monkeypatch.setattr(shutil, "disk_usage", lambda _: usage)
    h.lifecycle.inventory.request_rebuild()
    h.lifecycle.inventory.backfill()
    from research_compute_network.storage_projection import record_file
    with h.lifecycle._transaction() as db:
        db.execute("DELETE FROM storage_inventory_hours")
        record_file(db, project_id=h.job.project_id, role="origin_spool", location="center",
            job_id=h.job.job_id, unit_id=h.unit.work_unit_id, attempt_id="attempt-original",
            record={"relative_path": "registered-migration", "size_bytes": 20*1024**3, "sha256": "a"*64},
            baseline=True, now=now-timedelta(hours=3))
    for hours in (6, 3, 0):
        usage.free -= 20*1024**3  # Large unrelated migration with no normal file events.
        h.lifecycle.inventory.sample_volume(h.root, now=now-timedelta(hours=hours))
    value = h.lifecycle.inventory.snapshot(now=now)
    assert value["backfill_complete"] and value["growth_24h"] == []
    assert value["volumes"][0]["growth_bytes_per_day"] is None
    assert value["volumes"][0]["days_to_reserve"] is None
    assert value["volumes"][0]["forecast_reason"] == "no_confirmed_natural_growth"


def test_duplicate_pause_and_restart_retain_original_writer(broker, monkeypatch):
    first, duplicate = operation(broker), operation(broker)
    submitted = []
    monkeypatch.setattr(broker.executor, "submit", lambda f, *args: submitted.append(args))
    broker.start_transfer(first, collect=True)
    broker.start_transfer(duplicate, collect=True)
    paused = broker.pause_collection(duplicate)
    assert paused["collection_control"]["state"] == "user_paused"
    assert not broker.collection_cancels[first].is_set()
    broker.collection_targets.clear()
    monkeypatch.setattr(broker, "_schedule_collection", lambda *args: None)
    broker.recover_collections()
    assert list(broker.collection_targets.values()) == [first]
    broker.start_transfer(duplicate, collect=True)
    assert submitted == [(first, True)]
    assert broker.read_operation(duplicate)["collection_control"]["state"] == "attached"


def test_frozen_result_change_cannot_attach_to_old_request(broker, monkeypatch):
    from fastapi import HTTPException
    first, duplicate = operation(broker), operation(broker)
    monkeypatch.setattr(broker.executor, "submit", lambda *args: None)
    broker.update(first, collection_request={"producer": "original"})
    broker.update(duplicate, collection_request={"producer": "changed"})
    broker.start_transfer(first, collect=True)
    with pytest.raises(HTTPException) as conflict:
        broker.start_transfer(duplicate, collect=True)
    assert conflict.value.status_code == 409


def test_store_revocation_is_rechecked_atomically_when_pinning(custody, tmp_path, monkeypatch):
    h = custody
    resolver, receipt, root = registered(h, tmp_path)
    record = h.manifest.files[0]
    source = resolver.resolve(*selection(h), sha256_value(h.manifest.model_dump(mode="json")), record)
    monkeypatch.setattr(source, "validate", lambda: resolver.revoke_store(receipt["receipt"]["target"]["store_id"], actor_id="alice"))
    with pytest.raises(LifecycleError, match="revoked_or_changed"):
        source.pin()
    assert resolver.active_readers(receipt["receipt_id"]) == 0
