import json
import shutil
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from research_compute_network.hashing import sha256_value
from research_compute_network.restore_sources import RegisteredResultSources
from research_compute_network.storage_lifecycle import LifecycleError
from research_compute_network.volume_budget import VolumeBudget
from test_storage_lifecycle import custody, ready, intent, selection
from test_storage_algorithms import registered, archive_app
from test_scientific_retention import accepted


@pytest.mark.parametrize("revoke", ["acceptance", "custody"])
def test_scientific_custody_restores_surviving_original_files_and_keeps_mph_retired(custody, tmp_path, revoke):
    h = custody
    acceptance, proof, receipts = accepted(h)
    receipt = receipts[0]
    location = receipt["payload"]["target"]
    root = tmp_path / "scientific-archive"
    root.mkdir()
    for record in proof.scientific_files:
        target = root / record.relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(h.directory / record.relative_path, target)
    resolver = RegisteredResultSources(h.lifecycle, host_id=location["host_id"], probe=lambda _: SimpleNamespace(**location))
    resolver.register_store(root, location, kind="wkr_archive", actor_id="alice")
    resolver.register_receipt_files(receipt["record_id"], {f.relative_path:f.relative_path for f in proof.scientific_files}, actor_id="alice")
    retirement = h.lifecycle.scientific.create_retirement(acceptance, idempotency_key="model-original", actor_id="admin")
    assert h.lifecycle.run_retirement(retirement["intent_id"])["state"] == "completed"
    (h.directory / "metrics.csv").rename(h.directory / "saved-fixture-metrics.csv")
    app, manager = archive_app(h, resolver, tmp_path)
    client = TestClient(app)
    route = f"/v1/jobs/{h.job.job_id}/origin-results/{h.unit.work_unit_id}/attempt-original"
    try:
        response = client.get(route, params={"file":"metrics.csv"}, headers={"Range":"bytes=2-"})
        assert response.status_code == 206 and response.content == (root / "metrics.csv").read_bytes()[2:], response.text
        assert client.get(route, params={"file":"models/result.mph"}).status_code == 410
        h.lifecycle.scientific.revoke(acceptance if revoke == "acceptance" else receipt["record_id"], actor_id="alice", reason="fixture revoke")
        assert client.get(route, params={"file":"metrics.csv"}).status_code == 409
    finally:
        manager.close()


def test_restore_pins_and_destructive_permits_are_mutually_exclusive_and_close_drains(custody, tmp_path):
    h = custody
    resolver, receipt, root = registered(h, tmp_path)
    retirement = intent(h)
    record = next(f for f in h.manifest.files if f.relative_path == "metrics.csv")
    source = resolver.resolve(*selection(h), sha256_value(h.manifest.model_dump(mode="json")), record)
    pin = source.pin()
    try:
        with h.lifecycle._transaction() as db:
            with pytest.raises(LifecycleError, match="live_readers"):
                h.lifecycle._claim_writer_permit(db, retirement["intent_id"], record.relative_path)
        assert not resolver.begin_retirement(receipt["receipt_id"], actor_id="alice")["drained"]
        with pytest.raises(LifecycleError):
            source.pin()
    finally:
        pin.release()
    assert resolver.begin_retirement(receipt["receipt_id"], actor_id="alice")["drained"]
    resolver.register_receipt_files(receipt["receipt_id"], {record.relative_path:record.relative_path}, actor_id="alice")
    with pytest.raises(LifecycleError, match="revoked_or_changed"):
        resolver.resolve(*selection(h), sha256_value(h.manifest.model_dump(mode="json")), record)


def test_category_projection_tracks_policy_receipts_revocation_and_exact_retirement(custody):
    h = custody
    total = sum(f.size_bytes for f in h.manifest.files)
    h.lifecycle.inventory.refresh_categories()
    assert h.lifecycle.inventory.snapshot()["projects"][0]["pending_custody_bytes"] == total
    receipts = ready(h)
    assert h.lifecycle.inventory.snapshot()["projects"][0]["eligible_bytes"] is None
    h.lifecycle.inventory.refresh_categories()
    eligible = sum(f.size_bytes for f in h.manifest.files if f.relative_path != "artifact-manifest.json")
    assert h.lifecycle.inventory.snapshot()["projects"][0]["eligible_bytes"] == eligible
    retirement = intent(h)
    assert h.lifecycle.run_retirement(retirement["intent_id"])["state"] == "completed"
    row = h.lifecycle.inventory.snapshot()["projects"][0]
    assert row["confirmed_retired_bytes"] == eligible and row["eligible_bytes"] == 0
    h.lifecycle.revoke_receipt(receipts[0]["receipt_id"], actor_id="alice", reason="fixture revoke")
    assert h.lifecycle.inventory.snapshot()["projects"][0]["pending_custody_bytes"] is None
    h.lifecycle.inventory.refresh_categories()
    assert h.lifecycle.inventory.snapshot()["projects"][0]["confirmed_retired_bytes"] == eligible


def test_volume_sampling_observes_reserved_bytes_without_admitting_background_payload_io(custody):
    h = custody
    budget = VolumeBudget(h.database, host_id=h.binding.host_id.casefold(), free_bytes=lambda _: 100*1024**3)
    claim = budget.reserve(h.root, 123, holder_kind="origin_collection", holder_key="fixture")
    try:
        assert h.lifecycle.inventory.sample_volume(h.root)["reserved_bytes"] == 123
        assert h.lifecycle.run_gc_batch()[0]["reason_code"] == "storage_background_deferred"
    finally:
        budget.release(claim, writer_stopped=True, evidence="fixture ended")


@pytest.mark.parametrize("entrypoint", ["sdk", "cli"])
def test_real_download_entrypoints_discover_only_existing_requester_local_registration(custody, tmp_path, monkeypatch, entrypoint):
    from research_compute_network import restore_sources, collection_cli
    from research_compute_network.origin_transfer_client import OriginTransferClient
    h = custody
    resolver, receipt, archive = registered(h, tmp_path, "requester_local")
    location = receipt["receipt"]["target"]
    monkeypatch.setenv("RCN_HOME", str(tmp_path))
    monkeypatch.setenv("RCN_COLLECTION_STATE_HOME", str(tmp_path / "client-state"))
    monkeypatch.setattr(restore_sources, "current_host_id", lambda: location["host_id"])
    monkeypatch.setattr(restore_sources, "probe_volume_identity", lambda _: SimpleNamespace(**location))
    job, manifests = h.job.model_dump(mode="json"), [h.manifest.model_dump(mode="json")]
    api = SimpleNamespace(base_url="https://fixture.invalid", token="fixture", get_job_contract=lambda _: job,
                          collect_artifacts=lambda _: manifests)
    transfer = OriginTransferClient(api)
    index = {"job_id": h.job.job_id, "units": [{"work_unit_id": h.unit.work_unit_id, "attempt_id":"attempt-original",
        "manifest_sha256":sha256_value(manifests[0]), "bytes_available":False}]}
    calls = []
    def metadata_only(path, **kwargs):
        calls.append(path)
        assert path == f"/v1/jobs/{h.job.job_id}/origin-results", "local source fetched remote payload"
        return BytesIO(json.dumps(index).encode())
    monkeypatch.setattr(transfer, "_open", metadata_only)
    monkeypatch.setattr(transfer, "require_available", lambda: {})
    destination = tmp_path / "client-data"
    if entrypoint == "sdk":
        transfer.download_results(job, manifests, destination, durable=True)
    else:
        monkeypatch.setattr(collection_cli, "OriginTransferClient", lambda _: transfer)
        state = collection_cli.execute_collection_command(SimpleNamespace(collection_command="start", url=api.base_url,
            job_id=h.job.job_id, job_json=None, destination=destination, operation_id=None))
        assert state["phase"] == "finalized"
    assert calls == [f"/v1/jobs/{h.job.job_id}/origin-results"]
    for record in h.manifest.files:
        target = destination / h.job.origin_submitter_id / "incoming" / h.job.job_id / h.unit.work_unit_id / "attempt-original" / record.relative_path
        assert target.read_bytes() == (archive / record.relative_path).read_bytes()
