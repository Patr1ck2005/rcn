import hashlib
import json
import shutil
import threading
from io import BytesIO
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from research_compute_network.hashing import sha256_value
from research_compute_network.restore_sources import RegisteredResultSources
from research_compute_network.storage_io import BackgroundDeferred, BACKGROUND_CHUNK_BYTES, io_priority
from research_compute_network import origin_transfer_api as api
from test_storage_lifecycle import custody, ready, selection
from test_storage_algorithms import registered, archive_app
from test_scientific_retention import accepted
from test_collection_recovery import collection_case, Response


def large_metrics(h):
    data = bytes(range(256))*256
    (h.directory / "metrics.csv").write_bytes(data)
    records = [record.model_copy(update={"size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
               if record.relative_path == "metrics.csv" else record for record in h.manifest.files]
    h.manifest = h.manifest.model_copy(update={"files": records})
    h.repo.put_artifact_manifest(h.manifest)
    return next(record for record in records if record.relative_path == "metrics.csv"), data


def request_body(h, record):
    return {"operation_id": "same-archive-file", "work_unit_id": h.unit.work_unit_id,
        "attempt_id": "attempt-original", "file": record.relative_path,
        "manifest_sha256": sha256_value(h.manifest.model_dump(mode="json")),
        "size_bytes": record.size_bytes, "sha256": record.sha256}


def test_offline_archive_retries_original_ticket_and_revocation_stays_conflict(custody, tmp_path):
    h = custody
    record, data = large_metrics(h)
    resolver, receipt, root = registered(h, tmp_path)
    (h.directory / record.relative_path).rename(h.directory / "saved-metrics.csv")
    path = root / record.relative_path
    saved = path.with_name("offline-metrics.csv")
    path.rename(saved)
    app, manager = archive_app(h, resolver, tmp_path)
    try:
        client = TestClient(app)
        route = f"/v1/jobs/{h.job.job_id}/origin-result-preparations"
        ticket = client.post(route, json=request_body(h, record)).json()
        manager.tickets[ticket["ticket_id"]].worker.join(5)
        state = client.get(ticket["status_url"]).json()
        assert (state["state"], state["reason_code"], state["http_status"]) == ("restore_pending", "restore_source_unavailable", 503)
        assert client.get(ticket["content_url"]).status_code == 503
        assert resolver.active_readers(receipt["receipt_id"]) == 0
        saved.rename(path)
        retried = client.post(route, json=request_body(h, record)).json()
        assert retried["ticket_id"] == ticket["ticket_id"]
        manager.tickets[ticket["ticket_id"]].worker.join(5)
        response = client.get(ticket["content_url"], headers={"Range":"bytes=4096-"})
        assert response.status_code == 206 and response.content == data[4096:]
        h.lifecycle.revoke_receipt(receipt["receipt_id"], actor_id="alice", reason="fixture revocation")
        assert client.get(ticket["content_url"]).status_code == 409
    finally:
        manager.close()


@pytest.mark.parametrize("reason,status,retry", [("preparation_expired",409,True),
    ("preparation_process_restarted",409,True), ("preparation_process_stopped",409,True),
    ("restore_custody_revoked_or_changed",409,False), ("result_handle_changed",409,False),
    ("restore_source_unavailable",503,True), ("storage_background_deferred",503,True)])
def test_streaming_client_preserves_typed_reason_and_only_transients_retry(reason, status, retry):
    from urllib.error import HTTPError
    from research_compute_network.client import RcnApiError
    from research_compute_network.origin_transfer_client import OriginTransferClient
    from research_compute_network.member_client import _collection_retryable
    from research_compute_network.collection import collection_failure_state
    client = OriginTransferClient(SimpleNamespace(base_url="http://127.0.0.1:1", token=None, timeout=1))
    body = BytesIO(json.dumps({"detail":{"reason_code":reason}}).encode())
    def reject(*_a, **_kw):
        raise HTTPError("http://127.0.0.1:1/content", status, "fixture", {}, body)
    client._opener = SimpleNamespace(open=reject)
    with pytest.raises(RcnApiError) as failed:
        client._open("/content")
    assert body.closed and failed.value.reason_code == reason
    assert _collection_retryable(failed.value) is retry
    assert collection_failure_state(failed.value) == ("retry_wait" if retry else "conflict")


def test_ready_to_content_expiry_reprepares_same_ticket(custody, tmp_path):
    h = custody
    record, data = large_metrics(h)
    resolver, _receipt, _root = registered(h, tmp_path)
    (h.directory / record.relative_path).rename(h.directory / "saved-metrics.csv")
    app, manager = archive_app(h, resolver, tmp_path)
    try:
        client = TestClient(app)
        route = f"/v1/jobs/{h.job.job_id}/origin-result-preparations"
        ticket = client.post(route, json=request_body(h, record)).json()
        owned = manager.tickets[ticket["ticket_id"]]
        owned.worker.join(5)
        owned.last_active = 0
        response = client.get(ticket["content_url"])
        assert response.status_code == 503 and response.json()["detail"]["reason_code"] == "preparation_expired"
        assert client.post(route, json=request_body(h, record)).json()["ticket_id"] == ticket["ticket_id"]
        owned.worker.join(5)
        assert client.get(ticket["content_url"]).content == data
    finally:
        manager.close()


def test_archive_already_busy_defers_before_registered_volume_probe(custody, tmp_path, monkeypatch):
    h = custody
    record, _ = large_metrics(h)
    resolver, receipt, _root = registered(h, tmp_path)
    (h.directory / record.relative_path).rename(h.directory / "saved-metrics.csv")
    monkeypatch.setattr(resolver, "probe", lambda *_:pytest.fail("background source probe ran while normal collection active"))
    app, manager = archive_app(h, resolver, tmp_path)
    try:
        client = TestClient(app)
        with io_priority.foreground():
            ticket = client.post(f"/v1/jobs/{h.job.job_id}/origin-result-preparations", json=request_body(h, record)).json()
            manager.tickets[ticket["ticket_id"]].worker.join(5)
            state = client.get(ticket["status_url"]).json()
            assert (state["state"], state["reason_code"]) == ("restore_pending", "storage_background_deferred")
        assert resolver.active_readers(receipt["receipt_id"]) == 0
    finally:
        manager.close()


def test_requester_local_missing_copy_uses_existing_remote_transport(custody, tmp_path, monkeypatch):
    from urllib.parse import parse_qs, urlsplit
    from research_compute_network.collection import CollectionRunner
    h = custody
    resolver, receipt, root = registered(h, tmp_path, "requester_local")
    for record in h.manifest.files:
        path = root / record.relative_path
        path.rename(path.with_name("offline-"+path.name))
    monkeypatch.setenv("RCN_COLLECTION_STATE_HOME", str(tmp_path / "client-state"))
    index = {"job_id":h.job.job_id, "units":[{"work_unit_id":h.unit.work_unit_id, "attempt_id":"attempt-original",
        "manifest_sha256":sha256_value(h.manifest.model_dump(mode="json")), "bytes_available":False}]}
    downloads = []
    def opened(path, **kwargs):
        if path.endswith("/origin-results"):
            return Response(json.dumps(index).encode())
        file = parse_qs(urlsplit(path).query)["file"][0]
        record = next(r for r in h.manifest.files if r.relative_path == file)
        downloads.append(file)
        return Response((h.directory / file).read_bytes(), {"X-RCN-SHA256":record.sha256, "Content-Length":str(record.size_bytes)})
    transfer = SimpleNamespace(require_available=lambda: {}, _open=opened, _read_json=lambda response:json.loads(response.read()))
    runner = CollectionRunner(transfer, h.job.model_dump(mode="json"), [h.manifest.model_dump(mode="json")],
        tmp_path / "requested-data", local_sources=resolver)
    runner.run()
    assert runner.status()["phase"] == "finalized" and len(downloads) == len(h.manifest.files)
    assert resolver.active_readers(receipt["receipt_id"]) == 0


@pytest.mark.parametrize("reason", ["restore_source_unavailable", "storage_background_deferred"])
def test_transient_archive_releases_destination_and_resumes_original_partial(collection_case, monkeypatch, reason):
    from research_compute_network.client import RcnApiError
    from research_compute_network.member_client import _collection_retryable
    c = collection_case
    c.transfer.interrupted = True
    with pytest.raises(OSError):
        c.runner().run()
    c.transfer.interrupted = False
    original = c.transfer._open
    posts, online = [], []
    monkeypatch.setattr(c.transfer, "require_available", lambda: {"result_preparations":True})
    def opened(path, **kwargs):
        if path.endswith("origin-result-preparations"):
            posts.append(json.loads(kwargs["data"]))
            return Response(json.dumps({"ticket_id":"original-ticket", "state":"ready" if online else "restore_pending",
                "reason_code":None if online else reason, "http_status":503}).encode())
        return original(path, **kwargs)
    monkeypatch.setattr(c.transfer, "_open", opened)
    runner = c.runner()
    with pytest.raises(RcnApiError) as failure:
        runner.run()
    assert _collection_retryable(failure.value) and runner.claim is None
    assert runner.status()["phase"] == "retry_wait"
    assert next(iter(runner.status()["files"].values()))["durable_offset"] == 3
    online.append(True)
    runner.run()
    assert posts[0] == posts[1] and runner.operation_id == "original-operation"
    assert c.target.read_bytes() == c.content and c.transfer.calls[-1][1]["Range"] == "bytes=3-"
    assert not _collection_retryable(RcnApiError(409, "revoked", reason_code="restore_custody_revoked_or_changed"))


@pytest.mark.parametrize("scientific", [False, True])
@pytest.mark.parametrize("fault", ["missing", "bad_sha"])
def test_registered_candidates_skip_missing_but_never_integrity_failure(custody, tmp_path, scientific, fault):
    h = custody
    if scientific:
        from research_compute_network.scientific_retention import ScientificCustodyReceipt
        first = accepted(h, copies=1)[2][0]
        payload = first["payload"]
        second = ScientificCustodyReceipt.model_validate({**payload, "idempotency_key":"second-local-disk",
            "target":{**payload["target"], "store_id":"store-2", "volume_id":"volume-2", "physical_device_id":"device-2"}})
        receipts = [first, h.lifecycle.scientific.record_custody(second, actor_id="alice")]
    else:
        receipts = ready(h)
    receipts = [(item.get("record_id", item.get("receipt_id")), item.get("payload", item.get("receipt"))) for item in receipts]
    locations, roots = {}, {}
    resolver = RegisteredResultSources(h.lifecycle, host_id=receipts[0][1]["target"]["host_id"],
        probe=lambda path: SimpleNamespace(**locations[path]))
    for index, (receipt_id, receipt) in enumerate(receipts):
        root = tmp_path / f"archive-{index}"
        root.mkdir()
        locations[root] = receipt["target"]
        roots[receipt_id] = root
        for record in receipt["files"]:
            target = root / record["relative_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(h.directory / record["relative_path"], target)
        resolver.register_store(root, receipt["target"], kind="wkr_archive", actor_id="alice")
        resolver.register_receipt_files(receipt_id, {r["relative_path"]:r["relative_path"] for r in receipt["files"]}, actor_id="alice")
    original = (h.directory / "metrics.csv").read_bytes()
    (h.directory / "metrics.csv").rename(h.directory / "saved-metrics.csv")
    first = roots[sorted(roots)[0]] / "metrics.csv"
    if fault == "missing":
        first.rename(first.with_name("saved-metrics.csv"))
    else:
        first.write_bytes(b"x"*len(original))
    app, manager = archive_app(h, resolver, tmp_path)
    try:
        response = TestClient(app).get(f"/v1/jobs/{h.job.job_id}/origin-results/{h.unit.work_unit_id}/attempt-original",
            params={"file":"metrics.csv"}, headers={"Range":"bytes=2-"})
        if fault == "missing":
            assert response.status_code == 206 and response.content == original[2:], response.text
        else:
            assert response.status_code == 409
        assert all(resolver.active_readers(key) == 0 for key in roots)
    finally:
        manager.close()


def test_archive_verification_yields_volume_slot_to_real_normal_read_and_reuses_ticket(custody, tmp_path, monkeypatch):
    h = custody
    record, data = large_metrics(h)
    resolver, receipt, root = registered(h, tmp_path)
    (h.directory / record.relative_path).rename(h.directory / "saved-metrics.csv")
    app, manager = archive_app(h, resolver, tmp_path)
    read_chunk, normal_waiting, release_archive, normal_done = (threading.Event() for _ in range(4))
    original_open, original_acquire = api._open_verified_result, api.verification_slots.acquire
    blocked, failures = [], []
    def acquire(volume, cancelled=lambda: False):
        if io_priority.readers:
            normal_waiting.set()
        return original_acquire(volume, cancelled)
    def verified(path, size, digest, **kwargs):
        progress = kwargs.get("progress")
        if kwargs.get("background_budget") is not None:
            def observe(checked, total):
                if progress:
                    progress(checked, total)
                if checked and not blocked:
                    blocked.append(checked)
                    read_chunk.set()
                    assert release_archive.wait(5)
            kwargs["progress"] = observe
        return original_open(path, size, digest, **kwargs)
    monkeypatch.setattr(api, "_open_verified_result", verified)
    monkeypatch.setattr(api.verification_slots, "acquire", acquire)
    normal_record = next(r for r in h.manifest.files if r.relative_path == "artifact-manifest.json")
    def normal():
        try:
            stream, _ = api.open_verified_result(h.directory / normal_record.relative_path, normal_record.size_bytes, normal_record.sha256)
            stream.close()
        except BaseException as exc:
            failures.append(exc)
        finally:
            normal_done.set()
    worker = threading.Thread(target=normal)
    try:
        client = TestClient(app)
        base = f"/v1/jobs/{h.job.job_id}/origin-result-preparations"
        ticket = client.post(base, json=request_body(h, record)).json()
        assert read_chunk.wait(5)
        worker.start()
        assert normal_waiting.wait(5)
        release_archive.set()
        assert normal_done.wait(5) and not failures
        manager.tickets[ticket["ticket_id"]].worker.join(5)
        state = client.get(ticket["status_url"]).json()
        assert state["state"] == "restore_pending" and state["reason_code"] == "storage_background_deferred"
        assert api.verification_slots.active == 0 and resolver.active_readers(receipt["receipt_id"]) == 0
        retried = client.post(base, json=request_body(h, record)).json()
        assert retried["ticket_id"] == ticket["ticket_id"]
        manager.tickets[ticket["ticket_id"]].worker.join(5)
        response = client.get(ticket["content_url"], headers={"Range":f"bytes={BACKGROUND_CHUNK_BYTES}-"})
        assert response.status_code == 206 and response.content == data[BACKGROUND_CHUNK_BYTES:]
    finally:
        release_archive.set()
        if worker.ident is not None:
            worker.join(5)
        manager.close()


def test_prepared_archive_range_yields_after_one_chunk_and_releases_ready_ownership(custody, tmp_path):
    h = custody
    record, data = large_metrics(h)
    resolver, receipt, _root = registered(h, tmp_path)
    (h.directory / record.relative_path).rename(h.directory / "saved-metrics.csv")
    app, manager = archive_app(h, resolver, tmp_path)
    ordinary = next(r for r in h.manifest.files if r.relative_path == "artifact-manifest.json")
    normal_started, release_normal = threading.Event(), threading.Event()
    chunks, workers = [], []
    def normal_read():
        with io_priority.foreground():
            stream, _ = api.open_verified_result(h.directory / ordinary.relative_path, ordinary.size_bytes, ordinary.sha256)
            stream.close()
            normal_started.set()
            release_normal.wait(5)
    async def preempt(scope, receive, send):
        async def observed(message):
            await send(message)
            if scope["path"].endswith("/content") and message["type"] == "http.response.body" and message.get("body") and not chunks:
                chunks.append(len(message["body"]))
                worker = threading.Thread(target=normal_read)
                workers.append(worker)
                worker.start()
                assert normal_started.wait(5)
        await app(scope, receive, observed)
    try:
        client = TestClient(preempt)
        ticket = client.post(f"/v1/jobs/{h.job.job_id}/origin-result-preparations", json=request_body(h, record)).json()
        manager.tickets[ticket["ticket_id"]].worker.join(5)
        with pytest.raises(ConnectionAbortedError, match="archive yielded"):
            client.get(ticket["content_url"])
        assert chunks == [BACKGROUND_CHUNK_BYTES]
        state = client.get(ticket["status_url"]).json()
        assert state["state"] == "restore_pending"
        assert manager.tickets[ticket["ticket_id"]].resource is None
        assert resolver.active_readers(receipt["receipt_id"]) == 0
    finally:
        release_normal.set()
        for worker in workers:
            worker.join(5)
        manager.close()


def test_requester_local_archive_deferral_preserves_identity_and_releases_claim(custody, tmp_path, monkeypatch):
    from research_compute_network.collection import CollectionRunner
    h = custody
    record, _ = large_metrics(h)
    resolver, receipt, root = registered(h, tmp_path, "requester_local")
    monkeypatch.setenv("RCN_COLLECTION_STATE_HOME", str(tmp_path / "client-state"))
    index = {"job_id":h.job.job_id, "units":[{"work_unit_id":h.unit.work_unit_id, "attempt_id":"attempt-original",
        "manifest_sha256":sha256_value(h.manifest.model_dump(mode="json")), "bytes_available":False}]}
    transfer = SimpleNamespace(require_available=lambda: {}, _open=lambda *_a, **_kw: BytesIO(json.dumps(index).encode()),
                               _read_json=lambda response: json.loads(response.read()))
    runner = CollectionRunner(transfer, h.job.model_dump(mode="json"), [h.manifest.model_dump(mode="json")],
        tmp_path / "requested-data", local_sources=resolver)
    original = runner.operation_id
    with io_priority.foreground():
        stream, _ = api.open_verified_result(h.directory / record.relative_path, record.size_bytes, record.sha256)
        stream.close()
        with pytest.raises(BackgroundDeferred):
            runner.run()
    assert runner.status()["phase"] == "retry_wait" and runner.claim is None
    assert resolver.active_readers(receipt["receipt_id"]) == 0
    runner.run()
    assert runner.operation_id == original and runner.status()["phase"] == "finalized"
