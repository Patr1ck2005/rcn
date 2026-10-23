from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from research_compute_network import origin_transfer_api as transfer_api
from research_compute_network.hashing import sha256_value
from research_compute_network.result_preparations import (
    PreparationCancelled, ResultPreparations, TransferActivity, VerificationSlots,
)
from research_compute_network.release_maintenance import get_transfer_gate
from test_origin_transfer import complete, handoff, headers, upload_url


@pytest.fixture
def prepared(handoff):
    h = handoff
    h.preparations = next(callback.__self__ for callback in h.app.router.on_shutdown
                          if isinstance(getattr(callback, "__self__", None), ResultPreparations))
    h.gate = get_transfer_gate(h.tmp_path / "center")
    yield h
    h.preparations.close()


def request_body(h, *, operation="file-" + "a" * 64, payload=None):
    manifest, target = complete(h)
    if payload is not None:
        target.write_bytes(payload)
        manifest.files[0].size_bytes = len(payload)
        manifest.files[0].sha256 = hashlib.sha256(payload).hexdigest()
        h.repo.put_artifact_manifest(manifest)
    record = manifest.files[0]
    return {"operation_id": operation, "work_unit_id": manifest.work_unit_id,
            "attempt_id": "attempt-a", "file": record.relative_path,
            "manifest_sha256": sha256_value(manifest.model_dump(mode="json")),
            "size_bytes": record.size_bytes, "sha256": record.sha256}, target


def post(h, body):
    return h.client.post(f"/v1/jobs/{h.job.job_id}/origin-result-preparations", json=body, headers=headers(h))


def wait_state(h, ticket, states=("ready",)):
    deadline = time.monotonic() + 8
    while True:
        response = h.client.get(ticket["status_url"], headers=headers(h))
        assert response.status_code == 200, response.text
        result = response.json()
        if result["state"] in states:
            return result
        assert time.monotonic() < deadline, result
        time.sleep(0.01)


def test_ticket_roundtrip_binding_and_one_sha_for_all_ranges(prepared, monkeypatch):
    h = prepared
    body, target = request_body(h)
    opened = []
    original = transfer_api.open_verified_result
    def counted(*args, **kwargs):
        result = original(*args, **kwargs)
        opened.append(result[0])
        return result
    monkeypatch.setattr(transfer_api, "open_verified_result", counted)
    response = post(h, body)
    assert response.status_code == 202, response.text
    ticket = wait_state(h, response.json())
    assert ticket["checked_bytes"] == ticket["total_bytes"] == body["size_bytes"]
    assert ticket["last_progress_at"] and ticket["retry_after"] == 2
    assert post(h, body).json()["ticket_id"] == ticket["ticket_id"]
    capabilities = h.client.get("/v1/origin-transfer", headers=headers(h)).json()
    assert capabilities["result_preparations"] is True and capabilities["result_range_resume"] is True
    for selected, expected in [(None, target.read_bytes()), ("bytes=3-7", target.read_bytes()[3:8]),
                               ("bytes=7-", target.read_bytes()[7:]), ("bytes=-4", target.read_bytes()[-4:])]:
        extra = {} if selected is None else {"Range": selected, "If-Range": ticket["etag"]}
        result = h.client.get(ticket["content_url"], headers=dict(headers(h), **extra))
        assert result.status_code == (200 if selected is None else 206)
        assert result.content == expected
        assert result.headers["etag"] == '"' + body["sha256"] + '"'
        assert result.headers["X-RCN-SHA256"] == body["sha256"]
    assert len(opened) == 1 and not opened[0].closed
    for changed in (dict(body, sha256="b" * 64), dict(body, attempt_id="missing-attempt"),
                    dict(body, file="not-in-manifest")):
        conflict = post(h, changed)
        assert conflict.status_code == 409 and conflict.json()["detail"]["reason_code"] == "operation_id_conflict"
    changed = dict(body, operation_id="other", manifest_sha256="b" * 64)
    assert post(h, changed).json()["detail"]["reason_code"] == "result_manifest_binding_changed"
    assert h.client.get(ticket["status_url"], headers=headers(h, "bob")).status_code == 403
    assert h.client.get(ticket["content_url"]).status_code == 401
    assert h.client.delete(ticket["status_url"], headers=headers(h)).json()["state"] == "cancelled"
    assert h.client.delete(ticket["status_url"], headers=headers(h)).json()["state"] == "cancelled"
    assert opened[0].closed


@pytest.mark.parametrize("selected", ["bytes=0-1,3-4", "bytes=30-", "bytes=5-3", "bytes=-0", "units=0-1", "bytes=-", "bytes=" + "9" * 100 + "-"])
def test_invalid_single_range_is_416_and_does_not_consume_ticket(prepared, selected):
    h = prepared
    body, _ = request_body(h)
    ticket = wait_state(h, post(h, body).json())
    response = h.client.get(ticket["content_url"], headers=dict(headers(h), Range=selected))
    assert response.status_code == 416
    assert response.headers["Content-Range"] == f"bytes */{body['size_bytes']}"
    assert wait_state(h, ticket)["state"] == "ready"


def test_if_range_mismatch_returns_whole_exact_file(prepared):
    h = prepared
    body, target = request_body(h)
    ticket = wait_state(h, post(h, body).json())
    response = h.client.get(ticket["content_url"], headers=dict(headers(h), Range="bytes=4-", **{"If-Range": '"wrong"'}))
    assert response.status_code == 200 and response.content == target.read_bytes()


def test_status_does_not_extend_idle_and_immutable_reprepare_keeps_id(prepared):
    h = prepared
    body, _ = request_body(h)
    ticket = wait_state(h, post(h, body).json())
    live = h.preparations.tickets[ticket["ticket_id"]]
    live.last_active -= 121
    expired = h.client.get(ticket["status_url"], headers=headers(h)).json()
    assert expired["state"] == "expired" and live.resource is None
    assert h.client.get(ticket["content_url"], headers=headers(h)).status_code == 503
    renewed = post(h, body)
    assert renewed.status_code == 202 and renewed.json()["ticket_id"] == ticket["ticket_id"]
    assert wait_state(h, renewed.json())["state"] == "ready"


def test_persistent_ready_identity_requires_full_reprepare_after_process_restart(tmp_path):
    identity = {"operation_id": "file-a", "job_id": "job-a", "work_unit_id": "unit-a",
                "attempt_id": "attempt-a", "file": "results/a", "manifest_sha256": "a" * 64,
                "size_bytes": 4, "sha256": hashlib.sha256(b"test").hexdigest()}
    directory = tmp_path / "result-preparations"
    directory.mkdir()
    (directory / "ticket-a.json").write_text(json.dumps(dict(identity, ticket_id="ticket-a", actor_id="alice",
        state="ready", checked_bytes=4, total_bytes=4, last_progress_at="old", reason_code=None)))
    manager = ResultPreparations(tmp_path)
    try:
        assert manager.status("ticket-a", "alice", "job-a")["state"] == "reprepare_required"
        with pytest.raises(HTTPException) as not_ready:
            manager.begin_body("ticket-a", "alice", "job-a")
        assert not_ready.value.status_code == 503
        source = tmp_path / "a.bin"
        source.write_bytes(b"test")
        calls = []
        def factory(progress, cancelled):
            calls.append(True)
            handle, metadata = transfer_api.open_verified_result(source, 4, identity["sha256"], progress=progress, cancelled=cancelled)
            return SimpleNamespace(opened_file=handle, reader_pin=None, stat_result=metadata)
        assert manager.prepare("alice", identity, factory)["ticket_id"] == "ticket-a"
        manager.tickets["ticket-a"].worker.join(3)
        assert manager.status("ticket-a", "alice", "job-a")["state"] == "ready" and len(calls) == 1
    finally:
        manager.close()


def asgi_scope(path, selected):
    return {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}, "http_version": "1.1",
            "method": "GET", "scheme": "http", "path": path, "raw_path": path.encode(),
            "query_string": b"", "root_path": "", "server": ("testserver", 80), "client": ("127.0.0.1", 123),
            "headers": [(k.lower().encode(), v.encode()) for k, v in selected.items()]}


def test_real_asgi_disconnect_reuses_same_verified_handle_and_pin(prepared, monkeypatch):
    h = prepared
    payload = b"synthetic\x00" * 250000
    body, _ = request_body(h, payload=payload)
    calls = []
    original = transfer_api.open_verified_result
    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(transfer_api, "open_verified_result", counted)
    ticket = wait_state(h, post(h, body).json())
    live = h.preparations.tickets[ticket["ticket_id"]]
    stream = live.resource.opened_file
    accepted = bytearray()
    async def disconnect():
        async def receive():
            return {"type": "http.request", "body": b""}
        async def send(message):
            if message["type"] == "http.response.body":
                if accepted:
                    raise ConnectionError("synthetic disconnected client")
                accepted.extend(message["body"])
        await h.app(asgi_scope(ticket["content_url"], headers(h)), receive, send)
    with pytest.raises(ConnectionError):
        asyncio.run(disconnect())
    assert bytes(accepted) == payload[:len(accepted)] and 0 < len(accepted) < len(payload)
    assert live.resource.opened_file is stream and not stream.closed and not live.serving
    response = h.client.get(ticket["content_url"], headers=dict(headers(h), Range=f"bytes={len(accepted)}-", **{"If-Range": ticket["etag"]}))
    assert response.status_code == 206 and bytes(accepted) + response.content == payload
    assert len(calls) == 1


def test_cancel_blocked_verification_does_not_release_drain_activity_early(prepared, monkeypatch):
    h = prepared
    body, _ = request_body(h)
    entered, release = threading.Event(), threading.Event()
    original, streams, sequence = transfer_api.os.fdopen, [], []
    class BlockedReader:
        def __init__(self, stream):
            self.stream = stream
        def __getattr__(self, name):
            return getattr(self.stream, name)
        def read(self, count):
            assert count == 1024**2
            entered.set()
            assert release.wait(5)
            return self.stream.read(count)
        def close(self):
            self.stream.close()
            sequence.append("handle_closed")
    def blocked(descriptor, mode):
        stream = original(descriptor, mode)
        if mode == "rb":
            stream = BlockedReader(stream)
            streams.append(stream)
        return stream
    monkeypatch.setattr(transfer_api.os, "fdopen", blocked)
    lifecycle = h.app.state.storage_lifecycle
    original_pin = lifecycle.pin_reader
    def pin_reader(*args):
        pin = original_pin(*args)
        class OrderedPin:
            def release(self):
                assert streams and all(stream.closed for stream in streams)
                pin.release()
                sequence.append("pin_released")
        return OrderedPin()
    monkeypatch.setattr(lifecycle, "pin_reader", pin_reader)
    try:
        ticket = post(h, body).json()
        assert entered.wait(3)
        response = h.client.delete(ticket["status_url"], headers=headers(h))
        assert response.json()["state"] == "cancelling"
        assert streams and not streams[0].closed and sequence == []
        operation = str(uuid.uuid4())
        status = h.gate.begin(operation, {"fixture": True}, actor_id="admin")
        assert status["active_transfers"] == 1 and status["state"] == "draining"
        assert transfer_api.verification_slots.active == 1
        denied = h.client.get(f"/v1/jobs/{h.job.job_id}/origin-results/{body['work_unit_id']}/attempt-a",
                              params={"file": body["file"]}, headers=headers(h))
        assert denied.status_code == 503 and denied.headers["Retry-After"] == "5"
        assert denied.json()["detail"]["reason_code"] == "release_draining"
        denied = h.client.put(upload_url(h), content=h.archive.read_bytes(), headers=headers(h))
        assert denied.status_code == 503
        assert h.gate.snapshot(operation)["active_transfers"] == 1
        release.set()
        assert wait_state(h, ticket, ("cancelled",))["state"] == "cancelled"
        assert h.gate.snapshot(operation)["state"] == "drained"
        assert transfer_api.verification_slots.active == 0
        assert sequence == ["handle_closed", "pin_released"]
        h.gate.release(operation)
    finally:
        release.set()


def test_drain_closes_idle_ticket_and_release_allows_same_identity(prepared):
    h = prepared
    body, _ = request_body(h)
    ticket = wait_state(h, post(h, body).json())
    h.preparations.tickets[ticket["ticket_id"]].ready_at -= 6
    operation = str(uuid.uuid4())
    assert h.gate.begin(operation, {"fixture": True}, actor_id="admin")["active_transfers"] == 1
    assert wait_state(h, ticket, ("expired",))["reason_code"] == "release_draining"
    assert h.gate.snapshot(operation)["state"] == "drained"
    content = h.client.get(ticket["content_url"], headers=headers(h))
    assert content.status_code == 503 and content.headers["Retry-After"] == "5"
    assert content.json()["detail"] == {"reason_code": "release_draining", "state": "expired"}
    rejected = post(h, dict(body, operation_id="new-operation"))
    assert rejected.status_code == 503 and rejected.headers["Retry-After"] == "5"
    h.gate.release(operation)
    # Releasing the gate does not revive a closed handle. A stale content URL
    # remains retryable until the immutable POST prepares the original ticket.
    assert h.client.get(ticket["content_url"], headers=headers(h)).status_code == 503
    repeated = post(h, body)
    assert repeated.status_code == 202 and repeated.json()["ticket_id"] == ticket["ticket_id"]
    assert wait_state(h, repeated.json())["state"] == "ready"


@pytest.mark.parametrize("consume", [True, False])
def test_drain_keeps_accepted_verification_then_grace_or_content_end_expires(prepared, monkeypatch, consume):
    h = prepared
    body, source = request_body(h)
    entered, resume = threading.Event(), threading.Event()
    original = transfer_api._open_verified_result
    def blocked(*args, **kwargs):
        entered.set()
        assert resume.wait(5)
        return original(*args, **kwargs)
    monkeypatch.setattr(transfer_api, "_open_verified_result", blocked)
    operation = str(uuid.uuid4())
    try:
        first = post(h, body).json()
        assert entered.wait(3)
        second = post(h, dict(body, operation_id="second-accepted")).json()
        assert h.gate.begin(operation, {"fixture": True}, actor_id="admin")["active_transfers"] == 2
        h.preparations.drain_idle()
        for ticket in (first, second):
            assert not h.preparations.tickets[ticket["ticket_id"]].cancel.is_set()
            assert h.client.get(ticket["status_url"], headers=headers(h)).json()["state"] in {"queued", "verifying"}
        resume.set()
        for ticket in (first, second):
            ready = wait_state(h, ticket)
            assert ready["state"] == "ready"
            if consume:
                content = h.client.get(ticket["content_url"], headers=headers(h))
                assert content.status_code == 200 and content.content == source.read_bytes()
            else:
                h.preparations.drain_idle()
                assert h.client.get(ticket["status_url"], headers=headers(h)).json()["state"] == "ready"
                h.preparations.tickets[ticket["ticket_id"]].ready_at -= 6
                h.preparations.drain_idle()
            expired = h.client.get(ticket["status_url"], headers=headers(h)).json()
            assert expired["state"] == "expired" and expired["reason_code"] == "release_draining"
        assert h.gate.snapshot(operation)["state"] == "drained"
        deferred = post(h, body)
        assert deferred.status_code == 503 and deferred.headers["Retry-After"] == "5"
        h.gate.release(operation)
        repeated = post(h, body)
        assert repeated.status_code == 202 and repeated.json()["ticket_id"] == first["ticket_id"]
        assert wait_state(h, repeated.json())["state"] == "ready"
    finally:
        resume.set()


def test_full_sha_failure_is_terminal_and_releases_real_pin_and_gate(prepared):
    h = prepared
    body, source = request_body(h)
    source.write_bytes(b"!" * body["size_bytes"])
    ticket = post(h, body).json()
    result = wait_state(h, ticket, ("failed",))
    assert result["reason_code"] == "result_unavailable_or_integrity_failed" and result["http_status"] == 409
    assert h.preparations.tickets[ticket["ticket_id"]].resource is None
    operation = str(uuid.uuid4())
    assert h.gate.begin(operation, {"fixture": True}, actor_id="admin")["state"] == "drained"
    h.gate.release(operation)


def test_actual_asgi_upload_disconnect_releases_gate_after_partial_cleanup(prepared):
    h = prepared
    raw, messages = h.archive.read_bytes(), []
    operation = str(uuid.uuid4())
    async def exercise():
        count = 0
        async def receive():
            nonlocal count
            count += 1
            if count == 1:
                return {"type": "http.request", "body": raw[:10], "more_body": True}
            status = await asyncio.to_thread(h.gate.begin, operation, {"fixture": True}, actor_id="admin")
            assert status["active_transfers"] == 1 and status["state"] == "draining"
            assert list(h.center.root.rglob(".upload-*"))
            return {"type": "http.disconnect"}
        async def send(message):
            messages.append(message)
        scope = asgi_scope(upload_url(h), headers(h))
        scope["method"] = "PUT"
        await h.app(scope, receive, send)
    asyncio.run(exercise())
    assert messages[0]["status"] == 400
    assert not list(h.center.root.rglob(".upload-*"))
    assert h.gate.snapshot(operation)["state"] == "drained"
    h.gate.release(operation)


def test_real_asgi_legacy_get_keeps_gate_until_body_ends(prepared):
    h = prepared
    body, _ = request_body(h, payload=b"x" * (2 * 1024**2 + 9))
    base = f"/v1/jobs/{h.job.job_id}/origin-results/{body['work_unit_id']}/attempt-a"
    operation = str(uuid.uuid4())
    async def exercise():
        entered, resume = asyncio.Event(), asyncio.Event()
        async def receive():
            return {"type": "http.request", "body": b""}
        async def send(message):
            if message["type"] == "http.response.body" and not entered.is_set():
                entered.set()
                await resume.wait()
        scope = asgi_scope(base, headers(h))
        scope["query_string"] = b"file=results%2Fresult.txt"
        task = asyncio.create_task(h.app(scope, receive, send))
        await asyncio.wait_for(entered.wait(), 3)
        status = await asyncio.to_thread(h.gate.begin, operation, {"fixture": True}, actor_id="admin")
        assert status["active_transfers"] == 1 and status["state"] == "draining"
        resume.set()
        await task
    asyncio.run(exercise())
    assert h.gate.snapshot(operation)["state"] == "drained"
    h.gate.release(operation)


def test_real_asgi_body_survives_idle_ttl_and_cancel_closes_after_body(prepared):
    h = prepared
    body, _ = request_body(h, payload=b"x" * (2 * 1024**2 + 9))
    ticket = wait_state(h, post(h, body).json())
    live = h.preparations.tickets[ticket["ticket_id"]]
    stream = live.resource.opened_file
    async def exercise():
        entered, resume = asyncio.Event(), asyncio.Event()
        async def receive():
            return {"type": "http.request", "body": b""}
        async def send(message):
            if message["type"] == "http.response.body" and not entered.is_set():
                entered.set()
                await resume.wait()
        task = asyncio.create_task(h.app(asgi_scope(ticket["content_url"], headers(h)), receive, send))
        await asyncio.wait_for(entered.wait(), 3)
        live.last_active -= 200
        assert (await asyncio.to_thread(h.client.get, ticket["status_url"], headers=headers(h))).json()["state"] == "ready"
        assert not stream.closed
        cancelled = await asyncio.to_thread(h.client.delete, ticket["status_url"], headers=headers(h))
        assert cancelled.json()["state"] == "cancelling" and not stream.closed
        resume.set()
        with pytest.raises(PreparationCancelled):
            await task
    asyncio.run(exercise())
    assert stream.closed and not live.serving and live.resource is None
    assert h.client.get(ticket["status_url"], headers=headers(h)).json()["state"] == "cancelled"


def test_verification_slots_limit_global_two_and_one_per_volume():
    slots = VerificationSlots()
    slots.acquire("volume-a")
    slots.acquire("volume-b")
    entered, cancelled = threading.Event(), threading.Event()
    def waiting():
        with pytest.raises(PreparationCancelled):
            slots.acquire("volume-a", cancelled.is_set)
        entered.set()
    worker = threading.Thread(target=waiting)
    worker.start()
    assert not entered.wait(0.05) and slots.active == 2
    cancelled.set()
    worker.join(2)
    assert entered.is_set() and slots.active == 2
    slots.release("volume-a")
    slots.release("volume-b")


def test_ready_ticket_limits_actor_two_global_eight(tmp_path):
    manager = ResultPreparations(tmp_path)
    held = threading.Event()
    identity = {"operation_id": "one", "job_id": "j", "work_unit_id": "u", "attempt_id": "a",
                "file": "f", "manifest_sha256": "a" * 64, "size_bytes": 1, "sha256": "a" * 64}
    def blocked(progress, cancelled):
        held.wait(5)
        raise PreparationCancelled()
    try:
        for actor in range(4):
            for operation in ("one", "two"):
                manager.prepare(str(actor), dict(identity, operation_id=operation), blocked)
            if actor == 0:
                with pytest.raises(HTTPException) as limited:
                    manager.prepare("0", dict(identity, operation_id="three"), blocked)
                assert limited.value.status_code == 429
        with pytest.raises(HTTPException) as limited:
            manager.prepare("4", identity, blocked)
        assert limited.value.status_code == 429
    finally:
        held.set()
        manager.close()


def test_terminal_cache_is_bounded_and_exact_operation_index_survives_restart(tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"test")
    identity = {"operation_id": "operation-0", "job_id": "job-a", "work_unit_id": "unit-a",
                "attempt_id": "attempt-a", "file": "results/a", "manifest_sha256": "a" * 64,
                "size_bytes": 4, "sha256": hashlib.sha256(b"test").hexdigest()}
    manager = ResultPreparations(tmp_path, terminal_cache_limit=3)
    def factory(progress, cancelled):
        stream, metadata = transfer_api.open_verified_result(source, 4, identity["sha256"], progress=progress, cancelled=cancelled)
        return SimpleNamespace(opened_file=stream, reader_pin=None, stat_result=metadata)
    originals = []
    try:
        for number in range(11):
            request = dict(identity, operation_id=f"operation-{number}")
            view = manager.prepare("alice", request, factory)
            ticket = manager.tickets[view["ticket_id"]]
            ticket.worker.join(3)
            manager.cancel_ticket(view["ticket_id"], "alice", "job-a")
            originals.append(view["ticket_id"])
            assert len(manager.tickets) <= 3 and len(manager.operations) <= 3
        with pytest.raises(HTTPException) as conflict:
            manager.prepare("alice", dict(identity, file="different-file"), factory)
        assert conflict.value.status_code == 409 and conflict.value.detail["reason_code"] == "operation_id_conflict"
        assert manager.status(originals[0], "alice", "job-a")["state"] == "cancelled"
    finally:
        manager.close()
    # Startup reads neither historical JSON documents nor historical SQL rows.
    with monkeypatch.context() as context:
        context.setattr(Path, "read_text", lambda *args, **kwargs: pytest.fail("startup read historical ticket JSON"))
        restarted = ResultPreparations(tmp_path, terminal_cache_limit=3)
    try:
        assert not restarted.tickets and not restarted.operations
        repeated = restarted.prepare("alice", identity, factory)
        assert repeated["ticket_id"] == originals[0]
        restarted.tickets[originals[0]].worker.join(3)
        assert restarted.status(originals[0], "alice", "job-a")["state"] == "ready"
        with pytest.raises(HTTPException) as conflict:
            restarted.prepare("alice", dict(identity, size_bytes=5), factory)
        assert conflict.value.status_code == 409
        for ticket_id in originals[1:]:
            assert restarted.status(ticket_id, "alice", "job-a")["state"] == "cancelled"
            assert len(restarted.tickets) <= 4 and len(restarted.operations) <= 4
    finally:
        restarted.close()


def test_idle_sweeper_exits_and_next_admission_restarts_it(tmp_path):
    manager = ResultPreparations(tmp_path)
    identity = {"operation_id": "one", "job_id": "j", "work_unit_id": "u", "attempt_id": "a",
                "file": "f", "manifest_sha256": "a" * 64, "size_bytes": 1, "sha256": "a" * 64}
    def refused(progress, cancelled):
        raise PreparationCancelled()
    try:
        first = manager.prepare("alice", identity, refused)
        manager.tickets[first["ticket_id"]].worker.join(3)
        sweeper = manager.sweeper
        sweeper.join(3)
        assert not sweeper.is_alive() and manager.sweeper is None
        second = manager.prepare("alice", dict(identity, operation_id="two"), refused)
        assert manager.sweeper is not None and manager.sweeper is not sweeper
        manager.tickets[second["ticket_id"]].worker.join(3)
    finally:
        manager.close()
