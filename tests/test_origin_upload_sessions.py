"""HTTP continuation tests use synthetic Jobs only, never scientific execution."""
import hashlib
import io
import gzip
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
import uvicorn

from test_origin_transfer import handoff, headers
from research_compute_network.client import RcnApiError, RcnClient
from research_compute_network.hashing import sha256_file
from research_compute_network.models import FileRecord
from research_compute_network.origin_assets import asset_path
from research_compute_network.origin_transfer_api import OriginTransferStore
from research_compute_network.origin_transfer_client import OriginTransferClient
from research_compute_network.origin_upload_sessions import UploadSessions, UPLOAD_CHUNK_BYTES
from research_compute_network.release_maintenance import get_transfer_gate
from research_compute_network.volume_budget import VolumeBudget, HARD_RESERVE_BYTES


def base(h):
    return f"/v1/jobs/{h.job.job_id}/origin-upload-sessions"


def init(h, *, data=None, kind="bundle", target=None, size=None, digest=None):
    data = h.archive.read_bytes() if data is None else data
    body = dict(kind=kind, target_id=target or h.job.work_units[0].work_unit_id,
                size_bytes=len(data) if size is None else size,
                sha256=digest or hashlib.sha256(data).hexdigest(), encoding="identity")
    response = h.client.post(base(h), headers=headers(h), json=body)
    assert response.status_code == 200, response.text
    return response.json(), body


def chunk(h, session, data, offset=0, **overrides):
    selected = dict(headers(h), **{"Content-Length": str(len(data)), "Upload-Offset": str(offset),
                                  "X-RCN-SHA256": hashlib.sha256(data).hexdigest()})
    selected.update(overrides)
    return h.client.put(base(h) + "/" + session["session_id"] + "/chunk", content=data, headers=selected)


def wait_done(h, session, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = h.client.get(base(h) + "/" + session["session_id"], headers=headers(h))
        assert response.status_code == 200, response.text
        document = response.json()
        if document["state"] in {"completed", "failed"}:
            return document
        time.sleep(.02)
    pytest.fail("synthetic upload verification did not finish")


def manager(h):
    store = OriginTransferStore(h.center.root, budget_database=h.repo.engine.url.database)
    return UploadSessions(store, h.tmp_path / "center", repository=h.repo)


def test_session_rows_share_original_repository_and_preparation_index(handoff):
    from sqlalchemy import inspect
    from research_compute_network.repository import MetadataRepository
    h = handoff
    session, _ = init(h)
    assert inspect(h.repo.engine).has_table("origin_upload_sessions")
    assert not (h.tmp_path / "center/origin-upload-sessions/index.sqlite3").exists()
    assert not (h.tmp_path / "center/origin-upload-sessions/result-preparations").exists()
    assert chunk(h, session, h.archive.read_bytes()).status_code == 200
    fresh = MetadataRepository(str(h.repo.engine.url))
    try:
        selected = UploadSessions(OriginTransferStore(h.center.root, budget_database=h.repo.engine.url.database),
                                  h.tmp_path / "center", repository=fresh)
        assert selected.read(session["session_id"], "alice", h.job.job_id)["offset"] == h.archive.stat().st_size
        with h.repo.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA synchronous").scalar_one() == 1
    finally:
        fresh.engine.dispose()


def test_cross_job_legacy_gzip_and_resumable_writers_share_exact_claim(handoff, monkeypatch):
    h = handoff
    raw = os.urandom(1024**2)
    digest = hashlib.sha256(raw).hexdigest()
    h.job.input_manifest.append(FileRecord(relative_path="input/project/common.bin", size_bytes=len(raw), sha256=digest))
    h.repo.put_job(h.job)
    other = h.job.model_copy(deep=True, update={"job_id": "other-" + uuid.uuid4().hex, "revision": 0,
        "request_hash": hashlib.sha256((h.job.request_hash + "other").encode()).hexdigest()})
    h.repo.put_job(other)
    session, body = init(h, kind="asset", target=digest, data=raw)
    other_base = f"/v1/jobs/{other.job_id}/origin-upload-sessions"
    response = h.client.post(other_base, json=body, headers=headers(h))
    assert response.status_code == 200, response.text
    other_session = response.json()
    selected = manager(h)
    writer = selected.begin_chunk(session["session_id"], "alice", h.job.job_id, 0, len(raw))
    encoded = gzip.compress(raw, mtime=0)
    legacy_headers = dict(headers(h), **{"Content-Encoding": "gzip", "Content-Length": str(len(encoded)),
                                          "X-RCN-SHA256": hashlib.sha256(encoded).hexdigest()})
    legacy_url = f"/v1/jobs/{other.job_id}/origin-assets/{digest}"
    try:
        assert h.client.put(legacy_url, headers=legacy_headers, content=encoded).status_code == 429
        response = h.client.put(other_base + "/" + other_session["session_id"] + "/chunk", content=raw,
            headers=dict(headers(h), **{"Content-Length": str(len(raw)), "Upload-Offset": "0", "X-RCN-SHA256": digest}))
        assert response.status_code == 409
        assert len(selected.store.volume_budget.active_claims()) == 1
    finally:
        writer.close()
    entered, resume = threading.Event(), threading.Event()
    original = OriginTransferStore.create_temporary
    def hold_legacy(self, target, prefix):
        if prefix == ".asset-upload-":
            entered.set()
            assert resume.wait(10)
        return original(self, target, prefix)
    monkeypatch.setattr(OriginTransferStore, "create_temporary", hold_legacy)
    result = []
    worker = threading.Thread(target=lambda: result.append(h.client.put(legacy_url, headers=legacy_headers, content=encoded)))
    worker.start()
    try:
        assert entered.wait(5)
        assert chunk(h, session, raw).status_code == 429
        claims = selected.store.volume_budget.active_claims()
        assert len(claims) == 1 and claims[0]["required_bytes"] == len(encoded) + len(raw)
    finally:
        resume.set()
        worker.join(10)
    assert result[0].status_code == 200
    assert selected.store.volume_budget.active_claims() == []


def test_chunk_truncated_replay_conflict_identity_and_final_publication(handoff):
    h = handoff
    raw = h.archive.read_bytes()
    session, body = init(h)
    assert session["offset"] == 0 and session["chunk_bytes"] == UPLOAD_CHUNK_BYTES
    url = base(h) + "/" + session["session_id"]
    assert h.client.get(url, headers=headers(h, "bob")).status_code == 403
    assert h.client.post(base(h), headers=headers(h), json=dict(body, sha256="0" * 64)).status_code == 409
    truncated = chunk(h, session, raw[:-1], **{"Content-Length": str(len(raw))})
    assert truncated.status_code == 422
    assert h.client.get(url, headers=headers(h)).json()["offset"] == 0
    assert chunk(h, session, raw).status_code == 200
    assert chunk(h, session, raw).status_code == 200
    assert chunk(h, session, b"x" * len(raw)).status_code == 409
    assert h.client.post(url + "/finalize", headers=headers(h)).status_code == 202
    assert wait_done(h, session)["state"] == "completed"
    assert h.center.outgoing_path(h.job, h.job.work_units[0]).read_bytes() == raw
    assert not list(h.center.root.rglob("*.partial"))
    assert VolumeBudget(h.repo.engine.url.database).active_claims() == []


@pytest.mark.parametrize("blocked_cleanup", ["unlink", "claim_release"])
def test_completed_is_not_visible_until_partial_and_claim_are_released(handoff, monkeypatch, blocked_cleanup):
    h = handoff
    session, _ = init(h)
    assert chunk(h, session, h.archive.read_bytes()).status_code == 200
    selected = manager(h)
    document = selected.read(session["session_id"], "alice", h.job.job_id)
    partial = selected.partial(document)
    entered, proceed = threading.Event(), threading.Event()
    if blocked_cleanup == "unlink":
        original = Path.unlink
        def blocked(path, *args, **kwargs):
            if path == partial:
                entered.set()
                assert proceed.wait(15)
            return original(path, *args, **kwargs)
        monkeypatch.setattr(Path, "unlink", blocked)
    else:
        original = OriginTransferStore.release
        def blocked(store, key):
            if key == document["_holder_key"]:
                entered.set()
                assert proceed.wait(15)
            return original(store, key)
        monkeypatch.setattr(OriginTransferStore, "release", blocked)
    try:
        url = base(h) + "/" + session["session_id"]
        assert h.client.post(url + "/finalize", headers=headers(h)).status_code == 202
        assert entered.wait(5)
        # The canonical link exists already, but its owned cleanup is deliberately
        # blocked. Observing completed now is a protocol error, not a slow test.
        assert h.center.outgoing_path(h.job, h.job.work_units[0]).read_bytes() == h.archive.read_bytes()
        status = h.client.get(url, headers=headers(h)).json()
        assert status["state"] == "verifying" and status["ready"] is False
        assert partial.exists() is (blocked_cleanup == "unlink")
        assert len(selected.store.volume_budget.active_claims()) == 1
    finally:
        proceed.set()
        wait_done(h, session)
    assert not partial.exists()
    assert selected.store.volume_budget.active_claims() == []


@pytest.mark.parametrize("failure", ["sha", "archive"])
def test_final_verifier_rejects_bad_full_hash_or_original_contract(handoff, failure):
    h = handoff
    raw = h.archive.read_bytes() if failure == "sha" else b"not-a-sealed-bundle"
    session, _ = init(h, data=raw, digest="0" * 64 if failure == "sha" else None)
    assert chunk(h, session, raw).status_code == 200
    assert h.client.post(base(h) + "/" + session["session_id"] + "/finalize", headers=headers(h)).status_code == 202
    assert wait_done(h, session)["state"] == "failed"
    assert not h.center.outgoing_path(h.job, h.job.work_units[0]).exists()


def test_chunk_capacity_limit_and_cancel_release(handoff, monkeypatch):
    h = handoff
    session, _ = init(h)
    # Change existing instance's live capacity probe through the route manager.
    selected = manager(h)
    monkeypatch.setattr(selected.store.volume_budget, "free_bytes", lambda _: HARD_RESERVE_BYTES)
    with pytest.raises(Exception) as exc:
        selected.begin_chunk(session["session_id"], "alice", h.job.job_id, 0, h.archive.stat().st_size)
    assert exc.value.status_code == 507
    assert selected.status(session["session_id"], "alice", h.job.job_id)["offset"] == 0
    # Even this same low-space manager can cancel without making a write claim.
    assert selected.cancel(session["session_id"], "alice", h.job.job_id)["state"] == "cancelled"
    assert not list(h.center.root.rglob("*.partial"))
    assert VolumeBudget(h.repo.engine.url.database).active_claims() == []


def test_cross_process_lock_and_crash_offset_recovery(handoff):
    h = handoff
    session, _ = init(h)
    selected = manager(h)
    writer = selected.begin_chunk(session["session_id"], "alice", h.job.job_id, 0, h.archive.stat().st_size)
    script = """
import sys
from pathlib import Path
from research_compute_network.origin_transfer_api import OriginTransferStore
from research_compute_network.origin_upload_sessions import UploadSessions
from research_compute_network.repository import MetadataRepository
repo=MetadataRepository('sqlite:///'+Path(sys.argv[2]).as_posix())
m=UploadSessions(OriginTransferStore(Path(sys.argv[1]),budget_database=sys.argv[2]),Path(sys.argv[3]),repository=repo)
try:
    w=m.begin_chunk(sys.argv[4],'alice',sys.argv[5],0,int(sys.argv[6]))
except Exception as e:
    print(getattr(e,'status_code',0)); sys.exit(0)
sys.exit(9)
"""
    args = [sys.executable, "-c", script, str(h.center.root), h.repo.engine.url.database,
            str(h.tmp_path / "center"), session["session_id"], h.job.job_id, str(h.archive.stat().st_size)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=15,
                            env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src")),
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0 and result.stdout.strip() == "409", result.stderr
    writer.close()
    crash = script[:script.index("try:")] + """
import os
w=m.begin_chunk(sys.argv[4],'alice',sys.argv[5],0,int(sys.argv[6]))
with w.partial.open('ab') as out:
    out.write(b'unconfirmed bytes'); out.flush(); os.fsync(out.fileno())
os._exit(17)
"""
    args[2] = crash
    assert subprocess.run(args, timeout=15,
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src")),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).returncode == 17
    assert len(VolumeBudget(h.repo.engine.url.database).active_claims()) == 1
    # OS lock + exact process exit prove recovery; unconfirmed tail is discarded.
    assert chunk(h, session, h.archive.read_bytes()).status_code == 200
    assert selected.status(session["session_id"], "alice", h.job.job_id)["offset"] == h.archive.stat().st_size
    assert VolumeBudget(h.repo.engine.url.database).active_claims() == []


@pytest.mark.parametrize("revocation", ["user", "token"])
def test_finalization_is_202_drain_counts_verifier_and_revocation_rechecks(handoff, monkeypatch, revocation):
    h = handoff
    session, _ = init(h)
    assert chunk(h, session, h.archive.read_bytes()).status_code == 200
    entered, release = threading.Event(), threading.Event()
    original = OriginTransferStore.publish
    def delayed(self, *args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(self, *args, **kwargs)
    monkeypatch.setattr(OriginTransferStore, "publish", delayed)
    before = time.monotonic()
    assert h.client.post(base(h) + "/" + session["session_id"] + "/finalize", headers=headers(h)).status_code == 202
    assert time.monotonic() - before < 2
    assert entered.wait(5)
    gate = get_transfer_gate(h.tmp_path / "center")
    maintenance = str(uuid.uuid4())
    assert gate.begin(maintenance, {}, actor_id="admin")["active_transfers"] == 1
    assert chunk(h, session, h.archive.read_bytes()).status_code == 503
    if revocation == "user":
        user = h.repo.get_user("alice")
        user.active = False
        h.repo.put_user(user)
    else:
        token = h.repo.get_token_by_hash(hashlib.sha256(h.tokens["alice"].encode()).hexdigest())
        h.app.state.service.revoke_token(token.token_id, actor_id="admin")
    release.set()
    selected = manager(h)
    deadline = time.monotonic() + 10
    while selected.status(session["session_id"], "alice", h.job.job_id)["state"] == "verifying" and time.monotonic() < deadline:
        time.sleep(.02)
    assert selected.status(session["session_id"], "alice", h.job.job_id)["state"] == "failed"
    assert not h.center.outgoing_path(h.job, h.job.work_units[0]).exists()
    while gate.snapshot(maintenance)["active_transfers"] and time.monotonic() < deadline:
        time.sleep(.02)
    assert gate.snapshot(maintenance)["active_transfers"] == 0
    gate.release(maintenance)


def test_four_upload_writer_limit_includes_legacy_and_no_idle_claims(handoff):
    h = handoff
    records = [FileRecord(relative_path=f"project/asset-{i}", size_bytes=1,
                sha256=hashlib.sha256(bytes([i])).hexdigest()) for i in range(4)]
    h.job.input_manifest.extend(records)
    h.repo.put_job(h.job)
    sessions = [init(h, data=bytes([i]), kind="asset", target=record.sha256)[0] for i, record in enumerate(records)]
    selected = manager(h)
    assert selected.store.volume_budget.active_claims() == []
    writers = []
    try:
        for session in sessions[:3]:
            writers.append(selected.begin_chunk(session["session_id"], "alice", h.job.job_id, 0, 1))
        selected.store.reserve("legacy-upload", 1)
        with pytest.raises(Exception) as exc:
            selected.begin_chunk(sessions[3]["session_id"], "alice", h.job.job_id, 0, 1)
        assert exc.value.status_code == 429
        assert len(selected.store.volume_budget.active_claims()) == 4
        selected.store.release("legacy-upload")
        writers.append(selected.begin_chunk(sessions[3]["session_id"], "alice", h.job.job_id, 0, 1))
        assert sum(c["required_bytes"] for c in selected.store.volume_budget.active_claims()) == 4
    finally:
        selected.store.release("legacy-upload")
        for writer in writers:
            writer.close()
    assert selected.store.volume_budget.active_claims() == []


def test_managed_storage_pause_rejects_chunk_without_losing_session(handoff):
    from research_compute_network.storage_ops import set_write_pause
    h = handoff
    session, _ = init(h)
    args = dict(roles=["origin_spool"], operation_id="fixture-move", actor_id="admin", reason="synthetic migration")
    set_write_pause(h.tmp_path / "center", paused=True, **args)
    response = chunk(h, session, h.archive.read_bytes())
    assert response.status_code == 409 and response.json()["detail"]["reason_code"] == "storage_write_paused"
    assert h.client.get(base(h) + "/" + session["session_id"], headers=headers(h)).json()["offset"] == 0
    set_write_pause(h.tmp_path / "center", paused=False, **args)
    assert chunk(h, session, h.archive.read_bytes()).status_code == 200


def test_verification_restart_retains_full_offset(handoff):
    h = handoff
    session, _ = init(h)
    assert chunk(h, session, h.archive.read_bytes()).status_code == 200
    selected = manager(h)
    script = """
import os,sys,time
from pathlib import Path
from research_compute_network.origin_transfer_api import OriginTransferStore
from research_compute_network.origin_upload_sessions import UploadSessions
from research_compute_network.repository import MetadataRepository
repo=MetadataRepository('sqlite:///'+Path(sys.argv[2]).as_posix())
m=UploadSessions(OriginTransferStore(Path(sys.argv[1]),budget_database=sys.argv[2]),Path(sys.argv[3]),repository=repo)
def lost_process(*args):
    os._exit(18)
m.finalize(sys.argv[4],'alice',sys.argv[5],lambda _:None,lost_process)
time.sleep(10)
"""
    result = subprocess.run([sys.executable, "-c", script, str(h.center.root), h.repo.engine.url.database,
        str(h.tmp_path / "center"), session["session_id"], h.job.job_id], timeout=15,
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src")),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 18
    status = h.client.get(base(h) + "/" + session["session_id"], headers=headers(h)).json()
    assert status["state"] == "uploading" and status["offset"] == len(h.archive.read_bytes())
    assert h.client.post(base(h) + "/" + session["session_id"] + "/finalize", headers=headers(h)).status_code == 202
    assert wait_done(h, session)["state"] == "completed"


@pytest.mark.parametrize("release_claim", [False, True])
def test_restart_after_partial_cleanup_revalidates_canonical_without_reupload(handoff, release_claim):
    h = handoff
    session, _ = init(h)
    assert chunk(h, session, h.archive.read_bytes()).status_code == 200
    selected = manager(h)
    script = """
import os,sys,time
from pathlib import Path
from research_compute_network.origin_transfer_api import OriginTransferStore
from research_compute_network.origin_upload_sessions import UploadSessions
from research_compute_network.repository import MetadataRepository
repo=MetadataRepository('sqlite:///'+Path(sys.argv[2]).as_posix())
store=OriginTransferStore(Path(sys.argv[1]),budget_database=sys.argv[2])
m=UploadSessions(store,Path(sys.argv[3]),repository=repo)
job=repo.get_job(sys.argv[5])
release=store.release
def crash_during_cleanup(key):
    if sys.argv[6]=='True':
        release(key)
    os._exit(19)
store.release=crash_during_cleanup
def publish(document, partial, recheck):
    return store.publish(job,job.work_units[0],partial,before_publish=recheck)
m.finalize(sys.argv[4],'alice',sys.argv[5],lambda _:None,publish)
time.sleep(10)
"""
    result = subprocess.run([sys.executable, "-c", script, str(h.center.root), h.repo.engine.url.database,
        str(h.tmp_path / "center"), session["session_id"], h.job.job_id, str(release_claim)], timeout=15,
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src")),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 19
    document = selected.read(session["session_id"], "alice", h.job.job_id)
    assert document["state"] == "verifying" and document["_validation_only"] is True
    assert not selected.partial(document).exists()
    assert len(selected.store.volume_budget.active_claims()) == (0 if release_claim else 1)
    canonical = h.center.outgoing_path(h.job, h.job.work_units[0])
    assert canonical.read_bytes() == h.archive.read_bytes()
    url = base(h) + "/" + session["session_id"]
    status = h.client.get(url, headers=headers(h)).json()
    assert status["state"] == "uploading" and status["offset"] == h.archive.stat().st_size
    assert status["verification_required"] is True
    assert h.client.post(url + "/finalize", headers=headers(h)).status_code == 202
    completed = wait_done(h, session)
    assert completed["state"] == "completed" and completed["receipt"]["already_present"] is True
    assert not selected.partial(document).exists()
    assert selected.store.volume_budget.active_claims() == []
    assert canonical.read_bytes() == h.archive.read_bytes()


def test_existing_and_resealed_publication_is_reverified_without_new_bytes(handoff):
    h = handoff
    unit = h.job.work_units[0]
    url = f"/v1/jobs/{h.job.job_id}/origin-bundles/{unit.work_unit_id}"
    assert h.client.put(url, headers=headers(h), content=h.archive.read_bytes()).status_code == 200
    session, _ = init(h)
    assert session["offset"] == h.archive.stat().st_size
    assert wait_done(h, session)["receipt"]["already_present"] is True
    h.center.reseal_runtime(h.job, unit, "runtime-next")
    session, _ = init(h)
    assert wait_done(h, session)["receipt"]["already_present"] is True
    assert not list(h.center.root.rglob("*.partial"))
    h.center.outgoing_path(h.job, unit).write_bytes(b"corrupt")
    session, _ = init(h)
    assert wait_done(h, session)["state"] == "failed"


def test_public_client_rejects_legacy_capabilities(monkeypatch):
    client = OriginTransferClient(RcnClient("https://member.example"), require_resumable_uploads=True)
    monkeypatch.setattr(client, "_open", lambda *_args, **_kwargs: io.BytesIO(b'{"protocol":1,"enabled":true}'))
    with pytest.raises(RcnApiError) as exc:
        client.require_available()
    assert exc.value.reason_code == "resumable_uploads_required"


def test_8gib_boundary_sparse_partial_uses_64bit_offset(handoff):
    h = handoff
    size = 8 * 1024**3
    session, body = init(h, size=size, digest="1" * 64)
    assert h.client.post(base(h), headers=headers(h), json=dict(body, size_bytes=size + 1)).status_code == 422
    selected = manager(h)
    document = selected.read(session["session_id"], "alice", h.job.job_id)
    partial = selected.partial(document)
    with partial.open("r+b") as output:
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes
            ioctl = ctypes.WinDLL("kernel32", use_last_error=True).DeviceIoControl
            ioctl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                              ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
            ioctl.restype = wintypes.BOOL
            returned = wintypes.DWORD()
            assert ioctl(msvcrt.get_osfhandle(output.fileno()), 0x900C4, None, 0, None, 0, ctypes.byref(returned), None)
        output.truncate(size - UPLOAD_CHUNK_BYTES)
    document["offset"] = size - UPLOAD_CHUNK_BYTES
    selected.save(document)
    last = os.urandom(UPLOAD_CHUNK_BYTES)
    response = chunk(h, session, last, size - UPLOAD_CHUNK_BYTES)
    assert response.status_code == 200 and response.json()["offset"] == size
    assert partial.stat().st_size == size
    # Boundary fixture deliberately does not claim an 8-GiB full SHA run.
    assert h.client.delete(base(h) + "/" + session["session_id"], headers=headers(h)).status_code == 200


def test_105mib_incompressible_real_http_lost_response_resumes(handoff, monkeypatch):
    h = handoff
    source = h.tmp_path / "incompressible.bin"
    with source.open("wb") as output:
        for _ in range(105):
            output.write(os.urandom(1024**2))
    digest, size = sha256_file(source), source.stat().st_size
    h.job.input_manifest.append(FileRecord(relative_path="project/incompressible.bin", size_bytes=size, sha256=digest))
    h.repo.put_job(h.job)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(h.app, log_level="error", lifespan="off"))
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    worker.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(.02)
    client = OriginTransferClient(RcnClient(f"http://127.0.0.1:{listener.getsockname()[1]}", h.tokens["alice"]),
                                  require_resumable_uploads=True)
    original, sent, lost = client._open, [], [False]
    def lose_reply(path, **kwargs):
        response = original(path, **kwargs)
        if path.endswith("/chunk"):
            sent.append((int(kwargs["headers"]["Upload-Offset"]), int(kwargs["headers"]["Content-Length"])))
            if not lost[0]:
                lost[0] = True
                response.read()
                response.close()
                raise RcnApiError(0, "synthetic lost ACK")
        return response
    monkeypatch.setattr(client, "_open", lose_reply)
    try:
        receipt, _, _ = client._upload_resumable(h.job.job_id, "asset", digest, source, size, digest, client.require_available())
        assert receipt["ready"] and receipt["sha256"] == digest
        assert len(sent) == 14 and max(length for _, length in sent) == UPLOAD_CHUNK_BYTES
        assert len({offset for offset, _ in sent}) == len(sent)
        assert sum(length for _, length in sent) == size
        assert sha256_file(asset_path(h.center.root, h.job, digest)) == digest
        assert not list(h.center.root.rglob("*.partial"))
    finally:
        server.should_exit = True
        worker.join(10)
        listener.close()
