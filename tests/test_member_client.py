import json
import os
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
import threading
import time
from uuid import uuid4

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from research_compute_network.client import RcnApiError
from research_compute_network.member_client import MemberBroker, Login, create_member_app, member_api_client
from research_compute_network.member_client_credentials import PersonalCredentialStore
from research_compute_network.hashing import sha256_file, sha256_value
from research_compute_network.models import ArtifactManifest, FileRecord, JobStatus, WorkUnitAttempt, WorkUnitStatus
from research_compute_network.origin_transfer import TRANSFER_PROTOCOL
from research_compute_network.origin_transfer_client import OriginTransferClient
from research_compute_network.runtime_policy import STABLE_RUNTIME_VERSION
from research_compute_network.submission_operations import put_submission_operation, confirm_submission_operation
from conftest import approved_grant
from test_member_submission_operations import package


@pytest.fixture(autouse=True)
def isolated_collection_volume_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("RCN_COLLECTION_STATE_HOME", str(tmp_path / "collection-state"))


class Credentials:
    def __init__(self):
        self.value = None
    def save(self, **value):
        self.value = value
    def load(self):
        return self.value
    def clear(self):
        self.value = None


def application(tmp_path, service, *, transfer_factory=OriginTransferClient, static_root=None,
                ensure_running_callback=None):
    service.register_project(approved_grant(), actor_id="admin")
    class API:
        def __init__(self, url, token):
            self.actor = "user-a" if token == "personal-a" else "user-b"
        def current_actor(self):
            return {"actor_id": self.actor, "roles": ["member"]}
        def _request(self, method, path, payload=None):
            op_id = path.split("/")[3]
            if method == "PUT":
                from research_compute_network.submission_operations import SubmissionOperationRequest
                return put_submission_operation(service, op_id, SubmissionOperationRequest.model_validate(payload), actor_id=self.actor).model_dump(mode="json")
            if method == "POST":
                receipt = confirm_submission_operation(service, op_id, actor_id=self.actor)
                if fail_after_confirm:
                    fail_after_confirm.pop()
                    raise RcnApiError(0, "synthetic lost response")
                return receipt.model_dump(mode="json")
            receipt = service.repository.get_submission_operation(op_id)
            return receipt.model_dump(mode="json")
        def get_job_status(self, job_id):
            return service.repository.get_job(job_id).model_dump(mode="json")
        get_job = get_job_status
        def execution_runtime(self):
            return {"runtime_version": STABLE_RUNTIME_VERSION}
        def ensure_running(self):
            if ensure_running_callback:
                ensure_running_callback()
            return {"running": True}
        def collect_artifacts(self, job_id):
            return [item.model_dump(mode="json") for item in service.repository.list_artifact_manifests(job_id)]
        @property
        def base_url(self):
            return "https://center.example"
        token = None
        timeout = 3
    fail_after_confirm = []
    credentials = Credentials()
    app = create_member_app(state_root=tmp_path / "member", credential_store=credentials, api_factory=API,
                            transfer_factory=transfer_factory, static_root=static_root)
    return app, credentials, fail_after_confirm


def login(client):
    assert client.get("/local/v1/capabilities").status_code == 200
    assert client.post("/local/v1/session", json={"center_url": "https://center.example", "token": "personal-a"}).status_code == 200


def test_local_client_lost_confirm_response_restart_and_explicit_rerun(service, tmp_path):
    package(tmp_path)
    app, credentials, fail = application(tmp_path, service)
    with TestClient(app) as browser:
        login(browser)
        with (tmp_path / "request-user-a-demo-analysis-2.zip").open("rb") as stream:
            imported = browser.post("/local/v1/packages", content=stream.read(), headers={"Content-Type": "application/zip"}).json()
        op = str(uuid4())
        options = {"package_id": imported["package_id"]}
        assert browser.put(f"/local/v1/operations/{op}", json=options).status_code == 200
        fail.append(True)
        lost = browser.post(f"/local/v1/operations/{op}/confirm")
        assert lost.status_code == 503
        recovered = browser.get(f"/local/v1/operations/{op}").json()
        original_job = recovered["job_id"]
        assert original_job
        assert browser.post(f"/local/v1/operations/{op}/confirm").json()["job_id"] == original_job
    # Reopen the app from the same private journal and DPAPI-store abstraction.
    restarted = create_member_app(state_root=tmp_path / "member", credential_store=credentials, api_factory=app.state.broker.api_factory)
    with TestClient(restarted) as browser:
        browser.get("/local/v1/capabilities")
        assert browser.get(f"/local/v1/operations/{op}").json()["job_id"] == original_job
        new_op = str(uuid4())
        body = {"operation_id": new_op}
        assert browser.post(f"/local/v1/operations/{op}/rerun", json=body).json()["job_id"] is None
        assert browser.post(f"/local/v1/operations/{op}/rerun", json=body).json()["operation_id"] == new_op
        assert len(service.repository.list_jobs()) == 1
        assert browser.post(f"/local/v1/operations/{new_op}/confirm").json()["job_id"] != original_job
        assert len(service.repository.list_jobs()) == 2


def test_reimport_exact_zip_keeps_original_operation_and_terminal_job_after_broker_restart(service, tmp_path):
    package(tmp_path)
    raw = (tmp_path / "request-user-a-demo-analysis-2.zip").read_bytes()
    app, credentials, _ = application(tmp_path, service)
    with TestClient(app) as browser:
        login(browser)
        operation_id, job_id = imported_operation(browser, tmp_path)
        complete_fixture(service, job_id, TransferServer())
        assert browser.get(f"/local/v1/operations/{operation_id}").json()["job"]["status"] == "completed"
        response = browser.post("/local/v1/packages", content=raw, headers={"Content-Type": "application/zip"})
        assert response.status_code == 200
        restored = response.json()
        assert restored["operation_id"] == operation_id and restored["operation"]["job_id"] == job_id
    restarted = create_member_app(state_root=tmp_path / "member", credential_store=credentials,
        api_factory=app.state.broker.api_factory)
    with TestClient(restarted) as browser:
        browser.get("/local/v1/capabilities")
        response = browser.post("/local/v1/packages", content=raw, headers={"Content-Type": "application/zip"})
        assert response.status_code == 200
        restored = response.json()
        assert restored["operation_id"] == operation_id and restored["operation"]["job_id"] == job_id
        assert restored["operation"]["job"]["status"] == "completed"
        assert browser.post(f"/local/v1/operations/{operation_id}/confirm").json()["job_id"] == job_id
        assert len(service.repository.list_jobs()) == 1
        assert len(list((tmp_path / "member/operations").glob("*.json"))) == 1


def test_planning_not_delivered_recovers_saved_plan_with_same_uuid_after_restart(service, tmp_path):
    package(tmp_path)
    app, credentials, _ = application(tmp_path, service)
    API = app.state.broker.api_factory
    first_put = [True]
    put_ids = []
    class RecoveredAPI(API):
        def _request(self, method, path, payload=None):
            identifier = path.split("/")[3]
            if method == "PUT":
                put_ids.append(identifier)
                if first_put:
                    first_put.pop()
                    raise RcnApiError(0, "fixture never delivered")
            if method == "GET" and service.repository.get_submission_operation(identifier) is None:
                raise RcnApiError(404, "fixture operation absent")
            return super()._request(method, path, payload)
    app.state.broker.api_factory = RecoveredAPI
    operation_id = str(uuid4())
    with TestClient(app) as browser:
        login(browser)
        imported = browser.post("/local/v1/packages", content=(tmp_path / "request-user-a-demo-analysis-2.zip").read_bytes(),
            headers={"Content-Type": "application/zip"}).json()
        response = browser.put(f"/local/v1/operations/{operation_id}", json={"package_id": imported["package_id"], "requested_unit_count": 2})
        assert response.status_code == 503
        assert app.state.broker.read_operation(operation_id)["phase"] == "planning-unknown"
    restarted = create_member_app(state_root=tmp_path / "member", credential_store=credentials, api_factory=RecoveredAPI)
    with TestClient(restarted) as browser:
        browser.get("/local/v1/capabilities")
        recovered = browser.get(f"/local/v1/operations/{operation_id}")
        assert recovered.status_code == 200, recovered.text
        assert recovered.json()["phase"] == "planned" and recovered.json()["operation_id"] == operation_id
        remote = service.repository.get_submission_operation(operation_id)
        assert len(remote.plan.work_units) == 2 and remote.job_id is None
        assert put_ids == [operation_id, operation_id]
        original = browser.post(f"/local/v1/operations/{operation_id}/confirm").json()["job_id"]
        assert original and len(service.repository.list_jobs()) == 1


def test_local_boundary_rejects_foreign_origin_and_direct_submit(service, tmp_path):
    app, _, _ = application(tmp_path, service)
    with TestClient(app) as browser:
        assert browser.post("/local/v1/session", json={"center_url": "https://center.example", "token": "personal-a"}).status_code == 403
        login(browser)
        assert browser.get("/local/v1/session", headers={"Origin": "https://foreign.example"}).status_code == 403
        assert browser.get("/local/v1/session", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert browser.post("/v1/jobs", json={}).status_code == 403
        assert browser.post("/v1/partition-plans", json={}).status_code == 403
        assert browser.get("/local/v1/capabilities", headers={"Host": "attacker.example"}).status_code == 400


def test_other_person_package_rejected_and_busy_identity_cannot_change(service, tmp_path):
    package(tmp_path, actor="user-b")
    app, credentials, _ = application(tmp_path, service)
    with TestClient(app, raise_server_exceptions=False) as browser:
        login(browser)
        imported = browser.post("/local/v1/packages", content=(tmp_path / "request-user-b-demo-analysis-2.zip").read_bytes(), headers={"Content-Type": "application/zip"})
        assert imported.status_code == 403
        app.state.broker.busy.add("active-transfer")
        assert browser.post("/local/v1/session", json={"center_url": "https://center.example", "token": "personal-b"}).status_code == 409
        assert credentials.value["token"] == "personal-a"
        app.state.broker.busy.clear()


@pytest.mark.skipif(os.name != "nt", reason="Windows native DPAPI")
def test_actual_windows_personal_dpapi_roundtrip_has_no_plaintext(tmp_path):
    store = PersonalCredentialStore(tmp_path / "credentials")
    store.save(center_url="https://center.example", token="synthetic-personal-secret")
    assert b"synthetic-personal-secret" not in store.path.read_bytes()
    assert store.load()["token"] == "synthetic-personal-secret"
    store.clear()
    assert store.load() is None


def test_member_api_does_not_follow_redirect_or_environment_proxy():
    api = member_api_client("https://center.example", token="synthetic")
    handlers = api.opener.handlers
    assert any(type(handler).__name__ == "_NoRedirect" for handler in handlers)
    assert not any(type(handler).__name__ == "ProxyHandler" and handler.proxies for handler in handlers)


@pytest.mark.parametrize("transition", ["new-login", "logout"])
def test_stale_identity_response_cannot_overwrite_a_later_auth_transition(tmp_path, transition):
    entered, release = threading.Event(), threading.Event()
    failures = []
    class API:
        def __init__(self, url, token): self.token = token
        def current_actor(self):
            if self.token == "personal-a" and threading.current_thread().name == "stale-session":
                entered.set()
                assert release.wait(5)
            return {"actor_id": "user-a" if self.token == "personal-a" else "user-b"}
    broker = MemberBroker(tmp_path / "member", credential_store=Credentials(), api_factory=API)
    broker.sign_in(Login(center_url="https://center.example", token="personal-a"))
    def refresh():
        try: broker.session(refresh=True)
        except Exception as exc: failures.append(exc)
    thread = threading.Thread(target=refresh, name="stale-session")
    thread.start()
    try:
        assert entered.wait(3)
        if transition == "new-login":
            broker.sign_in(Login(center_url="https://center.example", token="personal-b"))
        else:
            broker.sign_out()
        release.set()
        thread.join(5)
        assert not thread.is_alive() and not failures
        value = broker.session()
        assert value["actor"] == ({"actor_id": "user-b"} if transition == "new-login" else None)
        assert value["connected"] is (transition == "new-login")
        assert broker.login is None or broker.login["token"] == "personal-b"
    finally:
        release.set(); thread.join(5); broker.close()


def test_transfer_start_and_logout_are_one_identity_transition(service, tmp_path, monkeypatch):
    package(tmp_path)
    app, _, _ = application(tmp_path, service)
    with TestClient(app) as browser:
        login(browser)
        operation_id, _ = imported_operation(browser, tmp_path)
        broker = app.state.broker
        entered, release, logout_entered = threading.Event(), threading.Event(), threading.Event()
        failures, logout_results = [], []
        original = broker.read_operation
        def blocked_read(identifier):
            value = original(identifier)
            if threading.current_thread().name == "start-transfer":
                entered.set(); assert release.wait(5)
            return value
        monkeypatch.setattr(broker, "read_operation", blocked_read)
        monkeypatch.setattr(broker.executor, "submit", lambda *a, **k: object())
        def start():
            try: broker.start_transfer(operation_id)
            except Exception as exc: failures.append(exc)
        def logout():
            logout_entered.set()
            try: broker.sign_out(); logout_results.append("logged-out")
            except HTTPException as exc: logout_results.append(exc.status_code)
        worker = threading.Thread(target=start, name="start-transfer")
        exiting = threading.Thread(target=logout, name="logout")
        worker.start()
        try:
            assert entered.wait(3)
            exiting.start(); assert logout_entered.wait(3)
            release.set(); worker.join(5); exiting.join(5)
            assert not worker.is_alive() and not exiting.is_alive()
            assert not failures and logout_results == [409]
            assert broker.login["token"] == "personal-a"
            assert operation_id in broker.busy
        finally:
            release.set(); worker.join(5)
            if exiting.ident is not None: exiting.join(5)
            broker.busy.clear()


def test_executor_rejection_rolls_back_transfer_busy_identity(service, tmp_path, monkeypatch):
    package(tmp_path)
    app, _, _ = application(tmp_path, service)
    with TestClient(app) as browser:
        login(browser)
        operation_id, job_id = imported_operation(browser, tmp_path)
        broker = app.state.broker
        def rejected(*args, **kwargs): raise RuntimeError("fixture executor stopped")
        monkeypatch.setattr(broker.executor, "submit", rejected)
        with pytest.raises(RuntimeError, match="executor stopped"):
            broker.start_transfer(operation_id)
        assert not broker.busy
        assert broker.read_operation(operation_id)["job_id"] == job_id
        assert broker.sign_out()["connected"] is False


def test_input_capacity_counts_only_missing_verified_bytes_and_keeps_original_ids(service, tmp_path, monkeypatch):
    from research_compute_network import member_client as local
    from research_compute_network.models import JobEnvelope
    from research_compute_network.submission_packages import prepare_submission_bundles
    manifest, _ = package(tmp_path)
    app, _, _ = application(tmp_path, service)
    with TestClient(app) as browser:
        login(browser)
        operation_id, job_id = imported_operation(browser, tmp_path)
        broker = app.state.broker
        value = broker.read_operation(operation_id)
        remote = service.repository.get_submission_operation(operation_id).model_dump(mode="json")
        job = service.repository.get_job(job_id).model_dump(mode="json")
        envelope = JobEnvelope.model_validate(job)
        source_bytes = sum(record.size_bytes for record in manifest.package_manifest.files)
        assets = {record.sha256: record.size_bytes for record in envelope.input_manifest}
        overhead = 1024**2 + 2 * len(json.dumps(remote, ensure_ascii=False).encode("utf-8"))
        space = {"free": local.RESERVE_BYTES + overhead + source_bytes + sum(assets.values()) - 1}
        monkeypatch.setattr(local.shutil, "disk_usage", lambda path: SimpleNamespace(free=space["free"]))
        spool = broker.root / "transfers" / operation_id
        with pytest.raises(local.MemberStorageError, match="member_input_disk_reserve"):
            broker._input_capacity(value, remote, spool, job)
        space["free"] += 1
        broker._input_capacity(value, remote, spool, job)
        prepare_submission_bundles(broker.package_path(value["package_id"]), remote, spool, runtime_version=STABLE_RUNTIME_VERSION)
        # Reusing the original verified extraction/assets requires only metadata.
        space["free"] = local.RESERVE_BYTES + overhead
        broker._input_capacity(value, remote, spool, job)
        assert broker.read_operation(operation_id)["job_id"] == job_id
        assert len(service.repository.list_jobs()) == 1


class TransferResponse(BytesIO):
    status = 200
    def __init__(self, raw, *, headers=None, interrupt=False):
        super().__init__(raw)
        self.headers = headers or {}
        self.interrupt = interrupt
        self.started = False
    def read(self, count=-1):
        if self.interrupt and self.started:
            raise OSError("fixture connection interrupted")
        self.started = True
        return super().read(4 if self.interrupt else count)


class TransferServer:
    """Protocol fixture: the real streaming client validates/reuses all bytes.

    No solver runs here. Packages and output bytes are deliberately synthetic.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.accepted = {}
        self.puts = []
        self.gets = []
        self.fail_upload_once = True
        self.interrupt_result_once = None
        self.result_index = None
        self.results = {}
        self.manifests = []
    def factory(self, api):
        client = OriginTransferClient(api)
        client._open = self.open
        return client
    def open(self, path, *, data=None, headers=None, method="GET", timeout=None):
        with self.lock:
            if path == "/v1/origin-transfer":
                return TransferResponse(json.dumps({"protocol": TRANSFER_PROTOCOL, "enabled": True,
                    "bundle_status": True, "content_addressed_inputs": 1, "asset_encoding": "gzip",
                    "max_bundle_bytes": 16 * 1024**2}).encode())
            if "/origin-results" in path:
                self.gets.append(path)
                if path.endswith("/origin-results"):
                    return TransferResponse(json.dumps(self.result_index).encode())
                from urllib.parse import parse_qs, urlsplit
                selected = parse_qs(urlsplit(path).query)["file"][0]
                unit = path.split("/origin-results/")[1].split("/")[0]
                record, content = self.results[(unit, selected)]
                interrupt = self.interrupt_result_once == (unit, selected)
                if interrupt:
                    self.interrupt_result_once = None
                return TransferResponse(content, headers={"X-RCN-SHA256": record.sha256,
                    "Content-Length": str(record.size_bytes)}, interrupt=interrupt)
            parts = path.split("?")[0].split("/")
            job_id, item = parts[3], parts[5]
            asset = "/origin-assets/" in path
            if method == "PUT":
                import gzip
                raw = data.read()
                assert __import__("hashlib").sha256(raw).hexdigest() == headers["X-RCN-SHA256"]
                content = gzip.decompress(raw) if asset else raw
                receipt = {"job_id": job_id, "ready": True, "size_bytes": len(content),
                           "sha256": item if asset else __import__("hashlib").sha256(raw).hexdigest()}
                if not asset:
                    receipt["work_unit_id"] = item
                self.accepted[path] = receipt
                self.puts.append(path)
                # A server can accept a bundle before the response disconnects.
                if not asset and self.fail_upload_once:
                    self.fail_upload_once = False
                    raise OSError("accepted upload response lost")
                return TransferResponse(json.dumps(receipt).encode())
            if path in self.accepted:
                return TransferResponse(json.dumps(self.accepted[path]).encode())
            if asset:
                raise AssertionError("asset expected to be populated from the package manifest before upload")
            return TransferResponse(json.dumps({"job_id": job_id, "work_unit_id": item, "ready": False}).encode())


def wait_for_transfer(broker, operation_id):
    deadline = time.monotonic() + 10
    while operation_id in broker.busy:
        assert time.monotonic() < deadline, "bounded transfer fixture did not finish"
        time.sleep(.02)
    return broker.read_operation(operation_id)


def imported_operation(browser, tmp_path, *, count=1):
    raw = (tmp_path / "request-user-a-demo-analysis-2.zip").read_bytes()
    receipt = browser.post("/local/v1/packages", content=raw,
        headers={"Content-Type": "application/zip", "X-RCN-Filename": "%E7%A0%94%E7%A9%B6.zip"})
    assert receipt.status_code == 200, receipt.text
    operation_id = str(uuid4())
    response = browser.put(f"/local/v1/operations/{operation_id}", json={
        "package_id": receipt.json()["package_id"], "requested_unit_count": count})
    assert response.status_code == 200, response.text
    confirmed = browser.post(f"/local/v1/operations/{operation_id}/confirm")
    assert confirmed.status_code == 200, confirmed.text
    return operation_id, confirmed.json()["job_id"]


def complete_fixture(service, job_id, server):
    job = service.repository.get_job(job_id)
    job.status = JobStatus.COMPLETED
    server.manifests = []
    index = []
    for unit in job.work_units:
        unit.status = WorkUnitStatus.COMPLETED
        attempt = "attempt-fixture-" + str(unit.ordinal)
        unit.attempts = [WorkUnitAttempt(attempt_id=attempt, state="completed")]
        records = []
        for filename, content in [("results/frequency.csv", b"frequency,quality\n1.0,20\n"),
                                  ("results/polarization.csv", b"channel,amplitude\nup,0.5\n")]:
            import hashlib
            record = FileRecord(relative_path=filename, size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
            records.append(record)
            server.results[(unit.work_unit_id, filename)] = record, content
        manifest = ArtifactManifest(job_id=job_id, work_unit_id=unit.work_unit_id,
            output_schema="synthetic-lightweight-output-v1", files=records)
        service.repository.put_artifact_manifest(manifest)
        server.manifests.append(manifest)
        index.append({"work_unit_id": unit.work_unit_id, "attempt_id": attempt,
                      "manifest_sha256": sha256_value(manifest.model_dump(mode="json"))})
    service.repository.put_job(job)
    server.result_index = {"job_id": job_id, "units": index}
    return job


def test_transfer_interruption_resumes_same_job_and_confirmed_bundle_bytes(service, tmp_path, monkeypatch):
    manifest, _ = package(tmp_path)
    server = TransferServer()
    # Assets are already present on this protocol fixture, exercising asset skip.
    original_open = server.open
    def response(path, **kwargs):
        if "/origin-assets/" in path and kwargs.get("method", "GET") == "GET":
            digest = path.rsplit("/", 1)[1]
            record = next(item for item in manifest.package_manifest.files if item.sha256 == digest)
            return TransferResponse(json.dumps({"job_id": path.split("/")[3], "sha256": digest,
                "size_bytes": record.size_bytes, "ready": True}).encode())
        return original_open(path, **kwargs)
    server.open = response
    app, _, _ = application(tmp_path, service, transfer_factory=server.factory)
    with TestClient(app) as browser:
        login(browser)
        operation_id, job_id = imported_operation(browser, tmp_path, count=2)
        start = browser.post(f"/local/v1/operations/{operation_id}/upload")
        assert start.status_code == 200, start.text
        interrupted = wait_for_transfer(app.state.broker, operation_id)
        assert interrupted["phase"] == "upload-interrupted"
        assert interrupted["job_id"] == job_id
        assert server.accepted
        puts_before = list(server.puts)
        retry = browser.post(f"/local/v1/operations/{operation_id}/upload")
        assert retry.status_code == 200, retry.text
        resumed = wait_for_transfer(app.state.broker, operation_id)
        assert resumed["upload"]["state"] == "complete"
        assert resumed["job_id"] == job_id
        for accepted_path in puts_before:
            assert server.puts.count(accepted_path) == puts_before.count(accepted_path)
        assert len(server.accepted) == len(service.repository.get_job(job_id).work_units)
        assert len(service.repository.list_jobs()) == 1


def test_result_interruption_reuses_complete_files_and_hash_checked_collection(service, tmp_path):
    package(tmp_path)
    server = TransferServer()
    app, _, _ = application(tmp_path, service, transfer_factory=server.factory)
    with TestClient(app) as browser:
        login(browser)
        operation_id, job_id = imported_operation(browser, tmp_path)
        job = complete_fixture(service, job_id, server)
        unit = job.work_units[0]
        server.interrupt_result_once = unit.work_unit_id, "results/polarization.csv"
        assert browser.post(f"/local/v1/operations/{operation_id}/collect").status_code == 200
        incomplete = wait_for_transfer(app.state.broker, operation_id)
        assert incomplete["phase"] == "collection-interrupted"
        assert len(list((app.state.broker.root / "results").rglob("frequency.csv"))) == 1
        # Durable collection retains only its own partial and original journal.
        partials = list((app.state.broker.root / "results").rglob("*.partial"))
        assert partials and all(".rcn-collections" in path.parts for path in partials)
        assert incomplete["collection_control"]["state"] == "retry_wait"
        frequency_requests = sum("frequency.csv" in url for url in server.gets)
        assert browser.post(f"/local/v1/operations/{operation_id}/collect").status_code == 200
        complete = wait_for_transfer(app.state.broker, operation_id)
        assert complete["collection"]["state"] == "complete"
        assert complete["collection"]["verified_files"] == 2
        assert sum("frequency.csv" in url for url in server.gets) == frequency_requests
        assert complete["job_id"] == job_id
        assert browser.post(f"/local/v1/operations/{operation_id}/confirm").json()["collection"]["state"] == "complete"
        assert len(service.repository.list_jobs()) == 1


def test_result_download_preserves_disk_reserve_before_creating_partial_file(service, tmp_path, monkeypatch):
    from types import SimpleNamespace
    import research_compute_network.origin_transfer_client as transfer_client
    from research_compute_network.member_client import RESERVE_BYTES
    package(tmp_path)
    server = TransferServer()
    app, _, _ = application(tmp_path, service, transfer_factory=server.factory)
    with TestClient(app) as browser:
        login(browser)
        operation_id, job_id = imported_operation(browser, tmp_path)
        job = complete_fixture(service, job_id, server)
        first_size = server.results[(job.work_units[0].work_unit_id, "results/frequency.csv")][0].size_bytes
        monkeypatch.setattr(transfer_client.shutil, "disk_usage", lambda path: SimpleNamespace(free=RESERVE_BYTES + first_size - 1))
        assert browser.post(f"/local/v1/operations/{operation_id}/collect").status_code == 200
        failed = wait_for_transfer(app.state.broker, operation_id)
        assert failed["error"]["reason_code"] == "origin_result_disk_reserve"
        assert not list((app.state.broker.root / "results").rglob("*.partial"))
        assert not list((app.state.broker.root / "results").rglob("frequency.csv"))
        assert not any("frequency.csv" in url for url in server.gets)


def test_wrong_result_bytes_never_create_verified_receipt(service, tmp_path):
    package(tmp_path)
    server = TransferServer()
    app, _, _ = application(tmp_path, service, transfer_factory=server.factory)
    with TestClient(app) as browser:
        login(browser)
        operation_id, job_id = imported_operation(browser, tmp_path)
        job = complete_fixture(service, job_id, server)
        selected = (job.work_units[0].work_unit_id, "results/frequency.csv")
        record, content = server.results[selected]
        server.results[selected] = record, b"x" * len(content)
        assert browser.post(f"/local/v1/operations/{operation_id}/collect").status_code == 200
        rejected = wait_for_transfer(app.state.broker, operation_id)
        assert rejected["phase"] == "collection-interrupted"
        assert rejected.get("collection", {}).get("state") != "complete"
        assert rejected["job_id"] == job_id
        assert not list((app.state.broker.root / "results").rglob("frequency.csv"))
        assert not list((app.state.broker.root / "results").rglob("transport-receipt.json"))
        assert rejected["collection_control"]["state"] == "fault_paused"


def test_session_and_operation_listing_never_return_personal_secret(service, tmp_path):
    package(tmp_path)
    app, _, _ = application(tmp_path, service)
    with TestClient(app) as browser:
        login(browser)
        operation_id, _ = imported_operation(browser, tmp_path)
        for path in ["/local/v1/capabilities", "/local/v1/session", "/local/v1/operations",
                     f"/local/v1/operations/{operation_id}"]:
            response = browser.get(path)
            assert response.status_code == 200
            assert "personal-a" not in response.text
            assert '"token"' not in response.text
        assert browser.delete("/local/v1/session").status_code == 200
        assert browser.get("/local/v1/operations").status_code == 401
        assert (app.state.broker.root / "operations" / (operation_id + ".json")).is_file()


@pytest.mark.skipif(os.environ.get("RCN_RUN_MEMBER_BROWSER") != "1", reason="explicit real local HTTP/browser integration")
def test_real_local_app_browser_smoke_with_streaming_and_recovery(service, tmp_path):
    """Actual browser/static app/broker HTTP; synthetic center and solver output.

    This verifies the real desktop API cookie, package/operation/transfer flow.
    Real COMSOL scientific acceptance remains a separate release requirement.
    """
    import socket
    import subprocess
    import shutil
    import uvicorn
    repository = Path(__file__).parents[1]
    static = Path(os.environ["RCN_MEMBER_BROWSER_STATIC"])
    assert (static / "index.html").is_file(), "build the member UI before its live smoke test"
    manifest, _ = package(tmp_path)
    server = TransferServer()
    original_open = server.open
    def response(path, **kwargs):
        if "/origin-assets/" in path and kwargs.get("method", "GET") == "GET":
            digest = path.rsplit("/", 1)[1]
            record = next(item for item in manifest.package_manifest.files if item.sha256 == digest)
            return TransferResponse(json.dumps({"job_id": path.split("/")[3], "sha256": digest,
                "size_bytes": record.size_bytes, "ready": True}).encode())
        return original_open(path, **kwargs)
    server.open = response
    def finish_synthetic_output():
        selected = service.repository.list_jobs()[-1]
        job = complete_fixture(service, selected.job_id, server)
        server.interrupt_result_once = job.work_units[0].work_unit_id, "results/polarization.csv"
    app, _, lost = application(tmp_path, service, transfer_factory=server.factory, static_root=static,
        ensure_running_callback=finish_synthetic_output)
    lost.append(True)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    web = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=web.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not web.started:
            assert thread.is_alive() and time.monotonic() < deadline, "local fixture server failed to start"
            time.sleep(.02)
        environment = dict(os.environ, RCN_TEST_URL=f"http://127.0.0.1:{port}",
            RCN_MEMBER_TASK_PACKAGE=str(tmp_path / "request-user-a-demo-analysis-2.zip"))
        command = [shutil.which("node"), str(repository / "web/node_modules/@playwright/test/cli.js"),
            "test", "--config", "web/playwright.config.js", "member-client-live.spec.js", "--project", "desktop"]
        completed = subprocess.run(command, cwd=repository, env=environment, capture_output=True,
                                   text=True, encoding="utf-8", timeout=120)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        jobs = service.repository.list_jobs()
        assert len(jobs) == 1
        assert len(server.puts) == 1  # acknowledged lost-response bundle is reused
        receipts = list((app.state.broker.root / "operations").glob("*.json"))
        assert len(receipts) == 1
        journal = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert journal["collection"]["state"] == "complete"
        assert journal["collection"]["verified_files"] == 2
        results = Path(journal["collection"]["directory"])
        for manifest in server.manifests:
            for record in manifest.files:
                target = next(results.rglob(Path(record.relative_path).name))
                assert sha256_file(target) == record.sha256
        assert not list(results.rglob("*.partial"))
    finally:
        web.should_exit = True
        thread.join(timeout=20)
        listener.close()
        assert not thread.is_alive(), "local test server left running"


def test_last_result_published_before_checkpoint_recovers_offline_with_one_sha_pass(service,tmp_path,monkeypatch):
    import research_compute_network.collection as sdk
    package(tmp_path);server=TransferServer()
    app,_,_=application(tmp_path,service,transfer_factory=server.factory)
    original_publish=sdk.publish_new_file;injected=False
    with TestClient(app)as browser:
        login(browser);operation_id,job_id=imported_operation(browser,tmp_path)
        complete_fixture(service,job_id,server)
        def publish_then_exit(temporary,destination):
            nonlocal injected
            original_publish(temporary,destination)
            if Path(destination).name=='polarization.csv'and not injected:
                injected=True
                raise OSError('injected exit immediately after last result publication')
        monkeypatch.setattr(sdk,'publish_new_file',publish_then_exit)
        assert browser.post(f'/local/v1/operations/{operation_id}/collect').status_code==200
        interrupted=wait_for_transfer(app.state.broker,operation_id)
        assert injected and interrupted['collection_control']['state']=='retry_wait'
        journal,=list((app.state.broker.root/'results').rglob('operation.json'))
        assert json.loads(journal.read_bytes())['phase']=='retry_wait'
        assert len(list((app.state.broker.root/'results').rglob('*.csv')))==2
        monkeypatch.setattr(sdk,'publish_new_file',original_publish)
        monkeypatch.setattr(server,'open',lambda *a,**kw:pytest.fail('offline local recovery queried center'))
        api=type(app.state.broker.client())
        monkeypatch.setattr(api,'get_job',lambda *a:pytest.fail('offline local recovery fetched Job'))
        monkeypatch.setattr(api,'collect_artifacts',lambda *a:pytest.fail('offline local recovery fetched manifests'))
        reads=[];verify=sdk.verify_file
        def counted(path,*a,**kw):reads.append(Path(path));return verify(path,*a,**kw)
        monkeypatch.setattr(sdk,'verify_file',counted)
        assert browser.post(f'/local/v1/operations/{operation_id}/collect').status_code==200
        complete=wait_for_transfer(app.state.broker,operation_id)
        assert complete['phase']=='collected'and complete['collection']['verified_files']==2
        assert len(reads)==2 and len(set(reads))==2
        assert json.loads(journal.read_bytes())['phase']=='finalized'
