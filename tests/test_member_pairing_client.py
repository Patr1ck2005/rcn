import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import threading
from uuid import uuid4

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from research_compute_network import agent_access
from research_compute_network import member_agent_config
from research_compute_network import member_pairing_client as module
from research_compute_network.agent_credentials import build_agent_credentials_router
from research_compute_network.client import RcnApiError
from research_compute_network.member_client import MemberBroker, create_member_app
from research_compute_network.member_pairing_client import LocalPairingRequest, pairing_status, start_pairing
from research_compute_network.personal_access_api import build_personal_access_router
from test_member_pairing import pairings


class EncryptedFixture:
    values = {}

    def __init__(self, root):
        self.root = Path(root)
        self.path = self.root / "personal-login.dpapi"
        self.root.mkdir(parents=True, exist_ok=True)

    def load(self):
        return copy.deepcopy(self.values.get(str(self.path))) if self.path.exists() else None

    def save(self, **value):
        self.values[str(self.path)] = copy.deepcopy(value)
        self.path.write_bytes(b"opaque-test-encrypted-envelope")

    def clear(self):
        self.values.pop(str(self.path), None)
        self.path.unlink(missing_ok=True)


@pytest.fixture
def local(pairings, tmp_path, monkeypatch):
    f = pairings
    f.app.include_router(build_agent_credentials_router(repository=f.repo, auth=module_auth(f)))
    f.app.include_router(build_personal_access_router(repository=f.repo, auth=module_auth(f)))
    EncryptedFixture.values = {}
    monkeypatch.setattr(module, "PersonalCredentialStore", EncryptedFixture)
    monkeypatch.setattr(member_agent_config, "PersonalCredentialStore", EncryptedFixture)
    monkeypatch.setattr(module.storage, "_private_directory", lambda path, **kwargs: Path(path).mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(module.storage, "_check_private_file", lambda path: None)
    f.calls, f.lose_put, f.lose_agent_put = [], False, False

    def factory(center, token=None):
        assert center == "https://center.example"
        class API:
            def _request(self, method, path, payload=None):
                f.calls.append((method, path, copy.deepcopy(payload)))
                if method == "PUT" and path.startswith("/v1/member-pairings/"):
                    root = f.root / "member-pairings" / path.rsplit("/", 1)[1]
                    assert (root / "pairing.json").exists()
                    original = EncryptedFixture(root / "credentials").load()
                    assert hashlib.sha256(original["token"].encode()).hexdigest() == payload["token_hash"]
                response = f.client.request(method, path, json=payload,
                    headers={"Authorization": "Bearer " + token} if token else {})
                if response.status_code >= 400:
                    reason = response.json().get("detail", {})
                    raise RcnApiError(response.status_code, "bounded fixture error",
                        reason_code=reason.get("reason_code") if isinstance(reason, dict) else None)
                if method == "PUT" and path.startswith("/v1/member-pairings/") and f.lose_put:
                    f.lose_put = False
                    raise RcnApiError(0, "lost application response")
                if method == "PUT" and path.startswith("/v1/me/agent-credentials/") and f.lose_agent_put:
                    f.lose_agent_put = False
                    raise RcnApiError(0, "lost Agent response")
                return response.json()

            def current_actor(self):
                return self._request("GET", "/v1/me")
        return API()

    f.root = tmp_path / "member"
    f.factory = factory
    f.broker = MemberBroker(f.root, credential_store=EncryptedFixture(f.root / "credentials"), api_factory=factory)
    f.diagnostics = []
    from research_compute_network import member_doctor
    f.real_diagnose = member_doctor.diagnose
    monkeypatch.setattr(member_doctor, "diagnose", lambda broker: f.diagnostics.append(broker.root) or {
        "schema_version": 1, "ok": True, "diagnostic_id": str(uuid4()), "secrets_included": False})
    yield f
    f.broker.close()


def module_auth(f):
    from research_compute_network.auth import PilotAuthenticator
    return PilotAuthenticator(f.repo, allow_local_trusted=False)


def payload(**changes):
    return LocalPairingRequest(center_url="https://center.example", name="Alice local", device_name="Alice PC",
        agent="codex", label="My Codex", **changes)


def approve(f, key, *, member=None):
    response = f.client.post("/v1/admin/member-pairings/" + key + "/approve",
        json={"member_id": member} if member else {"create_new": True}, headers=f.admin)
    assert response.status_code == 200, response.text
    return response.json()


def restart(f):
    f.broker.close()
    f.broker = MemberBroker(f.root, credential_store=EncryptedFixture(f.root / "credentials"), api_factory=f.factory)


def test_lost_application_response_restart_and_approved_auto_handoff(local):
    f = local
    f.lose_put = True
    with pytest.raises(RcnApiError):
        start_pairing(f.broker, payload())
    pointer = json.loads((f.root / "member-pairings/current.json").read_bytes())
    identifier = pointer["pairing_id"]
    encrypted = EncryptedFixture(f.root / "member-pairings" / identifier / "credentials").load()
    assert encrypted and not f.broker.login
    restart(f)
    pending = pairing_status(f.broker)
    assert pending["pairing_id"] == identifier and pending["state"] == "pending"
    approved = approve(f, identifier)
    result = pairing_status(f.broker)
    assert result["phase"] == "connected" and result["doctor"]["ok"]
    assert result["agent_configuration"]["identity_verified"]
    assert f.broker.login["actor"]["actor_id"] == approved["member_id"]
    assert f.broker.login["token"] == encrypted["token"]
    assert len(f.repo.list_tokens(user_id=approved["member_id"])) == 2
    agent_root = f.root / "agents" / result["agent_id"]
    agent = EncryptedFixture(agent_root / "credentials").load()
    assert agent["token"] != encrypted["token"] and set(agent["actor"]["scopes"]) == {"api", "agent"}
    assert encrypted["token"] not in json.dumps(result) and agent["token"] not in json.dumps(result)
    assert len(f.diagnostics) == 1
    restart(f)
    again = pairing_status(f.broker)
    assert again == result and len(f.diagnostics) == 1


def test_lost_agent_response_resumes_same_agent_without_reissuing(local):
    f = local
    pending = start_pairing(f.broker, payload())
    approved = approve(f, pending["pairing_id"])
    f.lose_agent_put = True
    with pytest.raises(RcnApiError):
        pairing_status(f.broker)
    assert len(f.repo.list_tokens(user_id=approved["member_id"])) == 2
    restart(f)
    result = pairing_status(f.broker)
    assert result["agent_id"] == pending["agent_id"] and result["phase"] == "connected"
    assert len(f.repo.list_tokens(user_id=approved["member_id"])) == 2
    assert len(f.diagnostics) == 1


def test_crash_after_dpapi_before_public_journal_recovers_original_uuid(local, monkeypatch):
    f = local
    original = module._save
    monkeypatch.setattr(module, "_save", lambda *a: (_ for _ in ()).throw(OSError("interrupted journal publication")))
    with pytest.raises(OSError):
        start_pairing(f.broker, payload())
    identifier = json.loads((f.root / "member-pairings/current.json").read_bytes())["pairing_id"]
    assert not f.calls
    monkeypatch.setattr(module, "_save", original)
    restart(f)
    result = pairing_status(f.broker)
    assert result["pairing_id"] == identifier and result["state"] == "pending"
    assert len([call for call in f.calls if call[0] == "PUT"]) == 1


def test_dpapi_failure_never_reaches_center_and_reuses_original_uuid(local, monkeypatch):
    f = local
    original = EncryptedFixture.save
    monkeypatch.setattr(EncryptedFixture, "save", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("DPAPI failed")))
    with pytest.raises(RuntimeError, match="DPAPI failed"):
        start_pairing(f.broker, payload())
    identifier = json.loads((f.root / "member-pairings/current.json").read_bytes())["pairing_id"]
    assert not f.calls
    monkeypatch.setattr(EncryptedFixture, "save", original)
    assert start_pairing(f.broker, payload())["pairing_id"] == identifier


def test_approved_handoff_runs_real_doctor_with_submission_and_agent_checks(local, monkeypatch):
    f = local
    pending = start_pairing(f.broker, payload())
    approve(f, pending["pairing_id"])
    from research_compute_network import member_doctor
    monkeypatch.setattr(member_doctor, "diagnose", lambda broker: f.real_diagnose(broker, verify_install=False))
    result = pairing_status(f.broker)
    assert result["doctor"]["ok"], result["doctor"]
    checks = {check["stage"]: check["status"] for check in result["doctor"]["checks"]}
    assert checks["login"] == checks["submission"] == checks["agent"] == "passed"


def test_interrupted_doctor_resumes_once_after_restart(local, monkeypatch):
    f = local
    pending = start_pairing(f.broker, payload())
    approve(f, pending["pairing_id"])
    from research_compute_network import member_doctor
    calls = []
    def interrupted(broker):
        calls.append(broker.root)
        raise KeyboardInterrupt()
    monkeypatch.setattr(member_doctor, "diagnose", interrupted)
    with pytest.raises(KeyboardInterrupt):
        pairing_status(f.broker)
    journal = f.root / "member-pairings" / pending["pairing_id"] / "pairing.json"
    assert json.loads(journal.read_bytes())["doctor_state"] == "started"
    restart(f)
    monkeypatch.setattr(member_doctor, "diagnose", lambda broker: calls.append(broker.root) or {"ok": True})
    result = pairing_status(f.broker)
    assert result["doctor_state"] == "completed" and result["doctor"]["ok"]
    assert len(calls) == 2
    assert pairing_status(f.broker) == result
    assert pairing_status(f.broker, retry_doctor=True) == result
    assert len(calls) == 2


@pytest.mark.parametrize("failure_kind", ["report", "exception"])
def test_failed_doctor_needs_explicit_retry_and_success_is_reused(local, monkeypatch, failure_kind):
    f = local
    pending = start_pairing(f.broker, payload())
    approve(f, pending["pairing_id"])
    from research_compute_network import member_doctor
    calls = []
    def failure(broker):
        calls.append(broker.root)
        if failure_kind == "exception":
            raise RuntimeError("SENSITIVE diagnostic exception body")
        return {"ok": False, "diagnostic_id": "original-failure"}
    monkeypatch.setattr(member_doctor, "diagnose", failure)
    result = pairing_status(f.broker)
    assert not result["doctor"]["ok"] and "SENSITIVE" not in json.dumps(result)
    for _ in range(3):
        assert pairing_status(f.broker) == result
    assert len(calls) == 1
    monkeypatch.setattr(member_doctor, "diagnose", lambda broker: calls.append(broker.root) or {"ok": True})
    args = agent_access.parser().parse_args(["join", "--status"])
    assert agent_access.execute(args, f.broker) == 0
    assert len(calls) == 2
    result = pairing_status(f.broker)
    assert result["doctor"]["ok"] and result["doctor_state"] == "completed"
    assert pairing_status(f.broker, retry_doctor=True) == result and len(calls) == 2


def test_existing_identity_preserves_tasks_results_and_pause_and_rejects_different_center(local):
    f = local
    actor = f.client.get("/v1/me", headers={"Authorization": "Bearer alice"}).json()
    f.broker.credentials.save(center_url="https://center.example", token="alice", actor=actor)
    f.broker.login = {"center_url": "https://center.example", "token": "alice", "actor": actor}
    f.broker.actor = actor
    originals = {}
    for relative in ["operations/original.json", "results/original.bin", "contribution/pause.json"]:
        path = f.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"preserve-existing-state")
        originals[path] = path.read_bytes()
    with pytest.raises(HTTPException) as failure:
        start_pairing(f.broker, payload().model_copy(update={"center_url": "https://other.example"}))
    assert failure.value.detail["reason_code"] == "member_pairing_existing_center_conflict"
    pending = start_pairing(f.broker, payload())
    approve(f, pending["pairing_id"], member="alice")
    result = pairing_status(f.broker)
    assert result["phase"] == "connected" and f.broker.login["actor"]["actor_id"] == "alice"
    assert all(path.read_bytes() == raw for path, raw in originals.items())


def test_different_approved_identity_cannot_overwrite_saved_login(local):
    f = local
    pending = start_pairing(f.broker, payload())
    actor = f.client.get("/v1/me", headers={"Authorization": "Bearer alice"}).json()
    f.broker.login = {"center_url": "https://center.example", "token": "alice", "actor": actor}
    f.broker.actor = actor
    approve(f, pending["pairing_id"], member="bob")
    with pytest.raises(HTTPException) as failure:
        pairing_status(f.broker)
    assert failure.value.detail["reason_code"] == "member_pairing_existing_identity_conflict"
    assert f.broker.login["token"] == "alice" and not list((f.root / "agents").glob("*"))


def test_sign_out_durably_pauses_automatic_pairing_until_explicit_resume(local):
    f = local
    pending = start_pairing(f.broker, payload())
    approve(f, pending["pairing_id"])
    f.broker.sign_out()
    before = len(f.calls)
    for _ in range(3):
        paused = pairing_status(f.broker)
        assert paused["pairing_id"] == pending["pairing_id"] and paused["resume_paused"] is True
        assert paused["agent_configuration"] is None and not f.broker.login
    assert len(f.calls) == before
    restart(f)
    assert pairing_status(f.broker)["resume_paused"] is True and not f.broker.login
    result = pairing_status(f.broker, pending["pairing_id"], resume=True)
    assert result["phase"] == "connected" and f.broker.login and len(f.diagnostics) == 1
    f.broker.sign_out()
    assert start_pairing(f.broker, payload())["pairing_id"] == pending["pairing_id"]
    assert f.broker.login and len(f.diagnostics) == 1


def test_inflight_approved_status_and_sign_out_are_serialized(local):
    f = local
    pending = start_pairing(f.broker, payload())
    approve(f, pending["pairing_id"])
    original_factory = f.broker.api_factory
    entered, release, signing_out = threading.Event(), threading.Event(), threading.Event()
    def blocked_factory(center, token=None):
        api = original_factory(center, token=token)
        original = api._request
        def request(method, path, data=None):
            if method == "GET" and path == "/v1/member-pairings/" + pending["pairing_id"]:
                entered.set()
                assert release.wait(5)
            return original(method, path, data)
        api._request = request
        return api
    f.broker.api_factory = blocked_factory
    def sign_out():
        signing_out.set()
        return f.broker.sign_out()
    with ThreadPoolExecutor(max_workers=2) as pool:
        status = pool.submit(pairing_status, f.broker)
        assert entered.wait(5)
        logout = pool.submit(sign_out)
        assert signing_out.wait(5)
        release.set()
        assert status.result(timeout=10)["phase"] == "connected"
        assert logout.result(timeout=10)["connected"] is False
    assert not f.broker.login and not f.broker.credentials.load()
    assert pairing_status(f.broker)["resume_paused"] is True and len(f.diagnostics) == 1


def test_logout_between_application_put_and_automatic_read_cannot_sign_back_in(local, monkeypatch):
    f = local
    original = module.pairing_status
    def pause_before_read(broker, identifier):
        broker.sign_out()
        return original(broker, identifier)
    monkeypatch.setattr(module, "pairing_status", pause_before_read)
    pending = start_pairing(f.broker, payload())
    assert pending["resume_paused"] is True and not f.broker.login
    approve(f, pending["pairing_id"])
    assert original(f.broker)["resume_paused"] is True and not f.broker.login


def test_revoked_pairing_read_does_not_recreate_credentials_or_repeat_doctor(local):
    f = local
    pending = start_pairing(f.broker, payload())
    approved = approve(f, pending["pairing_id"])
    pairing_status(f.broker)
    f.client.post("/v1/admin/member-pairings/" + pending["pairing_id"] + "/revoke", headers=f.admin)
    restart(f)
    result = pairing_status(f.broker)
    assert result["state"] == "revoked" and len(f.diagnostics) == 1
    assert len(f.repo.list_tokens(user_id=approved["member_id"])) == 2
    assert not f.repo.get_token(approved["credential_id"]).active


def test_local_routes_require_same_origin_session_and_hide_invalid_body(local):
    f = local
    app = create_member_app(state_root=f.root, credential_store=EncryptedFixture(f.root / "credentials"), api_factory=f.factory)
    with TestClient(app) as client:
        assert client.get("/local/v1/member-pairing").status_code == 403
        client.get("/local/v1/capabilities")
        assert client.get("/local/v1/member-pairing").json()["state"] == "not_started"
        response = client.post("/local/v1/member-pairing", json={"token": "MUST-NOT-ECHO"})
        assert response.status_code == 422 and "MUST-NOT-ECHO" not in response.text
        response = client.post("/local/v1/member-pairing", json=payload().model_dump(mode="json"))
        assert response.status_code == 200
        identifier = response.json()["pairing_id"]
        approve(f, identifier)
        assert client.delete("/local/v1/session").status_code == 200
        assert client.get("/local/v1/member-pairing").json()["resume_paused"] is True
        resumed = client.post("/local/v1/member-pairing/" + identifier + "/resume")
        assert resumed.status_code == 200 and resumed.json()["phase"] == "connected"


def test_join_cli_has_bounded_wait_and_can_query_without_login(local, monkeypatch, capsys):
    f = local
    args = agent_access.parser().parse_args(["join", "--center", "https://center.example", "--name", "Alice local",
        "--device-name", "Alice PC", "--agent", "codex", "--label", "My Codex"])
    assert agent_access.execute(args, f.broker) == 0
    pending = json.loads(capsys.readouterr().out)
    assert pending["state"] == "pending"
    assert agent_access.execute(agent_access.parser().parse_args(["join", "--status"]), f.broker) == 0
    assert json.loads(capsys.readouterr().out)["pairing_id"] == pending["pairing_id"]
    for wait in ["-1", "3601", "nan", "inf"]:
        with pytest.raises(agent_access.AgentAccessError, match="bounds"):
            agent_access.execute(agent_access.parser().parse_args(["join", "--status", "--wait", wait]), f.broker)
    times = iter([0, 0, 6])
    monkeypatch.setattr(module, "pairing_status", lambda *a, **k: pending)
    monkeypatch.setattr(agent_access.time, "monotonic", lambda: next(times))
    pauses = []
    monkeypatch.setattr(agent_access.time, "sleep", lambda value: pauses.append(value))
    assert agent_access.execute(agent_access.parser().parse_args(["join", "--status", "--wait", "5"]), f.broker) == 3
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert pauses == [5] and lines[-1]["reason_code"] == "member_pairing_wait_timeout"


def test_join_cli_lost_response_reports_original_uuid_and_safe_recovery(local, monkeypatch, capsys):
    f = local
    f.lose_put = True
    monkeypatch.setattr(agent_access, "MemberBroker", lambda *a, **k: f.broker)
    assert agent_access.main(["join", "--center", "https://center.example", "--name", "Alice local"]) == 2
    result = json.loads(capsys.readouterr().out)
    identifier = json.loads((f.root / "member-pairings/current.json").read_bytes())["pairing_id"]
    assert result["pairing_id"] == identifier and result["resume_same_pairing"]
    assert result["retry_arguments"] == ["join", "--status"]
