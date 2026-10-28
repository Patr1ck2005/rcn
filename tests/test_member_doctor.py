import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from research_compute_network import agent_access, member_doctor as doctor
from research_compute_network.client import RcnApiError
from research_compute_network.member_client import create_member_app
from research_compute_network.member_client_credentials import CredentialUnavailable
from test_member_client import Credentials


def test_offline_help_does_not_create_broker_or_touch_credentials(monkeypatch, capsys):
    def forbidden(*a, **kw):
        raise AssertionError("offline help must not initialize credentials")
    monkeypatch.setattr(agent_access, "MemberBroker", forbidden)
    assert agent_access.main(["help", "read", "member-getting-started"]) == 0
    assert "接入包" in capsys.readouterr().out
    assert agent_access.main(["help", "list", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["offline_available"]


@pytest.mark.parametrize("status,expected", [(0, "center_unavailable"), (401, "center_login_required"), (403, "center_permission_denied")])
def test_diagnostics_separate_failure_classes_without_echoing_secret(status, expected):
    result = doctor.error_detail(RcnApiError(status, "private-token-SENSITIVE upstream body"), stage="center")
    assert result["reason_code"] == expected
    assert "SENSITIVE" not in json.dumps(result)
    assert result["next_action"]


def test_doctor_reuses_single_resolution_and_never_submits(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor.storage, "_private_directory", lambda *a, **kw: None)
    calls = []
    class API:
        def current_actor(self):
            calls.append("identity")
            return {"actor_id": "alice"}
        def _request(self, method, path):
            calls.append((method, path))
            assert method == "GET" and path == "/v1/me/submission-policy"
            return {"source": "person", "policy": {"approved": True, "paused": False,
                "max_queued_units": 20, "max_running_units": 2, "allowed_profiles": ["fake"]}}
    def resolve(*args):
        calls.append("resolve")
        return API(), {"mode": "https"}
    broker = SimpleNamespace(root=tmp_path, login={"center_url": "https://center.example", "token": "private",
                              "actor": {"actor_id": "alice"}}, _api_with_connection=resolve)
    report = doctor.diagnose(broker, verify_install=False)
    assert report["ok"] and report["compute_started"] is False
    assert calls == ["resolve", "identity", ("GET", "/v1/me/submission-policy")]
    assert "private" not in json.dumps(report)


def test_corrupt_login_preserves_help_and_diagnostic_entry(tmp_path, monkeypatch):
    from research_compute_network import member_registration
    monkeypatch.setattr(member_registration, "_private_directory", lambda root, **kw: root.mkdir(parents=True, exist_ok=True))
    class Corrupt(Credentials):
        def load(self):
            raise CredentialUnavailable("member_credentials_invalid")
    app = create_member_app(state_root=tmp_path / "member", credential_store=Corrupt(), api_factory=lambda *a, **k: None)
    with TestClient(app) as client:
        client.get("/local/v1/capabilities")
        session = client.get("/local/v1/session").json()
        assert not session["connected"] and session["credential_error"] == "member_credentials_invalid"
        assert client.get("/v1/help/public/member-getting-started?format=markdown").status_code == 200
        report = client.post("/local/v1/doctor", json={}).json()
        assert not report["ok"] and any(c["reason_code"] == "member_credentials_invalid" for c in report["checks"])
        assert client.post("/local/v1/doctor", json={"repair": "yes"}).status_code == 422
        assert client.post("/local/v1/doctor", json={}, headers={"Origin": "https://foreign.example"}).status_code == 403


def test_client_only_component_supply_never_installs_server_or_firewall(monkeypatch, tmp_path):
    from research_compute_network import member_openssh_prerequisite as prerequisites
    script = prerequisites.CLIENT_INSTALL_SCRIPT
    assert "OpenSSH.Server" not in script and "Firewall" not in script and "Restart-Computer" not in script
    assert "OpenSSH.Client~~~~0.0.1.0" in script
    with pytest.raises(RuntimeError, match="consent"):
        prerequisites.ensure_member_ssh_client(state_root=tmp_path)


def test_unreadable_credential_directory_still_allows_offline_help(tmp_path, monkeypatch):
    from research_compute_network import member_client, member_registration
    monkeypatch.setattr(member_registration, "_private_directory", lambda root, **kw: root.mkdir(parents=True, exist_ok=True))
    def broken_store(root):
        raise member_registration.MemberRegistrationError("registration_root_permissions")
    monkeypatch.setattr(member_client, "PersonalCredentialStore", broken_store)
    app = create_member_app(state_root=tmp_path / "member", api_factory=lambda *a, **k: None)
    with TestClient(app) as client:
        client.get("/local/v1/capabilities")
        assert client.get("/v1/help/public/member-getting-started").status_code == 200
        report = client.post("/local/v1/doctor", json={}).json()
        assert any(c["reason_code"] == "registration_root_permissions" for c in report["checks"])


def test_all_import_failures_have_actionable_safe_diagnostics():
    from research_compute_network.member_connection_bundle import IMPORT_REASON_CODES, ConnectionImportError
    for code in IMPORT_REASON_CODES:
        value = doctor.error_detail(ConnectionImportError(code))
        assert value["reason_code"] == code
        assert value["next_action"] and value["help_slug"]


def test_repair_resumes_only_previously_confirmed_missing_ssh_import(tmp_path, monkeypatch):
    from research_compute_network import member_connection_bundle as imports, member_client_connection as connection
    from research_compute_network import member_openssh_prerequisite as prerequisites
    monkeypatch.setattr(doctor.storage, "_private_directory", lambda *a, **k: None)
    (tmp_path / "connection-imports").mkdir()
    broker = SimpleNamespace(root=tmp_path, login=None)
    pending = {"state": "failed", "import_id": "same-operation", "reason_code": "member_connection_import_ssh_prerequisite_required"}
    monkeypatch.setattr(imports, "pending_import", lambda b: pending)
    monkeypatch.setattr(connection, "load_spec", lambda root: None)
    calls = []
    monkeypatch.setattr(prerequisites, "ensure_member_ssh_client", lambda **kw: calls.append("supply"))
    monkeypatch.setattr(imports, "confirm_import", lambda b, identifier: calls.append(identifier))
    doctor.diagnose(broker, repair=True, verify_install=False)
    assert calls == ["supply", "same-operation"]
    calls.clear()
    pending["state"] = "awaiting_confirmation"
    doctor.diagnose(broker, repair=True, verify_install=False)
    assert calls == []


@pytest.mark.parametrize("approved,paused", [(False, False), (True, True)])
def test_doctor_does_not_claim_disabled_policy_can_submit(tmp_path, monkeypatch, approved, paused):
    monkeypatch.setattr(doctor.storage, "_private_directory", lambda *a, **k: None)
    api = SimpleNamespace(current_actor=lambda: {"actor_id": "alice"},
        _request=lambda *a: {"source": "person", "policy": {"approved": approved, "paused": paused,
            "max_queued_units": 20, "max_running_units": 2, "allowed_profiles": ["fake"]}})
    broker = SimpleNamespace(root=tmp_path, login={"center_url": "https://example.org", "token": "secret",
        "actor": {"actor_id": "alice"}}, _api_with_connection=lambda *a: (api, {}))
    report = doctor.diagnose(broker, verify_install=False)
    assert next(c for c in report["checks"] if c["stage"] == "submission")["status"] == "warning"
