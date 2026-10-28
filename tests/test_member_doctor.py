import json
import errno
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

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


def agent_broker(tmp_path, monkeypatch, *, sealed=True):
    from research_compute_network import member_agent_config
    monkeypatch.setattr(doctor.storage, "_private_directory", lambda *a, **kw: None)
    monkeypatch.setattr(doctor.storage, "_check_private_file", lambda *a, **kw: None)
    root = tmp_path / "安装 测试" / "desktop" / "agents" / str(uuid4())
    root.mkdir(parents=True)
    profile = {"schema_version": 1, "agent_id": root.name, "actor_id": "alice",
        "center_url": "https://center.example", "credential_fingerprint": hashlib.sha256(b"private").hexdigest(),
        "credential_id": "agent-credential", "target": "codex", "label": "Own Agent"}
    actor = {"actor_id": "alice", "credential_id": "agent-credential", "roles": ["member"], "scopes": ["api", "agent"]}
    if sealed:
        profile.update(registration_state="confirmed", credential_origin="self_service")
    (root / "agent-profile.json").write_text(json.dumps(profile), encoding="utf-8")
    cached = {**actor, **({"agent_registration": dict(profile)} if sealed else {})}
    calls = []
    class API:
        def current_actor(self):
            calls.append("identity")
            return actor
        def _request(self, method, path):
            calls.append((method, path))
            assert (method, path) == ("GET", "/v1/me/submission-policy")
            return {"source": "person", "policy": {"approved": True, "paused": False,
                "max_queued_units": 2, "max_running_units": 1, "allowed_profiles": ["fake"]}}
    def resolve(*args):
        calls.append("resolve")
        # Exercise the existing exact-root/profile/token check used in production.
        assert member_agent_config.member_connection_root(broker) == root.parent.parent
        return API(), {"mode": "https"}
    broker = SimpleNamespace(root=root, login={"center_url": profile["center_url"], "token": "private", "actor": cached},
                             _api_with_connection=resolve)
    return broker, actor, calls


@pytest.mark.parametrize("sealed", [True, False], ids=["self-service", "legacy-preissued"])
def test_agent_doctor_recognizes_own_root_without_enumerating_desktop_manager(tmp_path, monkeypatch, sealed):
    broker, actor, calls = agent_broker(tmp_path, monkeypatch, sealed=sealed)
    report = doctor.diagnose(broker, verify_install=False)
    assert report["ok"]
    check = next(c for c in report["checks"] if c["stage"] == "agent")
    assert check["status"] == "passed" and "此 Agent" in check["message"]
    assert "尚未配置" not in json.dumps(report, ensure_ascii=False)
    assert not report["next_actions"]
    assert calls == ["resolve", "identity", ("GET", "/v1/me/submission-policy")]
    assert "private" not in json.dumps(report)


def test_self_service_doctor_reuses_sealed_registration_after_one_transport_validation(tmp_path, monkeypatch):
    from research_compute_network import member_agent_config
    broker, actor, calls = agent_broker(tmp_path, monkeypatch)
    read = member_agent_config._read_profile
    reads = []
    def counted(path):
        reads.append(path)
        return read(path)
    monkeypatch.setattr(member_agent_config, "_read_profile", counted)
    assert doctor.diagnose(broker, verify_install=False)["ok"]
    assert reads == [broker.root / "agent-profile.json"]


@pytest.mark.parametrize("change", ["credential", "scope", "role", "person", "pending", "revoked", "fingerprint", "root", "missing-credential"])
def test_own_agent_doctor_never_confirms_changed_or_unconfirmed_identity(tmp_path, monkeypatch, change):
    broker, actor, calls = agent_broker(tmp_path, monkeypatch)
    # Bypass transport only to exercise the diagnostic's independent own binding.
    broker._api_with_connection = lambda *a: (SimpleNamespace(current_actor=lambda: actor,
        _request=lambda *a: {"source": "person"}), {})
    if change == "credential":
        actor["credential_id"] = "different"
    elif change == "scope":
        actor["scopes"] = ["api"]
    elif change == "role":
        actor["roles"] = ["member", "admin"]
    elif change == "person":
        actor["actor_id"] = "bob"
    elif change in {"pending", "revoked"}:
        broker.login["actor"]["agent_registration"]["registration_state"] = change
    elif change == "fingerprint":
        broker.login["actor"]["agent_registration"]["credential_fingerprint"] = "0" * 64
    elif change == "missing-credential":
        broker.login["actor"]["agent_registration"]["credential_id"] = None
    else:
        broker.root = tmp_path / "unrelated"
    report = doctor.diagnose(broker, verify_install=False)
    assert not report["ok"]
    assert next(c for c in report["checks"] if c["stage"] == "agent")["status"] != "passed"
    assert "private" not in json.dumps(report)


def test_own_agent_doctor_does_not_report_fresh_confirmation_offline(tmp_path, monkeypatch):
    broker, actor, calls = agent_broker(tmp_path, monkeypatch)
    def unavailable(*args):
        raise RcnApiError(401, "private response")
    broker._api_with_connection = unavailable
    report = doctor.diagnose(broker, verify_install=False)
    assert not report["ok"]
    check = next(c for c in report["checks"] if c["stage"] == "agent")
    assert check["status"] == "skipped" and "尚未配置" not in check["message"]
    assert "private" not in json.dumps(report)


def installed_doctor(tmp_path, monkeypatch):
    root = tmp_path / "安装 测试" / "member-fixture"
    (root / "runtime/python").mkdir(parents=True)
    (root / "member-software-release.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(doctor.sys, "executable", str(root / "runtime/python/pythonw.exe"))
    # A different cwd must not redirect selection to another release.
    monkeypatch.chdir(tmp_path)
    return root


def test_installed_doctor_serializes_full_verifications_and_never_caches(tmp_path, monkeypatch):
    from research_compute_network import member_client_installer as installer
    root = installed_doctor(tmp_path, monkeypatch)
    first_entered, second_started, release_first = threading.Event(), threading.Event(), threading.Event()
    second_entered = threading.Event()
    calls = []
    def verify(path, *, expected_payload_id):
        assert path == root and expected_payload_id == root.name
        calls.append(path)
        if len(calls) == 1:
            first_entered.set()
            assert release_first.wait(3)
        else:
            second_entered.set()
    monkeypatch.setattr(installer, "verify_snapshot", verify)
    def second():
        second_started.set()
        return doctor.installed_integrity()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(doctor.installed_integrity)
        try:
            assert first_entered.wait(3)
            other = pool.submit(second)
            assert second_started.wait(3)
            assert not second_entered.wait(.05)
            assert calls == [root]
        finally:
            release_first.set()
        assert first.result(timeout=3)["status"] == "passed"
        assert other.result(timeout=3)["status"] == "passed"
    assert calls == [root, root]
    doctor.installed_integrity()
    assert calls == [root, root, root]


@pytest.mark.parametrize("failure,code,reason", [
    (OSError(errno.EMFILE, "private path"), "member_installation_verification_unavailable", "resource_exhausted"),
    (PermissionError(errno.EACCES, "private path"), "member_installation_verification_unavailable", "permission_denied"),
    (FileNotFoundError(errno.ENOENT, "private path"), "member_installation_integrity_failed", "snapshot_file_missing"),
    (ValueError("member_software_files_changed"), "member_installation_integrity_failed", "member_software_files_changed"),
    (ValueError("member_software_directory_identity_changed"), "member_installation_integrity_failed", "member_software_directory_identity_changed"),
    (ValueError("member_software_linked_directory"), "member_installation_integrity_failed", "member_software_linked_directory"),
    (ValueError("private path or secret"), "member_installation_integrity_failed", "invalid_snapshot"),
    (KeyError("private manifest key"), "member_installation_integrity_failed", "invalid_snapshot"),
])
def test_installed_doctor_distinguishes_incomplete_verification_from_changed_payload(tmp_path, monkeypatch, failure, code, reason):
    from research_compute_network import member_client_installer as installer
    installed_doctor(tmp_path, monkeypatch)
    def verify(*args, **kwargs):
        raise failure
    monkeypatch.setattr(installer, "verify_snapshot", verify)
    report = doctor.installed_integrity()
    assert report["status"] == "failed" and report["reason_code"] == code
    assert report["verification_reason"] == reason
    assert "private" not in json.dumps(report)


@pytest.mark.parametrize("changed", [False, True])
def test_installed_doctor_uses_real_snapshot_verifier_for_unicode_release_and_cwd(tmp_path, monkeypatch, changed):
    from research_compute_network.member_release_catalog import current_member_release
    root = tmp_path / "安装 测试" / "building"
    runtime = root / "runtime/python"
    runtime.mkdir(parents=True)
    executable = runtime / "pythonw.exe"
    executable.write_bytes(b"inert interpreter fixture")
    files = {"python/pythonw.exe": hashlib.sha256(executable.read_bytes()).hexdigest()}
    identifier = "member-" + hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
    selected = root.with_name(identifier)
    root.rename(selected)
    release = current_member_release()
    manifest = {"payload_id": identifier, "runtime_files": files,
        "member_runtime": {"runtime_version": release.runtime_version, "archive_sha256": release.archive_sha256}}
    (selected / "member-software-release.json").write_text(json.dumps(manifest), encoding="utf-8")
    executable = selected / "runtime/python/pythonw.exe"
    monkeypatch.setattr(doctor.sys, "executable", str(executable))
    monkeypatch.chdir(tmp_path)
    if changed:
        executable.write_bytes(b"tampered interpreter fixture")
    result = doctor.installed_integrity()
    assert result["status"] == ("failed" if changed else "passed")
    if changed:
        assert result["reason_code"] == "member_installation_integrity_failed"
