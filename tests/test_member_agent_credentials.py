import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from threading import RLock
from types import SimpleNamespace

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from research_compute_network.client import RcnApiError
from research_compute_network import member_agent_config as module
from research_compute_network.member_agent_config import (
    configure_member_agent, export_member_agent_config, list_member_agent_configs,
    member_connection_root, revoke_member_agent_credential,
)
from test_personal_agent_credentials import credentials, AGENT, OTHER
from test_member_agent_config import FakeStore, isolated_store, exported_config


@pytest.fixture(autouse=True)
def contract_acl(monkeypatch):
    # These tests use a synthetic DPAPI store; keep native byte locking while
    # avoiding an ACL claim for the fixture's deliberately ordinary directory.
    monkeypatch.setattr(module.storage, "_check_private_file", lambda path: None)


class Broker:
    def __init__(self, root, center):
        self.root, self.center = root, center
        self.lock, self.auth_generation = RLock(), 1
        self.actor = {"actor_id": "alice", "roles": ["member"], "scopes": ["api"],
                      "credential_id": "alice-desktop"}
        self.login = {"center_url": "https://center.example", "token": "alice-login"}
        self.calls, self.after_put, self.before_put, self.actor_change = [], None, None, None

    def session(self, *, refresh=False):
        return {"connected": True, "center_url": self.login["center_url"], "actor": self.actor,
                "online": True, "remote_actions_available": True}

    def _api(self, center, token):
        broker = self
        assert center == "https://center.example"
        class API:
            def _request(self, method, path, payload=None):
                broker.calls.append((method, path, payload))
                if method == "PUT":
                    # The generated secret and entire original binding are
                    # already recoverable before any server request starts.
                    root = broker.root / "agents" / path.rsplit("/", 1)[1]
                    encrypted = FakeStore(root / "credentials").load()
                    assert encrypted and (root / "agent-profile.json").exists()
                    assert hashlib.sha256(encrypted["token"].encode()).hexdigest() == payload["token_hash"]
                    if broker.before_put:
                        broker.before_put()
                response = broker.center.client.request(method, path, json=payload,
                                                       headers={"Authorization": "Bearer " + token})
                if response.status_code >= 400:
                    raise RcnApiError(response.status_code, "synthetic bounded API error")
                if method == "PUT" and broker.after_put:
                    broker.after_put()
                return response.json()
            def current_actor(self):
                actor = self._request("GET", "/v1/me")
                return {**actor, **broker.actor_change} if broker.actor_change else actor
        return API()


def profile(broker, agent=AGENT):
    return json.loads((broker.root / "agents" / agent / "agent-profile.json").read_bytes())


def configure(broker, agent=AGENT, **updates):
    return configure_member_agent(broker, "generic", agent, label="My own Agent", **updates)


def test_automatic_export_generates_protected_independent_credential_and_keeps_label(credentials, tmp_path):
    broker = Broker(tmp_path / "member", credentials)
    result = export_member_agent_config(broker, "generic", AGENT, label="My chosen label")
    assert result["agent_label"] == "My chosen label" and result["target"] == "generic"
    local = profile(broker)
    assert local["registration_state"] == "confirmed"
    saved = FakeStore(broker.root / "agents" / AGENT / "credentials").load()
    assert len(saved["token"]) == 43 and saved["token"] != broker.login["token"]
    assert saved["token"].encode() not in base64.b64decode(result["content_base64"])
    assert saved["token"] not in json.dumps(local) and "alice-login" not in json.dumps(local)
    assert list_member_agent_configs(broker)["agents"][0]["configured"]
    assert exported_config(result)["command_prefix"][-1] == str(broker.root / "agents" / AGENT)
    assert json.dumps(exported_config(result)["command_prefix"], ensure_ascii=False) in result["setup_instructions"]
    assert "help read member-task-package" in result["setup_instructions"]
    assert broker.login == {"center_url": "https://center.example", "token": "alice-login"}


def test_export_accepts_installed_stable_launcher_contract(credentials, tmp_path):
    broker = Broker(tmp_path / "member", credentials)
    binary = broker.root / "bin" / "RCN-Agent.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"synthetic-launcher-placeholder")
    (broker.root / "active-version.json").write_text("{}")
    result = export_member_agent_config(broker, "generic", AGENT, label="Stable Agent")
    config = exported_config(result)
    assert config["launcher_kind"] == "active-installed-version"
    assert config["command_prefix"] == [str(binary), "--state-root", str(broker.root / "agents" / AGENT)]


def test_export_includes_version_matched_offline_markdown(credentials, tmp_path, monkeypatch):
    from research_compute_network import agent_access
    broker = Broker(tmp_path / "member", credentials)
    original = agent_access.instruction_artifacts
    def artifacts(agent, directory):
        result = original(agent, directory)
        (directory / "help").mkdir()
        (directory / "help" / "getting-started.md").write_text("Synthetic installed help", encoding="utf-8")
        return result
    monkeypatch.setattr(agent_access, "instruction_artifacts", artifacts)
    result = export_member_agent_config(broker, "generic", AGENT, label="Offline help Agent")
    assert "help/getting-started.md" in result["files"]


def test_local_export_and_revoke_routes_use_personal_login_without_token_field(credentials, tmp_path):
    from research_compute_network.member_client import create_member_app
    class DesktopStore:
        value = None
        def load(self): return self.value
        def save(self, **value): self.value = value
        def clear(self): self.value = None
    class API:
        def __init__(self, url, token): self.token = token
        def _request(self, method, path, payload=None):
            response = credentials.client.request(method, path, json=payload,
                headers={"Authorization": "Bearer " + self.token})
            if response.status_code >= 400:
                raise RcnApiError(response.status_code, "synthetic API error")
            return response.json()
        def current_actor(self): return self._request("GET", "/v1/me")
    app = create_member_app(state_root=tmp_path / "local-member", credential_store=DesktopStore(), api_factory=API)
    with TestClient(app, base_url="http://127.0.0.1") as browser:
        browser.get("/local/v1/capabilities")
        assert browser.post("/local/v1/session", json={"center_url": "https://center.example",
            "token": "alice-login"}).status_code == 200
        exported = browser.post("/local/v1/agent-instructions", json={"target": "generic",
            "agent_id": AGENT, "label": "An automatic Agent"})
        assert exported.status_code == 200, exported.text
        assert exported.json()["agent_label"] == "An automatic Agent"
        result = browser.post(f"/local/v1/agent-configurations/{AGENT}/revoke")
        assert result.status_code == 200 and result.json()["center_token_revoked"]


@pytest.mark.parametrize("lost_at", ["before_put", "after_put"])
def test_lost_reply_replays_original_uuid_name_hash_and_current_binding(credentials, tmp_path, lost_at):
    broker = Broker(tmp_path / "member", credentials)
    def lost():
        raise RcnApiError(503, "synthetic lost reply")
    setattr(broker, lost_at, lost)
    with pytest.raises(RcnApiError):
        configure(broker)
    original = profile(broker)
    assert original["registration_state"] == "pending"
    assert not list_member_agent_configs(broker)["agents"][0]["configured"]
    first_payload = broker.calls[0][2]
    setattr(broker, lost_at, None)
    current = configure(broker)
    assert current["configured"] and current["agent_id"] == AGENT
    assert broker.calls[1][2] == first_payload
    assert profile(broker)["credential_fingerprint"] == original["credential_fingerprint"]
    assert len(credentials.repo.list_tokens("alice")) == 2
    assert len([event for event in credentials.repo.list_events()
                if event.event_type == "personal_agent_credential.registered"]) == 1


def test_dpapi_failure_never_sends_registration(credentials, tmp_path, monkeypatch):
    broker = Broker(tmp_path / "member", credentials)
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic DPAPI failure")
    monkeypatch.setattr(FakeStore, "save", fail)
    with pytest.raises(RuntimeError, match="DPAPI"):
        configure(broker)
    assert broker.calls == [] and len(credentials.repo.list_tokens("alice")) == 1
    assert not (broker.root / "agents" / AGENT / "agent-profile.json").exists()


def test_crash_between_dpapi_and_journal_recovers_original_binding(credentials, tmp_path, monkeypatch):
    from research_compute_network import member_client
    broker = Broker(tmp_path / "member", credentials)
    original_write = member_client._write_json
    def fail(path, value):
        raise RuntimeError("synthetic journal failure")
    monkeypatch.setattr(member_client, "_write_json", fail)
    with pytest.raises(RuntimeError, match="journal"):
        configure(broker)
    saved = FakeStore(broker.root / "agents" / AGENT / "credentials").load()
    assert saved and broker.calls == []
    fingerprint = hashlib.sha256(saved["token"].encode()).hexdigest()
    monkeypatch.setattr(member_client, "_write_json", original_write)
    with pytest.raises(HTTPException) as changed:
        configure_member_agent(broker, "generic", AGENT, label="different label")
    assert changed.value.status_code == 409
    assert configure(broker)["configured"]
    assert profile(broker)["credential_fingerprint"] == fingerprint


@pytest.mark.parametrize("actor_change", [{"actor_id": "bob"}, {"credential_id": "another-token"},
    {"roles": ["admin"]}, {"scopes": ["api"]}, {"scopes": ["api", "agent", "extra"]}])
def test_confirmation_requires_exact_identity_id_scope_and_role(credentials, tmp_path, actor_change):
    broker = Broker(tmp_path / "member", credentials)
    broker.actor_change = actor_change
    with pytest.raises(HTTPException) as denied:
        configure(broker)
    assert denied.value.status_code == 403
    assert profile(broker)["registration_state"] == "pending"
    root = broker.root / "agents" / AGENT
    with pytest.raises(PermissionError):
        member_connection_root(SimpleNamespace(root=root, login=FakeStore(root / "credentials").load()))
    broker.actor_change = None
    assert configure(broker)["configured"]


def test_identity_switch_keeps_pending_original_and_never_rebinds(credentials, tmp_path):
    broker = Broker(tmp_path / "member", credentials)
    def switch():
        broker.auth_generation += 1
        broker.actor = {"actor_id": "bob", "roles": ["member"], "scopes": ["api"]}
        broker.login = {"center_url": "https://center.example", "token": "bob-login"}
    broker.after_put = switch
    with pytest.raises(HTTPException) as changed:
        configure(broker)
    assert changed.value.status_code == 409 and profile(broker)["actor_id"] == "alice"
    assert profile(broker)["registration_state"] == "pending"
    count = len(broker.calls)
    with pytest.raises(HTTPException) as foreign:
        configure(broker)
    assert foreign.value.status_code == 403 and len(broker.calls) == count
    assert list_member_agent_configs(broker)["agents"] == []


@pytest.mark.parametrize("field,value", [("label", "changed name"), ("target", "codex"),
                                         ("credential_fingerprint", "e" * 64)])
def test_pending_public_journal_cannot_change_original_encrypted_binding(credentials, tmp_path, field, value):
    broker = Broker(tmp_path / "member", credentials)
    def lost():
        raise RcnApiError(503, "synthetic disconnected before send")
    broker.before_put = lost
    with pytest.raises(RcnApiError):
        configure(broker)
    path = broker.root / "agents" / AGENT / "agent-profile.json"
    original = profile(broker)
    path.write_text(json.dumps({**original, field: value}))
    broker.before_put = None
    before = len(broker.calls)
    with pytest.raises(HTTPException):
        configure_member_agent(broker, value if field == "target" else "generic", AGENT,
                               label=value if field == "label" else "My own Agent")
    assert len(broker.calls) == before and len(credentials.repo.list_tokens("alice")) == 1


def test_revoke_one_agent_is_idempotent_and_preserves_other_agent_and_desktop(credentials, tmp_path):
    broker = Broker(tmp_path / "member", credentials)
    configure(broker)
    configure(broker, OTHER)
    first = revoke_member_agent_credential(broker, AGENT)
    assert first["center_token_revoked"] and first["local_login_removed"] and not first["configured"]
    assert revoke_member_agent_credential(broker, AGENT) == first
    with pytest.raises(HTTPException) as revoked:
        configure(broker)
    assert revoked.value.status_code == 401
    assert configure(broker, OTHER)["configured"]
    assert credentials.client.get("/v1/me", headers={"Authorization": "Bearer alice-login"}).status_code == 200
    assert [item["registration_state"] for item in list_member_agent_configs(broker)["agents"]] == ["revoked", "confirmed"]


def test_lost_revoke_reply_recovers_same_original_tombstone(credentials, tmp_path):
    broker = Broker(tmp_path / "member", credentials)
    configure(broker)
    normal_api = broker._api
    def api(center, token):
        client = normal_api(center, token)
        normal_request = client._request
        def request(method, path, payload=None):
            result = normal_request(method, path, payload)
            if method == "DELETE":
                raise RcnApiError(503, "synthetic lost revoke reply")
            return result
        client._request = request
        return client
    broker._api = api
    with pytest.raises(RcnApiError):
        revoke_member_agent_credential(broker, AGENT)
    assert profile(broker)["registration_state"] == "confirmed"
    broker._api = normal_api
    assert revoke_member_agent_credential(broker, AGENT)["center_token_revoked"]
    assert len([e for e in credentials.repo.list_events() if e.event_type == "personal_agent_credential.revoked"]) == 1


@pytest.mark.skipif(os.name != "nt", reason="CurrentUser DPAPI and native Windows ACL acceptance")
def test_native_dpapi_registration_retry_and_revoke_in_synthetic_root(credentials, tmp_path, monkeypatch):
    from research_compute_network.member_client_credentials import PersonalCredentialStore
    # Remove only this test's synthetic-store patches. No user profile,
    # installed application, production DB or existing credential is involved.
    monkeypatch.undo()
    monkeypatch.setattr(sys.modules[__name__], "FakeStore", PersonalCredentialStore)
    broker = Broker(tmp_path / "native-member", credentials)
    first = configure(broker)
    root = broker.root / "agents" / AGENT
    store = PersonalCredentialStore(root / "credentials")
    saved = store.load()
    assert saved["token"].encode() not in store.path.read_bytes()
    assert saved["actor"]["credential_id"] == first["credential_id"]
    assert member_connection_root(SimpleNamespace(root=root, login=saved)) == broker.root
    assert configure(broker)["credential_id"] == first["credential_id"]
    assert revoke_member_agent_credential(broker, AGENT)["center_token_revoked"]
    assert store.load() is None
