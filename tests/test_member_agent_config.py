import base64
from io import BytesIO
import json
from pathlib import Path
from threading import RLock
from types import SimpleNamespace
from uuid import UUID
from zipfile import ZipFile

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from research_compute_network import agent_access, member_agent_config as config_module
from research_compute_network.client import RcnApiError
from research_compute_network.member_agent_config import (
    clear_member_agent_login, export_member_agent_config, list_member_agent_configs,
)
from research_compute_network.member_client import MemberBroker, create_member_app

AGENT_A = '11111111-2222-4333-8444-555555555555'
AGENT_B = '11111111-2222-4333-8444-666666666666'


class FakeStore:
    values = {}

    def __init__(self, root):
        self.root = Path(root)
        self.path = self.root / 'personal-login.dpapi'

    def load(self):
        return self.values.get(str(self.path)) if self.path.exists() else None

    def save(self, **value):
        self.root.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(b'encrypted-placeholder-for-contract-test')
        self.values[str(self.path)] = value

    def clear(self):
        self.values.pop(str(self.path), None)
        self.path.unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def isolated_store(monkeypatch):
    FakeStore.values = {}
    monkeypatch.setattr(config_module, 'PersonalCredentialStore', FakeStore)
    # These are contract tests. Native DPAPI/ACL behavior has separate acceptance.
    monkeypatch.setattr(config_module.storage, '_private_directory', lambda path: Path(path).mkdir(parents=True, exist_ok=True))


class Broker:
    _api = MemberBroker._api
    _api_with_connection = MemberBroker._api_with_connection

    def __init__(self, root):
        self.root = root
        self.lock = RLock()
        self.auth_generation = 1
        self.actor = {'actor_id': 'member-a', 'roles': ['member']}
        self.login = {'center_url': 'https://center.example', 'token': 'private-desktop-credential-NEVER-EXPORT'}
        self.online, self.reason = True, None
        self.child_actor = {'actor_id': 'member-a', 'roles': ['member'], 'scopes': ['api', 'agent'], 'credential_id': 'token-agent-test'}
        self.revoked = set()

    def api_factory(self, url, token):
        def actor():
            if token in self.revoked:
                raise RcnApiError(401, 'revoked')
            return self.child_actor
        return SimpleNamespace(current_actor=actor)

    def session(self, *, refresh=False):
        return {'connected': True, 'center_url': self.login['center_url'], 'actor': self.actor,
                'online': self.online, 'remote_actions_available': self.online,
                'connection_error': {'reason_code': self.reason} if self.reason else None}


def export(broker, target='codex', *, agent_id=AGENT_A, token='independently-issued-agent-token', label='My Agent'):
    return export_member_agent_config(broker, target, agent_id, label=label, token=token)


def exported_config(result):
    with ZipFile(BytesIO(base64.b64decode(result['content_base64']))) as archive:
        return json.loads(archive.read('rcn-agent-access.json'))


@pytest.mark.parametrize('target,entry', [('codex', 'AGENTS.md'), ('claude', 'CLAUDE.md'), ('dsh', 'AGENTS.md')])
def test_export_reuses_cli_with_independent_agent_root_and_no_credential(tmp_path, target, entry):
    broker = Broker(tmp_path)
    result = export(broker, target)
    assert result['identity_verified'] and result['credential_included'] is False
    assert result['independent_credential'] and result['agent_id'] == AGENT_A
    with ZipFile(BytesIO(base64.b64decode(result['content_base64']))) as archive:
        assert archive.namelist() == result['files']
        config = json.loads(archive.read('rcn-agent-access.json'))
        assert config['command_prefix'][1:4] == ['-B', '-m', 'research_compute_network.agent_access']
        assert config['command_prefix'][-1] == str(tmp_path / 'agents' / AGENT_A)
        assert config['credential_storage'] == 'windows-current-user-dpapi'
        assert config['token_argv_supported'] is False
        for name in archive.namelist():
            assert broker.login['token'].encode() not in archive.read(name)
            assert b'independently-issued-agent-token' not in archive.read(name)
        guide = archive.read(f'{target.upper()}_SETUP.md').decode()
        assert entry in guide and '不要覆盖原有项目规则' in guide
        assert AGENT_A in guide and 'status' in guide and 'capabilities' in guide
    profile = (tmp_path / 'agents' / AGENT_A / 'agent-profile.json').read_text()
    assert 'independently-issued-agent-token' not in profile
    assert list(tmp_path.glob('.agent-export-*')) == []


@pytest.mark.parametrize('reason,status', [('center_unavailable', 503), ('center_login_required', 401)])
def test_offline_or_revoked_desktop_identity_cannot_export(tmp_path, reason, status):
    broker = Broker(tmp_path)
    broker.online, broker.reason = False, reason
    with pytest.raises(HTTPException) as denied:
        export(broker)
    assert denied.value.status_code == status
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('actor,status', [
    ({'actor_id': 'member-b', 'roles': ['member'], 'scopes': ['api', 'agent']}, 403),
    ({'actor_id': 'member-a', 'roles': ['admin'], 'scopes': ['api', 'agent']}, 403),
    ({'actor_id': 'member-a', 'roles': ['member'], 'scopes': ['api']}, 403),
])
def test_agent_requires_same_person_restricted_scope_and_no_admin(tmp_path, actor, status):
    broker = Broker(tmp_path)
    broker.child_actor = actor
    with pytest.raises(HTTPException) as denied:
        export(broker)
    assert denied.value.status_code == status
    assert list(tmp_path.iterdir()) == []


def test_desktop_or_other_agent_token_cannot_be_reused(tmp_path):
    broker = Broker(tmp_path)
    with pytest.raises(HTTPException) as denied:
        export(broker, token=broker.login['token'])
    assert denied.value.status_code == 422
    export(broker)
    with pytest.raises(HTTPException) as duplicate:
        export(broker, agent_id=AGENT_B)
    assert duplicate.value.status_code == 409
    assert not (tmp_path / 'agents' / AGENT_B).exists()


def test_repeat_export_clear_and_revocation_keep_other_agent_and_desktop_separate(tmp_path):
    broker = Broker(tmp_path)
    first = export(broker)
    second = export(broker, agent_id=AGENT_B, token='separately-issued-second-agent')
    assert exported_config(first)['command_prefix'][-1] != exported_config(second)['command_prefix'][-1]
    assert export(broker, token=None)['agent_id'] == AGENT_A
    assert len(list_member_agent_configs(broker)['agents']) == 2
    result = clear_member_agent_login(broker, UUID(AGENT_A))
    assert result['local_login_removed'] and result['center_token_revoked'] is False
    assert clear_member_agent_login(broker, AGENT_A)['local_login_removed']
    with pytest.raises(HTTPException) as missing:
        export(broker, token=None)
    assert missing.value.status_code == 401
    assert export(broker, agent_id=AGENT_B, token=None)['agent_id'] == AGENT_B
    assert broker.login['token'] == 'private-desktop-credential-NEVER-EXPORT'
    broker.revoked.add('separately-issued-second-agent')
    with pytest.raises(RcnApiError) as revoked:
        export(broker, agent_id=AGENT_B, token=None)
    assert revoked.value.status == 401
    broker.actor = {'actor_id': 'member-b'}
    assert list_member_agent_configs(broker)['agents'] == []
    with pytest.raises(HTTPException) as foreign:
        clear_member_agent_login(broker, AGENT_B)
    assert foreign.value.status_code == 403


def test_identity_change_during_generation_returns_no_bundle_and_retains_original_profile(tmp_path, monkeypatch):
    broker = Broker(tmp_path)
    original = agent_access.instruction_artifacts
    def switch_person(*args):
        result = original(*args)
        broker.auth_generation += 1
        return result
    monkeypatch.setattr(agent_access, 'instruction_artifacts', switch_person)
    with pytest.raises(HTTPException) as denied:
        export(broker)
    assert denied.value.status_code == 409
    assert list(tmp_path.glob('.agent-export-*')) == []
    assert list_member_agent_configs(broker)['agents'][0]['agent_id'] == AGENT_A


def test_gui_broker_exports_console_interpreter_for_json_output(tmp_path, monkeypatch):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    windowed, console = runtime / 'pythonw.exe', runtime / 'python.exe'
    windowed.write_bytes(b'windowed-placeholder')
    console.write_bytes(b'console-placeholder')
    monkeypatch.setattr(agent_access.sys, 'executable', str(windowed))
    config = exported_config(export(Broker(tmp_path)))
    assert config['command_prefix'][0] == str(console) and config['command_prefix'][1] == '-B'


def test_gui_broker_does_not_export_unusable_windowed_command(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_access.sys, 'executable', str(tmp_path / 'pythonw.exe'))
    with pytest.raises(HTTPException) as denied:
        export(Broker(tmp_path))
    assert denied.value.status_code == 500
    assert list(tmp_path.glob('.agent-export-*')) == []


def test_local_endpoint_rechecks_scope_revocation_and_rejects_server_paths(tmp_path):
    class Credentials:
        value = None
        def load(self): return self.value
        def save(self, **value): self.value = value
        def clear(self): self.value = None
    class API:
        revoked = False
        def __init__(self, url, token): self.token = token
        def current_actor(self):
            if self.revoked: raise RcnApiError(401, 'revoked')
            return {'actor_id': 'member-a', 'roles': ['member'], 'scopes': ['api', 'agent'] if self.token == 'agent-private' else ['api']}
    app = create_member_app(state_root=tmp_path / 'member', credential_store=Credentials(), api_factory=API)
    body = {'target': 'claude', 'agent_id': AGENT_A, 'label': 'My Claude', 'token': 'agent-private'}
    with TestClient(app, base_url="http://127.0.0.1") as browser:
        assert browser.get('/local/v1/capabilities').status_code == 200
        assert browser.post('/local/v1/agent-instructions', json=body).status_code == 401
        assert browser.post('/local/v1/session', json={'center_url': 'https://center.example', 'token': 'desktop-private'}).status_code == 200
        reply = browser.post('/local/v1/agent-instructions', json=body)
        assert reply.status_code == 200
        assert reply.json()['files'] == ['rcn-agent-access.json', 'AGENT_ACCESS.md', 'CLAUDE_SETUP.md']
        assert browser.get('/local/v1/agent-configurations').json()['agents'][0]['configured']
        assert browser.post('/local/v1/agent-instructions', json={**body, 'output': 'C:/unexpected'}).status_code == 422
        assert browser.post('/local/v1/agent-instructions', json={**body, 'target': 'arbitrary-shell'}).status_code == 422
        assert browser.post('/local/v1/agent-instructions', json=body, headers={'Origin': 'https://foreign.example'}).status_code == 403
        assert browser.delete(f'/local/v1/agent-configurations/{AGENT_A}').json()['center_token_revoked'] is False
        API.revoked = True
        assert browser.post('/local/v1/agent-instructions', json=body).status_code == 401


from research_compute_network import member_client as member, member_client_connection as connection
from test_member_client_connection import local_metadata, fake_processes


@pytest.mark.parametrize("native", [False, True])
def test_managed_export_and_exported_cli_use_parent_transport_with_independent_token(
        local_metadata, fake_processes, monkeypatch, capsys, native):
    root, spec, save = local_metadata
    reference = save()
    calls = []
    def actor(api):
        calls.append((api.base_url, api.token))
        assert api.base_url == "http://127.0.0.1:28765"
        assert api.token in {"desktop-private", "agent-private"}
        return {"actor_id": "original-person", "roles": ["member"],
                "scopes": ["api", "agent"] if api.token == "agent-private" else ["api"],
                "credential_id": "agent-credential" if api.token == "agent-private" else "desktop-credential"}
    monkeypatch.setattr(member.RcnClient, "current_actor", actor)
    monkeypatch.setattr(member, "default_client_root", lambda: root / "wrong-default-root")
    monkeypatch.setattr(member, "PersonalCredentialStore", FakeStore)
    class API:
        __slots__ = ("base_url", "token")
        def __init__(self, url, token): self.base_url, self.token = url, token
        current_actor = actor
    credentials = SimpleNamespace(load=lambda: {"center_url": reference, "token": "desktop-private",
        "actor": {"actor_id": "original-person", "roles": ["member"]}})
    app = create_member_app(state_root=root, credential_store=credentials,
                            api_factory=member.member_api_client if native else API)
    body = {"target": "codex", "agent_id": AGENT_A, "label": "Independent Agent", "token": "agent-private"}
    with TestClient(app, base_url="http://127.0.0.1") as browser:
        browser.get("/local/v1/capabilities")
        reply = browser.post("/local/v1/agent-instructions", json=body)
        assert reply.status_code == 200, reply.text
        config = exported_config(reply.json())
        agent_root = root / "agents" / AGENT_A
        assert config["command_prefix"][-2:] == ["--state-root", str(agent_root)]
        assert calls == [("http://127.0.0.1:28765", "desktop-private"),
                         ("http://127.0.0.1:28765", "agent-private")]
        reply = browser.post("/local/v1/agent-instructions", json={key: value for key, value in body.items() if key != "token"})
        assert reply.status_code == 200
        assert calls[-2:] == calls[:2]
        # Execute the exported module entry under the exported isolated root.
        assert agent_access.main(["--state-root", str(agent_root), "status"]) == 0
        status = json.loads(capsys.readouterr().out)
        assert status["online"] and status["actor"]["credential_id"] == "agent-credential"
        assert calls[-1] == ("http://127.0.0.1:28765", "agent-private")
        assert app.state.broker.login["token"] == "desktop-private"
        assert FakeStore(agent_root / "credentials").load()["token"] == "agent-private"
        assert len(fake_processes[3]) == 1 and not fake_processes[2]


@pytest.mark.parametrize("change", ["actor", "center", "fingerprint", "parent-spec", "key"])
def test_isolated_agent_rechecks_parent_binding_before_using_its_token(
        local_metadata, fake_processes, monkeypatch, capsys, change):
    root, spec, save = local_metadata
    reference = save()
    monkeypatch.setattr(member, "PersonalCredentialStore", FakeStore)
    calls = []
    def actor(api):
        calls.append(api.token)
        return {"actor_id": "original-person", "roles": ["member"], "scopes": ["api", "agent"]}
    monkeypatch.setattr(member.RcnClient, "current_actor", actor)
    credentials = SimpleNamespace(load=lambda: {"center_url": reference, "token": "desktop-private",
        "actor": {"actor_id": "original-person", "roles": ["member"]}})
    broker = MemberBroker(root, credential_store=credentials)
    try:
        export(broker, token="agent-private")
    finally:
        broker.close()
    agent_root = root / "agents" / AGENT_A
    path = agent_root / "agent-profile.json"
    profile = json.loads(path.read_bytes())
    if change == "actor": profile["actor_id"] = "another-person"
    elif change == "center": profile["center_url"] = "https://another.example"
    elif change == "fingerprint": profile["credential_fingerprint"] = "0" * 64
    elif change == "parent-spec":
        (root / connection.SPEC_NAME).write_text(json.dumps(spec, indent=2), encoding="utf-8")
    else:
        Path(spec["ssh"]["identity"]["path"]).write_bytes(b"changed key fixture")
    path.write_text(json.dumps(profile), encoding="utf-8")
    before = list(calls)
    assert agent_access.main(["--state-root", str(agent_root), "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["connected"] and not status["online"] and not status["remote_actions_available"]
    assert status["connection_error"]["reason_code"] == "center_unavailable"
    assert calls == before and len(fake_processes[3]) == 1
