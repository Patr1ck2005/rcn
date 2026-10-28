"""Portable private data-only connections, transactional login and trust reuse."""
import base64
from copy import deepcopy
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import threading
from uuid import uuid4
from zipfile import ZipFile, ZipInfo

import pytest

from research_compute_network import member_connection_bundle as bundles
from research_compute_network import member_client_connection as connection
from research_compute_network import member_client_credentials as credentials
from research_compute_network.client import RcnApiError


CENTER = "11111111-2222-4333-8444-555555555555"
OWNER = "fixture-owner"
ACCOUNT = "FIXTURE\\local-member"
TOKEN = "fixture-private-personal-token-NEVER-RETURN"
KEY = (b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\nZml4dHVyZS1vbmx5\n-----END OPENSSH PRIVATE KEY-----\n")
HOSTS = b"center.example ssh-ed25519 Zml4dHVyZS1ob3N0LWtleQ==\n"


class Store:
    def __init__(self):
        self.value = None
    def save(self, **value):
        self.value = deepcopy(value)
    def load(self):
        return deepcopy(self.value)
    def clear(self):
        self.value = None


def package(*, mode="https", token=TOKEN, **fields):
    descriptor = {"mode": "https", "https_url": "https://center.example"} if mode == "https" else {
        "mode": "managed-ssh", "ssh": {"host": "center.example", "user": "member-console", "center_port": 8765}}
    values = {"center_id": CENTER, "center_name": "Research center", "owner_user_id": OWNER,
              "connection_descriptor": descriptor, "personal_token": token}
    if mode == "managed-ssh":
        values.update(ssh_identity=KEY, known_hosts=HOSTS)
    values.update(fields)
    return bundles.build_bundle(**values)


@pytest.fixture
def local(tmp_path, monkeypatch):
    # The fixture does not claim Windows ACL or DPAPI acceptance. It exercises
    # the real bounded/CAS file store with a reversible fake encryption layer.
    monkeypatch.setattr(bundles.storage, "_private_directory", lambda p, **kw: Path(p).mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(bundles.storage, "_check_private_file", lambda p: None)
    monkeypatch.setattr(bundles, "_current_user_root", lambda p: None)
    monkeypatch.setattr(connection, "_owner", lambda: ACCOUNT)
    def crypt(raw, *, decrypt=False):
        return base64.b64decode(raw[7:]) if decrypt else b"SEALED:" + base64.b64encode(raw)
    monkeypatch.setattr(credentials, "_crypt", crypt)
    root = tmp_path / "client"
    root.mkdir()
    actor = {"actor_id": OWNER, "roles": ["member"], "scopes": ["api"]}
    calls = []
    def api(url, token):
        def current_actor():
            calls.append((url, token))
            return deepcopy(actor)
        return SimpleNamespace(current_actor=current_actor)
    broker = SimpleNamespace(root=root, lock=threading.RLock(), credentials=Store(), api_factory=api,
                             login=None, actor=None, auth_generation=0, busy=set(), online=False,
                             connection_error=None)
    return broker, actor, calls


def preview(broker, raw=None):
    return bundles.preview_bundle(broker, raw or package())["import_id"]


def json_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf8")


def test_preview_is_durable_encrypted_secret_free_and_has_no_remote_action(local):
    broker, _, calls = local
    raw = package()
    found = bundles.preview_bundle(broker, raw)
    assert found == {"import_id": hashlib.sha256(raw).hexdigest(), "package_sha256": hashlib.sha256(raw).hexdigest(),
                     "state": "awaiting_confirmation", "preview": {"owner_user_id": OWNER,
                         "center_name": "Research center", "mode": "https"}}
    assert calls == [] and broker.login is None
    assert not (broker.root / "connection.json").exists()
    persisted = (broker.root / "connection-imports" / (found["import_id"] + ".dpapi")).read_bytes()
    assert persisted.startswith(b"SEALED:") and TOKEN.encode() not in persisted
    assert bundles.read_import(broker, found["import_id"]) == found
    assert bundles.preview_bundle(broker, raw) == found


@pytest.mark.parametrize("field", ["preview", "reason_code", "state"])
def test_private_receipt_cannot_add_secret_fields_to_public_status(local, field):
    broker, _, calls = local
    identifier = preview(broker)
    state = bundles._load(broker.root, identifier)
    if field == "preview": state["preview"]["token"] = TOKEN
    else: state[field] = TOKEN
    bundles._save(broker.root, state)
    with pytest.raises(bundles.ConnectionImportError, match="invalid_journal") as found:
        bundles.read_import(broker, identifier)
    assert TOKEN not in str(found.value) and not calls


def test_confirm_verifies_real_identity_then_completes_without_worker_or_submissions(local):
    broker, _, calls = local
    identifier = preview(broker)
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    assert calls == [("https://center.example", TOKEN)]
    assert broker.login["token"] == TOKEN and broker.online is True
    spec, digest = connection.load_spec(broker.root)
    assert spec.center_id == CENTER and spec.owner_user_id == OWNER and spec.machine_id is None
    assert broker.login["center_url"] == connection.reference(spec, digest)
    assert not (broker.root.parent / "node.json").exists()
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["member", "admin", "agent", "missing"])
def test_identity_mismatch_leaves_original_login_and_connection_unchanged(local, change):
    broker, actor, _ = local
    first = preview(broker)
    bundles.confirm_import(broker, first)
    before = (broker.root / "connection.json").read_bytes(), deepcopy(broker.login)
    if change == "member": actor["actor_id"] = "someone-else"
    elif change == "admin": actor["roles"] = ["admin", "member"]
    elif change == "agent": actor["scopes"] = ["api", "agent"]
    else: actor.clear()
    identifier = preview(broker, package(token="fixture-replacement"))
    with pytest.raises(bundles.ConnectionImportError, match="personal_identity_mismatch"):
        bundles.confirm_import(broker, identifier)
    assert ((broker.root / "connection.json").read_bytes(), broker.login) == before
    assert bundles.read_import(broker, identifier)["state"] == "failed"


def test_lost_probe_response_is_same_import_no_remote_mutation(local):
    broker, _, calls = local
    api = broker.api_factory
    once = [True]
    def unreliable(url, token):
        actual = api(url, token)
        def current():
            if once:
                once.pop()
                raise RcnApiError(0, TOKEN)
            return actual.current_actor()
        return SimpleNamespace(current_actor=current)
    broker.api_factory = unreliable
    identifier = preview(broker)
    with pytest.raises(bundles.ConnectionImportError, match="center_unavailable") as found:
        bundles.confirm_import(broker, identifier)
    assert TOKEN not in str(found.value) and broker.login is None
    assert bundles.preview_bundle(broker, package())["import_id"] == identifier
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    assert len(calls) == 1


def test_personal_member_with_machine_owner_role_is_allowed_without_enrollment(local):
    broker, actor, calls = local
    actor["roles"] = ["member", "machine_owner"]
    identifier = preview(broker)
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    assert len(calls) == 1 and not (broker.root.parent / "node.json").exists()


@pytest.mark.parametrize("status,reason", [(401, "center_login_required"), (403, "center_permission_denied"),
                                         (0, "center_unavailable"), (503, "center_unavailable")])
def test_center_auth_and_network_failures_keep_distinct_secret_free_codes(local, status, reason):
    broker, _, _ = local
    def api(url, token):
        def fail():
            raise RcnApiError(status, TOKEN)
        return SimpleNamespace(current_actor=fail)
    broker.api_factory = api
    identifier = preview(broker)
    with pytest.raises(bundles.ConnectionImportError) as found:
        bundles.confirm_import(broker, identifier)
    assert found.value.reason_code == "member_connection_import_" + reason
    assert found.value.reason_code in bundles.IMPORT_REASON_CODES
    assert TOKEN not in json.dumps(bundles.read_import(broker, identifier))
    assert broker.login is None and not (broker.root / "connection.json").exists()


def test_lost_completed_response_retry_has_no_second_identity_call(local, monkeypatch):
    broker, _, calls = local
    identifier = preview(broker)
    save = bundles._save
    def lose(root, state):
        save(root, state)
        if state["state"] == "completed":
            raise ConnectionError("fixture lost local response")
    monkeypatch.setattr(bundles, "_save", lose)
    with pytest.raises(ConnectionError):
        bundles.confirm_import(broker, identifier)
    monkeypatch.setattr(bundles, "_save", save)
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    assert len(calls) == 1


def test_connection_update_migrates_agent_credentials_and_journals_without_execution(local):
    broker, _, calls = local
    identifier = preview(broker)
    bundles.confirm_import(broker, identifier)
    old = broker.login["center_url"]
    agent_id, operation_id = str(uuid4()), str(uuid4())
    agent = broker.root / "agents" / agent_id
    profile = {"schema_version": 1, "agent_id": agent_id, "actor_id": OWNER, "center_url": old,
               "target": "codex", "label": "Fixture", "credential_fingerprint": bundles._sha(b"agent-only")}
    json_file(agent / "agent-profile.json", profile)
    store = credentials.PersonalCredentialStore(agent / "credentials")
    store.save(center_url=old, token="agent-only", actor={"actor_id": OWNER, "agent_registration": profile})
    original = {"operation_id": operation_id, "center_url": old, "actor_id": OWNER,
                "phase": "submitted", "job_id": "original-job", "request_hash": "original-hash"}
    for root in (broker.root, agent):
        json_file(root / "operations" / (operation_id + ".json"), original)
    new = preview(broker, package(token="fixture-new-personal-token"))
    bundles.confirm_import(broker, new)
    current = broker.login["center_url"]
    # Changing only the personal token need not change the connection digest;
    # force a center display update to exercise content-addressed references.
    newer = preview(broker, package(center_name="Updated center", token="fixture-next-token"))
    bundles.confirm_import(broker, newer)
    current = broker.login["center_url"]
    assert current != old
    assert json.loads((agent / "agent-profile.json").read_text())["center_url"] == current
    assert store.load()["center_url"] == current
    assert store.load()["actor"]["agent_registration"]["center_url"] == current
    assert store.load()["token"] == "agent-only"
    for root in (broker.root, agent):
        assert json.loads((root / "operations" / (operation_id + ".json")).read_text()) == {**original, "center_url": current}
    assert len(calls) == 3


@pytest.mark.parametrize("fields,reason", [({"center_id": "22222222-2222-4333-8444-555555555555"}, "different_center"),
    ({"owner_user_id": "another-member"}, "different_member"),
    ({"connection_descriptor": {"mode": "https", "https_url": "https://evil.example"}}, "center_trust_changed")])
def test_existing_identity_and_endpoint_trust_prevent_automatic_merge(local, fields, reason):
    broker, _, calls = local
    bundles.confirm_import(broker, preview(broker))
    before = broker.login, (broker.root / "connection.json").read_bytes()
    identifier = preview(broker, package(**fields))
    with pytest.raises(bundles.ConnectionImportError, match=reason):
        bundles.confirm_import(broker, identifier)
    assert len(calls) == 1
    assert (broker.login, (broker.root / "connection.json").read_bytes()) == before


@pytest.mark.parametrize("change", ["owner", "root", "agent_root", "linked_root"])
def test_import_receipts_are_bound_to_current_owner_and_root(local, monkeypatch, change):
    broker, _, _ = local
    identifier = preview(broker)
    if change == "owner":
        monkeypatch.setattr(connection, "_owner", lambda: "different-account")
    elif change == "root":
        old = broker.root
        broker.root = old.parent / "copied-client"
        broker.root.mkdir()
        (broker.root / "connection-imports").mkdir()
        (broker.root / "connection-imports" / (identifier + ".dpapi")).write_bytes((old / "connection-imports" / (identifier + ".dpapi")).read_bytes())
    elif change == "agent_root":
        json_file(broker.root / "agent-profile.json", {})
    else:
        monkeypatch.setattr(connection.storage, "_unlinked", lambda path: (_ for _ in ()).throw(PermissionError("fixture symlink")))
    with pytest.raises((bundles.ConnectionImportError, PermissionError)):
        bundles.confirm_import(broker, identifier)


def rewrite(raw, transform):
    with ZipFile(BytesIO(raw)) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    transform(files)
    result = BytesIO()
    with ZipFile(result, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return result.getvalue()


@pytest.mark.parametrize("attack", ["traversal", "absolute", "backslash", "extra_script", "hash", "manifest_extra", "boolean_version", "json_duplicate", "size", "case_duplicate", "duplicate", "symlink"])
def test_archive_validation_precedes_disk_or_network_actions(local, attack):
    broker, _, calls = local
    raw = package()
    def change(files):
        if attack == "traversal": files["../escape"] = b"x"
        elif attack == "absolute": files["/escape"] = b"x"
        elif attack == "backslash": files["..\\escape"] = b"x"
        elif attack == "extra_script": files["run.cmd"] = b"echo no"
        elif attack == "hash": files["member-token.txt"] = b"different"
        elif attack == "manifest_extra":
            manifest = json.loads(files["manifest.json"])
            manifest["administrator_token"] = "forbidden"
            files["manifest.json"] = json.dumps(manifest).encode()
        elif attack == "boolean_version": files["manifest.json"] = files["manifest.json"].replace(b'"schema_version":1', b'"schema_version":true')
        elif attack == "json_duplicate": files["manifest.json"] = files["manifest.json"].replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
        elif attack == "size": files["member-token.txt"] = b"x" * (bundles.MAX_CONTENT_BYTES + 1)
        elif attack == "case_duplicate": files["MEMBER-TOKEN.TXT"] = b"x"
    if attack in {"duplicate", "symlink"}:
        output = BytesIO(raw)
        with ZipFile(output, "a") as archive:
            if attack == "duplicate":
                with pytest.warns(UserWarning):
                    archive.writestr("member-token.txt", b"x")
            else:
                info = ZipInfo("ssh-identity")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, b"/outside")
        raw = output.getvalue()
    else:
        raw = rewrite(raw, change)
    with pytest.raises(bundles.ConnectionImportError):
        bundles.preview_bundle(broker, raw)
    assert not calls and not (broker.root / "connection-imports").exists()


@pytest.mark.parametrize("descriptor", [{"mode": "https", "https_url": "http://center.example"},
    {"mode": "https", "https_url": "https://u:p@center.example"},
    {"mode": "https", "https_url": "https://center\n.example"},
    {"mode": "managed-ssh", "ssh": {"host": "center.example", "user": "member", "center_port": 8765, "upstream_port": 18765}},
    {"mode": "managed-ssh", "ssh": {"host": "-oProxyCommand", "user": "member", "center_port": 8765}},
    {"mode": "managed-ssh", "ssh": {"host": "center.example", "user": "member", "center_port": 8765, "identity_file": "C:/source/key"}}])
def test_portable_schema_forbids_http_commands_paths_and_broker_port(descriptor):
    with pytest.raises(bundles.ConnectionImportError):
        package(connection_descriptor=descriptor)


def test_missing_ssh_is_stable_and_old_configuration_remains_usable(local, monkeypatch):
    broker, _, calls = local
    monkeypatch.setattr(bundles, "_system_ssh", lambda: bundles._fail("ssh_prerequisite_required"))
    identifier = preview(broker, package(mode="managed-ssh"))
    with pytest.raises(bundles.ConnectionImportError, match="ssh_prerequisite_required"):
        bundles.confirm_import(broker, identifier)
    assert bundles.read_import(broker, identifier)["reason_code"] == "member_connection_import_ssh_prerequisite_required"
    assert not calls and broker.login is None and not (broker.root / "connection.json").exists()


def test_pending_status_enables_original_import_repair_without_approving_new_packages(local, monkeypatch):
    broker, _, _ = local
    assert bundles.pending_import(broker) is None
    identifier = preview(broker, package(mode="managed-ssh"))
    assert bundles.pending_import(broker)["state"] == "awaiting_confirmation"
    monkeypatch.setattr(bundles, "_system_ssh", lambda: bundles._fail("ssh_prerequisite_required"))
    with pytest.raises(bundles.ConnectionImportError):
        bundles.confirm_import(broker, identifier)
    found = bundles.pending_import(broker)
    assert found["import_id"] == identifier and found["state"] == "failed"
    assert found["preview"]["mode"] == "managed-ssh"
    assert found["reason_code"] == "member_connection_import_ssh_prerequisite_required"
    assert TOKEN not in json.dumps(found) and "ssh-identity" not in json.dumps(found)
    # A later user-selected package supersedes the earlier failed SSH attempt.
    newer = preview(broker, package())
    assert bundles.pending_import(broker)["import_id"] == newer
    bundles.confirm_import(broker, newer)
    assert bundles.pending_import(broker) is None


def test_failure_after_publishing_new_spec_rolls_back_original_login_and_journals(local, monkeypatch):
    broker, _, _ = local
    bundles.confirm_import(broker, preview(broker))
    old_login = deepcopy(broker.login)
    old_spec = (broker.root / "connection.json").read_bytes()
    original = {"actor_id": OWNER, "center_url": broker.login["center_url"], "job_id": "original-job"}
    path = broker.root / "operations" / "original.json"
    json_file(path, original)
    before = path.read_bytes()
    save = broker.credentials.save
    def fail(**value):
        save(**value)
        if value["token"] == "fixture-replacement":
            raise OSError("fixture after durable credential save")
    monkeypatch.setattr(broker.credentials, "save", fail)
    identifier = preview(broker, package(center_name="Updated", token="fixture-replacement"))
    with pytest.raises(bundles.ConnectionImportError, match="commit_failed"):
        bundles.confirm_import(broker, identifier)
    assert broker.login == old_login and broker.credentials.load() == old_login
    assert (broker.root / "connection.json").read_bytes() == old_spec
    assert path.read_bytes() == before


def test_process_crash_resumes_durable_local_commit_without_second_probe(local, monkeypatch):
    broker, _, calls = local
    identifier = preview(broker)
    apply = bundles._file_apply
    once = [True]
    def crash(root, change, **kw):
        apply(root, change, **kw)
        if once:
            once.pop()
            raise SystemExit("fixture process crash")
    monkeypatch.setattr(bundles, "_file_apply", crash)
    with pytest.raises(SystemExit):
        bundles.confirm_import(broker, identifier)
    assert bundles.read_import(broker, identifier)["state"] == "committing"
    monkeypatch.setattr(bundles, "_file_apply", apply)
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    assert len(calls) == 1


def test_large_history_uses_chunked_encrypted_migration_and_preserves_job_content(local):
    broker, _, calls = local
    bundles.confirm_import(broker, preview(broker))
    original = {"actor_id": OWNER, "center_url": broker.login["center_url"], "job_id": "retained-job",
                "phase": "submitted", "request_hash": "retained-request", "metadata": "fixture" * 60000}
    path = broker.root / "operations" / "retained.json"
    json_file(path, original)
    identifier = preview(broker, package(center_name="Revised display name"))
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    assert json.loads(path.read_text()) == {**original, "center_url": broker.login["center_url"]}
    directory = broker.root / "connection-imports" / identifier
    assert len(list((directory / "transaction").glob("0.*.dpapi"))) > 2
    for encrypted in (directory / "transaction").glob("*.dpapi"):
        assert encrypted.stat().st_size <= bundles.MAX_STATE_BYTES and TOKEN.encode() not in encrypted.read_bytes()
    assert len(calls) == 2


def test_cli_reads_named_environment_token_and_emits_no_secrets(local, monkeypatch, capsys):
    broker, _, _ = local
    descriptor = broker.root / "descriptor.json"
    json_file(descriptor, {"center_id": CENTER, "center_name": "Research center", "owner_user_id": OWNER,
                          "connection_descriptor": {"mode": "https", "https_url": "https://center.example"}})
    monkeypatch.setenv("RCN_FIXTURE_PERSONAL", TOKEN)
    target = broker.root / "private.zip"
    assert bundles.main(["build", "--descriptor-file", str(descriptor), "--token-env", "RCN_FIXTURE_PERSONAL", "--output", str(target)]) == 0
    assert TOKEN not in capsys.readouterr().out
    assert bundles._unpack(target.read_bytes())[0].owner_user_id == OWNER
    with pytest.raises(SystemExit):
        bundles.main(["build", "--token", TOKEN])


@pytest.fixture
def ssh_runtime(local, monkeypatch):
    broker, _, _ = local
    executable = broker.root.parent / "native-ssh.exe"
    executable.write_bytes(b"fixture-system-openssh")
    monkeypatch.setattr(bundles, "_system_ssh", lambda: {"path": str(executable), "sha256": bundles._sha(executable.read_bytes())})
    rows, ports, signals, launches = {}, {}, [], []
    class Process:
        def __init__(self, pid):
            if pid not in rows:
                raise connection.psutil.NoSuchProcess(pid)
            self.pid = pid
        def create_time(self): return rows[self.pid]["birth"]
        def exe(self): return rows[self.pid]["executable"]
        def cmdline(self): return rows[self.pid]["command"]
        def username(self): return rows[self.pid]["owner"]
        def ppid(self): return rows[self.pid]["parent_pid"]
        def children(self, recursive=False): return []
        def terminate(self):
            signals.append(self.pid)
            rows.pop(self.pid)
            for port, values in ports.items():
                ports[port] = [v for v in values if v[0] != self.pid]
        def wait(self, timeout): return 0
    def start(command, **options):
        pid = 600 + len(launches)
        launches.append((command, options))
        rows[pid] = {"birth": float(pid), "executable": command[0], "command": command,
                     "owner": ACCOUNT, "parent_pid": 700}
        port = int(command[3].split(":")[1])
        ports[port] = [(pid, "127.0.0.1")]
        return SimpleNamespace(pid=pid)
    monkeypatch.setattr(connection.psutil, "Process", Process)
    monkeypatch.setattr(connection, "_listeners", lambda port: ports.get(port, []))
    monkeypatch.setattr(connection.subprocess, "Popen", start)
    return rows, ports, signals, launches


def test_managed_ssh_import_binds_local_paths_and_adopts_staged_owned_process(local, ssh_runtime):
    broker, _, calls = local
    _, ports, signals, launches = ssh_runtime
    identifier = preview(broker, package(mode="managed-ssh"))
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    spec, digest = connection.load_spec(broker.root)
    assert spec.ssh.identity.path.startswith(str(broker.root))
    assert spec.ssh.known_hosts.path.startswith(str(broker.root))
    assert connection.resolve_center(broker.root, broker.login["center_url"]) == "http://127.0.0.1:28765"
    assert len(launches) == 1 and not signals
    command, options = launches[0]
    assert command[command.index("-F") + 1] == "none"
    assert "ProxyCommand=none" in command and "ControlPath=none" in command
    assert "GlobalKnownHostsFile=none" in command and "UpdateHostKeys=no" in command
    assert command[-1] == "member-console@center.example"
    assert options["stdin"] == options["stdout"] == options["stderr"] == connection.subprocess.DEVNULL
    assert ports[28765] == [(600, "127.0.0.1")]
    assert calls == [("http://127.0.0.1:28765", TOKEN)]
    assert json.loads((broker.root / "connection-process.json").read_text())["spec_sha256"] == digest


def test_ssh_update_preserves_old_channel_until_identity_verified_and_only_retires_owned_pid(local, ssh_runtime):
    broker, _, _ = local
    rows, _, signals, launches = ssh_runtime
    bundles.confirm_import(broker, preview(broker, package(mode="managed-ssh")))
    old_login = deepcopy(broker.login)
    api = broker.api_factory
    def check_before_commit(url, token):
        assert 600 in rows and not signals
        assert broker.login == old_login
        assert url != "http://127.0.0.1:28765"
        return api(url, token)
    broker.api_factory = check_before_commit
    identifier = preview(broker, package(mode="managed-ssh", center_name="New center name", token="fixture-new"))
    bundles.confirm_import(broker, identifier)
    assert len(launches) == 2 and signals == [600] and set(rows) == {601}
    spec, _ = connection.load_spec(broker.root)
    assert spec.ssh.upstream_port != 28765
    assert connection.resolve_center(broker.root, broker.login["center_url"]).startswith("http://127.0.0.1:")
    assert len(launches) == 2


def test_lost_ssh_completion_response_retries_only_previous_owned_channel_cleanup(local, ssh_runtime, monkeypatch):
    broker, _, calls = local
    rows, _, signals, _ = ssh_runtime
    bundles.confirm_import(broker, preview(broker, package(mode="managed-ssh")))
    identifier = preview(broker, package(mode="managed-ssh", center_name="Updated center"))
    save = bundles._save
    def lose(root, state):
        save(root, state)
        if state["state"] == "completed":
            raise ConnectionError("fixture lost completion response")
    monkeypatch.setattr(bundles, "_save", lose)
    with pytest.raises(ConnectionError):
        bundles.confirm_import(broker, identifier)
    assert set(rows) == {600, 601} and not signals
    monkeypatch.setattr(bundles, "_save", save)
    assert bundles.confirm_import(broker, identifier)["state"] == "completed"
    assert set(rows) == {601} and signals == [600] and len(calls) == 2


def test_unrelated_occupied_ssh_port_is_never_killed_or_replaced(local, ssh_runtime):
    broker, _, calls = local
    _, ports, signals, launches = ssh_runtime
    ports[28765] = [(999, "127.0.0.1")]
    with pytest.raises(bundles.ConnectionImportError):
        bundles.confirm_import(broker, preview(broker, package(mode="managed-ssh")))
    assert not calls and not signals and not launches
    assert not (broker.root / "connection.json").exists()


@pytest.mark.parametrize("field", ["identity", "known_hosts", "executable", "staged_spec", "existing_spec"])
def test_mutable_files_changed_during_identity_probe_abort_before_install(local, ssh_runtime, field):
    broker, _, _ = local
    if field == "existing_spec":
        bundles.confirm_import(broker, preview(broker, package(mode="managed-ssh")))
    original = (broker.root / "connection.json").read_bytes() if (broker.root / "connection.json").exists() else None
    original_login = deepcopy(broker.login)
    api = broker.api_factory
    def mutate(url, token):
        if field == "existing_spec":
            path = broker.root / "connection.json"
        else:
            stage = next(path for path in (broker.root / "connection-imports").glob("*/connection.json")
                         if path.parent.name == identifier)
            value = json.loads(stage.read_text())
            path = stage if field == "staged_spec" else Path(value["ssh"][field]["path"])
        path.write_bytes(path.read_bytes() + b" ")
        return api(url, token)
    broker.api_factory = mutate
    identifier = preview(broker, package(mode="managed-ssh", token="fixture-after"))
    with pytest.raises(bundles.ConnectionImportError):
        bundles.confirm_import(broker, identifier)
    assert broker.login == original_login
    assert len(ssh_runtime[0]) == (1 if field == "existing_spec" else 0)
    if field != "existing_spec":
        assert ((broker.root / "connection.json").read_bytes() if original else None) == original


def test_failed_ssh_identity_probe_stops_only_its_staged_process_and_preserves_old(local, ssh_runtime):
    broker, actor, _ = local
    rows, _, signals, launches = ssh_runtime
    bundles.confirm_import(broker, preview(broker, package(mode="managed-ssh")))
    old_login = deepcopy(broker.login)
    actor["actor_id"] = "different-owner"
    identifier = preview(broker, package(mode="managed-ssh", token="fixture-other"))
    with pytest.raises(bundles.ConnectionImportError, match="personal_identity_mismatch"):
        bundles.confirm_import(broker, identifier)
    assert broker.login == old_login and set(rows) == {600}
    assert signals == [601] and len(launches) == 2


def test_legacy_v1_connection_keeps_worker_gateway_bytes_and_paused_state(local):
    broker, _, calls = local
    machine = broker.root.parent / "node.json"
    gateway = broker.root.parent / "web-gateway.ps1"
    node_bytes = json.dumps({"machine_id": "existing-machine", "owner_user_id": OWNER, "paused": True,
                             "machine_credential": "fixture-worker-private"}).encode()
    machine.write_bytes(node_bytes)
    gateway.write_bytes(b"fixture legacy gateway unchanged")
    spec = {"schema_version": 1, "connection_id": str(uuid4()), "client_root": str(broker.root),
            "machine_id": "existing-machine", "owner_user_id": OWNER, "owner_account": ACCOUNT,
            "mode": "https", "https_url": "https://center.example", "legacy": {
                "node": {"path": str(machine), "sha256": bundles._sha(node_bytes)},
                "gateway": {"path": str(gateway), "sha256": bundles._sha(gateway.read_bytes())}}}
    json_file(broker.root / "connection.json", spec)
    old, digest = connection.load_spec(broker.root)
    handoff = {"schema_version": 1, "spec_sha256": digest, "completed": True,
               "task": None, "processes": [], "source_variant": "fixture-retained"}
    json_file(broker.root / "legacy-console-handoff.json", handoff)
    broker.login = {"center_url": connection.reference(old, digest), "token": "fixture-old", "actor": {"actor_id": OWNER}}
    broker.actor = broker.login["actor"]
    broker.credentials.save(**broker.login)
    bundles.confirm_import(broker, preview(broker))
    new, _ = connection.load_spec(broker.root)
    assert new.machine_id == "existing-machine" and new.legacy == old.legacy
    receipt = connection.prepare_handoff(broker.root)
    assert receipt == {**handoff, "spec_sha256": connection.load_spec(broker.root)[1]}
    assert machine.read_bytes() == node_bytes and gateway.read_bytes() == b"fixture legacy gateway unchanged"
    assert len(calls) == 1


def test_dpapi_failure_precedes_network_and_never_stores_plaintext(local, monkeypatch):
    broker, _, calls = local
    def fail(raw, **kw):
        raise credentials.CredentialUnavailable("fixture unavailable")
    monkeypatch.setattr(credentials, "_crypt", fail)
    with pytest.raises(credentials.CredentialUnavailable):
        preview(broker)
    assert not calls and not list((broker.root / "connection-imports").glob("*.dpapi"))


@pytest.mark.skipif(os.name != "nt", reason="Native Windows CurrentUser DPAPI and private ACL check")
def test_native_private_receipt_uses_dpapi_and_current_user_acl(tmp_path):
    root = tmp_path / "native-private-client"
    bundles.storage._private_directory(root)
    broker = SimpleNamespace(root=root, lock=threading.RLock())
    found = bundles.preview_bundle(broker, package())
    path = root / "connection-imports" / (found["import_id"] + ".dpapi")
    assert TOKEN.encode() not in path.read_bytes()
    bundles.storage._check_private_file(path)
    assert bundles.read_import(broker, found["import_id"]) == found
