"""Pinned member modes, exact gateway handoff and retained personal identity."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import threading
from uuid import uuid4

import pytest
from fastapi import HTTPException

from research_compute_network import member_client as client
from research_compute_network import member_client_connection as connection
from research_compute_network.origin_transfer_client import OriginTransferClient

OWNER = "FIXTURE\\member-owner"
ID = "11111111-2222-4333-8444-555555555555"


def pin(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": str(path.absolute()), "sha256": hashlib.sha256(data).hexdigest()}


@pytest.fixture
def local_metadata(tmp_path, monkeypatch):
    # Native private ACL operations are covered by member registration/lifecycle
    # integration tests. These tests characterize transport ownership boundaries.
    monkeypatch.setattr(connection.storage, "_private_directory",
                        lambda path, **kw: Path(path).mkdir(parents=True, exist_ok=True) if kw.get("create", True) else None)
    monkeypatch.setattr(connection.storage, "_check_private_file", lambda path: None)
    monkeypatch.setattr(connection, "_owner", lambda: OWNER)
    monkeypatch.setattr(connection, "_task_snapshot", lambda: None)
    root = tmp_path / "original-node/member-client"
    root.mkdir(parents=True)
    key = pin(root.parent / "original-key", b"fixture key preserved")
    hosts = pin(root.parent / "original-known-hosts", b"fixture exact pinned host")
    executable = pin(tmp_path / "native/ssh.exe", b"fixture native executable")
    ssh = {"executable": executable, "host": "center.example", "user": "member-console", "port": 22,
           "identity": key, "known_hosts": hosts, "upstream_port": 28765, "center_port": 8765}
    legacy_gateway = {"coordinator_ssh_host": ssh["host"], "coordinator_ssh_user": ssh["user"],
                      "coordinator_ssh_port": 22, "identity_file": key["path"], "known_hosts_file": hosts["path"],
                      "local_web_port": 18765, "central_web_port": 8765}
    node = {"machine_id": "original-machine", "owner_user_id": "original-owner-id", "worker": True,
            "gateway": legacy_gateway, "machine_credential": "fixture original enrollment", "paused": True}
    from research_compute_network.node import _gateway_script
    legacy = {"node": pin(root.parent / "node.json", json.dumps(node).encode()),
              "gateway": pin(root.parent / "web-gateway.ps1", _gateway_script(legacy_gateway).encode()),
              "startup": pin(root.parent / "startup.ps1", b"fixture reviewed startup script")}
    spec = {"schema_version": 1, "connection_id": ID, "client_root": str(root.absolute()),
            "machine_id": node["machine_id"], "owner_user_id": node["owner_user_id"], "owner_account": OWNER,
            "mode": "managed-ssh", "ssh": ssh, "legacy": legacy}
    def save(value=spec):
        (root / connection.SPEC_NAME).write_text(json.dumps(value), encoding="utf8")
        parsed, digest = connection.load_spec(root)
        return connection.reference(parsed, digest)
    save()
    return root, spec, save


@pytest.mark.parametrize("value", ["http://127.0.0.1:28765", "http://center.example", "https://u:p@center.example",
                                   "https://center.example/path", "https://center.example?x=y"])
def test_arbitrary_http_and_unpinned_center_values_remain_rejected(tmp_path, value):
    with pytest.raises((RuntimeError, HTTPException)):
        connection.resolve_center(tmp_path, value)
    with pytest.raises(HTTPException):
        client._center(value)


def test_https_default_and_explicit_https_spec_do_not_start_ssh(local_metadata, monkeypatch):
    root, spec, save = local_metadata
    spec.update(mode="https", https_url="https://center.example/")
    spec.pop("ssh")
    ref = save()
    assert connection.public_connection(root) == {"mode": "https", "center_reference": ref}
    monkeypatch.setattr(connection, "_ensure_ssh", lambda *a: pytest.fail("HTTPS must not start SSH"))
    assert connection.resolve_center(root, ref) == "https://center.example"
    assert connection.resolve_center(root, "https://center.example/") == "https://center.example"
    with pytest.raises(RuntimeError, match="reference_required"):
        connection.resolve_center(root, "https://another.example")
    assert connection.resolve_center(root / "no-config", "https://center.example/") == "https://center.example"


def test_unselected_mode_has_no_process_task_or_handoff_mutation(local_metadata, monkeypatch):
    root, spec, save = local_metadata
    spec.update(mode="unselected", https_url="https://center.example")
    ref = save()
    assert connection.public_connection(root) is None
    monkeypatch.setattr(connection, "_ensure_ssh", lambda *a: pytest.fail("no transport choice"))
    monkeypatch.setattr(connection, "preview_legacy", lambda *a, **k: pytest.fail("no handoff choice"))
    for action in (lambda: connection.resolve_center(root, ref), lambda: connection.prepare_handoff(root)):
        with pytest.raises(RuntimeError, match="mode_unselected"):
            action()
    assert not (root / "legacy-console-handoff.json").exists()


@pytest.mark.parametrize("change", ["root", "owner", "member", "port", "known_hosts", "identity", "node", "gateway"])
def test_explicit_binding_or_channel_drift_rejects_before_native_actions(local_metadata, monkeypatch, change):
    root, spec, save = local_metadata
    reference = save()
    if change == "root": spec["client_root"] = str(root / "another")
    elif change == "owner": spec["owner_account"] = "another-owner"
    elif change == "member": spec["machine_id"] = "another-machine"
    elif change == "port": spec["ssh"]["upstream_port"] = 18765
    else:
        selected = spec["ssh" if change in {"known_hosts", "identity"} else "legacy"][change]
        Path(selected["path"]).write_bytes(b"changed fixture")
    (root / connection.SPEC_NAME).write_text(json.dumps(spec), encoding="utf8")
    monkeypatch.setattr(connection.subprocess, "Popen", lambda *a, **k: pytest.fail("no process allowed"))
    with pytest.raises((RuntimeError, ValueError)):
        connection.resolve_center(root, reference)


def test_stable_reference_binds_spec_bytes_and_requires_private_metadata(local_metadata, monkeypatch):
    root, spec, save = local_metadata
    ref = save()
    assert connection.resolve_center(root, ref, start=False) == "http://127.0.0.1:28765"
    (root / connection.SPEC_NAME).write_text(json.dumps(spec, indent=2), encoding="utf8")
    with pytest.raises(RuntimeError, match="reference_changed"):
        connection.resolve_center(root, ref, start=False)
    monkeypatch.setattr(connection.storage, "_check_private_file", lambda path: (_ for _ in ()).throw(PermissionError()))
    with pytest.raises(PermissionError):
        connection.load_spec(root)


@pytest.fixture
def fake_processes(monkeypatch):
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
        def children(self, recursive=False):
            return [Process(pid) for pid, value in rows.items() if value["parent_pid"] == self.pid]
        def terminate(self):
            signals.append(self.pid)
            rows.pop(self.pid)
            for port, entries in ports.items():
                ports[port] = [entry for entry in entries if entry[0] != self.pid]
        def wait(self, timeout): return 0
    monkeypatch.setattr(connection.psutil, "Process", Process)
    monkeypatch.setattr(connection, "_listeners", lambda port: ports.get(port, []))
    def start(command, **options):
        launches.append((command, options))
        pid = 600
        rows[pid] = {"birth": 60., "executable": command[0], "command": command,
                     "owner": OWNER, "parent_pid": 700}
        ports[28765] = [(pid, "127.0.0.1")]
        return SimpleNamespace(pid=pid)
    monkeypatch.setattr(connection.subprocess, "Popen", start)
    return rows, ports, signals, launches


def add_legacy(root, spec, processes):
    rows, ports, _, _ = processes
    command = connection._ssh_command(connection.SshChannel.model_validate(spec["ssh"]), local_port=18765)
    rows[10] = {"birth": 100., "executable": str(root.parent / "powershell.exe"), "owner": OWNER, "parent_pid": 1,
                "command": [str(root.parent / "powershell.exe"), "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-File", spec["legacy"]["gateway"]["path"]]}
    rows[11] = {"birth": 101., "executable": command[0], "owner": OWNER, "parent_pid": 10, "command": command}
    ports[18765] = [(11, "127.0.0.1")]
    (root.parent / "gateway.pid").write_text("10", encoding="ascii")


def test_ssh_launch_is_hidden_pinned_fixed_port_and_reuses_exact_receipt(local_metadata, fake_processes):
    root, spec, save = local_metadata
    _, ports, signals, launches = fake_processes
    ref = save()
    assert connection.resolve_center(root, ref) == "http://127.0.0.1:28765"
    assert connection.resolve_center(root, ref) == "http://127.0.0.1:28765"
    assert len(launches) == 1 and signals == []
    command, options = launches[0]
    assert command[3] == "127.0.0.1:28765:127.0.0.1:8765"
    assert "StrictHostKeyChecking=yes" in command and "IdentitiesOnly=yes" in command
    assert options["stdin"] == options["stdout"] == options["stderr"] == connection.subprocess.DEVNULL
    if os.name == "nt":
        assert options["creationflags"] & connection.subprocess.CREATE_NO_WINDOW
    assert len(list(root.glob("connection-receipt-*.json"))) == 1
    assert ports[28765] == [(600, "127.0.0.1")]


def test_occupied_upstream_never_stops_listener_or_retires_legacy(local_metadata, fake_processes):
    root, spec, save = local_metadata
    _, ports, signals, launches = fake_processes
    add_legacy(root, spec, fake_processes)
    ports[28765] = [(999, "127.0.0.1")]
    with pytest.raises(RuntimeError, match="upstream_port_in_use"):
        connection.prepare_handoff(root)
    assert not signals and not launches
    assert not (root / "legacy-console-handoff.json").exists()


@pytest.mark.parametrize("mode", ["https", "managed-ssh"])
def test_exact_handoff_derives_live_births_preserves_keys_worker_state_and_results(local_metadata, fake_processes, mode):
    root, spec, save = local_metadata
    rows, _, signals, launches = fake_processes
    add_legacy(root, spec, fake_processes)
    if mode == "https":
        spec.update(mode="https", https_url="https://center.example")
        spec.pop("ssh")
        save()
    retained = {Path(item["path"]): Path(item["path"]).read_bytes() for item in spec["legacy"].values()}
    key = root.parent / "original-key"
    result = root / "result.csv"
    result.write_bytes(b"original result")
    retained[key] = key.read_bytes()
    retained[result] = result.read_bytes()
    before = connection.preview_legacy(root, publish=True)
    assert before["processes"][0]["birth"] == 101.
    assert before["processes"][1]["birth"] == 100.
    assert signals == []
    receipt = connection.prepare_handoff(root)
    assert receipt["completed"] and signals == [11, 10] and not rows and not launches
    assert connection.prepare_handoff(root) == receipt
    assert {path: path.read_bytes() for path in retained} == retained
    assert json.loads((root.parent / "node.json").read_bytes())["paused"] is True
    assert (root.parent / "gateway.pid").read_text() == "10"
    assert (root / "legacy-console-preview.json").exists()


@pytest.mark.parametrize("change", ["owner", "script", "child", "listener", "extra-child"])
def test_unrelated_or_changed_legacy_processes_never_receive_signals(local_metadata, fake_processes, change):
    root, spec, _ = local_metadata
    rows, ports, signals, _ = fake_processes
    add_legacy(root, spec, fake_processes)
    if change == "owner": rows[10]["owner"] = "another-owner"
    elif change == "script": rows[10]["command"][-1] += ".other"
    elif change == "child": rows[11]["command"][-1] = "another@center.example"
    elif change == "listener": ports[18765] = [(999, "127.0.0.1")]
    else: rows[12] = {**rows[11], "birth": 102.}
    with pytest.raises(RuntimeError, match="member_connection_legacy"):
        connection.prepare_handoff(root)
    assert signals == []


def test_reused_pid_after_saved_continuation_proof_refuses_retirement(local_metadata, fake_processes):
    root, spec, _ = local_metadata
    rows, _, signals, _ = fake_processes
    add_legacy(root, spec, fake_processes)
    receipt = connection.preview_legacy(root)
    receipt["completed"] = False
    connection._publish(root, "legacy-console-handoff.json", receipt)
    rows[11]["birth"] = 999.
    with pytest.raises(RuntimeError, match="process_identity_changed"):
        connection.prepare_handoff(root)
    assert signals == []
    assert json.loads((root / "legacy-console-handoff.json").read_bytes())["completed"] is False


def test_interrupted_handoff_resumes_exact_remaining_parent_without_replaying_child(local_metadata, fake_processes):
    root, spec, _ = local_metadata
    rows, ports, signals, launches = fake_processes
    add_legacy(root, spec, fake_processes)
    receipt = connection.preview_legacy(root)
    receipt["completed"] = False
    connection._publish(root, "legacy-console-handoff.json", receipt)
    rows.pop(11)
    ports[18765] = []
    assert connection.prepare_handoff(root)["completed"]
    assert signals == [10] and launches == []


def test_reused_channel_pid_never_starts_duplicate_or_stops_changed_process(local_metadata, fake_processes):
    root, _, save = local_metadata
    rows, _, signals, launches = fake_processes
    ref = save()
    connection.resolve_center(root, ref)
    rows[600]["birth"] = 999.
    with pytest.raises(RuntimeError, match="process_identity_changed"):
        connection.resolve_center(root, ref)
    assert len(launches) == 1 and signals == []


def test_concurrent_private_channel_start_cannot_launch_two_gateways(local_metadata, fake_processes, monkeypatch):
    root, _, save = local_metadata
    _, _, _, launches = fake_processes
    entered, release = threading.Event(), threading.Event()
    original = connection.subprocess.Popen
    def delayed(command, **options):
        entered.set()
        assert release.wait(timeout=10)
        return original(command, **options)
    monkeypatch.setattr(connection.subprocess, "Popen", delayed)
    ref = save()
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(connection.resolve_center, root, ref)
        assert entered.wait(timeout=5)
        second = executor.submit(connection.resolve_center, root, ref)
        try:
            with pytest.raises(connection.storage.MemberRegistrationError, match="already_running"):
                second.result(timeout=5)
        finally:
            release.set()
        assert first.result(timeout=5) == "http://127.0.0.1:28765"
    assert len(launches) == 1


def test_task_definition_ignores_only_console_enabled_state_and_preserves_trigger_identity():
    base = {"xml": "<Task><Triggers><Trigger><Enabled>false</Enabled></Trigger></Triggers><Settings><Enabled>true</Enabled></Settings></Task>"}
    disabled = {"xml": base["xml"].replace("<Settings><Enabled>true", "<Settings><Enabled>false")}
    assert connection._task_definition(base) == connection._task_definition(disabled)
    changed_trigger = {"xml": base["xml"].replace("<Trigger><Enabled>false", "<Trigger><Enabled>true")}
    assert connection._task_definition(base) != connection._task_definition(changed_trigger)


@pytest.fixture
def windows_task_query(monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows PowerShell task query semantics")
    native_powershell = connection._powershell

    def install(functions):
        monkeypatch.setattr(connection, "_powershell", lambda script: native_powershell(functions + script))
    return install


def test_task_snapshot_absent_exits_successfully(windows_task_query):
    # Execute the generated script, including its native process exit status.
    # A named lookup would emit the same error as the real ScheduledTasks module.
    windows_task_query(r"""
function Get-ScheduledTask {
    [CmdletBinding()]param([string]$TaskPath,[string]$TaskName)
    if($TaskPath -cne '\') { throw 'Wrong task root' }
    if($PSBoundParameters.ContainsKey('TaskName')) {
        $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new(
            [InvalidOperationException]::new('Task not found'), 'CmdletizationQuery_NotFound',
            [Management.Automation.ErrorCategory]::ObjectNotFound, $TaskName))
    }
}
function Export-ScheduledTask { throw 'Absent task must not be exported' }
""")
    assert connection._task_snapshot() is None


@pytest.mark.parametrize("failure", ["query", "export"])
def test_task_snapshot_scheduler_permission_errors_remain_failures(windows_task_query, failure):
    windows_task_query(r"""
function Get-ScheduledTask {
    [CmdletBinding()]param([string]$TaskPath)
    if('FAILURE' -eq 'query') { Write-Error 'Access is denied' -Category PermissionDenied }
    [pscustomobject]@{TaskName='ResearchComputeNetwork-MemberGateway';TaskPath='\'}
}
function Export-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
    if('FAILURE' -eq 'export') { Write-Error 'Access is denied' -Category PermissionDenied }
    '<Task />'
}
""".replace("FAILURE", failure))
    with pytest.raises(RuntimeError, match="^member_connection_legacy_task_check_failed$"):
        connection._task_snapshot()


@pytest.mark.parametrize("enabled", [False, True])
def test_task_snapshot_retains_existing_case_insensitive_task_identity(windows_task_query, enabled):
    task = {"TaskName": connection.LEGACY_TASK.swapcase(), "TaskPath": "\\",
            "Principal": {"UserId": OWNER}, "Settings": {"Enabled": enabled},
            "Actions": [{"Execute": "powershell.exe", "Arguments": '-File "C:\\member\\startup.ps1"'}]}
    xml = "<Task><Settings><Enabled>" + str(enabled).lower() + "</Enabled></Settings></Task>"
    literal = json.dumps(task).replace("'", "''")
    windows_task_query(r"""
function Get-ScheduledTask {
    [CmdletBinding()]param([string]$TaskPath,[string]$TaskName)
    if($TaskPath -cne '\' -or $PSBoundParameters.ContainsKey('TaskName')) { throw 'Wrong query' }
    [pscustomobject]@{TaskName='UnrelatedTask';TaskPath='\'}
    'TASK_JSON' | ConvertFrom-Json
}
function Export-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
    if($TaskName -cne 'TASK_NAME' -or $TaskPath -cne '\') { throw 'Wrong export identity' }
    'TASK_XML'
}
""".replace("TASK_JSON", literal).replace("TASK_NAME", task["TaskName"]).replace("TASK_XML", xml))
    assert connection._task_snapshot() == {"xml": xml, "owner": OWNER, "actions": task["Actions"], "enabled": enabled}


@pytest.mark.skipif(os.name != "nt" or os.environ.get("RCN_RUN_WINDOWS_SCHEDULER_INTEGRATION") != "1",
                    reason="Opt in to the real Windows scheduler with RCN_RUN_WINDOWS_SCHEDULER_INTEGRATION=1")
def test_task_snapshot_absence_on_real_windows_scheduler(monkeypatch):
    # Use a unique absent name; never create, disable, or remove a real task.
    monkeypatch.setattr(connection, "LEGACY_TASK", "RCN-ReadOnly-Absent-" + uuid4().hex)
    assert connection._task_snapshot() is None


def migrated_source(root, spec, save):
    node = json.loads(Path(spec["legacy"]["node"]["path"]).read_bytes())
    gateway = node["gateway"]
    private = root.parent / "legacy-console-v1"
    key = pin(private / "console_ed25519", b"original private fixture migration key")
    hosts = pin(private / "known_hosts", b"original private fixture host pin")
    gateway.update(coordinator_ssh_user="rcn_member_console", identity_file=key["path"], known_hosts_file=hosts["path"])
    arguments = ["-NT", "-L", "127.0.0.1:18765:127.0.0.1:8765", "-p", "22",
                 "-i", key["path"], "-o", "UserKnownHostsFile=" + hosts["path"],
                 "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ExitOnForwardFailure=yes",
                 "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30",
                 "-o", "ServerAliveCountMax=3", "rcn_member_console@" + gateway["coordinator_ssh_host"]]
    source = ("$ErrorActionPreference='Stop'\n$args=@(" + ",".join("'" + value + "'" for value in arguments)
              + ")\n& 'C:\\Windows\\System32\\OpenSSH\\ssh.exe' @args\nexit $LASTEXITCODE\n").encode()
    spec["legacy"]["node"] = pin(root.parent / "node.json", json.dumps(node).encode())
    spec["legacy"]["gateway"] = pin(root.parent / "web-gateway.ps1", source)
    save()
    return gateway, source


def test_migrated_generator_source_exact_argv_and_existing_task_action_are_consistent(local_metadata, fake_processes, monkeypatch):
    root, spec, save = local_metadata
    gateway, source = migrated_source(root, spec, save)
    add_legacy(root, spec, fake_processes)
    variant, expected, executable = connection._legacy_source(gateway, root.parent / "web-gateway.ps1")
    assert variant == "legacy-console-migration-v1"
    assert expected[0] == "-NT" and "ConnectTimeout=10" in expected
    assert source.decode().splitlines()[1] == "$args=@(" + ",".join("'" + value + "'" for value in expected) + ")"
    rows = fake_processes[0]
    rows[11].update(executable=executable, command=[executable, *expected])
    task = {"owner": OWNER, "enabled": True, "xml": "<Task><Settings><Enabled>true</Enabled></Settings></Task>",
            "actions": [{"Execute": "powershell.exe", "Arguments": '-NoProfile -ExecutionPolicy Bypass -File "' + spec["legacy"]["startup"]["path"] + '"'}]}
    monkeypatch.setattr(connection, "_task_snapshot", lambda: deepcopy(task))
    monkeypatch.setattr(connection, "_powershell", lambda *a: None)
    proof = connection.preview_legacy(root)
    assert proof["source_variant"] == variant and proof["task"]["definition_sha256"] == connection._task_definition(task)
    assert fake_processes[2] == []
    assert connection.prepare_handoff(root)["completed"]
    assert fake_processes[2] == [11, 10]


@pytest.mark.parametrize("change", ["timeout", "extra-option", "wrong-source", "wrong-executable"])
def test_migrated_variant_rejects_every_unreviewed_argument_source_or_executable(local_metadata, fake_processes, change):
    root, spec, save = local_metadata
    gateway, source = migrated_source(root, spec, save)
    add_legacy(root, spec, fake_processes)
    _, expected, executable = connection._legacy_source(gateway, root.parent / "web-gateway.ps1")
    rows = fake_processes[0]
    command = [executable, *expected]
    if change == "timeout": command[command.index("ConnectTimeout=10")] = "ConnectTimeout=11"
    elif change == "extra-option": command[1:1] = ["-o", "ProxyCommand=unreviewed"]
    elif change == "wrong-source":
        changed = source + b"Write-Output 'unreviewed extra source'\n"
        spec["legacy"]["gateway"] = pin(root.parent / "web-gateway.ps1", changed)
        save()
    else: executable = str(root.parent / "ssh.exe"); command[0] = executable
    rows[11].update(executable=executable, command=command)
    with pytest.raises(RuntimeError, match="legacy_(?:source_not_reviewed|ssh_not_owned)"):
        connection.prepare_handoff(root)
    assert fake_processes[2] == []


def test_only_exact_owned_console_startup_task_is_disabled(local_metadata, fake_processes, monkeypatch):
    root, spec, _ = local_metadata
    add_legacy(root, spec, fake_processes)
    task = {"owner": OWNER, "enabled": True, "xml": "<Task><Settings><Enabled>true</Enabled></Settings></Task>",
            "actions": [{"Execute": "powershell.exe", "Arguments": '-NoProfile -ExecutionPolicy Bypass -File "' + spec["legacy"]["startup"]["path"] + '"'}]}
    commands = []
    monkeypatch.setattr(connection, "_task_snapshot", lambda: deepcopy(task))
    monkeypatch.setattr(connection, "_powershell", lambda command: commands.append(command))
    connection.prepare_handoff(root)
    assert len(commands) == 1 and "Disable-ScheduledTask" in commands[0]
    assert connection.LEGACY_TASK in commands[0] and "Stop-ScheduledTask" not in commands[0]
    assert "RCN-Member-" not in commands[0] and "SYSTEM" not in commands[0]


@pytest.mark.parametrize("change", ["SYSTEM", "worker-action"])
def test_system_or_worker_tasks_are_preserved_without_any_signal(local_metadata, fake_processes, monkeypatch, change):
    root, spec, _ = local_metadata
    add_legacy(root, spec, fake_processes)
    task = {"owner": OWNER if change != "SYSTEM" else "SYSTEM", "enabled": True,
            "xml": "<Task><Settings><Enabled>true</Enabled></Settings></Task>",
            "actions": [{"Execute": "powershell.exe", "Arguments": "worker supervisor action" if change == "worker-action" else
                         '-NoProfile -ExecutionPolicy Bypass -File "' + spec["legacy"]["startup"]["path"] + '"'}]}
    monkeypatch.setattr(connection, "_task_snapshot", lambda: task)
    monkeypatch.setattr(connection, "_powershell", lambda *a: pytest.fail("must preserve task"))
    with pytest.raises(RuntimeError, match="legacy_task_not_owned"):
        connection.prepare_handoff(root)
    assert fake_processes[2] == []


def test_broker_and_origin_transfer_resolve_private_upstream_but_keep_stable_login_reference(local_metadata, monkeypatch):
    root, _, save = local_metadata
    ref = save()
    starts = []
    monkeypatch.setattr(connection, "_ensure_ssh", lambda *args: starts.append(args))
    class Credentials:
        value = None
        def load(self): return self.value
        def save(self, **values): self.value = values
    credentials = Credentials()
    factories = []
    def factory(url, token):
        factories.append(url)
        return SimpleNamespace(base_url=url, token=token, current_actor=lambda: {"actor_id": "original-person"})
    broker = client.MemberBroker(root, credential_store=credentials, api_factory=factory)
    try:
        initial = broker.session()
        assert initial["configured_connection"] == {"mode": "managed-ssh", "center_reference": ref}
        assert initial["center_url"] == ref and starts == []
        broker.sign_in(client.Login(center_url=ref, token="synthetic personal token"))
        api = broker.client()
        transfer = OriginTransferClient(api)
        assert transfer.client.base_url == "http://127.0.0.1:28765"
        assert credentials.value["center_url"] == broker.login["center_url"] == ref
        assert factories == ["http://127.0.0.1:28765", "http://127.0.0.1:28765"]
        actual = client.member_api_client(ref, token="synthetic", connection_root=root)
        assert OriginTransferClient(actual).client.base_url == api.base_url
        with pytest.raises(HTTPException):
            broker.sign_in(client.Login(center_url="http://127.0.0.1:28765", token="synthetic"))
    finally:
        broker.close()
