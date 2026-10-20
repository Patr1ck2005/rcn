"""Owner-private member connections and exact legacy console handoff.

Normal center entries require HTTPS. An HTTP upstream is available only through
an explicit per-member, pinned SSH spec; it is never a browser-supplied URL.
An unselected spec is inspectable and cannot start or retire any transport.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4
import xml.etree.ElementTree as ET

import psutil
from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import member_registration as storage

BROKER_PORT = 18765
SPEC_NAME = "connection.json"
LEGACY_TASK = "ResearchComputeNetwork-MemberGateway"


def _fail(reason):
    raise RuntimeError("member_connection_" + reason)


def https_center(value):
    parsed = urlsplit(value.strip())
    try:
        port = parsed.port
    except ValueError:
        _fail("https_required")
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
            or port is not None and not 1 <= port <= 65535):
        _fail("https_required")
    return value.strip().rstrip("/")


def _path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        _fail("absolute_path_required")
    storage._unlinked(path)
    return path


def _digest(path):
    path = _path(path)
    before = path.stat()
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        while part := stream.read(1024 * 1024):
            sha.update(part)
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        _fail("pinned_file_changed")
    return sha.hexdigest()


class PrivateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FilePin(PrivateModel):
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    def verify(self, *, private=False):
        path = _path(self.path)
        if private:
            storage._check_private_file(path)
        if _digest(path) != self.sha256:
            _fail("pinned_file_changed")
        return path


class SshChannel(PrivateModel):
    executable: FilePin
    host: str = Field(pattern=r"^[A-Za-z0-9.-]+$")
    user: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    port: int = Field(ge=1, le=65535)
    identity: FilePin
    known_hosts: FilePin
    upstream_port: int = Field(ge=1, le=65535)
    center_port: int = Field(ge=1, le=65535)

    @model_validator(mode="after")
    def fixed_separate_port(self):
        if self.upstream_port == BROKER_PORT:
            _fail("upstream_collides_with_broker")
        return self


class LegacyConsole(PrivateModel):
    node: FilePin
    gateway: FilePin
    startup: FilePin | None = None


class ConnectionSpec(PrivateModel):
    schema_version: Literal[1]
    connection_id: str = Field(pattern=r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
    client_root: str
    machine_id: str = Field(min_length=1, max_length=128)
    owner_user_id: str = Field(min_length=1, max_length=128)
    owner_account: str = Field(min_length=1, max_length=256)
    mode: Literal["unselected", "https", "managed-ssh"]
    https_url: str | None = None
    ssh: SshChannel | None = None
    legacy: LegacyConsole | None = None

    @model_validator(mode="after")
    def selected_fields(self):
        if self.https_url is not None:
            https_center(self.https_url)
        if self.mode == "https" and (not self.https_url or self.ssh is not None):
            _fail("https_spec_invalid")
        if self.mode == "managed-ssh" and (not self.ssh or self.https_url is not None):
            _fail("ssh_spec_invalid")
        return self


def _owner():
    return psutil.Process().username()


def load_spec(root):
    root = _path(Path(root).absolute())
    path = root / SPEC_NAME
    if not path.exists():
        return None
    storage._private_directory(root, create=False)
    storage._check_private_file(path)
    raw = storage._read_bytes(path, maximum=65536)
    spec = ConnectionSpec.model_validate(json.loads(raw))
    if _path(spec.client_root) != root or spec.owner_account.casefold() != _owner().casefold():
        _fail("owner_or_root_changed")
    if spec.legacy:
        node_path = spec.legacy.node.verify(private=True)
        spec.legacy.gateway.verify(private=True)
        if spec.legacy.startup:
            spec.legacy.startup.verify(private=True)
        if node_path != root.parent / "node.json" or _path(spec.legacy.gateway.path) != root.parent / "web-gateway.ps1":
            _fail("legacy_root_changed")
        node = json.loads(storage._read_bytes(node_path, maximum=65536))
        if node.get("machine_id") != spec.machine_id or node.get("owner_user_id") != spec.owner_user_id:
            _fail("member_identity_changed")
    return spec, hashlib.sha256(raw).hexdigest()


def reference(spec, digest):
    return "rcn-managed://" + spec.connection_id + "/" + digest


def _publish(root, name, value):
    path = Path(root) / name
    storage._check_private_file(path)
    before = storage._read_bytes(path, maximum=65536) if path.exists() else None
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    with storage._exclusive(Path(root)):
        storage._publish(path, raw, expected=before)


def _ssh_command(channel, *, local_port=None):
    channel.executable.verify()
    identity = channel.identity.verify(private=True)
    hosts = channel.known_hosts.verify(private=True)
    return [channel.executable.path, "-N", "-L",
            f"127.0.0.1:{local_port or channel.upstream_port}:127.0.0.1:{channel.center_port}",
            "-p", str(channel.port), "-i", str(identity), "-o", "UserKnownHostsFile=" + str(hosts),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ExitOnForwardFailure=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
            channel.user + "@" + channel.host]


def _snapshot(process):
    return {"pid": process.pid, "birth": process.create_time(), "executable": process.exe(),
            "command": process.cmdline(), "owner": process.username(), "parent_pid": process.ppid()}


def _same_process(pin, *, missing_ok=False):
    try:
        process = psutil.Process(pin["pid"])
        current = _snapshot(process)
    except psutil.NoSuchProcess:
        if missing_ok:
            return None
        _fail("process_missing")
    if current != pin:
        _fail("process_identity_changed")
    return process


def _listeners(port):
    return [(item.pid, item.laddr.ip) for item in psutil.net_connections(kind="tcp")
            if item.status == psutil.CONN_LISTEN and item.laddr.port == port]


def _powershell(script):
    from .member_ssh_service import _powershell as executable
    result = subprocess.run([executable(), "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        _fail("legacy_task_check_failed")
    return json.loads(result.stdout) if result.stdout.strip() else None


def _task_snapshot():
    return _powershell("$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName '" + LEGACY_TASK
        + "' -TaskPath '\\' -ErrorAction SilentlyContinue;if($t){[pscustomobject]@{xml=(Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath);owner=$t.Principal.UserId;actions=@($t.Actions|Select-Object Execute,Arguments);enabled=[bool]$t.Settings.Enabled}|ConvertTo-Json -Depth 6 -Compress}")


def _task_definition(task):
    if not task:
        return None
    xml = ET.fromstring(task["xml"])
    for item in xml.iter():
        if item.tag.rsplit("}", 1)[-1] == "Settings":
            for child in list(item):
                if child.tag.rsplit("}", 1)[-1] == "Enabled":
                    item.remove(child)
    return hashlib.sha256(ET.tostring(xml, encoding="utf8")).hexdigest()


def _file_command(command, script):
    lowered = [value.casefold() for value in command]
    try:
        at = lowered.index("-file")
    except ValueError:
        return False
    if at != len(command) - 2 or Path(command[-1]) != script:
        return False
    return lowered[1:at] in (["-noprofile", "-executionpolicy", "bypass"],
                             ["-noprofile", "-noninteractive", "-executionpolicy", "bypass"])


def _legacy_source(gateway, path):
    """Bind each reviewed script generator to its one exact SSH argv variant."""
    from .node import _gateway_script
    arguments = ["-N", "-L", f"127.0.0.1:{BROKER_PORT}:127.0.0.1:{gateway.get('central_web_port')}",
                 "-p", str(gateway.get("coordinator_ssh_port"))]
    if gateway.get("identity_file"):
        arguments += ["-i", gateway["identity_file"]]
    if gateway.get("known_hosts_file"):
        arguments += ["-o", "UserKnownHostsFile=" + gateway["known_hosts_file"]]
    arguments += ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ExitOnForwardFailure=yes",
                  "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
                  str(gateway.get("coordinator_ssh_user")) + "@" + str(gateway.get("coordinator_ssh_host"))]
    source = storage._read_bytes(path, maximum=65536).decode("utf8").replace("\r\n", "\n")
    if source == _gateway_script(gateway):
        return "node-gateway-v1", arguments, None
    # Literal output of repoint-member-console.ps1: the existing migration has
    # an independently pinned local identity, -NT and one fixed connect bound.
    private = path.parent / "legacy-console-v1"
    key, hosts = str(private / "console_ed25519"), str(private / "known_hosts")
    if (gateway.get("coordinator_ssh_user") == "rcn_member_console" and gateway.get("central_web_port") == 8765
            and gateway.get("identity_file") == key and gateway.get("known_hosts_file") == hosts):
        migrated = ["-NT", *arguments[1:]]
        at = migrated.index("StrictHostKeyChecking=yes") + 1
        migrated[at:at] = ["-o", "ConnectTimeout=10"]
        if all("'" not in value and "\n" not in value and "\r" not in value for value in migrated):
            executable = r"C:\Windows\System32\OpenSSH\ssh.exe"
            script = ("$ErrorActionPreference='Stop'\n$args=@("
                      + ",".join("'" + value + "'" for value in migrated) + ")\n& '" + executable
                      + "' @args\nexit $LASTEXITCODE\n")
            if source == script:
                return "legacy-console-migration-v1", migrated, executable
    _fail("legacy_source_not_reviewed")


def preview_legacy(root, *, publish=False):
    loaded = load_spec(root)
    if not loaded:
        _fail("spec_required")
    spec, digest = loaded
    proof = {"schema_version": 1, "spec_sha256": digest, "processes": [], "task": None}
    if not spec.legacy:
        return proof
    legacy = spec.legacy
    gateway_path = legacy.gateway.verify(private=True)
    node = json.loads(storage._read_bytes(legacy.node.verify(private=True), maximum=65536))
    old = node.get("gateway", {})
    if old.get("local_web_port") != BROKER_PORT:
        _fail("legacy_port_changed")
    variant, expected, exact_executable = _legacy_source(old, gateway_path)
    proof["source_variant"] = variant
    pid_path = Path(root).parent / "gateway.pid"
    if pid_path.exists():
        storage._check_private_file(pid_path)
        pid = int(storage._read_bytes(pid_path).decode().strip())
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            parent = None
        if parent:
            pin = _snapshot(parent)
            if (Path(pin["executable"]).name.casefold() not in {"powershell.exe", "pwsh.exe"}
                    or pin["owner"].casefold() != spec.owner_account.casefold()
                    or not _file_command(pin["command"], gateway_path)):
                _fail("legacy_process_not_owned")
            children = parent.children(recursive=False)
            if len(children) != 1:
                _fail("legacy_children_changed")
            child = _snapshot(children[0])
            if (Path(child["executable"]).name.casefold() != "ssh.exe" or child["command"][1:] != expected
                    or Path(child["command"][0]) != Path(child["executable"])
                    or exact_executable and Path(child["executable"]) != Path(exact_executable)
                    or child["owner"].casefold() != spec.owner_account.casefold() or child["parent_pid"] != pin["pid"]):
                _fail("legacy_ssh_not_owned")
            if _listeners(BROKER_PORT) != [(child["pid"], "127.0.0.1")]:
                _fail("legacy_listener_changed")
            proof["processes"] = [child, pin]
    if not proof["processes"] and _listeners(BROKER_PORT):
        _fail("legacy_listener_not_owned")
    task = _task_snapshot() if os.name == "nt" else None
    if task:
        if not legacy.startup:
            _fail("legacy_startup_pin_required")
        startup = legacy.startup.verify(private=True)
        if startup != Path(root).parent / "startup.ps1" or task["owner"].casefold() != spec.owner_account.casefold():
            _fail("legacy_task_not_owned")
        actions = task["actions"]
        expected = '-NoProfile -ExecutionPolicy Bypass -File "' + str(startup) + '"'
        if (len(actions) != 1 or Path(actions[0]["Execute"]).name.casefold() != "powershell.exe"
                or actions[0]["Arguments"] != expected):
            _fail("legacy_task_not_owned")
        proof["task"] = {"definition_sha256": _task_definition(task), "owner": task["owner"],
                         "xml_sha256": hashlib.sha256(task["xml"].encode()).hexdigest(), "enabled": task["enabled"]}
    if publish:
        _publish(root, "legacy-console-preview.json", proof)
    return proof


def _disable_task(pin):
    current = _task_snapshot()
    if not current or _task_definition(current) != pin["definition_sha256"] or current["owner"] != pin["owner"]:
        _fail("legacy_task_identity_changed")
    if current["enabled"]:
        expected = hashlib.sha256(current["xml"].encode()).hexdigest()
        owner = "'" + pin["owner"].replace("'", "''") + "'"
        _powershell("$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName '" + LEGACY_TASK
            + "' -TaskPath '\\' -ErrorAction Stop;$xml=Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath;"
            "$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($xml)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};"
            "if($hash -cne '" + expected + "' -or $t.Principal.UserId -cne " + owner + "){throw 'Console task changed'};"
            "Disable-ScheduledTask -InputObject $t|Out-Null")


def prepare_handoff(root):
    """Retire only the pinned console, after recording observed live births."""
    loaded = load_spec(root)
    if not loaded:
        return {"handoff": "not-configured"}
    spec, digest = loaded
    if spec.mode == "unselected":
        _fail("mode_unselected")
    lock_root = Path(root) / "console-handoff-lock"
    storage._private_directory(lock_root)
    with storage._exclusive(lock_root):
        return _handoff_locked(root, spec, digest)


def _handoff_locked(root, spec, digest):
    fresh = load_spec(root)
    if not fresh or fresh[1] != digest:
        _fail("handoff_spec_changed")
    receipt_path = Path(root) / "legacy-console-handoff.json"
    if receipt_path.exists():
        storage._check_private_file(receipt_path)
        receipt = json.loads(storage._read_bytes(receipt_path, maximum=65536))
        if receipt.get("spec_sha256") != digest:
            _fail("handoff_spec_changed")
        if receipt.get("completed"):
            return receipt
    else:
        if spec.ssh:
            _ssh_command(spec.ssh)
            if _listeners(spec.ssh.upstream_port):
                _fail("upstream_port_in_use")
        receipt = preview_legacy(root, publish=True)
        receipt["completed"] = False
        _publish(root, "legacy-console-handoff.json", receipt)
    # Every signal is against a freshly rechecked captured PID+birth+command+
    # executable+owner, never a port lookup. Missing members allow exact resume.
    processes = [_same_process(pin, missing_ok=True) for pin in receipt["processes"]]
    child_pids = {pin["pid"] for pin in receipt["processes"]
                  if pin["parent_pid"] in {item["pid"] for item in receipt["processes"]}}
    for pin, process in zip(receipt["processes"], processes):
        if process and any(child.pid not in child_pids for child in process.children(recursive=False)):
            _fail("legacy_children_changed")
    allowed = {(pid, "127.0.0.1") for pid in child_pids}
    if any(listener not in allowed for listener in _listeners(BROKER_PORT)):
        _fail("legacy_listener_not_owned")
    if receipt["task"]:
        _disable_task(receipt["task"])
    for pin, process in zip(receipt["processes"], processes):
        process = _same_process(pin, missing_ok=True)
        if process:
            process.terminate()
            try:
                process.wait(timeout=10)
            except psutil.TimeoutExpired:
                _fail("legacy_process_still_draining")
    if _listeners(BROKER_PORT):
        _fail("legacy_listener_still_present")
    receipt["completed"] = True
    _publish(root, "legacy-console-handoff.json", receipt)
    return receipt


def _ensure_ssh(root, spec, digest):
    lock_root = Path(root) / "channel-lock"
    storage._private_directory(lock_root)
    with storage._exclusive(lock_root):
        fresh = load_spec(root)
        if not fresh or fresh[1] != digest:
            _fail("channel_spec_changed")
        return _ensure_ssh_locked(root, spec, digest)


def _ensure_ssh_locked(root, spec, digest):
    command = _ssh_command(spec.ssh)
    path = Path(root) / "connection-process.json"
    process = None
    if path.exists():
        storage._check_private_file(path)
        pin = json.loads(storage._read_bytes(path, maximum=65536))
        if pin.get("spec_sha256") != digest or pin.get("command") != command:
            _fail("channel_receipt_changed")
        process = _same_process({key: value for key, value in pin.items() if key != "spec_sha256"}, missing_ok=True)
    if not process:
        if _listeners(spec.ssh.upstream_port):
            _fail("upstream_port_in_use")
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        process = psutil.Process(child.pid)
        pin = {**_snapshot(process), "spec_sha256": digest}
        if pin["owner"].casefold() != spec.owner_account.casefold():
            _fail("channel_owner_changed")
        _publish(root, "connection-receipt-" + str(uuid4()) + ".json", pin)
        _publish(root, "connection-process.json", pin)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        _same_process({key: value for key, value in pin.items() if key != "spec_sha256"})
        listeners = _listeners(spec.ssh.upstream_port)
        if listeners == [(process.pid, "127.0.0.1")]:
            return
        if listeners:
            _fail("upstream_listener_not_owned")
        time.sleep(.15)
    _fail("channel_start_pending")


def public_connection(root):
    loaded = load_spec(root)
    if not loaded or loaded[0].mode == "unselected":
        return None
    spec, digest = loaded
    if spec.ssh:
        _ssh_command(spec.ssh)
    return {"mode": spec.mode, "center_reference": reference(spec, digest)}


def resolve_center(root, value, *, start=True):
    loaded = load_spec(root)
    if not value.startswith("rcn-managed://"):
        center = https_center(value)
        if loaded:
            spec, _ = loaded
            if spec.mode == "unselected":
                _fail("mode_unselected")
            if spec.mode != "https" or center != https_center(spec.https_url):
                _fail("reference_required")
        return center
    if not loaded:
        _fail("spec_required")
    spec, digest = loaded
    if value != reference(spec, digest):
        _fail("reference_changed")
    if spec.mode == "unselected":
        _fail("mode_unselected")
    if spec.mode == "https":
        return https_center(spec.https_url)
    _ssh_command(spec.ssh)
    if start:
        _ensure_ssh(root, spec, digest)
    return f"http://127.0.0.1:{spec.ssh.upstream_port}"
