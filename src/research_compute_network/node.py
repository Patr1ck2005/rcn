"""Member-node enrollment and loopback web gateway lifecycle."""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

import psutil

from .models import MachineMetrics, MachineState
from .service import PACKAGE_VERSION, PROTOCOL_VERSION, STABLE_RUNTIME_VERSION


NODE_STARTUP_TASK = "ResearchComputeNetwork-MemberGateway"
NODE_SHORTCUT_NAME = "Research Compute Network.lnk"
NODE_LAUNCHER_SCRIPT = "open-console.ps1"
NODE_LAUNCHER_MANIFEST = "launcher.json"


def default_node_root() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "ResearchComputeNetwork"


def node_preflight(*, worker: bool) -> dict:
    usage = shutil.disk_usage(default_node_root().anchor or Path.cwd().anchor)
    return {
        "hostname": socket.gethostname(),
        "cpu_count": psutil.cpu_count(logical=True) or 1,
        "memory_mb": int(psutil.virtual_memory().total / (1024 * 1024)),
        "free_disk_mb": int(usage.free / (1024 * 1024)),
        "ssh_available": shutil.which("ssh") is not None,
        "worker_requested": worker,
        "runtime_version": STABLE_RUNTIME_VERSION if worker else None,
        "protocol_version": PROTOCOL_VERSION,
        "package_version": PACKAGE_VERSION,
    }


def _post_json(url: str, payload: dict, *, timeout_s: int = 30) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"node enrollment failed ({exc.code}): {detail}") from exc


def setup_node(
    *,
    control_plane_url: str,
    enrollment_code: str,
    machine_id: str,
    owner_user_id: str,
    worker: bool,
    coordinator_ssh_host: str,
    coordinator_ssh_user: str,
    coordinator_ssh_port: int = 22,
    identity_file: Path | None = None,
    known_hosts_file: Path | None = None,
    central_web_port: int = 8000,
    local_web_port: int = 18765,
    root: Path | None = None,
    start_gateway: bool = False,
    install_launcher: bool = False,
    desktop_dir: Path | None = None,
) -> dict:
    state_root = (root or default_node_root()).resolve()
    state_root.mkdir(parents=True, exist_ok=True)
    preflight = node_preflight(worker=worker)
    if not preflight["ssh_available"]:
        raise RuntimeError("Windows OpenSSH client is required for the web access gateway")
    config_path = state_root / "node.json"
    existing_config = None
    if config_path.is_file():
        try:
            existing_config = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing_config = None
    if existing_config and existing_config.get("enrollment_state") == "enrolled_paused" and not worker:
        # Idempotent rerun (B0 friction fix): a completed submitter enrollment
        # must never consume a second one-time code. Refresh gateway state and
        # return the surviving configuration.
        gateway_result = {"gateway_started": False}
        if start_gateway:
            gateway_result = start_node_gateway(root=state_root)
            _wait_local_port(local_web_port)
        return {
            "machine_id": existing_config.get("machine_id"),
            "policy_state": "paused_pending_admin_acceptance",
            "config_path": str(config_path),
            "gateway_path": str(state_root / "web-gateway.ps1"),
            "web_url": f"http://127.0.0.1:{existing_config.get('gateway', {}).get('local_web_port', local_web_port)}",
            "preflight": preflight,
            "idempotent_rerun": True,
            **gateway_result,
        }
    machine = MachineState(
        machine_id=machine_id,
        owner_user_id=owner_user_id,
        hostname=preflight["hostname"],
        labels={"member-node"},
        capabilities={"submitter", *( ["worker"] if worker else [])},
        total_cpus=preflight["cpu_count"],
        total_memory_mb=preflight["memory_mb"],
        metrics=MachineMetrics(
            total_memory_mb=preflight["memory_mb"],
            available_memory_mb=int(psutil.virtual_memory().available / (1024 * 1024)),
            free_disk_mb=preflight["free_disk_mb"],
            source="node-preflight",
        ),
        package_version=PACKAGE_VERSION,
        runtime_version=STABLE_RUNTIME_VERSION if worker else None,
        protocol_version=PROTOCOL_VERSION,
        capability_report=preflight,
    )
    config = {
        "schema_version": 1,
        "control_plane_url": control_plane_url.rstrip("/"),
        "machine_id": machine_id,
        "owner_user_id": owner_user_id,
        "worker": worker,
        "enrollment_state": "pending",
        "machine_credential": None,
        "gateway": {
            "coordinator_ssh_host": coordinator_ssh_host,
            "coordinator_ssh_user": coordinator_ssh_user,
            "coordinator_ssh_port": coordinator_ssh_port,
            "identity_file": str(identity_file.resolve()) if identity_file else None,
            "known_hosts_file": str(known_hosts_file.resolve()) if known_hosts_file else None,
            "central_web_port": central_web_port,
            "local_web_port": local_web_port,
        },
    }
    config_path = state_root / "node.json"
    config_path.write_text(json.dumps(config, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    gateway_path = state_root / "web-gateway.ps1"
    gateway_path.write_text(_gateway_script(config["gateway"]), encoding="utf-8")
    gateway_result = {"gateway_started": False}
    if start_gateway:
        gateway_result = start_node_gateway(root=state_root)
        _wait_local_port(local_web_port)
    response = _post_json(
        control_plane_url.rstrip("/") + "/v1/node/enroll",
        {"enrollment_code": enrollment_code, "machine": machine.model_dump(mode="json")},
    )
    config["enrollment_state"] = "enrolled_paused"
    config["machine_credential"] = response["machine_credential"]["token"]
    config_path.write_text(json.dumps(config, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    result = {
        "machine_id": machine_id,
        "policy_state": response["policy_state"],
        "config_path": str(config_path),
        "gateway_path": str(gateway_path),
        "web_url": f"http://127.0.0.1:{local_web_port}",
        "preflight": preflight,
        **gateway_result,
    }
    if install_launcher:
        # B0 friction fix: the launcher is cosmetic; an existing desktop
        # shortcut must never fail the setup after enrollment consumed the
        # one-time code. Surface the collision in the payload instead.
        try:
            result["launcher"] = install_node_launcher(root=state_root, desktop_dir=desktop_dir)
        except FileExistsError as exc:
            result["launcher"] = {
                "launcher_installed": False,
                "reason": str(exc),
                "hint": "existing desktop shortcut left untouched; remove it or pick another --desktop-dir and rerun",
            }
    return result


def configure_node_gateway(
    *,
    machine_id: str,
    owner_user_id: str,
    coordinator_ssh_host: str,
    coordinator_ssh_user: str,
    coordinator_ssh_port: int = 22,
    identity_file: Path | None = None,
    known_hosts_file: Path | None = None,
    central_web_port: int = 8765,
    local_web_port: int = 18765,
    root: Path | None = None,
    install_launcher: bool = True,
    desktop_dir: Path | None = None,
) -> dict:
    """Configure console-only access for an already registered worker."""
    if not machine_id.strip() or not owner_user_id.strip():
        raise ValueError("machine ID and owner user ID are required")
    if not coordinator_ssh_host.strip() or not coordinator_ssh_user.strip():
        raise ValueError("coordinator SSH host and user are required")
    for name, port in (
        ("coordinator SSH", coordinator_ssh_port),
        ("central Web", central_web_port),
        ("local Web", local_web_port),
    ):
        if not 1 <= port <= 65535:
            raise ValueError(f"{name} port must be between 1 and 65535")
    for name, path in (("identity", identity_file), ("known-hosts", known_hosts_file)):
        if path is not None and not path.is_file():
            raise FileNotFoundError(f"{name} file does not exist: {path}")
    state_root = (root or default_node_root()).resolve()
    state_root.mkdir(parents=True, exist_ok=True)
    gateway = {
        "coordinator_ssh_host": coordinator_ssh_host,
        "coordinator_ssh_user": coordinator_ssh_user,
        "coordinator_ssh_port": coordinator_ssh_port,
        "identity_file": str(identity_file.resolve()) if identity_file else None,
        "known_hosts_file": str(known_hosts_file.resolve()) if known_hosts_file else None,
        "central_web_port": central_web_port,
        "local_web_port": local_web_port,
    }
    config_path = state_root / "node.json"
    existing = json.loads(config_path.read_text(encoding="utf-8")) if config_path.is_file() else None
    if existing and (
        existing.get("machine_id") != machine_id
        or existing.get("owner_user_id") != owner_user_id
    ):
        raise ValueError("existing node configuration belongs to another machine or owner")
    config = {
        **(existing or {}),
        "schema_version": 1,
        "control_plane_url": (existing or {}).get(
            "control_plane_url",
            f"http://127.0.0.1:{local_web_port}",
        ),
        "machine_id": machine_id,
        "owner_user_id": owner_user_id,
        "worker": (existing or {}).get("worker", True),
        "enrollment_state": (existing or {}).get(
            "enrollment_state",
            "existing_worker_console_only",
        ),
        "machine_credential": (existing or {}).get("machine_credential"),
        "gateway": gateway,
    }
    config_path.write_text(json.dumps(config, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    gateway_path = state_root / "web-gateway.ps1"
    gateway_path.write_text(_gateway_script(gateway), encoding="utf-8")
    result = {
        "configured": True,
        "machine_id": machine_id,
        "config_path": str(config_path),
        "gateway_path": str(gateway_path),
        "web_url": f"http://127.0.0.1:{local_web_port}/app/fleet",
    }
    if install_launcher:
        result["launcher"] = install_node_launcher(root=state_root, desktop_dir=desktop_dir)
    return result


def _wait_local_port(port: int, *, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"SSH web gateway did not open 127.0.0.1:{port}")


def _wait_local_console(web_url: str, *, timeout_s: float = 15.0) -> None:
    endpoint = web_url.rstrip("/") + "/v1/help/public"
    deadline = time.monotonic() + timeout_s
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(endpoint, timeout=1.0) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if isinstance(payload, list) and any(item.get("slug") == "overview" for item in payload):
                return
            last_error = "unexpected service identity"
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise RuntimeError(f"RCN console did not become ready at {web_url}: {last_error}")


def _gateway_script(gateway: dict) -> str:
    arguments = [
        "  '-N',",
        f"  '-L', '127.0.0.1:{gateway['local_web_port']}:127.0.0.1:{gateway['central_web_port']}',",
        f"  '-p', '{gateway['coordinator_ssh_port']}',",
    ]
    if gateway.get("identity_file"):
        arguments.extend(["  '-i',", f"  {_ps_literal(gateway['identity_file'])},"])
    if gateway.get("known_hosts_file"):
        arguments.append(f"  '-o', {_ps_literal('UserKnownHostsFile=' + gateway['known_hosts_file'])},")
    arguments.extend([
        "  '-o', 'BatchMode=yes',",
        "  '-o', 'IdentitiesOnly=yes',",
        "  '-o', 'ExitOnForwardFailure=yes',",
        "  '-o', 'StrictHostKeyChecking=yes',",
        "  '-o', 'ServerAliveInterval=30',",
        "  '-o', 'ServerAliveCountMax=3',",
        f"  {_ps_literal(gateway['coordinator_ssh_user'] + '@' + gateway['coordinator_ssh_host'])}",
    ])
    return "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "$ssh = (Get-Command ssh.exe -ErrorAction Stop).Source",
        "$args = @(",
        *arguments,
        ")",
        "& $ssh @args",
        "exit $LASTEXITCODE",
        "",
    ])


def start_node_gateway(*, root: Path | None = None) -> dict:
    state_root = (root or default_node_root()).resolve()
    status = node_status(root=state_root)
    if status["gateway_running"]:
        return {"gateway_started": False, "gateway_pid": status["gateway_pid"]}
    script = state_root / "web-gateway.ps1"
    if not script.is_file():
        raise FileNotFoundError("node gateway is not configured; run node setup first")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    (state_root / "gateway.pid").write_text(str(process.pid), encoding="ascii")
    return {"gateway_started": True, "gateway_pid": process.pid}


def open_node_console(*, root: Path | None = None, open_browser: bool = True) -> dict:
    state_root = (root or default_node_root()).resolve()
    status = node_status(root=state_root)
    if not status["configured"] or not status["web_url"]:
        raise FileNotFoundError("node is not configured; run node setup first")
    started = start_node_gateway(root=state_root)
    try:
        _wait_local_console(status["web_url"])
    except Exception:
        if started["gateway_started"]:
            stop_node(root=state_root)
        raise
    target = status["web_url"].rstrip("/") + "/app/fleet"
    if open_browser and not webbrowser.open(target, new=2):
        raise RuntimeError(f"default browser did not accept the RCN console URL: {target}")
    return {
        **started,
        "console_ready": True,
        "browser_opened": open_browser,
        "web_url": target,
    }


def _gateway_process_matches(pid: int, script: Path) -> bool:
    try:
        process = psutil.Process(pid)
        command = " ".join(process.cmdline()).lower()
    except (psutil.Error, OSError):
        return False
    script_path = str(script).lower()
    return script_path in command


def node_status(*, root: Path | None = None) -> dict:
    state_root = (root or default_node_root()).resolve()
    config_path = state_root / "node.json"
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.is_file() else None
    pid_path = state_root / "gateway.pid"
    pid = int(pid_path.read_text(encoding="ascii")) if pid_path.is_file() else None
    running = bool(pid and _gateway_process_matches(pid, state_root / "web-gateway.ps1"))
    if pid and not running:
        pid_path.unlink(missing_ok=True)
        pid = None
    gateway = config.get("gateway", {}) if config else {}
    launcher_manifest = state_root / NODE_LAUNCHER_MANIFEST
    launcher_installed = False
    launcher_shortcut = None
    if launcher_manifest.is_file():
        try:
            launcher = json.loads(launcher_manifest.read_text(encoding="utf-8"))
            shortcut = Path(launcher["shortcut_path"])
            launcher_shortcut = str(shortcut)
            launcher_installed = (
                shortcut.is_file()
                and _sha256_path(shortcut) == launcher.get("shortcut_sha256")
            )
        except (KeyError, OSError, ValueError, json.JSONDecodeError):
            launcher_installed = False
    return {
        "configured": config is not None,
        "machine_id": config.get("machine_id") if config else None,
        "worker": config.get("worker") if config else False,
        "enrollment_state": config.get("enrollment_state") if config else None,
        "gateway_running": running,
        "gateway_pid": pid if running else None,
        "web_url": f"http://127.0.0.1:{gateway.get('local_web_port', 18765)}" if config else None,
        "launcher_installed": launcher_installed,
        "launcher_shortcut": launcher_shortcut,
        "state_root": str(state_root),
    }


def stop_node(*, root: Path | None = None) -> dict:
    state_root = (root or default_node_root()).resolve()
    pid_path = state_root / "gateway.pid"
    stopped = False
    if pid_path.is_file():
        pid = int(pid_path.read_text(encoding="ascii"))
        if psutil.pid_exists(pid):
            if not _gateway_process_matches(pid, state_root / "web-gateway.ps1"):
                raise RuntimeError("refusing to stop a process that is not the RCN web gateway")
            process = psutil.Process(pid)
            process.terminate()
            try:
                process.wait(timeout=10)
            except psutil.TimeoutExpired:
                process.kill()
            stopped = True
        pid_path.unlink(missing_ok=True)
    return {"gateway_stopped": stopped, "state_root": str(state_root)}


def install_node_startup(*, root: Path | None = None) -> dict:
    state_root = (root or default_node_root()).resolve()
    if not (state_root / "node.json").is_file():
        raise FileNotFoundError("node is not configured; run node setup first")
    launcher = state_root / "startup.ps1"
    python_literal = sys.executable.replace("'", "''")
    root_literal = str(state_root).replace("'", "''")
    launcher.write_text(
        "\n".join([
            "$ErrorActionPreference = 'Stop'",
            f"& '{python_literal}' -m research_compute_network.cli node start --state-root '{root_literal}'",
            "exit $LASTEXITCODE",
            "",
        ]),
        encoding="utf-8",
    )
    command = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{launcher}"'
    completed = subprocess.run(
        ["schtasks.exe", "/Create", "/TN", NODE_STARTUP_TASK, "/SC", "ONLOGON", "/TR", command, "/F"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout).strip())
    return {"task_name": NODE_STARTUP_TASK, "launcher": str(launcher), "duplicate_start_guard": "gateway.pid"}


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _desktop_directory() -> Path:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    desktop = completed.stdout.strip()
    if completed.returncode != 0 or not desktop:
        raise RuntimeError((completed.stderr or "Windows Desktop directory is unavailable").strip())
    return Path(desktop).resolve()


def _launcher_script(state_root: Path) -> str:
    root_literal = _ps_literal(str(state_root))
    return "\n".join([
        "param([switch]$NoBrowser)",
        "$ErrorActionPreference = 'Stop'",
        f"$stateRoot = {root_literal}",
        "$gatewayScript = Join-Path $stateRoot 'web-gateway.ps1'",
        "$pidPath = Join-Path $stateRoot 'gateway.pid'",
        "$startedPid = $null",
        "function Get-ManagedGatewayProcess([int]$ProcessId) {",
        "  $process = Get-CimInstance Win32_Process -Filter \"ProcessId = $ProcessId\" -ErrorAction SilentlyContinue",
        "  if ($null -eq $process -or [string]::IsNullOrWhiteSpace($process.CommandLine)) { return $null }",
        "  if ($process.CommandLine.IndexOf($gatewayScript, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $null }",
        "  return $process",
        "}",
        "try {",
        "  if (-not (Test-Path -LiteralPath $gatewayScript -PathType Leaf)) { throw 'Web gateway is not configured.' }",
        "  $config = Get-Content -LiteralPath (Join-Path $stateRoot 'node.json') -Raw | ConvertFrom-Json",
        "  $localPort = [int]$config.gateway.local_web_port",
        "  if ($localPort -lt 1 -or $localPort -gt 65535) { throw 'The configured local Web port is invalid.' }",
        "  $gatewayProcess = $null",
        "  if (Test-Path -LiteralPath $pidPath -PathType Leaf) {",
        "    $recordedPid = 0",
        "    if ([int]::TryParse((Get-Content -LiteralPath $pidPath -Raw).Trim(), [ref]$recordedPid)) {",
        "      $gatewayProcess = Get-ManagedGatewayProcess $recordedPid",
        "    }",
        "    if ($null -eq $gatewayProcess) { Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue }",
        "  }",
        "  if ($null -eq $gatewayProcess) {",
        "    $arguments = '-NoProfile -ExecutionPolicy Bypass -File \"' + $gatewayScript + '\"'",
        "    $gatewayProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -WindowStyle Hidden -PassThru",
        "    $startedPid = [int]$gatewayProcess.Id",
        "    [IO.File]::WriteAllText($pidPath, [string]$startedPid, [Text.Encoding]::ASCII)",
        "  }",
        "  $endpoint = 'http://127.0.0.1:' + $localPort + '/v1/help/public'",
        "  $deadline = [DateTime]::UtcNow.AddSeconds(15)",
        "  $ready = $false",
        "  $lastError = 'no response'",
        "  while ([DateTime]::UtcNow -lt $deadline) {",
        "    try {",
        "      $help = @(Invoke-RestMethod -Uri $endpoint -Method Get -TimeoutSec 2)",
        "      if (@($help | Where-Object { $_.slug -eq 'overview' }).Count -gt 0) { $ready = $true; break }",
        "      $lastError = 'unexpected service identity'",
        "    } catch { $lastError = $_.Exception.Message }",
        "    Start-Sleep -Milliseconds 250",
        "  }",
        "  if (-not $ready) { throw ('RCN console did not become ready: ' + $lastError) }",
        "  if (-not $NoBrowser) { Start-Process ('http://127.0.0.1:' + $localPort + '/app/fleet') }",
        "} catch {",
        "  if ($null -ne $startedPid) {",
        "    $managed = Get-ManagedGatewayProcess $startedPid",
        "    if ($null -ne $managed) { Stop-Process -Id $startedPid -Force -ErrorAction SilentlyContinue }",
        "    Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue",
        "  }",
        "  Add-Type -AssemblyName PresentationFramework",
        "  [System.Windows.MessageBox]::Show(('Unable to open Research Compute Network.' + [Environment]::NewLine + [Environment]::NewLine + $_.Exception.Message), 'Research Compute Network') | Out-Null",
        "  exit 1",
        "}",
        "",
    ])


def install_node_launcher(*, root: Path | None = None, desktop_dir: Path | None = None) -> dict:
    state_root = (root or default_node_root()).resolve()
    if not (state_root / "node.json").is_file():
        raise FileNotFoundError("node is not configured; run node setup first")
    desktop = (desktop_dir or _desktop_directory()).resolve()
    desktop.mkdir(parents=True, exist_ok=True)
    shortcut = desktop / NODE_SHORTCUT_NAME
    manifest_path = state_root / NODE_LAUNCHER_MANIFEST
    if shortcut.exists():
        if not manifest_path.is_file():
            raise FileExistsError(f"refusing to replace an unmanaged desktop shortcut: {shortcut}")
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        if previous.get("shortcut_path") != str(shortcut) or previous.get("shortcut_sha256") != _sha256_path(shortcut):
            raise FileExistsError(f"refusing to replace a modified desktop shortcut: {shortcut}")

    script = state_root / NODE_LAUNCHER_SCRIPT
    script.write_text(_launcher_script(state_root), encoding="utf-8")
    powershell = shutil.which("powershell.exe") or "powershell.exe"
    shortcut_arguments = f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script}"'
    command = "; ".join([
        "$shell = New-Object -ComObject WScript.Shell",
        f"$shortcut = $shell.CreateShortcut({_ps_literal(str(shortcut))})",
        f"$shortcut.TargetPath = {_ps_literal(powershell)}",
        f"$shortcut.Arguments = {_ps_literal(shortcut_arguments)}",
        f"$shortcut.WorkingDirectory = {_ps_literal(str(state_root))}",
        "$shortcut.Description = 'Open the protected Research Compute Network console'",
        "$shortcut.IconLocation = 'shell32.dll,18'",
        "$shortcut.Save()",
    ])
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0 or not shortcut.is_file():
        script.unlink(missing_ok=True)
        raise RuntimeError((completed.stderr or completed.stdout or "desktop shortcut creation failed").strip())
    manifest = {
        "schema_version": 1,
        "shortcut_path": str(shortcut),
        "shortcut_sha256": _sha256_path(shortcut),
        "script_path": str(script),
        "script_sha256": _sha256_path(script),
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return {
        "launcher_installed": True,
        "shortcut_path": str(shortcut),
        "script_path": str(script),
        "web_url": node_status(root=state_root)["web_url"],
    }


def remove_node_launcher(*, root: Path | None = None) -> dict:
    state_root = (root or default_node_root()).resolve()
    manifest_path = state_root / NODE_LAUNCHER_MANIFEST
    if not manifest_path.is_file():
        return {"launcher_removed": False, "modified_files_preserved": []}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    modified = []
    removed = []
    for path_key, hash_key in (("shortcut_path", "shortcut_sha256"), ("script_path", "script_sha256")):
        path = Path(manifest[path_key])
        if not path.exists():
            continue
        if _sha256_path(path) != manifest.get(hash_key):
            modified.append(str(path))
            continue
        path.unlink()
        removed.append(str(path))
    if not modified:
        manifest_path.unlink(missing_ok=True)
    return {
        "launcher_removed": bool(removed),
        "removed": removed,
        "modified_files_preserved": modified,
    }


def remove_node_startup() -> dict:
    completed = subprocess.run(
        ["schtasks.exe", "/Delete", "/TN", NODE_STARTUP_TASK, "/F"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return {"task_name": NODE_STARTUP_TASK, "removed": completed.returncode == 0}


def uninstall_node(*, root: Path | None = None) -> dict:
    state_root = (root or default_node_root()).resolve()
    stop_node(root=state_root)
    removed = []
    startup = remove_node_startup()
    launcher = remove_node_launcher(root=state_root)
    for name in ("node.json", "web-gateway.ps1", "gateway.pid", "startup.ps1"):
        path = state_root / name
        if path.is_file():
            path.unlink()
            removed.append(str(path))
    return {"removed": removed, "startup": startup, "launcher": launcher, "state_root": str(state_root)}
