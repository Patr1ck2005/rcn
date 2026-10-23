"""Build and verify no-secret, self-contained release artifacts."""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from collections.abc import Iterable

from .control_plane_startup import (
    CONTROL_PLANE_MANAGER,
    build_control_plane_launcher_script,
    build_control_plane_manager,
    build_control_plane_task_xml,
)
from .service import PACKAGE_VERSION, PROTOCOL_VERSION, STABLE_RUNTIME_VERSION


FORBIDDEN_NAMES = {"node.json", "known_hosts", "authorized_keys", "control-plane.db"}
SECRET_PATTERN = re.compile(
    rb"(?:-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._~-]{16,}|machine_credential\"\s*:\s*\"(?!<))"
)


def runtime_rollout_plan(machine_ids: list[str], *, canary_machine_id: str) -> dict:
    """Return the mandatory canary-first rollout stages for one sealed runtime."""
    if not machine_ids or len(machine_ids) != len(set(machine_ids)):
        raise ValueError("runtime rollout machine IDs must be non-empty and unique")
    if canary_machine_id not in machine_ids:
        raise ValueError("canary machine must be included in the rollout")
    remaining = [machine_id for machine_id in machine_ids if machine_id != canary_machine_id]
    return {
        "drain_before_rollout": True,
        "stages": [
            {"name": "canary", "machine_ids": [canary_machine_id], "requires_acceptance": True},
            {"name": "promotion", "machine_ids": remaining, "requires_acceptance": True},
        ],
        "restore_dispatcher_from_desired_state": True,
        "rollback_on_canary_failure": True,
    }


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stage_web_assets(project_root: Path) -> Path:
    web_root = project_root / "web"
    target = project_root / "src" / "research_compute_network" / "web_dist"
    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm is required to build the server Web resources")
    if not (web_root / "node_modules").is_dir():
        subprocess.run([npm, "ci"], cwd=web_root, check=True)
    subprocess.run([npm, "run", "build"], cwd=web_root, check=True)
    if not (target / "index.html").is_file() or not any((target / "assets").iterdir()):
        raise RuntimeError("Web build did not produce a complete dist directory")
    return target


def build_wheel(project_root: Path, wheel_root: Path, *, require_clean_source: bool = False) -> Path:
    """Build a complete isolated source snapshot with a content identity.

    The caller's unrelated setuptools cache is neither reused nor deleted.
    Build identity is placed only in the snapshot, not the live working tree.
    """
    from .release_identity import source_metadata, stamp, package_hashes, verify_wheel_version
    import tomllib
    project_root = Path(project_root).resolve()
    wheel_root = Path(wheel_root).resolve()
    if list(wheel_root.glob("research_compute_network-*.whl")):
        raise FileExistsError("refusing ambiguous existing release wheel destination")
    metadata = source_metadata(project_root)
    if require_clean_source and (metadata.get('source_commit') is None or metadata.get('source_dirty') is not False):
        raise ValueError('official release requires verified clean source identity')
    stage_web_assets(project_root)
    if source_metadata(project_root) != metadata:
        raise RuntimeError('source identity changed during Web build')
    source_package = project_root / "src" / "research_compute_network"
    source_files = package_hashes(source_package)
    project_bytes = (project_root / "pyproject.toml").read_bytes()
    readme_bytes = (project_root / "README.md").read_bytes() if (project_root / "README.md").is_file() else None
    version = tomllib.loads(project_bytes.decode("utf-8"))["project"]["version"]
    wheel_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rcn-wheel-snapshot-") as temporary:
        snapshot = Path(temporary)
        (snapshot / "pyproject.toml").write_bytes(project_bytes)
        if readme_bytes is not None:
            (snapshot / "README.md").write_bytes(readme_bytes)
        package = snapshot / "src" / "research_compute_network"
        shutil.copytree(project_root / "src" / "research_compute_network", package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "build_identity.json"))
        if ((project_root / "pyproject.toml").read_bytes() != project_bytes
                or (readme_bytes is not None and (project_root / "README.md").read_bytes() != readme_bytes)
                or package_hashes(package) != source_files or package_hashes(source_package) != source_files):
            raise RuntimeError("package source changed while taking release snapshot")
        stamp(package, package_version=version, metadata=metadata)
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", str(snapshot), "--no-deps", "--wheel-dir", str(wheel_root)],
            check=True, capture_output=True, text=True,
        )
    wheels = list(wheel_root.glob("research_compute_network-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("release build must produce exactly one Research Compute Network wheel")
    verify_wheel_version(wheels[0], expected_version=version)
    return wheels[0]


def build_node_release(project_root: Path, output: Path) -> Path:
    project_root = project_root.resolve()
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rcn-node-release-") as temporary:
        wheel = build_wheel(project_root, Path(temporary) / "wheel")
        readme = (project_root / "docs" / "member-node-deployment.md").read_bytes()
        quickstart = (project_root / "docs" / "agent-quickstart.md").read_bytes()
        config = json.dumps({
            "control_plane_url": "http://127.0.0.1:18765",
            "machine_id": "<assigned-machine-id>",
            "owner_user_id": "<member-user-id>",
            "machine_credential": "<created-during-enrollment-not-in-release>",
        }, indent=2).encode("utf-8") + b"\n"
        installer = rb'''param(
  [string]$Python = ""
)
$ErrorActionPreference = "Stop"
Write-Warning "This group-preview package is reproducible but not organization code-signed. Verify the separately supplied SHA-256 before continuing."

# 0. Locate the invitation file delivered separately (never inside this ZIP).
$invitation = Get-ChildItem -LiteralPath $PSScriptRoot -Filter "invitation.json" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $invitation) {
  Write-Host ""
  Write-Host "  invitation.json was not found next to install-member.ps1" -ForegroundColor Yellow
  Write-Host "  Your administrator sends it as a SEPARATE file. Put it in this folder and run this installer again."
  Read-Host "Press Enter to close"
  exit 1
}

# 1. Ensure Python 3.11 (guided; nothing is silently downloaded).
function Find-Python311 {
  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) {
    $probe = & py -3.11 -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $probe) { return $probe.Trim() }
  }
  $plain = Get-Command python -ErrorAction SilentlyContinue
  if ($plain) {
    & python -c "import sys; exit(0 if sys.version_info[:2]==(3,11) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { return $plain.Source }
  }
  return $null
}
$interpreter = if ($Python) { $Python } else { Find-Python311 }
if (-not $interpreter) {
  Write-Host ""
  Write-Host "  Python 3.11 is required (one-time setup)." -ForegroundColor Cyan
  Write-Host "  1. Run:   winget install -e --id Python.Python.3.11"
  Write-Host "     (or install from https://www.python.org/downloads/ and tick 'Add python.exe to PATH')"
  Write-Host "  2. Then run this installer again."
  Read-Host "Press Enter to close"
  exit 1
}

# 2. Install the wheel.
$wheels = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter "research_compute_network-*.whl")
if ($wheels.Count -ne 1) { throw "member package must contain exactly one Research Compute Network wheel" }
& $interpreter -m pip install --upgrade $wheels[0].FullName
if ($LASTEXITCODE -ne 0) { throw "wheel installation failed" }

# 3. Hand over to the in-package wizard: enroll + gateway + desktop + login.
& $interpreter -m research_compute_network.cli member-install $invitation.FullName
if ($LASTEXITCODE -ne 0) { throw "member setup failed" }
Write-Host ""
Write-Host "Research Compute Network is ready." -ForegroundColor Green
Write-Host "Your login token is on the WELCOME.txt page that just opened"
Write-Host "(saved in %LOCALAPPDATA%\ResearchComputeNetwork\WELCOME.txt)."
Read-Host "Press Enter to close"
'''
        publisher_notice = (
            "RCN 0.13.3 stabilization\n\n"
            "This ZIP and PowerShell installer are not organization code-signed. "
            "Windows SmartScreen may show a warning. Verify the separately supplied "
            "SHA-256 manifest and publisher identity before running it. The package "
            "contains no token, private key, machine credential, database, template, "
            "or project data.\n"
        ).encode("utf-8")
        payloads = {
            wheel.name: wheel.read_bytes(),
            "README.md": readme,
            "QUICKSTART.md": quickstart,
            "node-config.example.json": config,
            "install-member.ps1": installer,
            "PUBLISHER-NOTICE.txt": publisher_notice,
        }
        manifest = {
            "schema_version": 1,
            "package_version": PACKAGE_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "runtime_version": STABLE_RUNTIME_VERSION,
            "files": {
                name: {"size_bytes": len(payload), "sha256": sha256_bytes(payload)}
                for name, payload in payloads.items()
            },
            "excludes": ["tokens", "private keys", "project data", "COMSOL templates", "remote paths"],
        }
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in payloads.items():
                archive.writestr(name, payload)
            archive.writestr("release-manifest.json", json.dumps(manifest, indent=2) + "\n")
    validate_release_package(output, sensitive_markers=(
        str(project_root),
        str(Path.home()),
        Path.home().name,
    ))
    integrity = output.with_suffix(output.suffix + ".sha256.json")
    integrity.write_text(json.dumps({
        "schema_version": 1,
        "algorithm": "sha256",
        "files": {output.name: {"size_bytes": output.stat().st_size, "sha256": sha256_path(output)}},
    }, indent=2) + "\n", encoding="utf-8")
    verify_release_integrity(output, integrity)
    return output


def _sealed_runtime_payload(path: Path) -> tuple[str, bytes]:
    runtime = path.resolve()
    if not runtime.is_file():
        raise FileNotFoundError(runtime)
    payload = runtime.read_bytes()
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = set(archive.namelist())
            required = {
                "runtime-manifest.json",
                "remote-agent/supervisor.py",
                "remote-agent/comsol_recipe_worker.py",
                "remote-agent/comsol_recipe_contracts.py",
            }
            if not required.issubset(names) or not any(
                name.startswith("workbench-src/research_agent_workbench/")
                for name in names
            ):
                raise ValueError("sealed runtime archive has an incomplete runtime layout")
            manifest = json.loads(archive.read("runtime-manifest.json"))
    except (json.JSONDecodeError, KeyError, zipfile.BadZipFile) as exc:
        raise ValueError("sealed runtime archive is invalid") from exc
    version = str(manifest.get("version") or "")
    if version != STABLE_RUNTIME_VERSION:
        raise ValueError(
            f"sealed runtime {version!r} does not match stable runtime {STABLE_RUNTIME_VERSION}"
        )
    return f"sealed-runtime/runtime-{version}.zip", payload


def build_control_plane_release(
    project_root: Path,
    output: Path,
    sealed_runtime: Path,
) -> Path:
    """Build the authenticated center package without operational state."""
    project_root = project_root.resolve()
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rcn-control-plane-release-") as temporary:
        wheel = build_wheel(project_root, Path(temporary) / "wheel")
        manager_path = build_control_plane_manager(Path(temporary) / CONTROL_PLANE_MANAGER)
        runtime_name, runtime_payload = _sealed_runtime_payload(sealed_runtime)
        launcher_path = Path(r"D:\ResearchComputeNetwork\control-plane\startup\control-plane-launch.ps1")
        pointer_path = Path(r"D:\ResearchComputeNetwork\control-plane\runtime\current.json")
        startup_xml = build_control_plane_task_xml(
            database_url="sqlite:///D:/ResearchComputeNetwork/control-plane/control-plane.db",
            host="127.0.0.1",
            port=8765,
            allow_local_trusted=False,
            manager_executable=Path(r"D:\ResearchComputeNetwork\control-plane\startup") / CONTROL_PLANE_MANAGER,
            runtime_pointer=pointer_path,
        ).encode("utf-16")
        launcher = build_control_plane_launcher_script().encode("utf-8")
        pointer_example = json.dumps({
            "schema_version": 1,
            "deployment_id": "<deployment-id>",
            "package_version": PACKAGE_VERSION,
            "worker_runtime_version": STABLE_RUNTIME_VERSION,
            "runtime_root": r"D:\ResearchComputeNetwork\control-plane\runtime\<deployment-id>",
            "python_executable": r"D:\ResearchComputeNetwork\control-plane\runtime\<deployment-id>\Scripts\python.exe",
            "database_url": "sqlite:///D:/ResearchComputeNetwork/control-plane/control-plane.db",
            "host": "127.0.0.1",
            "port": 8765,
            "require_auth": True,
            "candidate_runtime_versions": [],
        }, indent=2).encode("utf-8") + b"\n"
        rollback = (
            "# Control Plane rollback\n\n"
            "Before installation, back up the live SQLite database online, the current "
            "runtime pointer, and the existing scheduled-task XML. Drain at an atomic "
            "boundary. On failed authentication, migration, Dispatcher lease, gateway, "
            "or Job/Attempt checks, restore the previous runtime pointer and task XML. "
            "Do not replace the production database with this package; it contains no database.\n"
        ).encode("utf-8")
        payloads = {
            wheel.name: wheel.read_bytes(),
            runtime_name: runtime_payload,
            "control-plane-startup.example.xml": startup_xml,
            "control-plane-launch.ps1": launcher,
            CONTROL_PLANE_MANAGER: manager_path.read_bytes(),
            "runtime-pointer.example.json": pointer_example,
            "ROLLBACK.md": rollback,
            "SECURITY.md": (project_root / "docs" / "security.md").read_bytes(),
        }
        manifest = {
            "schema_version": 1,
            "release_kind": "control-plane",
            "release_channel": "group-preview",
            "package_version": PACKAGE_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "runtime_version": STABLE_RUNTIME_VERSION,
            "requires_auth": True,
            "files": {
                name: {"size_bytes": len(payload), "sha256": sha256_bytes(payload)}
                for name, payload in payloads.items()
            },
            "excludes": ["database", "tokens", "private keys", "backups", "runtime pointers"],
        }
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in payloads.items():
                archive.writestr(name, payload)
            archive.writestr("release-manifest.json", json.dumps(manifest, indent=2) + "\n")
    validate_release_package(output, sensitive_markers=(
        str(project_root), str(Path.home()), Path.home().name,
    ))
    integrity = output.with_suffix(output.suffix + ".sha256.json")
    integrity.write_text(json.dumps({
        "schema_version": 1,
        "algorithm": "sha256",
        "files": {output.name: {"size_bytes": output.stat().st_size, "sha256": sha256_path(output)}},
    }, indent=2) + "\n", encoding="utf-8")
    verify_release_integrity(output, integrity)
    return output


def verify_release_integrity(release: Path, manifest_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    record = manifest.get("files", {}).get(release.name)
    if not record:
        raise ValueError("integrity manifest does not describe the release")
    if record.get("size_bytes") != release.stat().st_size or record.get("sha256") != sha256_path(release):
        raise ValueError("release SHA-256 integrity verification failed")


def validate_release_package(path: Path, *, sensitive_markers: Iterable[str] = ()) -> None:
    private_values = {
        marker.encode("utf-8")
        for marker in sensitive_markers
        if marker and len(marker) >= 4
    }

    def scan_archive(archive: zipfile.ZipFile, prefix: str = "") -> None:
        for info in archive.infolist():
            display_name = f"{prefix}{info.filename}"
            if Path(info.filename).name.lower() in FORBIDDEN_NAMES:
                raise ValueError(f"release contains forbidden file: {display_name}")
            payload = archive.read(info)
            if SECRET_PATTERN.search(payload):
                raise ValueError(f"release may contain a credential: {display_name}")
            if any(value.lower() in payload.lower() for value in private_values):
                raise ValueError(f"release contains a local private marker: {display_name}")
            if info.filename.lower().endswith((".whl", ".zip")):
                with zipfile.ZipFile(io.BytesIO(payload)) as nested:
                    scan_archive(nested, prefix=f"{display_name}!/")

    with zipfile.ZipFile(path) as archive:
        scan_archive(archive)
        manifest = json.loads(archive.read("release-manifest.json"))
        declared = manifest.get("files", {})
        actual = {info.filename for info in archive.infolist()} - {"release-manifest.json"}
        if actual != set(declared):
            raise ValueError("release manifest does not exactly describe archive contents")
        for name, record in declared.items():
            payload = archive.read(name)
            if record.get("size_bytes") != len(payload) or record.get("sha256") != sha256_bytes(payload):
                raise ValueError(f"release file integrity mismatch: {name}")
