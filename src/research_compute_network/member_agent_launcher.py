"""Build and install the small stable Windows entry; no member-side compiler."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from . import member_registration as storage


def build_launcher(runtime: Path) -> Path:
    output = Path(runtime) / "bin" / "RCN-Agent.exe"
    output.parent.mkdir(parents=True, exist_ok=True)
    compiler = Path(os.environ.get("WINDIR", "C:/Windows")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if not compiler.is_file():
        raise RuntimeError("member_launcher_build_compiler_missing")
    result = subprocess.run([str(compiler), "/nologo", "/target:exe", "/optimize+", "/deterministic+",
        "/reference:System.Web.Extensions.dll", "/out:" + str(output), str(Path(__file__).with_suffix(".cs"))],
        capture_output=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        # Inbox compiler versions before Roslyn do not accept /deterministic.
        if b"CS2007" not in result.stdout or b"deterministic" not in result.stdout:
            raise RuntimeError("member_launcher_compile_failed")
        result = subprocess.run([str(compiler), "/nologo", "/target:exe", "/optimize+",
            "/reference:System.Web.Extensions.dll", "/out:" + str(output), str(Path(__file__).with_suffix(".cs"))],
            capture_output=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            raise RuntimeError("member_launcher_compile_failed")
    return output


def install_launcher(root: Path) -> dict:
    from .member_client_installer import verify_snapshot
    release = Path(sys.executable).absolute().parents[2]
    manifest_path = release / "member-software-release.json"
    if not manifest_path.is_file():
        return {}  # Development/legacy entries retain their existing Python route.
    manifest = verify_snapshot(release)
    source = release / "runtime/bin/RCN-Agent.exe"
    expected = manifest["runtime_files"].get("bin/RCN-Agent.exe")
    if not expected or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
        raise RuntimeError("member_launcher_release_mismatch")
    directory = Path(root).absolute() / "bin"
    storage._private_directory(directory)
    target = directory / source.name
    storage._check_private_file(target)
    before = storage._read_bytes(target, maximum=262144) if target.exists() else None
    raw = source.read_bytes()
    retained = False
    marker = Path(root) / "active-version.json"
    if before is not None and marker.exists():
        storage._check_private_file(marker)
        previous = json.loads(storage._read_bytes(marker))
        # Protocol 1 deliberately survives software updates. Keeping its pinned
        # bytes also lets an already running CLI finish while Windows locks it.
        retained = (previous.get("launcher_protocol") == 1 and
                    previous.get("launcher_sha256") == hashlib.sha256(before).hexdigest())
    if retained:
        expected = hashlib.sha256(before).hexdigest()
    elif raw != before:
        storage._publish(target, raw, expected=before, maximum=262144)
    python = release / "runtime/python/python.exe"
    return {"release_root": str(release), "python_path": str(python),
            "python_sha256": manifest["runtime_files"]["python/python.exe"],
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "launcher_sha256": expected, "launcher_protocol": 1}


def command_prefix(broker):
    from .member_agent_config import member_connection_root
    root = member_connection_root(broker)
    launcher = root / "bin/RCN-Agent.exe"
    marker = root / "active-version.json"
    if launcher.is_file() and marker.is_file():
        storage._check_private_file(launcher)
        storage._check_private_file(marker)
        return [str(launcher), "--state-root", str(broker.root)], "active-installed-version"
    python = Path(sys.executable)
    if python.name.casefold() == "pythonw.exe":
        python = python.with_name("python.exe")
    return [str(python), "-B", "-m", "research_compute_network.agent_access", "--state-root", str(broker.root)], "python-module"
