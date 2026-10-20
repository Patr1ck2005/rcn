"""Launch the original requested sealed COMSOL bootstrap under isolated Python.

This changes only process-local import routing. The original request, job,
scientific source and bootstrap bytes are preserved. No environment or runtime
installation is edited, and the read-only probe never starts a worker.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

ROUTE_MODE = "explicit-sealed-path-v1"
LAUNCHER_NAME = "requested_runtime_imports.py"


def _read(path: Path) -> bytes:
    for parent in (path, *path.parents):
        status = parent.lstat()
        if stat.S_ISLNK(status.st_mode) or getattr(status, "st_file_attributes", 0) & 1024:
            raise ValueError("linked requested runtime")
    status = path.stat()
    if not stat.S_ISREG(status.st_mode) or status.st_size > 262144:
        raise ValueError("requested runtime file exceeds the sealed source bound")
    raw = path.read_bytes()
    fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                                 value.st_ctime_ns, value.st_mode)
    if len(raw) != status.st_size or fingerprint(path.stat()) != fingerprint(status):
        raise ValueError("requested runtime file changed during read")
    return raw


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _base(value: str | Path) -> Path:
    base = Path(value)
    if (not base.is_absolute() or ".." in base.parts or not re.fullmatch(r"[0-9a-f]{24}", base.name)
            or base.parent.name != "versions" or base.parent.parent.name != "agent"):
        raise ValueError("an exact requested version root is required")
    return base


def _foreign_source(value: str, base: Path) -> bool:
    path = Path(value)
    return bool(path.name in {"workbench-src", "remote-agent"}
                and path.parent.parent.name == "versions" and path.parent != base)


def activate_requested_runtime(runtime_root: str | Path) -> tuple[dict, bytes]:
    """Verify the sealed entry, then select its actual package in this process."""
    base = _base(runtime_root)
    manifest = json.loads(_read(base / "runtime-manifest.json"))
    if manifest.get("version") != base.name or not isinstance(manifest.get("files"), dict):
        raise ValueError("requested runtime manifest identity differs")
    init_path = base / "workbench-src/research_agent_workbench/__init__.py"
    bootstrap = base / "remote-agent/comsol_worker_bootstrap.py"
    init_raw, bootstrap_raw = _read(init_path), _read(bootstrap)
    for name, raw in (("workbench/__init__.py", init_raw),
                      ("remote-agent/comsol_worker_bootstrap.py", bootstrap_raw)):
        if _sha(raw) != manifest["files"].get(name):
            raise ValueError("requested sealed entry bytes differ: " + name)
    # A fresh interpreter must not inherit a scientific package already loaded
    # from the primary version by a site hook or another launcher.
    for name, module in tuple(sys.modules.items()):
        if name == "research_agent_workbench" or name.startswith("research_agent_workbench."):
            origin = getattr(module, "__file__", None)
            if not origin or not Path(origin).is_relative_to(init_path.parent):
                raise ValueError("another scientific runtime was already imported")
    paths = [str(path) for path in (base / "site-packages", base / "workbench-src", base / "remote-agent")
             if path.is_dir()]
    sys.path[:] = paths + [path for path in sys.path if path not in paths and not _foreign_source(path, base)]
    importlib.invalidate_caches()
    package = importlib.import_module("research_agent_workbench")
    if Path(package.__file__) != init_path or _sha(_read(init_path)) != _sha(init_raw):
        raise ValueError("configured Python imported a different sealed Workbench")
    launcher = Path(__file__).absolute()
    return {"route_mode": ROUTE_MODE, "isolated": sys.flags.isolated,
            "ignore_environment": sys.flags.ignore_environment,
            "workbench_module_path": str(init_path), "workbench_module_sha256": _sha(init_raw),
            "bootstrap_path": str(bootstrap), "bootstrap_sha256": _sha(bootstrap_raw),
            "launcher_path": str(launcher), "launcher_sha256": _sha(_read(launcher))}, bootstrap_raw


def probe_requested_runtime(runtime_root: str | Path) -> dict:
    return activate_requested_runtime(runtime_root)[0]


def _hide_windows_children() -> None:
    """Apply before worker imports alias Popen; preserve existing launch flags."""
    if sys.platform != "win32" or getattr(subprocess.Popen, "_rcn_requested_runtime_hidden", False):
        return
    original = subprocess.Popen

    class HiddenPopen(original):
        _rcn_requested_runtime_hidden = True

        def __init__(self, *arguments, **options):
            options["creationflags"] = options.get("creationflags", 0) | subprocess.CREATE_NO_WINDOW
            super().__init__(*arguments, **options)

    subprocess.Popen = HiddenPopen


def execute_requested_runtime(runtime_root: str | Path, job_path: str | Path) -> None:
    base, job = _base(runtime_root), Path(job_path)
    request = json.loads((job.parent.parent / "request.json").read_bytes())
    envelope = json.loads(job.read_bytes())
    if request.get("runtime_version") != base.name or envelope.get("runtime_version", base.name) != base.name:
        raise ValueError("original job/request runtime differs from the selected sealed root")
    _hide_windows_children()
    proof, bootstrap_raw = activate_requested_runtime(base)
    # Execute the same bytes that passed verification, rather than opening the
    # path again between its SHA proof and the original bootstrap execution.
    sys.argv = [proof["bootstrap_path"], "--job", str(job_path)]
    scope = {"__name__": "__main__", "__file__": proof["bootstrap_path"],
             "__package__": None, "__builtins__": __builtins__}
    exec(compile(bootstrap_raw, proof["bootstrap_path"], "exec"), scope)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", required=True)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--job")
    actions.add_argument("--probe", action="store_true")
    args = parser.parse_args(argv)
    if args.probe:
        print(json.dumps(probe_requested_runtime(args.runtime_root), separators=(",", ":")))
    else:
        execute_requested_runtime(args.runtime_root, args.job)


if __name__ == "__main__":
    main()
