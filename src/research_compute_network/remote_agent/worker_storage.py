"""Attempt-owned scratch, separate from results and human COMSOL recoveries.

Only scratch created by this module is disposable. Retained outputs still use
the existing preview/confirm contract; this is not a general disk cleaner.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path, PureWindowsPath
import shutil
import stat
import time

SCRATCH_MARKER = ".rcn-scratch.json"
SCRATCH_ENV = "RCN_ATTEMPT_SCRATCH"
SCRATCH_DIRS = ("temp", "comsol-temp", "recovery", "configuration", "data")
EXIT_PROOF = ".rcn-scratch-exit.json"
START_GATE = ".rcn-worker-start.json"


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def _plain_path(path, root):
    """Reject junctions/symlinks, including every ancestor inside the root."""
    path, root = Path(path).absolute(), Path(root).absolute()
    path.relative_to(root)
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("scratch path contains a reparse point")
        # Also reject a redirected ancestor of the managed root itself.
    path.resolve().relative_to(root.resolve())
    return path


def _identity(root, root_uuid, run_dir, request, *, retained=False):
    run_dir = _plain_path(run_dir, root)
    relative = run_dir.relative_to(Path(root).absolute()).parts
    if retained and len(relative) == 6 and relative[:2] == ("runs", "retained") and relative[2] in {"success", "failed"}:
        suffix = hashlib.sha256(str(request["request_hash"]).encode()).hexdigest()[:12]
        unit = request["work_unit_id"]
        conflict = unit + "-conflict-" + suffix
        leaf = relative[-1]
        if leaf != unit and leaf != conflict and not (
            leaf.startswith(conflict + "-") and leaf[len(conflict) + 1:].isdigit()
        ):
            raise ValueError("scratch retained layout identity mismatch")
        layout = (*relative[3:5], unit)
    elif len(relative) == 5 and relative[:2] == ("runs", "active"):
        layout = relative[2:]
    else:
        raise ValueError("scratch requires an active project/job/unit directory")
    if tuple(layout) != tuple(request[key] for key in ("project_id", "job_id", "work_unit_id")):
        raise ValueError("scratch run layout identity mismatch")
    if _load(_plain_path(Path(root) / ".rcn-root.json", root)).get("root_uuid") != root_uuid:
        raise ValueError("scratch root UUID mismatch")
    identity = {"schema_version": 1, "root_uuid": root_uuid,
                "external_run_id": request["external_run_id"], "request_hash": request["request_hash"]}
    run_marker = _load(_plain_path(run_dir / ".rcn-run.json", root))
    if any(run_marker.get(key) != identity[key] for key in ("root_uuid", "external_run_id", "request_hash")):
        raise ValueError("scratch run marker identity mismatch")
    return identity


def scratch_reserve_gib(root, config):
    return config.get("c_drive_reserve_gib", 10) if PureWindowsPath(root).drive.upper() == "C:" else config.get("disk_reserve_gib", 10)


def prepare_scratch(root, root_uuid, run_dir, request, *, reserve_gib=10):
    """Fail before COMSOL starts if scratch is unowned or headroom is gone."""
    identity = _identity(root, root_uuid, run_dir, request)
    run_dir = Path(run_dir)
    scratch = _plain_path(run_dir / "scratch", root)
    marker = _plain_path(run_dir / SCRATCH_MARKER, root)
    resources = (request.get("resolved_resources") or {}).get("resources") or {}
    disk_mb = int(resources.get("disk_mb", 0))
    required = disk_mb * 1024**2 + int(reserve_gib) * 1024**3
    if disk_mb < 0 or int(reserve_gib) < 0:
        raise ValueError("invalid scratch disk reservation")
    if shutil.disk_usage(run_dir).free < required:
        raise OSError("insufficient disk space on managed scratch volume before worker launch")
    # Never adopt an input-supplied directory or a previous attempt's scratch.
    if scratch.exists() or marker.exists():
        raise ValueError("scratch already exists; explicit reconciliation required")
    # Persist ownership before making disposable files; a failed mkdir can
    # then be cleaned using positive never-launched / stopped-tree evidence.
    with marker.open("x", encoding="utf-8") as handle:
        json.dump(identity, handle, sort_keys=True)
    scratch.mkdir()
    for name in SCRATCH_DIRS:
        (scratch / name).mkdir()
    return scratch


def scratch_environment(scratch):
    scratch = Path(scratch).resolve()
    return {"TEMP": str(scratch / "temp"), "TMP": str(scratch / "temp"),
            "TMPDIR": str(scratch / "temp"),
            "COMSOL_TMPDIR": str(scratch / "comsol-temp"), SCRATCH_ENV: str(scratch)}


def validated_worker_scratch(job_path):
    """Worker cannot redirect storage to an arbitrary environment path."""
    run_dir = Path(job_path).absolute().parent.parent
    scratch = _plain_path(run_dir / "scratch", run_dir)
    if os.environ.get(SCRATCH_ENV) != str(scratch.resolve()):
        raise ValueError("COMSOL worker is missing supervisor-owned scratch")
    marker = _load(_plain_path(run_dir / SCRATCH_MARKER, run_dir))
    request = _load(_plain_path(run_dir / "request.json", run_dir))
    if marker != _identity(run_dir.parents[4], marker.get("root_uuid"), run_dir, request):
        raise ValueError("COMSOL scratch identity mismatch")
    run_marker = _load(_plain_path(run_dir / ".rcn-run.json", run_dir))
    for key in ("external_run_id", "request_hash"):
        if not marker.get(key) or marker[key] != request.get(key) or marker[key] != run_marker.get(key):
            raise ValueError("COMSOL scratch attempt identity mismatch")
    if not marker.get("root_uuid") or marker["root_uuid"] != run_marker.get("root_uuid"):
        raise ValueError("COMSOL scratch root identity mismatch")
    for name in SCRATCH_DIRS:
        if not _plain_path(scratch / name, run_dir).is_dir():
            raise ValueError("COMSOL scratch layout is incomplete")
    return scratch


def allow_worker_start(root, root_uuid, run_dir, request):
    """Publish only after the supervisor attached its exact Windows Job."""
    identity = _identity(root, root_uuid, run_dir, request)
    with _plain_path(Path(run_dir) / START_GATE, root).open("x", encoding="utf-8") as handle:
        json.dump(identity, handle, sort_keys=True)


def await_worker_start(job_path, timeout_s=15):
    run_dir = Path(job_path).absolute().parent.parent
    deadline = time.monotonic() + timeout_s
    identity = _load(_plain_path(run_dir / SCRATCH_MARKER, run_dir))
    while time.monotonic() < deadline:
        try:
            if _load(_plain_path(run_dir / START_GATE, run_dir)) != identity:
                raise ValueError("COMSOL process-tree gate identity mismatch")
            return
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.05)
    raise RuntimeError("supervisor did not authorize COMSOL process-tree startup")


def record_tree_exit(root, root_uuid, run_dir, request):
    identity = _identity(root, root_uuid, run_dir, request, retained=True)
    if _load(_plain_path(Path(run_dir) / SCRATCH_MARKER, root)) != identity:
        raise ValueError("scratch exit proof identity mismatch")
    proof = _plain_path(Path(run_dir) / EXIT_PROOF, root)
    if proof.exists():
        if _load(proof) != identity:
            raise ValueError("scratch exit proof changed")
        return
    with proof.open("x", encoding="utf-8") as handle:
        json.dump(identity, handle, sort_keys=True)


def has_tree_exit_proof(root, root_uuid, run_dir, request):
    identity = _identity(root, root_uuid, run_dir, request, retained=True)
    proof = _plain_path(Path(run_dir) / EXIT_PROOF, root)
    return proof.is_file() and _load(proof) == identity


def cleanup_scratch(root, root_uuid, run_dir, request, *, tree_stopped):
    """Called only after the exact process tree ended, never on historical data."""
    marker = Path(run_dir) / SCRATCH_MARKER
    if not marker.exists():
        return {"state": "not_managed", "deleted_bytes": 0}
    identity = _identity(root, root_uuid, run_dir, request, retained=True)
    if _load(_plain_path(marker, root)) != identity:
        raise ValueError("scratch cleanup identity mismatch")
    if not tree_stopped:
        return {"state": "pending_process_exit", "deleted_bytes": 0}
    scratch = _plain_path(Path(run_dir) / "scratch", root)
    if not scratch.exists():
        return {"state": "already_clean", "deleted_bytes": 0}
    size = 0
    # Preflight the complete subtree before any delete. Do not follow junctions
    # into outputs, template caches, another attempt, or user-owned directories.
    for directory, dirs, files in os.walk(scratch, followlinks=False):
        for name in [*dirs, *files]:
            child = _plain_path(Path(directory) / name, root)
            if name in files:
                size += child.stat().st_size
    shutil.rmtree(scratch)
    return {"state": "cleaned", "deleted_bytes": size}
