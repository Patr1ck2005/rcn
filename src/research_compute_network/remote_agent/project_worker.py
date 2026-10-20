"""Run one project-owned entry point inside a unit sandbox.

The supervisor supplies a structured job JSON.  This runner never invokes a
shell: the entry point is a validated relative path and arguments are passed as
a JSON file.  Project code is therefore flexible while the transport remains
sealed and auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath


PROFILE = "project-worker-v1"
ALLOWED_JOB_KEYS = {
    "schema_version", "profile_id", "entrypoint", "arguments", "out_manifest",
    "timeout_seconds",
}


def _load(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("project worker job must be an object")
    unknown = set(payload) - ALLOWED_JOB_KEYS
    if unknown:
        raise ValueError("unsupported project worker fields: %s" % ", ".join(sorted(unknown)))
    if payload.get("schema_version") != 1 or payload.get("profile_id") != PROFILE:
        raise ValueError("invalid project worker profile")
    return payload


def _relative(value: str, label: str) -> Path:
    normalized = PurePosixPath(str(value))
    if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
        raise ValueError("%s must be a non-empty relative path" % label)
    return Path(*normalized.parts)


def _manifest(output: Path) -> Path:
    files = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "project-worker-manifest.json":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files.append({
            "relative_path": path.relative_to(output).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": digest,
        })
    target = output / "project-worker-manifest.json"
    target.write_text(json.dumps({"schema_version": 1, "profile_id": PROFILE, "files": files}, indent=2), encoding="utf-8")
    return target


def run_job(job_path: Path) -> Path:
    job = _load(job_path)
    run_dir = job_path.parent.parent
    input_root = (run_dir / "input" / "project").resolve()
    output_root = (run_dir / "output").resolve()
    input_root.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)
    entrypoint = (input_root / _relative(job.get("entrypoint", ""), "entrypoint")).resolve()
    entrypoint.relative_to(input_root)
    if not entrypoint.is_file():
        raise FileNotFoundError(entrypoint)
    arguments_path = run_dir / "input" / "arguments.json"
    arguments = job.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ValueError("project worker arguments must be an object")
    arguments_path.write_text(json.dumps(arguments, ensure_ascii=False, indent=2), encoding="utf-8")
    output_rel = _relative(job.get("out_manifest", "output/project-worker-manifest.json"), "out_manifest")
    output_path = (run_dir / output_rel).resolve()
    output_path.relative_to(run_dir.resolve())
    output_root.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "RCN_PROJECT_WORKER_ARGS": str(arguments_path),
        "RCN_PROJECT_WORKER_OUTPUT": str(output_root),
        "PYTHONIOENCODING": "utf-8",
    })
    timeout = int(job.get("timeout_seconds", 3600))
    if timeout < 1 or timeout > 86400:
        raise ValueError("timeout_seconds is outside the allowed range")
    # The scientific entrypoint is a console process; without CREATE_NO_WINDOW
    # every dispatched attempt pops a visible console on the machine desktop.
    windowless = (
        {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
        if os.name == "nt"
        else {}
    )
    completed = subprocess.run(
        [sys.executable, str(entrypoint), "--args-json", str(arguments_path), "--output-dir", str(output_root)],
        cwd=str(input_root),
        env=env,
        check=False,
        timeout=timeout,
        **windowless,
    )
    if completed.returncode != 0:
        raise RuntimeError("project worker exit code %s" % completed.returncode)
    manifest = _manifest(output_root)
    if output_path != manifest:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
    return output_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    args = parser.parse_args(argv)
    run_job(Path(args.job))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
