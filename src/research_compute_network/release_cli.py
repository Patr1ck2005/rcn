"""CLI adapter for the recoverable Control Plane release transaction."""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any

from .deployment import (
    control_plane_release_status,
    prepare_control_plane_release,
    promote_control_plane_release,
    rollback_control_plane_release,
    recover_control_plane_release,
    record_bootstrap_gate_evidence,
    verify_prepared_release,
)


def execute_release_command(
    args: Any,
    *,
    default_state_root: Path,
    default_database: Path,
) -> dict:
    if args.release_command == "status":
        return control_plane_release_status(args.manifest)
    if args.release_command in {"prepare", "hotfix"}:
        token = ""
        if args.release_command == "hotfix":
            token = os.environ.get("RCN_TOKEN", "")
            if not token:
                raise ValueError(
                    "RCN_TOKEN is required; the token is read from the environment and never printed"
                )
        state_root = Path(args.state_root).resolve() if args.state_root else default_state_root
        database = Path(args.database).resolve() if args.database else default_database
        prepared = prepare_control_plane_release(
            state_root=state_root,
            database=database,
            runtime_root=args.runtime_root,
            service_url=args.service_url,
            task_name=args.task_name,
            wheel=args.wheel,
            expected_machine_count=args.expected_machines,
            deployment_id=args.deployment_id,
            release_mode=("hotfix" if args.release_command == "hotfix" else getattr(args, "release_mode", "standard")),
            candidate_runtime_versions=getattr(
                args,
                "candidate_runtime_versions",
                None,
            ),
            allowed_quarantined_machine_ids=getattr(
                args,
                "allowed_quarantined_machine_ids",
                (),
            ),
            allowed_maintenance_machine_ids=getattr(
                args,
                "allowed_maintenance_machine_ids",
                (),
            ),
            service_already_stopped=bool(
                getattr(args, "service_already_stopped", False)
            ),
            machine_health_grace_s=float(
                getattr(args, "machine_health_grace_s", 300.0)
            ),
            bootstrap_gate_evidence=getattr(args, "bootstrap_gate_evidence", None),
        )
        if args.release_command == "prepare":
            return prepared
        return promote_control_plane_release(prepared["manifest_path"], token=token)

    token = os.environ.get("RCN_TOKEN", "")
    if not token:
        raise ValueError(
            "RCN_TOKEN is required; the token is read from the environment and never printed"
        )
    if args.release_command == "bootstrap-evidence":
        return record_bootstrap_gate_evidence(
            state_root=Path(args.state_root).resolve() if args.state_root else default_state_root,
            database=Path(args.database).resolve() if args.database else default_database,
            runtime_root=args.runtime_root, service_url=args.service_url, task_name=args.task_name,
            attestation=json.loads(Path(args.attestation).read_text(encoding="utf-8")), token=token)
    if args.release_command == "promote":
        return promote_control_plane_release(args.manifest, token=token)
    if args.release_command == "recover":
        return recover_control_plane_release(args.manifest, token=token)
    if args.release_command == "verify":
        return verify_prepared_release(args.manifest, token=token)
    if args.release_command == "rollback":
        return rollback_control_plane_release(args.manifest, token=token)
    raise ValueError(f"unknown release command: {args.release_command}")


def configure_bootstrap_release_parser(release_sub) -> None:
    """Call after existing release commands are registered; no new shell verbs."""
    for name in ("prepare", "hotfix"):
        release_sub.choices[name].add_argument("--bootstrap-gate-evidence", default=None,
            help="Exact pre-prepare administrator quiet-window evidence for a legacy guarded API")
    parser = release_sub.add_parser("bootstrap-evidence", help="Record an explicitly coordinated legacy quiet window; do not stop anything")
    parser.add_argument("--state-root", default=None)
    parser.add_argument("--database", default=None)
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("--service-url", default="http://127.0.0.1:8765")
    parser.add_argument("--task-name", default="ResearchComputeNetwork-ControlPlane")
    parser.add_argument("--attestation", required=True, help="JSON with reason and three explicit quiet-window authorizations")
