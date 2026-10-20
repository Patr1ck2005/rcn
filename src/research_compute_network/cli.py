"""Vendor-neutral CLI for humans, scripts, and local research agents."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

import uvicorn
import yaml

from .api import create_app
from .control_plane_startup import install_control_plane_startup, remove_control_plane_startup
from .dispatcher import Dispatcher
from .integrations import resolve_workbench_workspace_root
from .models import (
    ApprovalRecord,
    ArtifactManifest,
    Assignment,
    JobEnvelope,
    MachinePolicy,
    MachineState,
    MachineExecutionConfig,
    ProjectGrant,
    RemoteRunRecord,
    ResourceRequest,
    SolverVariant,
    UserAccount,
    UserRole,
    MachineMode,
    WorkUnit,
)
from .numerical_probe import NumericalProbeRunner
from .onboarding import MachineOnboardingManager
from . import operator_tools
from .node import (
    configure_node_gateway,
    install_node_launcher,
    install_node_startup,
    node_status,
    open_node_console,
    remove_node_launcher,
    remove_node_startup,
    setup_node,
    start_node_gateway,
    stop_node,
    uninstall_node,
)
from .origin import OriginSpool, build_project_worker_job
from .owner_control import run_tray, set_owner_mode
from .repository import MetadataRepository
from .retry_migration_audit import RetryMigrationAuditor
from .release import build_control_plane_release, build_node_release
from .release_cli import execute_release_command
from .storage import database_path, prepare_storage_migration, promote_storage_migration, promote_storage_migration_coordinated, rollback_storage_migration, storage_doctor
from .release_retention import pin_release, preview_release_retention, stage_release_candidates
from .schedulers.legacy_ssh import LegacySshBaseline
from .service import (
    NetworkService,
    PACKAGE_VERSION,
    PROTOCOL_VERSION,
    STABLE_RUNTIME_VERSION,
)
from .runtime_policy import DEFAULT_RUNTIME_POLICY, RuntimePolicy
from .ssh_acceptance import SshAcceptanceHarness
from .telemetry import MachineAgent, WindowsMetricsSampler
from .tunnel import build_boot_task_xml, build_reconnect_script
from .schedulers.ssh import OpenSshTransport, SshSchedulerAdapter
from .ssh_bundle import build_safe_fake_unit_bundle
from .profiles import SAFE_FAKE_TASK_V1
from .paths import (
    ControlPlanePaths,
    LEGACY_DATABASE_URL_ENV,
    RCN_DATABASE_URL_ENV,
    database_url as resolve_database_url,
    default_rcn_home,
)
from .migration import (
    create_clean_formal_database,
    cutover_sqlite_database,
    migrate_sqlite_database,
    sqlite_table_counts,
)


SOURCE_ROOT = Path(__file__).resolve().parents[2]
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
HTTP_KEEP_ALIVE_SECONDS = 30


class _ReconciliationSshAdapter(SshSchedulerAdapter):
    """Restrict recovery I/O to the persisted Attempts present at CLI startup."""

    def __init__(self, config, transport, bundle_builder, known_external_ids: set[str]) -> None:
        super().__init__(config, transport, bundle_builder)
        self._known_external_ids = frozenset(known_external_ids)

    @staticmethod
    def _refuse_execution() -> NoReturn:
        raise RuntimeError("--reconcile-only forbids submission, preparation and activation")

    def submit(self, job: JobEnvelope, assignment: Assignment) -> str:
        self._refuse_execution()

    def prepare(self, job: JobEnvelope, assignment: Assignment, external_job_id: str) -> str:
        self._refuse_execution()

    def activate(self, external_job_id: str) -> None:
        self._refuse_execution()

    def _require_known_attempt(self, external_job_id: str) -> None:
        if external_job_id not in self._known_external_ids:
            raise RuntimeError("--reconcile-only requires a known Attempt on this machine")

    def cancel(self, external_job_id: str) -> None:
        self._require_known_attempt(external_job_id)
        super().cancel(external_job_id)

    def poll(self, external_job_id: str) -> RemoteRunRecord:
        self._require_known_attempt(external_job_id)
        return super().poll(external_job_id)

    def collect_artifacts(self, external_job_id: str, destination: str) -> list[str]:
        self._require_known_attempt(external_job_id)
        return super().collect_artifacts(external_job_id, destination)


class _ReconciliationDispatcher(Dispatcher):
    """Keep a zero-budget recovery cycle from reviving unstarted work."""

    def _reconcile_reservations(self) -> None:
        # Reservation recovery can activate a prepared run. Existing Attempts
        # are handled by the ordinary poll/cancel/collection reconciliation.
        return None

    def _activate_ready_reservations(self, machine_id: str | None = None) -> int:
        return 0

    def _maybe_reactivate_standby(self, job, unit, attempt, run) -> bool:
        return False

    def _reconcile_machine_attempts(
        self, work: list[tuple[JobEnvelope, WorkUnit, str, str]],
    ) -> tuple[int, int]:
        observation_work = [item for item in work if item[3] != "submit"]
        reconciled, pending = super()._reconcile_machine_attempts(observation_work)
        # An assigned Attempt without an external ID has no known remote run
        # to observe. Preserve it pending rather than submitting or failing it.
        return reconciled, pending + len(work) - len(observation_work)


def _assignment_runtime_version(
    assignment,
    config,
    runtime_policy: RuntimePolicy | None = None,
) -> str:
    """Select the sealed runtime for this attempt, including the legacy window.

    The Dispatcher package version is not necessarily the worker runtime for an
    already-admitted job.  The assignment's approval-bound runtime must be
    carried into the origin bundle; falling back to the machine config keeps
    legacy callers compatible while retaining the explicit allowlist gate.
    """
    runtime_version = assignment.runtime_version or config.runtime_version or STABLE_RUNTIME_VERSION
    policy = runtime_policy or DEFAULT_RUNTIME_POLICY
    if not policy.accepts_worker_runtime(runtime_version):
        raise RuntimeError(
            f"worker runtime {runtime_version!r} is incompatible with the supported sealed runtimes"
        )
    return runtime_version


def _database_url(value: str | None) -> str:
    return resolve_database_url(value)


def validate_serve_options(
    *,
    host: str,
    require_auth: bool,
    tls_certfile: str | None,
    tls_keyfile: str | None,
    trusted_hosts: list[str],
) -> None:
    """Enforce the security boundary before a control-plane listener starts."""
    is_loopback = host in LOOPBACK_HOSTS
    has_cert = bool(tls_certfile)
    has_key = bool(tls_keyfile)
    invalid_trusted_hosts = [
        value
        for value in trusted_hosts
        if not value.strip()
        or value != value.strip()
        or value == "*"
        or value.startswith("*.")
        or "://" in value
        or "/" in value
    ]
    if invalid_trusted_hosts:
        raise ValueError("--trusted-host values must be explicit DNS names or IP addresses without wildcards or URLs")
    if has_cert != has_key:
        raise ValueError("--tls-certfile and --tls-keyfile must be provided together")
    if has_cert and (not Path(tls_certfile).is_file() or not Path(tls_keyfile).is_file()):
        raise ValueError("TLS certificate and key files must both exist")
    if not is_loopback:
        if not require_auth:
            raise ValueError("non-loopback control-plane listeners require --require-auth")
        if not has_cert:
            raise ValueError("non-loopback control-plane listeners require TLS certificate and key files")
        if not trusted_hosts:
            raise ValueError("non-loopback control-plane listeners require at least one --trusted-host")


def _json_file(path: str | Path) -> dict:
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    if source.suffix.lower() in {".yaml", ".yml"}:
        value = yaml.safe_load(text)
    else:
        value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(f"structured input must be a mapping: {source}")
    return value


def _print(model) -> None:
    payload = model.model_dump(mode="json") if hasattr(model, "model_dump") else model
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _profile_limit(value: str) -> tuple[str, int]:
    profile_id, separator, raw_limit = value.partition("=")
    if not separator or not profile_id.strip():
        raise argparse.ArgumentTypeError("profile limit must use PROFILE=COUNT")
    try:
        limit = int(raw_limit)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("profile limit COUNT must be an integer") from exc
    if limit < 1:
        raise argparse.ArgumentTypeError("profile limit COUNT must be at least 1")
    return profile_id, limit


def _service(
    database_url: str,
    *,
    runtime_policy: RuntimePolicy | None = None,
) -> NetworkService:
    service = NetworkService(MetadataRepository(database_url), runtime_policy=runtime_policy)
    service.initialize()
    return service


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Research Compute Network")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--ssh-acceptance-inputs", choices=["packaged", "workbench"], default="packaged",
                        help="installed fixed inputs by default; explicit workbench mode retains source-development workflows")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Initialize operational metadata schema")
    storage = sub.add_parser("storage", help="Inspect and compact metadata storage")
    storage_sub = storage.add_subparsers(dest="storage_command", required=True)
    doctor = storage_sub.add_parser("doctor", help="Report metadata and release storage sizes")
    doctor.add_argument("--root", default=None)
    migrate = storage_sub.add_parser("migrate", help="Prepare, promote, or rollback payload compaction")
    migrate_sub = migrate.add_subparsers(dest="migrate_command", required=True)
    prepare = migrate_sub.add_parser("prepare")
    prepare.add_argument("--output-dir", required=True)
    promote = migrate_sub.add_parser("promote")
    promote.add_argument("manifest")
    promote.add_argument("--confirm", action="store_true")
    promote.add_argument("--coordinated", action="store_true", help="Drain Dispatcher and use the managed Control Plane restart")
    promote.add_argument("--release-manifest", default=None, help="Prepared Control Plane release manifest for coordinated cutover")
    promote.add_argument("--service-url", default="http://127.0.0.1:8765")
    promote.add_argument("--task-name", default="ResearchComputeNetwork-ControlPlane")
    promote.add_argument("--expected-machines", type=int, default=5)
    rollback = migrate_sub.add_parser("rollback")
    rollback.add_argument("manifest")
    rollback.add_argument("--confirm", action="store_true")
    retention = sub.add_parser("release-retention", help="Preview and stage old release backups")
    retention_sub = retention.add_subparsers(dest="retention_command", required=True)
    p = retention_sub.add_parser("preview")
    p.add_argument("--state-root", default=None)
    p = retention_sub.add_parser("stage")
    p.add_argument("confirmation_hash")
    p.add_argument("--state-root", default=None)
    p = retention_sub.add_parser("pin")
    p.add_argument("deployment_id")
    p.add_argument("--state-root", default=None)
    p.add_argument("--unpin", action="store_true")
    p = sub.add_parser("doctor", help="Report local readiness or machine-observation consistency")
    p.add_argument(
        "doctor_scope",
        nargs="?",
        choices=["system", "machine-observations"],
        default="system",
    )
    p = sub.add_parser("state-migrate", help="Create and verify a new SQLite state database with online backup")
    p.add_argument("source")
    p.add_argument("destination")
    p = sub.add_parser("state-clean-baseline", help="Create a job-free formal database from approved configuration")
    p.add_argument("source")
    p.add_argument("destination")
    p.add_argument("archive")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("state-cutover", help="Atomically install a prepared database with one-step rollback")
    p.add_argument("active")
    p.add_argument("prepared")
    p.add_argument("rollback")

    p = sub.add_parser("serve", help="Run the HTTP(S) control-plane API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--demo", action="store_true", help="Seed and animate six simulated machines")
    p.add_argument(
        "--require-auth",
        action="store_true",
        help="Require a personal bearer token on loopback (use with an SSH web gateway)",
    )
    p.add_argument("--tls-certfile", default=None, help="PEM certificate for HTTPS listeners")
    p.add_argument("--tls-keyfile", default=None, help="PEM private key for HTTPS listeners")
    p.add_argument(
        "--trusted-host",
        action="append",
        default=[],
        help="Allowed Host header for LAN/HTTPS listeners; repeat for aliases",
    )
    p.add_argument(
        "--canary-runtime-version",
        action="append",
        default=[],
        help=(
            "Explicitly allow a sealed runtime fingerprint for bounded canary validation; "
            "never used by the formal startup task"
        ),
    )
    p = sub.add_parser("control-plane-startup-install", help="Install fixed Windows boot and crash recovery")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--python-executable", default=None)
    p.add_argument(
        "--allow-local-trusted",
        action="store_true",
        help="Development-only override that permits token-free loopback access",
    )
    p.add_argument(
        "--canary-runtime-version",
        action="append",
        default=[],
        help="Explicit candidate runtime allowlist for a bounded canary startup",
    )
    sub.add_parser("control-plane-startup-remove", help="Remove fixed Windows boot recovery task")

    p = sub.add_parser("dispatch", help="Run the independent single-active Dispatcher")
    p.add_argument("--owner-id", default=None)
    p.add_argument("--interval-s", type=float, default=5.0)
    p.add_argument("--lease-ttl-s", type=int, default=30)
    p.add_argument("--reconcile-grace-s", type=int, default=90)
    p.add_argument("--origin-root", default=None, help="Origin-owned bundle and incoming staging root")
    p.add_argument("--staging-root", default=None)
    p.add_argument(
        "--max-assignments-per-cycle",
        type=int,
        default=16,
        help="Bound assignments attempted by each dispatcher cycle",
    )
    p.add_argument(
        "--reconcile-only",
        action="store_true",
        help="Permit only reconciliation of existing attempts; never submit new work",
    )
    p.add_argument("--once", action="store_true")
    p.add_argument(
        "--canary-runtime-version",
        action="append",
        default=[],
        help="Explicit candidate runtime policy inherited from the Control Plane",
    )

    break_glass = sub.add_parser("break-glass", help="Manage the local break-glass emergency control")
    break_glass_sub = break_glass.add_subparsers(dest="break_glass_command", required=True)
    p = break_glass_sub.add_parser("set-pin", help="Set the scrypt-hashed emergency PIN without exposing it in argv")
    p.add_argument("--actor", default="admin")

    origin = sub.add_parser("origin", help="Prepare and verify origin-owned sealed bundles")
    origin_sub = origin.add_subparsers(dest="origin_command", required=True)
    from .collection_cli import add_collection_parser
    add_collection_parser(origin_sub)
    p = origin_sub.add_parser("prepare-project-worker")
    p.add_argument("job_json")
    p.add_argument("--project-root", required=True)
    p.add_argument("--origin-root", required=True)
    p.add_argument("--runtime-version", default=STABLE_RUNTIME_VERSION)
    p.add_argument("--unit-id", default=None)
    p = origin_sub.add_parser("verify")
    p.add_argument("job_json")
    p.add_argument("--origin-root", required=True)
    p.add_argument("--unit-id", required=True)
    p = origin_sub.add_parser("status")
    p.add_argument("job_json")
    p.add_argument("--origin-root", required=True)
    p.add_argument("--unit-id", default=None)

    p = sub.add_parser("issue-enrollment", help="Issue a one-time member-node enrollment code")
    p.add_argument("owner_user_id")
    p.add_argument("--ttl-minutes", type=int, default=30)
    p.add_argument("--actor", default="admin")

    node = sub.add_parser("node", help="Manage a member submitter/worker node")
    node_sub = node.add_subparsers(dest="node_command", required=True)
    p = node_sub.add_parser("setup", help="Enroll this computer and configure its local web gateway")
    p.add_argument("--url", required=True)
    p.add_argument("--enrollment-code", required=True)
    p.add_argument("--machine-id", required=True)
    p.add_argument("--owner-user-id", required=True)
    p.add_argument("--worker", action="store_true")
    p.add_argument("--ssh-host", required=True)
    p.add_argument("--ssh-user", required=True)
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--identity-file", default=None)
    p.add_argument("--known-hosts-file", default=None)
    p.add_argument("--central-web-port", type=int, default=8765)
    p.add_argument("--local-web-port", type=int, default=18765)
    p.add_argument("--state-root", default=None)
    p.add_argument("--start-gateway", action="store_true")
    p.add_argument("--install-launcher", action="store_true")
    p.add_argument("--desktop-dir", default=None)
    p = node_sub.add_parser("gateway-configure", help="Configure a console gateway for an existing worker")
    p.add_argument("--machine-id", required=True)
    p.add_argument("--owner-user-id", required=True)
    p.add_argument("--ssh-host", required=True)
    p.add_argument("--ssh-user", required=True)
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--identity-file", default=None)
    p.add_argument("--known-hosts-file", default=None)
    p.add_argument("--central-web-port", type=int, default=8765)
    p.add_argument("--local-web-port", type=int, default=18765)
    p.add_argument("--state-root", default=None)
    p.add_argument("--desktop-dir", default=None)
    p.add_argument("--no-launcher", action="store_true")
    for name in ("status", "start", "stop", "startup-install", "startup-remove", "uninstall"):
        p = node_sub.add_parser(name, help=f"{name.title()} the local member-node gateway")
        p.add_argument("--state-root", default=None)
    p = node_sub.add_parser("open", help="Start or reuse the gateway and open the protected Web console")
    p.add_argument("--state-root", default=None)
    p.add_argument("--no-browser", action="store_true")
    p = node_sub.add_parser("launcher-install", help="Install the managed Windows desktop shortcut")
    p.add_argument("--state-root", default=None)
    p.add_argument("--desktop-dir", default=None)
    p = node_sub.add_parser("launcher-remove", help="Remove only the unchanged managed desktop shortcut")
    p.add_argument("--state-root", default=None)

    p = sub.add_parser("node-release-build", help="Build a versioned no-secret member-node release ZIP")
    p.add_argument("output")
    p = sub.add_parser("control-plane-release-build", help="Build the authenticated center deployment ZIP")
    p.add_argument("output")
    p.add_argument("--sealed-runtime", required=True)

    release = sub.add_parser("release", help="Prepare, promote, verify, or roll back the Control Plane")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    p = release_sub.add_parser("prepare", help="Back up and prepare one recoverable deployment transaction")
    p.add_argument("--runtime-root", required=True)
    p.add_argument("--state-root", default=None)
    p.add_argument("--database", default=None)
    p.add_argument("--service-url", default="http://127.0.0.1:8765")
    p.add_argument("--task-name", default="ResearchComputeNetwork-ControlPlane")
    p.add_argument("--wheel", default=None)
    p.add_argument("--expected-machines", type=int, default=5)
    p.add_argument("--deployment-id", default=None)
    p.add_argument(
        "--candidate-runtime-version",
        dest="candidate_runtime_versions",
        action="append",
        default=None,
        help=(
            "Replace the candidate Worker runtime allowlist in the prepared pointer; "
            "repeat for multiple fingerprints"
        ),
    )
    p.add_argument(
        "--allow-quarantined-machine",
        dest="allowed_quarantined_machine_ids",
        action="append",
        default=[],
        help=(
            "Permit one explicitly named machine-local execution quarantine during verification; "
            "requires unfinished execution evidence"
        ),
    )
    p.add_argument(
        "--allow-maintenance-machine",
        dest="allowed_maintenance_machine_ids",
        action="append",
        default=[],
        help=(
            "Permit one explicitly named, otherwise healthy machine that is in "
            "administrator maintenance mode during verification"
        ),
    )
    p.add_argument(
        "--service-already-stopped",
        action="store_true",
        help=(
            "Use a maintenance-stopped release only after the service is unreachable and its "
            "Dispatcher lease has expired"
        ),
    )
    p.add_argument(
        "--machine-health-grace-s",
        type=float,
        default=300.0,
        help=(
            "Seconds the promotion may wait out self-healing tunnel or telemetry jitter on "
            "still-accepting machines before failing; 0 keeps the strict legacy behavior"
        ),
    )
    p.add_argument(
        "--mode",
        dest="release_mode",
        choices=("standard", "hotfix", "additive"),
        default="standard",
        help="Use hotfix or validated additive schema upgrades while Jobs remain in flight",
    )
    p = release_sub.add_parser(
        "hotfix",
        help="Prepare, promote, and verify a live-job-safe Control Plane-only hotfix",
    )
    p.add_argument("--runtime-root", required=True)
    p.add_argument("--state-root", default=None)
    p.add_argument("--database", default=None)
    p.add_argument("--service-url", default="http://127.0.0.1:8765")
    p.add_argument("--task-name", default="ResearchComputeNetwork-ControlPlane")
    p.add_argument("--wheel", default=None)
    p.add_argument("--expected-machines", type=int, default=5)
    p.add_argument("--deployment-id", default=None)
    p.add_argument(
        "--candidate-runtime-version",
        dest="candidate_runtime_versions",
        action="append",
        default=None,
        help=(
            "Replace the candidate Worker runtime allowlist in the prepared pointer; "
            "repeat for multiple fingerprints"
        ),
    )
    p.add_argument(
        "--allow-maintenance-machine",
        dest="allowed_maintenance_machine_ids",
        action="append",
        default=[],
        help=(
            "Permit one explicitly named, otherwise healthy machine that is in "
            "administrator maintenance mode during verification"
        ),
    )
    p.add_argument(
        "--machine-health-grace-s",
        type=float,
        default=300.0,
        help=(
            "Seconds the promotion may wait out self-healing tunnel or telemetry jitter on "
            "still-accepting machines before failing; 0 keeps the strict legacy behavior"
        ),
    )
    for name in ("promote", "verify", "rollback", "status", "recover"):
        p = release_sub.add_parser(name, help=f"{name.capitalize()} one prepared deployment transaction")
        p.add_argument("manifest")
    from .release_cli import configure_bootstrap_release_parser
    configure_bootstrap_release_parser(release_sub)

    sub.add_parser("demo-cleanup-preview", help="Preview exact demo records in the formal database")
    p = sub.add_parser("demo-cleanup-confirm", help="Delete only the hash-confirmed demo records")
    p.add_argument("confirmation_hash")
    p.add_argument("--actor", default="admin")

    p = sub.add_parser("create-user", help="Create or update an invited user")
    p.add_argument("user_id")
    p.add_argument("--display-name", required=True)
    p.add_argument("--roles", nargs="+", choices=[role.value for role in UserRole], default=[UserRole.MEMBER.value])
    p.add_argument("--actor", default="admin")

    p = sub.add_parser("member-setup", help="Universal installer handoff with confirmed invitation snapshot; never grants compute")
    p.add_argument("invitation")
    p.add_argument("--expected-schema", type=int, choices=[1, 2], required=True)
    p.add_argument("--invitation-sha256", required=True)
    p.add_argument("--accept-registration", action="store_true")
    p.add_argument("--prepare-worker-root", action="store_true", help="Consent to preparing a new protected Worker directory; no compute starts")
    p.add_argument("--worker-root", help="Optional new Windows Worker directory; existing deployments require migration")
    p.add_argument("--worker-runtime", help="Install the original hash-pinned sealed archive into the new Worker root")
    p.add_argument("--start-supervisor", action="store_true", help="Explicitly start the current-user supervisor at zero capacity; never grants compute")
    p.add_argument("--connect-worker", action="store_true", help="Explicit standard-local-member SSH service installation (visible UAC), user tunnel activation and center bootstrap; never grants compute")
    p.add_argument("--prepare-openssh", action="store_true", help="Explicitly supply missing Windows OpenSSH components through Windows Update/WSUS with visible UAC; never reboot or change existing services")
    p.add_argument("--prepare-relay", action="store_true", help="Request the center-approved restricted relay and prepare its guard files; no task is started")
    p.add_argument("--activate-tunnel", action="store_true", help="Explicitly install/activate reviewed transport tasks after protected-root and idle-supervisor gates; never grants compute or elevates silently")
    p.add_argument("--configure-compute", action="store_true", help="Display the member's own resource/schedule consent dialog; never marks machine acceptance passed")
    p.add_argument("--no-launcher", action="store_true")
    p.add_argument("--install-startup", action="store_true")
    p.add_argument("--open-browser", action="store_true")

    p = sub.add_parser("member-compute", help="Read current admission or explicitly configure local compute consent")
    p.add_argument("invitation")
    p.add_argument("--state-root", required=True)
    p.add_argument("--invitation-sha256", required=True)
    p.add_argument("--status", action="store_true")
    p.add_argument("--interactive", action="store_true")
    p.add_argument("--preferences", help="Non-secret resource/schedule JSON; requires exact offer confirmation")
    p.add_argument("--confirm-offer-sha256")
    p.add_argument("--accept-compute", action="store_true")

    p = sub.add_parser("member-relay-sync", help="Refresh dedicated relay key leases under an approved policy; never stops existing sessions")
    p.add_argument("--authorization-root", required=True, help="existing protected relay deployment directory")
    p.add_argument("--watch", action="store_true", help="run the same bounded reconciliation once per minute until interrupted")

    p = sub.add_parser("member-register", help="Register with a v2 invitation using a durable local identity; does not enable compute")
    p.add_argument("invitation", help="private v2 invitation JSON from the administrator")
    p.add_argument("--state-root", help="dedicated private registration directory; never a production control-plane root")

    p = sub.add_parser("tunnel-task-bundle-build", help="Export an opt-in coordinated guard/request task pair without accessing a control plane")
    p.add_argument("--config", required=True, help="reviewed non-secret MachineExecutionConfig JSON")
    p.add_argument("--identity-file", required=True, help="member-local protected SSH identity reference")
    p.add_argument("--known-hosts-file", required=True, help="member-local pinned host-key reference")
    p.add_argument("--output", required=True, help="new output directory; does not install or migrate tasks")

    p = sub.add_parser("submission-package-build", help="Package compiled project-side request and declared data inputs")
    p.add_argument("request_json")
    p.add_argument("--input-root", required=True)
    p.add_argument("--origin-layout", help="JSON mapping project_yaml, scan_spec and template input paths")
    p.add_argument("--output", required=True)
    p = sub.add_parser("member-client-installer-build", help="Build public invitation-free client with complete offline science closure")
    p.add_argument("--wheel", required=True)
    p.add_argument("--wheelhouse", required=True)
    p.add_argument("--embeddable", required=True)
    p.add_argument("--wheel-sha256", required=True)
    p.add_argument("--makensis")
    p.add_argument("--output", required=True)
    p = sub.add_parser("member-installer-build", help="Build one universal member Setup.exe from reviewed offline release inputs")
    p.add_argument("--wheel", required=True, help="reviewed research-compute-network wheel")
    p.add_argument("--wheel-sha256", required=True, help="SHA-256 of the reviewed release wheel")
    p.add_argument("--wheelhouse", required=True, help="offline dependency wheels and get-pip.py")
    p.add_argument("--python-archive", required=True, help="Python 3.11 AMD64 embeddable ZIP")
    p.add_argument("--sealed-runtime", help="Include the original approved sealed Worker archive in the public installer")
    p.add_argument("--member-ssh", action="store_true", help="Include explicit standard-local-user SSH connection flow; requires --sealed-runtime")
    p.add_argument("--output", required=True, help="new universal Setup.exe path; never includes a member invitation")

    p = sub.add_parser("member-install", help="One-shot member setup from an invitation file (member machines only)")
    p.add_argument("invitation", help="path of invitation.json delivered by your administrator")
    p.add_argument("--no-launcher", action="store_true", help="skip the desktop shortcut")
    p.add_argument("--install-startup", action="store_true", help="register the logon autostart task")
    p.add_argument("--open-browser", action="store_true", help="open the console in a browser when done (default off)")
    p = sub.add_parser("invite-member", help="Generate a member invitation file (one-time code + gateway key + personal token)")
    p.add_argument("user_id")
    p.add_argument("--center-host", required=True, help="host members dial for SSH (LAN IP or DNS name)")
    p.add_argument("--center-ssh-user", required=True, help="center SSH account members log into")
    p.add_argument("--machine-id", default=None, help="stable machine ID; default MEMBER-<user>-<suffix>")
    p.add_argument("--worker", action="store_true", help="invite as compute worker (requires machine_owner role)")
    p.add_argument("--central-web-port", type=int, default=8765)
    p.add_argument("--coordinator-ssh-port", type=int, default=22)
    p.add_argument("--local-web-port", type=int, default=18765)
    p.add_argument("--ttl-minutes", type=int, default=60)
    p.add_argument("--actor", default="admin")
    p.add_argument("--output", required=True, help="path of the invitation JSON to write (deliver with the member ZIP)")
    p.add_argument("--installer", default=None, help="also build a per-member Setup.exe at this path (requires NSIS + wheelhouse)")
    p.add_argument("--wheelhouse", default=None, help="offline wheelhouse directory for --installer (default releases/wheelhouse-cp311)")
    p.add_argument("--authorized-keys-file", default=None, help="center authorized_keys for the gateway key (default: administrators file; pass the member's .ssh file for standard-user accounts)")

    p = sub.add_parser("issue-token", help="Issue a bearer token; the secret is printed once")
    p.add_argument("user_id")
    p.add_argument("--actor", default="admin")

    p = sub.add_parser("issue-machine-token", help="Issue a machine-bound telemetry token")
    p.add_argument("machine_id")
    p.add_argument("--actor", default="admin")

    p = sub.add_parser("revoke-machine-token", help="Revoke a machine-bound telemetry token")
    p.add_argument("machine_id")
    p.add_argument("credential_id")
    p.add_argument("--actor", default="admin")

    p = sub.add_parser("agent-run", help="Continuously report local Windows telemetry")
    p.add_argument("--machine-id", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--url", default="http://127.0.0.1:8765")
    p.add_argument("--interval-s", type=float, default=5.0)

    p = sub.add_parser("owner-set-mode", help="Set the local machine-owner sharing mode")
    p.add_argument("machine_id")
    p.add_argument("owner_user_id")
    p.add_argument("mode", choices=[mode.value for mode in MachineMode])

    p = sub.add_parser("owner-tray", help="Run the optional Windows tray controller")
    p.add_argument("machine_id")
    p.add_argument("owner_user_id")

    p = sub.add_parser("ssh-config-put", help="Register non-secret SSH execution configuration")
    p.add_argument("json_file")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-tunnel-script", help="Generate a fixed reverse-SSH reconnect script")
    p.add_argument("machine_id")
    p.add_argument("output")
    p.add_argument("--identity-file")
    p.add_argument("--known-hosts-file")
    p.add_argument("--task-xml", help="also write a UTF-16 Task Scheduler XML")
    p.add_argument("--run-as", choices=["SYSTEM", "user"], default="SYSTEM")
    p = sub.add_parser("ssh-tunnel-install", help="Install and start the generated fixed tunnel task remotely")
    p.add_argument("machine_id")
    p.add_argument("--identity-file")
    p.add_argument("--known-hosts-file")
    p.add_argument("--run-as", choices=["SYSTEM", "user"], default="SYSTEM")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-tunnel-bootstrap", help="Generate and authorize the fixed remote tunnel identity")
    p.add_argument("machine_id")
    p.add_argument("--actor", default="admin")
    sub.add_parser("ssh-onboarding-profiles", help="List state-owned reviewed onboarding profiles")
    p = sub.add_parser("ssh-onboarding-profiles-import", help="Import reviewed onboarding profiles into ignored state")
    p.add_argument("profile_file")
    p = sub.add_parser("ssh-onboarding-host-key-import", help="Import one ToDesk-verified public host key into ignored state")
    p.add_argument("machine_id")
    p.add_argument("key_file")
    p.add_argument("expected_fingerprint")
    p = sub.add_parser("ssh-onboarding-preflight", help="Run the strictly read-only preflight for one planned worker")
    p.add_argument("machine_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-onboarding-approve", help="Approve a passed preflight and register a paused deployment target")
    p.add_argument("machine_id")
    p.add_argument("--actor", default="admin")
    sub.add_parser("ssh-onboarding-report", help="Write the sanitized four-machine preflight matrix")
    p = sub.add_parser("member-acceptance-status", help="Read latest self-service member acceptance evidence and remaining real-machine actions")
    p.add_argument("enrollment_id")

    sub.add_parser("release-identity", help="Read this installed package's content identity without opening state")
    sub.add_parser("release-identity-verify", help="Hash installed package files against its build identity without remote I/O")
    sub.add_parser("distribution-contract", help="Describe private invitation and public installer boundaries without secrets")
    sub.add_parser("ssh-acceptance-capability", help="Check installed full SSH acceptance inputs without opening production state")
    p = sub.add_parser("ssh-acceptance-verify-runtime", help="Verify already installed sealed runtime and stage the fixed template, without rebuilding or restarting")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-create", help="Create a full SSH acceptance run for one registered machine")
    p.add_argument("--concurrency", type=int, choices=[1, 2, 3], default=None)
    p.add_argument("machine_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-preflight", help="Run pinned-SSH and worker COMSOL preflight checks")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-init-root", help="Initialize the marked isolated worker root")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-deploy", help="Deploy versioned supervisor, Workbench runtime and template cache")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-deploy-python", help="Deploy the pinned private CPython 3.11 runtime and wheels")
    p.add_argument("run_id")
    p.add_argument("--wheel-root", default=str(default_rcn_home() / "runtime-wheels"))
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-supervisor-status", help="Read worker supervisor heartbeat")
    p.add_argument("machine_id")
    p = sub.add_parser("ssh-supervisor-startup-status", help="Read the fixed supervisor startup task state")
    p.add_argument("machine_id")
    p = sub.add_parser("ssh-supervisor-restart", help="Restart only the exact configured worker supervisor")
    p.add_argument("machine_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser(
        "ssh-sealed-runtime-deploy",
        help="Deploy a verified sealed runtime to one idle enrolled machine with rollback",
    )
    p.add_argument("machine_id")
    p.add_argument("archive")
    p.add_argument("runtime_version")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-supervisor-runtime-promote", help="Promote the verified running sealed runtime only")
    p.add_argument("machine_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-supervisor-startup-install", help="Install the fixed supervisor logon task without opening scheduling")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-readiness-set", help="Record auditable conditional-production readiness")
    p.add_argument("machine_id")
    p.add_argument("--operational-execution", choices=["pending", "passed", "failed"], required=True)
    p.add_argument("--conditional-production", choices=["disabled", "enabled"], required=True)
    p.add_argument("--startup-after-reboot", choices=["pending", "passed", "failed"], required=True)
    p.add_argument("--numeric-equivalence", choices=["pending", "passed", "warning", "failed"], required=True)
    p.add_argument("--warning", action="append", default=[])
    p.add_argument("--cpu-family", required=True)
    p.add_argument("--runtime-version", required=True)
    p.add_argument("--comsol-version", required=True)
    p.add_argument("--owner-mode", choices=["open", "drain", "paused"], default="open")
    p.add_argument(
        "--profile-limit",
        action="append",
        type=_profile_limit,
        default=None,
        metavar="PROFILE=COUNT",
        help="repeatable per-profile concurrency limit; omitted limits are preserved",
    )
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-retry-migration-audit", help="Run the fixed cross-machine retry/migration audit")
    p.add_argument("source_machine_id")
    p.add_argument("target_machine_id")
    p = sub.add_parser("ssh-gamma-local-probe", help="Run the fixed three-point local-Gamma COMSOL probe serially")
    p.add_argument("machine_id")
    p.add_argument("--timeout-s", type=float, default=1800)
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-submit", help="Submit the fixed three-point scan at concurrency 1, 2 or 3")
    p.add_argument("run_id")
    p.add_argument("concurrency", type=int, choices=[1, 2, 3])
    p.add_argument(
        "--solver",
        choices=["mumps", "cudss"],
        default="mumps",
        help="fixed solver path exercised by this acceptance round",
    )
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-safe-fake", help="Run the fixed no-command SSH task and verify its artifact")
    p.add_argument("run_id")
    p.add_argument("--timeout-s", type=float, default=120)
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-project-worker", help="Run the fixed bounded project-worker smoke task")
    p.add_argument("run_id")
    p.add_argument("--timeout-s", type=float, default=120)
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-collect", help="Wait for and collect one acceptance concurrency round")
    p.add_argument("run_id")
    p.add_argument("concurrency", type=int, choices=[1, 2, 3])
    p.add_argument("external_run_ids", nargs="+")
    p.add_argument("--timeout-s", type=float, default=7200)
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-cancel", help="Cancel one exact SSH work-unit process tree")
    p.add_argument("machine_id")
    p.add_argument("external_run_id")
    p = sub.add_parser("ssh-acceptance-cancel-stage", help="Run one exact process-tree cancellation acceptance stage")
    p.add_argument("run_id")
    p.add_argument("stage", choices=["python_start", "comsol_start", "solve"])
    p.add_argument("--timeout-s", type=float, default=180)
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-transfer-cancel", help="Cancel local artifact activation and verify hash-safe retry")
    p.add_argument("run_id")
    p.add_argument("external_run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-no-residual", help="Verify no pilot-scoped Python or COMSOL process remains")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-tunnel-prepare", help="Stage three sequential units for manual tunnel interruption")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-tunnel-cycle", help="Schedule an exact self-recovering tunnel interruption")
    p.add_argument("run_id")
    p.add_argument("--outage-seconds", type=int, default=30)
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-tunnel-verify", help="Verify completion and no relaunch after tunnel recovery")
    p.add_argument("run_id")
    p.add_argument("external_run_ids", nargs=3)
    p.add_argument("--outage-seconds", type=float, required=True)
    p.add_argument("--timeout-s", type=float, default=600)
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-cleanup-preview", help="List eligible retained directories without deleting them")
    p.add_argument("machine_id")
    p = sub.add_parser("ssh-cleanup-confirm", help="Delete one previewed marker-authorized retained directory")
    p.add_argument("machine_id")
    p.add_argument("relative_path")
    p.add_argument("root_uuid")
    p = sub.add_parser("ssh-acceptance-reboot-arm", help="Arm one real Windows reboot acceptance without rebooting the member")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-reboot-verify", help="Verify a new boot and automatic supervisor recovery for the armed run")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-report", help="Write the sanitized SSH acceptance report")
    p.add_argument("--require-passed", action="store_true", help="Exit nonzero unless all original full-acceptance checks passed")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("ssh-acceptance-enable", help="Enable accepted SSH execution and register ASUS logon startup")
    p.add_argument("run_id")
    p.add_argument("--actor", default="admin")
    p = sub.add_parser("probe-legacy-ssh", help="Characterize the existing dispatcher without running it")
    p.add_argument("dispatcher")

    p = sub.add_parser("register-project", help="Register or update an approved project grant")
    p.add_argument("json_file")
    p.add_argument("--actor", default="admin")

    p = sub.add_parser("register-machine", help="Register machine state and owner policy")
    p.add_argument("machine_json")
    p.add_argument("policy_json")
    p.add_argument("--actor", default="admin")

    p = sub.add_parser("approve", help="Record a machine-owner approval")
    p.add_argument("json_file")
    p.add_argument("--actor", default="machine-owner")

    p = sub.add_parser("build-project-worker-job", help="Build a project-worker envelope with input hashes")
    p.add_argument("--project-root", required=True)
    p.add_argument("--entrypoint", required=True)
    p.add_argument("--project-file", action="append", default=[])
    p.add_argument("--arguments-json", default=None)
    p.add_argument("--origin", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--project-id", required=True)
    p.add_argument("--expected-duration-s", type=int, default=600)
    p.add_argument("--priority", type=int, default=0)
    p.add_argument("--cpus", type=int, default=1)
    p.add_argument("--memory-mb", type=int, default=1024)
    p.add_argument("--disk-mb", type=int, default=1024)

    p = sub.add_parser("submit", help="Submit a previously built JobEnvelope JSON")
    p.add_argument("json_file")
    p.add_argument("--actor", default="local-agent")

    sub.add_parser("jobs", help="List local submission jobs")
    p = sub.add_parser("cancel", help="Cancel a job")
    p.add_argument("job_id")
    p.add_argument("--reason", default="")
    p.add_argument("--actor", default="local-agent")

    p = sub.add_parser("retry", help="Requeue retryable failed work units")
    p.add_argument("job_id")
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser("cancel-unit", help="Cancel exactly one work unit")
    p.add_argument("job_id")
    p.add_argument("work_unit_id")
    p.add_argument("--reason", default="")
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser("retry-unit", help="Requeue exactly one retryable work unit")
    p.add_argument("job_id")
    p.add_argument("work_unit_id")
    p.add_argument("--allow-cancelled", action="store_true", help="Also requeue a cancelled unit")
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser("reassign-unit", help="Redirect one work unit to another machine (step-wise)")
    p.add_argument("job_id")
    p.add_argument("work_unit_id")
    p.add_argument("target_machine_id")
    p.add_argument("--reason", required=True, help="Auditable reason for the reassignment")
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser(
        "migrate-unstarted-approval",
        help="Rebind only unstarted units of a Job to another active solver approval",
    )
    p.add_argument("job_id")
    p.add_argument("approval_id")
    p.add_argument("--actor", default="admin")
    p.add_argument(
        "--solver-variant", action="append", choices=[variant.value for variant in SolverVariant],
        help="Allowed solver; repeat for MUMPS/cuDSS. Omission retains mixed-solver migration.",
    )
    p.add_argument("--reason", default="migrate unstarted units to the approved MUMPS/cuDSS contract")
    p = sub.add_parser("clear-standby", help="Clear a stuck standby reservation and requeue the unit")
    p.add_argument("job_id")
    p.add_argument("work_unit_id")
    p.add_argument("--reason", default="clear stuck standby reservation and requeue")
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser("job-reservations", help="Show where a job's standby reservations sit")
    p.add_argument("job_id")
    p.add_argument("--all", action="store_true", help="Include finished reservations")
    p = sub.add_parser("set-job-placement", help="Point a queued job at one machine")
    p.add_argument("job_id")
    p.add_argument("machine_id")
    p.add_argument("--required", action="store_true", help="Hard-pin the job to the machine (admin)")
    p.add_argument("--reason", default=None)
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser("machine-capacity", help="Hot-resize a machine (CPU ceiling / hard capacity)")
    p.add_argument("machine_id")
    p.add_argument("--max-cpus", type=int, default=None, help="Policy CPU ceiling (applies immediately)")
    p.add_argument("--hard-capacity", type=int, default=None, help="Hard capacity units (two-step ticket)")
    p.add_argument("--target", type=int, default=None, help="Target concurrency (<= hard capacity)")
    p.add_argument("--ticket-id", default=None, help="Ticket id from the preview step")
    p.add_argument("--confirm-hash", default=None, help="Confirmation hash from the preview step")
    p.add_argument("--reason", default="operator capacity adjustment")
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser("set-job-priority", help="Hot-set one Job's dispatch priority (clamped to ceiling)")
    p.add_argument("job_id")
    p.add_argument("priority", type=int)
    p.add_argument("--reason", default=None)
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser("project-grant", help="Hot-update project ceilings (priority / concurrency / quota)")
    p.add_argument("project_id")
    p.add_argument("--priority-ceiling", type=int, default=None)
    p.add_argument("--max-running", type=int, default=None)
    p.add_argument("--max-queued", type=int, default=None)
    p.add_argument("--actor", default="local-agent")
    p = sub.add_parser("auto-retry", help="Queue failed units for their next bounded attempt")
    p.add_argument("--actor", default="scheduler")
    p = sub.add_parser("job-attempts", help="Show immutable attempts for a job")
    p.add_argument("job_id")

    p = sub.add_parser("unit-started", help="Mark an assigned work unit as running")
    p.add_argument("job_id")
    p.add_argument("work_unit_id")
    p.add_argument("--actor", default="machine-owner")

    p = sub.add_parser("unit-completed", help="Complete a work unit and register its artifact manifest")
    p.add_argument("job_id")
    p.add_argument("work_unit_id")
    p.add_argument("manifest_json")
    p.add_argument("--duration-s", type=float, required=True)
    p.add_argument("--actor", default="machine-owner")

    p = sub.add_parser("unit-failed", help="Report a retryable or terminal work-unit failure")
    p.add_argument("job_id")
    p.add_argument("work_unit_id")
    p.add_argument("--error", required=True)
    p.add_argument("--terminal", action="store_true")
    p.add_argument("--actor", default="machine-owner")

    p = sub.add_parser("artifact-manifests", help="List registered artifact manifests for a job")
    p.add_argument("job_id")

    p = sub.add_parser("schedule-once", help="Run one metadata-only matching cycle")
    p.add_argument("--actor", default="scheduler")
    sub.add_parser("machines", help="List registered machines")
    sub.add_parser("events", help="List audit events")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in {"release-identity", "release-identity-verify"}:
        from .release_identity import current_build, verify_installed
        result = verify_installed() if args.command.endswith("-verify") else current_build()
        _print(result)
        return 0 if result.get("verified", result.get("available", False)) else 2
    if args.command == "distribution-contract":
        from .reliability_report import distribution_contract
        _print(distribution_contract())
        return 0
    if args.command == "ssh-acceptance-capability":
        from .ssh_acceptance_inputs import packaged_acceptance_capability
        result = packaged_acceptance_capability()
        _print(result)
        return 0 if result["available"] else 2
    if args.command == "member-compute":
        from .member_admission_client import configure_member_compute, member_admission_status
        from .member_registration import MemberRegistrationError, _read_bytes, _json_document
        try:
            options = dict(state_root=Path(args.state_root), expected_invitation_sha256=args.invitation_sha256)
            if args.status:
                if args.preferences or args.accept_compute or args.interactive or args.confirm_offer_sha256:
                    raise MemberRegistrationError('admission_status_is_read_only')
                result = member_admission_status(Path(args.invitation), **options)
            else:
                preferences = _json_document(_read_bytes(Path(args.preferences))) if args.preferences else None
                result = configure_member_compute(Path(args.invitation), **options, preferences=preferences,
                    confirm_offer_sha256=args.confirm_offer_sha256, accept_compute=args.accept_compute, interactive=args.interactive)
            _print(result)
            return 0
        except (MemberRegistrationError, OSError, ValueError, RuntimeError):
            _print({'grants_execution':False,'reason_code':'member_compute_configuration_unconfirmed','preserve_local_identity':True})
            return 2
    if args.command == "member-relay-sync":
        from .member_relay_cli import synchronize
        return synchronize(args.database_url, Path(args.authorization_root), watch=args.watch)
    if args.command == "member-setup":
        from .member_setup import setup_member
        from .member_registration import MemberRegistrationError
        from .invitation_wizard import WizardError

        try:
            _print(setup_member(Path(args.invitation), expected_schema=args.expected_schema,
                invitation_sha256=args.invitation_sha256, accept_registration=args.accept_registration,
                install_launcher=not args.no_launcher, install_startup=args.install_startup,
                open_browser=args.open_browser, prepare_worker=args.prepare_worker_root,
                worker_root=Path(args.worker_root) if args.worker_root else None, prepare_relay=args.prepare_relay,
                configure_compute=args.configure_compute, activate_tunnel=args.activate_tunnel,
                runtime_archive=Path(args.worker_runtime) if args.worker_runtime else None,
                start_supervisor=args.start_supervisor, connect_worker=args.connect_worker,
                prepare_openssh=args.prepare_openssh))
            return 0
        except MemberRegistrationError as exc:
            _print({"setup_completed": False, "reason_code": str(exc), "preserve_local_identity": True})
            return 2
        except (WizardError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RuntimeError):
            # Legacy errors may contain an HTTP body or credential path. Do not echo them.
            _print({"setup_completed": False, "reason_code": "member_setup_failed",
                    "preserve_local_identity": True})
            return 2
    if args.command == "member-register":
        # Member-only path: do not resolve a control-plane DB or RCN_HOME.
        from .member_registration import MemberRegistrationError, register_member

        try:
            _print(register_member(Path(args.invitation), state_root=Path(args.state_root) if args.state_root else None))
            return 0
        except MemberRegistrationError as exc:
            retryable = str(exc) in {"registration_connection_failed_retry_same_invitation",
                "registration_response_unavailable", "registration_already_running"}
            _print({"registered": False, "reason_code": str(exc),
                    "retry_with_same_invitation": retryable, "preserve_local_identity": True})
            return 2
        except (OSError, subprocess.TimeoutExpired):
            _print({"registered": False, "reason_code": "registration_local_io_failed",
                    "retry_with_same_invitation": False, "preserve_local_identity": True})
            return 2
    if args.command == "tunnel-task-bundle-build":
        from .tunnel import build_coordinated_tunnel_bundle, write_coordinated_tunnel_bundle

        config = MachineExecutionConfig.model_validate(_json_file(args.config))
        bundle = build_coordinated_tunnel_bundle(config, identity_file=args.identity_file,
            known_hosts_file=args.known_hosts_file)
        _print(write_coordinated_tunnel_bundle(bundle, Path(args.output)))
        return 0
    if args.command == "submission-package-build":
        from .submission_packages import build_submission_package
        from .models import PartitionRequest
        document = json.loads(Path(args.request_json).read_text(encoding="utf-8"))
        request = PartitionRequest.model_validate(document.get("request", document))
        layout = json.loads(Path(args.origin_layout).read_text(encoding="utf-8")) if args.origin_layout else None
        result = build_submission_package(Path(args.output), request, Path(args.input_root), origin_layout=layout)
        _print({"package_path": str(Path(args.output).absolute()), "manifest": result.model_dump(mode="json")})
        return 0
    if args.command == "member-client-installer-build":
        from .member_client_installer import build_member_client_installer
        _print(build_member_client_installer(wheel_path=args.wheel, wheelhouse_dir=args.wheelhouse,
            embeddable_zip=args.embeddable, output_exe=args.output, expected_wheel_sha256=args.wheel_sha256,
            makensis=args.makensis))
        return 0
    if args.command in {"release-identity", "release-identity-verify"}:
        from .release_identity import current_build, verify_installed
        result = verify_installed() if args.command.endswith("-verify") else current_build()
        _print(result)
        return 0 if result.get("verified", result.get("available", False)) else 2
    if args.command == "member-installer-build":
        # Pure offline build: do not resolve/open the default production state,
        # create a user, issue an invitation or construct a NetworkService.
        from .universal_installer import build_universal_installer

        _print(build_universal_installer(
            wheel_path=Path(args.wheel), expected_wheel_sha256=args.wheel_sha256,
            wheelhouse_dir=Path(args.wheelhouse), embeddable_zip=Path(args.python_archive),
            output_exe=Path(args.output),
            sealed_runtime=Path(args.sealed_runtime) if args.sealed_runtime else None,
            member_ssh=args.member_ssh,
        ))
        return 0
    if args.command == "origin" and args.origin_command == "collect":
        from .collection_cli import execute_collection_command
        _print(execute_collection_command(args))
        return 0
    database_url = _database_url(args.database_url)
    state = ControlPlanePaths.from_root()

    if args.command == "serve":
        runtime_policy = RuntimePolicy.with_candidates(args.canary_runtime_version)
        if (
            args.demo
            and args.database_url is None
            and not os.environ.get(RCN_DATABASE_URL_ENV)
            and not os.environ.get(LEGACY_DATABASE_URL_ENV)
        ):
            database_url = resolve_database_url(None, demo=True)
        validate_serve_options(
            host=args.host,
            require_auth=args.require_auth,
            tls_certfile=args.tls_certfile,
            tls_keyfile=args.tls_keyfile,
            trusted_hosts=args.trusted_host,
        )
        local_trusted = args.host in LOOPBACK_HOSTS and not args.require_auth
        app = create_app(
            database_url=database_url,
            allow_local_trusted=local_trusted,
            demo=args.demo,
            trusted_hosts=args.trusted_host or None,
            auto_recover_dispatcher=not args.demo,
            runtime_policy=runtime_policy,
        )
        server = uvicorn.Server(uvicorn.Config(
            app,
            host=args.host,
            port=args.port,
            ssl_certfile=args.tls_certfile,
            ssl_keyfile=args.tls_keyfile,
            timeout_keep_alive=HTTP_KEEP_ALIVE_SECONDS,
        ))
        from .release_maintenance import install_cooperative_shutdown
        def request_server_shutdown():
            app.state.cooperative_shutdown_requested.set()
            server.should_exit = True

        close_shutdown = install_cooperative_shutdown(state.root, request_server_shutdown)
        try:
            server.run()
        finally:
            close_shutdown()
        return 0
    if args.command == "break-glass":
        if args.break_glass_command == "set-pin":
            import getpass

            first = getpass.getpass("New break-glass PIN: ")
            second = getpass.getpass("Repeat break-glass PIN: ")
            if first != second:
                raise ValueError("break-glass PIN entries do not match")
            service = _service(database_url)
            config = service.set_break_glass_pin(first, actor_id=args.actor)
            _print({"configured": config.active, "updated_at": config.updated_at.isoformat()})
            return 0
    if args.command == "doctor":
        if args.doctor_scope == "machine-observations":
            service = _service(database_url)
            _print(service.machine_observations.diagnostics())
            return 0
        _print({
            "package_version": PACKAGE_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "runtime_version": STABLE_RUNTIME_VERSION,
            "state_root": str(state.root),
            "database_exists": state.database.is_file(),
            "database_tables": sqlite_table_counts(state.database) if state.database.is_file() else {},
        })
        return 0
    if args.command == "storage":
        database = database_path(database_url)
        if args.storage_command == "doctor":
            _print(storage_doctor(database, root=Path(args.root).resolve() if args.root else None))
            return 0
        if args.migrate_command == "prepare":
            _print(prepare_storage_migration(database, Path(args.output_dir)))
            return 0
        if args.migrate_command == "promote":
            if args.coordinated:
                token = os.environ.get("RCN_TOKEN", "")
                if not token:
                    raise ValueError("RCN_TOKEN is required; it is read from the environment and never printed")
                _print(promote_storage_migration_coordinated(
                    Path(args.manifest), confirm=args.confirm, token=token,
                    service_url=args.service_url, task_name=args.task_name,
                    expected_machine_count=args.expected_machines,
                    release_manifest_path=Path(args.release_manifest) if args.release_manifest else None,
                ))
            else:
                _print(promote_storage_migration(Path(args.manifest), confirm=args.confirm))
            return 0
        if args.migrate_command == "rollback":
            _print(rollback_storage_migration(Path(args.manifest), confirm=args.confirm))
            return 0
        raise AssertionError(f"unhandled storage command: {args.storage_command}")
    if args.command == "release-retention":
        retention_root = Path(args.state_root).resolve() if args.state_root else state.root
        if args.retention_command == "preview":
            _print(preview_release_retention(retention_root))
        elif args.retention_command == "stage":
            _print(stage_release_candidates(retention_root, args.confirmation_hash))
        elif args.retention_command == "pin":
            _print(pin_release(retention_root, args.deployment_id, pinned=not args.unpin))
        return 0
    if args.command == "state-migrate":
        _print(migrate_sqlite_database(args.source, args.destination))
        return 0
    if args.command == "state-clean-baseline":
        _print(create_clean_formal_database(
            args.source,
            args.destination,
            args.archive,
            actor_id=args.actor,
        ))
        return 0
    if args.command == "state-cutover":
        _print(cutover_sqlite_database(args.active, args.prepared, args.rollback))
        return 0
    if args.command == "control-plane-startup-install":
        _print(install_control_plane_startup(
            database_url=database_url,
            state_root=state.root / "startup",
            python_executable=args.python_executable,
            host=args.host,
            port=args.port,
            allow_local_trusted=args.allow_local_trusted,
            canary_runtime_versions=args.canary_runtime_version,
        ))
        return 0
    if args.command == "control-plane-startup-remove":
        _print(remove_control_plane_startup())
        return 0
    if args.command == "node":
        state_root = Path(args.state_root).resolve() if args.state_root else None
        if args.node_command == "setup":
            _print(setup_node(
                control_plane_url=args.url,
                enrollment_code=args.enrollment_code,
                machine_id=args.machine_id,
                owner_user_id=args.owner_user_id,
                worker=args.worker,
                coordinator_ssh_host=args.ssh_host,
                coordinator_ssh_user=args.ssh_user,
                coordinator_ssh_port=args.ssh_port,
                identity_file=Path(args.identity_file).resolve() if args.identity_file else None,
                known_hosts_file=Path(args.known_hosts_file).resolve() if args.known_hosts_file else None,
                central_web_port=args.central_web_port,
                local_web_port=args.local_web_port,
                root=state_root,
                start_gateway=args.start_gateway,
                install_launcher=args.install_launcher,
                desktop_dir=Path(args.desktop_dir).resolve() if args.desktop_dir else None,
            ))
        elif args.node_command == "gateway-configure":
            _print(configure_node_gateway(
                machine_id=args.machine_id,
                owner_user_id=args.owner_user_id,
                coordinator_ssh_host=args.ssh_host,
                coordinator_ssh_user=args.ssh_user,
                coordinator_ssh_port=args.ssh_port,
                identity_file=Path(args.identity_file).resolve() if args.identity_file else None,
                known_hosts_file=Path(args.known_hosts_file).resolve() if args.known_hosts_file else None,
                central_web_port=args.central_web_port,
                local_web_port=args.local_web_port,
                root=state_root,
                install_launcher=not args.no_launcher,
                desktop_dir=Path(args.desktop_dir).resolve() if args.desktop_dir else None,
            ))
        elif args.node_command == "status":
            _print(node_status(root=state_root))
        elif args.node_command == "start":
            _print(start_node_gateway(root=state_root))
        elif args.node_command == "stop":
            _print(stop_node(root=state_root))
        elif args.node_command == "startup-install":
            _print(install_node_startup(root=state_root))
        elif args.node_command == "startup-remove":
            _print(remove_node_startup())
        elif args.node_command == "open":
            _print(open_node_console(root=state_root, open_browser=not args.no_browser))
        elif args.node_command == "launcher-install":
            _print(install_node_launcher(
                root=state_root,
                desktop_dir=Path(args.desktop_dir).resolve() if args.desktop_dir else None,
            ))
        elif args.node_command == "launcher-remove":
            _print(remove_node_launcher(root=state_root))
        elif args.node_command == "uninstall":
            _print(uninstall_node(root=state_root))
        return 0
    if args.command == "member-install":
        # Early block on purpose: the member machine has no center database,
        # and main() unconditionally constructs one below. The wizard only
        # touches the local node root and the center via HTTP/SSH.
        from .invitation_wizard import run_wizard

        _print(run_wizard(
            invitation_path=Path(args.invitation),
            install_launcher=not args.no_launcher,
            install_startup=args.install_startup,
            open_browser=args.open_browser,
        ))
        return 0
    if args.command == "node-release-build":
        _print({"release_path": str(build_node_release(SOURCE_ROOT, Path(args.output)))})
        return 0
    if args.command == "control-plane-release-build":
        _print({"release_path": str(build_control_plane_release(
            SOURCE_ROOT,
            Path(args.output),
            Path(args.sealed_runtime),
        ))})
        return 0
    if args.command == "release":
        _print(execute_release_command(
            args,
            default_state_root=state.root,
            default_database=state.database,
        ))
        return 0
    if args.command == "agent-run":
        MachineAgent(
            machine_id=args.machine_id,
            token=args.token,
            base_url=args.url,
            sampler=WindowsMetricsSampler(),
        ).run_forever(interval_s=args.interval_s)
        return 0
    if args.command == "probe-legacy-ssh":
        _print(LegacySshBaseline(args.dispatcher).probe())
        return 0
    if args.command == "build-project-worker-job":
        arguments = {}
        if args.arguments_json:
            payload = _json_file(args.arguments_json)
            arguments = payload
        job = build_project_worker_job(
            project_root=args.project_root,
            entrypoint=args.entrypoint,
            project_files=args.project_file,
            arguments=arguments,
            origin_submitter_id=args.origin,
            user_id=args.user,
            project_id=args.project_id,
            expected_duration_s=args.expected_duration_s,
            priority=args.priority,
            resources=ResourceRequest(cpus=args.cpus, memory_mb=args.memory_mb, disk_mb=args.disk_mb),
        )
        _print(job)
        return 0

    if args.command == "origin":
        job = JobEnvelope.model_validate(_json_file(args.job_json))
        spool = OriginSpool(args.origin_root)
        if args.origin_command == "prepare-project-worker":
            _print({
                "bundles": [str(path) for path in spool.publish_project_worker(
                    job=job,
                    project_root=args.project_root,
                    runtime_version=args.runtime_version,
                    work_unit_id=args.unit_id,
                )],
            })
        elif args.origin_command == "verify":
            unit = next(item for item in job.work_units if item.work_unit_id == args.unit_id)
            _print(spool.status(job, unit))
            spool.validate(job, unit)
        else:
            units = spool._selected_units(job, args.unit_id)
            _print([spool.status(job, unit) for unit in units])
        return 0

    if args.command == "owner-tray":
        run_tray(database_url, machine_id=args.machine_id, owner_user_id=args.owner_user_id)
        return 0

    runtime_policy = (
        RuntimePolicy.with_candidates(args.canary_runtime_version)
        if args.command == "dispatch"
        else DEFAULT_RUNTIME_POLICY
    )
    service = _service(database_url, runtime_policy=runtime_policy)
    repository = service.repository
    onboarding = MachineOnboardingManager(
        service,
        state_root=state.onboarding,
    )
    if args.command == "dispatch":
        if args.reconcile_only and args.max_assignments_per_cycle != 0:
            raise RuntimeError("--reconcile-only requires --max-assignments-per-cycle 0")
        # A temporary write barrier still permits process startup, metadata
        # readiness and reconciliation. Actual builders require write admission.
        bundle_root = state.validate_storage("dispatcher_bundles")
        if not bundle_root.is_dir():
            state.validate_storage_write("dispatcher_bundles")
            bundle_root.mkdir(parents=True, exist_ok=True)
        origin_root = Path(args.origin_root or args.staging_root or state.origin_spool).resolve()
        from .volume_budget import VolumeBudget
        center_volume_budget = (VolumeBudget(repository.engine.url.database)
            if repository.engine.url.get_backend_name() == "sqlite"
            and repository.engine.url.database not in {None, "", ":memory:"} else None)
        origin_spool = OriginSpool(origin_root, volume_budget=center_volume_budget, storage_validator=(
            lambda: state.validate_storage_write("origin_spool")
        ) if origin_root == state.origin_spool else None)
        import threading
        from .schedulers.ssh import stoppable_runner
        io_stop_event = threading.Event()
        known_external_ids: dict[str, set[str]] = {}
        if args.reconcile_only:
            for job in repository.list_operational_jobs():
                for unit in job.work_units:
                    for attempt in unit.attempts:
                        if attempt.machine_id and attempt.external_run_id:
                            known_external_ids.setdefault(attempt.machine_id, set()).add(
                                attempt.external_run_id
                            )

        def adapter_provider(machine_id: str):
            config = repository.get_machine_execution_config(machine_id)
            if config is None:
                raise RuntimeError(f"SSH execution config not found: {machine_id}")
            # A sealed runtime upgrade must not strand an already-running
            # Attempt or prevent its collection after scientific acceptance
            # disables new execution. Recovery uses a restricted adapter and
            # dispatcher as well as a zero assignment budget.
            recovery_only = args.reconcile_only or not config.enabled or not service.runtime_policy.accepts_worker_runtime(config.runtime_version)
            recovery_ids = known_external_ids.get(machine_id, set())
            if recovery_only and not args.reconcile_only:
                recovery_ids = {
                    a.external_run_id for j in repository.list_operational_jobs(machine_id=machine_id)
                    for u in j.work_units for a in u.attempts
                    if a.machine_id == machine_id and a.external_run_id
                }
            transport = OpenSshTransport(config, state_root=state.ssh,
                                         runner=stoppable_runner(io_stop_event),
                                         budget_database=repository.engine.url.database,
                                         collection_storage_validator=(lambda: state.validate_storage_write("origin_spool"))
                                         if origin_root == state.origin_spool else None)

            def bundle_builder(job, assignment, external_run_id):
                state.validate_storage_write("dispatcher_bundles")
                output_zip = bundle_root / f"{external_run_id}.zip"
                runtime_version = _assignment_runtime_version(
                    assignment,
                    config,
                    service.runtime_policy,
                )
                if job.execution_profile_id == SAFE_FAKE_TASK_V1.profile_id:
                    from types import SimpleNamespace
                    unit = next(u for u in job.work_units if u.work_unit_id == assignment.work_unit_id)
                    # The fixed acceptance task has no input files. Reuse the
                    # same full staging/ZIP admission and unique owned scratch.
                    with origin_spool._bundle_write(job, unit, assignment, SimpleNamespace(files=[]),
                            output_zip, external_run_id, runtime_version,
                            lambda: state.validate_storage_write("dispatcher_bundles")) as owned_zip:
                        built = build_safe_fake_unit_bundle(
                            job=job, assignment=assignment, external_run_id=external_run_id,
                            config=config, runtime_version=runtime_version, output_zip=owned_zip)
                        state.validate_storage_write("dispatcher_bundles")
                        OriginSpool.publish_or_reuse_execution_bundle(built, output_zip)
                    return output_zip
                return origin_spool.materialize_execution_bundle(
                    job=job,
                    assignment=assignment,
                    external_run_id=external_run_id,
                    config=config,
                    runtime_version=runtime_version,
                    output_zip=output_zip,
                    cache_uploader=transport.upload_cache_object,
                    bundle_storage_validator=lambda: state.validate_storage_write("dispatcher_bundles"),
                )

            if recovery_only:
                return _ReconciliationSshAdapter(config, transport, bundle_builder, recovery_ids)
            return SshSchedulerAdapter(config, transport, bundle_builder)

        dispatcher_type = _ReconciliationDispatcher if args.reconcile_only else Dispatcher
        dispatcher = dispatcher_type(
            service,
            adapter_provider,
            owner_id=args.owner_id,
            lease_ttl_s=args.lease_ttl_s,
            reconcile_grace_s=args.reconcile_grace_s,
            origin_spool=origin_spool,
            staging_provider=(
                lambda job, unit, attempt_id: origin_spool.incoming_path(job, unit, attempt_id)
            ),
            max_assignments_per_cycle=args.max_assignments_per_cycle,
            nonblocking_io=not args.once and not args.reconcile_only,
            io_stop_event=io_stop_event,
        )
        if args.once:
            active = dispatcher.run_cycle()
            dispatcher.stop()
            _print({"active": active, "status": dispatcher.status.model_dump(mode="json")})
        else:
            dispatcher.run_forever(interval_s=args.interval_s)
        return 0
    if args.command == "issue-enrollment":
        _print(service.issue_enrollment(
            args.owner_user_id,
            actor_id=args.actor,
            ttl_minutes=args.ttl_minutes,
        ))
        return 0
    if args.command == "demo-cleanup-preview":
        _print(service.preview_demo_cleanup())
        return 0
    if args.command == "demo-cleanup-confirm":
        _print(service.confirm_demo_cleanup(args.confirmation_hash, actor_id=args.actor))
        return 0
    if args.command == "member-acceptance-status":
        from .member_acceptance_status import member_acceptance_status
        _print(member_acceptance_status(repository,args.enrollment_id))
        return 0
    if args.command == "ssh-config-put":
        _print(service.put_machine_execution_config(
            MachineExecutionConfig.model_validate(_json_file(args.json_file)),
            actor_id=args.actor,
        ))
        return 0
    if args.command == "ssh-tunnel-script":
        config = repository.get_machine_execution_config(args.machine_id)
        if config is None:
            raise KeyError(f"SSH machine execution config not found: {args.machine_id}")
        generated = build_reconnect_script(
            config,
            identity_file=args.identity_file,
            known_hosts_file=args.known_hosts_file,
        )
        Path(args.output).write_text(generated.script, encoding="utf-8")
        task_xml = None
        if args.task_xml:
            task_xml = build_boot_task_xml(config, args.output, run_as=args.run_as)
            Path(args.task_xml).write_text(task_xml, encoding="utf-16")
        _print({"machine_id": generated.machine_id, "task_name": generated.task_name, "script": str(Path(args.output)), "task_xml": str(Path(args.task_xml)) if args.task_xml else None, "run_as": args.run_as})
        return 0
    if args.command == "ssh-tunnel-install":
        config = repository.get_machine_execution_config(args.machine_id)
        if config is None:
            raise KeyError(f"SSH machine execution config not found: {args.machine_id}")
        remote_script = str(Path(config.remote_root) / "agent" / "tunnel" / "reverse-ssh.ps1")
        transport = OpenSshTransport(
            config,
            state_root=state.ssh,
        )
        identity_file = args.identity_file or str(transport.tunnel_identity_path)
        known_hosts_file = args.known_hosts_file or str(transport.tunnel_known_hosts_path)
        generated = build_reconnect_script(
            config,
            identity_file=identity_file,
            known_hosts_file=known_hosts_file,
        )
        xml = build_boot_task_xml(config, remote_script, run_as=args.run_as)
        result = transport.install_tunnel_task(generated.script, xml, task_name=generated.task_name)
        service._event("machine.tunnel_task_installed", args.actor, "machine", args.machine_id, **result)
        _print(result)
        return 0
    if args.command == "ssh-tunnel-bootstrap":
        config = repository.get_machine_execution_config(args.machine_id)
        if config is None:
            raise KeyError(f"SSH machine execution config not found: {args.machine_id}")
        transport = OpenSshTransport(config, state_root=state.ssh)
        result = transport.bootstrap_tunnel_identity()
        service._event(
            "machine.tunnel_identity_bootstrapped",
            args.actor,
            "machine",
            args.machine_id,
            fingerprint=result.get("fingerprint"),
        )
        _print(result)
        return 0
    if args.command == "ssh-onboarding-profiles":
        _print(onboarding.profile_statuses())
        return 0
    if args.command == "ssh-onboarding-profiles-import":
        _print(onboarding.import_profiles(args.profile_file))
        return 0
    if args.command == "ssh-onboarding-host-key-import":
        _print(onboarding.import_verified_host_key(
            args.machine_id,
            args.key_file,
            args.expected_fingerprint,
        ))
        return 0
    if args.command == "ssh-onboarding-preflight":
        _print(onboarding.run_preflight(args.machine_id, actor_id=args.actor))
        return 0
    if args.command == "ssh-onboarding-approve":
        _print(onboarding.approve_for_deployment(args.machine_id, actor_id=args.actor))
        return 0
    if args.command == "ssh-onboarding-report":
        _print({"report_path": str(onboarding.write_matrix_report())})
        return 0

    def ssh_harness_for_machine(
        machine_id: str,
        *,
        require_workbench: bool = True,
    ) -> SshAcceptanceHarness:
        config = repository.get_machine_execution_config(machine_id)
        if config is None:
            raise KeyError(f"SSH machine execution config not found: {machine_id}")
        if args.command.startswith("ssh-acceptance-") and args.ssh_acceptance_inputs == "packaged":
            from .ssh_acceptance_inputs import PackagedAcceptanceInputs, AcceptanceReadTransport
            from .schedulers.ssh import OpenSshTransport
            return SshAcceptanceHarness(service, project_root=state.root, workspace_root=state.root,
                machine_config=config, acceptance_inputs=PackagedAcceptanceInputs(state.root),
                transport=AcceptanceReadTransport(OpenSshTransport(config, state_root=state.ssh)))
        return SshAcceptanceHarness(
            service,
            project_root=SOURCE_ROOT,
            workspace_root=(resolve_workbench_workspace_root() if require_workbench else SOURCE_ROOT),
            machine_config=config,
        )

    if args.command == "ssh-acceptance-create":
        _print(ssh_harness_for_machine(
            args.machine_id,
            require_workbench=False,
        ).create_run(actor_id=args.actor, concurrency=args.concurrency))
        return 0
    if args.command in {
        "ssh-acceptance-verify-runtime",
        "ssh-acceptance-preflight",
        "ssh-acceptance-init-root",
        "ssh-acceptance-deploy",
        "ssh-acceptance-deploy-python",
        "ssh-acceptance-submit",
        "ssh-acceptance-safe-fake",
        "ssh-acceptance-project-worker",
        "ssh-acceptance-collect",
        "ssh-acceptance-cancel-stage",
        "ssh-acceptance-transfer-cancel",
        "ssh-acceptance-no-residual",
        "ssh-acceptance-tunnel-prepare",
        "ssh-acceptance-tunnel-cycle",
        "ssh-acceptance-tunnel-verify",
        "ssh-acceptance-reboot-arm",
        "ssh-acceptance-reboot-verify",
        "ssh-acceptance-report",
        "ssh-acceptance-enable",
        "ssh-supervisor-startup-install",
    }:
        run = repository.get_ssh_acceptance_run(args.run_id)
        if run is None:
            raise KeyError(f"SSH acceptance run not found: {args.run_id}")
        harness = ssh_harness_for_machine(
            run.worker_id,
            require_workbench=args.command not in {
                "ssh-acceptance-safe-fake",
                "ssh-acceptance-project-worker",
            },
        )
        if run.remote_root != harness.machine_config.remote_root:
            raise ValueError("acceptance run root changed; do not reuse evidence across roots")
        if args.command == "ssh-acceptance-verify-runtime":
            _print(harness.verify_installed_runtime(run, actor_id=args.actor))
        elif args.command == "ssh-acceptance-preflight":
            _print(harness.preflight(run, actor_id=args.actor))
            return 2 if run.status.value == "failed" else 0
        elif args.command == "ssh-acceptance-init-root":
            _print(harness.initialize_root(run, actor_id=args.actor))
        elif args.command == "ssh-acceptance-deploy":
            _print(harness.deploy(run, actor_id=args.actor))
        elif args.command == "ssh-acceptance-deploy-python":
            _print(harness.deploy_managed_python(
                run,
                wheel_root=Path(args.wheel_root),
                actor_id=args.actor,
            ))
        elif args.command == "ssh-acceptance-submit":
            _print({
                "external_run_ids": harness.submit_concurrency(
                    run,
                    args.concurrency,
                    solver_variant=SolverVariant(args.solver),
                    actor_id=args.actor,
                ),
                "solver_variant": args.solver,
            })
        elif args.command == "ssh-acceptance-safe-fake":
            _print(harness.run_safe_fake_task(run, actor_id=args.actor, timeout_s=args.timeout_s))
        elif args.command == "ssh-acceptance-project-worker":
            _print(harness.run_project_worker_task(run, actor_id=args.actor, timeout_s=args.timeout_s))
        elif args.command == "ssh-acceptance-collect":
            _print({"merged_path": str(harness.wait_and_collect(
                run,
                args.concurrency,
                args.external_run_ids,
                actor_id=args.actor,
                timeout_s=args.timeout_s,
            ))})
        elif args.command == "ssh-acceptance-cancel-stage":
            _print(harness.run_cancel_test(
                run,
                args.stage,
                actor_id=args.actor,
                timeout_s=args.timeout_s,
            ))
        elif args.command == "ssh-acceptance-transfer-cancel":
            _print(harness.run_transfer_cancel_test(
                run,
                args.external_run_id,
                actor_id=args.actor,
            ))
        elif args.command == "ssh-acceptance-no-residual":
            _print(harness.verify_no_residual_processes(run, actor_id=args.actor))
        elif args.command == "ssh-acceptance-tunnel-prepare":
            _print({
                "external_run_ids": harness.prepare_tunnel_recovery_test(
                    run,
                    actor_id=args.actor,
                )
            })
        elif args.command == "ssh-acceptance-tunnel-cycle":
            _print(harness.schedule_tunnel_outage(
                actor_id=args.actor,
                outage_seconds=args.outage_seconds,
            ))
        elif args.command == "ssh-acceptance-tunnel-verify":
            _print(harness.verify_tunnel_recovery_test(
                run,
                args.external_run_ids,
                actor_id=args.actor,
                outage_seconds=args.outage_seconds,
                timeout_s=args.timeout_s,
            ))
        elif args.command == "ssh-acceptance-reboot-arm":
            _print(harness.arm_startup_after_reboot(run,actor_id=args.actor))
        elif args.command == "ssh-acceptance-reboot-verify":
            _print(harness.verify_startup_after_reboot(run,actor_id=args.actor))
        elif args.command == "ssh-acceptance-report":
            _print({"report_path": str(harness.write_report(run, actor_id=args.actor)),
                    "run_id": run.run_id, "status": run.status.value})
            return 2 if args.require_passed and run.status.value != "passed" else 0
        elif args.command == "ssh-acceptance-enable":
            _print(harness.enable_after_acceptance(run, actor_id=args.actor))
        elif args.command == "ssh-supervisor-startup-install":
            _print(harness.install_supervisor_startup(run, actor_id=args.actor))
        return 0
    if args.command == "ssh-supervisor-status":
        _print(ssh_harness_for_machine(args.machine_id, require_workbench=False).supervisor_status())
        return 0
    if args.command == "ssh-supervisor-startup-status":
        _print(ssh_harness_for_machine(args.machine_id, require_workbench=False).supervisor_startup_status())
        return 0
    if args.command == "ssh-supervisor-restart":
        _print(ssh_harness_for_machine(args.machine_id, require_workbench=False).restart_supervisor(actor_id=args.actor))
        return 0
    if args.command == "ssh-sealed-runtime-deploy":
        _print(ssh_harness_for_machine(args.machine_id, require_workbench=False).deploy_sealed_runtime(
            Path(args.archive),
            args.runtime_version,
            actor_id=args.actor,
        ))
        return 0
    if args.command == "ssh-supervisor-runtime-promote":
        _print(ssh_harness_for_machine(args.machine_id, require_workbench=False).promote_running_runtime(actor_id=args.actor))
        return 0
    if args.command == "ssh-readiness-set":
        _print(service.set_machine_conditional_readiness(
            args.machine_id,
            operational_execution=args.operational_execution,
            conditional_production=args.conditional_production,
            startup_after_reboot=args.startup_after_reboot,
            numeric_equivalence=args.numeric_equivalence,
            capability_warnings=args.warning,
            execution_provenance={
                "cpu_family": args.cpu_family,
                "runtime_version": args.runtime_version,
                "comsol_version": args.comsol_version,
            },
            owner_mode=MachineMode(args.owner_mode),
            profile_concurrency_limits=(dict(args.profile_limit) if args.profile_limit is not None else None),
            actor_id=args.actor,
        ))
        return 0
    if args.command == "ssh-retry-migration-audit":
        _print(RetryMigrationAuditor(
            service,
            project_root=SOURCE_ROOT,
            source_machine_id=args.source_machine_id,
            target_machine_id=args.target_machine_id,
        ).run())
        return 0
    if args.command == "ssh-gamma-local-probe":
        _print(NumericalProbeRunner(ssh_harness_for_machine(args.machine_id)).run_gamma_local(
            actor_id=args.actor,
            timeout_s=args.timeout_s,
        ))
        return 0
    if args.command == "ssh-acceptance-cancel":
        ssh_harness_for_machine(args.machine_id).request_cancel(args.external_run_id)
        _print({"external_run_id": args.external_run_id, "cancel_requested": True})
        return 0
    if args.command == "ssh-cleanup-preview":
        _print(ssh_harness_for_machine(args.machine_id).cleanup_preview())
        return 0
    if args.command == "ssh-cleanup-confirm":
        _print(ssh_harness_for_machine(args.machine_id).cleanup_confirm(args.relative_path, args.root_uuid))
        return 0
    if args.command == "init-db":
        print(database_url)
    elif args.command == "create-user":
        _print(service.create_user(
            UserAccount(
                user_id=args.user_id,
                display_name=args.display_name,
                roles={UserRole(role) for role in args.roles},
            ),
            actor_id=args.actor,
        ))
    elif args.command == "issue-token":
        _print(service.issue_token(args.user_id, actor_id=args.actor))
    elif args.command == "invite-member":
        from .invitation import generate_member_invitation

        output_path = Path(args.output)
        result = generate_member_invitation(
            repository,
            user_id=args.user_id,
            actor_id=args.actor,
            center_host=args.center_host,
            center_ssh_user=args.center_ssh_user,
            machine_id=args.machine_id,
            worker=args.worker,
            central_web_port=args.central_web_port,
            coordinator_ssh_port=args.coordinator_ssh_port,
            local_web_port=args.local_web_port,
            ttl_minutes=args.ttl_minutes,
            output=output_path,
            authorized_keys_file=Path(args.authorized_keys_file) if args.authorized_keys_file else None,
        )
        if args.installer:
            from .member_installer import build_member_installer
            from .release import build_wheel, stage_web_assets

            project_root = SOURCE_ROOT
            wheelhouse_dir = Path(
                args.wheelhouse
                or (default_rcn_home() / "releases" / "wheelhouse-cp311")
            )
            if not wheelhouse_dir.is_dir():
                raise FileNotFoundError(
                    f"wheelhouse not found: {wheelhouse_dir} (see member_installer docs)"
                )
            embeddable = wheelhouse_dir / "python-3.11.9-embed-amd64.zip"
            if not embeddable.is_file():
                raise FileNotFoundError(f"embeddable python missing: {embeddable}")
            with tempfile.TemporaryDirectory(prefix="rcn-invite-wheel-") as temporary:
                wheel_path = build_wheel(project_root, Path(temporary) / "wheel")
                result["installer"] = build_member_installer(
                    invitation=json.loads(output_path.read_text(encoding="utf-8")),
                    invitation_bytes=output_path.read_bytes(),
                    wheel_path=wheel_path,
                    wheelhouse_dir=wheelhouse_dir,
                    embeddable_zip=embeddable,
                    output_exe=Path(args.installer),
                )
        _print(result)
    elif args.command == "issue-machine-token":
        _print(service.issue_machine_credential(args.machine_id, actor_id=args.actor))
    elif args.command == "revoke-machine-token":
        _print(service.revoke_machine_credential(
            args.machine_id,
            args.credential_id,
            actor_id=args.actor,
        ))
    elif args.command == "owner-set-mode":
        set_owner_mode(
            repository,
            machine_id=args.machine_id,
            owner_user_id=args.owner_user_id,
            mode=MachineMode(args.mode),
        )
        _print(repository.get_policy(args.machine_id))
    elif args.command == "register-project":
        _print(service.register_project(ProjectGrant.model_validate(_json_file(args.json_file)), actor_id=args.actor))
    elif args.command == "register-machine":
        _print(service.register_machine(
            MachineState.model_validate(_json_file(args.machine_json)),
            MachinePolicy.model_validate(_json_file(args.policy_json)),
            actor_id=args.actor,
        ))
    elif args.command == "approve":
        _print(service.approve(ApprovalRecord.model_validate(_json_file(args.json_file)), actor_id=args.actor))
    elif args.command == "submit":
        _print(service.submit(JobEnvelope.model_validate(_json_file(args.json_file)), actor_id=args.actor))
    elif args.command == "jobs":
        _print([job.model_dump(mode="json") for job in repository.list_jobs()])
    elif args.command == "cancel":
        _print(service.cancel(args.job_id, actor_id=args.actor, reason=args.reason))
    elif args.command == "retry":
        _print(service.retry(args.job_id, actor_id=args.actor))
    elif args.command == "cancel-unit":
        _print(service.cancel_unit(
            args.job_id,
            args.work_unit_id,
            actor_id=args.actor,
            reason=args.reason,
        ))
    elif args.command == "retry-unit":
        _print(service.retry_unit(
            args.job_id,
            args.work_unit_id,
            actor_id=args.actor,
            allow_cancelled=args.allow_cancelled,
        ))
    elif args.command == "reassign-unit":
        result = service.reassign_unit(
            args.job_id,
            args.work_unit_id,
            args.target_machine_id,
            actor_id=args.actor,
            reason=args.reason,
        )
        _print({
            "stage": result["stage"],
            "job_id": result["job"].job_id,
            "work_unit_id": args.work_unit_id,
            "target_machine_id": args.target_machine_id,
            "unit_status": (
                next(
                    (
                        unit.status.value
                        for unit in result["job"].work_units
                        if unit.work_unit_id == args.work_unit_id
                    ),
                    None,
                )
            ),
            "next_action": (
                "cancellation propagating; re-run reassign-unit once the attempt leaves cancel_pending"
                if result["stage"] == "cancel_requested"
                else "unit pinned to the target machine; dispatcher will pick it up"
            ),
        })
    elif args.command == "migrate-unstarted-approval":
        migrated = service.migrate_unstarted_solver_contract(
            args.job_id,
            approval_id=args.approval_id,
            actor_id=args.actor,
            solver_variants=(
                {SolverVariant(value) for value in args.solver_variant}
                if args.solver_variant is not None else None
            ),
            reason=args.reason,
        )
        _print({
            "job_id": migrated.job_id,
            "approval_id": args.approval_id,
            "migrated_units": sum(
                1 for unit in migrated.work_units if unit.solver_approval_id == args.approval_id
            ),
        })
    elif args.command == "clear-standby":
        _print(operator_tools.clear_standby(
            service,
            args.job_id,
            args.work_unit_id,
            actor_id=args.actor,
            reason=args.reason,
        ))
    elif args.command == "job-reservations":
        _print(operator_tools.list_job_reservations(service, args.job_id, active_only=not args.all))
    elif args.command == "set-job-placement":
        _print(operator_tools.pin_job_placement(
            service,
            args.job_id,
            args.machine_id,
            actor_id=args.actor,
            required=args.required,
            reason=args.reason,
        ))
    elif args.command == "machine-capacity":
        results = {}
        if args.max_cpus is not None:
            results["cpu_ceiling"] = operator_tools.set_machine_cpus(
                service,
                args.machine_id,
                max_cpus=args.max_cpus,
                actor_id=args.actor,
            )
        if args.hard_capacity is not None:
            results["capacity_change"] = operator_tools.issue_capacity_change(
                service,
                args.machine_id,
                hard_capacity_units=args.hard_capacity,
                reason=args.reason,
                actor_id=args.actor,
                ticket_id=args.ticket_id,
                confirmation_hash=args.confirm_hash,
            )
        elif args.target is not None:
            results["target_capacity"] = operator_tools.set_target_capacity(
                service,
                args.machine_id,
                target_concurrent_units=args.target,
                reason=args.reason,
                actor_id=args.actor,
                ticket_id=args.ticket_id,
                confirmation_hash=args.confirm_hash,
            )
        if not results:
            raise SystemExit("machine-capacity requires --max-cpus and/or --hard-capacity/--target")
        _print(results)
    elif args.command == "set-job-priority":
        _print(operator_tools.set_job_priority(
            service,
            args.job_id,
            priority=args.priority,
            actor_id=args.actor,
            reason=args.reason,
        ))
    elif args.command == "project-grant":
        _print(operator_tools.retune_project_grant(
            service,
            args.project_id,
            actor_id=args.actor,
            priority_ceiling=args.priority_ceiling,
            max_running_units=args.max_running,
            max_queued_units=args.max_queued,
        ))
    elif args.command == "auto-retry":
        _print({"requeued_units": service._auto_retry_failed_units(actor_id=args.actor)})
    elif args.command == "job-attempts":
        job = repository.get_job(args.job_id)
        if job is None:
            raise KeyError(f"job not found: {args.job_id}")
        _print([
            {"work_unit_id": unit.work_unit_id, "attempts": [attempt.model_dump(mode="json") for attempt in unit.attempts]}
            for unit in job.work_units
        ])
    elif args.command == "unit-started":
        _print(service.mark_unit_started(args.job_id, args.work_unit_id, actor_id=args.actor))
    elif args.command == "unit-completed":
        _print(service.complete_unit(
            args.job_id,
            args.work_unit_id,
            manifest=ArtifactManifest.model_validate(_json_file(args.manifest_json)),
            duration_s=args.duration_s,
            actor_id=args.actor,
        ))
    elif args.command == "unit-failed":
        _print(service.fail_unit(
            args.job_id,
            args.work_unit_id,
            error=args.error,
            retryable=not args.terminal,
            actor_id=args.actor,
        ))
    elif args.command == "artifact-manifests":
        _print([
            manifest.model_dump(mode="json")
            for manifest in repository.list_artifact_manifests(args.job_id)
        ])
    elif args.command == "schedule-once":
        assignment = service.schedule_once(actor_id=args.actor)
        _print(assignment.model_dump(mode="json") if assignment else None)
    elif args.command == "machines":
        _print([machine.model_dump(mode="json") for machine in repository.list_machines()])
    elif args.command == "events":
        _print([event.model_dump(mode="json") for event in repository.list_events()])
    else:
        raise AssertionError(f"unhandled command: {args.command}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
