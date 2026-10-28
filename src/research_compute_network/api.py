"""FastAPI control-plane interface."""

from __future__ import annotations

from .runtime_cache_admission import CachedRuntimeAdmissionRequest

import asyncio
import contextlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Literal

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse, Response
from pydantic_core import to_json
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .submission_operations import (SubmissionOperationRequest, SubmissionOperationConflict, operation_id, put_submission_operation, confirm_submission_operation)
from .read_models import JobVisibility
from .event_visibility import EventVisibility
from .control_transactions import (control_by_ticket, claim_control_execution,
                                   recover_control_delivery, IMMEDIATE_MACHINE_ACTIONS)
from .auth import AuthContext, PilotAuthenticator, require_role
from .metadata_actions import (
    MetadataActionConflict, MetadataActionForbidden, execute_metadata_action,
    metadata_action_receipt, metadata_action_request, run_preflight_metadata_action,
)
from .scheduling_controls import SchedulingChange, SchedulingConfirmation
from .fleet_presentation import present_fleet
from .help import HelpCatalog
from .hashing import sha256_value
from .models import (
    AlertStatus,
    AccessRestriction,
    AdminOperation,
    ApprovalRecord,
    EnrollmentRequest,
    ExecutionProfile,
    FeatureSettings,
    FeatureVisibility,
    JobEnvelope,
    MachineExecutionConfig,
    MachineCommandResult,
    MachineControlAction,
    MachineControlTarget,
    ControlTargetResult,
    ControlTargetState,
    DispatcherControlAction,
    MachineMode,
    MachinePolicy,
    MachineState,
    OriginImportReceipt,
    OriginAdapterRegistration,
    PartitionRequest,
    PlacementConstraint,
    ProjectStatus,
    ResourcePolicy,
    SolverCompatibilityApproval,
    SolverVariant,
    UserAccount,
    UserRole,
    SupervisorState,
    TelemetryState,
    UnitCompletion,
    UnitFailure,
    derived_job_status,
    job_activity_state,
)
from .onboarding import MachineOnboardingManager
from .machine_api import build_machine_observation_router
from .project_api import build_project_router
from .machine_cpu_override_api import build_machine_cpu_override_router
from .origin_transfer_api import build_origin_transfer_router
from .storage_lifecycle import StorageLifecycle
from .storage_lifecycle_api import build_storage_lifecycle_router
from .dispatcher_control import DispatcherProcessController
from .paths import ControlPlanePaths
from .partitioning import PartitionConfirmationRequired
from .submission_operations import (
    SubmissionOperationRequest, SubmissionOperationConflict, operation_id,
    put_submission_operation, confirm_submission_operation,
)
from .repository import MetadataRepository, PolicyRevisionConflict, RevisionConflictError
from .remote_storage import validate_remote_root_path
from .schedulers.ssh import OpenSshTransport
from .service import (
    ExecutionCompatibilityError,
    NetworkService,
    PACKAGE_VERSION,
)
from .runtime_policy import ControlPlaneIdentity, RuntimePolicy
from .ssh_acceptance import SshAcceptanceHarness
from .scientific_acceptance_review import ScientificAcceptanceReviewRequest
from .ssh_monitor import SshMachineMonitor
from .simulator import DemoSimulator
from .tunnel import build_boot_task_xml, build_reconnect_script, validate_startup_configuration


PACKAGE_WEB_DIST = Path(str(files("research_compute_network").joinpath("web_dist")))
SOURCE_WEB_DIST = Path(__file__).resolve().parents[2] / "web" / "dist"


def web_dist() -> Path:
    # The Vite build is staged into the package directory. Prefer it so a
    # legacy web/dist tree cannot silently serve an older console in source runs.
    if (PACKAGE_WEB_DIST / "index.html").is_file():
        return PACKAGE_WEB_DIST
    return SOURCE_WEB_DIST


def job_summary(job: JobEnvelope) -> dict:
    """Return the operational list view without scientific unit payloads."""
    payload = job.model_dump(
        mode="json",
        exclude={"input_manifest", "work_units"},
    )
    payload["work_units"] = []
    payload["recorded_status"] = payload["status"]
    payload["status"] = derived_job_status(job).value
    payload["activity_state"] = job_activity_state(job)
    for unit in job.work_units:
        compact = unit.model_dump(
            mode="json",
            exclude={"payload", "attempts"},
        )
        compact["required_capabilities"] = sorted(compact["required_capabilities"])
        compact["allowed_solver_variants"] = sorted(compact["allowed_solver_variants"])
        compact["attempts"] = (
            [unit.attempts[-1].model_dump(mode="json")]
            if unit.attempts
            else []
        )
        payload["work_units"].append(compact)
    return payload


class MachineRegistration(BaseModel):
    machine: MachineState
    policy: MachinePolicy


class CancelRequest(BaseModel):
    reason: str = ""


class AttemptAbandonmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_attempt_id: str = Field(min_length=1, max_length=512)
    expected_external_run_id: str | None = Field(max_length=512)
    reason: str = Field(min_length=1, max_length=1000)
    operation_id: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("expected_attempt_id", "expected_external_run_id", "reason", "operation_id")
    @classmethod
    def nonblank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("attempt abandonment requires an explicit identity and reason")
        return value


class UnitReassignRequest(BaseModel):
    target_machine_id: str
    reason: str = ""
    operation_id: str | None = None
    expected_attempt_id: str | None = None
    expected_external_run_id: str | None = None


class UnstartedSolverContractRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1, max_length=256)
    solver_variants: set[SolverVariant] = Field(min_length=1, max_length=2)
    expected_revision: int = Field(ge=0, strict=True)
    reason: str = Field(min_length=1, max_length=1000)

    @field_validator("reason", "approval_id")
    @classmethod
    def nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("solver contract controls require explicit approval and reason")
        return value


# Compact /v1/jobs keeps unit details embedded for the most recent N history
# jobs so the runs board can render full finished-job cards; older history
# records degrade to counts (unit_count / completed_unit_count), keeping the
# 15-second compact refresh bounded no matter how many jobs accumulate.
COMPACT_HISTORY_EMBED_LIMIT = 50


class MachineModeRequest(BaseModel):
    mode: MachineMode
    reason: str = ""


class ResourcePolicyConfirmation(BaseModel):
    policy: ResourcePolicy
    expected_revision: int = Field(ge=0)
    confirmation_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class MachineExecutionTuningRequest(BaseModel):
    disk_reserve_gib: int = Field(ge=1)
    success_retention_days: int = Field(ge=0)
    failure_retention_days: int = Field(ge=0)
    poll_interval_s: int = Field(ge=5, le=300)
    profile_concurrency_limits: dict[str, int] = Field(default_factory=dict)


class MachineSshTimeoutsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ssh_connect_timeout_s: int = Field(ge=1, le=30, strict=True)
    ssh_status_timeout_s: int = Field(ge=20, le=120, strict=True)
    reason: str = Field(min_length=1, max_length=1000)

    @field_validator("reason")
    @classmethod
    def nonblank_reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("SSH timeout changes require an explicit reason")
        return value


class CleanupConfirmation(BaseModel):
    relative_path: str
    root_uuid: str


class DemoCleanupConfirmation(BaseModel):
    confirmation_hash: str


class TunnelInstallRequest(BaseModel):
    run_as: Literal["SYSTEM", "user"] = "SYSTEM"


class EnrollmentIssueRequest(BaseModel):
    owner_user_id: str
    ttl_minutes: int = 30


class SelfEnrollmentIssueRequest(BaseModel):
    ttl_minutes: int = Field(default=30, ge=1, le=120)


class ExternalComsolConsentRequest(BaseModel):
    authorized: bool


class PressureOverridePreviewRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    ttl_minutes: int = Field(default=30, ge=1, le=120)
    requested_concurrent_units: int | None = Field(default=None, ge=1)


class PressureOverrideConfirmRequest(BaseModel):
    ticket_id: str
    confirmation_hash: str


class AdminOperationPreviewRequest(BaseModel):
    action: AdminOperation
    job_id: str
    work_unit_id: str | None = None
    reason: str = Field(default="", max_length=500)


class AdminOperationConfirmRequest(BaseModel):
    ticket_id: str
    confirmation_hash: str


class MachineControlPreviewRequest(BaseModel):
    action: MachineControlAction
    targets: list[MachineControlTarget] = Field(min_length=1, max_length=5)
    reason: str = Field(default="", max_length=500)


class MachineControlConfirmRequest(BaseModel):
    ticket_id: str
    confirmation_hash: str
    break_glass_pin: str | None = Field(default=None, max_length=128)
    typed_machine_id: str | None = None
    process_set_hash: str | None = None


class RuntimeControlPreviewRequest(BaseModel):
    action: Literal["promote_runtime", "rollback_runtime"]
    reason: str = Field(min_length=1, max_length=500)


class RuntimeControlConfirmRequest(BaseModel):
    ticket_id: str
    confirmation_hash: str


class BreakGlassPinRequest(BaseModel):
    pin: str = Field(min_length=8, max_length=128)


class AlertTransitionRequest(BaseModel):
    status: AlertStatus
    snoozed_until: datetime | None = None
    request_id: str | None = None
    expected_status: AlertStatus | None = None
    expected_last_seen_at: datetime | None = None
    expected_occurrence_count: int | None = Field(default=None, ge=1)
    expected_acknowledged_at: datetime | None = None
    expected_snoozed_until: datetime | None = None
    expected_resolved_at: datetime | None = None


class TokenIssueOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent: bool = Field(default=False, strict=True)


class DispatcherControlPreviewRequest(BaseModel):
    action: DispatcherControlAction
    reason: str = Field(default="", max_length=500)


class DispatcherControlConfirmRequest(BaseModel):
    ticket_id: str
    confirmation_hash: str


def _public_execution_config(
    config: MachineExecutionConfig,
    *,
    include_connection_details: bool = True,
) -> dict:
    """Expose operational metadata without returning the pinned key line."""
    payload = config.model_dump(mode="json")
    payload["telemetry_policy_sha256"] = sha256_value(
        config.telemetry_policy.model_dump(mode="json")
    )
    payload["pinned_host_key_present"] = bool(config.pinned_host_key)
    payload.pop("pinned_host_key", None)
    if not include_connection_details:
        for key in (
            "ssh_host",
            "ssh_port",
            "ssh_user",
            "remote_root",
            "python_executable",
            "comsol_root",
            "coordinator_host",
            "coordinator_port",
            "coordinator_user",
            "reverse_forward_host",
            "reverse_forward_port",
            "root_uuid",
            "legacy_worker_path",
        ):
            payload.pop(key, None)
    return payload


def _current_reconciliation_status(repository: MetadataRepository, payload: dict) -> dict:
    """Publish one current metadata proof alongside the historical cycle counter."""
    snapshot = repository.get_reconciliation_snapshot()
    return {
        **payload,
        "published_pending_reconciliation": payload.get("pending_reconciliation", 0),
        "pending_reconciliation": snapshot["unit_count"],
        "pending_reconciliation_source": "current_operational_metadata_v1",
        "reconciliation_snapshot": {
            "unit_count": snapshot["unit_count"],
            "identity_sha256": snapshot["identity_sha256"],
        },
    }


def create_app(
    *,
    database_url: str = "sqlite:///./.state/control-plane.db",
    authenticator: PilotAuthenticator | None = None,
    allow_local_trusted: bool = True,
    demo: bool = False,
    trusted_hosts: list[str] | None = None,
    auto_recover_dispatcher: bool = False,
    runtime_policy: RuntimePolicy | None = None,
) -> FastAPI:
    repository = MetadataRepository(database_url)
    service = NetworkService(repository, runtime_policy=runtime_policy)
    identity = ControlPlaneIdentity.current(service.runtime_policy)
    dataset_mode = "demo" if demo else "formal"
    service.initialize(dataset_mode=dataset_mode)
    auth = authenticator or PilotAuthenticator(repository, allow_local_trusted=allow_local_trusted)
    help_catalog = HelpCatalog()
    state = ControlPlanePaths.from_root()
    dispatcher_controller = DispatcherProcessController(
        repository,
        database_url=database_url,
        paths=state,
        runtime_policy=service.runtime_policy,
    )
    static_root = web_dist()

    app = FastAPI(
        title="Research Compute Network",
        version=PACKAGE_VERSION,
        docs_url="/docs" if allow_local_trusted else None,
        redoc_url="/redoc" if allow_local_trusted else None,
        openapi_url="/openapi.json" if allow_local_trusted else None,
    )
    from .member_release_catalog import RuntimeNotConfigured

    @app.exception_handler(RuntimeNotConfigured)
    async def runtime_unavailable(_request, _exc):
        return JSONResponse(status_code=409, content={"detail": {
            "reason_code": "runtime_not_configured",
            "message": "An operator-approved external runtime is required."}})

    from .release_maintenance import build_release_maintenance_router, get_transfer_gate
    app.state.cooperative_shutdown_requested = threading.Event()
    app.state.transfer_gate = get_transfer_gate(state.root)
    app.include_router(build_release_maintenance_router(state.root, auth))

    @app.exception_handler(HTTPException)
    async def structured_http_error(_request: Request, exc: HTTPException) -> JSONResponse:
        payload: dict = {"detail": exc.detail}
        if exc.status_code in {401, 403, 409}:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            reason_code = detail.get("reason_code") if isinstance(detail, dict) else None
            if not reason_code:
                reason_code = {
                    401: "authentication_required",
                    403: "authorization_required",
                    409: "state_conflict",
                }[exc.status_code]
            default_next_action = (
                "连接运营台并提供个人访问 token"
                if exc.status_code == 401 else
                "查看所需角色或授权，并向对应 owner 或管理员申请"
                if exc.status_code == 403 else
                "刷新当前状态并按返回原因处理后重试"
            )
            restriction = AccessRestriction(
                reason_code=reason_code,
                current_state=detail.get("current_state") or (
                    "unauthenticated" if exc.status_code == 401 else "restricted"
                ),
                missing_roles=set(detail.get("missing_roles") or []),
                missing_project_grant=detail.get("missing_project_grant"),
                missing_profile=detail.get("missing_profile"),
                missing_capabilities=set(detail.get("missing_capabilities") or []),
                quota=dict(detail.get("quota") or {}),
                next_action=detail.get("next_action") or default_next_action,
                action_path=detail.get("action_path") or (
                    "/connect" if exc.status_code == 401 else "/app/help/access-control"
                ),
                requires=detail.get("requires") or (
                    "member" if exc.status_code == 401 else "admin"
                ),
                message=detail.get("message") or "该功能存在，但当前身份/项目/机器尚未获得所需权限。",
            )
            payload["restriction"] = restriction.model_dump(mode="json")
        return JSONResponse(status_code=exc.status_code, content=payload, headers=exc.headers)
    from .public_member_ingress import INGRESS_HOST, PublicMemberIngress
    if trusted_hosts:
        # The managed ingress fixes this origin Host; its outer guard limits
        # the public route surface and requires explicit member identity.
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=[*trusted_hosts, INGRESS_HOST])
    app.add_middleware(PublicMemberIngress, state_root=state.root)
    app.state.repository = repository
    app.state.service = service
    app.state.dataset_mode = dataset_mode
    app.state.control_plane_identity = identity
    from .member_enrollment_api import build_member_enrollment_router

    from .member_admission_monitor import install_member_admission_monitor
    install_member_admission_monitor(app, repository=repository, service=service,
        verification_root=state.onboarding / 'transport-proofs', dataset_mode=dataset_mode, state_root=state.root)

    app.include_router(build_machine_cpu_override_router(repository=repository, service=service, auth=auth))
    app.include_router(build_member_enrollment_router(
        repository=repository, auth=auth, dataset_mode=dataset_mode,
        verification_root=state.onboarding / 'transport-proofs',
    ))
    app.include_router(
        build_project_router(
            repository=repository,
            service=service,
            auth=auth,
        )
    )

    from .personal_access_api import build_personal_access_router
    app.include_router(build_personal_access_router(repository=repository, auth=auth))
    from .agent_credentials import build_agent_credentials_router
    app.include_router(build_agent_credentials_router(repository=repository, auth=auth))
    from .member_pairing import build_member_pairing_router
    app.include_router(build_member_pairing_router(repository=repository, auth=auth, state_root=state.root))

    def job_visibility(context):
        if UserRole.ADMIN in context.roles:
            return None
        settings = repository.get_feature_settings()
        if settings.visibility == FeatureVisibility.OWN_DETAIL or not settings.show_group_job_details:
            return JobVisibility(user_id=context.actor_id)
        return JobVisibility(user_id=context.actor_id,
            project_ids=frozenset(g.project_id for g in repository.list_project_grants() if g.authorizes(context.actor_id)),
            machine_ids=frozenset(m.machine_id for m in repository.list_machines() if m.owner_user_id == context.actor_id))

    def require_project_access(project_id: str, context: AuthContext, *, allow_auto_registration: bool = False) -> None:
        """Enforce project membership independently from user ownership."""
        if UserRole.ADMIN in context.roles:
            return
        grant = repository.get_project_grant(project_id)
        if grant is None and allow_auto_registration:
            from .personal_runtime import bootstrap_person
            policy = bootstrap_person(service, context.actor_id)
            if policy is not None and policy.approved and policy.auto_project and not policy.paused:
                return
        if grant is None:
            reason = "project grant not found"
            reason_code = "project_grant_missing"
            current_state = "unregistered"
            requires = "admin"
            next_action = "在项目页面提交登记申请，等待管理员首次确认"
        elif grant.status == ProjectStatus.FROZEN:
            reason = "project is frozen"
            reason_code = "project_frozen"
            current_state = "frozen"
            requires = "admin"
            next_action = "查看冻结原因并联系管理员恢复项目"
        elif grant.status != ProjectStatus.ACTIVE:
            reason = "project grant is not approved"
            reason_code = "project_not_active"
            current_state = grant.status.value
            requires = "admin"
            next_action = "等待管理员完成项目首次确认和 Profile 批准"
        elif not grant.authorizes(context.actor_id):
            reason = "user is not authorized for project"
            reason_code = "project_authorization_required"
            current_state = "user_not_granted"
            requires = "project_owner"
            next_action = "请项目 owner 将当前用户添加为可信提交者"
        else:
            return
        service.record_project_access_denied(
            project_id,
            actor_id=context.actor_id,
            reason=reason,
        )
        raise HTTPException(status_code=403, detail={
            "reason_code": reason_code,
            "message": "该功能存在，但当前身份/项目尚未获得所需权限。",
            "current_state": current_state,
            "missing_project_grant": project_id,
            "next_action": next_action,
            "action_path": "/app/projects",
            "requires": requires,
        })

    def require_job_access(found: JobEnvelope, context: AuthContext) -> None:
        if UserRole.ADMIN in context.roles:
            return
        grant = repository.get_project_grant(found.project_id)
        if grant is not None and grant.authorizes(context.actor_id):
            return
        owned_machine_ids = {
            machine.machine_id for machine in repository.list_machines()
            if machine.owner_user_id == context.actor_id
        }
        if any(
            unit.assigned_machine_id in owned_machine_ids
            for unit in found.work_units
        ):
            return
        service.record_project_access_denied(
            found.project_id,
            actor_id=context.actor_id,
            reason="job is outside the user's project and machine ownership boundary",
        )
        raise HTTPException(status_code=404, detail="job not found")

    def require_job_owner(found: JobEnvelope, context: AuthContext) -> None:
        if UserRole.ADMIN in context.roles:
            return
        require_project_access(found.project_id, context)
        if found.user_id == context.actor_id:
            return
        service.record_project_access_denied(
            found.project_id,
            actor_id=context.actor_id,
            requested_user_id=found.user_id,
            reason="job is owned by another user",
        )
        raise HTTPException(status_code=403, detail="job is owned by another user")

    def operational_job_or_404(job_id: str) -> JobEnvelope:
        """Load only the mutable Job projection for access and lifecycle APIs."""
        found = repository.get_operational_job(job_id)
        if found is None:
            raise HTTPException(status_code=404, detail="job not found")
        return found

    lifecycle = None
    if repository.engine.url.get_backend_name() == "sqlite" and repository.engine.url.database not in {None, "", ":memory:"}:
        lifecycle = StorageLifecycle(repository, state.origin_spool,
            center_binding=state.storage_registry.binding("origin_spool"),
            validate_center=lambda: state.validate_storage("origin_spool"),
            validate_retirement=lambda: state.validate_storage_write("origin_spool"))
        app.state.storage_lifecycle = lifecycle
        app.include_router(build_storage_lifecycle_router(
            lifecycle=lifecycle, auth=auth, require_owner=require_job_owner))
        from .worker_model_retirement_api import build_worker_model_retirement_router
        app.include_router(build_worker_model_retirement_router(lifecycle=lifecycle, auth=auth))
        storage_gc_stop = threading.Event()

        async def collect_verified_duplicates() -> None:
            # One finite batch at a time; retirement does not block dispatch or
            # turn metadata/API readiness into a wait on scientific data IO.
            while True:
                work = asyncio.create_task(asyncio.to_thread(lifecycle.run_gc_batch,
                    max_units=4, max_files=16, stop_event=storage_gc_stop))
                try:
                    result = await asyncio.shield(work)
                    app.state.storage_gc = {"phase": "active", "last_batch": result}
                except asyncio.CancelledError:
                    with contextlib.suppress(Exception):
                        await work
                    raise
                except Exception as exc:
                    app.state.storage_gc = {"phase": "deferred", "error_type": type(exc).__name__}
                await asyncio.sleep(30)

        @app.get("/v1/admin/storage/inventory")
        def storage_inventory(context: AuthContext = Depends(auth.actor)) -> dict:
            require_role(context, UserRole.ADMIN)
            return lifecycle.inventory.snapshot()

        @app.on_event("startup")
        async def start_storage_gc() -> None:
            storage_gc_stop.clear()
            app.state.storage_gc = {"phase": "scheduled"}
            app.state.storage_gc_task = asyncio.create_task(collect_verified_duplicates())

        @app.on_event("shutdown")
        async def join_storage_gc() -> None:
            storage_gc_stop.set()
            task = getattr(app.state, "storage_gc_task", None)
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        @app.get("/v1/admin/storage/status")
        def storage_status(context: AuthContext = Depends(auth.actor)) -> dict:
            require_role(context, UserRole.ADMIN)
            from .storage_roots import read_write_pause
            import shutil
            import sqlite3
            roles = {}
            for role in ("origin_spool", "dispatcher_bundles"):
                binding = state.storage_registry.binding(role)
                row = {"registered": binding is not None, "root": str(getattr(state, role)),
                       "store_id": binding.store_id if binding else None,
                       "generation": binding.generation if binding else None}
                try:
                    root = state.validate_storage(role)
                    ancestor = root
                    while not ancestor.exists() and ancestor != ancestor.parent:
                        ancestor = ancestor.parent
                    usage = shutil.disk_usage(ancestor)
                    row.update(available=True, free_bytes=usage.free, total_bytes=usage.total,
                               hard_reserve_bytes=10 * 1024**3)
                except (OSError, ValueError) as exc:
                    row.update(available=False, reason_code=getattr(exc, "reason_code", "storage_unavailable"))
                roles[role] = row
            with sqlite3.connect(lifecycle.database, timeout=5) as db:
                counts = {"policies": db.execute("SELECT COUNT(*) FROM storage_lifecycle_policies").fetchone()[0],
                          "receipts": db.execute("SELECT COUNT(*) FROM storage_lifecycle_receipts WHERE revoked_at IS NULL").fetchone()[0],
                          "pending_retirements": db.execute("SELECT COUNT(*) FROM storage_lifecycle_intents WHERE state='pending'").fetchone()[0],
                          "reader_pins": db.execute("SELECT COUNT(*) FROM storage_lifecycle_readers").fetchone()[0]}
                counts.update({
                    "scientific_acceptances": db.execute("SELECT COUNT(*) FROM scientific_export_acceptances WHERE revoked_at IS NULL").fetchone()[0],
                    "scientific_custody_receipts": db.execute("SELECT COUNT(*) FROM scientific_export_custody WHERE revoked_at IS NULL").fetchone()[0],
                    "model_policies": db.execute("SELECT COUNT(*) FROM scientific_model_policies").fetchone()[0],
                    "pending_model_retirements": db.execute("SELECT COUNT(*) FROM storage_lifecycle_intents WHERE state='pending' AND operation_kind='solved_model'").fetchone()[0],
                })
                claims = db.execute("SELECT host_id,volume_id,SUM(required_bytes),COUNT(*) FROM storage_volume_claims "
                    "WHERE state='active' GROUP BY host_id,volume_id").fetchall()
            return {"roles": roles, "lifecycle": counts, "write_pause": read_write_pause(state.root),
                    "active_capacity_claims": [{"host_id": r[0], "volume_id": r[1], "required_bytes": r[2], "count": r[3]} for r in claims],
                    "gc": {key: value for key, value in getattr(app.state, "storage_gc", {}).items() if key != "last_batch"}}

    app.include_router(build_origin_transfer_router(
        repository=repository, auth=auth, root=state.origin_spool,
        require_owner=require_job_owner,
        enabled=os.environ.get("RCN_ORIGIN_TRANSFER") == "1",
        validate_root=lambda: state.validate_storage("origin_spool"),
        validate_write=lambda: state.validate_storage_write("origin_spool"),
        budget_database=repository.engine.url.database if lifecycle is not None else None,
        lifecycle=lifecycle,
        control_root=state.root,
    ))
    app.state.onboarding = MachineOnboardingManager(
        service,
        state_root=state.onboarding,
    )
    app.state.dispatcher_controller = dispatcher_controller
    app.mount(
        "/assets",
        StaticFiles(directory=str(static_root / "assets"), check_dir=False),
        name="web-assets",
    )
    if auto_recover_dispatcher and not demo:
        async def recover_dispatcher_in_background() -> None:
            # API readiness never depends on a remote Attempt or a recovery
            # subprocess. One joined recovery invocation at a time; no replay
            # is started while a previous thread is still doing work.
            while True:
                work = asyncio.create_task(asyncio.to_thread(dispatcher_controller.recover_desired_state))
                try:
                    result = await asyncio.shield(work)
                    app.state.dispatcher_recovery = result
                    if result.get("outcome") in {"started", "already_running", "desired_state_not_open"}:
                        return
                except asyncio.CancelledError:
                    with contextlib.suppress(Exception):
                        await work
                    raise
                except Exception as exc:
                    app.state.dispatcher_recovery = {
                        "outcome": "deferred", "reason_code": "dispatcher_recovery_deferred",
                        "error_type": type(exc).__name__, "retry_after_s": 5,
                    }
                await asyncio.sleep(5)

        @app.on_event("startup")
        async def recover_dispatcher_on_startup() -> None:
            app.state.dispatcher_recovery = {"outcome": "scheduled", "remote_io_blocks_api": False}
            app.state.dispatcher_recovery_task = asyncio.create_task(recover_dispatcher_in_background())

        @app.on_event("shutdown")
        async def join_dispatcher_recovery() -> None:
            task = getattr(app.state, "dispatcher_recovery_task", None)
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
    if demo:
        simulator = DemoSimulator(service)
        simulator.bootstrap()
        app.state.demo_simulator = simulator

        @app.on_event("startup")
        async def start_demo_simulator() -> None:
            async def run_demo() -> None:
                while True:
                    simulator.tick()
                    await asyncio.sleep(2)
            app.state.demo_task = asyncio.create_task(run_demo())

        @app.on_event("shutdown")
        async def stop_demo_simulator() -> None:
            task = getattr(app.state, "demo_task", None)
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
    else:
        monitor = SshMachineMonitor(
            service,
            state_root=state.ssh,
            # Keep probe fan-out deliberately small, but do not let one busy
            # desktop monopolize the only slot and freeze the entire fleet.
            max_parallel_polls=2,
        )
        app.state.ssh_monitor = monitor

        @app.on_event("startup")
        async def start_ssh_monitor() -> None:
            app.state.ssh_monitor_task = asyncio.create_task(monitor.run_forever())

        @app.on_event("shutdown")
        async def stop_ssh_monitor() -> None:
            task = getattr(app.state, "ssh_monitor_task", None)
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    def require_assigned_machine_owner(
        job_id: str,
        work_unit_id: str,
        context: AuthContext,
    ) -> None:
        require_role(context, UserRole.MACHINE_OWNER)
        job = operational_job_or_404(job_id)
        unit = next(
            (candidate for candidate in job.work_units if candidate.work_unit_id == work_unit_id),
            None,
        )
        if unit is None:
            raise HTTPException(status_code=404, detail="work unit not found")
        if unit.assigned_machine_id is None:
            raise HTTPException(status_code=409, detail="work unit is not assigned")
        machine = repository.get_machine(unit.assigned_machine_id)
        if machine is None:
            raise HTTPException(status_code=409, detail="assigned machine is not registered")
        if UserRole.ADMIN not in context.roles and machine.owner_user_id != context.actor_id:
            raise HTTPException(status_code=403, detail="work unit is assigned to another owner's machine")

    def require_machine_owner(machine_id: str, context: AuthContext) -> None:
        require_role(context, UserRole.MACHINE_OWNER)
        machine = repository.get_machine(machine_id)
        if machine is None:
            raise HTTPException(status_code=404, detail="machine not found")
        if UserRole.ADMIN not in context.roles and machine.owner_user_id != context.actor_id:
            raise HTTPException(status_code=403, detail="machine owner mismatch")

    def metadata_mutation(action, context, kind, subject_id, mutate, *, sensitive=False,
                          wake_reason=None, wake_if=None):
        applied = False
        def apply():
            nonlocal applied
            result = jsonable_encoder(mutate())
            applied = True
            return result
        try:
            result = execute_metadata_action(repository, request_id=action[0],
                actor_id=context.actor_id, kind=kind, subject_id=subject_id,
                payload=action[1], mutate=apply,
                sensitive_payload=sensitive)
        except MetadataActionForbidden as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except MetadataActionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        # wake() writes a local notification file. It cannot participate in the
        # SQL transaction, and replay must not send a second notification.
        if applied and wake_reason is not None and (wake_if is None or wake_if(result)):
            dispatcher_controller.wake(reason=wake_reason)
        return result

    def require_metadata_visibility(receipt, context):
        kind, subject = receipt["kind"], receipt["subject_id"]
        if kind in {"machine_policy", "machine_external_comsol_consent"}:
            require_machine_owner(subject, context)
        elif kind in {"project_trusted_user_add", "project_trusted_user_remove"}:
            grant = repository.get_project_grant(subject)
            if grant is None:
                raise HTTPException(status_code=404, detail="project not found")
            if grant.owner_user_id != context.actor_id:
                raise HTTPException(status_code=403, detail="project owner required")
        elif kind == "project_registration":
            require_role(context, UserRole.MEMBER)
        elif kind in {
            "profile_create", "user_update", "user_token_revoke", "project_update",
            "project_registration_review", "project_freeze", "personal_submission_policy",
            "machine_execution_tuning", "feature_settings", "break_glass_pin",
            "resource_policy_confirm", "solver_approval_revoke", "scheduling_confirm",
            "member_admission_revoke", "onboarding_preflight", "abandon_attempt",
        }:
            require_role(context, UserRole.ADMIN)
        else:
            # New kinds need an explicit current-authorization rule before they
            # can be exposed through the common recovery endpoint.
            raise HTTPException(status_code=403, detail="operation visibility unavailable")

    def require_machine_detail_visibility(machine_id: str, context: AuthContext) -> MachineState:
        machine = repository.get_machine(machine_id)
        if machine is None:
            raise HTTPException(status_code=404, detail="machine not found")
        if UserRole.ADMIN in context.roles or machine.owner_user_id == context.actor_id:
            return machine
        raise HTTPException(
            status_code=403,
            detail={
                "reason_code": "machine_detail_owner_required",
                "message": "machine details are available only to its owner and administrators",
            },
        )

    app.include_router(
        build_machine_observation_router(
            repository=repository,
            service=service,
            auth=auth,
            require_machine_detail_visibility=require_machine_detail_visibility,
            wake_dispatcher=dispatcher_controller.wake,
            public_execution_config=_public_execution_config,
        )
    )

    def machine_transport(machine_id: str) -> OpenSshTransport:
        config = repository.get_machine_execution_config(machine_id)
        if config is None or not config.enabled:
            raise RuntimeError(f"enabled machine execution config not found: {machine_id}")
        return OpenSshTransport(config, state_root=state.ssh)

    def record_remote_command_result(operation_id: str, payload: dict, *, actor_id: str) -> None:
        result = MachineCommandResult.model_validate(payload)
        repository.put_machine_command_result(result)
        service.update_control_target(
            operation_id,
            ControlTargetResult(
                machine_id=result.machine_id,
                state=result.state,
                message=result.message,
                command_id=result.command_id,
                updated_at=result.completed_at or result.created_at,
            ),
            actor_id=actor_id,
        )

    def refresh_control_run(operation_id: str) -> dict:
        recover_control_delivery(service, operation_id, transport_for=machine_transport)
        run = repository.get_control_operation_run(operation_id)
        if run is None:
            raise KeyError(f"control operation not found: {operation_id}")
        for target in list(run.targets):
            if target.command_id is None or target.state in {
                ControlTargetState.COMPLETED,
                ControlTargetState.FAILED,
            }:
                continue
            try:
                payload = machine_transport(target.machine_id).read_machine_command_result(target.command_id)
                if payload is not None:
                    record_remote_command_result(
                        operation_id,
                        payload,
                        actor_id=f"machine-command:{target.machine_id}",
                    )
            except (OSError, RuntimeError, ValueError):
                # A status read failure is not itself a remote command failure.
                # The persisted operation remains acknowledged and retryable.
                continue
        refreshed = repository.get_control_operation_run(operation_id)
        assert refreshed is not None
        return refreshed.model_dump(mode="json")

    @app.get("/health")
    def health(_context: AuthContext = Depends(auth.actor)) -> dict:
        return {
            "status": "ok",
            "artifact_storage": "origin_submitter",
            "dataset_mode": app.state.dataset_mode,
        }

    @app.get("/v1/help/public")
    def public_help_index() -> list[dict]:
        return help_catalog.list_public()

    @app.get("/v1/help/public/{slug}")
    def public_help_article(slug: str, format: str = "html") -> dict:
        article = help_catalog.public_markdown(slug) if format == "markdown" else help_catalog.public(slug)
        if article is None:
            raise HTTPException(status_code=404, detail="help article not found")
        return article

    @app.get("/v1/help/protected")
    def protected_help_index(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        return help_catalog.list_for_roles(context.roles)

    @app.get("/v1/help/catalog")
    def help_catalog_index(context: AuthContext = Depends(auth.actor)) -> dict:
        return {
            "public": help_catalog.list_public(),
            "protected": help_catalog.list_role_catalog(context.roles),
        }

    @app.get("/v1/help/protected/{slug}")
    def protected_help_article(slug: str, format: str = "html", context: AuthContext = Depends(auth.actor)) -> dict:
        article = help_catalog.protected_markdown(slug, context.roles) if format == "markdown" else help_catalog.protected(slug, context.roles)
        if article is None:
            raise HTTPException(status_code=404, detail="help article not found")
        return article

    @app.get("/", response_class=HTMLResponse, response_model=None)
    def dashboard():
        index = static_root / "index.html"
        if index.is_file():
            return FileResponse(index)
        return HTMLResponse(
            "<h1>Research Compute Network</h1><p>The React client has not been built. "
            "Run the web build before opening this page.</p>",
        )

    @app.get("/v1/me")
    def current_actor(context: AuthContext = Depends(auth.actor)) -> dict:
        return {
            "actor_id": context.actor_id,
            "roles": sorted(role.value for role in context.roles),
            "scopes": sorted(context.scopes),
            "credential_id": getattr(context, "credential_id", None),
            "local_trusted": context.actor_id == "local-pilot",
        }

    @app.get("/v1/release/identity")
    def release_identity(context: AuthContext = Depends(auth.actor)) -> dict:
        from .release_identity import current_build
        return {"build":current_build(),"control_plane_deployment_id":identity.deployment_id,
                "package_version":identity.package_version,"worker_runtime_version":identity.worker_runtime_version,
                "protocol_version":identity.protocol_version}

    @app.get("/v1/distribution/contract")
    def member_distribution_contract(context: AuthContext = Depends(auth.actor)) -> dict:
        from .reliability_report import distribution_contract
        return distribution_contract()

    @app.get("/v1/admin/reliability-report")
    def reliability_report(context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        from .reliability_report import report
        return report(repository)

    @app.get("/v1/execution-runtime")
    def execution_runtime(context: AuthContext = Depends(auth.actor)) -> dict:
        """Return the control-plane-authorized runtime for origin sealing.

        Agents use this value as provenance; they cannot select an arbitrary
        runtime descriptor and therefore cannot create bundles that the
        Dispatcher will reject later.
        """
        return {
            "submission_operation_schema": 1,
            "person_submission_policy_schema": 1,
            "personal_agent_credentials_schema": 1,
            "metadata_operation_schema": 1,
            "machine_policy_cas_schema": 1,
            "compute_credit_schema": 1,
            "control_operation_replay_schema": 1,
            "member_retirement_schema": 1,
            "member_release_runtime_version": service.member_release.runtime_version,
            # runtime_version remains the compatibility alias used by existing
            # origin adapters. The explicit fields remove identity ambiguity.
            "runtime_version": identity.worker_runtime_version,
            "worker_runtime_version": identity.worker_runtime_version,
            "package_version": identity.package_version,
            "protocol_version": identity.protocol_version,
            "control_plane_deployment_id": identity.deployment_id,
            "disk_estimate_schema": 1,
            "task_priority_schema": 1,
            "submission_operation_schema": 1,
            "member_retirement_schema": 1,
            "member_release_runtime_version": service.member_release.runtime_version,
            # Launcher-provided identity lets release verify compare the live
            # process with runtime/current.json without persisting credentials.
            "process_executable": str(Path(sys.executable).resolve()),
            "configured_python_executable": os.environ.get("RCN_CONTROL_PLANE_PYTHON_EXECUTABLE"),
            "configured_runtime_root": os.environ.get("RCN_CONTROL_PLANE_RUNTIME_ROOT"),
            "state": "enabled" if service.member_release.configured else "runtime_not_configured",
            "runtime_configured": service.member_release.configured,
        }

    @app.get("/v1/member-release")
    def member_release(_context: AuthContext = Depends(auth.actor)) -> dict:
        from .member_release_catalog import approved_scientific_equivalence
        selected = service.member_release
        evidence = None  # Scientific equivalence remains an origin-side decision.
        return {"schema_version": 1, "runtime_version": selected.runtime_version,
            "archive_sha256": selected.archive_sha256, "base_runtime_version": selected.base_runtime_version,
            "owner_session_required": selected.owner_session_required,
            "runtime_configured": selected.configured,
            "scientific_equivalence_sha256": sha256_value(evidence) if evidence else None,
            "scientific_equivalence": evidence}

    @app.get("/v1/overview")
    @repository.read_connection_scope()
    @repository.read_metadata_cache()
    def overview(context: AuthContext = Depends(auth.actor)) -> dict:
        now = datetime.now(timezone.utc)
        settings = repository.get_feature_settings()
        is_admin = UserRole.ADMIN in context.roles
        machines = repository.list_machines()
        job_scope = job_visibility(context)
        running_jobs = repository.count_jobs(["running"], visibility=job_scope)
        queued_jobs = repository.count_jobs(["queued"], visibility=job_scope)
        # Overview needs two lifecycle counts, not one Python index DTO for
        # every Job. Authorization is applied inside each SQL aggregate.
        jobs = []
        if not is_admin and settings.visibility == FeatureVisibility.OWN_DETAIL:
            machines = [machine for machine in machines if machine.owner_user_id == context.actor_id]
        if not is_admin and (
            settings.visibility == FeatureVisibility.OWN_DETAIL
            or not settings.show_group_job_details
        ):
            jobs = [job for job in jobs if job.user_id == context.actor_id]
        repository.preload_machine_policies(machine.machine_id for machine in machines)
        policies = {policy.machine_id: policy for policy in (repository.get_policy(m.machine_id) for m in machines) if policy}
        visible_machine_ids = {machine.machine_id for machine in machines}
        execution_configs = {
            config.machine_id: config
            for config in repository.list_machine_execution_configs()
            if config.machine_id in visible_machine_ids
        }
        runtime_statuses = {
            status.machine_id: status for status in repository.list_machine_operational_statuses()
        }
        # Heartbeats are useful telemetry, but their running-unit list can be
        # briefly stale while a remote supervisor starts or reports a batch.
        # Scheduler-owned active attempts are the capacity and UI authority.
        # Capacity uses every non-terminal Attempt, while activity must only
        # count work that is actually solving. Assigned/submitting Attempts
        # may represent a remote queued/prepared standby and are not running.
        attempt_counts = repository.machine_attempt_state_counts()
        scheduled_active_units = attempt_counts["active"]
        scheduled_running_units = attempt_counts["running"]
        scheduled_assigned_units = attempt_counts["assigned"]
        scheduled_collecting_units = attempt_counts["collecting"]
        online = [
            machine for machine in machines
            if runtime_statuses.get(machine.machine_id)
            and runtime_statuses[machine.machine_id].supervisor_state == SupervisorState.ONLINE
        ]
        schedulable = [
            machine for machine in online
            if runtime_statuses[machine.machine_id].telemetry_state == TelemetryState.LIVE
            and policies.get(machine.machine_id)
            and policies[machine.machine_id].effective_mode() == MachineMode.OPEN
            and (
                execution_configs.get(machine.machine_id) is None
                or execution_configs[machine.machine_id].enabled
            )
        ]
        alerts = []
        for machine in machines:
            policy = policies.get(machine.machine_id)
            runtime = runtime_statuses.get(machine.machine_id)
            if runtime is None or runtime.heartbeat_phase.value in {"stale", "offline"}:
                alerts.append({
                    "machine_id": machine.machine_id,
                    "kind": "executor",
                    "message": runtime.supervisor_state.value if runtime else "unavailable",
                })
            if runtime is None or runtime.telemetry_state != TelemetryState.LIVE:
                alerts.append({
                    "machine_id": machine.machine_id,
                    "kind": "telemetry",
                    "message": runtime.telemetry_state.value if runtime else "unavailable",
                })
            if policy and policy.effective_mode() != MachineMode.OPEN:
                alerts.append({"machine_id": machine.machine_id, "kind": "mode", "message": policy.effective_mode().value})
            if machine.metrics.cpu_total_percent >= 90:
                alerts.append({"machine_id": machine.machine_id, "kind": "load", "message": "CPU above 90%"})
        event_scope = EventVisibility(repository, context)
        events = [event for event in repository.list_events(limit=30) if event_scope.allows(event)]
        if not is_admin and settings.visibility != FeatureVisibility.FULL:
            visible_subjects = {machine.machine_id for machine in machines}
            visible_subjects.update(job.job_id for job in jobs)
            visible_subjects.update(
                unit.work_unit_id for job in jobs for unit in job.work_units
            )
            events = [
                event for event in events
                if event.actor_id == context.actor_id
                or event.subject_id in visible_subjects
                or event.details.get("job_id") in visible_subjects
                or event.details.get("machine_id") in visible_subjects
            ]
        # The execution config is the authoritative promoted runtime.  Older
        # machine registrations may retain the enrollment-time runtime and
        # must not make Fleet display a stale version after promotion.
        machine_payloads = []
        for machine in machines:
            payload = machine.model_copy(
                update={
                    "runtime_version": (
                        execution_configs[machine.machine_id].runtime_version
                        if execution_configs.get(machine.machine_id) is not None
                        else machine.runtime_version
                    )
                }
            ).model_dump(mode="json")
            scheduled_count = scheduled_running_units.get(machine.machine_id, 0)
            telemetry_count = machine.metrics.running_units
            active_count = scheduled_active_units.get(machine.machine_id, 0)
            payload["scheduled_running_units"] = scheduled_count
            payload["scheduled_active_units"] = active_count
            payload["scheduled_assigned_units"] = scheduled_assigned_units.get(machine.machine_id, 0)
            payload["scheduled_collecting_units"] = scheduled_collecting_units.get(machine.machine_id, 0)
            payload["telemetry_running_units"] = telemetry_count
            payload["running_units_source"] = "scheduler_attempts"
            payload["running_units_mismatch"] = scheduled_count != telemetry_count
            # Keep legacy clients correct: the existing metrics field is now
            # the scheduler-authoritative count, while the raw heartbeat value
            # remains available as telemetry_running_units.
            payload["metrics"]["running_units"] = scheduled_count
            payload["metrics"]["telemetry_running_units"] = telemetry_count
            payload["metrics"]["running_units_source"] = "scheduler_attempts"
            machine_payloads.append(payload)
        # Reservations occupy a future slot even though they do not create an
        # Attempt yet.  Expose that distinction to Fleet so a prepared
        # standby is never mistaken for an idle machine or an extra slot.
        active_reservations = repository.list_dispatch_reservations(active_only=True)
        reservations_by_machine: dict[str, list] = {}
        for reservation in active_reservations:
            reservations_by_machine.setdefault(reservation.machine_id, []).append(reservation)
        capacity_by_machine = []
        for machine in machines:
            runtime = runtime_statuses.get(machine.machine_id)
            policy = policies.get(machine.machine_id)
            config = execution_configs.get(machine.machine_id)
            reasons = []
            warnings = []
            if runtime is None or runtime.heartbeat_phase.value != "healthy":
                reasons.append(f"heartbeat:{runtime.heartbeat_phase.value if runtime else 'offline'}")
            if runtime is None or runtime.heartbeat_phase.value in {"stale", "offline"}:
                reasons.append(f"telemetry:{runtime.telemetry_state.value if runtime else 'unavailable'}")
            if policy is None or policy.effective_mode() != MachineMode.OPEN:
                reasons.append(f"mode:{policy.effective_mode().value if policy else 'missing'}")
            if config is None or not config.enabled:
                reasons.append("execution:disabled")
            if runtime is not None and runtime.capacity_drift:
                warnings.append(
                    "capacity_drift:"
                    f"target={config.target_concurrent_units if config else 'missing'}:"
                    f"remote={runtime.supervisor_reported_concurrent_units}"
                )
            validated_cap = min(
                policy.max_concurrent_units if policy else 0,
                config.max_concurrent_units if config else 0,
                config.target_concurrent_units if config else 0,
            )
            effective_cap = min(
                validated_cap,
                runtime.effective_comsol_concurrency
                if runtime and runtime.effective_comsol_concurrency is not None
                else validated_cap,
                runtime.supervisor_reported_concurrent_units
                if runtime and runtime.supervisor_reported_concurrent_units is not None
                else validated_cap,
            )
            eligible_slots = effective_cap if not reasons else 0
            occupied_slots = scheduled_active_units.get(machine.machine_id, 0)
            overcommitted_slots = max(0, occupied_slots - eligible_slots)
            machine_reservations = reservations_by_machine.get(machine.machine_id, [])
            reserved_slots = len(machine_reservations)
            prepared_reservations = sum(
                reservation.state == "prepared" for reservation in machine_reservations
            )
            preparing_reservations = sum(
                reservation.state == "preparing" for reservation in machine_reservations
            )
            physical_available_slots = max(0, eligible_slots - occupied_slots)
            capacity_by_machine.append({
                "machine_id": machine.machine_id,
                "validated_slots": validated_cap,
                "supervisor_reported_slots": (
                    runtime.supervisor_reported_concurrent_units if runtime else None
                ),
                "capacity_drift": runtime.capacity_drift if runtime else False,
                "eligible_slots": eligible_slots,
                "occupied_slots": occupied_slots,
                "overcommitted_slots": overcommitted_slots,
                "physical_available_slots": physical_available_slots,
                "reserved_slots": reserved_slots,
                "prepared_reservations": prepared_reservations,
                "preparing_reservations": preparing_reservations,
                "available_slots": max(0, physical_available_slots - reserved_slots),
                "refill_ready": prepared_reservations > 0,
                "blocking_reasons": reasons,
                "warning_reasons": warnings,
                "capacity_reason": runtime.capacity_reason if runtime else "no operational status",
            })
        return present_fleet({
            "generated_at": now,
            "machines": machine_payloads,
            "policies": {machine_id: policy.model_dump(mode="json") for machine_id, policy in policies.items()},
            "operational_statuses": {
                machine_id: status.model_dump(mode="json")
                for machine_id, status in runtime_statuses.items()
                if machine_id in visible_machine_ids
            },
            "execution_configs": {
                machine_id: _public_execution_config(
                    config,
                    include_connection_details=(
                        is_admin
                        or next(
                            machine.owner_user_id
                            for machine in machines
                            if machine.machine_id == machine_id
                        ) == context.actor_id
                    ),
                )
                for machine_id, config in execution_configs.items()
            },
            "summary": {
                "online_machines": len(online),
                "offline_machines": len(machines) - len(online),
                "running_jobs": running_jobs,
                "queued_jobs": queued_jobs,
                "available_memory_mb": sum(machine.metrics.available_memory_mb for machine in schedulable),
                "available_cpus": sum(
                    min(machine.total_cpus, policies[machine.machine_id].max_cpus)
                    for machine in schedulable
                ),
                "available_gpus": sum(
                    min(machine.total_gpus, policies[machine.machine_id].max_gpus)
                    for machine in schedulable
                ),
                "validated_slots": sum(item["validated_slots"] for item in capacity_by_machine),
                "eligible_slots": sum(item["eligible_slots"] for item in capacity_by_machine),
                "occupied_slots": sum(item["occupied_slots"] for item in capacity_by_machine),
                "overcommitted_slots": sum(
                    item["overcommitted_slots"] for item in capacity_by_machine
                ),
                "physical_available_slots": sum(item["physical_available_slots"] for item in capacity_by_machine),
                "reserved_slots": sum(item["reserved_slots"] for item in capacity_by_machine),
                "prepared_reservations": sum(item["prepared_reservations"] for item in capacity_by_machine),
                "preparing_reservations": sum(item["preparing_reservations"] for item in capacity_by_machine),
            },
            "capacity": capacity_by_machine,
            "alerts": alerts,
            "recent_events": [event.model_dump(mode="json") for event in events],
            "dispatcher": _current_reconciliation_status(
                repository, repository.get_dispatcher_status().model_dump(mode="json")
            ),
            "ssh_monitor": monitor.health_snapshot() if not demo else None,
        }, repository.list_machine_credentials())

    @app.get("/v1/dispatcher/status")
    def dispatcher_status(context: AuthContext = Depends(auth.actor)) -> dict:
        status_payload = _current_reconciliation_status(
            repository, repository.get_dispatcher_status().model_dump(mode="json")
        )
        lease = repository.get_dispatcher_lease()
        status_payload["lease"] = lease.model_dump(mode="json") if lease else None
        status_payload["process"] = dispatcher_controller.snapshot()
        status_payload["startup_recovery"] = getattr(app.state, "dispatcher_recovery", {"outcome": "not_requested"})
        status_payload["startup_recovery_scope"] = "last_startup_receipt_not_live_dispatcher_status"
        return status_payload

    @app.post("/v1/dispatcher/ensure-running")
    def dispatcher_ensure_running(context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.MEMBER)
        try:
            return dispatcher_controller.ensure_running(actor_id=context.actor_id)
        except (RuntimeError, TimeoutError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/dispatcher-controls/preview")
    def dispatcher_control_preview(
        request_body: DispatcherControlPreviewRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        snapshot = dispatcher_controller.snapshot()
        try:
            return service.preview_dispatcher_control(
                request_body.action,
                fingerprint=snapshot["fingerprint"],
                impact=snapshot,
                reason=request_body.reason,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/dispatcher-controls/confirm")
    def dispatcher_control_confirm(
        request_body: DispatcherControlConfirmRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        previous = control_by_ticket(repository, request_body.ticket_id,
            actor_id=context.actor_id, confirmation_hash=request_body.confirmation_hash)
        if previous is not None:
            return refresh_control_run(previous.operation_id)
        snapshot = dispatcher_controller.snapshot()
        try:
            run = service.confirm_dispatcher_control(
                request_body.ticket_id,
                request_body.confirmation_hash,
                current_fingerprint=snapshot["fingerprint"],
                actor_id=context.actor_id,
            )
            if not claim_control_execution(repository, request_body.ticket_id):
                return refresh_control_run(run.operation_id)
            assert isinstance(run.action, DispatcherControlAction)
            result = dispatcher_controller.execute(run.action)
            return service.update_control_target(
                run.operation_id,
                ControlTargetResult(
                    machine_id="dispatcher",
                    state=ControlTargetState.COMPLETED,
                    message=f"Dispatcher {run.action.value} completed",
                ),
                actor_id=context.actor_id,
            ).model_dump(mode="json") | {"dispatcher": result}
        except (RuntimeError, TimeoutError, ValueError) as exc:
            if "run" in locals():
                service.update_control_target(
                    run.operation_id,
                    ControlTargetResult(
                        machine_id="dispatcher",
                        state=ControlTargetState.FAILED,
                        message=str(exc)[:500],
                    ),
                    actor_id=context.actor_id,
                )
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    from .cluster_insights import ClusterInsights
    insights_reader = ClusterInsights(repository)
    app.state.insights_reader = insights_reader
    app.state.insights_readiness = {"status": "pending", "window_hours": 24}

    @app.on_event("startup")
    async def prepare_insights_read_model() -> None:
        # service.initialize completed schema migration and indexed backfill
        # before this hook. ASGI readiness waits for the derived default view.
        started = time.perf_counter()
        try:
            snapshot = await asyncio.to_thread(insights_reader.prepare_default_snapshot)
        except Exception as exc:
            app.state.insights_readiness = {"status": "failed", "error_type": type(exc).__name__,
                "duration_s": time.perf_counter()-started}
            raise
        app.state.insights_readiness = {"status": "ready", "window_hours": 24,
            "duration_s": time.perf_counter()-started, "generated_at": snapshot["generated_at"],
            "source": snapshot["source"]}

    @app.on_event("shutdown")
    async def close_insights_read_model() -> None:
        await asyncio.to_thread(insights_reader.close)


    @app.get("/v1/member-release")
    def member_release(_context: AuthContext = Depends(auth.actor)) -> dict:
        from .member_release_catalog import approved_scientific_equivalence
        selected = service.member_release
        evidence = None  # Scientific equivalence remains an origin-side decision.
        return {"schema_version": 1, "runtime_version": selected.runtime_version,
            "archive_sha256": selected.archive_sha256, "base_runtime_version": selected.base_runtime_version,
            "owner_session_required": selected.owner_session_required,
            "runtime_configured": selected.configured,
            "scientific_equivalence_sha256": sha256_value(evidence) if evidence else None,
            "scientific_equivalence": evidence}

    @app.put("/v1/machines/{machine_id}/retirement-operations/{operation_uuid}")
    def request_member_retirement(machine_id: str, operation_uuid: str,
            payload: dict = Body(...), context: AuthContext = Depends(auth.actor)) -> dict:
        require_machine_owner(machine_id, context)
        if set(payload) != {"reason"} or payload["reason"] != "member_client_uninstall":
            raise HTTPException(400, "member retirement requires the fixed uninstall reason")
        try:
            receipt = service.request_member_retirement(machine_id, operation_uuid, actor_id=context.actor_id,
                reason=payload["reason"], is_admin=UserRole.ADMIN in context.roles)
            dispatcher_controller.wake(reason=f"member-retirement:{operation_uuid}")
            return receipt
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/v1/machines/{machine_id}/retirement-operations/{operation_uuid}")
    def member_retirement_status(machine_id: str, operation_uuid: str,
            context: AuthContext = Depends(auth.actor)) -> dict:
        require_machine_owner(machine_id, context)
        try:
            return service.member_retirement_status(machine_id, operation_uuid)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/machines/{machine_id}/retirement-operations/{operation_uuid}/reconcile")
    def reconcile_member_retirement(machine_id: str, operation_uuid: str,
            payload: dict = Body(default={}), context: AuthContext = Depends(auth.actor)) -> dict:
        require_machine_owner(machine_id, context)
        if payload:
            raise HTTPException(400, "retirement progress must come from the fixed authenticated transport")
        try:
            receipt = service.member_retirement_status(machine_id, operation_uuid)
            config = repository.get_machine_execution_config(machine_id)
            from .member_retirement import MemberRetirementTransport
            try:
                progress = MemberRetirementTransport(config, state_root=state.ssh).read_progress(receipt["operation_id"])
            except (OSError, RuntimeError):
                # Disconnect is not no-start evidence. Preserve every original
                # Attempt and report a resumable pending receipt.
                return {**receipt, "reason_code": "member_retirement_progress_pending"}
            result = service.reconcile_member_retirement(machine_id, operation_uuid, progress, actor_id=context.actor_id)
            dispatcher_controller.wake(reason=f"member-retirement-reconciled:{operation_uuid}")
            return result
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.put("/v1/submission-operations/{operation_uuid}")
    def put_member_submission(operation_uuid: str, payload: SubmissionOperationRequest,
                              context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.MEMBER)
        request = payload.package_manifest.request
        if request.user_id != context.actor_id:
            raise HTTPException(403, "submission package belongs to another member")
        try:
            return put_submission_operation(service, operation_uuid, payload, actor_id=context.actor_id,
                is_admin=UserRole.ADMIN in context.roles).model_dump(mode="json")
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except SubmissionOperationConflict as exc:
            raise HTTPException(409, {"reason_code": exc.reason_code, "message": str(exc)}) from exc
        except PartitionConfirmationRequired as exc:
            raise HTTPException(403 if exc.reason_code.startswith(("person_", "project_", "submission_person")) else 400, exc.detail()) from exc
        except ExecutionCompatibilityError as exc:
            raise HTTPException(403 if exc.reason_code.startswith(("person_", "project_", "submission_person")) else 400, exc.detail()) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/v1/submission-operations/{operation_uuid}")
    def get_member_submission(operation_uuid: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.MEMBER)
        try:
            op_id = operation_id(operation_uuid)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        found = repository.get_submission_operation(op_id)
        if found is None:
            raise HTTPException(404, "submission operation not found")
        if found.actor_id != context.actor_id:
            raise HTTPException(403, "submission operation belongs to another member")
        return found.model_dump(mode="json")

    @app.post("/v1/submission-operations/{operation_uuid}/confirm")
    def confirm_member_submission(operation_uuid: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.MEMBER)
        try:
            result = confirm_submission_operation(service, operation_uuid, actor_id=context.actor_id,
                is_admin=UserRole.ADMIN in context.roles)
            dispatcher_controller.wake(reason=f"member-submit:{result.job_id}")
            return result.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except SubmissionOperationConflict as exc:
            raise HTTPException(409, {"reason_code": exc.reason_code, "message": str(exc)}) from exc
        except ExecutionCompatibilityError as exc:
            raise HTTPException(403 if exc.reason_code.startswith(("person_", "project_", "submission_person")) else 400, exc.detail()) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/v1/operations/insights")
    def operations_insights(window_hours: int = Query(default=24, ge=1, le=168),
                            context: AuthContext = Depends(auth.actor)) -> dict:
        if window_hours not in {1, 6, 24, 168}:
            raise HTTPException(status_code=422, detail="window_hours must be 1, 6, 24 or 168")
        return insights_reader.snapshot(context, window_hours=window_hours)

    @app.get("/v1/operations/metrics")
    def operations_metrics(context: AuthContext = Depends(auth.actor)) -> dict:
        return repository.get_operations_metrics(visibility=job_visibility(context))

    @app.get("/v1/operations/summary")
    def global_operations_summary(context: AuthContext = Depends(auth.actor)) -> dict:
        """Global read-only operations contract without scientific payloads."""
        machines = repository.list_machines()
        statuses = repository.list_machine_operational_statuses()
        dispatcher = repository.get_dispatcher_status()
        counts = repository.get_job_activity_counts(visibility=job_visibility(context))
        phases = [status.heartbeat_phase.value for status in statuses]
        return {
            "generated_at": datetime.now(timezone.utc),
            "machines": {
                "total": len(machines),
                "healthy": phases.count("healthy"),
                "delayed": phases.count("delayed"),
                "stale": phases.count("stale"),
                "offline": max(0, len(machines) - len(phases) + phases.count("offline")),
            },
            "jobs": {
                "current": counts["current"],
                "needs_attention": counts["needs_attention"],
                "history": counts["history"],
            },
            "dispatcher": _current_reconciliation_status(repository, {
                "phase": dispatcher.phase,
                "desired_state": dispatcher.desired_state,
                "blocked_reason": dispatcher.blocked_reason,
                "pending_reconciliation": dispatcher.pending_reconciliation,
            }),
        }

    @app.get("/v1/profiles")
    def profiles(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        return [profile.model_dump(mode="json") for profile in repository.list_profiles()]

    @app.post("/v1/profiles")
    def create_profile(
        profile: ExecutionProfile,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return metadata_mutation(action, context, "profile_create", profile.profile_id,
                lambda: service.create_profile_version(
                profile,
                actor_id=context.actor_id,
            ).model_dump(mode="json"))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.put("/v1/users/{user_id}")
    def put_user(
        user_id: str,
        user: UserAccount,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if user_id != user.user_id:
            raise HTTPException(status_code=400, detail="user ID mismatch")
        return metadata_mutation(action, context, "user_update", user_id,
            lambda: service.create_user(user, actor_id=context.actor_id).model_dump(mode="json"))

    @app.get("/v1/users")
    def users(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return [user.model_dump(mode="json") for user in repository.list_users()]

    @app.post("/v1/users/{user_id}/tokens")
    def issue_token(user_id: str, request: Request,
                    options: TokenIssueOptions | None = Body(default=None),
                    context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.issue_token(user_id, actor_id=context.actor_id,
                request_id=request.headers.get("X-RCN-Request-ID"),
                agent=options.agent if options is not None else False).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail={"reason_code": "token_issuance_requires_reconciliation",
                "message": str(exc), "operation": getattr(exc, "receipt", None)}) from exc

    @app.get("/v1/admin/metadata-operations/{request_id}")
    def metadata_operation(request_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        from .mutation_receipts import mutation_receipt
        from .pressure_transactions import pressure_override_receipt
        try:
            receipt = mutation_receipt(repository, request_id, context.actor_id)
            if receipt is None:
                receipt = pressure_override_receipt(repository, request_id, context.actor_id)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        if receipt is None:
            raise HTTPException(status_code=404, detail="operation not found")
        return receipt

    @app.get("/v1/metadata-operations/{request_id}")
    def personal_metadata_operation(request_id: str, response: Response,
                                    context: AuthContext = Depends(auth.actor)) -> dict:
        response.headers["Cache-Control"] = "no-store"
        try:
            receipt = metadata_action_receipt(repository, request_id, context.actor_id)
        except MetadataActionForbidden as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except MetadataActionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if receipt is None:
            raise HTTPException(status_code=404, detail="operation not found")
        require_metadata_visibility(receipt, context)
        return receipt

    @app.post("/v1/machines/{machine_id}/agent-token")
    def issue_machine_token(machine_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.issue_machine_credential(machine_id, actor_id=context.actor_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.delete("/v1/machines/{machine_id}/agent-tokens/{credential_id}")
    def revoke_machine_token(
        machine_id: str,
        credential_id: str,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.revoke_machine_credential(
                machine_id,
                credential_id,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/v1/origin-adapters")
    def origin_adapters(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        return [
            adapter.model_dump(mode="json")
            for adapter in repository.list_origin_adapters()
            if adapter.active or UserRole.ADMIN in context.roles
        ]

    @app.put("/v1/admin/origin-adapters/{adapter_id}")
    def put_origin_adapter(
        adapter_id: str,
        adapter: OriginAdapterRegistration,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if adapter_id != adapter.adapter_id:
            raise HTTPException(status_code=400, detail="origin adapter ID mismatch")
        adapter.registered_by = context.actor_id
        repository.put_origin_adapter(adapter)
        service._event(
            "origin_adapter.updated",
            context.actor_id,
            "origin_adapter",
            adapter_id,
            active=adapter.active,
            accepts_new_submissions=adapter.accepts_new_submissions,
        )
        return adapter.model_dump(mode="json")

    @app.put("/v1/machines/{machine_id}")
    def put_machine(
        machine_id: str,
        registration: MachineRegistration,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.MACHINE_OWNER)
        if machine_id != registration.machine.machine_id:
            raise HTTPException(status_code=400, detail="machine ID mismatch")
        if repository.get_machine(machine_id) is not None:
            require_machine_owner(machine_id, context)
        if UserRole.ADMIN not in context.roles and context.actor_id != registration.machine.owner_user_id:
            raise HTTPException(status_code=403, detail="machine owner mismatch")
        if UserRole.ADMIN not in context.roles and registration.policy.admin_mode_override is not None:
            raise HTTPException(status_code=403, detail="only an administrator can set an admin override")
        try:
            machine = service.register_machine(
                registration.machine,
                registration.policy,
                actor_id=context.actor_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return machine.model_dump(mode="json")

    @app.post("/v1/admin/machines/{machine_id}/pressure-override/preview")
    def pressure_override_preview(
        machine_id: str,
        request_body: PressureOverridePreviewRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.preview_pressure_override(
                machine_id,
                reason=request_body.reason,
                ttl_minutes=request_body.ttl_minutes,
                requested_concurrent_units=request_body.requested_concurrent_units,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/machines/{machine_id}/pressure-override/confirm")
    def pressure_override_confirm(
        machine_id: str,
        request_body: PressureOverrideConfirmRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.confirm_pressure_override(
                machine_id,
                ticket_id=request_body.ticket_id,
                confirmation_hash=request_body.confirmation_hash,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/machine-controls/preview")
    def machine_control_preview(
        request_body: MachineControlPreviewRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.preview_machine_control(
                request_body.action,
                request_body.targets,
                reason=request_body.reason,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ExecutionCompatibilityError as exc:
            raise HTTPException(status_code=409, detail=exc.detail()) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/users/{user_id}/tokens")
    def user_tokens(user_id: str, context: AuthContext = Depends(auth.actor)) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return [token.model_dump(mode="json") for token in repository.list_tokens(user_id)]

    @app.delete("/v1/users/{user_id}/tokens/{token_id}")
    def revoke_user_token(
        user_id: str,
        token_id: str,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        token = repository.get_token(token_id)
        if token is None or token.user_id != user_id:
            raise HTTPException(status_code=404, detail="API token not found")
        return metadata_mutation(action, context, "user_token_revoke", user_id,
            lambda: service.revoke_token(token_id, actor_id=context.actor_id).model_dump(
                mode="json", exclude={"token_hash"}))

    @app.post("/v1/admin/machine-controls/confirm")
    def machine_control_confirm(
        request_body: MachineControlConfirmRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            previous = control_by_ticket(repository, request_body.ticket_id,
                actor_id=context.actor_id, confirmation_hash=request_body.confirmation_hash)
            if previous is not None:
                return refresh_control_run(previous.operation_id)
            run, commands = service.confirm_machine_control(
                request_body.ticket_id,
                request_body.confirmation_hash,
                actor_id=context.actor_id,
                break_glass_pin=request_body.break_glass_pin,
                typed_machine_id=request_body.typed_machine_id,
                process_set_hash=request_body.process_set_hash,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if not commands:
            return refresh_control_run(run.operation_id)
        if not any(command.action in IMMEDIATE_MACHINE_ACTIONS for command in commands):
            return recover_control_delivery(service, run.operation_id, transport_for=machine_transport,
                                             actor_id=context.actor_id).model_dump(mode="json")
        if not claim_control_execution(repository, request_body.ticket_id):
            return refresh_control_run(run.operation_id)
        for command in commands:
            try:
                if command.action in {
                    MachineControlAction.RESTART_SUPERVISOR,
                    MachineControlAction.FORCE_RESTART_SUPERVISOR,
                }:
                    # Restart is the recovery path for a supervisor that is
                    # stale or has exited. It cannot be sent through the
                    # supervisor inbox because that process is precisely what
                    # is unavailable. The harness performs exact PID/command
                    # identity checks and starts only the sealed configured
                    # runtime; it never touches COMSOL process trees.
                    result = ssh_harness(command.machine_id).restart_supervisor(
                        actor_id=context.actor_id,
                    )
                    reported_runtime = str(
                        result.get("supervisor", {}).get("runtime_version") or ""
                    )
                    # Runtime attestation is meaningful only for the sealed
                    # release.  Legacy control-plane fixtures may report
                    # their configured test runtime; keep the restart result
                    # observable without weakening the sealed-runtime gate.
                    if service.runtime_policy.accepts_worker_runtime(reported_runtime):
                        service.record_runtime_attestation(
                            command.machine_id,
                            reported_runtime,
                            actor_id=f"{context.actor_id}:runtime-attestation",
                        )
                    run = service.update_control_target(
                        run.operation_id,
                        ControlTargetResult(
                            machine_id=command.machine_id,
                            state=ControlTargetState.COMPLETED,
                            message=(
                                "supervisor restarted with sealed runtime "
                                f"{reported_runtime or command.runtime_version}"
                            ),
                            command_id=command.command_id,
                        ),
                        actor_id=context.actor_id,
                    )
                else:
                    machine_transport(command.machine_id).submit_machine_command(
                        command.model_dump(mode="json")
                    )
                    run = service.update_control_target(
                        run.operation_id,
                        ControlTargetResult(
                            machine_id=command.machine_id,
                            state=ControlTargetState.ACKNOWLEDGED,
                            message="remote supervisor accepted the command file",
                            command_id=command.command_id,
                        ),
                        actor_id=context.actor_id,
                    )
            except (OSError, RuntimeError, ValueError) as exc:
                run = service.update_control_target(
                    run.operation_id,
                    ControlTargetResult(
                        machine_id=command.machine_id,
                        state=ControlTargetState.FAILED,
                        message="reconciliation_required: immediate control outcome could not be confirmed",
                        command_id=command.command_id,
                    ),
                    actor_id=context.actor_id,
                )
        return run.model_dump(mode="json")

    @app.post("/v1/admin/machines/{machine_id}/runtime-controls/preview")
    def runtime_control_preview(
        machine_id: str,
        request_body: RuntimeControlPreviewRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            snapshot = ssh_harness(machine_id).runtime_control_snapshot(request_body.action)
            return service.preview_runtime_control(
                MachineControlAction(request_body.action),
                machine_id,
                runtime_snapshot=snapshot,
                reason=request_body.reason,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (OSError, RuntimeError, ValueError, TimeoutError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/machines/{machine_id}/runtime-controls/confirm")
    def runtime_control_confirm(
        machine_id: str,
        request_body: RuntimeControlConfirmRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        previous = control_by_ticket(repository, request_body.ticket_id,
            actor_id=context.actor_id, confirmation_hash=request_body.confirmation_hash)
        if previous is not None:
            return refresh_control_run(previous.operation_id)
        ticket = repository.get_machine_control_ticket(request_body.ticket_id)
        if ticket is None or len(ticket.targets) != 1 or ticket.targets[0].machine_id != machine_id:
            raise HTTPException(status_code=404, detail="runtime control preview not found")
        harness = ssh_harness(machine_id)
        try:
            snapshot = harness.runtime_control_snapshot(ticket.action.value)
            target_runtime = str(ticket.impact[machine_id].get("target_runtime_version") or "")
            run = service.confirm_runtime_control(
                request_body.ticket_id,
                request_body.confirmation_hash,
                runtime_snapshot=snapshot,
                actor_id=context.actor_id,
            )
            if not claim_control_execution(repository, request_body.ticket_id):
                return refresh_control_run(run.operation_id)
            if ticket.action == MachineControlAction.PROMOTE_RUNTIME:
                result = harness.promote_running_runtime(actor_id=context.actor_id)
            else:
                result = harness.rollback_running_runtime(target_runtime, actor_id=context.actor_id)
            run = service.update_control_target(
                run.operation_id,
                ControlTargetResult(
                    machine_id=machine_id,
                    state=ControlTargetState.COMPLETED,
                    message=(
                        f"runtime {result.get('runtime_version')} is active and persisted"
                    ),
                ),
                actor_id=context.actor_id,
            )
        except (OSError, RuntimeError, ValueError, TimeoutError) as exc:
            if 'run' not in locals():
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            run = service.update_control_target(
                run.operation_id,
                ControlTargetResult(
                    machine_id=machine_id,
                    state=ControlTargetState.FAILED,
                    message=str(exc)[:500],
                ),
                actor_id=context.actor_id,
            )
        return run.model_dump(mode="json")

    @app.get("/v1/admin/control-runs")
    def control_runs(
        limit: int = Query(default=100, ge=1, le=500),
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return [
            run.model_dump(mode="json")
            for run in repository.list_control_operation_runs(limit=limit)
        ]

    @app.get("/v1/machines/{machine_id}/detail")
    def machine_detail(
        machine_id: str,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        machine = require_machine_detail_visibility(machine_id, context)
        policy_revision = repository.get_policy_revision(machine_id)
        config = repository.get_machine_execution_config(machine_id)
        status = repository.get_machine_operational_status(machine_id)
        jobs = repository.list_job_index(machine_id=machine_id, limit=100, visibility=job_visibility(context))
        events = repository.list_events(limit=100, subject_type="machine", subject_id=machine_id)
        machine_view = machine.model_copy(
            update={"runtime_version": config.runtime_version if config else machine.runtime_version}
        )
        return {
            "machine": machine_view.model_dump(mode="json"),
            "policy": policy_revision["policy"] if policy_revision else None,
            "policy_revision_hash": policy_revision["revision_hash"] if policy_revision else None,
            "operational_status": status.model_dump(mode="json") if status else None,
            "execution_config": _public_execution_config(
                config,
                include_connection_details=(
                    UserRole.ADMIN in context.roles or machine.owner_user_id == context.actor_id
                ),
            ) if config else None,
            "jobs": jobs,
            "events": [event.model_dump(mode="json") for event in events if EventVisibility(repository, context).allows(event)],
            "alerts": [
                alert.model_dump(mode="json")
                for alert in repository.list_alerts(include_resolved=True)
                if alert.subject_type == "machine" and alert.subject_id == machine_id
            ],
        }

    @app.get("/v1/admin/control-runs/by-ticket/{ticket_id}")
    def control_run_by_ticket(ticket_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        run = control_by_ticket(repository, ticket_id)
        if run is None:
            raise HTTPException(404, "control confirmation has not been accepted")
        return refresh_control_run(run.operation_id)

    @app.get("/v1/admin/control-runs/{operation_id}")
    def control_run(
        operation_id: str,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return refresh_control_run(operation_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.put("/v1/admin/break-glass/pin")
    def set_break_glass_pin(
        request_body: BreakGlassPinRequest,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        def mutate():
            config = service.set_break_glass_pin(request_body.pin, actor_id=context.actor_id)
            return {"configured": config.active, "updated_at": config.updated_at}
        try:
            return metadata_mutation(action, context, "break_glass_pin", "global", mutate, sensitive=True)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/admin/break-glass")
    def break_glass_status(context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        config = repository.get_break_glass_config()
        return {
            "configured": bool(config and config.active),
            "updated_at": config.updated_at if config else None,
        }

    @app.post("/v1/admin/operations/preview")
    def admin_operation_preview(
        request_body: AdminOperationPreviewRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.preview_admin_operation(
                request_body.action,
                job_id=request_body.job_id,
                work_unit_id=request_body.work_unit_id,
                reason=request_body.reason,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/operations/confirm")
    def admin_operation_confirm(
        request_body: AdminOperationConfirmRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            result = service.confirm_admin_operation(
                ticket_id=request_body.ticket_id,
                confirmation_hash=request_body.confirmation_hash,
                actor_id=context.actor_id,
            )
            dispatcher_controller.wake(reason=f"admin-operation:{request_body.ticket_id}")
            return {"accepted": True, "job": result.model_dump(mode="json")}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/machines/{machine_id}/mode")
    def set_machine_mode(
        machine_id: str,
        request: MachineModeRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_machine_owner(machine_id, context)
        try:
            return service.set_machine_mode(
                machine_id,
                request.mode,
                actor_id=context.actor_id,
                reason=request.reason,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ExecutionCompatibilityError as exc:
            raise HTTPException(status_code=409, detail=exc.detail()) from exc

    @app.get("/v1/machines/{machine_id}/policy-revision")
    def machine_policy_revision(machine_id: str, response: Response,
                                context: AuthContext = Depends(auth.actor)) -> dict:
        require_machine_owner(machine_id, context)
        response.headers["Cache-Control"] = "no-store"
        revision = repository.get_policy_revision(machine_id)
        if revision is None:
            raise HTTPException(status_code=404, detail="machine policy not found")
        return revision

    @app.put("/v1/machines/{machine_id}/retirement-operations/{operation_uuid}")
    def request_member_retirement(machine_id: str, operation_uuid: str,
            payload: dict = Body(...), context: AuthContext = Depends(auth.actor)) -> dict:
        require_machine_owner(machine_id, context)
        if set(payload) != {"reason"} or payload["reason"] != "member_client_uninstall":
            raise HTTPException(400, "member retirement requires the fixed uninstall reason")
        try:
            receipt = service.request_member_retirement(machine_id, operation_uuid, actor_id=context.actor_id,
                reason=payload["reason"], is_admin=UserRole.ADMIN in context.roles)
            dispatcher_controller.wake(reason=f"member-retirement:{operation_uuid}")
            return receipt
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/v1/machines/{machine_id}/retirement-operations/{operation_uuid}")
    def member_retirement_status(machine_id: str, operation_uuid: str,
            context: AuthContext = Depends(auth.actor)) -> dict:
        require_machine_owner(machine_id, context)
        try:
            return service.member_retirement_status(machine_id, operation_uuid)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/v1/machines/{machine_id}/retirement-operations/{operation_uuid}/reconcile")
    def reconcile_member_retirement(machine_id: str, operation_uuid: str,
            payload: dict = Body(default={}), context: AuthContext = Depends(auth.actor)) -> dict:
        require_machine_owner(machine_id, context)
        if payload:
            raise HTTPException(400, "retirement progress must come from the fixed authenticated transport")
        try:
            receipt = service.member_retirement_status(machine_id, operation_uuid)
            config = repository.get_machine_execution_config(machine_id)
            from .member_retirement import MemberRetirementTransport
            try:
                progress = MemberRetirementTransport(config, state_root=state.ssh).read_progress(receipt["operation_id"])
            except (OSError, RuntimeError):
                # Disconnect is not no-start evidence. Preserve every original
                # Attempt and report a resumable pending receipt.
                return {**receipt, "reason_code": "member_retirement_progress_pending"}
            result = service.reconcile_member_retirement(machine_id, operation_uuid, progress, actor_id=context.actor_id)
            dispatcher_controller.wake(reason=f"member-retirement-reconciled:{operation_uuid}")
            return result
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.put("/v1/machines/{machine_id}/policy")
    def put_policy(
        machine_id: str,
        policy: MachinePolicy,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_machine_owner(machine_id, context)
        if machine_id != policy.machine_id:
            raise HTTPException(status_code=400, detail="machine ID mismatch")
        if UserRole.ADMIN not in context.roles and context.actor_id != policy.owner_user_id:
            raise HTTPException(status_code=403, detail="machine owner mismatch")
        def mutate():
            raw_body = action[1]["body"]
            expected = raw_body.get("expected_policy_payload_sha256")
            if "expected_policy_payload_sha256" in raw_body and (
                    not isinstance(expected, str) or len(expected) != 64
                    or any(char not in "0123456789abcdef" for char in expected)):
                raise PolicyRevisionConflict("machine policy revision must be a lowercase SHA256")
            return service.update_policy(policy, actor_id=context.actor_id,
                admin_override_authorized=UserRole.ADMIN in context.roles,
                expected_policy_payload_sha256=expected).model_dump(mode="json")
        try:
            return metadata_mutation(action, context, "machine_policy", machine_id, mutate)
        except PolicyRevisionConflict as exc:
            raise HTTPException(status_code=409, detail={
                "reason_code": "machine_policy_revision_conflict", "message": str(exc)}) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/approvals")
    def approve(
        approval: ApprovalRecord,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.MACHINE_OWNER)
        machine = repository.get_machine(approval.machine_id)
        if machine is not None and UserRole.ADMIN not in context.roles and context.actor_id != machine.owner_user_id:
            raise HTTPException(status_code=403, detail="machine owner mismatch")
        if UserRole.ADMIN not in context.roles and approval.approved_by != context.actor_id:
            raise HTTPException(status_code=403, detail="approval signer does not match token owner")
        try:
            return service.approve(approval, actor_id=context.actor_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/solver-approvals")
    def approve_solver(
        approval: SolverCompatibilityApproval,
        request: Request,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if approval.approved_by != context.actor_id:
            raise HTTPException(status_code=403, detail="approval signer does not match token owner")
        try:
            return service.approve_solver(approval, actor_id=context.actor_id,
                request_id=request.headers.get("X-RCN-Request-ID")).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/solver-approvals")
    def solver_approvals(
        project_id: str | None = None,
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return [
            approval.model_dump(mode="json")
            for approval in repository.list_solver_approvals(project_id=project_id)
        ]

    @app.get("/v1/admin/template-environments")
    def template_environments(
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        """Return approved generic Study environments and observed immutable provenance."""
        require_role(context, UserRole.ADMIN)
        # This inventory only compares immutable template/study provenance.
        # Keep scientific item payloads out of an administrator list view.
        jobs = repository.list_operational_jobs(limit=1000)
        result = []
        for approval in repository.list_solver_approvals():
            if approval.execution_profile_id not in {"workbench-comsol-study-v1", "workbench-comsol-study-v2"}:
                continue
            matching = [
                job for job in jobs
                if job.project_id == approval.project_id
                and job.execution_profile_id == approval.execution_profile_id
                and job.template_role == approval.template_role
            ]
            result.append({
                "approval": approval.model_dump(mode="json"),
                "observed_template_hashes": sorted({
                    job.template_sha256 for job in matching if job.template_sha256
                }),
                "observed_study_kinds": sorted({
                    job.study_kind.value for job in matching if job.study_kind
                }),
                "output_contracts": sorted({
                    job.output_contract_sha256
                    for job in matching if job.output_contract_sha256
                }),
                "recent_jobs": [
                    {
                        "job_id": job.job_id,
                        "study_kind": job.study_kind.value if job.study_kind else None,
                        "template_sha256": job.template_sha256,
                        "output_contract_sha256": job.output_contract_sha256,
                        "warnings": job.planning_warnings,
                        "created_at": job.created_at,
                    }
                    for job in sorted(matching, key=lambda value: value.created_at, reverse=True)[:10]
                ],
            })
        return result

    @app.delete("/v1/solver-approvals/{approval_id}")
    def revoke_solver_approval(
        approval_id: str,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        def mutate():
            approval = repository.get_solver_approval(approval_id)
            if approval is None:
                raise HTTPException(status_code=404, detail="solver approval not found")
            if approval.active:
                approval.active = False
                repository.put_solver_approval(approval)
                service._event(
                    "solver_approval.revoked", context.actor_id, "solver_approval",
                    approval_id, project_id=approval.project_id,
                )
            return approval.model_dump(mode="json")
        return metadata_mutation(action, context, "solver_approval_revoke", approval_id, mutate)

    @app.put("/v1/submission-operations/{operation_uuid}")
    def put_member_submission(operation_uuid: str, payload: SubmissionOperationRequest,
                              context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.MEMBER)
        request = payload.package_manifest.request
        if request.user_id != context.actor_id:
            raise HTTPException(403, "submission package belongs to another member")
        try:
            return put_submission_operation(service, operation_uuid, payload, actor_id=context.actor_id,
                is_admin=UserRole.ADMIN in context.roles).model_dump(mode="json")
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except SubmissionOperationConflict as exc:
            raise HTTPException(409, {"reason_code": exc.reason_code, "message": str(exc)}) from exc
        except PartitionConfirmationRequired as exc:
            raise HTTPException(400, exc.detail()) from exc
        except ExecutionCompatibilityError as exc:
            raise HTTPException(400, exc.detail()) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/v1/submission-operations/{operation_uuid}")
    def get_member_submission(operation_uuid: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.MEMBER)
        try:
            op_id = operation_id(operation_uuid)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        found = repository.get_submission_operation(op_id)
        if found is None:
            raise HTTPException(404, "submission operation not found")
        if found.actor_id != context.actor_id:
            raise HTTPException(403, "submission operation belongs to another member")
        return found.model_dump(mode="json")

    @app.post("/v1/submission-operations/{operation_uuid}/confirm")
    def confirm_member_submission(operation_uuid: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.MEMBER)
        try:
            result = confirm_submission_operation(service, operation_uuid, actor_id=context.actor_id,
                is_admin=UserRole.ADMIN in context.roles)
            dispatcher_controller.wake(reason=f"member-submit:{result.job_id}")
            return result.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except SubmissionOperationConflict as exc:
            raise HTTPException(409, {"reason_code": exc.reason_code, "message": str(exc)}) from exc
        except ExecutionCompatibilityError as exc:
            raise HTTPException(400, exc.detail()) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/v1/partition-plans")
    def plan_partition(
        request: PartitionRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.MEMBER)
        if UserRole.ADMIN not in context.roles and request.user_id != context.actor_id:
            service.record_project_access_denied(
                request.project_id,
                actor_id=context.actor_id,
                requested_user_id=request.user_id,
                reason="partition request user does not match token owner",
            )
            raise HTTPException(status_code=403, detail="partition request user does not match token owner")
        require_project_access(request.project_id, context, allow_auto_registration=True)
        try:
            return service.plan_partition(request, actor_id=context.actor_id).model_dump(mode="json")
        except PartitionConfirmationRequired as exc:
            raise HTTPException(status_code=400, detail=exc.detail()) from exc
        except ExecutionCompatibilityError as exc:
            raise HTTPException(status_code=400, detail=exc.detail()) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/partition-plans/{plan_id}")
    def partition_plan(plan_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        found = repository.get_partition_plan(plan_id)
        if found is None:
            raise HTTPException(status_code=404, detail="partition plan not found")
        require_project_access(found.request.project_id, context)
        return found.model_dump(mode="json")

    @app.post("/v1/partition-plans/{plan_id}/confirm")
    def confirm_partition(plan_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        found = repository.get_partition_plan(plan_id)
        if found is None:
            raise HTTPException(status_code=404, detail="partition plan not found")
        if UserRole.ADMIN not in context.roles and found.request.user_id != context.actor_id:
            service.record_project_access_denied(
                found.request.project_id,
                actor_id=context.actor_id,
                requested_user_id=found.request.user_id,
                reason="partition plan is owned by another user",
            )
            raise HTTPException(status_code=403, detail="partition plan is owned by another user")
        require_project_access(found.request.project_id, context)
        try:
            return service.confirm_partition(plan_id, actor_id=context.actor_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except RevisionConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason_code": "job_revision_conflict",
                    "message": "the Job changed while confirmation was being persisted",
                    "next_action": "refresh the plan and retry confirmation",
                },
            ) from exc
        except ExecutionCompatibilityError as exc:
            raise HTTPException(status_code=400, detail=exc.detail()) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/jobs")
    def submit(job: JobEnvelope, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.MEMBER)
        if UserRole.ADMIN not in context.roles and context.actor_id != job.user_id:
            service.record_project_access_denied(
                job.project_id,
                actor_id=context.actor_id,
                requested_user_id=job.user_id,
                reason="job user does not match token owner",
            )
            raise HTTPException(status_code=403, detail="job user does not match token owner")
        require_project_access(job.project_id, context, allow_auto_registration=True)
        try:
            submitted = service.submit(job, actor_id=context.actor_id)
            dispatcher_controller.wake(reason=f"job-submit:{submitted.job_id}")
            return submitted.model_dump(mode="json")
        except ExecutionCompatibilityError as exc:
            raise HTTPException(status_code=400, detail=exc.detail()) from exc
        except RevisionConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason_code": "job_revision_conflict",
                    "message": "the Job changed while submission was being persisted",
                    "next_action": "refresh the Job state and retry submission",
                },
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/projects/{project_id}/execution-compatibility")
    def execution_compatibility(
        project_id: str,
        payload: dict = Body(...),
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.MEMBER)
        require_project_access(project_id, context)
        try:
            request = PartitionRequest.model_validate(payload)
        except ValidationError as exc:
            raise HTTPException(
                status_code=400,
                detail={"reason_code": "invalid_request_contract", "message": str(exc)},
            ) from exc
        if request.project_id != project_id:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason_code": "project_id_mismatch",
                    "message": "request project_id must match the project-scoped endpoint",
                },
            )
        if UserRole.ADMIN not in context.roles and request.user_id != context.actor_id:
            raise HTTPException(status_code=403, detail="partition request user does not match token owner")
        try:
            return service.execution_compatibility(request)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail={"reason_code": "invalid_scientific_contract", "message": str(exc)},
            ) from exc

    @app.get("/v1/jobs")
    @repository.read_connection_scope()
    @repository.read_metadata_cache()
    def jobs(
        status: list[str] | None = Query(default=None),
        project_id: str | None = None,
        machine_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        view: Literal["full", "summary", "compact"] = Query(default="compact"),
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        from .models import JobStatus

        if project_id is not None:
            require_project_access(project_id, context)
        try:
            statuses = [JobStatus(item) for item in status] if status else None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"invalid job status: {exc}") from exc
        user_id = None
        if view in {"summary", "compact"}:
            summaries = repository.list_job_summaries(
                statuses,
                user_id=user_id,
                project_id=project_id,
                machine_id=machine_id,
                limit=limit,
                offset=offset,
                visibility=job_visibility(context),
                compact=view == "compact",
            )
            environment_cache: dict[tuple, dict] = {}
            def current_inspection_needed(summary):
                return not (view == "compact" and summary.get("activity_state") == "history"
                    and summary.get("current_execution_required") is False)

            current_projects = {
                str(summary.get("project_id") or "") for summary in summaries
                if current_inspection_needed(summary)
            }
            concurrency_cache = service.project_concurrency_snapshots(current_projects) if current_projects else {}
            # Summaries arrive newest-first; the most recent N history jobs
            # keep their embedded unit details for the runs board.
            history_embed_budget = COMPACT_HISTORY_EMBED_LIMIT
            def trim_history_units(summary):
                nonlocal history_embed_budget
                if view == "compact" and summary.get("activity_state") == "history":
                    if history_embed_budget > 0:
                        history_embed_budget -= 1
                        summary["history_units_embedded"] = True
                    else:
                        summary["work_units"] = []
                        summary["history_units_embedded"] = False

            for summary in summaries:
                if not current_inspection_needed(summary):
                    # A completed execution's historical evidence does not
                    # depend on today's Fleet. Inspect current placement only
                    # when a detail/explicit diagnostic actually requests it.
                    summary["execution_environment"] = None
                    summary["execution_environment_state"] = "not_requested"
                    summary["project_concurrency"] = None
                    summary["project_concurrency_state"] = "not_requested"
                    trim_history_units(summary)
                    continue
                environment_key = (
                    summary.get("project_id"),
                    summary.get("user_id"),
                    summary.get("execution_profile_id"),
                    summary.get("solver_approval_id"),
                    summary.get("solver_compatibility_fingerprint"),
                    summary.get("template_sha256"),
                    summary.get("template_role"),
                    summary.get("study_kind"),
                    tuple(sorted({
                        capability
                        for unit in summary.get("work_units", [])
                        for capability in unit.get("required_capabilities", [])
                    })),
                    tuple(sorted({
                        variant
                        for unit in summary.get("work_units", [])
                        for variant in unit.get("allowed_solver_variants", [])
                    })),
                )
                environment = environment_cache.get(environment_key)
                if environment is None:
                    environment = service.job_summary_environment(summary)
                    environment_cache[environment_key] = environment
                summary["execution_environment"] = environment
                if view == "compact":
                    summary["execution_environment_state"] = "current"
                summary_project_id = str(summary.get("project_id") or "")
                concurrency = concurrency_cache[summary_project_id]
                summary["project_concurrency"] = concurrency
                if view == "compact":
                    summary["project_concurrency_state"] = "current"
                if environment.get("status") != "executable":
                    reasons = list(summary.get("blocking_reasons") or [])
                    reasons.extend(
                        f"执行环境：{reason}"
                        for reason in environment.get("reason_codes") or []
                    )
                    summary["blocking_reasons"] = list(dict.fromkeys(reasons))
                    if reasons:
                        summary["last_transition_reason"] = reasons[0]
                if (
                    concurrency.get("max_running_units") is not None
                    and int(concurrency.get("used_units") or 0)
                    >= int(concurrency["max_running_units"])
                    and any(
                        unit.get("status") == "queued"
                        for unit in summary.get("work_units", [])
                    )
                ):
                    prepared_units = int(concurrency.get("prepared_units") or 0)
                    standby_note = (
                        f"（另有 {prepared_units} 个预热备胎，不占额度）"
                        if prepared_units > 0
                        else ""
                    )
                    reason = (
                        "项目并发 "
                        f"{concurrency.get('active_units', 0)}/{concurrency['max_running_units']} 已满"
                        f"{standby_note}，其余单元等槽释放"
                    )
                    reasons = list(summary.get("blocking_reasons") or [])
                    if reason not in reasons:
                        reasons.append(reason)
                    summary["blocking_reasons"] = reasons
                    summary["last_transition_reason"] = reason
                trim_history_units(summary)
            return Response(content=to_json(summaries), media_type="application/json")
        visible_project_ids = {
            grant.project_id for grant in repository.list_project_grants()
            if grant.authorizes(context.actor_id)
        }
        owned_machine_ids = {
            machine.machine_id for machine in repository.list_machines()
            if machine.owner_user_id == context.actor_id
        }
        # A current declarative Job can expand to tens of megabytes. Bulk
        # hydration is neither a list operation nor a stable compatibility
        # surface; callers enumerate compact records and fetch one full Job by
        # ID when they actually need its scientific payload.
        if limit != 1:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason_code": "bulk_full_job_payload_forbidden",
                    "message": "full Job payload listing requires limit=1",
                    "next_action": (
                        "list compact Jobs, then GET /v1/jobs/{job_id} for one complete contract"
                    ),
                },
            )
        found = repository.list_jobs(
            statuses,
            visibility=job_visibility(context),
            user_id=user_id,
            project_id=project_id,
            machine_id=machine_id,
            limit=limit if UserRole.ADMIN in context.roles or project_id is not None else None,
            offset=offset if UserRole.ADMIN in context.roles or project_id is not None else 0,
        )
        if UserRole.ADMIN not in context.roles and project_id is None:
            found = [
                job for job in found
                if job.project_id in visible_project_ids
                or any(unit.assigned_machine_id in owned_machine_ids for unit in job.work_units)
            ][offset:offset + limit]
        return [job.model_dump(mode="json") for job in found]

    @app.put("/v1/jobs/{job_id}/placement")
    def job_placement(
        job_id: str,
        placement: PlacementConstraint,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        found = operational_job_or_404(job_id)
        is_admin = UserRole.ADMIN in context.roles
        require_job_owner(found, context)
        try:
            return service.set_job_placement(
                job_id,
                placement,
                actor_id=context.actor_id,
                allow_required=is_admin,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.put("/v1/admin/jobs/{job_id}/unstarted-solver-contract")
    def unstarted_solver_contract(
        job_id: str,
        request_body: UnstartedSolverContractRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            updated = service.migrate_unstarted_solver_contract(
                job_id,
                approval_id=request_body.approval_id,
                solver_variants=request_body.solver_variants,
                expected_revision=request_body.expected_revision,
                reason=request_body.reason,
                actor_id=context.actor_id,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except RevisionConflictError as exc:
            raise HTTPException(status_code=409, detail={
                "reason_code": "job_revision_conflict",
                "message": str(exc),
                "next_action": "refresh the Job; do not replay against a changed revision",
            }) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        dispatcher_controller.wake(reason=f"unstarted-solver-contract:{job_id}")
        return job_summary(updated)

    @app.get("/v1/jobs/{job_id}/contract")
    def job_contract(job_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        found = repository.get_job(job_id)
        if found is None:
            raise HTTPException(status_code=404, detail="job not found")
        require_job_owner(found, context)
        return found.model_dump(mode="json")

    @app.get("/v1/jobs/{job_id}")
    def job(
        job_id: str,
        view: Literal["full", "operational", "storage"] = Query(default="full"),
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        found = (
            repository.get_job(job_id)
            if view == "full"
            else repository.get_operational_job(job_id)
        )
        if found is None:
            raise HTTPException(status_code=404, detail="job not found")
        require_job_access(found, context)
        if view == "storage":
            # Custody/retirement needs fresh producer and Attempt identities,
            # not an ETA built from fleet-wide completion history on each read.
            payload = found.model_dump(mode="json")
            payload["detail_view"] = "storage"
            return payload
        detail = repository.get_job_operational_detail(job_id, job=found)
        if detail is None:
            return found.model_dump(mode="json")
        detail["detail_view"] = view
        return detail

    @app.get("/v1/jobs/{job_id}/execution-conditions")
    @repository.read_metadata_cache()
    def job_execution_conditions(job_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        found = operational_job_or_404(job_id)
        require_job_access(found, context)
        summary = repository.get_job_execution_summary(job_id)
        if summary is None:
            raise HTTPException(status_code=404, detail="job not found")
        return {"job_id": job_id, "generated_at": datetime.now(timezone.utc).isoformat(),
            "execution_environment": service.job_summary_environment(summary),
            "project_concurrency": service.project_concurrency_snapshot(found.project_id)}

    @app.get("/v1/jobs/{job_id}/events")
    def job_events(
        job_id: str,
        limit: int = Query(default=500, ge=1, le=1000),
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        found = operational_job_or_404(job_id)
        require_job_access(found, context)
        return [
            event.model_dump(mode="json")
            for event in repository.list_job_events(found, limit=limit)
        ]

    @app.get("/v1/jobs/{job_id}/placement-diagnostics")
    def job_placement_diagnostics(
        job_id: str,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        found = operational_job_or_404(job_id)
        require_job_access(found, context)
        return service.placement_diagnostics(job_id)

    @app.post("/v1/jobs/{job_id}/cancel")
    def cancel(
        job_id: str,
        request: CancelRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        found = repository.get_operational_job(job_id)
        if found is not None:
            require_job_owner(found, context)
        try:
            return service.cancel(job_id, actor_id=context.actor_id, reason=request.reason).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/jobs/{job_id}/retry")
    def retry(job_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        found = repository.get_operational_job(job_id)
        if found is not None:
            require_job_owner(found, context)
        try:
            return service.retry(job_id, actor_id=context.actor_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/jobs/{job_id}/attempts")
    def job_attempts(job_id: str, context: AuthContext = Depends(auth.actor)) -> list[dict]:
        found = operational_job_or_404(job_id)
        require_job_access(found, context)
        return [
            {
                "job_id": found.job_id,
                "work_unit_id": unit.work_unit_id,
                "attempts": [attempt.model_dump(mode="json") for attempt in unit.attempts],
            }
            for unit in found.work_units
        ]

    @app.get("/v1/jobs/{job_id}/units/{work_unit_id}/attempts")
    def unit_attempts(job_id: str, work_unit_id: str, context: AuthContext = Depends(auth.actor)) -> list[dict]:
        found = operational_job_or_404(job_id)
        require_job_access(found, context)
        unit = next((candidate for candidate in found.work_units if candidate.work_unit_id == work_unit_id), None)
        if unit is None:
            raise HTTPException(status_code=404, detail="work unit not found")
        return [attempt.model_dump(mode="json") for attempt in unit.attempts]

    def require_job_or_unit_owner(job_id: str, work_unit_id: str, context: AuthContext) -> None:
        found = operational_job_or_404(job_id)
        if UserRole.ADMIN in context.roles or found.user_id == context.actor_id:
            return
        unit = next((candidate for candidate in found.work_units if candidate.work_unit_id == work_unit_id), None)
        if unit is None:
            raise HTTPException(status_code=404, detail="work unit not found")
        machine = repository.get_machine(unit.assigned_machine_id) if unit.assigned_machine_id else None
        if machine is None or machine.owner_user_id != context.actor_id:
            raise HTTPException(status_code=403, detail="work unit is owned by another project or machine")

    @app.post("/v1/jobs/{job_id}/units/{work_unit_id}/cancel")
    def cancel_unit(
        job_id: str,
        work_unit_id: str,
        request: CancelRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_job_or_unit_owner(job_id, work_unit_id, context)
        try:
            return service.cancel_unit(
                job_id,
                work_unit_id,
                actor_id=context.actor_id,
                reason=request.reason,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/admin/jobs/{job_id}/units/{work_unit_id}/abandon-and-retry")
    def abandon_and_retry_unit(
        job_id: str,
        work_unit_id: str,
        request: AttemptAbandonmentRequest,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        def mutate():
            result = service.abandon_and_retry_unit(
                job_id, work_unit_id, expected_attempt_id=request.expected_attempt_id,
                expected_external_run_id=request.expected_external_run_id,
                reason=request.reason, operation_id=request.operation_id, actor_id=context.actor_id,
            )
            return result
        try:
            return metadata_mutation(action, context, "abandon_attempt", job_id, mutate,
                wake_reason=f"unit-abandoned:{work_unit_id}", wake_if=lambda result: result["outcome"] == "queued")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/jobs/{job_id}/units/{work_unit_id}/retry")
    def retry_unit(
        job_id: str,
        work_unit_id: str,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_job_or_unit_owner(job_id, work_unit_id, context)
        try:
            retried = service.retry_unit(job_id, work_unit_id, actor_id=context.actor_id)
            dispatcher_controller.wake(reason=f"unit-retry:{work_unit_id}")
            return retried.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/jobs/{job_id}/units/{work_unit_id}/reassign")
    def reassign_unit(
        job_id: str,
        work_unit_id: str,
        request: UnitReassignRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_job_or_unit_owner(job_id, work_unit_id, context)
        try:
            result = service.reassign_unit(
                job_id,
                work_unit_id,
                request.target_machine_id,
                actor_id=context.actor_id,
                reason=request.reason,
                operation_id=request.operation_id,
                expected_attempt_id=request.expected_attempt_id,
                expected_external_run_id=request.expected_external_run_id,
            )
            if result["stage"] == "reassigned":
                dispatcher_controller.wake(reason=f"unit-reassigned:{work_unit_id}")
            return {**result, "job": result["job"].model_dump(mode="json")}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/jobs/{job_id}/units/{work_unit_id}/reassign-operations/{operation_id}")
    def get_reassignment_operation(job_id: str, work_unit_id: str, operation_id: str,
                                   context: AuthContext = Depends(auth.actor)) -> dict:
        from .unit_reassignment import reassignment_result
        require_job_or_unit_owner(job_id, work_unit_id, context)
        try:
            result = reassignment_result(service.repository, operation_id, job_id=job_id,
                work_unit_id=work_unit_id, actor_id=context.actor_id)
            return {**result, "job": result["job"].model_dump(mode="json")}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/jobs/{job_id}/units/{work_unit_id}/started")
    def unit_started(
        job_id: str,
        work_unit_id: str,
        expected_attempt_id: str | None = None,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_assigned_machine_owner(job_id, work_unit_id, context)
        try:
            return service.mark_unit_started(job_id, work_unit_id, actor_id=context.actor_id,
                                             expected_attempt_id=expected_attempt_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/jobs/{job_id}/units/{work_unit_id}/completed")
    def unit_completed(
        job_id: str,
        work_unit_id: str,
        completion: UnitCompletion,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_assigned_machine_owner(job_id, work_unit_id, context)
        try:
            completed = service.complete_unit(
                job_id,
                work_unit_id,
                manifest=completion.manifest,
                duration_s=completion.duration_s,
                actor_id=context.actor_id,
                expected_attempt_id=completion.expected_attempt_id,
            )
            dispatcher_controller.wake(reason=f"unit-completed:{work_unit_id}")
            return completed.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/jobs/{job_id}/units/{work_unit_id}/failed")
    def unit_failed(
        job_id: str,
        work_unit_id: str,
        failure: UnitFailure,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_assigned_machine_owner(job_id, work_unit_id, context)
        try:
            failed = service.fail_unit(
                job_id,
                work_unit_id,
                error=failure.error,
                retryable=failure.retryable,
                failure_class=failure.failure_class,
                actor_id=context.actor_id,
                expected_attempt_id=failure.expected_attempt_id,
            )
            dispatcher_controller.wake(reason=f"unit-failed:{work_unit_id}")
            return failed.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/jobs/{job_id}/artifact-manifests")
    def artifact_manifests(job_id: str, context: AuthContext = Depends(auth.actor)) -> list[dict]:
        found = operational_job_or_404(job_id)
        require_job_access(found, context)
        return [
            manifest.model_dump(mode="json")
            for manifest in repository.list_artifact_manifests(job_id)
        ]

    @app.post("/v1/scheduler/assign-once")
    def assign_once(context: AuthContext = Depends(auth.actor)) -> dict | None:
        require_role(context, UserRole.ADMIN)
        assignment = service.schedule_once(actor_id=context.actor_id)
        return assignment.model_dump(mode="json") if assignment else None

    @app.post("/v1/scheduler/auto-retry")
    def auto_retry(context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        return {"requeued_units": service._auto_retry_failed_units(actor_id=context.actor_id)}

    @app.get("/v1/admin/alerts")
    def alerts(
        include_resolved: bool = False,
        limit: int = Query(default=500, ge=1, le=1000),
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return [
            alert.model_dump(mode="json")
            for alert in repository.list_alerts(include_resolved=include_resolved, limit=limit)
        ]

    @app.get("/v1/jobs/{job_id}/origin-import-receipt")
    def origin_import_receipt(job_id: str, context: AuthContext = Depends(auth.actor)) -> dict | None:
        found = operational_job_or_404(job_id)
        require_job_access(found, context)
        receipt = repository.get_origin_import_receipt(job_id)
        return receipt.model_dump(mode="json") if receipt else None

    @app.post("/v1/jobs/{job_id}/origin-import-receipt")
    def put_origin_import_receipt(
        job_id: str,
        receipt: OriginImportReceipt,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        found = operational_job_or_404(job_id)
        require_job_owner(found, context)
        if receipt.job_id != job_id:
            raise HTTPException(status_code=400, detail="origin import receipt Job ID mismatch")
        try:
            return service.record_origin_import(receipt, actor_id=context.actor_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/alerts/{alert_id}/transition")
    def transition_alert(
        alert_id: str,
        request_body: AlertTransitionRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.transition_alert(
                alert_id,
                request_body.status,
                actor_id=context.actor_id,
                snoozed_until=request_body.snoozed_until,
                request_id=request_body.request_id,
                expected_state={name.removeprefix("expected_"): getattr(request_body, name)
                    for name in request_body.model_fields_set if name.startswith("expected_")}
                    if any(name.startswith("expected_") for name in request_body.model_fields_set) else None,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/audit-events")
    def events(
        limit: int = Query(default=200, ge=1, le=1000),
        subject_type: str | None = None,
        subject_id: str | None = None,
        event_type: str | None = None,
        before_sequence: int | None = Query(default=None, ge=1),
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        visibility = EventVisibility(repository, context)
        return [
            event.model_dump(mode="json")
            for event in repository.list_events(
                limit,
                subject_type=subject_type,
                subject_id=subject_id,
                event_type=event_type,
                before_sequence=before_sequence,
            ) if visibility.allows(event)
        ]

    @app.get("/v1/events/stream")
    async def event_stream(request: Request, context: AuthContext = Depends(auth.actor)) -> StreamingResponse:
        async def generate():
            last_sequence = 0
            try:
                last_sequence = int(request.headers.get("Last-Event-ID", "0") or 0)
            except ValueError:
                last_sequence = 0
            latest_sequence = await asyncio.to_thread(repository.latest_event_sequence)
            connected = json.dumps({"latest_sequence": latest_sequence}, separators=(",", ":"))
            yield f"event: connected\ndata: {connected}\n\n"
            while not await request.is_disconnected():
                if app.state.cooperative_shutdown_requested.is_set():
                    yield 'retry: 5000\nevent: maintenance\ndata: {"reason_code":"service_shutdown"}\n\n'
                    return
                if await asyncio.to_thread(app.state.transfer_gate.admission_closed):
                    yield 'retry: 5000\nevent: maintenance\ndata: {"reason_code":"release_draining"}\n\n'
                    return
                try:
                    current_context = await asyncio.to_thread(auth.actor, request.headers.get("authorization"))
                except HTTPException:
                    return
                visibility = await asyncio.to_thread(EventVisibility, repository, current_context)
                pending = await asyncio.to_thread(repository.list_events_after, last_sequence, limit=1000)
                for event in pending:
                    last_sequence = event.sequence
                    if not await asyncio.to_thread(visibility.allows, event):
                        continue
                    payload = json.dumps(event.model_dump(mode="json"), ensure_ascii=True, separators=(",", ":"))
                    yield f"id: {event.sequence}\nevent: state\ndata: {payload}\n\n"
                else:
                    if not pending:
                        yield ": keepalive\n\n"
                await asyncio.sleep(1)
        return StreamingResponse(generate(), media_type="text/event-stream")

    @app.get("/v1/settings/scheduling")
    def scheduling_policy(context: AuthContext = Depends(auth.actor)) -> dict:
        from .scheduling_controls import describe
        return describe(repository.get_feature_settings())

    @app.post("/v1/admin/scheduling/preview")
    def preview_scheduling(change: SchedulingChange, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        from .scheduling_controls import preview
        try:
            return preview(repository, change, context.actor_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/scheduling/confirm")
    def confirm_scheduling(change: SchedulingConfirmation, context: AuthContext = Depends(auth.actor),
                           action: tuple = Depends(metadata_action_request)) -> dict:
        require_role(context, UserRole.ADMIN)
        from .scheduling_controls import confirm
        def mutate():
            result = confirm(repository, change, context.actor_id)
            return result
        try:
            return metadata_mutation(action, context, "scheduling_confirm", "global", mutate,
                wake_reason="scheduling-policy-updated")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/settings/features")
    def feature_settings(context: AuthContext = Depends(auth.actor)) -> dict:
        return service.feature_settings().model_dump(mode="json")

    @app.put("/v1/settings/features")
    def put_feature_settings(
        settings: FeatureSettings,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return metadata_mutation(action, context, "feature_settings", "global",
                lambda: service.update_feature_settings(settings, actor_id=context.actor_id).model_dump(mode="json"))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/resource-policies/{profile_id}/preview")
    def preview_resource_policy(
        profile_id: str,
        policy: ResourcePolicy,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if policy.profile_id != profile_id:
            raise HTTPException(status_code=400, detail="resource policy profile ID mismatch")
        try:
            return service.preview_resource_policy(policy)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/admin/resource-policies/{profile_id}/confirm")
    def confirm_resource_policy(
        profile_id: str,
        request_body: ResourcePolicyConfirmation,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if request_body.policy.profile_id != profile_id:
            raise HTTPException(status_code=400, detail="resource policy profile ID mismatch")
        def mutate():
            confirmed = service.confirm_resource_policy(
                request_body.policy,
                expected_revision=request_body.expected_revision,
                confirmation_hash=request_body.confirmation_hash,
                actor_id=context.actor_id,
            )
            return confirmed.model_dump(mode="json")
        try:
            return metadata_mutation(action, context, "resource_policy_confirm", profile_id, mutate,
                wake_reason=f"resource-policy:{profile_id}")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/demo/tick")
    def demo_tick(context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        simulator = getattr(app.state, "demo_simulator", None)
        if simulator is None:
            raise HTTPException(status_code=409, detail="demo simulator is not enabled")
        simulator.tick()
        return {"tick": simulator.tick_count}

    @app.get("/v1/admin/demo-data/cleanup-preview")
    def demo_cleanup_preview(context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        if app.state.dataset_mode != "formal":
            raise HTTPException(status_code=409, detail="demo cleanup is only available for a formal dataset")
        return service.preview_demo_cleanup().model_dump(mode="json")

    @app.post("/v1/admin/demo-data/cleanup-confirm")
    def demo_cleanup_confirm(
        request_body: DemoCleanupConfirmation,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if app.state.dataset_mode != "formal":
            raise HTTPException(status_code=409, detail="demo cleanup is only available for a formal dataset")
        try:
            return service.confirm_demo_cleanup(
                request_body.confirmation_hash,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/machines/{machine_id}/execution-config")
    def execution_config(machine_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        config = repository.get_machine_execution_config(machine_id)
        if config is None:
            raise HTTPException(status_code=404, detail="machine execution config not found")
        return _public_execution_config(config)

    @app.post("/v1/admin/machines/{machine_id}/cached-runtime-admissions")
    def admit_machine_cached_runtime(
        machine_id: str,
        body: CachedRuntimeAdmissionRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if body.evidence.machine_id != machine_id:
            raise HTTPException(status_code=400, detail="machine ID mismatch")
        try:
            saved = service.admit_cached_runtime(body.evidence, reason=body.reason, actor_id=context.actor_id,
                                                cache_runtime=body.cache_runtime)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if dispatcher_controller is not None:
            dispatcher_controller.wake(reason="cached-runtime-admission:" + machine_id)
        return _public_execution_config(saved)

    @app.put("/v1/admin/machines/{machine_id}/ssh-timeouts")
    def put_machine_ssh_timeouts(
        machine_id: str,
        body: MachineSshTimeoutsRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            updated = service.update_machine_ssh_timeouts(
                machine_id,
                ssh_connect_timeout_s=body.ssh_connect_timeout_s,
                ssh_status_timeout_s=body.ssh_status_timeout_s,
                reason=body.reason,
                actor_id=context.actor_id,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _public_execution_config(updated)

    @app.put("/v1/machines/{machine_id}/execution-config")
    def put_execution_config(
        machine_id: str,
        config: MachineExecutionConfig,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if config.machine_id != machine_id:
            raise HTTPException(status_code=400, detail="machine ID mismatch")
        existing_config = repository.get_machine_execution_config(machine_id)
        if existing_config is not None and not config.pinned_host_key:
            config.pinned_host_key = existing_config.pinned_host_key
        if (
            existing_config is not None
            and config.max_concurrent_units != existing_config.max_concurrent_units
        ):
            raise HTTPException(
                status_code=409,
                detail="hard capacity changes require the audited set_hard_capacity control",
            )
        startup_errors = validate_startup_configuration(config)
        if startup_errors:
            raise HTTPException(status_code=400, detail="; ".join(startup_errors))
        try:
            return _public_execution_config(service.put_machine_execution_config(config, actor_id=context.actor_id))
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/machines/{machine_id}/scientific-acceptance/review")
    def review_scientific_acceptance(
        machine_id: str,
        request_body: ScientificAcceptanceReviewRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            reviewed = service.review_scientific_acceptance(machine_id,
                run_id=request_body.run_id, report_sha256=request_body.report_sha256,
                reason=request_body.reason, actor_id=context.actor_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        dispatcher_controller.wake(reason=f"scientific-acceptance-review:{machine_id}")
        return _public_execution_config(reviewed)

    @app.put("/v1/machines/{machine_id}/execution-tuning")
    def put_execution_tuning(
        machine_id: str,
        tuning: MachineExecutionTuningRequest,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        def mutate():
            updated = service.update_machine_execution_tuning(
                    machine_id,
                    disk_reserve_gib=tuning.disk_reserve_gib,
                    success_retention_days=tuning.success_retention_days,
                    failure_retention_days=tuning.failure_retention_days,
                    poll_interval_s=tuning.poll_interval_s,
                    profile_concurrency_limits=tuning.profile_concurrency_limits,
                    actor_id=context.actor_id,
                )
            return _public_execution_config(updated)
        try:
            return metadata_mutation(action, context, "machine_execution_tuning", machine_id, mutate,
                wake_reason=f"execution-tuning:{machine_id}")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/machines/{machine_id}/execution-config/tunnel-install")
    def install_tunnel_task(
        machine_id: str,
        request_body: TunnelInstallRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        config = repository.get_machine_execution_config(machine_id)
        if config is None:
            raise HTTPException(status_code=404, detail="machine execution config not found")
        if config.tunnel_startup not in {"boot", "logon"}:
            raise HTTPException(status_code=409, detail="tunnel startup is manual")
        remote_script = str(Path(config.remote_root) / "agent" / "tunnel" / "reverse-ssh.ps1")
        try:
            transport = OpenSshTransport(
                config,
                state_root=Path(__file__).resolve().parents[2] / ".state" / "ssh",
            )
            generated = build_reconnect_script(
                config,
                identity_file=str(transport.tunnel_identity_path),
                known_hosts_file=str(transport.tunnel_known_hosts_path),
            )
            xml = build_boot_task_xml(config, remote_script, run_as=request_body.run_as)
            result = transport.install_tunnel_task(generated.script, xml, task_name=generated.task_name)
            service._event(
                "machine.tunnel_task_installed",
                context.actor_id,
                "machine",
                machine_id,
                run_as=request_body.run_as,
                task_name=generated.task_name,
            )
            return result
        except (OSError, RuntimeError, ValueError, TimeoutError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/machines/{machine_id}/execution-config/tunnel-bootstrap")
    def bootstrap_tunnel_identity(
        machine_id: str,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        config = repository.get_machine_execution_config(machine_id)
        if config is None:
            raise HTTPException(status_code=404, detail="machine execution config not found")
        try:
            result = OpenSshTransport(
                config,
                state_root=Path(__file__).resolve().parents[2] / ".state" / "ssh",
            ).bootstrap_tunnel_identity()
            service._event(
                "machine.tunnel_identity_bootstrapped",
                context.actor_id,
                "machine",
                machine_id,
                fingerprint=result.get("fingerprint"),
            )
            return result
        except (OSError, RuntimeError, ValueError, TimeoutError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/machines/{machine_id}/execution-config/validate-root")
    def validate_execution_root(machine_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        config = repository.get_machine_execution_config(machine_id)
        if config is None:
            raise HTTPException(status_code=404, detail="machine execution config not found")
        try:
            normalized = str(validate_remote_root_path(config.remote_root))
            probe = OpenSshTransport(
                config,
                state_root=Path(__file__).resolve().parents[2] / ".state" / "ssh",
            ).probe()
            return {"valid": probe.available, "normalized_root": normalized, "probe": probe.model_dump(mode="json")}
        except (ValueError, OSError) as exc:
            return {"valid": False, "errors": [str(exc)]}

    def ssh_harness(machine_id: str) -> SshAcceptanceHarness:
        config = repository.get_machine_execution_config(machine_id)
        if config is None:
            raise HTTPException(status_code=404, detail="machine execution config not found")
        project_root = Path(__file__).resolve().parents[2]
        return SshAcceptanceHarness(
            service,
            project_root=project_root,
            workspace_root=project_root.parents[1],
            machine_config=config,
        )

    @app.post("/v1/machines/{machine_id}/execution-config/initialize-root")
    def initialize_execution_root(machine_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        harness = ssh_harness(machine_id)
        run = harness.create_run(actor_id=context.actor_id)
        harness.initialize_root(run, actor_id=context.actor_id)
        return {"run": run.model_dump(mode="json"), "config": _public_execution_config(harness.machine_config)}

    @app.get("/v1/machines/{machine_id}/remote-runs")
    def remote_runs(machine_id: str, context: AuthContext = Depends(auth.actor)) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        runs = repository.list_remote_runs(machine_id)
        attempt_index = repository.remote_run_attempt_index(run.job_id for run in runs)
        result = []
        for run in runs:
            payload = run.model_dump(mode="json")
            attempt = attempt_index.get(run.external_run_id)
            payload["recorded_state"] = payload["state"]
            payload["effective_state"] = attempt[0] if attempt else "historical"
            payload["historical"] = attempt is None or not attempt[1]
            result.append(payload)
        return result

    @app.get("/v1/machines/{machine_id}/cleanup-preview")
    def cleanup_preview(machine_id: str, context: AuthContext = Depends(auth.actor)) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return ssh_harness(machine_id).cleanup_preview()

    @app.post("/v1/machines/{machine_id}/cleanup-confirm")
    def cleanup_confirm(
        machine_id: str,
        request_body: CleanupConfirmation,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        result = ssh_harness(machine_id).cleanup_confirm(request_body.relative_path, request_body.root_uuid)
        service._event(
            "machine.cleanup_confirmed",
            context.actor_id,
            "machine",
            machine_id,
            relative_path=request_body.relative_path,
        )
        return result

    @app.get("/v1/acceptance/scientific/capability")
    def scientific_acceptance_capability(context: AuthContext = Depends(auth.actor)) -> dict:
        from .scientific_acceptance_contract import scientific_acceptance_capability as capability
        return capability()

    @app.get("/v1/acceptance/ssh")
    def ssh_acceptance_runs(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return [run.model_dump(mode="json") for run in repository.list_ssh_acceptance_runs()]

    @app.get("/v1/acceptance/ssh/{run_id}")
    def ssh_acceptance_run(run_id: str, context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        run = repository.get_ssh_acceptance_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="SSH acceptance run not found")
        return run.model_dump(mode="json")

    @app.get("/v1/admin/onboarding/profiles")
    def onboarding_profiles(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return app.state.onboarding.profile_statuses()

    @app.get("/v1/admin/onboarding/runs")
    def onboarding_runs(
        machine_id: str | None = Query(default=None),
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return [
            run.model_dump(mode="json")
            for run in repository.list_machine_preflight_runs(machine_id)
        ]

    @app.post("/v1/admin/onboarding/{machine_id}/preflight")
    def onboarding_preflight(
        machine_id: str,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ):
        require_role(context, UserRole.ADMIN)
        if app.state.dataset_mode != "formal":
            raise HTTPException(status_code=409, detail="machine onboarding is unavailable in demo mode")
        try:
            result = run_preflight_metadata_action(repository, request_id=action[0],
                actor_id=context.actor_id, subject_id=machine_id, payload=action[1],
                mutate=lambda run_id: app.state.onboarding.run_preflight(
                    machine_id, actor_id=context.actor_id, run_id=run_id).model_dump(mode="json"))
            if result.get("state") in {"running", "reconciliation_required"}:
                return JSONResponse(status_code=202, content=result)
            return result
        except MetadataActionForbidden as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (KeyError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/onboarding/report")
    def onboarding_report(context: AuthContext = Depends(auth.actor)) -> dict:
        require_role(context, UserRole.ADMIN)
        return {"report_path": str(app.state.onboarding.write_matrix_report())}

    @app.post("/v1/admin/enrollments")
    def issue_enrollment(
        request_body: EnrollmentIssueRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return service.issue_enrollment(
                request_body.owner_user_id,
                actor_id=context.actor_id,
                ttl_minutes=request_body.ttl_minutes,
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/admin/enrollments")
    def enrollments(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        require_role(context, UserRole.ADMIN)
        return [item.model_dump(mode="json") for item in repository.list_enrollments()]

    @app.post("/v1/me/enrollments")
    def issue_my_enrollment(
        request_body: SelfEnrollmentIssueRequest,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_role(context, UserRole.MACHINE_OWNER)
        try:
            return service.issue_self_enrollment(
                context.actor_id,
                ttl_minutes=request_body.ttl_minutes,
            ).model_dump(mode="json")
        except (KeyError, ValueError) as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "enrollment_unavailable", "message": str(exc)},
            ) from exc

    @app.get("/v1/me/enrollments")
    def my_enrollments(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        require_role(context, UserRole.MACHINE_OWNER)
        return [
            item.model_dump(mode="json")
            for item in repository.list_enrollments(owner_user_id=context.actor_id)
        ]

    @app.put("/v1/machines/{machine_id}/external-comsol-consent")
    def set_external_comsol_consent(
        machine_id: str,
        request_body: ExternalComsolConsentRequest,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_machine_owner(machine_id, context)
        try:
            return metadata_mutation(action, context, "machine_external_comsol_consent", machine_id,
                lambda: service.set_external_comsol_consent(
                machine_id,
                authorized=request_body.authorized,
                actor_id=context.actor_id,
            ).model_dump(mode="json"))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/node/enroll")
    def enroll_node(request_body: EnrollmentRequest) -> dict:
        try:
            machine, credential = service.enroll_machine(
                request_body.enrollment_code,
                request_body.machine,
            )
            return {
                "machine": machine.model_dump(mode="json"),
                "machine_credential": credential.model_dump(mode="json"),
                "policy_state": "paused_pending_admin_acceptance",
            }
        except ValueError as exc:
            message = str(exc)
            reason_code = next((
                code for fragment, code in (
                    ("invalid, expired, or already used", "enrollment_code_unavailable"),
                    ("owner does not match", "enrollment_owner_mismatch"),
                    ("incompatible protocol", "protocol_version_incompatible"),
                    ("incompatible worker runtime", "worker_runtime_incompatible"),
                    ("already registered", "machine_already_registered"),
                )
                if fragment in message
            ), "enrollment_conflict")
            raise HTTPException(
                status_code=409,
                detail={"reason_code": reason_code, "message": message},
            ) from exc

    @app.get("/{full_path:path}", response_class=HTMLResponse, response_model=None)
    def spa_fallback(full_path: str):
        if not full_path.startswith(("help", "connect", "app")):
            raise HTTPException(status_code=404, detail="not found")
        index = static_root / "index.html"
        if index.is_file():
            return FileResponse(index)
        return HTMLResponse("<div id=\"root\"></div>")

    return app
