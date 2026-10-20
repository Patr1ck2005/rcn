"""Versioned public contracts for jobs, machines, approvals, and artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import math
from pathlib import PurePosixPath
import re
from typing import Any, Literal
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .dispatch_policy import SchedulingPolicy

from .member_admission_contract import MemberExecutionLimit


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


class JobStatus(StrEnum):
    AWAITING_APPROVAL = "awaiting_approval"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED_RETRIABLE = "failed_retriable"
    FAILED_TERMINAL = "failed_terminal"
    CANCELLED = "cancelled"


class WorkUnitStatus(StrEnum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    RECONCILE_PENDING = "reconcile_pending"
    COLLECTING = "collecting"
    COMPLETED = "completed"
    FAILED_RETRIABLE = "failed_retriable"
    FAILED_TERMINAL = "failed_terminal"
    CANCELLED = "cancelled"


class MachineMode(StrEnum):
    OPEN = "open"
    DRAIN = "drain"
    PAUSED = "paused"
    EMERGENCY_STOP = "emergency_stop"


class MachineControlAction(StrEnum):
    SET_ADMIN_MODE = "set_admin_mode"
    CLEAR_ADMIN_MODE = "clear_admin_mode"
    SET_TARGET_CAPACITY = "set_target_capacity"
    SET_HARD_CAPACITY = "set_hard_capacity"
    ACCEPT_HARD_CAPACITY = "accept_hard_capacity"
    HEALTH_PROBE = "health_probe"
    GRACEFUL_STOP = "graceful_stop"
    EMERGENCY_STOP_NETWORK = "emergency_stop_network"
    EMERGENCY_STOP_HOST = "emergency_stop_host"
    RESTART_SUPERVISOR = "restart_supervisor"
    FORCE_RESTART_SUPERVISOR = "force_restart_supervisor"
    PROMOTE_RUNTIME = "promote_runtime"
    ROLLBACK_RUNTIME = "rollback_runtime"


class DispatcherControlAction(StrEnum):
    START = "start"
    DRAIN = "drain"
    STOP = "stop"
    RESTART = "restart"
    FORCE_STOP = "force_stop"
    RECONCILE = "reconcile"


class ControlOperationState(StrEnum):
    ACCEPTED = "accepted"
    REMOTE_ACKNOWLEDGED = "remote_acknowledged"
    COMPLETED = "completed"
    PARTIAL_FAILED = "partial_failed"
    FAILED = "failed"


class ControlTargetState(StrEnum):
    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    COMPLETED = "completed"
    FAILED = "failed"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    SNOOZED = "snoozed"
    RESOLVED = "resolved"


class ApprovalScope(StrEnum):
    PROJECT = "project"
    EXECUTION_PROFILE = "execution_profile"


class UserRole(StrEnum):
    ADMIN = "admin"
    MEMBER = "member"
    MACHINE_OWNER = "machine_owner"


class ProjectStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    FROZEN = "frozen"
    REJECTED = "rejected"


class ProjectRegistrationStatus(StrEnum):
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class FeatureVisibility(StrEnum):
    FULL = "full"
    GROUP_OVERVIEW = "group_overview"
    OWN_DETAIL = "own_detail"


class AcceptanceStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    BLOCKED = "blocked"


class RemoteRunState(StrEnum):
    STAGED = "staged"
    PREPARED = "prepared"
    QUEUED = "queued"
    RUNNING = "running"
    CANCEL_PENDING = "cancel_pending"
    RECONCILE_PENDING = "reconcile_pending"
    UNCERTAIN = "uncertain"
    COLLECTING = "collecting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class FailureClass(StrEnum):
    INFRASTRUCTURE = "infrastructure"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SCIENTIFIC_INPUT = "scientific_input"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class SolverVariant(StrEnum):
    MUMPS = "mumps"
    CUDSS = "cudss"


class SolverPolicy(StrEnum):
    """High-level solver contract for new submissions."""

    AUTO_FAST = "auto_fast"
    COMPATIBILITY_MUMPS = "compatibility_mumps"


class ResourceMode(StrEnum):
    """Whether the request uses dynamic admission or a legacy reservation."""

    DYNAMIC = "dynamic"
    FIXED = "fixed"


class ComsolStudyKind(StrEnum):
    EIGENFREQUENCY = "eigenfrequency"
    FREQUENCY_DOMAIN = "frequency_domain"
    STATIONARY = "stationary"
    TIME_DEPENDENT = "time_dependent"


class SolutionArchiveKind(StrEnum):
    NONE = "none"
    STRUCTURED = "structured"
    MPH = "mph"
    BOTH = "both"


class ArchiveGranularity(StrEnum):
    ATOM = "atom"
    UNIT = "unit"


class DispatcherPhase(StrEnum):
    STARTING = "starting"
    ACTIVE = "active"
    STANDBY = "standby"
    STOPPED = "stopped"
    ERROR = "error"


class TransportState(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNKNOWN = "unknown"


class SupervisorState(StrEnum):
    ONLINE = "online"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class TelemetryState(StrEnum):
    LIVE = "live"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class ControlState(StrEnum):
    ACCEPTING = "accepting"
    TRANSPORT_BLOCKED = "transport_blocked"
    MAINTENANCE = "maintenance"
    EXECUTOR_UNAVAILABLE = "executor_unavailable"


class HeartbeatPhase(StrEnum):
    HEALTHY = "healthy"
    DELAYED = "delayed"
    STALE = "stale"
    OFFLINE = "offline"


class PressureState(StrEnum):
    NORMAL = "normal"
    CANDIDATE = "candidate"
    PRESSURED = "pressured"
    TELEMETRY_STALE = "telemetry_stale"
    OVERRIDE = "override"


class OnboardingStage(StrEnum):
    PLANNED = "planned"
    HOST_KEY_VERIFIED = "host_key_verified"
    PREFLIGHT_RUNNING = "preflight_running"
    PREFLIGHT_COMPLETE = "preflight_complete"
    AWAITING_APPROVAL = "awaiting_approval"
    DEPLOYED = "deployed"
    ACCEPTED = "accepted"


class DeploymentReadiness(StrEnum):
    READY = "ready"
    NEEDS_MANAGED_PYTHON = "needs_managed_python"
    BLOCKED = "blocked"


class UserAccount(BaseModel):
    schema_version: Literal[1] = 1
    user_id: str
    display_name: str
    roles: set[UserRole] = Field(default_factory=lambda: {UserRole.MEMBER})
    active: bool = True
    created_at: datetime = Field(default_factory=utc_now)


class ApiTokenRecord(BaseModel):
    schema_version: Literal[1] = 1
    token_id: str = Field(default_factory=lambda: new_id("token"))
    user_id: str
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scopes: set[str] = Field(default_factory=lambda: {"api"})
    active: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or utc_now()
        return self.active and (self.expires_at is None or self.expires_at > current)


class MachineAgentCredential(BaseModel):
    schema_version: Literal[1] = 1
    credential_id: str = Field(default_factory=lambda: new_id("machine-token"))
    machine_id: str
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_by: str
    active: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or utc_now()
        return self.active and (self.expires_at is None or self.expires_at > current)


class IssuedToken(BaseModel):
    token_id: str
    user_id: str
    token: str
    expires_at: datetime | None = None


class ResourceRequest(BaseModel):
    cpus: int = Field(default=1, ge=1)
    memory_mb: int = Field(default=1024, ge=256)
    disk_mb: int = Field(default=1024, ge=0)
    gpus: int = Field(default=0, ge=0)


class ResourcePolicy(BaseModel):
    """Network-owned bounded defaults for one execution Profile."""

    schema_version: Literal[1] = 1
    profile_id: str
    revision: int = Field(default=1, ge=1)
    baseline: ResourceRequest
    minimum: ResourceRequest = Field(
        default_factory=lambda: ResourceRequest(cpus=1, memory_mb=256, disk_mb=0, gpus=0)
    )
    maximum: ResourceRequest = Field(
        default_factory=lambda: ResourceRequest(
            cpus=64,
            memory_mb=262144,
            disk_mb=1048576,
            gpus=8,
        )
    )
    minimum_success_samples: int = Field(default=20, ge=1)
    downward_step_percent: float = Field(default=10.0, gt=0, le=10)
    memory_percentile: float = Field(default=99.0, ge=50, le=100)
    memory_margin_percent: float = Field(default=25.0, ge=0, le=200)
    memory_margin_floor_mb: int = Field(default=2048, ge=0)
    disk_percentile: float = Field(default=99.0, ge=50, le=100)
    disk_margin_percent: float = Field(default=25.0, ge=0, le=200)
    disk_margin_floor_mb: int = Field(default=1024, ge=0)
    automatic_adjustment: bool = True
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_bounds(self) -> "ResourcePolicy":
        for name in ("cpus", "memory_mb", "disk_mb", "gpus"):
            low = getattr(self.minimum, name)
            baseline = getattr(self.baseline, name)
            high = getattr(self.maximum, name)
            if not low <= baseline <= high:
                raise ValueError(
                    f"resource policy {name} must satisfy minimum <= baseline <= maximum"
                )
        return self


class ResolvedResources(BaseModel):
    """Auditable resource decision persisted with Units and frozen per Attempt."""

    schema_version: Literal[1] = 1
    resources: ResourceRequest
    source: Literal[
        "network_profile_default",
        "network_policy",
        "network_adaptive",
        "network_dynamic",
        "origin_legacy",
        "origin_requested",
    ]
    policy_revision: int = Field(default=1, ge=1)
    evidence_sample_count: int = Field(default=0, ge=0)
    memory_safety_margin_mb: int = Field(default=0, ge=0)
    disk_safety_margin_mb: int = Field(default=0, ge=0)
    resolved_at: datetime = Field(default_factory=utc_now)


class ComsolExpressionRequest(BaseModel):
    """One lossless COMSOL expression requested by the originating Workbench."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    expression: str = Field(min_length=1, max_length=4096)
    unit: str | None = Field(default=None, max_length=128)
    evaluation: Literal["global", "table"] = "global"
    table_tag: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    dataset_tag: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    inner: Literal["first", "last"] | list[int] | None = None
    outer: int | list[int] | None = None

    @field_validator("expression")
    @classmethod
    def validate_expression_text(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("COMSOL expressions cannot contain control characters")
        return value

    @model_validator(mode="after")
    def validate_table_selector(self) -> "ComsolExpressionRequest":
        if self.evaluation == "table" and not self.table_tag:
            raise ValueError("table expressions require table_tag")
        if self.evaluation == "global" and self.table_tag is not None:
            raise ValueError("global expressions cannot select a table")
        if isinstance(self.inner, list) and (
            not self.inner or any(value < 1 for value in self.inner)
        ):
            raise ValueError("inner solution indices must be positive")
        outer = [self.outer] if isinstance(self.outer, int) else self.outer
        if outer is not None and (not outer or any(value < 1 for value in outer)):
            raise ValueError("outer solution indices must be positive")
        return self


class ComsolMaxVolumeOptions(BaseModel):
    """Only the postprocessing defaults verified on the existing COMSOL 6.4 route."""
    model_config = ConfigDict(extra="forbid")
    points: Literal["lagrange"] = "lagrange"
    refine: Literal[5] = 5
    include_position: Literal[True] = True
    obj: Literal["real"] = "real"
    dataseries: Literal["none"] = "none"
    normalization: Literal["none"] = "none"


class ComsolDomainEvaluationRequest(BaseModel):
    """Named three-dimensional result evaluation, not a solver or script request."""
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    expression: str = Field(min_length=1, max_length=4096)
    evaluation: Literal["intvolume", "maxvolume"]
    expression_semantics: Literal["complex_scalar", "real_scalar", "real_intensity"] = "complex_scalar"
    selection: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    dataset_tag: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    unit: str | None = Field(default=None, max_length=128)
    inner: list[int] = Field(min_length=1, max_length=4096)
    outer: int | None = Field(default=None, ge=1)
    max_volume: ComsolMaxVolumeOptions | None = None
    # Retains the scalar-request interface used by existing local plan validators.
    table_tag: None = None

    @field_validator("expression")
    @classmethod
    def validate_domain_expression(cls, value):
        if any(ord(character) < 32 for character in value):
            raise ValueError("COMSOL expressions cannot contain control characters")
        return value

    @field_validator("inner", mode="before")
    @classmethod
    def validate_explicit_inner(cls, value):
        if not isinstance(value, list) or not value:
            raise ValueError("domain evaluation requires explicit inner solution indices")
        if any(type(index) is not int or index < 1 for index in value):
            raise ValueError("inner indices must be positive strict integers")
        if len(set(value)) != len(value):
            raise ValueError("duplicate inner indices are not lossless coverage")
        return value

    @field_validator("outer", mode="before")
    @classmethod
    def validate_domain_outer(cls, value):
        if value is not None and (type(value) is not int or value < 1):
            raise ValueError("outer must be one positive strict integer or null")
        return value

    @model_validator(mode="after")
    def validate_domain_settings(self):
        if self.evaluation == "maxvolume" and self.max_volume is None:
            raise ValueError("MaxVolume requires explicit verified default settings")
        if self.evaluation == "maxvolume" and self.expression_semantics != "real_intensity":
            raise ValueError("MaxVolume is restricted to explicitly declared real intensity")
        if self.evaluation == "intvolume" and self.max_volume is not None:
            raise ValueError("IntVolume cannot carry maximum settings")
        if self.evaluation == "intvolume" and self.expression_semantics not in {"real_scalar", "complex_scalar"}:
            raise ValueError("IntVolume real-only quantities use real_scalar")
        return self


class ComsolGridRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["native", "regular"] = "native"
    axes: dict[str, list[float]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_grid(self) -> "ComsolGridRequest":
        if self.mode == "regular":
            if not self.axes or not 1 <= len(self.axes) <= 3:
                raise ValueError("regular COMSOL grids require one to three axes")
            if not set(self.axes).issubset({"x", "y", "z"}):
                raise ValueError("regular COMSOL grid axes must be x, y, or z")
            if any(not values for values in self.axes.values()):
                raise ValueError("regular COMSOL grid axes cannot be empty")
            if any(
                not math.isfinite(value)
                for values in self.axes.values()
                for value in values
            ):
                raise ValueError("regular COMSOL grid axes must be finite")
        elif self.axes:
            raise ValueError("native COMSOL grids cannot define explicit axes")
        return self


class ComsolUnitRegularGridRequest(ComsolGridRequest):
    mode: Literal["regular"] = "regular"
    coordinate_unit: Literal["m", "cm", "mm", "um", "nm"]

    @model_validator(mode="after")
    def validate_global_xyz(self):
        if set(self.axes) != {"x", "y", "z"}:
            raise ValueError("unit-aware three-dimensional regular fields require explicit xyz")
        return self


class ComsolFieldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    expressions: list[str] = Field(min_length=1, max_length=128)
    dataset_tag: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    selection: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
    )
    grid: ComsolGridRequest | ComsolUnitRegularGridRequest = Field(default_factory=ComsolGridRequest)
    inner: Literal["first", "last"] | list[int] | None = None
    outer: int | list[int] | None = None

    @field_validator("expressions")
    @classmethod
    def validate_field_expressions(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("field expressions must be unique")
        if any(not value or len(value) > 4096 or any(ord(ch) < 32 for ch in value) for value in values):
            raise ValueError("field expressions must be non-empty control-free strings")
        return values

    @field_validator("inner", "outer", mode="before")
    @classmethod
    def validate_unit_selectors_before_coercion(cls, value, info):
        if isinstance(info.data.get("grid"),ComsolUnitRegularGridRequest):
            if info.field_name == "inner" and (not isinstance(value,list) or not value or len(set(value))!=len(value) or any(type(index) is not int or index<1 for index in value)):
                raise ValueError("unit-aware inner coverage must use positive strict integers")
            if info.field_name == "outer" and value is not None and (type(value) is not int or value<1):
                raise ValueError("unit-aware outer must be one strict integer")
        return value

    @model_validator(mode="after")
    def validate_solution_selectors(self) -> "ComsolFieldRequest":
        if isinstance(self.grid, ComsolUnitRegularGridRequest):
            if not isinstance(self.inner,list) or not self.inner or len(set(self.inner))!=len(self.inner) or any(type(index) is not int or index<1 for index in self.inner):
                raise ValueError("unit-aware fields require explicit strict inner coverage")
            if self.outer is not None and (type(self.outer) is not int or self.outer<1):
                raise ValueError("unit-aware fields require a single strict outer index")
        if isinstance(self.inner, list) and (
            not self.inner or any(value < 1 for value in self.inner)
        ):
            raise ValueError("inner solution indices must be positive")
        outer = [self.outer] if isinstance(self.outer, int) else self.outer
        if outer is not None and (not outer or any(value < 1 for value in outer)):
            raise ValueError("outer solution indices must be positive")
        return self


class ComsolOutputRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1, 2] = 1
    semantic_outputs: list[str] = Field(default_factory=list)
    expressions: list[ComsolExpressionRequest | ComsolDomainEvaluationRequest] = Field(default_factory=list)
    fields: list[ComsolFieldRequest] = Field(default_factory=list)
    solution_archive: SolutionArchiveKind = SolutionArchiveKind.NONE
    archive_granularity: ArchiveGranularity = ArchiveGranularity.UNIT
    # Opt-in runtime custody of solved models. Absence preserves frozen legacy
    # output requests; science exports remain independently selected above.
    temporary_solution_retention: Literal["recovery"] | None = Field(
        default=None, exclude_if=lambda value: value is None,
    )
    readout_adapter_id: None = Field(
        default=None, exclude_if=lambda value: value is None,
    )

    @field_validator("semantic_outputs")
    @classmethod
    def validate_semantic_outputs(cls, values: list[str]) -> list[str]:
        pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
        if len(values) != len(set(values)) or any(not pattern.fullmatch(value) for value in values):
            raise ValueError("semantic output aliases must be unique safe identifiers")
        return values

    @model_validator(mode="after")
    def validate_outputs(self) -> "ComsolOutputRequest":
        if any(isinstance(value, ComsolDomainEvaluationRequest) for value in self.expressions) and self.schema_version != 2:
            raise ValueError("typed domain evaluations require output schema_version=2")
        if any(isinstance(value.grid,ComsolUnitRegularGridRequest) for value in self.fields) and self.schema_version != 2:
            raise ValueError("unit-aware field outputs require output schema_version=2")
        names = [value.name for value in self.expressions] + [value.name for value in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("COMSOL output names must be unique")
        if self.archive_granularity == ArchiveGranularity.ATOM and self.solution_archive == SolutionArchiveKind.NONE:
            raise ValueError("atom archive granularity requires a structured or MPH archive")
        if (
            not self.semantic_outputs
            and not self.expressions
            and not self.fields
            and self.solution_archive == SolutionArchiveKind.NONE
            and self.readout_adapter_id is None
        ):
            raise ValueError("COMSOL output request must select outputs or a solution archive")
        return self


class PartitionConstraints(BaseModel):
    """Operational grouping rules for opaque scientific items."""

    preserve_ordinal: Literal[True] = True
    prohibit_mixed_setup_fingerprints: bool = False


class AtomicComputeItem(BaseModel):
    """One immutable, Workbench-owned scientific calculation item."""

    schema_version: Literal[1] = 1
    item_id: str
    ordinal: int = Field(ge=0)
    payload: dict[str, Any]
    estimated_duration_s: float | None = Field(default=None, gt=0)
    setup_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    coordinates: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class TemplateParameterEvidence(BaseModel):
    """Workbench template-inspection evidence used by planning safety guards."""

    schema_version: Literal[1] = 1
    template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inspection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    global_parameter_names: list[str] = Field(default_factory=list)

    @field_validator("global_parameter_names")
    @classmethod
    def validate_global_parameter_names(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name) for name in value):
            raise ValueError("template global parameter names must be valid COMSOL identifiers")
        if len(value) != len(set(value)):
            raise ValueError("template global parameter names must be unique")
        return sorted(value)


class UnitDiskEstimate(BaseModel):
    """Opt-in planning bound, applied to each actual partition, not the whole task."""

    model_config = ConfigDict(extra="forbid")
    bytes_per_atom: int = Field(gt=0, le=2**63 - 1, strict=True)
    shared_input_bytes: int = Field(default=0, ge=0, le=2**63 - 1, strict=True)
    minimum_disk_mb: int = Field(default=0, ge=0, strict=True)
    provenance: str = Field(min_length=1, max_length=512)

    @field_validator("provenance")
    @classmethod
    def nonempty_provenance(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("disk estimate provenance must not be blank")
        return value.strip()


class PartitionRequest(BaseModel):
    """Opaque scientific items plus operational grouping preferences."""

    schema_version: Literal[1, 2] = 2
    origin_submitter_id: str
    origin_adapter_id: str = "workbench"
    user_id: str
    project_id: str
    execution_profile_id: str
    campaign_id: str | None = None
    campaign_task_id: str | None = None
    recipe_kind: str | None = None
    study_kind: ComsolStudyKind | None = None
    template_role: str | None = None
    template_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    template_parameter_evidence: TemplateParameterEvidence | None = None
    output_contract_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    estimated_output_bytes: int | None = Field(default=None, ge=0)
    planning_warnings: list[str] = Field(default_factory=list)
    source_spec_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_manifest: list["FileRecord"] = Field(default_factory=list)
    items: list[AtomicComputeItem] = Field(min_length=1)
    target_unit_s: int = Field(default=1800, ge=1, le=86400)
    preferred_max_unit_s: int = Field(default=3600, ge=1, le=86400)
    estimated_seconds_per_item: float | None = Field(default=None, gt=0)
    disk_estimate: UnitDiskEstimate | None = None
    requested_unit_count: int | None = Field(default=None, ge=1)
    # v2 origins may omit resource quantities. Network resolves and persists
    # the operational values before a plan can be created. v1 payloads retain
    # their explicitly supplied/default resource contract.
    resources: ResourceRequest | None = None
    resolved_resources: ResolvedResources | None = None
    required_capabilities: set[str] = Field(default_factory=set)
    allowed_solver_variants: set[SolverVariant] = Field(
        default_factory=lambda: {SolverVariant.MUMPS}
    )
    solver_policy: SolverPolicy = SolverPolicy.AUTO_FAST
    resource_mode: ResourceMode = ResourceMode.DYNAMIC
    # Persisted so a plan round-trip does not mistake a legacy inferred
    # contract for an explicitly requested auto_fast policy.
    solver_policy_explicit: bool = Field(default=False, repr=False)
    solver_approval_id: str | None = None
    solver_compatibility_fingerprint: str | None = None
    unit_payload_kind: str = "partitioned_compute_items"
    timeout_s: int = Field(default=3600, ge=1, le=86400)
    retry_policy: "RetryPolicy" = Field(default_factory=lambda: RetryPolicy())
    priority: int = Field(default=0, ge=-100, le=100)
    initial_machine_spread: list[str] = Field(default_factory=list)
    priority_explicit: bool | None = Field(default=None, strict=True, exclude_if=lambda value: value is None)
    partition_constraints: PartitionConstraints = Field(default_factory=PartitionConstraints)

    @model_validator(mode="before")
    @classmethod
    def mark_solver_policy_explicit(cls, value: Any) -> Any:
        if isinstance(value, dict):
            data = dict(value)
            # A missing policy key identifies a pre-0.13 payload. Any new
            # payload that names auto_fast is explicit, including an invalid
            # mixed variant set that must be rejected instead of downgraded.
            data["solver_policy_explicit"] = (
                bool(value["solver_policy_explicit"])
                if "solver_policy_explicit" in value
                else "solver_policy" in value
            )
            return data
        return value

    @model_validator(mode="after")
    def validate_partition_request(self) -> "PartitionRequest":
        # Requests created before the explicit contract existed are retained
        # as compatibility MUMPS requests. New adapters must state auto_fast
        # explicitly, so an ambiguous v2 payload cannot silently downgrade.
        if "solver_policy" not in self.model_fields_set and (
            self.schema_version == 1 or self.allowed_solver_variants == {SolverVariant.MUMPS}
        ):
            self.solver_policy = SolverPolicy.COMPATIBILITY_MUMPS
        if "resource_mode" not in self.model_fields_set and self.schema_version == 1:
            self.resource_mode = ResourceMode.FIXED
        ids = [item.item_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("atomic item IDs must be unique")
        ordinals = [item.ordinal for item in self.items]
        if sorted(ordinals) != list(range(len(ordinals))):
            raise ValueError("atomic item ordinals must be contiguous from zero")
        if self.target_unit_s > self.preferred_max_unit_s:
            raise ValueError("target unit duration must not exceed the preferred maximum")
        if self.requested_unit_count is not None and self.requested_unit_count > len(self.items):
            raise ValueError("requested unit count cannot exceed the atomic item count")
        if bool(self.campaign_id) != bool(self.campaign_task_id):
            raise ValueError("campaign_id and campaign_task_id must be provided together")
        if self.partition_constraints.prohibit_mixed_setup_fingerprints:
            if any(item.setup_fingerprint is None for item in self.items):
                raise ValueError("setup fingerprints are required by the partition constraints")
        return self


class RetryPolicy(BaseModel):
    """Bounded retry and migration policy carried with a job envelope."""

    max_attempts: int = Field(default=3, ge=1, le=10)
    retry_all_failures: bool = False
    allow_migration: bool = True



class FileRecord(BaseModel):
    relative_path: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_type: str = "application/octet-stream"

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts or normalized in {"", "."}:
            raise ValueError("artifact paths must be non-empty relative paths")
        return str(path)


class AtomicItemExecution(BaseModel):
    item_id: str
    ordinal: int = Field(ge=0)
    solver_variant: SolverVariant
    duration_s: float | None = Field(default=None, ge=0)


class AtomicResultManifest(BaseModel):
    """Portable point-level resume evidence produced by a Workbench worker."""

    item_id: str
    ordinal: int = Field(ge=0)
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_version: str
    files: list[FileRecord] = Field(min_length=1)
    completed_at: datetime = Field(default_factory=utc_now)


class ArtifactManifest(BaseModel):
    schema_version: Literal[1] = 1
    job_id: str
    work_unit_id: str
    files: list[FileRecord] = Field(default_factory=list)
    output_schema: str
    producer: dict[str, str] = Field(default_factory=dict)
    item_provenance: list[AtomicItemExecution] = Field(default_factory=list)
    atomic_results: list[AtomicResultManifest] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_atomic_results(self) -> "ArtifactManifest":
        item_ids = [item.item_id for item in self.atomic_results]
        ordinals = [item.ordinal for item in self.atomic_results]
        if len(item_ids) != len(set(item_ids)) or len(ordinals) != len(set(ordinals)):
            raise ValueError("atomic result manifests must have unique item IDs and ordinals")
        declared_files = {file.relative_path: file for file in self.files}
        for atomic in self.atomic_results:
            for file in atomic.files:
                declared = declared_files.get(file.relative_path)
                if declared is None or declared != file:
                    raise ValueError("atomic result file must exactly match the Unit manifest")
        return self

    def resumable_item_ids(self, *, config_sha256: str, runtime_version: str) -> set[str]:
        return {
            item.item_id
            for item in self.atomic_results
            if item.config_sha256 == config_sha256
            and item.runtime_version == runtime_version
            and item.files
        }


class ExecutionProfile(BaseModel):
    schema_version: Literal[1] = 1
    profile_id: str
    version: str
    executor_kind: str
    platforms: set[str] = Field(default_factory=lambda: {"windows"})
    required_capabilities: set[str] = Field(default_factory=set)
    output_schema: str
    allow_arbitrary_command: Literal[False] = False
    default_resources: ResourceRequest = Field(default_factory=ResourceRequest)


class ProjectGrant(BaseModel):
    schema_version: Literal[1] = 1
    project_id: str
    owner_user_id: str
    person_policy_inherited: bool = Field(default=False, exclude_if=lambda value: not value)
    # Kept inside the JSON grant payload so existing SQLite databases migrate
    # additively: old grants remain owner-authorized and new Agent identities
    # must be explicitly listed here.
    authorized_user_ids: set[str] = Field(default_factory=set)
    approved: bool = False
    status: ProjectStatus = ProjectStatus.PENDING
    frozen_reason: str = ""
    allowed_profiles: set[str] = Field(default_factory=set)
    trusted_machine_labels: set[str] = Field(default_factory=set)
    max_queued_units: int = Field(default=2000, ge=1)
    max_running_units: int = Field(default=4, ge=1)
    priority_ceiling: int = Field(default=0, ge=-100, le=100)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def normalize_legacy_status(self) -> "ProjectGrant":
        # Existing 0.12.x rows only carry ``approved``. Preserve their active
        # behavior while allowing 0.13 to represent pending/frozen projects.
        if "status" not in self.model_fields_set:
            self.status = (
                ProjectStatus.ACTIVE if self.approved else ProjectStatus.PENDING
            )
        self.approved = self.status == ProjectStatus.ACTIVE
        if self.status != ProjectStatus.FROZEN:
            self.frozen_reason = ""
        return self

    def authorizes(self, user_id: str) -> bool:
        return user_id == self.owner_user_id or user_id in self.authorized_user_ids

    def permits_submission(self, user_id: str) -> bool:
        return self.status == ProjectStatus.ACTIVE and self.authorizes(user_id)


class ProjectRegistrationRequest(BaseModel):
    schema_version: Literal[1] = 1
    registration_id: str = Field(default_factory=lambda: new_id("project-registration"))
    project_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    requested_by: str
    display_name: str = Field(min_length=1, max_length=160)
    purpose: str = Field(min_length=1, max_length=1000)
    requested_profiles: set[str] = Field(default_factory=set)
    status: ProjectRegistrationStatus = ProjectRegistrationStatus.REQUESTED
    reviewed_by: str | None = None
    review_reason: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class AccessRestriction(BaseModel):
    """Safe, actionable explanation for an unavailable operation."""

    reason_code: str
    current_state: str | None = None
    missing_roles: set[UserRole] = Field(default_factory=set)
    missing_project_grant: str | None = None
    missing_profile: str | None = None
    missing_capabilities: set[str] = Field(default_factory=set)
    quota: dict[str, int] = Field(default_factory=dict)
    next_action: str
    action_path: str | None = None
    requires: Literal["admin", "project_owner", "machine_owner", "member", "none"] = "none"
    message: str = "该功能存在，但当前身份/项目/机器尚未获得所需权限。"


class OriginAdapterRegistration(BaseModel):
    schema_version: Literal[1] = 1
    adapter_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    version: str
    contract_kind: Literal["partition-request-v2", "legacy-read-only"] = "partition-request-v2"
    allowed_profile_ids: set[str] = Field(default_factory=set)
    active: bool = True
    accepts_new_submissions: bool = True
    registered_by: str
    created_at: datetime = Field(default_factory=utc_now)


class OriginImportReceipt(BaseModel):
    """Immutable acknowledgement that an origin imported one completed Job.

    ``import_mode="complete"`` keeps the historical contract: the Job is
    completed and every WorkUnit has a registered manifest. ``import_mode=
    "partial"`` records a truthful partial import of a terminal Job whose
    remaining WorkUnits are not active; the Network derives and enforces the
    imported/missing WorkUnit ledger server-side.
    """

    schema_version: Literal[1] = 1
    job_id: str
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    dataset_id: str
    manifest_summary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_id: str | None = None
    campaign_task_id: str | None = None
    imported_by: str
    imported_at: datetime = Field(default_factory=utc_now)
    import_mode: Literal["complete", "partial"] = "complete"
    work_unit_count: int | None = Field(default=None, ge=0)
    imported_work_unit_ids: list[str] | None = None
    missing_work_unit_ids: list[str] | None = None


class TimeWindow(BaseModel):
    start: str = Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    end: str = Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")


class FullCpuOverride(BaseModel):
    """Explicit owner-authorized CPU oversubscription, independent of science review."""

    model_config = ConfigDict(extra="forbid")
    authorized_by: str = Field(min_length=1, max_length=160)
    reason: str = Field(min_length=1, max_length=2000)
    authorized_at: datetime
    # Omission preserves legacy policy hashes and full-machine behavior.
    max_threads_per_attempt: int | None = Field(
        default=None, ge=1, strict=True, exclude_if=lambda value: value is None,
    )

    @field_validator("authorized_by", "reason")
    @classmethod
    def validate_authorization_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("full CPU authorization requires a nonempty actor and reason")
        return value


class MachinePolicy(BaseModel):
    schema_version: Literal[1] = 1
    machine_id: str
    owner_user_id: str
    member_profile_grants: dict[str, set[str]] = Field(default_factory=dict, exclude_if=lambda value: not value)
    timezone: str = "Asia/Shanghai"
    weekly_windows: dict[int, list[TimeWindow]] = Field(default_factory=dict)
    owner_mode: MachineMode = MachineMode.PAUSED
    admin_mode_override: MachineMode | None = None
    admin_override_reason: str = ""
    admin_override_actor: str | None = None
    admin_override_at: datetime | None = None
    keyboard_idle_min_s: int = Field(default=1200, ge=0)
    non_pool_cpu_max_percent: float = Field(default=15.0, ge=0, le=100)
    cpu_window_s: int = Field(default=600, ge=1)
    memory_reserve_mb: int = Field(default=8192, ge=0)
    max_cpus: int = Field(default=1, ge=1)
    # Absent on legacy rows: never silently reclassify the existing fleet.
    shared_machine: bool = Field(default=False, strict=True)
    cpu_reserve_percent: int = Field(default=25, ge=25, le=100, strict=True)
    full_cpu_override: FullCpuOverride | None = None
    # Opt-in scheduling envelope, based only on comparable collected peaks.
    memory_peak_margin_percent: float | None = Field(
        default=None, ge=0, le=200, exclude_if=lambda value: value is None,
    )
    max_memory_mb: int = Field(default=8192, ge=256)
    max_gpus: int = Field(default=0, ge=0)
    max_concurrent_units: int = Field(default=1, ge=1)
    external_comsol_termination_authorized: bool = True
    external_comsol_consent_updated_by: str | None = None
    external_comsol_consent_updated_at: datetime | None = None
    # Invitation-specific AND gate; normal policy edits cannot remove or broaden it.
    member_execution_limit: MemberExecutionLimit | None = None
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("weekly_windows")
    @classmethod
    def validate_weekdays(cls, value: dict[int, list[TimeWindow]]) -> dict[int, list[TimeWindow]]:
        invalid = [day for day in value if day < 0 or day > 6]
        if invalid:
            raise ValueError(f"weekday keys must be 0..6, got {invalid}")
        return value

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown machine-policy timezone: {value}") from exc
        return value

    def effective_cpu_cap(self, total_cpus: int) -> int:
        """Hard scheduler thread budget, not an operating-system CPU-time quota."""
        total = max(0, int(total_cpus))
        cap = min(total, self.max_cpus)
        if self.shared_machine and self.full_cpu_override is None:
            reserve = max(25, min(100, self.cpu_reserve_percent))
            cap = min(cap, total * (100 - reserve) // 100)
        if self.member_execution_limit is not None:
            cap = min(cap, self.member_execution_limit.max_cpus)
        return max(0, cap)

    def effective_mode(self) -> MachineMode:
        return self.admin_mode_override or self.owner_mode


class GpuMetric(BaseModel):
    index: int = Field(ge=0)
    name: str
    utilization_percent: float | None = Field(default=None, ge=0, le=100)
    utilization_average_percent: float | None = Field(default=None, ge=0, le=100)
    utilization_5m_average_percent: float | None = Field(default=None, ge=0, le=100)
    utilization_peak_percent: float | None = Field(default=None, ge=0, le=100)
    utilization_p95_percent: float | None = Field(default=None, ge=0, le=100)
    busy_duty_cycle_percent: float | None = Field(default=None, ge=0, le=100)
    sample_count: int = Field(default=0, ge=0)
    memory_used_mb: int | None = Field(default=None, ge=0)
    memory_peak_mb: int | None = Field(default=None, ge=0)
    memory_total_mb: int | None = Field(default=None, ge=0)
    temperature_c: float | None = Field(default=None, ge=-50, le=150)
    available: bool = True
    sampling_quality: Literal["nvml", "nvidia-smi", "degraded", "unavailable"] = "degraded"


class ExternalLoadSnapshot(BaseModel):
    """Aggregated load from processes outside Network's own process tree.

    The generic fields are the source of truth.  The ``external_comsol_*``
    fields are retained as derived compatibility aliases for 0.13.0 clients
    and persisted observations; they are never used by capacity policy.
    """

    schema_version: Literal[1] = 1
    state: PressureState = PressureState.NORMAL
    external_process_count: int = Field(default=0, ge=0)
    external_cpu_percent: float = Field(default=0.0, ge=0, le=100)
    external_memory_mb: int = Field(default=0, ge=0)
    external_gpu_utilization_percent: float = Field(default=0.0, ge=0, le=100)
    process_set_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    attribution_quality: Literal["complete", "partial", "degraded", "unavailable"] = "unavailable"
    unattributed_cpu_percent: float = Field(default=0.0, ge=0, le=100)
    unattributed_memory_mb: int = Field(default=0, ge=0)
    reason_codes: list[str] = Field(default_factory=list)
    candidate_since: datetime | None = None
    pressured_since: datetime | None = None
    cleared_at: datetime | None = None
    reason: str = "no external load pressure"
    observed_at: datetime = Field(default_factory=utc_now)

    # 0.13.0 compatibility aliases.  Despite the historical name, these carry
    # the WHOLE non-Network process aggregate (browser, IDE, input method,
    # ...), NOT only COMSOL.  They are deliberately not referenced by
    # capacity.py and exist only so old agents keep reading the API.  New
    # consumers must use the generic external_process_count /
    # external_cpu_percent / external_memory_mb fields.  Diagnosis guidance:
    # docs/operations-runbook.zh.md section S4.
    external_comsol_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Deprecated 0.13.0 alias of external_process_count: the aggregate "
            "over ALL non-Network processes, not only COMSOL."
        ),
    )
    external_comsol_cpu_percent: float = Field(
        default=0.0,
        ge=0,
        le=100,
        description="Deprecated 0.13.0 alias of external_cpu_percent.",
    )
    external_comsol_memory_mb: int = Field(
        default=0,
        ge=0,
        description="Deprecated 0.13.0 alias of external_memory_mb.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_payload(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        aliases = {
            "external_process_count": "external_comsol_count",
            "external_cpu_percent": "external_comsol_cpu_percent",
            "external_memory_mb": "external_comsol_memory_mb",
        }
        legacy_payload = any(key in data for key in aliases.values())
        for generic, legacy in aliases.items():
            if legacy in data and (
                generic not in data
                or (data.get(generic) in (None, 0, 0.0, "") and data.get(legacy) not in (None, 0, 0.0, ""))
            ):
                data[generic] = data[legacy]
        if legacy_payload and "attribution_quality" not in data:
            # 0.13.0 agents did not report attribution quality.  Treat their
            # process sample as partial evidence so the old CPU/GPU pressure
            # behaviour remains readable while new degraded samples warn only.
            data["attribution_quality"] = "partial"
        if "reason" not in data and any(key in data for key in aliases.values()):
            data["reason"] = "legacy external load observation; policy applied by Control Plane"
        return data

    @model_validator(mode="after")
    def derive_legacy_aliases(self) -> "ExternalLoadSnapshot":
        self.external_comsol_count = self.external_process_count
        self.external_comsol_cpu_percent = self.external_cpu_percent
        self.external_comsol_memory_mb = self.external_memory_mb
        return self


class ExternalPressureSnapshot(ExternalLoadSnapshot):
    """Compatibility name for the generic external-load snapshot."""


class PressurePolicySettings(BaseModel):
    """Administrator-managed thresholds for external-load capacity reduction.

    "External" means every non-Network process on the machine (the owner's own
    work included); the COMSOL-specific naming is historical.
    """

    # CPU and GPU thresholds must stay symmetric: the original asymmetric CPU
    # default of 10% derated owner-active desktop machines during normal use
    # because typical interactive load already sits
    # above 10%. Production settings persist their own values; this default
    # only applies to fresh installations.
    external_cpu_threshold_percent: float = Field(default=40.0, ge=0, le=100)
    external_gpu_threshold_percent: float = Field(default=40.0, ge=0, le=100)
    memory_mode: Literal["resource_gate_only", "low_headroom", "absolute"] = "resource_gate_only"
    external_memory_threshold_mb: int = Field(default=4096, ge=0)
    available_memory_floor_mb: int = Field(default=8192, ge=0)
    enter_after_seconds: int = Field(default=30, ge=0, le=3600)
    clear_after_seconds: int = Field(default=120, ge=0, le=7200)
    pressured_dispatch_cap: int = Field(default=1, ge=0, le=64)
    telemetry_stale_cap: int = Field(default=1, ge=0, le=1)
    # A single late telemetry sample (a busy supervisor under full load) must
    # not flap capacity down to the stale cap and back every few seconds.
    # Within this grace window the machine keeps its normal capacity; beyond
    # it, the stale cap applies as before.
    telemetry_stale_grace_s: int = Field(default=180, ge=0, le=3600)
    max_override_minutes: int = Field(default=30, ge=1, le=120)


class TelemetryPolicySettings(BaseModel):
    """Administrator-visible sampling policy shared by supervisors."""

    sample_interval_s: int = Field(default=1, ge=1, le=60)
    cpu_sample_window_s: int = Field(default=60, ge=1, le=300)
    peak_window_s: int = Field(default=300, ge=1, le=900)
    sample_timeout_s: int = Field(default=8, ge=1, le=30)
    stale_after_s: int = Field(default=45, ge=5, le=3600)
    external_process_names: list[str] = Field(
        default_factory=lambda: ["comsol", "mphserver", "comsol server"],
        min_length=1,
        max_length=32,
    )

    @field_validator("external_process_names")
    @classmethod
    def validate_external_process_names(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().lower() for value in values]
        if any(not value or len(value) > 128 for value in normalized):
            raise ValueError("external process names must be non-empty and at most 128 characters")
        if len(normalized) != len(set(normalized)):
            raise ValueError("external process names must be unique")
        return normalized


class AttemptResourceUsage(BaseModel):
    work_unit_id: str
    peak_memory_mb: int = Field(default=0, ge=0)
    output_bytes: int = Field(default=0, ge=0)
    active_processes: int = Field(default=0, ge=0)


class ExecutionDiskVolume(BaseModel):
    # Only purpose and volume identifier leave the worker, never user paths.
    role: Literal["work_root", "temp", "tmp", "comsol_user", "comsol_tmp"]
    volume: str = Field(pattern=r"^[A-Z]:$")
    free_mb: int = Field(ge=0)


class ExecutionDiskSnapshot(BaseModel):
    source: Literal["ssh-worker-default-volumes"] = "ssh-worker-default-volumes"
    observed_at: datetime
    available: bool = False
    volumes: list[ExecutionDiskVolume] = Field(default_factory=list)
    reason_code: Literal["", "disk_probe_unavailable"] = ""
    # Control-plane-derived hysteresis; never a machine policy override.
    blocked: bool = False
    clear_since: datetime | None = None


class MachineMetrics(BaseModel):
    cpu_total_percent: float = Field(default=0.0, ge=0, le=100)
    cpu_current_percent: float | None = Field(default=None, ge=0, le=100)
    cpu_average_percent: float | None = Field(default=None, ge=0, le=100)
    cpu_peak_percent: float | None = Field(default=None, ge=0, le=100)
    network_cpu_percent: float | None = Field(default=None, ge=0, le=100)
    external_cpu_percent: float | None = Field(default=None, ge=0, le=100)
    cpu_attribution_quality: Literal[
        "job_object", "process_tree", "degraded", "unavailable"
    ] = "unavailable"
    keyboard_idle_s: int = Field(default=0, ge=0)
    non_pool_cpu_percent: float = Field(default=100.0, ge=0, le=100)
    memory_used_mb: int = Field(default=0, ge=0)
    total_memory_mb: int = Field(default=0, ge=0)
    available_memory_mb: int = Field(default=0, ge=0)
    disk_used_mb: int = Field(default=0, ge=0)
    total_disk_mb: int = Field(default=0, ge=0)
    free_disk_mb: int = Field(default=0, ge=0)
    execution_disk: ExecutionDiskSnapshot | None = None
    running_units: int = Field(default=0, ge=0)
    gpu: list[GpuMetric] = Field(default_factory=list)
    external_load: ExternalLoadSnapshot = Field(default_factory=ExternalLoadSnapshot)
    external_process_set_hash: str | None = None
    external_process_count: int = Field(default=0, ge=0)
    external_pressure: ExternalPressureSnapshot = Field(default_factory=ExternalPressureSnapshot)
    external_comsol_process_set_hash: str | None = None
    external_comsol_process_count: int = Field(default=0, ge=0)
    attempt_resource_usage: list[AttemptResourceUsage] = Field(default_factory=list)
    available: bool = True
    unavailable_reasons: list[str] = Field(default_factory=list)
    source: str = "unknown"
    observed_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="before")
    @classmethod
    def normalize_external_load(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if "external_pressure" in data:
            # Both names can be present in a 0.13.x payload.  The pressure
            # object is the legacy wire view of the same timestamped sample;
            # prefer it here so a model_copy/update cannot leave a stale zero
            # valued external_load alongside a fresh pressure payload.
            data["external_load"] = data["external_pressure"]
        if "external_process_count" not in data:
            legacy_count = data.get("external_comsol_process_count")
            if legacy_count is not None:
                data["external_process_count"] = legacy_count
        if "external_process_set_hash" not in data:
            legacy_hash = data.get("external_comsol_process_set_hash")
            if legacy_hash is not None:
                data["external_process_set_hash"] = legacy_hash
        if "external_process_count" not in data and "external_pressure" in data:
            pressure = data["external_pressure"]
            if isinstance(pressure, dict) and "external_comsol_count" in pressure:
                data["external_process_count"] = pressure["external_comsol_count"]
        return data

    @model_validator(mode="after")
    def derive_external_load_aliases(self) -> "MachineMetrics":
        if (
            self.external_pressure.external_process_count > self.external_load.external_process_count
            or self.external_pressure.external_cpu_percent > self.external_load.external_cpu_percent
            or self.external_pressure.process_set_hash != self.external_load.process_set_hash
        ):
            self.external_load = ExternalLoadSnapshot.model_validate(
                self.external_pressure.model_dump(mode="python")
            )
        # The top-level generic fields are retained as a compatibility view of
        # the snapshot.  Do not overwrite an explicitly supplied legacy value
        # before observation consistency checks have had a chance to reject a
        # contradictory payload.
        if self.external_process_count == 0 and self.external_load.external_process_count:
            self.external_process_count = self.external_load.external_process_count
        if self.external_process_set_hash is None:
            self.external_process_set_hash = self.external_load.process_set_hash
        self.external_pressure = ExternalPressureSnapshot.model_validate(
            self.external_load.model_dump(mode="python")
        )
        if self.external_comsol_process_count == 0 and self.external_process_count:
            self.external_comsol_process_count = self.external_process_count
        if self.external_comsol_process_set_hash is None:
            self.external_comsol_process_set_hash = self.external_process_set_hash
        return self


class MachineState(BaseModel):
    schema_version: Literal[1] = 1
    machine_id: str
    owner_user_id: str
    hostname: str
    platform: str = "windows"
    labels: set[str] = Field(default_factory=set)
    capabilities: set[str] = Field(default_factory=set)
    total_cpus: int = Field(ge=1)
    total_memory_mb: int = Field(ge=256)
    total_gpus: int = Field(default=0, ge=0)
    package_version: str = "0.11.0"
    runtime_version: str | None = None
    protocol_version: str = "1"
    capability_report: dict[str, Any] = Field(default_factory=dict)
    metrics: MachineMetrics = Field(default_factory=MachineMetrics)
    applied_telemetry_policy: TelemetryPolicySettings | None = None
    applied_telemetry_policy_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    last_heartbeat_at: datetime = Field(default_factory=utc_now)


class MachineHeartbeat(BaseModel):
    schema_version: Literal[1] = 1
    machine_id: str
    metrics: MachineMetrics
    running_work_unit_ids: list[str] = Field(default_factory=list)
    # Optional for legacy agents; SSH supervisors provide this identity from
    # their sealed status file so the control plane can attest the running runtime.
    runtime_version: str | None = None
    supervisor_reported_concurrent_units: int | None = Field(default=None, ge=0, le=64)
    applied_telemetry_policy: TelemetryPolicySettings | None = None
    applied_telemetry_policy_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )


class PressureOverrideTicket(BaseModel):
    schema_version: Literal[1] = 1
    ticket_id: str = Field(default_factory=lambda: new_id("pressure-override"))
    machine_id: str
    issued_by: str
    reason: str = Field(min_length=1, max_length=500)
    confirmation_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_until: datetime
    requested_concurrent_units: int | None = Field(default=None, ge=1)
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime


class AdminOperation(StrEnum):
    CANCEL_JOB = "cancel_job"
    RETRY_JOB = "retry_job"
    CANCEL_UNIT = "cancel_unit"
    RETRY_UNIT = "retry_unit"


class AdminOperationTicket(BaseModel):
    schema_version: Literal[1] = 1
    ticket_id: str = Field(default_factory=lambda: new_id("admin-operation"))
    action: AdminOperation
    job_id: str
    work_unit_id: str | None = None
    reason: str = Field(default="", max_length=500)
    expected_revision: int = Field(ge=0)
    impact: dict[str, Any] = Field(default_factory=dict)
    confirmation_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_by: str
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime


class MetricSample(BaseModel):
    schema_version: Literal[1] = 1
    sample_id: str
    machine_id: str
    sample_kind: Literal["raw", "minute"]
    metrics: MachineMetrics
    recorded_at: datetime = Field(default_factory=utc_now)


class ChannelObservation(BaseModel):
    """Control-plane evidence, not a new Worker heartbeat contract."""

    observed_at: datetime
    transport_state: TransportState = TransportState.UNKNOWN
    supervisor_at: datetime | None = None
    metric_at: datetime | None = None
    healthy: bool = False
    consecutive_successes: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    ready: bool = False


class MachineOperationalStatus(BaseModel):
    schema_version: Literal[1] = 1
    machine_id: str
    connection_evidence: dict[Literal["ssh", "outbound"], ChannelObservation] = Field(default_factory=dict)
    transport_state: TransportState = TransportState.UNKNOWN
    supervisor_state: SupervisorState = SupervisorState.UNAVAILABLE
    telemetry_state: TelemetryState = TelemetryState.UNAVAILABLE
    control_state: ControlState = ControlState.EXECUTOR_UNAVAILABLE
    last_checked_at: datetime | None = None
    last_supervisor_heartbeat_at: datetime | None = None
    last_metric_at: datetime | None = None
    telemetry_source: str = "unknown"
    detail: str = ""
    consecutive_successes: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    heartbeat_phase: HeartbeatPhase = HeartbeatPhase.OFFLINE
    pressure_state: PressureState = PressureState.NORMAL
    effective_comsol_concurrency: int | None = Field(default=None, ge=0)
    capacity_reason: str = ""
    capacity_decision_at: datetime | None = None
    supervisor_reported_concurrent_units: int | None = Field(default=None, ge=0, le=64)
    capacity_drift: bool = False
    capacity_drift_reason: str = ""
    pressure_override_until: datetime | None = None
    pressure_override_reason: str = ""
    pressure_override_actor: str | None = None
    pressure_override_hash: str | None = None
    pressure_override_concurrency: int | None = Field(default=None, ge=1)
    effective_capacity: int | None = Field(default=None, ge=0)
    external_process_set_hash: str | None = None
    external_process_count: int = Field(default=0, ge=0)
    capacity_reason_codes: list[str] = Field(default_factory=list)
    external_comsol_process_set_hash: str | None = None
    external_comsol_process_count: int = Field(default=0, ge=0)
    observation_consistent: bool = True
    observation_issues: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_capacity_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if "external_process_count" not in data and "external_comsol_process_count" in data:
            data["external_process_count"] = data["external_comsol_process_count"]
        if "external_process_set_hash" not in data and "external_comsol_process_set_hash" in data:
            data["external_process_set_hash"] = data["external_comsol_process_set_hash"]
        if "effective_capacity" not in data and "effective_comsol_concurrency" in data:
            data["effective_capacity"] = data["effective_comsol_concurrency"]
        return data

    @model_validator(mode="before")
    @classmethod
    def derive_legacy_heartbeat_phase(cls, value: Any) -> Any:
        if isinstance(value, dict) and value.get("heartbeat_phase") is None:
            value = dict(value)
            supervisor = value.get("supervisor_state")
            telemetry = value.get("telemetry_state")
            transport = value.get("transport_state")
            if supervisor == "online" and telemetry == "live":
                value["heartbeat_phase"] = HeartbeatPhase.HEALTHY
            elif supervisor == "stale" or telemetry == "stale":
                value["heartbeat_phase"] = HeartbeatPhase.STALE
            elif transport == "connected":
                value["heartbeat_phase"] = HeartbeatPhase.DELAYED
            else:
                value["heartbeat_phase"] = HeartbeatPhase.OFFLINE
        return value


class MachineControlTarget(BaseModel):
    machine_id: str
    requested_mode: MachineMode | None = None
    target_concurrent_units: int | None = Field(default=None, ge=0)
    hard_capacity_units: int | None = Field(default=None, ge=1, le=64, exclude_if=lambda value: value is None)
    acceptance_reference: str | None = Field(default=None, max_length=500, exclude_if=lambda value: value is None)


class MachineControlTicket(BaseModel):
    schema_version: Literal[1] = 1
    ticket_id: str = Field(default_factory=lambda: new_id("machine-control"))
    action: MachineControlAction
    targets: list[MachineControlTarget] = Field(min_length=1)
    reason: str = Field(default="", max_length=500)
    expected_fingerprints: dict[str, str]
    impact: dict[str, dict[str, Any]] = Field(default_factory=dict)
    confirmation_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    requires_break_glass: bool = False
    issued_by: str
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime


class ControlTargetResult(BaseModel):
    machine_id: str
    state: ControlTargetState = ControlTargetState.PENDING
    message: str = ""
    command_id: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)


class ControlOperationRun(BaseModel):
    schema_version: Literal[1] = 1
    operation_id: str = Field(default_factory=lambda: new_id("control-operation"))
    ticket_id: str
    action: MachineControlAction | DispatcherControlAction
    state: ControlOperationState = ControlOperationState.ACCEPTED
    requested_by: str
    reason: str = ""
    request_targets: list[MachineControlTarget] = Field(default_factory=list)
    impact: dict[str, dict[str, Any]] = Field(default_factory=dict)
    targets: list[ControlTargetResult] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class MachineCommand(BaseModel):
    schema_version: Literal[1] = 1
    command_id: str = Field(default_factory=lambda: new_id("machine-command"))
    machine_id: str
    action: MachineControlAction
    root_uuid: str
    runtime_version: str
    nonce: str
    reason: str = ""
    expected_process_set_hash: str | None = None
    target_concurrent_units: int | None = Field(default=None, ge=0)
    hard_capacity_units: int | None = Field(default=None, ge=1, le=64)
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime


class MachineCommandResult(BaseModel):
    schema_version: Literal[1] = 1
    command_id: str
    machine_id: str
    action: MachineControlAction
    state: ControlTargetState
    affected_network_runs: int = Field(default=0, ge=0)
    affected_comsol_processes: int = Field(default=0, ge=0)
    process_set_hash: str | None = None
    message: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class DispatcherControlTicket(BaseModel):
    schema_version: Literal[1] = 1
    ticket_id: str = Field(default_factory=lambda: new_id("dispatcher-control"))
    action: DispatcherControlAction
    reason: str = Field(default="", max_length=500)
    expected_fingerprint: str
    impact: dict[str, Any] = Field(default_factory=dict)
    confirmation_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_by: str
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime


class BreakGlassConfig(BaseModel):
    schema_version: Literal[1] = 1
    config_id: Literal["global"] = "global"
    salt_hex: str = Field(pattern=r"^[0-9a-f]{32,}$")
    digest_hex: str = Field(pattern=r"^[0-9a-f]{64,}$")
    n: int = Field(default=32768, ge=16384)
    r: int = Field(default=8, ge=1)
    p: int = Field(default=1, ge=1)
    active: bool = True
    updated_at: datetime = Field(default_factory=utc_now)


class AlertRecord(BaseModel):
    schema_version: Literal[1] = 1
    alert_id: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.ACTIVE
    subject_type: str
    subject_id: str
    kind: str
    message: str
    reason: str = ""
    occurrence_count: int = Field(default=1, ge=1)
    first_seen_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    snoozed_until: datetime | None = None
    resolved_at: datetime | None = None


class DatasetMetadata(BaseModel):
    schema_version: Literal[1] = 1
    dataset_id: Literal["global"] = "global"
    mode: Literal["formal", "demo"]
    updated_at: datetime = Field(default_factory=utc_now)


class DemoCleanupPreview(BaseModel):
    schema_version: Literal[1] = 1
    confirmation_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    counts: dict[str, int] = Field(default_factory=dict)
    object_ids: dict[str, list[str]] = Field(default_factory=dict)


class FeatureSettings(BaseModel):
    schema_version: Literal[1] = 1
    settings_id: Literal["global"] = "global"
    visibility: FeatureVisibility = FeatureVisibility.FULL
    show_group_job_details: bool = True
    show_machine_details: bool = True
    allow_owner_controls: bool = True
    allow_admin_settings: bool = True
    pressure_policy: PressurePolicySettings = Field(default_factory=PressurePolicySettings)
    telemetry_policy: TelemetryPolicySettings = Field(default_factory=TelemetryPolicySettings)
    resource_policies: dict[str, ResourcePolicy] = Field(default_factory=dict)
    scheduling_policy: SchedulingPolicy | None = Field(default=None, exclude_if=lambda value: value is None)
    scheduling_revision: int = Field(default=0, ge=0, exclude_if=lambda value: value == 0)
    scheduling_confirmation: str | None = Field(default=None, exclude_if=lambda value: value is None)
    updated_at: datetime = Field(default_factory=utc_now)


class AcceptanceCheck(BaseModel):
    check_id: str
    label: str
    status: AcceptanceStatus = AcceptanceStatus.PENDING
    message: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)


class MachineOnboardingProfile(BaseModel):
    """Non-secret, reviewed defaults for one planned worker."""

    schema_version: Literal[1] = 1
    machine_id: str
    owner_user_id: str
    order: int = Field(ge=0)
    expected_hostname: str
    ssh_host: str = "localhost"
    ssh_port: int = Field(ge=1, le=65535)
    ssh_user: str
    proposed_root: str
    max_cpus: int = Field(ge=1)
    max_memory_mb: int = Field(ge=256)
    memory_reserve_mb: int = Field(default=12288, ge=0)
    max_gpus: int = Field(default=0, ge=0)
    target_concurrent_units: int = Field(default=1, ge=1)
    disk_reserve_gib: int = Field(default=10, ge=1)
    python_executable: str | None = None
    comsol_root: str | None = None
    legacy_worker_path: str | None = None
    persistent_warnings: list[str] = Field(default_factory=list)


class MachinePreflightRun(BaseModel):
    """Sanitized evidence from a strictly read-only remote inspection."""

    schema_version: Literal[1] = 1
    run_id: str = Field(default_factory=lambda: new_id("ssh-preflight"))
    machine_id: str
    stage: OnboardingStage = OnboardingStage.PLANNED
    status: AcceptanceStatus = AcceptanceStatus.PENDING
    readiness: DeploymentReadiness = DeploymentReadiness.BLOCKED
    expected_hostname: str
    observed_hostname: str | None = None
    proposed_root: str
    host_key_fingerprint: str | None = None
    checks: list[AcceptanceCheck] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    report_path: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class MachineExecutionConfig(BaseModel):
    schema_version: Literal[1] = 1
    machine_id: str
    transport: Literal["ssh"] = "ssh"
    ssh_host: str = "localhost"
    ssh_port: int = Field(default=2222, ge=1, le=65535)
    ssh_user: str = "rcn-worker"
    # Optional center transport deadlines; absent legacy configs keep the
    # established 5s connection and 20s supervisor-status deadlines.
    ssh_connect_timeout_s: int | None = Field(
        default=None, ge=1, le=30, strict=True, exclude_if=lambda value: value is None,
    )
    ssh_status_timeout_s: int | None = Field(
        default=None, ge=20, le=120, strict=True, exclude_if=lambda value: value is None,
    )
    pinned_host_key: str = ""
    remote_root: str = r"D:\ResearchComputeNetwork"
    python_executable: str = "python.exe"
    comsol_root: str = ""
    comsol_version: str = "6.4"
    disk_reserve_gib: int = Field(default=10, ge=1)
    c_drive_reserve_gib: int = Field(default=10, ge=1)
    success_retention_days: int = Field(default=3, ge=0)
    failure_retention_days: int = Field(default=7, ge=0)
    max_concurrent_units: int = Field(default=1, ge=1)
    target_concurrent_units: int = Field(default=1, ge=0)
    accepted_hard_capacity_units: int | None = Field(default=None, ge=1, le=64)
    hard_capacity_pending_acceptance: bool = False
    hard_capacity_forced_by: str | None = None
    hard_capacity_forced_at: datetime | None = None
    hard_capacity_force_reason: str = ""
    hard_capacity_acceptance_reference: str | None = None
    hard_capacity_accepted_by: str | None = None
    hard_capacity_accepted_at: datetime | None = None
    profile_concurrency_limits: dict[str, int] = Field(default_factory=dict)
    telemetry_policy: TelemetryPolicySettings = Field(default_factory=TelemetryPolicySettings)
    poll_interval_s: int = Field(default=15, ge=5, le=300)
    enabled: bool = False
    operational_execution: Literal["pending", "passed", "failed"] = "pending"
    conditional_production: Literal["disabled", "enabled"] = "disabled"
    startup_after_reboot: Literal["pending", "passed", "failed"] = "pending"
    numeric_equivalence: Literal["pending", "passed", "warning", "failed"] = "pending"
    capability_warnings: list[str] = Field(default_factory=list)
    execution_provenance: dict[str, str] = Field(default_factory=dict)
    supervisor_startup: Literal["manual", "logon", "boot"] = "manual"
    tunnel_startup: Literal["manual", "logon", "boot"] = "manual"
    coordinator_host: str = "127.0.0.1"
    coordinator_port: int = Field(default=22, ge=1, le=65535)
    coordinator_user: str = "rcn-coordinator"
    reverse_forward_host: str = "127.0.0.1"
    reverse_forward_port: int = Field(default=2222, ge=1, le=65535)
    tunnel_task_name: str = "ResearchComputeNetwork-ReverseSSH"
    # Non-secret references used by the supervisor's independent heartbeat.
    # The token contents remain on the worker and are never persisted here.
    control_plane_heartbeat_url: str | None = None
    machine_token_file: str | None = None
    scientific_model_retirement_enabled: bool = Field(
        default=False, strict=True, exclude_if=lambda value: value is False,
    )
    root_uuid: str | None = None
    runtime_version: str | None = None
    # Expected Windows identity and legacy worker location are onboarding
    # metadata, not credentials.  They let the SSH acceptance harness operate
    # on any registered worker without assuming a particular account.
    expected_hostname: str | None = None

    legacy_worker_path: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="before")
    @classmethod
    def default_target_to_execution_cap(cls, value: Any) -> Any:
        """Preserve the effective capacity of execution configs written before 0.8."""
        if isinstance(value, dict) and value.get("target_concurrent_units") is None:
            value = dict(value)
            value["target_concurrent_units"] = value.get("max_concurrent_units", 1)
        if isinstance(value, dict) and value.get("accepted_hard_capacity_units") is None:
            value = dict(value)
            value["accepted_hard_capacity_units"] = value.get("max_concurrent_units", 1)
        return value

    @field_validator("profile_concurrency_limits")
    @classmethod
    def validate_profile_concurrency_limits(cls, value: dict[str, int]) -> dict[str, int]:
        if any(not profile_id.strip() for profile_id in value):
            raise ValueError("profile concurrency limit keys must not be blank")
        invalid = {profile_id: limit for profile_id, limit in value.items() if limit < 1}
        if invalid:
            raise ValueError(f"profile concurrency limits must be at least 1, got {invalid}")
        return value


class RemoteRunRecord(BaseModel):
    schema_version: Literal[1] = 1
    external_run_id: str
    machine_id: str
    job_id: str
    work_unit_id: str
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: RemoteRunState = RemoteRunState.STAGED
    remote_relative_path: str
    progress_percent: float = Field(default=0.0, ge=0, le=100)
    completed_items: int | None = Field(default=None, ge=0)
    total_items: int | None = Field(default=None, ge=1)
    eta_s: float | None = Field(default=None, ge=0)
    solver_variant: SolverVariant | None = None
    message: str = ""
    artifacts_available: bool = False
    failure_class: FailureClass | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class CleanupCandidate(BaseModel):
    relative_path: str
    outcome: Literal["success", "failed"]
    eligible_at: datetime
    size_bytes: int = Field(default=0, ge=0)
    root_uuid: str
    run_marker_valid: bool = False


class SshAcceptanceRun(BaseModel):
    schema_version: Literal[1] = 1
    run_id: str = Field(default_factory=lambda: new_id("ssh-acceptance"))
    status: AcceptanceStatus = AcceptanceStatus.PENDING
    coordinator_hostname: str = ""
    worker_id: str = ""
    worker_hostname: str = ""
    remote_root: str = r"D:\ResearchComputeNetwork"
    concurrency_levels: list[int] = Field(default_factory=lambda: [1, 2, 3])
    checks: list[AcceptanceCheck] = Field(default_factory=list)
    external_run_ids: list[str] = Field(default_factory=list)
    report_path: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ApprovalRecord(BaseModel):
    schema_version: Literal[1] = 1
    approval_id: str = Field(default_factory=lambda: new_id("approval"))
    machine_id: str
    scope: ApprovalScope
    subject_id: str
    approved_by: str
    active: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or utc_now()
        return self.active and (self.expires_at is None or self.expires_at > current)


class SolverMeshPolicy(BaseModel):
    """Exact reviewed mesh behavior bound into a solver approval."""

    mode: Literal["auto_size", "template_features"]
    mesh_tag: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    size: str | None = None

    @model_validator(mode="after")
    def validate_mode(self) -> "SolverMeshPolicy":
        if self.mode == "auto_size" and not self.size:
            raise ValueError("auto_size MeshPolicy requires a size")
        if self.mode == "template_features" and self.size is not None:
            raise ValueError("template_features MeshPolicy cannot specify a size")
        return self


class SolverCompatibilityApproval(BaseModel):
    """Human approval for solver interchangeability under one exact fingerprint."""

    schema_version: Literal[1] = 1
    approval_id: str = Field(default_factory=lambda: new_id("solver-approval"))
    project_id: str
    execution_profile_id: str
    comsol_version: str
    runtime_version: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
    )
    runtime_predecessor_approval_id: str | None = None
    runtime_equivalence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    template_role: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    allowed_study_kinds: set[ComsolStudyKind] = Field(default_factory=set)
    template_hash_policy: Literal["exact", "warn_on_change"] = "exact"
    mesh_policy: SolverMeshPolicy | None = None
    solver_variants: set[SolverVariant] = Field(
        default_factory=lambda: {SolverVariant.MUMPS, SolverVariant.CUDSS}
    )
    fingerprint: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    approved_by: str
    active: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def populate_fingerprint(self) -> "SolverCompatibilityApproval":
        from .hashing import sha256_value

        if bool(self.runtime_predecessor_approval_id) != bool(self.runtime_equivalence_sha256):
            raise ValueError("runtime successor approval requires both a predecessor and equivalence evidence hash")
        if self.runtime_predecessor_approval_id == self.approval_id:
            raise ValueError("runtime successor cannot name itself as predecessor")
        is_template_build = self.execution_profile_id == "workbench-comsol-template-build-v1"
        is_saved_readout = self.execution_profile_id == "workbench-comsol-saved-readout-v1"
        if is_saved_readout and self.solver_variants != {SolverVariant.MUMPS}:
            raise ValueError("saved readout approval must preserve the MUMPS source lineage")
        if is_template_build and self.solver_variants != {SolverVariant.MUMPS}:
            raise ValueError("template construction approval must preserve the MUMPS source flow")
        if not (is_template_build or is_saved_readout) and self.solver_variants != {SolverVariant.MUMPS, SolverVariant.CUDSS}:
            raise ValueError("the initial solver approval must cover exactly MUMPS and cuDSS")
        structured_mesh_profiles = {
            "workbench-comsol-eigen-v3",
            "workbench-comsol-eigen-v4",
            "workbench-comsol-frequency-v2",
            "workbench-comsol-study-v1",
            "workbench-comsol-study-v2",
            "workbench-comsol-template-build-v1",
        }
        if self.execution_profile_id in structured_mesh_profiles and self.mesh_policy is None:
            raise ValueError("structured COMSOL Profiles require an approved MeshPolicy")
        if self.execution_profile_id in {"workbench-comsol-study-v1", "workbench-comsol-study-v2"}:
            if not self.template_role or not self.allowed_study_kinds or not self.runtime_version:
                raise ValueError(
                    "generic COMSOL approvals require a template role, Study kinds, and runtime version"
                )
        if is_template_build:
            from .remote_agent.template_build_contracts import (
                TEMPLATE_BUILD_MESH_POLICY, TEMPLATE_BUILD_PRESETS,
                template_build_preset_contract,
            )
            registered_sources = {
                (registered["template_role"], registered["template_sha256"])
                for preset in TEMPLATE_BUILD_PRESETS
                for registered in [template_build_preset_contract(preset)]
            }
            if (not self.runtime_version or self.allowed_study_kinds
                    or (self.template_role, self.template_sha256) not in registered_sources
                    or self.template_hash_policy != "exact"
                    or self.comsol_version != "6.4"
                    or self.mesh_policy.model_dump(mode="json", exclude_none=True) != TEMPLATE_BUILD_MESH_POLICY):
                raise ValueError("template construction approval requires the exact source, mesh and runtime with zero Studies")
        if is_saved_readout:
            from .remote_agent.saved_readout_contracts import saved_readout_source_contract
            registered = saved_readout_source_contract(self.template_role, self.template_sha256)
            if (not self.runtime_version or self.allowed_study_kinds
                    or self.template_role != registered["template_role"]
                    or self.template_sha256 != registered["template_sha256"]
                    or self.template_hash_policy != "exact"
                    or self.comsol_version != "6.4" or self.mesh_policy is not None):
                raise ValueError("saved readout approval requires the exact source and runtime with zero Studies and no mesh operation")
        fingerprint_payload = {
            "project_id": self.project_id,
            "execution_profile_id": self.execution_profile_id,
            "comsol_version": self.comsol_version,
            "template_sha256": self.template_sha256,
            "solver_variants": sorted(variant.value for variant in self.solver_variants),
        }
        # Preserve the historical fingerprint exactly for legacy approvals.
        if self.mesh_policy is not None:
            fingerprint_payload["mesh_policy"] = self.mesh_policy.model_dump(mode="json")
        if self.template_role is not None:
            fingerprint_payload["template_role"] = self.template_role
        if self.allowed_study_kinds:
            fingerprint_payload["allowed_study_kinds"] = sorted(
                kind.value for kind in self.allowed_study_kinds
            )
        if self.template_hash_policy != "exact":
            fingerprint_payload["template_hash_policy"] = self.template_hash_policy
        if self.runtime_version is not None:
            fingerprint_payload["runtime_version"] = self.runtime_version
        if self.runtime_predecessor_approval_id is not None:
            fingerprint_payload["runtime_predecessor_approval_id"] = self.runtime_predecessor_approval_id
            fingerprint_payload["runtime_equivalence_sha256"] = self.runtime_equivalence_sha256
        expected = sha256_value(fingerprint_payload)
        if self.fingerprint and self.fingerprint != expected:
            raise ValueError("solver compatibility fingerprint does not match its bound configuration")
        self.fingerprint = expected
        return self

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or utc_now()
        return self.active and (self.expires_at is None or self.expires_at > current)


class AttemptAbandonmentRecord(BaseModel):
    """Administrator's permanent decision to discard one original Attempt."""

    operation_id: str
    actor_id: str
    reason: str
    abandoned_at: datetime
    expected_attempt_id: str
    expected_external_run_id: str | None


class WorkUnitAttempt(BaseModel):
    """One immutable launch attempt for a migratable work unit."""

    attempt_id: str
    machine_id: str | None = None
    external_run_id: str | None = None
    state: Literal[
        "assigned",
        "submitting",
        "running",
        "cancel_pending",
        "reconcile_pending",
        "uncertain",
        "collecting",
        "completed",
        "failed",
        "cancelled",
        "abandoned",
    ] = "assigned"
    abandonment: AttemptAbandonmentRecord | None = Field(default=None, exclude_if=lambda value: value is None)
    started_at: datetime | None = None
    # Scheduler handoff is distinct from actual solver start. A standby can
    # occupy a slot while the worker is still preparing its Job Object.
    assigned_at: datetime | None = None
    activation_requested_at: datetime | None = None
    activation_retry_count: int = Field(default=0, ge=0, le=3)
    finished_at: datetime | None = None
    execution_end_observed_at: datetime | None = Field(default=None, exclude_if=lambda value: value is None)
    last_observed_at: datetime | None = None
    cancel_requested_at: datetime | None = None
    collected_at: datetime | None = None
    failure_reason: str | None = None
    failure_class: FailureClass | None = None
    solver_variant: SolverVariant = SolverVariant.MUMPS
    solver_approval_id: str | None = None
    solver_compatibility_fingerprint: str | None = None
    runtime_version: str | None = None
    dispatch_reservation_id: str | None = None
    resolved_resources: ResolvedResources | None = None
    peak_memory_mb: int | None = Field(default=None, ge=0)
    peak_disk_mb: int | None = Field(default=None, ge=0)
    pressure_state: PressureState | None = None
    effective_capacity: int | None = Field(default=None, ge=0)
    capacity_reason: str = ""
    capacity_decision_at: datetime | None = None
    telemetry_observed_at: datetime | None = None
    migrated: bool = False
    prepared: bool = False
    remote_run_allocated: bool = False
    execution_started: bool = False
    execution_completed: bool = False


class PlacementConstraint(BaseModel):
    preferred_machine_id: str | None = None
    required_machine_id: str | None = None
    reason: str | None = None
    requested_by: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_constraint(self) -> "PlacementConstraint":
        if self.required_machine_id and self.preferred_machine_id:
            if self.required_machine_id != self.preferred_machine_id:
                raise ValueError("required and preferred machine must agree when both are set")
        if (self.required_machine_id or self.preferred_machine_id) and not self.reason:
            raise ValueError("machine placement requires an audit reason")
        return self


class WorkUnit(BaseModel):
    schema_version: Literal[1] = 1
    work_unit_id: str = Field(default_factory=lambda: new_id("unit"))
    ordinal: int = Field(ge=0)
    payload: dict[str, Any]
    atomic_item_ids: list[str] = Field(default_factory=list)
    expected_duration_s: int = Field(default=1800, ge=1, le=86400)
    resources: ResourceRequest = Field(default_factory=ResourceRequest)
    resolved_resources: ResolvedResources | None = None
    required_capabilities: set[str] = Field(default_factory=set)
    allowed_solver_variants: set[SolverVariant] = Field(
        default_factory=lambda: {SolverVariant.MUMPS}
    )
    solver_policy: SolverPolicy = SolverPolicy.AUTO_FAST
    resource_mode: ResourceMode = ResourceMode.DYNAMIC
    # False identifies pre-0.13 mixed solver payloads. Those rows retain
    # historical compatibility behavior; new explicit contracts are never
    # silently downgraded by the dispatcher.
    solver_policy_explicit: bool = Field(default=False, repr=False)
    solver_approval_id: str | None = None
    preferred_machine_id: str | None = None
    required_machine_id: str | None = None
    status: WorkUnitStatus = WorkUnitStatus.QUEUED
    assigned_machine_id: str | None = None
    actual_duration_s: float | None = Field(default=None, ge=0)
    progress_percent: float = Field(default=0.0, ge=0, le=100)
    completed_items: int | None = Field(default=None, ge=0)
    total_items: int | None = Field(default=None, ge=1)
    eta_s: float | None = Field(default=None, ge=0)
    progress_message: str = ""
    failure_reason: str | None = None
    dispatch_failure_count: int = Field(default=0, ge=0)
    dispatch_not_before_at: datetime | None = None
    attempt_count: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=3, ge=1, le=10)
    attempts: list[WorkUnitAttempt] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_solver_and_placement(self) -> "WorkUnit":
        if "solver_policy" not in self.model_fields_set and self.allowed_solver_variants == {SolverVariant.MUMPS}:
            self.solver_policy = SolverPolicy.COMPATIBILITY_MUMPS
        if "resource_mode" not in self.model_fields_set and self.schema_version == 1:
            self.resource_mode = ResourceMode.FIXED
        if self.required_machine_id and self.preferred_machine_id:
            if self.required_machine_id != self.preferred_machine_id:
                raise ValueError("required and preferred unit machine must agree")
        return self


class JobEnvelope(BaseModel):
    schema_version: Literal[1, 2] = 2
    job_id: str = Field(default_factory=lambda: new_id("job"))
    origin_submitter_id: str
    origin_adapter_id: str = "workbench"
    user_id: str
    project_id: str
    execution_profile_id: str
    campaign_id: str | None = None
    campaign_task_id: str | None = None
    recipe_kind: str | None = None
    study_kind: ComsolStudyKind | None = None
    template_role: str | None = None
    template_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    template_parameter_evidence: TemplateParameterEvidence | None = None
    output_contract_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    estimated_output_bytes: int | None = Field(default=None, ge=0)
    planning_warnings: list[str] = Field(default_factory=list)
    source_spec_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_manifest: list[FileRecord] = Field(default_factory=list)
    work_units: list[WorkUnit]
    partition_plan_id: str | None = None
    atomic_item_count: int | None = Field(default=None, ge=1)
    solver_approval_id: str | None = None
    solver_compatibility_fingerprint: str | None = None
    solver_policy: SolverPolicy = SolverPolicy.AUTO_FAST
    resource_mode: ResourceMode = ResourceMode.DYNAMIC
    solver_policy_explicit: bool = Field(default=False, repr=False)
    timeout_s: int = Field(default=3600, ge=1, le=86400)
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    priority: int = Field(default=0, ge=-100, le=100)
    effective_priority: int | None = Field(default=None, ge=-100, le=100)
    priority_ceiling_snapshot: int | None = Field(default=None, ge=-100, le=100)
    # Nullable markers preserve legacy sealed payloads. New origins distinguish
    # omitted priority from explicit zero across planning/JSON round trips.
    priority_explicit: bool | None = Field(default=None, strict=True, exclude_if=lambda value: value is None)
    duration_estimate_complete: bool | None = Field(default=None, strict=True, exclude_if=lambda value: value is None)
    priority_source: Literal['task', 'short_compute', 'project_default', 'system_default'] | None = Field(
        default=None, exclude_if=lambda value: value is None)
    placement: PlacementConstraint = Field(default_factory=PlacementConstraint)
    record_class: Literal["production", "acceptance", "smoke"] = "production"
    status: JobStatus = JobStatus.AWAITING_APPROVAL
    revision: int = Field(default=0, ge=0)
    last_scheduled_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_unique_units(self) -> "JobEnvelope":
        if "solver_policy" not in self.model_fields_set and all(
            unit.solver_policy == SolverPolicy.COMPATIBILITY_MUMPS for unit in self.work_units
        ):
            self.solver_policy = SolverPolicy.COMPATIBILITY_MUMPS
        if "resource_mode" not in self.model_fields_set and self.schema_version == 1:
            self.resource_mode = ResourceMode.FIXED
        ids = [unit.work_unit_id for unit in self.work_units]
        if len(ids) != len(set(ids)):
            raise ValueError("work_unit_id values must be unique within a job")
        ordinals = [unit.ordinal for unit in self.work_units]
        if sorted(ordinals) != list(range(len(ordinals))):
            raise ValueError("work-unit ordinals must be contiguous from zero")
        item_ids = [item_id for unit in self.work_units for item_id in unit.atomic_item_ids]
        if item_ids and len(item_ids) != len(set(item_ids)):
            raise ValueError("atomic items must appear in exactly one work unit")
        if self.atomic_item_count is not None and len(item_ids) != self.atomic_item_count:
            raise ValueError("work-unit atomic item coverage does not match the job count")
        if bool(self.campaign_id) != bool(self.campaign_task_id):
            raise ValueError("campaign_id and campaign_task_id must be provided together")
        return self


def unit_has_retryable_infrastructure_failure(unit: WorkUnit) -> bool:
    if unit.status != WorkUnitStatus.FAILED_RETRIABLE or unit.attempt_count >= unit.max_attempts:
        return False
    if not unit.attempts:
        return False
    attempt = unit.attempts[-1]
    return attempt.state == "failed" and attempt.failure_class in {
        FailureClass.INFRASTRUCTURE,
        FailureClass.RESOURCE_EXHAUSTION,
    }


def derived_job_status(job: JobEnvelope) -> JobStatus:
    statuses = {unit.status for unit in job.work_units}
    if job.status == JobStatus.AWAITING_APPROVAL and statuses.issubset({WorkUnitStatus.QUEUED}):
        return JobStatus.AWAITING_APPROVAL
    active = {
        WorkUnitStatus.ASSIGNED,
        WorkUnitStatus.RUNNING,
        WorkUnitStatus.RECONCILE_PENDING,
        WorkUnitStatus.COLLECTING,
    }
    if statuses.intersection(active):
        return JobStatus.RUNNING
    if WorkUnitStatus.QUEUED in statuses:
        return JobStatus.QUEUED
    if any(unit_has_retryable_infrastructure_failure(unit) for unit in job.work_units):
        return JobStatus.FAILED_RETRIABLE
    if job.work_units and all(unit.status == WorkUnitStatus.COMPLETED for unit in job.work_units):
        return JobStatus.COMPLETED
    if WorkUnitStatus.CANCELLED in statuses:
        return JobStatus.CANCELLED
    if statuses:
        return JobStatus.FAILED_TERMINAL
    return job.status


def job_activity_state(job: JobEnvelope) -> Literal[
    "active", "queued", "recoverable", "needs_attention", "history"
]:
    status = derived_job_status(job)
    if status == JobStatus.RUNNING:
        return "active"
    if status == JobStatus.QUEUED:
        return "queued"
    if status == JobStatus.FAILED_RETRIABLE:
        return "recoverable"
    if status in {
        JobStatus.COMPLETED,
        JobStatus.CANCELLED,
        JobStatus.FAILED_TERMINAL,
    }:
        return "history"
    return "needs_attention"


class PartitionPlan(BaseModel):
    """A deterministic, reviewable grouping that freezes into a v2 job."""

    schema_version: Literal[1] = 1
    plan_id: str
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    request: PartitionRequest
    work_units: list[WorkUnit]
    atomic_item_count: int = Field(ge=1)
    status: Literal["draft", "confirmed"] = "draft"
    confirmed_job_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    confirmed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_coverage(self) -> "PartitionPlan":
        expected = [item.item_id for item in self.request.items]
        actual = [item_id for unit in self.work_units for item_id in unit.atomic_item_ids]
        if len(actual) != len(set(actual)):
            raise ValueError("partition plan repeats an atomic item")
        if sorted(actual) != sorted(expected):
            raise ValueError("partition plan does not exactly cover the atomic items")
        if self.atomic_item_count != len(expected):
            raise ValueError("partition plan item count is inconsistent")
        ordinals = [unit.ordinal for unit in self.work_units]
        if sorted(ordinals) != list(range(len(ordinals))):
            raise ValueError("partition work-unit ordinals must be contiguous from zero")
        return self


class AuditEvent(BaseModel):
    schema_version: Literal[1] = 1
    event_id: str = Field(default_factory=lambda: new_id("event"))
    sequence: int = Field(default_factory=lambda: int(utc_now().timestamp() * 1_000_000), ge=0)
    event_type: str
    actor_id: str
    subject_type: str
    subject_id: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class Assignment(BaseModel):
    job_id: str
    work_unit_id: str
    machine_id: str
    scheduler: str
    attempt_id: str | None = None
    solver_variant: SolverVariant = SolverVariant.MUMPS
    solver_approval_id: str | None = None
    solver_compatibility_fingerprint: str | None = None
    runtime_version: str | None = None
    dispatch_reservation_id: str | None = None
    prepared: bool = False
    external_run_id: str | None = None
    assigned_at: datetime = Field(default_factory=utc_now)


class DispatchReservation(BaseModel):
    """A persisted standby bundle that has not consumed an Attempt."""

    schema_version: Literal[1] = 1
    reservation_id: str = Field(default_factory=lambda: new_id("reservation"))
    active_key: str | None = None
    job_id: str
    work_unit_id: str
    machine_id: str
    slot_index: int = Field(ge=0)
    # The submitted envelope and the materialized worker request have distinct
    # hashes. Freeze both: later Job edits must not rewrite a staged identity.
    job_request_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    request_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    state: Literal[
        "preparing",
        "prepared",
        "activating",
        "consumed",
        "cancelled",
        "expired",
    ] = "preparing"
    solver_variant: SolverVariant = SolverVariant.MUMPS
    solver_approval_id: str | None = None
    solver_compatibility_fingerprint: str | None = None
    runtime_version: str | None = None
    resolved_resources: ResolvedResources
    external_run_id: str | None = None
    reason: str = ""
    prepared_at: datetime | None = None
    activated_at: datetime | None = None
    expires_at: datetime
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class UnitCompletion(BaseModel):
    duration_s: float = Field(ge=0)
    manifest: ArtifactManifest
    expected_attempt_id: str | None = Field(default=None, exclude_if=lambda value: value is None)


class UnitFailure(BaseModel):
    error: str
    failure_class: FailureClass | None = None
    retryable: bool | None = None
    expected_attempt_id: str | None = Field(default=None, exclude_if=lambda value: value is None)


class DispatcherLease(BaseModel):
    lease_name: Literal["dispatcher"] = "dispatcher"
    owner_id: str
    acquired_at: datetime
    heartbeat_at: datetime
    expires_at: datetime


class DispatcherStatus(BaseModel):
    io_snapshot: dict[str, Any] | None = Field(default=None, exclude_if=lambda value: value is None)
    status_id: Literal["dispatcher"] = "dispatcher"
    owner_id: str | None = None
    phase: DispatcherPhase = DispatcherPhase.STOPPED
    package_version: str = "0.11.0"
    protocol_version: str = "1"
    runtime_version: str | None = None
    accepting_assignments: bool = True
    control_mode: Literal["open", "drain"] = "open"
    desired_state: Literal["open", "drain", "stopped"] = "open"
    stop_reason: str = ""
    blocked_reason: str = ""
    auto_resume_allowed: bool = True
    last_recovered_at: datetime | None = None
    heartbeat_at: datetime | None = None
    last_cycle_started_at: datetime | None = None
    last_successful_cycle_at: datetime | None = None
    last_error_at: datetime | None = None
    last_error: str | None = None
    cycle_count: int = Field(default=0, ge=0)
    assignments: int = Field(default=0, ge=0)
    reconciled_attempts: int = Field(default=0, ge=0)
    pending_reconciliation: int = Field(default=0, ge=0)
    # Bounded self-recovery bookkeeping for the collection circuit breaker.
    # Optional with defaults so older persisted JSON payloads validate unchanged.
    collection_circuit_auto_resume_count: int = Field(default=0, ge=0)
    collection_circuit_auto_resume_reset_at: datetime | None = None
    # Exact causes of the current global circuit, not a paged UI alert list.
    collection_circuit_alert_ids: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utc_now)


class EnrollmentRecord(BaseModel):
    # Control-plane registration metadata only; not a Worker wire contract.
    registration_mode: Literal["legacy", "resumable-v1"] = "legacy"
    invited_machine_id: str | None = None
    registration_url: str | None = None
    revoked_at: datetime | None = None
    exchange_request_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    exchange_credential_id: str | None = None
    # Possession-proven management identity, never an automatic SSH/compute grant.
    ssh_transport_public_key: str | None = None
    ssh_transport_statement_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    ssh_transport_bound_at: datetime | None = None
    # Signed bootstrap location claim only; remote/runtime acceptance is separate.
    worker_root_binding: dict[str, Any] | None = None
    # Stable dedicated relay reservation; never reused implicitly after revocation.
    member_relay_binding: dict[str, Any] | None = None
    conditional_admission_offer: dict[str, Any] | None = None
    member_compute_consent: dict[str, Any] | None = None
    member_admission_result: dict[str, Any] | None = None
    # Center-owned SSH bootstrap intent; never a client-supplied passed checklist.
    member_ssh_bootstrap: dict[str, Any] | None = None
    enrollment_id: str = Field(default_factory=lambda: new_id("enrollment"))
    code_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_by: str
    owner_user_id: str
    expires_at: datetime
    used_at: datetime | None = None
    machine_id: str | None = None
    hostname: str | None = None
    requested_capabilities: set[str] = Field(default_factory=set)
    created_at: datetime = Field(default_factory=utc_now)

    def is_available(self, now: datetime | None = None) -> bool:
        current = now or utc_now()
        return self.revoked_at is None and self.used_at is None and self.expires_at > current


class IssuedEnrollment(BaseModel):
    enrollment_id: str
    enrollment_code: str
    expires_at: datetime


class EnrollmentRequest(BaseModel):
    enrollment_code: str
    machine: MachineState
    model_config = ConfigDict(extra="forbid")
