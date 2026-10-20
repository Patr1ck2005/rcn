"""Single structured placement evaluator shared by dispatch and diagnostics."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from .capacity import effective_capacity
from .disk_guard import execution_disk_block_reason, execution_disk_headroom, execution_disk_space, volume_reserve_mb
from .models import (
    ApprovalRecord,
    ApprovalScope,
    ExecutionProfile,
    HeartbeatPhase,
    JobEnvelope,
    MachineExecutionConfig,
    MachineMode,
    MachineOperationalStatus,
    MachinePolicy,
    MachineState,
    PressurePolicySettings,
    ProjectGrant,
    ResourceRequest,
    ResourceMode,
    SolverCompatibilityApproval,
    SolverPolicy,
    SolverVariant,
    SupervisorState,
    TelemetryState,
    WorkUnit,
)
from .policy import active_window


class PlacementBlocker(BaseModel):
    code: str
    category: Literal[
        "control",
        "capacity",
        "resources",
        "schedule",
        "pressure",
        "profile",
        "authorization",
        "runtime",
        "solver",
        "bundle",
        "fairness",
    ]
    message: str
    required: float | int | str | list[str] | None = None
    available: float | int | str | list[str] | None = None
    reserved: float | int | None = None
    unit: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ResourceVector(BaseModel):
    cpus: int = Field(default=0, ge=0)
    memory_mb: int = Field(default=0, ge=0)
    disk_mb: int = Field(default=0, ge=0)
    gpus: int = Field(default=0, ge=0)


class MachinePlacementEvaluation(BaseModel):
    machine_id: str
    eligible: bool
    blockers: list[PlacementBlocker] = Field(default_factory=list)
    effective_capacity: int = 0
    occupied_slots: int = 0
    prepared_slots: int = 0
    pressure_state: str = "normal"
    capacity_reason: str = ""
    active_resources: ResourceVector = Field(default_factory=ResourceVector)
    resource_limits: ResourceVector = Field(default_factory=ResourceVector)
    resource_source: str = "unknown"
    policy_revision: int = 1


def _approved(
    approvals: list[ApprovalRecord],
    machine_id: str,
    project_id: str,
    profile_id: str,
    now: datetime,
) -> bool:
    return any(
        approval.machine_id == machine_id
        and approval.is_active(now)
        and (
            approval.scope == ApprovalScope.PROJECT
            and approval.subject_id == project_id
            or approval.scope == ApprovalScope.EXECUTION_PROFILE
            and approval.subject_id == profile_id
        )
        for approval in approvals
    )


def _sum_resources(units: list[WorkUnit]) -> ResourceVector:
    def active_resources(unit: WorkUnit) -> ResourceVector:
        active_states = {
            "assigned",
            "submitting",
            "running",
            "cancel_pending",
            "reconcile_pending",
            "uncertain",
            "collecting",
        }
        attempt = next(
            (candidate for candidate in reversed(unit.attempts) if candidate.state in active_states),
            None,
        )
        if attempt is not None and attempt.resolved_resources is not None:
            resources = attempt.resolved_resources.resources
        elif unit.resolved_resources is not None:
            resources = unit.resolved_resources.resources
        else:
            resources = unit.resources
        if (
            attempt is not None
            and "solver_variant" in attempt.model_fields_set
            and attempt.solver_variant == SolverVariant.MUMPS
            and unit.resource_mode == ResourceMode.DYNAMIC
            and unit.solver_policy == SolverPolicy.AUTO_FAST
            and unit.allowed_solver_variants == {SolverVariant.MUMPS, SolverVariant.CUDSS}
        ):
            # This contract's GPU request is optional cuDSS capacity. Its
            # selected MUMPS Attempt uses none; retain the frozen declaration.
            return resources.model_copy(update={"gpus": 0})
        return resources

    resources = [active_resources(unit) for unit in units]
    return ResourceVector(
        cpus=sum(resource.cpus for resource in resources),
        memory_mb=sum(resource.memory_mb for resource in resources),
        disk_mb=sum(resource.disk_mb for resource in resources),
        gpus=sum(resource.gpus for resource in resources),
    )


def _shared_dynamic_cudss_gpus(units: list[WorkUnit]) -> int:
    """Count only positively identified, nonexclusive dynamic GPU claims."""

    active_states = {
        "assigned", "submitting", "running", "cancel_pending",
        "reconcile_pending", "uncertain", "collecting",
    }
    shared = 0
    for unit in units:
        if (
            unit.resource_mode != ResourceMode.DYNAMIC
            or unit.solver_policy != SolverPolicy.AUTO_FAST
            or SolverVariant.CUDSS not in unit.allowed_solver_variants
        ):
            continue
        attempt = next(
            (candidate for candidate in reversed(unit.attempts) if candidate.state in active_states),
            None,
        )
        if (
            attempt is not None
            and "solver_variant" in attempt.model_fields_set
            and attempt.solver_variant == SolverVariant.CUDSS
            and attempt.resolved_resources is not None
        ):
            shared += attempt.resolved_resources.resources.gpus
    return shared


def evaluate_placement(
    *,
    machine: MachineState,
    policy: MachinePolicy | None,
    execution_config: MachineExecutionConfig | None,
    operational_status: MachineOperationalStatus | None,
    grant: ProjectGrant,
    profile: ExecutionProfile,
    job: JobEnvelope,
    unit: WorkUnit,
    approvals: list[ApprovalRecord],
    solver_approval: SolverCompatibilityApproval | None,
    active_units: list[WorkUnit],
    active_profile_units: list[WorkUnit],
    prepared_slots: int = 0,
    standby: bool = False,
    pressure_settings: PressurePolicySettings | None = None,
    now: datetime | None = None,
) -> MachinePlacementEvaluation:
    """Evaluate every static and live placement condition once.

    The returned blockers are suitable for both the Dispatcher and member-safe
    Web diagnostics. They intentionally contain no credentials, process IDs,
    commands, paths, or payload values.
    """

    current = now or datetime.now(timezone.utc)
    blockers: list[PlacementBlocker] = []

    def block(code: str, category: str, message: str, **values: Any) -> None:
        blockers.append(PlacementBlocker(
            code=code,
            category=category,
            message=message,
            **values,
        ))

    active_resources = _sum_resources(active_units)
    resource_source = (
        unit.resolved_resources.source if unit.resolved_resources is not None else "origin_legacy"
    )
    policy_revision = (
        unit.resolved_resources.policy_revision if unit.resolved_resources is not None else 1
    )
    if policy is None:
        block("machine_policy_missing", "authorization", "机器尚未配置业主策略")
        return MachinePlacementEvaluation(
            machine_id=machine.machine_id,
            eligible=False,
            blockers=blockers,
            occupied_slots=len(active_units),
            prepared_slots=prepared_slots,
            active_resources=active_resources,
            resource_source=resource_source,
            policy_revision=policy_revision,
        )

    from .failure_policy import memory_retry_blocker
    memory_hold = memory_retry_blocker(job, unit, machine, policy, execution_config)
    if memory_hold is not None:
        block("memory_failure_conditions_unchanged", "resources",
              "该机器同任务已证内存不足；需提高内存申报或降低并发后重新核对", details=memory_hold)

    admission_limit = policy.member_execution_limit
    from .scientific_acceptance_contract import is_bound_scientific_job
    scientific_probe = is_bound_scientific_job(job, machine, execution_config)
    if admission_limit is not None:
        runtime = (solver_approval.runtime_version if solver_approval is not None
                   else execution_config.runtime_version if execution_config else None)
        fixed_probe_allowed = bool(scientific_probe and admission_limit.is_active(current)
            and admission_limit.runtime_version == runtime)
        if not fixed_probe_allowed and not admission_limit.permits(grant.project_id, profile.profile_id, runtime, now=current, user_id=job.user_id):
            block('member_admission_scope', 'authorization', '邀请授权范围、有效期或运行时不匹配；不影响已开始的计算')

    resource_limits = ResourceVector(
        cpus=policy.effective_cpu_cap(machine.total_cpus),
        memory_mb=min(machine.total_memory_mb, policy.max_memory_mb, admission_limit.max_memory_mb if admission_limit else policy.max_memory_mb),
        disk_mb=execution_disk_headroom(machine.metrics, now=current)[0],
        gpus=min(machine.total_gpus, policy.max_gpus, 0 if admission_limit else policy.max_gpus),
    )

    mode = policy.effective_mode()
    if mode != MachineMode.OPEN:
        block("machine_mode", "control", f"机器模式为 {mode.value}", available=mode.value)
    if execution_config is not None and not execution_config.enabled:
        block("execution_disabled", "control", "机器执行配置未启用")

    if operational_status is None:
        block("operational_status_missing", "control", "没有执行器运行状态")
    else:
        if operational_status.supervisor_state != SupervisorState.ONLINE:
            block(
                "executor_unavailable",
                "control",
                "执行器未在线",
                available=operational_status.supervisor_state.value,
            )
        # Only a positively observed break blocks dispatch. Legacy/in-memory
        # registrations may not have a transport monitor and therefore remain
        # "unknown"; production SSH configurations quickly resolve that state.
        if operational_status.transport_state.value == "disconnected":
            block(
                "transport_disconnected",
                "control",
                "传输通道断开；已运行计算继续，但暂停新派发",
                available=operational_status.transport_state.value,
            )
        if operational_status.heartbeat_phase != HeartbeatPhase.HEALTHY:
            block(
                "heartbeat_recovering",
                "control",
                "执行器连接仍在恢复观察期；连续两次成功后恢复派发",
                required=HeartbeatPhase.HEALTHY.value,
                available=operational_status.heartbeat_phase.value,
            )
        if operational_status.telemetry_state != TelemetryState.LIVE:
            block(
                "telemetry_unavailable",
                "control",
                "资源遥测不是实时状态",
                available=operational_status.telemetry_state.value,
            )

    heartbeat_age = max(0.0, (current - machine.last_heartbeat_at).total_seconds())
    if heartbeat_age > 90:
        block(
            "heartbeat_stale",
            "control",
            f"执行器最后确认已过去 {heartbeat_age:.0f} 秒",
            required=90,
            available=round(heartbeat_age, 1),
            unit="s",
        )

    window = active_window(policy, current)
    if window is None:
        block("outside_schedule", "schedule", "当前不在业主允许的运行时段")
    else:
        remaining_s = (window[1] - current.astimezone(window[1].tzinfo)).total_seconds()
        if remaining_s < unit.expected_duration_s:
            block(
                "schedule_time_remaining",
                "schedule",
                "当前运行时段剩余时间不足",
                required=unit.expected_duration_s,
                available=max(0, round(remaining_s)),
                unit="s",
            )

    metrics = machine.metrics
    if metrics.keyboard_idle_s < policy.keyboard_idle_min_s:
        block(
            "keyboard_idle",
            "schedule",
            "键盘鼠标空闲时间未达到阈值",
            required=policy.keyboard_idle_min_s,
            available=metrics.keyboard_idle_s,
            unit="s",
        )
    static_execution_limit = min(
        policy.max_concurrent_units,
        admission_limit.max_concurrent_units if admission_limit else policy.max_concurrent_units,
        execution_config.max_concurrent_units if execution_config is not None else policy.max_concurrent_units,
    )
    reported_capacity = (
        operational_status.supervisor_reported_concurrent_units
        if operational_status is not None else None
    )
    if reported_capacity is not None:
        static_execution_limit = min(static_execution_limit, reported_capacity)
    profile_limit = (
        execution_config.profile_concurrency_limits.get(job.execution_profile_id)
        if execution_config is not None
        else None
    )
    telemetry_state = (
        operational_status.telemetry_state
        if operational_status is not None
        else TelemetryState.UNAVAILABLE
    )
    telemetry_stale_age_s = None
    if telemetry_state != TelemetryState.LIVE:
        observed_at = metrics.observed_at
        if observed_at is not None:
            telemetry_stale_age_s = max(0.0, (current - observed_at).total_seconds())
    capacity = effective_capacity(
        policy_cap=policy.max_concurrent_units,
        execution_cap=static_execution_limit,
        target_cap=(
            min(
                execution_config.target_concurrent_units,
                reported_capacity
                if reported_capacity is not None
                else execution_config.target_concurrent_units,
            )
            if execution_config is not None
            else static_execution_limit
        ),
        profile_cap=profile_limit,
        profile_id=job.execution_profile_id,
        pressure=metrics.external_load,
        telemetry_state=telemetry_state,
        telemetry_stale_age_s=telemetry_stale_age_s,
        override_until=(operational_status.pressure_override_until if operational_status else None),
        override_cap=(operational_status.pressure_override_concurrency if operational_status else None),
        settings=pressure_settings,
        allow_cpu_contention=policy.full_cpu_override is not None,
        now=current,
        available_memory_mb=metrics.available_memory_mb,
        memory_reserve_mb=policy.memory_reserve_mb,
        free_disk_mb=metrics.free_disk_mb,
        disk_reserve_mb=(volume_reserve_mb(execution_config.remote_root, execution_config.disk_reserve_gib * 1024,
                                          execution_config.c_drive_reserve_gib * 1024) if execution_config else None),
        disk_block_reason=execution_disk_block_reason(
            metrics, now=current,
            reserve_mb=execution_config.disk_reserve_gib * 1024 if execution_config else 0,
            c_drive_reserve_mb=execution_config.c_drive_reserve_gib * 1024 if execution_config else 20 * 1024,
            root_volume=execution_config.remote_root if execution_config else "",
        ),
    )
    capacity_reason = capacity.reason
    if operational_status is not None and operational_status.capacity_drift_reason:
        capacity_reason = f"{operational_status.capacity_drift_reason}; {capacity_reason}"
    occupied_slots = max(len(active_units), metrics.running_units)
    if standby:
        standby_limit = min(occupied_slots, capacity.effective_cap)
        if occupied_slots == 0:
            block("standby_not_needed", "capacity", "机器没有运行 slot，不需要 standby")
        elif prepared_slots >= standby_limit:
            block(
                "standby_limit",
                "capacity",
                "每个运行 slot 最多保留一个 standby",
                required=prepared_slots + 1,
                available=standby_limit,
                unit="slot",
            )
    elif occupied_slots >= capacity.effective_cap:
        block(
            "machine_concurrency",
            "capacity",
            "机器有效并发 slot 已占满",
            required=occupied_slots + 1,
            available=capacity.effective_cap,
            reserved=prepared_slots,
            unit="slot",
            details={
                "capacity_reason": capacity_reason,
                "pressure_state": capacity.state.value,
                "supervisor_reported_concurrent_units": reported_capacity,
            },
        )
    effective_profile_limit = min(profile_limit or capacity.effective_cap, capacity.effective_cap)
    if not standby and len(active_profile_units) >= effective_profile_limit:
        block(
            "profile_concurrency",
            "capacity",
            "该 Profile 的机器并发上限已占满",
            required=len(active_profile_units) + 1,
            available=effective_profile_limit,
            unit="slot",
        )

    for name, label, unit_name in (
        ("cpus", "CPU", "core"),
        ("memory_mb", "内存", "MiB"),
        ("gpus", "GPU", "device"),
    ):
        if name == "cpus" and policy.full_cpu_override is not None:
            # Explicit CPU oversubscription retains every non-CPU admission gate.
            # The cap applies to each process, while the OS schedules coexistence.
            required = max(unit.resources.cpus,
                           unit.resolved_resources.resources.cpus
                           if unit.resolved_resources is not None else unit.resources.cpus)
        elif name == "cpus" and policy.shared_machine:
            # Count frozen Attempts, including uncertain/collecting work.
            # Dynamic mode and pressure overrides cannot spend the owner reserve.
            requested = (unit.resolved_resources.resources.cpus
                         if unit.resolved_resources is not None else unit.resources.cpus)
            required = requested + (0 if standby else active_resources.cpus)
        elif name == "cpus" and unit.resource_mode == ResourceMode.DYNAMIC:
            # Dynamic COMSOL units advertise a CPU floor, while the machine
            # concurrency cap and live pressure decide how many may coexist.
            # Do not turn a historical 4-core reservation into a hidden
            # per-machine partition that defeats automatic thread use.
            required = getattr(unit.resources, name)
        elif (
            name == "gpus"
            and unit.resource_mode == ResourceMode.DYNAMIC
            and unit.solver_policy == SolverPolicy.AUTO_FAST
            and unit.allowed_solver_variants == {SolverVariant.MUMPS, SolverVariant.CUDSS}
        ):
            # In a mixed dynamic contract, GPU selects cuDSS on a capable
            # host; it must not exclude CPU-only hosts that can use MUMPS.
            required = 0
        elif (
            name == "gpus"
            and unit.resource_mode == ResourceMode.DYNAMIC
            and unit.solver_policy == SolverPolicy.AUTO_FAST
            and unit.allowed_solver_variants == {SolverVariant.CUDSS}
        ):
            # Dynamic cuDSS needs real, owner-allowed devices, but its GPU
            # count is not an exclusive whole-card reservation. Machine and
            # Profile slot caps still bound coexistence. Preserve fixed or
            # unidentified active GPU claims and all frozen accounting.
            required = max(
                1, unit.resources.gpus,
                unit.resolved_resources.resources.gpus if unit.resolved_resources else 0,
            )
            if not standby:
                required += max(0, active_resources.gpus - _shared_dynamic_cudss_gpus(active_units))
        elif (
            name == "gpus"
            and unit.resource_mode == ResourceMode.DYNAMIC
            and unit.allowed_solver_variants == {SolverVariant.MUMPS}
            and unit.resources.gpus == 0
            and (unit.resolved_resources is None or unit.resolved_resources.resources.gpus == 0)
        ):
            # A proven GPU-zero CPU candidate adds no device claim. Existing
            # nonexclusive dynamic cuDSS use must not become an exclusive-card
            # requirement only because the next candidate selects MUMPS.
            # Preserve every fixed/unproven claim and the frozen accounting.
            required = (0 if standby else max(
                0, active_resources.gpus - _shared_dynamic_cudss_gpus(active_units),
            ))
        else:
            required = (
                getattr(unit.resources, name)
                if standby
                else getattr(active_resources, name) + getattr(unit.resources, name)
            )
        available = getattr(resource_limits, name)
        if (name == 'cpus' and policy.full_cpu_override is not None
                and policy.full_cpu_override.max_threads_per_attempt is not None):
            available = min(available, policy.full_cpu_override.max_threads_per_attempt)
        if required > available:
            block(
                f"{name}_allocation",
                "resources",
                f"{label} 声明总量超过机器上限",
                required=required,
                available=available,
                unit=unit_name,
            )

    # A cuDSS-only request is intentionally GPU-bound. Mixed auto_fast jobs
    # use cuDSS on capable GPU machines and MUMPS on CPU-only machines.
    if (
        unit.solver_policy == SolverPolicy.AUTO_FAST
        and unit.allowed_solver_variants == {SolverVariant.CUDSS}
        and "solver-cudss" not in machine.capabilities
    ):
        block(
            "cudss_capability_missing",
            "solver",
            "该任务显式限定 cuDSS，但机器没有已验收的 cuDSS 能力",
            required="solver-cudss",
            available=sorted(machine.capabilities),
            details={
                "solver_policy": unit.solver_policy.value,
                "next_action": "允许 auto_fast 使用 MUMPS，或选择具备 cuDSS 的机器",
                "requires": "admin",
            },
        )

    memory_required = unit.resources.memory_mb + policy.memory_reserve_mb
    if metrics.available_memory_mb < memory_required:
        block(
            "memory_headroom",
            "resources",
            (
                f"需要 {unit.resources.memory_mb} MiB + 预留 {policy.memory_reserve_mb} MiB；"
                f"可用 {metrics.available_memory_mb} MiB，缺少 {memory_required - metrics.available_memory_mb} MiB"
            ),
            required=memory_required,
            available=metrics.available_memory_mb,
            reserved=policy.memory_reserve_mb,
            unit="MiB",
        )
    disk_reserve_mb = (execution_config.disk_reserve_gib * 1024) if execution_config else 0
    disk_kwargs = dict(now=current, reserve_mb=disk_reserve_mb,
        c_drive_reserve_mb=execution_config.c_drive_reserve_gib * 1024 if execution_config else 20 * 1024,
        root_volume=execution_config.remote_root if execution_config else "")
    disk_free_mb, disk_reserve_mb, disk_source = execution_disk_space(metrics, **disk_kwargs)
    disk_required = unit.resources.disk_mb + disk_reserve_mb
    disk_reason = execution_disk_block_reason(metrics, **disk_kwargs)
    if disk_reason:
        block("execution_disk_guard", "resources", disk_reason)
    if disk_free_mb < disk_required:
        block(
            "disk_headroom",
            "resources",
            (
                f"需要 {unit.resources.disk_mb} MiB + 预留 {disk_reserve_mb} MiB；"
                f"写入卷 {disk_source} 可用 {disk_free_mb} MiB，缺少 {disk_required - disk_free_mb} MiB"
            ),
            required=disk_required,
            available=disk_free_mb,
            reserved=disk_reserve_mb,
            unit="MiB",
        )

    if solver_approval is not None and solver_approval.runtime_version is not None:
        expected = solver_approval.runtime_version
        from .runtime_cache_admission import accepts_cached_runtime
        cached = accepts_cached_runtime(machine, execution_config, expected)
        if machine.runtime_version != expected and not cached:
            block(
                "machine_runtime_mismatch",
                "runtime",
                "机器尚未运行当前 sealed runtime",
                required=expected,
                available=machine.runtime_version or "unregistered",
            )
        if execution_config is None or (execution_config.runtime_version != expected and not cached):
            block(
                "execution_runtime_mismatch",
                "runtime",
                "机器执行配置尚未指向当前 sealed runtime",
                required=expected,
                available=(execution_config.runtime_version if execution_config else "unconfigured"),
            )

    if machine.platform not in profile.platforms:
        block("platform", "profile", "机器平台不受该 Profile 支持", available=machine.platform)
    missing = sorted((profile.required_capabilities | unit.required_capabilities) - machine.capabilities)
    if missing:
        block(
            "capabilities",
            "profile",
            f"缺少能力：{', '.join(missing)}",
            details={"missing": missing},
        )
    if not grant.approved:
        block("project_not_approved", "authorization", "项目尚未获准使用 Network")
    if profile.profile_id not in grant.allowed_profiles:
        block("profile_not_granted", "authorization", "项目未获准使用该执行 Profile")
    scoped_trust = bool(admission_limit is not None
        and admission_limit.permits(grant.project_id, profile.profile_id,
            (solver_approval.runtime_version if solver_approval is not None
             else execution_config.runtime_version if execution_config else None), now=current, user_id=job.user_id)
        and set(admission_limit.project_trust_labels.get(grant.project_id, [])) == grant.trusted_machine_labels)
    if grant.trusted_machine_labels and not grant.trusted_machine_labels.issubset(machine.labels) and not scoped_trust:
        block("trust_labels", "authorization", "机器不满足项目 trust labels")
    person_owner_consent = profile.profile_id in policy.member_profile_grants.get(job.user_id, set())
    signed_person_consent = bool(admission_limit is not None
        and profile.profile_id in admission_limit.person_profiles.get(job.user_id, [])
        and admission_limit.permits(grant.project_id, profile.profile_id,
            solver_approval.runtime_version if solver_approval else execution_config.runtime_version if execution_config else None,
            now=current, user_id=job.user_id))
    if not person_owner_consent and not signed_person_consent and not _approved(approvals, machine.machine_id, grant.project_id, profile.profile_id, current):
        block("owner_approval", "authorization", "机器业主未批准该项目或 Profile")

    return MachinePlacementEvaluation(
        machine_id=machine.machine_id,
        eligible=not blockers,
        blockers=blockers,
        effective_capacity=capacity.effective_cap,
        occupied_slots=occupied_slots,
        prepared_slots=prepared_slots,
        pressure_state=capacity.state.value,
        capacity_reason=capacity_reason,
        active_resources=active_resources,
        resource_limits=resource_limits,
        resource_source=resource_source,
        policy_revision=policy_revision,
    )
