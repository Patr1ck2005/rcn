"""Single-source machine observation and capacity decisions.

The transport, API, and Dispatcher layers consume this module instead of
independently interpreting telemetry.  It deliberately contains no I/O so one
observation always produces the same persisted and displayed decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from .connection_health import merge_channel_evidence, project_channel_health
from .capacity import CapacityDecision, PressureTracker, effective_capacity
from .disk_guard import execution_disk_block_reason, execution_disk_space, update_disk_snapshot, volume_reserve_mb
from .models import (
    ControlState,
    HeartbeatPhase,
    MachineExecutionConfig,
    ExternalLoadSnapshot,
    MachineHeartbeat,
    MachineMetrics,
    MachineMode,
    MachineOperationalStatus,
    MachinePolicy,
    MachineState,
    MetricSample,
    PressurePolicySettings,
    PressureState,
    SupervisorState,
    TelemetryState,
    TransportState,
)


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class MachineObservation:
    """Immutable evidence captured during one machine sample."""

    machine_id: str
    observed_at: datetime
    metrics: MachineMetrics
    running_work_unit_ids: tuple[str, ...]
    runtime_version: str | None
    source: str

    @classmethod
    def from_heartbeat(
        cls,
        heartbeat: MachineHeartbeat,
        *,
        previous_metrics: MachineMetrics,
        pressure_settings: PressurePolicySettings,
        memory_reserve_mb: int | None = None,
        disk_reserve_mb: int | None = None,
        c_drive_reserve_mb: int = 20 * 1024,
        root_volume: str = "",
    ) -> "MachineObservation":
        metrics = heartbeat.metrics.model_copy(deep=True)
        if not metrics.available:
            raise ValueError("unavailable telemetry cannot replace the last valid machine metrics")
        metrics.execution_disk = update_disk_snapshot(
            metrics.execution_disk, previous_metrics.execution_disk,
            reserve_mb=disk_reserve_mb or 0,
            clear_after_s=pressure_settings.clear_after_seconds,
            c_drive_reserve_mb=c_drive_reserve_mb,
        )
        # The pressure-shaped field is the wire-compatible view used by old
        # agents. When it carries this heartbeat's timestamp, promote it to
        # the generic snapshot before applying policy. Contradictory legacy
        # count/hash evidence is rejected instead of silently normalized.
        pressure = metrics.external_pressure
        inconsistent_legacy = (
            metrics.external_comsol_process_count > 0
            and metrics.external_comsol_process_count != pressure.external_comsol_count
        )
        if metrics.external_comsol_process_set_hash and not pressure.process_set_hash:
            pressure.process_set_hash = metrics.external_comsol_process_set_hash
        if _aware(pressure.observed_at) == _aware(metrics.observed_at):
            if (
                metrics.external_comsol_process_set_hash
                and pressure.process_set_hash
                and metrics.external_comsol_process_set_hash != pressure.process_set_hash
            ):
                inconsistent_legacy = True
            metrics.external_load = ExternalLoadSnapshot.model_validate(
                pressure.model_dump(mode="python")
            )
        disk_free, disk_reserve, _ = execution_disk_space(
            metrics, now=max(_aware(metrics.observed_at), _aware(metrics.execution_disk.observed_at))
            if metrics.execution_disk else metrics.observed_at,
            reserve_mb=disk_reserve_mb or 0, c_drive_reserve_mb=c_drive_reserve_mb,
            root_volume=root_volume,
        )
        metrics.external_load = PressureTracker(
            snapshot=previous_metrics.external_pressure.model_copy(deep=True)
        ).update(
            metrics.external_load,
            now=metrics.observed_at,
            policy=pressure_settings,
            available_memory_mb=metrics.available_memory_mb,
            memory_reserve_mb=memory_reserve_mb,
            free_disk_mb=disk_free,
            disk_reserve_mb=disk_reserve if disk_reserve_mb is not None else None,
        )
        metrics.external_pressure = metrics.external_load
        if not inconsistent_legacy:
            metrics.external_process_count = metrics.external_load.external_process_count
            metrics.external_process_set_hash = metrics.external_load.process_set_hash
            metrics.external_comsol_process_count = metrics.external_process_count
            metrics.external_comsol_process_set_hash = metrics.external_process_set_hash
        metrics.running_units = len(heartbeat.running_work_unit_ids)
        return cls(
            machine_id=heartbeat.machine_id,
            observed_at=metrics.observed_at,
            metrics=metrics,
            running_work_unit_ids=tuple(heartbeat.running_work_unit_ids),
            runtime_version=heartbeat.runtime_version,
            source=metrics.source,
        )


@dataclass(frozen=True)
class MachineCapacityDecision:
    """Capacity result plus the exact inputs that produced it."""

    configured_cap: int
    effective_capacity: int
    pressure_state: PressureState
    reason: str
    decided_at: datetime

    @classmethod
    def from_capacity(
        cls,
        decision: CapacityDecision,
        *,
        decided_at: datetime,
    ) -> "MachineCapacityDecision":
        return cls(
            configured_cap=decision.normal_cap,
            effective_capacity=decision.effective_cap,
            pressure_state=decision.state,
            reason=decision.reason,
            decided_at=decided_at,
        )


@dataclass(frozen=True)
class MachineObservationResult:
    machine: MachineState
    status: MachineOperationalStatus | None
    raw_sample: MetricSample
    observation: MachineObservation


class MachineObservationRepository(Protocol):
    def get_machine(self, machine_id: str) -> MachineState | None: ...

    def get_machine_operational_status(
        self, machine_id: str
    ) -> MachineOperationalStatus | None: ...

    def get_policy(self, machine_id: str) -> MachinePolicy | None: ...

    def get_machine_execution_config(
        self, machine_id: str
    ) -> MachineExecutionConfig | None: ...

    def get_feature_settings(self): ...

    def list_machines(self) -> list[MachineState]: ...

    def list_metric_samples(
        self,
        machine_id: str,
        *,
        sample_kind: str,
        since: datetime,
        limit: int = 5000,
    ) -> list[MetricSample]: ...


def decide_machine_capacity(
    *,
    policy: MachinePolicy | None,
    config: MachineExecutionConfig | None,
    status: MachineOperationalStatus,
    metrics: MachineMetrics,
    settings: PressurePolicySettings,
    previous: MachineOperationalStatus | None,
) -> MachineCapacityDecision:
    reported = status.supervisor_reported_concurrent_units
    policy_cap = policy.max_concurrent_units if policy else 1
    execution_cap = config.max_concurrent_units if config else 1
    target_cap = config.target_concurrent_units if config else execution_cap
    if reported is not None:
        execution_cap = min(execution_cap, reported)
        target_cap = min(target_cap, reported)
    decided_at = status.last_metric_at or status.last_checked_at or metrics.observed_at
    stale_age_s = None
    if status.telemetry_state != TelemetryState.LIVE:
        reference = status.last_checked_at or metrics.observed_at
        if reference is not None and status.last_metric_at is not None:
            stale_age_s = max(
                0.0, (reference - status.last_metric_at).total_seconds()
            )
    decision = effective_capacity(
        policy_cap=policy_cap,
        execution_cap=execution_cap,
        target_cap=target_cap,
        profile_cap=None,
        profile_id="machine-observation",
        pressure=metrics.external_load,
        telemetry_state=status.telemetry_state,
        telemetry_stale_age_s=stale_age_s,
        override_until=previous.pressure_override_until if previous else None,
        override_cap=previous.pressure_override_concurrency if previous else None,
        settings=settings,
        allow_cpu_contention=bool(policy and policy.full_cpu_override is not None),
        now=decided_at,
        available_memory_mb=metrics.available_memory_mb,
        memory_reserve_mb=policy.memory_reserve_mb if policy else None,
        free_disk_mb=metrics.free_disk_mb,
        disk_reserve_mb=(volume_reserve_mb(config.remote_root, config.disk_reserve_gib * 1024,
                                          config.c_drive_reserve_gib * 1024) if config else None),
        disk_block_reason=execution_disk_block_reason(
            metrics, now=status.last_checked_at or decided_at,
            reserve_mb=config.disk_reserve_gib * 1024 if config else 0,
            c_drive_reserve_mb=config.c_drive_reserve_gib * 1024 if config else 20 * 1024,
            root_volume=config.remote_root if config else "",
        ),
    )
    return MachineCapacityDecision.from_capacity(decision, decided_at=decided_at)


def finalize_operational_status(
    status: MachineOperationalStatus,
    *,
    machine: MachineState,
    policy: MachinePolicy | None,
    config: MachineExecutionConfig | None,
    previous: MachineOperationalStatus | None,
    pressure_settings: PressurePolicySettings,
) -> MachineOperationalStatus:
    """Return the canonical operational view for one observation."""

    result = project_channel_health(merge_channel_evidence(status, previous))
    # Legacy callers may provide the process-set identity on the status while
    # the machine snapshot has not yet been normalized. Preserve that evidence
    # until a newer generic observation replaces it.
    observed_process_hash = (
        machine.metrics.external_process_set_hash
        or machine.metrics.external_comsol_process_set_hash
        or result.external_process_set_hash
        or result.external_comsol_process_set_hash
    )
    observed_process_count = max(
        machine.metrics.external_process_count,
        machine.metrics.external_comsol_process_count,
        result.external_process_count,
        result.external_comsol_process_count,
    )
    if previous is not None and result.supervisor_reported_concurrent_units is None:
        result.supervisor_reported_concurrent_units = previous.supervisor_reported_concurrent_units
    if (
        previous is not None
        and previous.last_metric_at is not None
        and result.last_metric_at is not None
        and _aware(result.last_metric_at) < _aware(previous.last_metric_at)
    ):
        # Preserve the persisted status identity while the repository rejects
        # this older sample by timestamp.
        result.last_metric_at = previous.last_metric_at

    reported = result.supervisor_reported_concurrent_units
    if config is not None and reported is not None:
        result.capacity_drift = reported != config.target_concurrent_units
        result.capacity_drift_reason = (
            f"Control Plane target is {config.target_concurrent_units}, but the remote Supervisor "
            f"reports {reported}; effective dispatch capacity is clamped to the remote value"
            if result.capacity_drift
            else ""
        )

    if policy is not None and policy.effective_mode() != MachineMode.OPEN:
        result.control_state = ControlState.MAINTENANCE
    elif result.supervisor_state != SupervisorState.ONLINE:
        result.control_state = ControlState.EXECUTOR_UNAVAILABLE
    elif result.transport_state != TransportState.CONNECTED:
        result.control_state = ControlState.TRANSPORT_BLOCKED
    else:
        result.control_state = ControlState.ACCEPTING

    has_new_live_observation = (
        result.telemetry_state == TelemetryState.LIVE
        and result.last_metric_at is not None
        and (previous is None or _aware(previous.last_metric_at) != _aware(result.last_metric_at))
    )
    if result.telemetry_state != TelemetryState.LIVE:
        decision = decide_machine_capacity(
            policy=policy,
            config=config,
            status=result,
            metrics=machine.metrics,
            settings=pressure_settings,
            previous=previous,
        )
        result.pressure_state = decision.pressure_state
        result.effective_capacity = decision.effective_capacity
        result.effective_comsol_concurrency = decision.effective_capacity
        result.capacity_reason = decision.reason
        result.capacity_decision_at = decision.decided_at
    elif result.capacity_decision_at is not None and result.last_metric_at is None:
        # A status-only caller supplied a complete decision without a new
        # metric sample. Preserve that explicit evidence.
        pass
    elif has_new_live_observation and config is None:
        result.pressure_state = machine.metrics.external_pressure.state
        result.effective_capacity = None
        result.effective_comsol_concurrency = None
        result.capacity_reason = machine.metrics.external_pressure.reason
        result.capacity_decision_at = result.last_metric_at
        result.external_process_set_hash = observed_process_hash
        result.external_process_count = observed_process_count
        result.external_comsol_process_set_hash = result.external_process_set_hash
        result.external_comsol_process_count = result.external_process_count
    elif has_new_live_observation or previous is None:
        decision = decide_machine_capacity(
            policy=policy,
            config=config,
            status=result,
            metrics=machine.metrics,
            settings=pressure_settings,
            previous=previous,
        )
        result.pressure_state = decision.pressure_state
        result.effective_capacity = decision.effective_capacity
        result.effective_comsol_concurrency = decision.effective_capacity
        result.capacity_reason = decision.reason
        result.capacity_decision_at = decision.decided_at
        result.external_process_set_hash = observed_process_hash
        result.external_process_count = observed_process_count
        result.external_comsol_process_set_hash = result.external_process_set_hash
        result.external_comsol_process_count = result.external_process_count
    elif previous is not None:
        result.pressure_state = previous.pressure_state
        result.effective_capacity = previous.effective_capacity
        result.effective_comsol_concurrency = previous.effective_comsol_concurrency
        result.capacity_reason = previous.capacity_reason
        result.capacity_decision_at = previous.capacity_decision_at

    if previous is not None:
        if result.pressure_override_until is None:
            result.pressure_override_until = previous.pressure_override_until
            result.pressure_override_reason = previous.pressure_override_reason
            result.pressure_override_actor = previous.pressure_override_actor
            result.pressure_override_hash = previous.pressure_override_hash
            result.pressure_override_concurrency = previous.pressure_override_concurrency
        if result.external_process_set_hash is None:
            result.external_process_set_hash = previous.external_process_set_hash
            result.external_process_count = previous.external_process_count
        result.external_comsol_process_set_hash = result.external_process_set_hash
        result.external_comsol_process_count = result.external_process_count

    result.capacity_reason_codes = list(machine.metrics.external_load.reason_codes)

    issues = observation_consistency_issues(machine, result)
    result.observation_consistent = not issues
    result.observation_issues = issues
    if result.capacity_drift and result.capacity_drift_reason not in result.capacity_reason:
        result.capacity_reason = "; ".join(
            filter(None, (result.capacity_drift_reason, result.capacity_reason))
        )
    return result


def observation_consistency_issues(
    machine: MachineState,
    status: MachineOperationalStatus | None,
    latest_raw: MetricSample | None = None,
) -> list[str]:
    issues: list[str] = []
    metric_at = _aware(machine.metrics.observed_at)
    heartbeat_at = _aware(machine.last_heartbeat_at)
    if metric_at != heartbeat_at:
        issues.append("machine heartbeat and metric timestamps differ")
    if machine.metrics.external_process_count != machine.metrics.external_load.external_process_count:
        issues.append("external process count differs between metrics and load evidence")
    if machine.metrics.external_process_set_hash != machine.metrics.external_load.process_set_hash:
        issues.append("external process hash differs between metrics and load evidence")
    if status is not None and status.telemetry_state == TelemetryState.LIVE:
        # A sample older than the persisted observation is rejected atomically
        # by the repository. Do not turn that expected ordering race into a
        # misleading consistency failure against the previous status.
        if _aware(status.last_metric_at) == metric_at:
            if _aware(status.capacity_decision_at) != metric_at:
                issues.append("capacity decision references a different observation")
            if status.external_process_count != machine.metrics.external_process_count:
                issues.append("operational status external process count is stale")
            if status.external_process_set_hash != machine.metrics.external_process_set_hash:
                issues.append("operational status external process hash is stale")
    if latest_raw is not None:
        if _aware(latest_raw.recorded_at) != metric_at:
            issues.append("latest raw metric sample is not the machine observation")
        if latest_raw.metrics.external_process_count != machine.metrics.external_process_count:
            issues.append("raw metric external process count differs from machine state")
        if latest_raw.metrics.external_process_set_hash != machine.metrics.external_process_set_hash:
            issues.append("raw metric external process hash differs from machine state")
    return issues


class MachineObservationApplication:
    """Prepare canonical observation aggregates and read-only diagnostics."""

    def __init__(self, repository: MachineObservationRepository) -> None:
        self.repository = repository

    def prepare(
        self,
        heartbeat: MachineHeartbeat,
        *,
        status: MachineOperationalStatus | None,
    ) -> MachineObservationResult:
        machine = self.repository.get_machine(heartbeat.machine_id)
        if machine is None:
            raise KeyError(f"machine not found: {heartbeat.machine_id}")
        previous_status = self.repository.get_machine_operational_status(heartbeat.machine_id)
        pressure_settings = self.repository.get_feature_settings().pressure_policy
        policy = self.repository.get_policy(heartbeat.machine_id)
        config = self.repository.get_machine_execution_config(heartbeat.machine_id)
        observation = MachineObservation.from_heartbeat(
            heartbeat,
            previous_metrics=machine.metrics,
            pressure_settings=pressure_settings,
            memory_reserve_mb=policy.memory_reserve_mb if policy else None,
            disk_reserve_mb=config.disk_reserve_gib * 1024 if config else None,
            c_drive_reserve_mb=config.c_drive_reserve_gib * 1024 if config else 20 * 1024,
            root_volume=config.remote_root if config else "",
        )
        updated = machine.model_copy(deep=True)
        updated.metrics = observation.metrics
        updated.last_heartbeat_at = observation.observed_at
        if heartbeat.applied_telemetry_policy is not None:
            updated.applied_telemetry_policy = heartbeat.applied_telemetry_policy
        if heartbeat.applied_telemetry_policy_sha256 is not None:
            updated.applied_telemetry_policy_sha256 = heartbeat.applied_telemetry_policy_sha256
        if observation.metrics.gpu:
            updated.total_gpus = len(observation.metrics.gpu)

        final_status = None
        if status is not None:
            final_status = finalize_operational_status(
                status,
                machine=updated,
                policy=policy,
                config=config,
                previous=previous_status,
                pressure_settings=pressure_settings,
            )
        sample = MetricSample(
            sample_id=f"{updated.machine_id}:raw:{observation.observed_at.isoformat()}",
            machine_id=updated.machine_id,
            sample_kind="raw",
            metrics=observation.metrics,
            recorded_at=observation.observed_at,
        )
        return MachineObservationResult(updated, final_status, sample, observation)

    def diagnostics(self, *, now: datetime | None = None) -> dict:
        checked_at = now or datetime.now(timezone.utc)
        machines = []
        for machine in self.repository.list_machines():
            status = self.repository.get_machine_operational_status(machine.machine_id)
            samples = self.repository.list_metric_samples(
                machine.machine_id,
                sample_kind="raw",
                since=machine.metrics.observed_at,
                limit=10,
            )
            latest_raw = samples[-1] if samples else None
            issues = observation_consistency_issues(machine, status, latest_raw)
            observed_at = _aware(machine.metrics.observed_at)
            age_s = max(0.0, (checked_at - observed_at).total_seconds()) if observed_at else None
            machines.append({
                "machine_id": machine.machine_id,
                "consistent": not issues,
                "issues": issues,
                "observation_at": machine.metrics.observed_at.isoformat(),
                "observation_age_s": round(age_s, 3) if age_s is not None else None,
                "source": machine.metrics.source,
                "external_process_count": machine.metrics.external_process_count,
                "external_process_set_hash": machine.metrics.external_process_set_hash,
                "external_load": {
                    "cpu_percent": machine.metrics.external_load.external_cpu_percent,
                    "gpu_utilization_percent": machine.metrics.external_load.external_gpu_utilization_percent,
                    "memory_mb": machine.metrics.external_load.external_memory_mb,
                    "attribution_quality": machine.metrics.external_load.attribution_quality,
                    "reason_codes": list(machine.metrics.external_load.reason_codes),
                },
                # Compatibility aliases remain available to 0.13.0 clients.
                "external_comsol_process_count": machine.metrics.external_comsol_process_count,
                "external_comsol_process_set_hash": machine.metrics.external_comsol_process_set_hash,
                "pressure_state": (
                    status.pressure_state.value if status else machine.metrics.external_pressure.state.value
                ),
                "configured_capacity": (
                    self.repository.get_machine_execution_config(machine.machine_id).target_concurrent_units
                    if self.repository.get_machine_execution_config(machine.machine_id)
                    else None
                ),
                "effective_capacity": status.effective_capacity if status else None,
                "effective_comsol_concurrency": status.effective_comsol_concurrency if status else None,
                "capacity_reason": status.capacity_reason if status else "operational status unavailable",
                "capacity_reason_codes": status.capacity_reason_codes if status else list(machine.metrics.external_load.reason_codes),
            })
        return {
            "checked_at": checked_at.isoformat(),
            "consistent": all(item["consistent"] for item in machines),
            "machine_count": len(machines),
            "machines": machines,
        }
