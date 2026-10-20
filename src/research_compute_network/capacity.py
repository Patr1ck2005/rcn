"""Runtime capacity decisions for shared machines.

The static machine and execution configuration remains the owner-approved
upper bound.  Runtime pressure is derived from a generic external-load
observation so the scheduler does not need to know which scientific program
created the load.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .models import ExternalLoadSnapshot, ExternalPressureSnapshot, PressurePolicySettings, PressureState, TelemetryState

_PRESSURE_CODES = {
    "external_cpu_pressure",
    "external_gpu_pressure",
    "external_memory_pressure",
    "memory_reserve_pressure",
    "disk_reserve_pressure",
    "telemetry_attribution_degraded",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def external_pressure_reason(
    snapshot: ExternalLoadSnapshot,
    *,
    policy: PressurePolicySettings | None = None,
    available_memory_mb: int | None = None,
    memory_reserve_mb: int | None = None,
    free_disk_mb: int | None = None,
    disk_reserve_mb: int | None = None,
) -> tuple[bool, str]:
    configured = policy or PressurePolicySettings()
    triggers: list[str] = []
    if snapshot.attribution_quality in {"complete", "partial"}:
        if snapshot.external_cpu_percent >= configured.external_cpu_threshold_percent:
            triggers.append("external_cpu_pressure")
        if snapshot.external_gpu_utilization_percent >= configured.external_gpu_threshold_percent:
            triggers.append("external_gpu_pressure")
    elif snapshot.external_process_count or snapshot.external_cpu_percent or snapshot.external_gpu_utilization_percent:
        snapshot.reason_codes = sorted(set(snapshot.reason_codes) | {"telemetry_attribution_degraded"})
    if (
        memory_reserve_mb is not None
        and available_memory_mb is not None
        and available_memory_mb < memory_reserve_mb
    ):
        triggers.append("memory_reserve_pressure")
    if (
        configured.memory_mode == "low_headroom"
        and available_memory_mb is not None
        and available_memory_mb < configured.available_memory_floor_mb
    ):
        triggers.append("memory_reserve_pressure")
    if configured.memory_mode == "absolute" and snapshot.external_memory_mb >= configured.external_memory_threshold_mb:
        # Compatibility for pre-0.13.1 policy settings.  New deployments use
        # the machine's explicit memory reserve above. Keep this independent
        # so a configured reserve cannot silently disable a legacy policy.
        triggers.append("external_memory_pressure")
    if disk_reserve_mb is not None and free_disk_mb is not None and free_disk_mb < disk_reserve_mb:
        triggers.append("disk_reserve_pressure")
    if triggers:
        return True, "; ".join(triggers)
    if snapshot.reason_codes:
        return False, "; ".join(snapshot.reason_codes)
    if snapshot.external_memory_mb and configured.memory_mode == "resource_gate_only":
        return False, "external load below thresholds; per-task resource gates remain authoritative"
    return False, "external load below configured pressure thresholds"


def has_external_pressure(
    snapshot: ExternalLoadSnapshot,
    *,
    policy: PressurePolicySettings | None = None,
    available_memory_mb: int | None = None,
    memory_reserve_mb: int | None = None,
    free_disk_mb: int | None = None,
    disk_reserve_mb: int | None = None,
) -> bool:
    return external_pressure_reason(
        snapshot,
        policy=policy,
        available_memory_mb=available_memory_mb,
        memory_reserve_mb=memory_reserve_mb,
        free_disk_mb=free_disk_mb,
        disk_reserve_mb=disk_reserve_mb,
    )[0]


@dataclass
class PressureTracker:
    """Apply enter/clear hysteresis to successive remote samples."""

    snapshot: ExternalLoadSnapshot = field(default_factory=ExternalLoadSnapshot)

    def update(
        self,
        sample: ExternalLoadSnapshot,
        *,
        now: datetime | None = None,
        policy: PressurePolicySettings | None = None,
        available_memory_mb: int | None = None,
        memory_reserve_mb: int | None = None,
        free_disk_mb: int | None = None,
        disk_reserve_mb: int | None = None,
    ) -> ExternalLoadSnapshot:
        current = now or sample.observed_at or _utc_now()
        configured = policy or PressurePolicySettings()
        candidate, observed_reason = external_pressure_reason(
            sample,
            policy=configured,
            available_memory_mb=available_memory_mb,
            memory_reserve_mb=memory_reserve_mb,
            free_disk_mb=free_disk_mb,
            disk_reserve_mb=disk_reserve_mb,
        )
        previous = self.snapshot
        reason_codes = sorted(
            set(sample.reason_codes)
            | {code for code in observed_reason.split("; ") if code in _PRESSURE_CODES}
        )
        if candidate:
            candidate_since = previous.candidate_since or current
            pressured_since = previous.pressured_since
            state = previous.state
            if state != PressureState.PRESSURED and (
                current - candidate_since
            ).total_seconds() >= configured.enter_after_seconds:
                state = PressureState.PRESSURED
                pressured_since = pressured_since or current
            elif state == PressureState.NORMAL:
                state = PressureState.CANDIDATE
            reason = observed_reason
            result = sample.model_copy(update={
                "state": state,
                "candidate_since": candidate_since,
                "pressured_since": pressured_since,
                "cleared_at": None,
                "reason": reason,
                "reason_codes": reason_codes,
                "observed_at": current,
            })
        else:
            if previous.state == PressureState.PRESSURED and previous.cleared_at is None:
                cleared_at = current
                if configured.clear_after_seconds == 0:
                    state = PressureState.NORMAL
                    reason = observed_reason
                else:
                    state = PressureState.PRESSURED
                    reason = "pressure below threshold; waiting for clear hysteresis"
            elif previous.state == PressureState.PRESSURED and previous.cleared_at is not None:
                cleared_at = previous.cleared_at
                if (current - cleared_at).total_seconds() >= configured.clear_after_seconds:
                    state = PressureState.NORMAL
                    cleared_at = current
                    reason = "external load pressure cleared"
                else:
                    state = PressureState.PRESSURED
                    reason = "pressure below threshold; waiting for clear hysteresis"
            else:
                state = PressureState.NORMAL
                cleared_at = current
                reason = observed_reason
            if state == PressureState.PRESSURED:
                # The Control Plane reconstructs this tracker for each
                # heartbeat. Keep the known cause while its clear window is
                # still active, including non-CPU or unknown reason codes.
                # A quiet raw sample alone must not erase that evidence.
                reason_codes = sorted(
                    set(reason_codes) | set(previous.reason_codes)
                    | {code for code in previous.reason.split("; ") if code in _PRESSURE_CODES}
                )
            result = sample.model_copy(update={
                "state": state,
                "candidate_since": None,
                "pressured_since": previous.pressured_since if state == PressureState.PRESSURED else None,
                "cleared_at": cleared_at,
                "reason": reason,
                "reason_codes": reason_codes,
                "observed_at": current,
            })
        self.snapshot = result
        return result


@dataclass(frozen=True)
class CapacityDecision:
    normal_cap: int
    effective_cap: int
    state: PressureState
    reason: str


def effective_capacity(
    *,
    policy_cap: int,
    execution_cap: int,
    profile_cap: int | None,
    profile_id: str,
    pressure: ExternalLoadSnapshot,
    telemetry_state: TelemetryState,
    telemetry_stale_age_s: float | None = None,
    target_cap: int | None = None,
    override_until: datetime | None = None,
    override_cap: int | None = None,
    settings: PressurePolicySettings | None = None,
    now: datetime | None = None,
    available_memory_mb: int | None = None,
    memory_reserve_mb: int | None = None,
    free_disk_mb: int | None = None,
    disk_reserve_mb: int | None = None,
    disk_block_reason: str = "",
    allow_cpu_contention: bool = False,
) -> CapacityDecision:
    configured = settings or PressurePolicySettings()
    configured_target = execution_cap if target_cap is None else target_cap
    normal_cap = min(
        policy_cap,
        execution_cap,
        configured_target,
        profile_cap if profile_cap is not None else execution_cap,
    )
    current = now or _utc_now()
    # Disk exhaustion is a hard resource gate, not soft CPU load pressure.
    # Neither a stale-telemetry grace nor an admin pressure override bypasses it.
    if disk_block_reason or (disk_reserve_mb is not None and free_disk_mb is not None
                            and free_disk_mb < disk_reserve_mb):
        return CapacityDecision(
            normal_cap, 0, PressureState.PRESSURED,
            disk_block_reason or "disk_reserve_pressure: insufficient free disk",
        )
    if telemetry_state != TelemetryState.LIVE:
        # A briefly late telemetry sample must not flap the machine between
        # its normal cap and the stale cap (observed as hundreds of
        # pressure_changed oscillations per day under full load). Within the
        # grace window since the last good sample, retain normal capacity;
        # beyond it, fall back to the conservative stale cap.
        if (
            configured.telemetry_stale_grace_s > 0
            and telemetry_stale_age_s is not None
            and telemetry_stale_age_s <= configured.telemetry_stale_grace_s
        ):
            return CapacityDecision(
                normal_cap,
                normal_cap,
                PressureState.TELEMETRY_STALE,
                "telemetry stale within grace window; retaining capacity",
            )
        return CapacityDecision(
            normal_cap,
            min(normal_cap, configured.telemetry_stale_cap),
            PressureState.TELEMETRY_STALE,
            "telemetry is stale or unavailable",
        )
    if override_until is not None and override_until > current:
        requested_override = normal_cap if override_cap is None else override_cap
        override_effective = min(
            policy_cap,
            execution_cap,
            requested_override,
            profile_cap if profile_cap is not None else execution_cap,
        )
        return CapacityDecision(
            normal_cap,
            override_effective,
            PressureState.OVERRIDE,
            "active administrator pressure override",
        )
    if pressure.state == PressureState.PRESSURED:
        recorded_codes = set(pressure.reason_codes) | {
            code for code in pressure.reason.split("; ") if code in _PRESSURE_CODES
        }
        if (allow_cpu_contention
                and pressure.attribution_quality in {"complete", "partial"}
                and recorded_codes == {"external_cpu_pressure"}):
            # Owner consent permits CPU contention only. Recheck current load
            # and resource reserves so a stale CPU-only reason cannot hide a
            # newly observed GPU, memory or disk restriction.
            _, current_reason = external_pressure_reason(
                pressure, policy=configured,
                available_memory_mb=available_memory_mb,
                memory_reserve_mb=memory_reserve_mb,
                free_disk_mb=free_disk_mb,
                disk_reserve_mb=disk_reserve_mb,
            )
            current_codes = {
                code for code in current_reason.split("; ") if code in _PRESSURE_CODES
            }
            if current_codes <= {"external_cpu_pressure"}:
                return CapacityDecision(
                    normal_cap, normal_cap, PressureState.OVERRIDE,
                    "owner-authorized full CPU contention; CPU pressure does not reduce capacity",
                )
        # Missing reasons during clear hysteresis cannot prove that the prior
        # pressure was CPU-only; retain the existing conservative clear window.
        return CapacityDecision(
            normal_cap,
            min(normal_cap, configured.pressured_dispatch_cap),
            pressure.state,
            pressure.reason,
        )
    return CapacityDecision(normal_cap, normal_cap, pressure.state, pressure.reason)


def effective_comsol_capacity(**kwargs) -> CapacityDecision:
    """Compatibility wrapper; capacity policy is now profile-agnostic."""

    return effective_capacity(**kwargs)
