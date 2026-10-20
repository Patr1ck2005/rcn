"""Read-time freshness rules for machine operational observations."""

from __future__ import annotations

from datetime import datetime, timezone

from .models import (
    ControlState,
    HeartbeatPhase,
    MachineOperationalStatus,
    SupervisorState,
    TelemetryState,
    TransportState,
)


def age_machine_operational_status(
    status: MachineOperationalStatus,
    *,
    now: datetime | None = None,
    stale_after_s: int = 90,
    offline_after_s: int = 180,
) -> MachineOperationalStatus:
    """Return a freshness-derived view without mutating persisted evidence."""

    if "outbound" in status.connection_evidence:
        from .connection_health import project_channel_health

        return project_channel_health(status, now=now, stale_after_s=stale_after_s,
                                      offline_after_s=offline_after_s)

    if status.last_checked_at is None:
        return status
    current = now or datetime.now(timezone.utc)
    checked_at = status.last_checked_at
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    age_s = max(0.0, (current - checked_at.astimezone(timezone.utc)).total_seconds())
    if age_s <= stale_after_s:
        return status

    offline = age_s > max(stale_after_s, offline_after_s)
    telemetry_state = (
        TelemetryState.STALE if status.last_metric_at is not None else TelemetryState.UNAVAILABLE
    )
    return status.model_copy(update={
        "transport_state": TransportState.UNKNOWN,
        "supervisor_state": SupervisorState.STALE,
        "telemetry_state": telemetry_state,
        "control_state": ControlState.EXECUTOR_UNAVAILABLE,
        "heartbeat_phase": HeartbeatPhase.OFFLINE if offline else HeartbeatPhase.STALE,
        "detail": f"monitor observation is {age_s:.0f}s old; live transport state is unknown",
        "consecutive_successes": 0,
    })
