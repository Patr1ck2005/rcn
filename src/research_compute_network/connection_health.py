"""Independent, server-observed SSH and outbound-heartbeat evidence.

This is control-plane metadata only: Worker heartbeat/status wire contracts and
sealed bytes stay unchanged. A new observation cannot re-date the other path.
The merge is idempotent and is repeated under the repository write transaction
so concurrent HTTP/pull writers do not erase each other's channel evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
from .models import (
    ChannelObservation, ControlState, HeartbeatPhase, MachineOperationalStatus,
    SupervisorState, TelemetryState, TransportState,
)


class StaleMachineObservationError(ValueError):
    """Validated identity reached the center, but a newer metric snapshot won."""


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def fresh(value: datetime | None, now: datetime, maximum_s: float = 90) -> bool:
    return value is not None and 0 <= (_aware(now) - _aware(value)).total_seconds() <= maximum_s


def merge_channel_evidence(
    incoming: MachineOperationalStatus,
    previous: MachineOperationalStatus | None,
) -> MachineOperationalStatus:
    result = incoming.model_copy(deep=True)
    channels = {name: item.model_copy(deep=True) for name, item in
                (previous.connection_evidence.items() if previous else [])}
    for name, item in incoming.connection_evidence.items():
        prior = channels.get(name)
        if prior is not None and _aware(item.observed_at) <= _aware(prior.observed_at):
            continue
        item = item.model_copy(deep=True)
        item.consecutive_successes = (prior.consecutive_successes if prior else 0) + 1 if item.healthy else 0
        item.consecutive_failures = 0 if item.healthy else (prior.consecutive_failures if prior else 0) + 1
        item.ready = item.healthy and (prior is None or prior.ready or item.consecutive_successes >= 2)
        channels[name] = item
    result.connection_evidence = channels
    return result


def project_channel_health(
    status: MachineOperationalStatus,
    *,
    now: datetime | None = None,
    stale_after_s: int = 90,
    offline_after_s: int = 180,
) -> MachineOperationalStatus:
    """Overlay only proven health; legacy records are handled by their old reader."""
    if "outbound" not in status.connection_evidence:
        return status
    now = now or datetime.now(timezone.utc)
    result = status.model_copy(deep=True)
    ssh = result.connection_evidence.get("ssh")
    outbound = result.connection_evidence.get("outbound")
    live_ssh = ssh if ssh and fresh(ssh.observed_at, now, stale_after_s) else None
    live_outbound = outbound if outbound and fresh(outbound.observed_at, now, stale_after_s) else None
    result.transport_state = live_ssh.transport_state if live_ssh else TransportState.UNKNOWN
    candidates = [item for item in (live_ssh, live_outbound) if item and fresh(item.supervisor_at, now, stale_after_s)]
    supervisor_live = bool(candidates)
    metric_live = fresh(result.last_metric_at, now, stale_after_s) and any(
        fresh(item.metric_at, now, stale_after_s) for item in candidates
    )
    if supervisor_live:
        result.supervisor_state = SupervisorState.ONLINE
        result.last_supervisor_heartbeat_at = max(_aware(item.supervisor_at) for item in candidates)
    else:
        result.supervisor_state = SupervisorState.STALE if result.last_supervisor_heartbeat_at else SupervisorState.UNAVAILABLE
    result.telemetry_state = (TelemetryState.LIVE if metric_live else
                              TelemetryState.STALE if result.last_metric_at else TelemetryState.UNAVAILABLE)
    counter_source = ssh or outbound
    result.consecutive_successes = counter_source.consecutive_successes if counter_source else 0
    result.consecutive_failures = counter_source.consecutive_failures if counter_source else 0
    result.last_checked_at = max(_aware(item.observed_at) for item in result.connection_evidence.values())
    if supervisor_live and metric_live:
        if live_ssh is not None:
            ready = live_ssh.ready and live_ssh.transport_state == TransportState.CONNECTED
        else:
            # A never-SSH/legacy HTTP-only node keeps its existing unknown
            # transport behavior. A formerly monitored node cannot bypass a
            # missing SSH check just by posting a heartbeat.
            ready = ssh is None and bool(live_outbound and live_outbound.ready)
        result.heartbeat_phase = HeartbeatPhase.HEALTHY if ready else HeartbeatPhase.DELAYED
    else:
        recent = any(fresh(item.observed_at, now, offline_after_s) for item in result.connection_evidence.values())
        result.heartbeat_phase = HeartbeatPhase.STALE if recent else HeartbeatPhase.OFFLINE
    if result.control_state != ControlState.MAINTENANCE:
        result.control_state = (ControlState.EXECUTOR_UNAVAILABLE if not supervisor_live else
                                ControlState.TRANSPORT_BLOCKED if result.transport_state != TransportState.CONNECTED else
                                ControlState.ACCEPTING)
    if live_ssh and live_ssh.transport_state != TransportState.CONNECTED and live_outbound and supervisor_live:
        result.detail = "SSH unavailable; independent authenticated heartbeat is live"
    elif live_ssh and live_ssh.transport_state == TransportState.CONNECTED and not supervisor_live:
        result.detail = "SSH reachable; supervisor evidence is stale or unavailable"
    elif not live_ssh and not live_outbound:
        result.detail = "No fresh channel evidence; host or network unreachable, cause unconfirmed"
    elif ssh and not live_ssh and live_outbound:
        result.detail = "Independent heartbeat is live; SSH observation expired (transport unknown)"
    return result


def ssh_observation(status: MachineOperationalStatus) -> ChannelObservation:
    return ChannelObservation(
        observed_at=status.last_checked_at or datetime.now(timezone.utc),
        transport_state=status.transport_state,
        supervisor_at=(status.last_supervisor_heartbeat_at
                       if status.transport_state == TransportState.CONNECTED else None),
        metric_at=(status.last_metric_at if status.transport_state == TransportState.CONNECTED else None),
        healthy=(status.transport_state == TransportState.CONNECTED and
                 status.supervisor_state == SupervisorState.ONLINE and status.telemetry_state == TelemetryState.LIVE),
    )
