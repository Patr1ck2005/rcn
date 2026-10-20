"""Background SSH pull monitor for accepted Windows workers."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from .connection_health import StaleMachineObservationError, ssh_observation
from .models import (
    HeartbeatPhase,
    MachineExecutionConfig,
    MachineHeartbeat,
    MachineMetrics,
    MachineOperationalStatus,
    SupervisorState,
    TelemetryState,
    TransportState,
)
from .schedulers.ssh import OpenSshTransport
from .service import NetworkService


TransportFactory = Callable[[MachineExecutionConfig], OpenSshTransport]
logger = logging.getLogger(__name__)


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("remote timestamp is missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("remote timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _safe_detail(exc: BaseException) -> str:
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        return "reverse SSH port accepted TCP but SSH banner/status timed out; likely half-open tunnel"
    text = " ".join(str(exc).split())
    return f"{type(exc).__name__}: {text}"[:240]


def _reported_concurrency(payload: dict) -> int | None:
    value = payload.get("max_concurrent_units")
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("remote supervisor capacity is invalid")
    reported = int(value)
    if reported < 0 or reported > 64:
        raise ValueError("remote supervisor capacity is outside the supported range")
    return reported


def _capacity_drift(config: MachineExecutionConfig, reported: int | None) -> tuple[bool, str]:
    if reported is None or reported == config.target_concurrent_units:
        return False, ""
    return True, (
        f"Control Plane target is {config.target_concurrent_units}, but the remote Supervisor "
        f"reports {reported}; effective dispatch capacity is clamped to the remote value"
    )


class SshMachineMonitor:
    def __init__(
        self,
        service: NetworkService,
        *,
        state_root: str | Path,
        transport_factory: TransportFactory | None = None,
        supervisor_stale_after_s: int = 45,
        telemetry_stale_after_s: int = 45,
        heartbeat_stale_after_s: int = 90,
        max_parallel_polls: int = 1,
    ) -> None:
        self.service = service
        self.repository = service.repository
        self.state_root = Path(state_root)
        self.transport_factory = transport_factory or (
            lambda config: OpenSshTransport(config, state_root=self.state_root)
        )
        self.supervisor_stale_after_s = supervisor_stale_after_s
        self.telemetry_stale_after_s = telemetry_stale_after_s
        self.heartbeat_stale_after_s = heartbeat_stale_after_s
        self.max_parallel_polls = max(1, max_parallel_polls)
        self._next_poll: dict[str, float] = {}
        self.last_cycle_at: datetime | None = None
        self.last_successful_cycle_at: datetime | None = None
        self.last_error: str | None = None
        self.last_cycle_error_count = 0
        self.cycle_count = 0
        self.active_polls = 0

    def _publish_status(self, status: MachineOperationalStatus, *, actor_id: str) -> MachineOperationalStatus:
        evidence = ssh_observation(status)
        status.connection_evidence = {"ssh": evidence}
        updated = self.service.update_operational_status(status, actor_id=actor_id)
        self.repository.put_machine_channel_observation(status.machine_id, "ssh", evidence)
        return self.repository.get_machine_operational_status(status.machine_id) or updated

    def poll_once(self, config: MachineExecutionConfig) -> MachineOperationalStatus:
        machine_id = config.machine_id
        actor = f"ssh-monitor:{machine_id}"
        previous = self.repository.get_machine_operational_status(machine_id)
        checked_at = datetime.now(timezone.utc)
        try:
            payload = self.transport_factory(config).read_supervisor_status()
            checked_at = datetime.now(timezone.utc)
            if payload.get("machine_id") != machine_id:
                raise ValueError("remote supervisor machine identity mismatch")
            if config.root_uuid and payload.get("root_uuid") != config.root_uuid:
                raise ValueError("remote supervisor root identity mismatch")
            reported_capacity = _reported_concurrency(payload)
            capacity_drift, capacity_drift_reason = _capacity_drift(config, reported_capacity)
            supervisor_at = _parse_datetime(payload.get("updated_at"))
            supervisor_age = (checked_at - supervisor_at).total_seconds()
            if supervisor_age > self.supervisor_stale_after_s:
                failures = (previous.consecutive_failures if previous else 0) + 1
                is_stale = supervisor_age >= self.heartbeat_stale_after_s and failures >= 2
                status = MachineOperationalStatus(
                    machine_id=machine_id,
                    transport_state=TransportState.CONNECTED,
                    supervisor_state=SupervisorState.STALE if is_stale else SupervisorState.ONLINE,
                    telemetry_state=(
                        TelemetryState.STALE if previous and previous.last_metric_at else TelemetryState.UNAVAILABLE
                    ),
                    last_checked_at=checked_at,
                    last_supervisor_heartbeat_at=supervisor_at,
                    last_metric_at=previous.last_metric_at if previous else None,
                    telemetry_source=previous.telemetry_source if previous else "ssh-supervisor",
                    detail=f"supervisor heartbeat is {supervisor_age:.0f}s old",
                    consecutive_successes=0,
                    consecutive_failures=failures,
                    heartbeat_phase=HeartbeatPhase.STALE if is_stale else HeartbeatPhase.DELAYED,
                    supervisor_reported_concurrent_units=reported_capacity,
                    capacity_drift=capacity_drift,
                    capacity_drift_reason=capacity_drift_reason,
                )
                return self._publish_status(status, actor_id=actor)

            raw_metrics = payload.get("metrics")
            if not isinstance(raw_metrics, dict) or not raw_metrics.get("available"):
                failures = (previous.consecutive_failures if previous else 0) + 1
                reasons = raw_metrics.get("unavailable_reasons", []) if isinstance(raw_metrics, dict) else []
                status = MachineOperationalStatus(
                    machine_id=machine_id,
                    transport_state=TransportState.CONNECTED,
                    supervisor_state=SupervisorState.ONLINE,
                    telemetry_state=TelemetryState.UNAVAILABLE,
                    last_checked_at=checked_at,
                    last_supervisor_heartbeat_at=supervisor_at,
                    last_metric_at=previous.last_metric_at if previous else None,
                    telemetry_source="ssh-supervisor",
                    detail="; ".join(str(reason) for reason in reasons)[:240] or "remote metrics unavailable",
                    consecutive_successes=0,
                    consecutive_failures=failures,
                    heartbeat_phase=(
                        HeartbeatPhase.STALE if failures >= 2 else HeartbeatPhase.DELAYED
                    ),
                    supervisor_reported_concurrent_units=reported_capacity,
                    capacity_drift=capacity_drift,
                    capacity_drift_reason=capacity_drift_reason,
                )
                return self._publish_status(status, actor_id=actor)

            metrics = MachineMetrics.model_validate(raw_metrics)
            metric_age = (checked_at - metrics.observed_at).total_seconds()
            telemetry_stale_after_s = (
                config.telemetry_policy.stale_after_s
                if config.telemetry_policy is not None
                else self.telemetry_stale_after_s
            )
            if metric_age > telemetry_stale_after_s:
                failures = (previous.consecutive_failures if previous else 0) + 1
                is_stale = metric_age >= self.heartbeat_stale_after_s and failures >= 2
                status = MachineOperationalStatus(
                    machine_id=machine_id,
                    transport_state=TransportState.CONNECTED,
                    supervisor_state=SupervisorState.ONLINE,
                    telemetry_state=TelemetryState.STALE,
                    last_checked_at=checked_at,
                    last_supervisor_heartbeat_at=supervisor_at,
                    last_metric_at=metrics.observed_at,
                    telemetry_source=metrics.source,
                    detail=f"telemetry sample is {metric_age:.0f}s old",
                    consecutive_successes=0,
                    consecutive_failures=failures,
                    heartbeat_phase=HeartbeatPhase.STALE if is_stale else HeartbeatPhase.DELAYED,
                    supervisor_reported_concurrent_units=reported_capacity,
                    capacity_drift=capacity_drift,
                    capacity_drift_reason=capacity_drift_reason,
                )
                return self._publish_status(status, actor_id=actor)

            running_ids = [str(value) for value in payload.get("active_run_ids", [])]
            successes = (previous.consecutive_successes if previous else 0) + 1
            recovering = previous is not None and previous.heartbeat_phase != HeartbeatPhase.HEALTHY
            heartbeat_phase = (
                HeartbeatPhase.HEALTHY if not recovering or successes >= 2 else HeartbeatPhase.DELAYED
            )
            status_seed = MachineOperationalStatus(
                machine_id=machine_id,
                transport_state=TransportState.CONNECTED,
                supervisor_state=SupervisorState.ONLINE,
                telemetry_state=TelemetryState.LIVE,
                last_checked_at=checked_at,
                last_supervisor_heartbeat_at=supervisor_at,
                last_metric_at=metrics.observed_at,
                telemetry_source=metrics.source,
                consecutive_successes=successes,
                consecutive_failures=0,
                heartbeat_phase=heartbeat_phase,
                supervisor_reported_concurrent_units=reported_capacity,
                capacity_drift=capacity_drift,
                capacity_drift_reason=capacity_drift_reason,
            )
            status_seed.connection_evidence = {"ssh": ssh_observation(status_seed)}
            try:
                result = self.service.record_machine_observation(
                    MachineHeartbeat(
                        machine_id=machine_id,
                        metrics=metrics,
                        running_work_unit_ids=running_ids,
                        runtime_version=str(payload.get("runtime_version") or "") or None,
                        supervisor_reported_concurrent_units=reported_capacity,
                        applied_telemetry_policy=payload.get("applied_telemetry_policy"),
                        applied_telemetry_policy_sha256=(
                            str(payload.get("applied_telemetry_policy_sha256") or "") or None
                        ),
                    ),
                    actor_id=actor,
                    operational_status=status_seed,
                )
                assert result.status is not None
                stored_status = result.status
            except StaleMachineObservationError:
                # Only this typed ordering conflict is harmless. Runtime/root
                # mismatches and malformed observations remain hard failures.
                stored_status = self.repository.get_machine_operational_status(machine_id) or status_seed
            # Store successful transport evidence even when a newer HTTP raw
            # sample won the observation transaction. These are separate clocks.
            self.repository.put_machine_channel_observation(machine_id, "ssh", ssh_observation(status_seed))
            return self.repository.get_machine_operational_status(machine_id) or stored_status
        except (OSError, RuntimeError, ValueError, TimeoutError, subprocess.TimeoutExpired) as exc:
            checked_at = datetime.now(timezone.utc)
            failures = (previous.consecutive_failures if previous else 0) + 1
            offline = failures >= 2
            status = MachineOperationalStatus(
                machine_id=machine_id,
                transport_state=TransportState.DISCONNECTED,
                supervisor_state=(
                    SupervisorState.UNAVAILABLE if offline
                    else previous.supervisor_state if previous else SupervisorState.UNAVAILABLE
                ),
                telemetry_state=(
                    TelemetryState.STALE if previous and previous.last_metric_at else TelemetryState.UNAVAILABLE
                ),
                last_checked_at=checked_at,
                last_supervisor_heartbeat_at=previous.last_supervisor_heartbeat_at if previous else None,
                last_metric_at=previous.last_metric_at if previous else None,
                telemetry_source=previous.telemetry_source if previous else "ssh-supervisor",
                detail=_safe_detail(exc),
                consecutive_successes=0,
                consecutive_failures=failures,
                heartbeat_phase=HeartbeatPhase.OFFLINE if offline else HeartbeatPhase.DELAYED,
            )
            return self._publish_status(status, actor_id=actor)

    async def _poll_config(
        self,
        config: MachineExecutionConfig,
        *,
        semaphore: asyncio.Semaphore,
    ) -> str | None:
        loop = asyncio.get_running_loop()
        retry_delay_s = min(5, config.poll_interval_s) + (
            sum(config.machine_id.encode("utf-8")) % 3
        )
        try:
            async with semaphore:
                status = await asyncio.to_thread(self.poll_once, config)
            interval_s = (
                config.poll_interval_s
                if status.heartbeat_phase == HeartbeatPhase.HEALTHY
                else retry_delay_s
            )
            self._next_poll[config.machine_id] = loop.time() + interval_s
            return None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._next_poll[config.machine_id] = loop.time() + retry_delay_s
            logger.exception("SSH monitor poll failed for %s", config.machine_id)
            return f"{config.machine_id}: {_safe_detail(exc)}"

    async def run_cycle(self) -> None:
        loop = asyncio.get_running_loop()
        self.cycle_count += 1
        self.last_cycle_at = datetime.now(timezone.utc)
        try:
            configs = self.repository.list_machine_execution_configs()
        except Exception as exc:
            self.last_cycle_error_count = 1
            self.last_error = _safe_detail(exc)
            logger.exception("SSH monitor could not list machine execution configs")
            return

        active_ids = {config.machine_id for config in configs}
        self._next_poll = {
            machine_id: due for machine_id, due in self._next_poll.items() if machine_id in active_ids
        }
        now = loop.time()
        due_configs = [
            config
            for config in configs
            if now >= self._next_poll.get(config.machine_id, 0.0)
        ]
        semaphore = asyncio.Semaphore(self.max_parallel_polls)
        poll_errors = [
            error
            for error in await asyncio.gather(*(
                self._poll_config(config, semaphore=semaphore)
                for config in due_configs
            ))
            if error is not None
        ]
        errors = len(poll_errors)
        self.last_cycle_error_count = errors
        if errors == 0:
            self.last_successful_cycle_at = datetime.now(timezone.utc)
            self.last_error = None
        else:
            self.last_error = "; ".join(poll_errors)[:500]

    def health_snapshot(self) -> dict[str, object]:
        return {
            "cycle_count": self.cycle_count,
            "last_cycle_at": self.last_cycle_at.isoformat() if self.last_cycle_at else None,
            "last_successful_cycle_at": (
                self.last_successful_cycle_at.isoformat() if self.last_successful_cycle_at else None
            ),
            "last_cycle_error_count": self.last_cycle_error_count,
            "last_error": self.last_error,
            "active_polls": self.active_polls,
        }

    def _due_configs(
        self,
        configs: list[MachineExecutionConfig],
        *,
        active_ids: set[str],
        now: float,
    ) -> list[MachineExecutionConfig]:
        """Return the oldest-due probes that fit the available poll slots.

        Repository order must not become probe priority. With serial polling, a
        sufficiently busy prefix can otherwise become due again before the
        monitor reaches a later machine and starve that machine indefinitely.
        """
        for index, config in enumerate(configs):
            if config.machine_id not in self._next_poll:
                # Do not open every reverse tunnel in the same second during
                # startup or after a monitor restart.
                self._next_poll[config.machine_id] = now + index
        available_slots = max(0, self.max_parallel_polls - len(active_ids))
        if available_slots == 0:
            return []
        due = [
            config
            for config in configs
            if config.machine_id not in active_ids
            and now >= self._next_poll[config.machine_id]
        ]
        due.sort(key=lambda config: (self._next_poll[config.machine_id], config.machine_id))
        return due[:available_slots]

    async def run_forever(self) -> None:
        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(self.max_parallel_polls)
        active: dict[str, asyncio.Task[str | None]] = {}
        try:
            while True:
                self.cycle_count += 1
                self.last_cycle_at = datetime.now(timezone.utc)
                completed_errors: list[str] = []
                for machine_id, task in list(active.items()):
                    if not task.done():
                        continue
                    active.pop(machine_id)
                    try:
                        error = task.result()
                    except asyncio.CancelledError:
                        continue
                    except Exception as exc:
                        error = f"{machine_id}: {_safe_detail(exc)}"
                        logger.exception("SSH monitor task failed for %s", machine_id)
                    if error:
                        completed_errors.append(error)

                try:
                    configs = self.repository.list_machine_execution_configs()
                except Exception as exc:
                    completed_errors.append(_safe_detail(exc))
                    configs = []
                    logger.exception("SSH monitor could not list machine execution configs")
                active_ids = {config.machine_id for config in configs}
                self._next_poll = {
                    machine_id: due
                    for machine_id, due in self._next_poll.items()
                    if machine_id in active_ids
                }
                now = loop.time()
                for config in self._due_configs(
                    configs,
                    active_ids=set(active),
                    now=now,
                ):
                    active[config.machine_id] = asyncio.create_task(
                        self._poll_config(config, semaphore=semaphore)
                    )

                self.active_polls = len(active)
                self.last_cycle_error_count = len(completed_errors)
                if completed_errors:
                    self.last_error = "; ".join(completed_errors)[:500]
                else:
                    self.last_error = None
                    self.last_successful_cycle_at = datetime.now(timezone.utc)
                await asyncio.sleep(1)
        finally:
            for task in active.values():
                task.cancel()
            await asyncio.gather(*active.values(), return_exceptions=True)
            self.active_polls = 0
