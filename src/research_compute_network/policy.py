"""Machine eligibility and approval policy evaluation."""

from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field

from .models import (
    ApprovalRecord,
    ApprovalScope,
    ExecutionProfile,
    MachineMode,
    MachinePolicy,
    MachineState,
    ProjectGrant,
    TimeWindow,
    WorkUnit,
)


class PolicyDecision(BaseModel):
    eligible: bool
    reasons: list[str] = Field(default_factory=list)


def _parse_clock(value: str) -> time:
    hour, minute = (int(part) for part in value.split(":"))
    return time(hour=hour, minute=minute)


def _window_bounds(now_local: datetime, window: TimeWindow) -> tuple[datetime, datetime]:
    start_clock = _parse_clock(window.start)
    end_clock = _parse_clock(window.end)
    start = now_local.replace(hour=start_clock.hour, minute=start_clock.minute, second=0, microsecond=0)
    end = now_local.replace(hour=end_clock.hour, minute=end_clock.minute, second=0, microsecond=0)
    if end <= start:
        end += timedelta(days=1)
        if now_local.time() < end_clock:
            start -= timedelta(days=1)
            end -= timedelta(days=1)
    return start, end


def active_window(policy: MachinePolicy, now: datetime) -> tuple[datetime, datetime] | None:
    try:
        local_now = now.astimezone(ZoneInfo(policy.timezone))
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown machine-policy timezone: {policy.timezone}") from exc

    # An omitted schedule means the owner has imposed no time restriction.
    # Pausing a machine remains an explicit mode change instead of an
    # ambiguous empty calendar.
    if not policy.weekly_windows:
        return local_now - timedelta(days=1), local_now + timedelta(days=3650)

    candidates: list[TimeWindow] = []
    candidates.extend(policy.weekly_windows.get(local_now.weekday(), []))
    candidates.extend(policy.weekly_windows.get((local_now.weekday() - 1) % 7, []))
    for window in candidates:
        start, end = _window_bounds(local_now, window)
        if start <= local_now < end:
            return start, end
    return None


def _approved(
    approvals: list[ApprovalRecord],
    machine_id: str,
    project_id: str,
    profile_id: str,
    now: datetime,
) -> bool:
    for approval in approvals:
        if approval.machine_id != machine_id or not approval.is_active(now):
            continue
        if approval.scope == ApprovalScope.PROJECT and approval.subject_id == project_id:
            return True
        if approval.scope == ApprovalScope.EXECUTION_PROFILE and approval.subject_id == profile_id:
            return True
    return False


def evaluate_machine(
    *,
    machine: MachineState,
    policy: MachinePolicy,
    grant: ProjectGrant,
    profile: ExecutionProfile,
    unit: WorkUnit,
    approvals: list[ApprovalRecord],
    now: datetime | None = None,
    heartbeat_timeout_s: int = 90,
) -> PolicyDecision:
    current = now or datetime.now(timezone.utc)
    reasons: list[str] = []

    mode = policy.effective_mode()
    if mode != MachineMode.OPEN:
        reasons.append(f"machine mode is {mode.value}")

    heartbeat_age = (current - machine.last_heartbeat_at).total_seconds()
    if heartbeat_age > heartbeat_timeout_s:
        reasons.append(f"machine heartbeat is stale ({heartbeat_age:.0f}s)")

    window = active_window(policy, current)
    if window is None:
        reasons.append("outside owner-approved schedule")
    elif (window[1] - current.astimezone(window[1].tzinfo)).total_seconds() < unit.expected_duration_s:
        reasons.append("insufficient time remains in the current schedule window")

    metrics = machine.metrics
    if metrics.keyboard_idle_s < policy.keyboard_idle_min_s:
        reasons.append("keyboard/mouse idle threshold not met")
    # CPU/GPU pressure is decided once by the generic capacity service. Keep
    # memory and disk as hard per-task safety gates because a task may not fit
    # even when dispatch capacity is otherwise available.
    if metrics.available_memory_mb < unit.resources.memory_mb + policy.memory_reserve_mb:
        reasons.append("available memory would violate the owner reserve")
    if metrics.free_disk_mb < unit.resources.disk_mb:
        reasons.append("insufficient free disk")
    if metrics.running_units >= policy.max_concurrent_units:
        reasons.append("machine concurrent-unit limit reached")

    if unit.resources.cpus > policy.effective_cpu_cap(machine.total_cpus):
        reasons.append("CPU request exceeds the effective machine cap")
    if unit.resources.memory_mb > min(machine.total_memory_mb, policy.max_memory_mb):
        reasons.append("memory request exceeds the effective machine cap")
    if unit.resources.gpus > min(machine.total_gpus, policy.max_gpus):
        reasons.append("GPU request exceeds the effective machine cap")

    if machine.platform not in profile.platforms:
        reasons.append("machine platform is not supported by the execution profile")
    required = profile.required_capabilities | unit.required_capabilities
    missing = sorted(required - machine.capabilities)
    if missing:
        reasons.append(f"missing capabilities: {', '.join(missing)}")

    if not grant.approved:
        reasons.append("project is not approved")
    if profile.profile_id not in grant.allowed_profiles:
        reasons.append("execution profile is not approved for the project")
    if grant.trusted_machine_labels and not grant.trusted_machine_labels.issubset(machine.labels):
        reasons.append("machine does not satisfy the project's trust labels")
    if not _approved(approvals, machine.machine_id, grant.project_id, profile.profile_id, current):
        reasons.append("machine owner has not approved this project or execution profile")

    return PolicyDecision(eligible=not reasons, reasons=reasons)
