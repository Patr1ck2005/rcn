"""Operator hot-control tools for precise in-flight adjustments.

The control plane is not only an automatic scheduler: an operator sometimes
needs small, audited, reversible adjustments without stopping the Dispatcher
or resubmitting work. These helpers back the ``rcn`` operator commands:

- ``clear_standby``         clear a stuck standby reservation and requeue the unit
- ``pin_job_placement``     pin a queued job to one machine (preferred or required)
- ``set_machine_cpus``      hot-update a machine's CPU policy ceiling
- ``set_job_priority``      hot-update a Job's accepted dispatch priority
- ``issue_capacity_change`` raise/lower a machine's hard capacity through the
                            audited two-step machine-control ticket flow
- ``retune_project_grant``  hot-update project ceilings (priority, concurrency, quota)
- ``list_job_reservations`` show where a job's standby reservations currently sit

Every mutation flows through the regular service layer, so each one lands in
the same audit trail as an API-driven change, attributed to ``actor_id``.
"""

from __future__ import annotations

from typing import Any

from .models import (
    MachineControlAction,
    MachineControlTarget,
    PlacementConstraint,
    ProjectGrant,
)

__all__ = [
    "clear_standby",
    "issue_capacity_change",
    "list_job_reservations",
    "pin_job_placement",
    "retune_project_grant",
    "set_job_priority",
    "set_machine_cpus",
    "set_target_capacity",
]


def list_job_reservations(service, job_id: str, *, active_only: bool = True) -> list[dict[str, Any]]:
    """Return a Job's dispatch reservations: which machine/slot holds each one."""
    reservations = [
        reservation
        for reservation in service.repository.list_dispatch_reservations(active_only=active_only)
        if reservation.job_id == job_id
    ]
    return [reservation.model_dump(mode="json") for reservation in reservations]


def clear_standby(
    service,
    job_id: str,
    work_unit_id: str,
    *,
    actor_id: str,
    reason: str = "clear stuck standby reservation and requeue",
) -> dict[str, Any]:
    """Cancel a unit with a stuck standby reservation and requeue it unreserved.

    A prepared reservation pins its unit to one machine/slot until that slot
    frees (and a prepared reservation's TTL is extended to about a day), so a
    unit whose placement or capacity assumptions changed can otherwise wait a
    long time. Cancelling the unit alone does not free it: once the unit is
    requeued it reads as QUEUED again and the dispatcher's reservation sweep
    no longer considers it stale. This composite therefore explicitly finishes
    every active reservation for the unit (after the unit is cancelled, before
    it is requeued), then returns the unit to the queue unreserved so the
    normal dispatch order can place it on the first fitting slot. Machine-side
    staging left by the prepared run is reclaimed by the usual retention and
    cleanup cycle.
    """
    service.cancel_unit(job_id, work_unit_id, actor_id=actor_id, reason=reason)
    finished = 0
    for reservation in service.repository.list_dispatch_reservations(active_only=True):
        if reservation.job_id == job_id and reservation.work_unit_id == work_unit_id:
            service.finish_dispatch_reservation(
                reservation.reservation_id,
                state="cancelled",
                reason=reason,
                actor_id=actor_id,
            )
            finished += 1
    job = service.retry_unit(job_id, work_unit_id, actor_id=actor_id, allow_cancelled=True)
    unit = next(item for item in job.work_units if item.work_unit_id == work_unit_id)
    remaining = [
        reservation
        for reservation in service.repository.list_dispatch_reservations(active_only=True)
        if reservation.job_id == job_id and reservation.work_unit_id == work_unit_id
    ]
    return {
        "job_id": job_id,
        "work_unit_id": work_unit_id,
        "unit_status": unit.status.value,
        "job_status": job.status.value,
        "reservations_finished": finished,
        "residual_reservations": len(remaining),
    }


def pin_job_placement(
    service,
    job_id: str,
    machine_id: str,
    *,
    actor_id: str,
    required: bool = False,
    reason: str | None = None,
) -> dict[str, Any]:
    """Point a queued job at one machine (preferred, or required for admins)."""
    constraint = PlacementConstraint(
        preferred_machine_id=machine_id,
        required_machine_id=machine_id if required else None,
        reason=reason or f"operator placement pin to {machine_id}",
    )
    job = service.set_job_placement(
        job_id,
        constraint,
        actor_id=actor_id,
        allow_required=True,
    )
    return {
        "job_id": job_id,
        "machine_id": machine_id,
        "required": bool(constraint.required_machine_id),
        "job_status": job.status.value,
    }


def set_machine_cpus(
    service,
    machine_id: str,
    *,
    max_cpus: int,
    actor_id: str,
) -> dict[str, Any]:
    """Hot-update one machine's CPU policy ceiling (the per-machine resource gate).

    The CPU ceiling is a policy field, not part of the validated hard capacity,
    so it can follow the hardware reality directly. Keep it consistent with the
    concurrency you intend to run: concurrent units each reserve their resolved
    CPU count against this ceiling.
    """
    policy = service.repository.get_policy(machine_id)
    if policy is None:
        raise KeyError(f"machine policy not found: {machine_id}")
    before = policy.max_cpus
    service.update_policy(policy.model_copy(update={"max_cpus": max_cpus}), actor_id=actor_id)
    return {"machine_id": machine_id, "max_cpus": {"before": before, "after": max_cpus}}


def issue_capacity_change(
    service,
    machine_id: str,
    *,
    hard_capacity_units: int,
    reason: str,
    actor_id: str,
    ticket_id: str | None = None,
    confirmation_hash: str | None = None,
) -> dict[str, Any]:
    """Raise/lower a machine's hard capacity through the audited ticket flow.

    Two-step by design (mirrors the Web console): the first call previews the
    impact and returns the ticket id plus its confirmation hash; re-running
    with BOTH ``ticket_id`` and ``confirmation_hash`` executes that exact
    previewed ticket. After execution the machine's supervisor synchronizes
    its local cap on the next command cycle; the change stays
    ``hard_capacity_pending_acceptance`` until an operator issues
    ACCEPT_HARD_CAPACITY with the agent's acceptance reference, so the raise
    is visible and reversible the whole time.

    Note: the dispatch target capacity is a separate, smaller knob
    (:func:`set_target_capacity`) and must not exceed the resulting hard cap.
    """
    if (ticket_id is None) != (confirmation_hash is None):
        raise ValueError(
            "the confirm step requires both ticket_id and confirmation_hash "
            "from the preview step"
        )
    if ticket_id is not None:
        run, commands = service.confirm_machine_control(
            ticket_id,
            confirmation_hash,
            actor_id=actor_id,
        )
        return {
            "stage": "confirmed",
            "operation_id": run.operation_id,
            "state": run.state.value,
            "results": [result.model_dump(mode="json") for result in run.targets],
            "next": (
                "the supervisor synchronizes its local cap on the next command "
                "cycle; the change stays pending_acceptance until "
                "ACCEPT_HARD_CAPACITY is issued with the agent's acceptance "
                "reference"
            ),
        }
    ticket = service.preview_machine_control(
        MachineControlAction.SET_HARD_CAPACITY,
        [MachineControlTarget(machine_id=machine_id, hard_capacity_units=hard_capacity_units)],
        reason=reason,
        actor_id=actor_id,
    )
    return {
        "stage": "preview",
        "ticket_id": ticket.ticket_id,
        "confirmation_hash": ticket.confirmation_hash,
        "expires_at": ticket.expires_at.isoformat(),
        "impact": ticket.impact.get(machine_id, {}),
        "next": (
            "re-run with ticket_id and confirmation_hash set to the values "
            "above after reviewing the impact"
        ),
    }


def set_target_capacity(
    service,
    machine_id: str,
    *,
    target_concurrent_units: int,
    reason: str,
    actor_id: str,
    ticket_id: str | None = None,
    confirmation_hash: str | None = None,
) -> dict[str, Any]:
    """Set the dispatch target concurrency (must not exceed the hard cap).

    Same two-step ticket flow as :func:`issue_capacity_change`.
    """
    if (ticket_id is None) != (confirmation_hash is None):
        raise ValueError(
            "the confirm step requires both ticket_id and confirmation_hash "
            "from the preview step"
        )
    if ticket_id is not None:
        run, commands = service.confirm_machine_control(
            ticket_id,
            confirmation_hash,
            actor_id=actor_id,
        )
        return {
            "stage": "confirmed",
            "operation_id": run.operation_id,
            "state": run.state.value,
            "results": [result.model_dump(mode="json") for result in run.targets],
        }
    ticket = service.preview_machine_control(
        MachineControlAction.SET_TARGET_CAPACITY,
        [MachineControlTarget(machine_id=machine_id, target_concurrent_units=target_concurrent_units)],
        reason=reason,
        actor_id=actor_id,
    )
    return {
        "stage": "preview",
        "ticket_id": ticket.ticket_id,
        "confirmation_hash": ticket.confirmation_hash,
        "expires_at": ticket.expires_at.isoformat(),
        "impact": ticket.impact.get(machine_id, {}),
    }


def set_job_priority(
    service,
    job_id: str,
    *,
    priority: int,
    actor_id: str,
    reason: str | None = None,
) -> dict[str, Any]:
    """Hot-set an explicit task priority under its current authorized ceiling.

    Synchronize the stored base ``effective_priority`` used by dispatch with
    the displayed priority and the current project ceiling snapshot. Existing
    aging, starvation protection, Attempts, and scientific inputs are retained.
    A value above the grant ceiling is clamped; the supported range is -100
    through 100, including negative priorities for lower-priority work.
    """
    from .models import JobStatus
    from .dispatch_policy import policy_for, task_priority_ceiling

    if isinstance(priority, bool) or not isinstance(priority, int) or not -100 <= priority <= 100:
        raise ValueError("priority must be an integer between -100 and 100")

    before: dict[str, int | None] = {}

    def apply(current):
        if current.status not in {JobStatus.QUEUED, JobStatus.AWAITING_APPROVAL,
                                  JobStatus.RUNNING, JobStatus.FAILED_RETRIABLE}:
            raise ValueError(
                f"priority can only change on queued/running/retriable jobs, not {current.status.value}"
            )
        # Read the current grant and capture the old values inside the CAS
        # callback, so a retry audits the mutation that actually committed.
        grant = service.repository.get_project_grant(current.project_id)
        policy = policy_for(service.repository)
        parallel_estimate = service._parallel_batch_estimate(current, policy=policy)
        ceiling = task_priority_ceiling(policy, current, grant, parallel_estimate=parallel_estimate)
        clamped = min(priority, ceiling) if ceiling is not None else priority
        before.update(
            priority=current.priority,
            effective_priority=current.effective_priority,
            priority_ceiling_snapshot=current.priority_ceiling_snapshot,
        )
        current.priority = clamped
        current.effective_priority = clamped
        current.priority_ceiling_snapshot = ceiling
        current.priority_explicit = True
        current.priority_source = 'task'

    updated = service.repository.mutate_job(job_id, apply, hydrate_blobs=False)
    after = {
        "priority": updated.priority,
        "effective_priority": updated.effective_priority,
        "priority_ceiling_snapshot": updated.priority_ceiling_snapshot,
    }
    service._event(
        "job.priority_updated",
        actor_id,
        "job",
        job_id,
        priority=updated.priority,
        requested=priority,
        priority_ceiling=updated.priority_ceiling_snapshot,
        before=before,
        after=after,
        reason=reason or f"operator priority adjustment to {updated.priority}",
    )
    return {
        "job_id": job_id,
        "priority": updated.priority,
        "effective_priority": updated.effective_priority,
        "requested": priority,
        "priority_ceiling": updated.priority_ceiling_snapshot,
        "clamped": updated.priority != priority,
        "before": before,
        "after": after,
    }


def retune_project_grant(
    service,
    project_id: str,
    *,
    actor_id: str,
    priority_ceiling: int | None = None,
    max_running_units: int | None = None,
    max_queued_units: int | None = None,
) -> dict[str, Any]:
    """Hot-update a project grant's ceilings without touching anything else."""
    grant = service.repository.get_project_grant(project_id)
    if grant is None:
        raise KeyError(f"project grant not found: {project_id}")
    updates: dict[str, int] = {}
    if priority_ceiling is not None:
        updates["priority_ceiling"] = priority_ceiling
    if max_running_units is not None:
        updates["max_running_units"] = max_running_units
    if max_queued_units is not None:
        updates["max_queued_units"] = max_queued_units
    if not updates:
        raise ValueError("retune_project_grant requires at least one field to change")
    updated: ProjectGrant = grant.model_copy(update=updates)
    service.register_project(updated, actor_id=actor_id)
    return {
        "project_id": project_id,
        "priority_ceiling": updated.priority_ceiling,
        "max_running_units": updated.max_running_units,
        "max_queued_units": updated.max_queued_units,
    }
