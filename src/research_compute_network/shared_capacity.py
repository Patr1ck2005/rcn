"""Transactional scheduler CPU claims. Not an OS CPU quota or fair-share system."""
from collections import defaultdict


class SharedCapacityConflict(ValueError):
    """Another committed assignment or owner change consumed the shared budget."""


ACTIVE_ATTEMPT_STATES = frozenset({
    'assigned', 'submitting', 'running', 'cancel_pending', 'reconcile_pending',
    'uncertain', 'collecting',
})
ACTIVE_UNIT_STATES = frozenset({'assigned', 'running', 'reconcile_pending'})


def cpu_claims(job) -> dict[str, int]:
    """Conservatively retain every unclosed attempt, even after job cancellation.

    Uses only the existing operational projection and sealed Attempt resources.
    A delayed/uncertain attempt cannot disappear merely because a retry exists.
    """
    claims = defaultdict(int)
    if job is None:
        return {}
    for unit in job.work_units:
        attempts = [attempt for attempt in unit.attempts if attempt.state in ACTIVE_ATTEMPT_STATES]
        if attempts:
            for attempt in attempts:
                machine_id = attempt.machine_id or unit.assigned_machine_id
                if not machine_id:
                    continue
                resolved = attempt.resolved_resources or unit.resolved_resources
                resources = resolved.resources if resolved is not None else unit.resources
                claims[machine_id] += resources.cpus
        elif unit.assigned_machine_id and unit.status.value in ACTIVE_UNIT_STATES:
            resolved = unit.resolved_resources
            claims[unit.assigned_machine_id] += (resolved.resources if resolved else unit.resources).cpus
    return dict(claims)
