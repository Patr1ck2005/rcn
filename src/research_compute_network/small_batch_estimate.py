"""Pure feasible batch-wall-time estimates at current compatible maximum capacity.

RCN's existing slot occupancy is intentionally absent from this model. Memory
is reclaimed only with fresh complete attribution; otherwise measured free
memory remains the conservative bound.
Owner, health, external load, approval and per-Unit resource gates remain. This
is a conservative list schedule of indivisible Units, not total work / slots,
and is neither an actual queue ETA nor a promise of optimal machine allocation.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Callable

from .models import (
    ResourceMode, ResolvedResources, SolverPolicy, SolverVariant, WorkUnitAttempt, WorkUnitStatus,
)
from .parameter_guard import GENERIC_STUDY_PROFILE_IDS
from .placement import evaluate_placement
from .policy import active_window
from .runtime_compatibility import select_machine_execution_approval

_SEALED_PROFILES = GENERIC_STUDY_PROFILE_IDS | {
    "workbench-comsol-template-build-v1", "workbench-comsol-saved-readout-v1",
}
_BASIS = ("feasible indivisible-Unit list schedule at snapshot maximum compatible capacity; "
          "RCN slot occupancy excluded; memory reclaimed only from fresh complete process attribution; "
          "owner/health/external-load/project/profile/runtime/solver/resource gates retained; "
          "declared durations, not queue ETA")


@dataclass(frozen=True)
class ParallelBatchSnapshot:
    """Reusable read snapshot; pass this as estimate_parallel_batch's repository.

    Building it once avoids per-Job database reads during a scheduling sort.
    Models are copied when built, and estimation never mutates those copies.
    resource_calibrator may be the formal dispatch candidate method with its
    history_cache already bound; opted-in dynamic memory policies require it.
    """

    now: datetime
    machines: tuple
    policies: dict
    configs: dict
    statuses: dict
    grants: dict
    profiles: dict
    approvals: tuple
    solver_approvals: dict
    pressure_settings: object
    resource_calibrator: Callable | None = None


def build_parallel_batch_snapshot(repository, *, now=None, resource_calibrator=None) -> ParallelBatchSnapshot:
    if isinstance(repository, ParallelBatchSnapshot):
        return repository
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    machines = tuple(item.model_copy(deep=True) for item in repository.list_machines())

    def indexed(items, key):
        return {getattr(item, key): item.model_copy(deep=True) for item in items}

    return ParallelBatchSnapshot(
        now=current, machines=machines,
        policies={machine.machine_id: (policy.model_copy(deep=True) if policy is not None else None)
                  for machine in machines if (policy := repository.get_policy(machine.machine_id)) is not None},
        configs=indexed(repository.list_machine_execution_configs(), "machine_id"),
        statuses=indexed(repository.list_machine_operational_statuses(), "machine_id"),
        grants=indexed(repository.list_project_grants(), "project_id"),
        profiles=indexed(repository.list_profiles(), "profile_id"),
        approvals=tuple(item.model_copy(deep=True) for item in repository.list_approvals()),
        solver_approvals=indexed(repository.list_solver_approvals(), "approval_id"),
        pressure_settings=repository.get_feature_settings().pressure_policy.model_copy(deep=True),
        resource_calibrator=resource_calibrator,
    )


def _answer(seconds=None, slots=0, reason="unknown"):
    return {"estimated_parallel_seconds": float(seconds) if seconds is not None else None,
            "compatible_slots": slots, "estimate_complete": seconds is not None,
            "reason": reason, "basis": _BASIS}


def _duration(unit):
    value = unit.expected_duration_s
    if isinstance(value, bool):
        return None
    try:
        value = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    return value if math.isfinite(value) and value > 0 else None


def _empty_rcn_machine(machine, *, now=None):
    copied = machine.model_copy(deep=True)
    metrics = copied.metrics
    # Only a fresh, complete process inventory identifies non-RCN memory.
    # Default zero fields in unavailable/legacy/degraded telemetry do not
    # prove that used memory belongs to RCN. Preserve measured headroom then.
    # Never reclaim historical process peaks as if they were current RSS.
    total = min(copied.total_memory_mb, metrics.total_memory_mb or copied.total_memory_mb)
    external = metrics.external_load
    current = now or datetime.now(timezone.utc)
    observed = external.observed_at
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    age = (current - observed).total_seconds()
    trusted_memory = (metrics.available and external.attribution_quality == "complete"
                      and external.process_set_hash is not None and 0 <= age <= 90)
    if trusted_memory:
        metrics.available_memory_mb = max(0, total - external.external_memory_mb - external.unattributed_memory_mb)
    else:
        metrics.available_memory_mb = min(total, metrics.available_memory_mb)
    metrics.running_units = 0
    return copied


def _approval(snapshot, job, unit, machine, config, now):
    required = job.execution_profile_id in _SEALED_PROFILES or SolverVariant.CUDSS in unit.allowed_solver_variants
    approval_id = unit.solver_approval_id or job.solver_approval_id
    if not approval_id:
        return None, not required
    original = snapshot.solver_approvals.get(approval_id)
    if original is None or not original.is_active(now):
        return None, False
    if (original.project_id != job.project_id or original.execution_profile_id != job.execution_profile_id
            or not unit.allowed_solver_variants.issubset(original.solver_variants)):
        return None, False
    if approval_id == job.solver_approval_id and original.fingerprint != job.solver_compatibility_fingerprint:
        return None, False
    if (job.template_sha256 and original.template_hash_policy == "exact"
            and job.template_sha256 != original.template_sha256):
        return None, False
    if original.template_role is not None and original.template_role != job.template_role:
        return None, False
    if original.allowed_study_kinds and job.study_kind not in original.allowed_study_kinds:
        return None, False
    if job.execution_profile_id in _SEALED_PROFILES and job.study_kind is not None and not original.allowed_study_kinds:
        return None, False
    if original.runtime_version is None:
        return original, job.execution_profile_id not in _SEALED_PROFILES
    selected = select_machine_execution_approval(
        original, snapshot.solver_approvals.values(), machine, config, now=now,
    )
    return selected, selected is not None


def _solver(unit, machine, policy, approval):
    gpu = (max(machine.total_gpus, sum(item.available for item in machine.metrics.gpu)) > 0
           and policy.max_gpus > 0 and "solver-cudss" in machine.capabilities)
    latest = unit.attempts[-1] if unit.attempts else None
    failed_cudss = bool(latest and latest.state == "failed" and latest.solver_variant == SolverVariant.CUDSS
                        and any(term in str(latest.failure_reason or "").lower()
                                for term in ("cudss", "gpu runtime", "gpu unavailable")))
    if (unit.solver_policy == SolverPolicy.AUTO_FAST and SolverVariant.CUDSS in unit.allowed_solver_variants
            and gpu and approval is not None and not failed_cudss):
        return SolverVariant.CUDSS
    return SolverVariant.MUMPS if SolverVariant.MUMPS in unit.allowed_solver_variants else None


def _resource_unit(unit, solver):
    copied = unit.model_copy(deep=True)
    # Do not spend less than either a declared or already resolved envelope.
    copied.resources = unit.resources.model_copy(update={
        name: max(getattr(unit.resources, name), getattr(unit.resolved_resources.resources, name)
                  if unit.resolved_resources is not None else 0)
        for name in ("cpus", "memory_mb", "disk_mb", "gpus")
    })
    if (solver == SolverVariant.MUMPS and copied.resource_mode == ResourceMode.DYNAMIC
            and copied.solver_policy == SolverPolicy.AUTO_FAST
            and copied.allowed_solver_variants == {SolverVariant.MUMPS, SolverVariant.CUDSS}):
        copied.resources = copied.resources.model_copy(update={"gpus": 0})
    copied.resolved_resources = ResolvedResources(resources=copied.resources.model_copy(deep=True), source="origin_requested")
    # Only synthetic concurrent occupants use these attempts. They let the
    # existing placement evaluator recognize its authorized shared cuDSS mode.
    copied.attempts = [WorkUnitAttempt(attempt_id="parallel-estimate-" + copied.work_unit_id,
        machine_id="parallel-estimate", state="running", solver_variant=solver,
        resolved_resources=copied.resolved_resources.model_copy(deep=True))]
    return copied


def estimate_parallel_batch(repository, job, *, units=None, now=None) -> dict:
    """Estimate a whole submitted batch, or an explicit remaining-Unit subset.

    An empty subset, missing duration declaration or any Unit lacking a feasible
    compatible placement yields unknown. Live Jobs and repository state are not
    changed. compatible_slots is the feasible schedule's peak simultaneous Unit
    count, bounded by the batch size and project cap, not a sum of fleet slots.
    """
    selected = list(job.work_units if units is None else units)
    if not selected:
        return _answer(reason="no_units")
    durations = [_duration(unit) for unit in selected]
    declared = (job.duration_estimate_complete if job.duration_estimate_complete is not None else
                all("expected_duration_s" in unit.model_fields_set for unit in selected))
    if not declared or any(value is None for value in durations):
        return _answer(reason="duration_estimate_incomplete")
    if len({unit.work_unit_id for unit in selected}) != len(selected):
        return _answer(reason="duplicate_units")
    snapshot = build_parallel_batch_snapshot(repository, now=now)
    current = now or snapshot.now
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    grant = snapshot.grants.get(job.project_id)
    profile = snapshot.profiles.get(job.execution_profile_id)
    if grant is None or profile is None or not grant.approved or not grant.authorizes(job.user_id):
        return _answer(reason="project_or_profile_not_authorized")
    machines = {machine.machine_id: _empty_rcn_machine(machine, now=current) for machine in snapshot.machines}
    options = []
    for unit, duration in zip(selected, durations):
        choices = []
        required = unit.required_machine_id or job.placement.required_machine_id
        pinned = unit.attempts[-1].machine_id if unit.attempts and not job.retry_policy.allow_migration else None
        for machine_id, machine in machines.items():
            if (required and machine_id != required) or (pinned and machine_id != pinned):
                continue
            policy = snapshot.policies.get(machine_id)
            config = snapshot.configs.get(machine_id)
            if policy is None or config is None:
                continue
            approval, valid = _approval(snapshot, job, unit, machine, config, current)
            solver = _solver(unit, machine, policy, approval) if valid else None
            if solver is None:
                continue
            runtime = approval.runtime_version if approval is not None else machine.runtime_version
            needs_calibration = (unit.resource_mode == ResourceMode.DYNAMIC and unit.status == WorkUnitStatus.QUEUED
                                 and policy.memory_peak_margin_percent is not None and bool(runtime))
            calibrated = unit
            if needs_calibration:
                # Use the same service-owned candidate calculation as actual
                # dispatch. A low original declaration is not a safe fallback
                # when the owner enabled comparable-peak calibration.
                if snapshot.resource_calibrator is None:
                    continue
                calibrated = snapshot.resource_calibrator(
                    job, unit, machine, policy, runtime_version=runtime, execution_approval=approval,
                )
            candidate = _resource_unit(calibrated, solver)
            decision = evaluate_placement(machine=machine, policy=policy, execution_config=config,
                operational_status=snapshot.statuses.get(machine_id), grant=grant, profile=profile, job=job,
                unit=unit.model_copy(update={"resources": candidate.resources}), approvals=list(snapshot.approvals),
                solver_approval=approval, active_units=[], active_profile_units=[],
                pressure_settings=snapshot.pressure_settings, now=current)
            window = active_window(policy, current)
            if decision.eligible and window is not None:
                choices.append((machine_id, candidate, approval, (window[1] - current).total_seconds()))
        if not choices:
            return _answer(reason="no_compatible_resources_for_unit")
        options.append((unit, duration, choices))
    # Scarce placements first; longest work first within equal scarcity.
    options.sort(key=lambda row: (len(row[2]), -row[1], row[0].ordinal, row[0].work_unit_id))
    pending = list(options)
    running = []  # (finish, machine_id, copied Unit)
    elapsed = 0.0
    makespan = 0.0
    peak = 0
    while pending:
        for entry in list(pending):
            if len(running) >= grant.max_running_units:
                break
            unit, duration, choices = entry
            # Prefer the least occupied compatible host, with deterministic ties.
            ordered = sorted(choices, key=lambda row: (sum(item[1] == row[0] for item in running), row[0]))
            for machine_id, candidate, approval, window_remaining in ordered:
                # Match placement's remaining-window admission at every
                # simulated new start. Already-running work may drain, but
                # that does not authorize a later start with too little time.
                if elapsed + duration > window_remaining:
                    continue
                machine = machines[machine_id]
                policy = snapshot.policies[machine_id]
                active = [item[2] for item in running if item[1] == machine_id]
                decision = evaluate_placement(machine=machine, policy=policy, execution_config=snapshot.configs.get(machine_id),
                    operational_status=snapshot.statuses.get(machine_id), grant=grant, profile=profile, job=job,
                    unit=unit.model_copy(update={"resources": candidate.resources}), approvals=list(snapshot.approvals), solver_approval=approval,
                    active_units=active, active_profile_units=active, pressure_settings=snapshot.pressure_settings, now=current)
                if not decision.eligible:
                    continue
                cpu = sum(item.resources.cpus for item in active) + candidate.resources.cpus
                memory = sum(item.resources.memory_mb for item in active) + candidate.resources.memory_mb
                if (policy.full_cpu_override is None and cpu > decision.resource_limits.cpus) or (
                    memory + policy.memory_reserve_mb > machine.metrics.available_memory_mb):
                    continue
                finish = elapsed + duration
                running.append((finish, machine_id, candidate))
                makespan = max(makespan, finish)
                peak = max(peak, len(running))
                pending.remove(entry)
                break
        if not pending:
            break
        if not running:
            return _answer(slots=peak, reason="no_feasible_resource_schedule")
        elapsed = min(item[0] for item in running)
        running = [item for item in running if item[0] > elapsed]
    return _answer(makespan, peak, "feasible_parallel_schedule")
