"""Operational scheduling preferences, never scientific or execution contracts.

All strategies keep existing grant, runtime, solver, owner and resource gates.
Usage is requested-resource time, not measured CPU consumption or contribution
credit. Unknown timings remain explicitly uncovered.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import math
import statistics
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Priority = Annotated[int, Field(ge=-100, le=100, strict=True)]


class SchedulingPolicy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal[1] = 1
    strategy: Literal['balanced','small_batch_first','throughput'] = 'balanced'
    starvation_after_s: int = Field(default=7200, ge=60, le=86400, strict=True)
    small_batch_max_units: int = Field(default=4, ge=1, le=128, strict=True)
    small_batch_max_serial_seconds: int = Field(default=1800, ge=60, le=86400, strict=True)
    # An absent field retains the original policy wire shape and serial rule.
    # A value enables compatible-capacity parallel completion classification.
    small_batch_max_parallel_seconds: int | None = Field(
        default=None, ge=60, le=86400, strict=True, exclude_if=lambda value: value is None,
    )
    fairness_quantum_core_seconds: int = Field(default=3600, ge=60, le=86400, strict=True)
    history_window_hours: int = Field(default=24, ge=1, le=168, strict=True)
    performance_min_samples: int = Field(default=3, ge=3, le=50, strict=True)
    # Absent values retain the old wire representation and requested priorities.
    default_priority: Priority | None = Field(default=None, exclude_if=lambda value: value is None)
    short_compute_priority: Priority | None = Field(default=None, exclude_if=lambda value: value is None)
    project_priorities: dict[Annotated[str, Field(min_length=1, strict=True)], Priority] = Field(
        default_factory=dict, exclude_if=lambda value: not value,
    )

    @field_validator('project_priorities')
    @classmethod
    def nonblank_project_ids(cls, value):
        if any(not project_id.strip() for project_id in value):
            raise ValueError('project priority keys must be nonblank exact project IDs')
        return value


def project_priority(policy, project_id, requested, *, ceiling=None):
    """An explicit task value wins; project values supply omitted defaults."""
    base = requested if requested is not None else policy.project_priorities.get(
        project_id, policy.default_priority if policy.default_priority is not None else 0)
    return min(base, ceiling) if ceiling is not None else base


def requested_task_priority(job):
    explicit = job.priority_explicit
    if explicit is None:
        explicit = 'priority' in job.model_fields_set
    return job.priority if explicit else None


def _parallel_classification(policy, parallel_estimate, *, timings_known):
    estimate = parallel_estimate or {}
    raw = estimate.get('estimated_parallel_seconds')
    seconds = number(raw) if raw is not None else None
    known = bool(timings_known and estimate.get('estimate_complete') is True
                 and seconds is not None and seconds > 0)
    return {'classification_basis': 'compatible_parallel_capacity',
            'estimated_parallel_seconds': seconds if known else None,
            'compatible_slots': estimate.get('compatible_slots', 0),
            'parallel_estimate_reason': estimate.get('reason', 'compatible_capacity_unknown'),
            'parallel_eligible': bool(known and seconds <= policy.small_batch_max_parallel_seconds)}


def short_compute_size(job, policy, *, parallel_estimate=None):
    """Classify the entire submitted batch, never its shrinking queued tail."""
    costs = [number(unit.expected_duration_s) for unit in job.work_units]
    estimates_declared = (job.duration_estimate_complete if job.duration_estimate_complete is not None
                          else all('expected_duration_s' in unit.model_fields_set for unit in job.work_units))
    known = (bool(costs) and estimates_declared
             and all(cost > 0 for cost in costs))
    total = sum(costs) if known else None
    result = {'submitted_units': len(costs), 'declared_serial_seconds': total,
              'estimate_complete': known,
              'eligible': bool(known and len(costs) <= policy.small_batch_max_units
                               and total <= policy.small_batch_max_serial_seconds)}
    if policy.small_batch_max_parallel_seconds is not None:
        extra = _parallel_classification(policy, parallel_estimate, timings_known=known)
        result.update(extra)
        result['eligible'] = result.pop('parallel_eligible')
    return result


def task_priority_ceiling(policy, job, grant, *, parallel_estimate=None):
    if grant is None:
        return None
    ceiling = grant.priority_ceiling
    if policy.short_compute_priority is not None and short_compute_size(job, policy, parallel_estimate=parallel_estimate)['eligible']:
        ceiling = max(ceiling, policy.short_compute_priority)
    return ceiling


def resolve_submission_priority(policy, job, *, ceiling=None, parallel_estimate=None):
    requested = requested_task_priority(job)
    size = short_compute_size(job, policy, parallel_estimate=parallel_estimate)
    if requested is not None:
        return requested, 'task', size
    if policy.short_compute_priority is not None and size['eligible']:
        base, source = policy.short_compute_priority, 'short_compute'
    elif job.project_id in policy.project_priorities:
        base, source = policy.project_priorities[job.project_id], 'project_default'
    else:
        base = policy.default_priority if policy.default_priority is not None else 0
        source = 'system_default'
    return min(base, ceiling) if ceiling is not None else base, source, size


def policy_for(repository):
    return repository.get_feature_settings().scheduling_policy or SchedulingPolicy()


def number(value, default=0.0):
    if isinstance(value,bool):return default
    try:result=float(value)
    except (ValueError,TypeError,OverflowError):return default
    return result if math.isfinite(result) and result>=0 else default


def aware(value):
    if isinstance(value,str):
        try:value=datetime.fromisoformat(value.replace('Z','+00:00'))
        except ValueError:return None
    if not isinstance(value,datetime):return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def usage_from_projections(projections, *, now, hours=24):
    now=aware(now);cutoff=now-timedelta(hours=hours)
    def blank():return {'wall_seconds':0.,'core_seconds':0.,'gpu_seconds':0.,
                       'timed_attempts':0,'missing_timing_attempts':0,'live_attempts':0,
                       'observed_execution_end_attempts':0,'legacy_finished_at_attempts':0}
    projects=defaultdict(blank);users=defaultdict(blank);seen=set()
    for job in projections:
        if not isinstance(job,dict):continue
        p=projects[str(job.get('project_id',''))];u=users[str(job.get('user_id',''))]
        if job.get('record_class','production')!='production':continue
        for unit in job.get('work_units') or []:
            if not isinstance(unit,dict):continue
            for attempt in unit.get('attempts') or []:
                if not isinstance(attempt,dict):continue
                key=(job.get('job_id'),unit.get('work_unit_id'),attempt.get('attempt_id'))
                if not key[-1] or key in seen:continue
                seen.add(key)
                start=aware(attempt.get('started_at'))
                observed_end=aware(attempt.get('execution_end_observed_at'))
                end=observed_end or aware(attempt.get('finished_at'))
                active=attempt.get('state') in {'running','uncertain','reconcile_pending','cancel_pending'}
                if end is None and active and start is not None and not attempt.get('execution_completed'):
                    end=now
                # A completed execution without a known end remains uncovered;
                # repeated collection errors cannot charge compute forever.
                if start is None or end is None or end<start or start>now:
                    for group in (p,u):group['missing_timing_attempts']+=1
                    continue
                duration=max(0.,(min(now,end)-max(cutoff,start)).total_seconds())
                if not duration:continue
                frozen=attempt.get('resolved_resources') or unit.get('resolved_resources') or {}
                resources=frozen.get('resources') or unit.get('resources') or {}
                cpus=number(resources.get('cpus'));gpus=number(resources.get('gpus'))
                for group in (p,u):
                    group['wall_seconds']+=duration
                    group['core_seconds']+=duration*cpus
                    group['gpu_seconds']+=duration*gpus
                    group['timed_attempts']+=1
                    group['live_attempts']+=int(active and end==now and observed_end is None and attempt.get('finished_at') is None)
                    group['observed_execution_end_attempts']+=int(observed_end is not None)
                    group['legacy_finished_at_attempts']+=int(observed_end is None and attempt.get('finished_at') is not None)
    return {'projects':dict(projects),'users':dict(users),'window_hours':hours,
            'window_start':cutoff.isoformat(),'observed_at':now.isoformat(),
            'basis':'requested-resource-time; clipped to actual attempt interval; includes failures; no contribution credit'}


def job_size(job, policy, *, parallel_estimate=None):
    remaining=[u for u in job.work_units if str(u.status) not in {'completed','cancelled','failed_terminal'}]
    costs=[number(u.expected_duration_s) for u in remaining]
    known=bool(remaining) and all(value>0 for value in costs)
    cost=sum(costs) if known else math.inf
    small=bool(known and len(remaining)<=policy.small_batch_max_units and cost<=policy.small_batch_max_serial_seconds)
    result = {'remaining_units':len(remaining),'declared_serial_seconds':cost if known else None,
              'small_batch':small,'unknown_cost':not known}
    if policy.small_batch_max_parallel_seconds is not None:
        declared = job.duration_estimate_complete is not False
        extra = _parallel_classification(policy, parallel_estimate, timings_known=known and declared)
        result.update(extra)
        result['small_batch'] = result.pop('parallel_eligible')
    return result


def dispatch_order(job, *, now, policy, priority, project_usage=None, user_usage=None, parallel_estimate=None):
    p=project_usage or {};u=user_usage or {};now=aware(now)
    last=aware(job.last_scheduled_at) or aware(job.created_at) or now
    wait=max(0.,(now-last).total_seconds());protected=wait>=policy.starvation_after_s
    size=job_size(job,policy,parallel_estimate=parallel_estimate);quantum=policy.fairness_quantum_core_seconds
    # Explicit/effective priority remains authoritative. Waiting protection
    # breaks ties inside that rank; small-job traffic cannot starve equally
    # ranked large work, but it cannot silently reverse an operator's focus.
    # Existing bounded priority aging remains in the service, unchanged.
    head=(-priority, 0 if protected else 1, -wait if protected else 0)
    fair=(number(p.get('core_seconds'))//quantum,number(p.get('gpu_seconds'))//quantum)
    tail=(number(u.get('core_seconds')),number(u.get('gpu_seconds')),last,
          aware(job.created_at) or now,job.job_id)
    if policy.strategy=='small_batch_first':
        short_cost = (size.get('estimated_parallel_seconds') if policy.small_batch_max_parallel_seconds is not None
                      else size['declared_serial_seconds'])
        return (*head,*fair,0 if size['small_batch'] else 1,
                short_cost if size['small_batch'] else 0,*tail)
    if policy.strategy=='throughput':
        return (*head,*fair,size['declared_serial_seconds'] if not size['unknown_cost'] else math.inf,*tail)
    return (*head,number(p.get('core_seconds')),number(p.get('gpu_seconds')),*tail)


def machine_ratio(history, *, job, machine_id, runtime_version, solver, min_samples=3, requested_cpus=None):
    """Comparable same-contract successful history; no cross-science pooling.

    Durations are end-to-end observed execution intervals, not a claim of pure
    solver speed. No data changes an accepted Unit, thread count or solver.
    """
    fields=('project_id','execution_profile_id','template_sha256','source_spec_sha256','output_contract_sha256')
    ratios=[]
    for sample in history:
        if sample.job_id!=job.job_id and (not all(getattr(job,n,None) for n in fields)
            or any(getattr(sample,n,None)!=getattr(job,n,None) for n in fields)):
            continue
        for unit in sample.work_units:
            if str(unit.status)!='completed':continue
            for attempt in unit.attempts[-1:]:
                if (attempt.machine_id!=machine_id or attempt.state!='completed' or not attempt.collected_at
                    or attempt.runtime_version!=runtime_version or attempt.solver_variant!=solver
                    or attempt.prepared or attempt.dispatch_reservation_id is not None
                    or str(attempt.external_run_id or '').startswith(f'ssh-{machine_id}-reservation-')
                    or attempt.resolved_resources is None
                    or (requested_cpus is not None and attempt.resolved_resources.resources.cpus != requested_cpus)):
                    continue
                actual=number(unit.actual_duration_s);expected=number(unit.expected_duration_s)
                if actual and expected:ratios.append(min(100.,max(.01,actual/expected)))
    return {'ratio':statistics.median(ratios) if len(ratios)>=min_samples else None,
            'samples':len(ratios),'basis':'comparable-end-to-end-history' if len(ratios)>=min_samples else 'balanced-cold-start'}
