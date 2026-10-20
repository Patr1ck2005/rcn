"""Deterministic grouping of Workbench-owned atomic calculation items."""

from __future__ import annotations

import math
from datetime import datetime, timezone

from .hashing import sha256_value
from .models import JobEnvelope, PartitionPlan, PartitionRequest, WorkUnit, ResourcePolicy, ResolvedResources
from .profiles import BUILTIN_PROFILES
from .resource_policy import default_resource_policy, resolve_partition_disk, resolve_resources


class PartitionConfirmationRequired(ValueError):
    """New plans need a user decision, not an invented grouping estimate."""

    reason_code = "partition_duration_confirmation_required"
    message = (
        "Multi-item partitioning requires a duration estimate for every item "
        "(or estimated_seconds_per_item), or an explicit requested_unit_count. "
        "请主动询问用户提供耗时估计或指定 Unit 数；不要自行猜测。 "
        "Ask the user for duration estimates or a Unit count; do not guess, "
        "infer from history, or bypass this decision through another submission endpoint."
    )

    def __init__(self, missing_item_count: int):
        super().__init__(self.message)
        self.missing_item_count = missing_item_count

    def detail(self) -> dict:
        return {
            "reason_code": self.reason_code,
            "message": self.message,
            "requires": "user_confirmation",
            "next_action": "ask_user_for_duration_estimates_or_unit_count",
            "missing_item_count": self.missing_item_count,
        }


def _require_partition_estimates(request: PartitionRequest) -> None:
    # Validate only new planning, not model loading or confirmation of an
    # already persisted plan. Explicit counts are an intentional user choice;
    # a single item has no grouping decision to make.
    if len(request.items) <= 1 or request.requested_unit_count is not None:
        return
    missing = sum(
        item.estimated_duration_s is None and request.estimated_seconds_per_item is None
        for item in request.items
    )
    if missing:
        raise PartitionConfirmationRequired(missing)


def _split_evenly(items: list, count: int) -> list[list]:
    quotient, remainder = divmod(len(items), count)
    groups: list[list] = []
    start = 0
    for ordinal in range(count):
        size = quotient + (1 if ordinal < remainder else 0)
        groups.append(items[start:start + size])
        start += size
    return groups


def _setup_groups(request: PartitionRequest) -> list[list]:
    items = sorted(request.items, key=lambda item: item.ordinal)
    if not request.partition_constraints.prohibit_mixed_setup_fingerprints:
        return [items]
    grouped: dict[str, list] = {}
    for item in items:
        assert item.setup_fingerprint is not None
        grouped.setdefault(item.setup_fingerprint, []).append(item)
    return list(grouped.values())


def _requested_groups(request: PartitionRequest, setups: list[list]) -> list[list]:
    count = request.requested_unit_count
    assert count is not None
    if count < len(setups):
        raise ValueError(
            "requested unit count cannot keep all setup fingerprints isolated; "
            f"minimum is {len(setups)}"
        )
    allocations = [1] * len(setups)
    while sum(allocations) < count:
        candidates = [
            index for index, items in enumerate(setups)
            if allocations[index] < len(items)
        ]
        if not candidates:
            raise ValueError("requested unit count exceeds the setup-aware maximum")
        selected = max(
            candidates,
            key=lambda index: (len(setups[index]) / allocations[index], -index),
        )
        allocations[selected] += 1
    groups = [
        group
        for items, allocation in zip(setups, allocations, strict=True)
        for group in _split_evenly(items, allocation)
    ]
    return sorted(groups, key=lambda group: group[0].ordinal)


def _pack_by_duration(items: list, estimates: list, target_s: float, max_s: float | None) -> list[list]:
    result: list[list] = []
    current: list = []
    current_s = 0.0
    for item, estimate in zip(items, estimates, strict=True):
        item_s = float(estimate or target_s)
        if current and current_s + item_s > target_s:
            result.append(current)
            current = []
            current_s = 0.0
        current.append(item)
        current_s += item_s
        if max_s is not None and current_s >= max_s:
            result.append(current)
            current = []
            current_s = 0.0
    if current:
        result.append(current)
    return result


def _duration_groups(request: PartitionRequest, items: list) -> list[list]:
    if request.requested_unit_count is not None:
        raise AssertionError("explicit counts are allocated across setup groups")
    estimates = [
        item.estimated_duration_s or request.estimated_seconds_per_item
        for item in items
    ]
    if not any(estimates):
        return [[item] for item in items]
    return _pack_by_duration(items, estimates, request.target_unit_s, request.preferred_max_unit_s)


DEFAULT_MAX_QUEUED_UNITS = 2000


def _groups(request: PartitionRequest, max_queued_units: int | None = None) -> list[list]:
    setups = _setup_groups(request)
    if request.requested_unit_count is not None:
        return _requested_groups(request, setups)
    quota = max_queued_units or DEFAULT_MAX_QUEUED_UNITS
    flat_items = [item for setup in setups for item in setup]
    total_estimate = sum(
        float(item.estimated_duration_s or request.estimated_seconds_per_item or request.target_unit_s)
        for item in flat_items
    )
    groups = [group for items in setups for group in _duration_groups(request, items)]
    # Quota clamp: Workbench duration hints are advisory, never allowed to
    # fragment a submission past the project's queued-unit quota (the
    # temp1/v10 lesson: inflated per-item estimates produced one unit per
    # atom and hit max_queued_units). Scale the target up and repack until
    # the plan fits; atoms larger than the scaled target still get their own
    # unit. A submission whose atoms genuinely cannot fit stays over quota
    # and is rejected by the submit gate with its normal reason.
    if len(groups) > quota:
        target = request.target_unit_s
        while len(groups) > quota and target < total_estimate:
            target = max(target * 2, math.ceil(total_estimate / quota))
            groups = [
                group
                for items in setups
                for group in _pack_by_duration(
                    items,
                    [item.estimated_duration_s or request.estimated_seconds_per_item for item in items],
                    target,
                    None,
                )
            ]
    return sorted(groups, key=lambda group: group[0].ordinal)


def create_partition_plan(
    request: PartitionRequest, *, max_queued_units: int | None = None,
    resource_policy: ResourcePolicy | None = None,
) -> PartitionPlan:
    _require_partition_estimates(request)
    if request.priority_explicit is None:
        request.priority_explicit = 'priority' in request.model_fields_set
    if request.resources is None:
        profile = BUILTIN_PROFILES.get(request.execution_profile_id)
        if profile is None:
            raise ValueError("partition resources must be resolved by Network before planning")
        resolved = resolve_resources(
            profile=profile,
            schema_version=request.schema_version,
            requested=None,
            policy=resource_policy,
        )
        request.resources = resolved.resources
        request.resolved_resources = resolved
    grouped = _groups(request, max_queued_units)
    disk_decisions = []
    if request.disk_estimate is not None:
        selected = resource_policy
        if selected is None:
            profile = BUILTIN_PROFILES.get(request.execution_profile_id)
            if profile is None:
                raise ValueError("explicit resource policy required for disk estimation on a custom profile")
            selected = default_resource_policy(profile)
        if selected.profile_id != request.execution_profile_id:
            raise ValueError("resource policy does not match the execution profile")
        base = request.resolved_resources or ResolvedResources(
            resources=request.resources.model_copy(deep=True), source="origin_requested",
        )
        disk_decisions = [resolve_partition_disk(request.disk_estimate, atom_count=len(group),
            base=base, policy=selected) for group in grouped]
        # The request-level summary represents the largest actual Unit, not a
        # stale profile default or the aggregate output of the whole task.
        peak = max(disk_decisions, key=lambda decision: decision.resources.disk_mb)
        request.resources = peak.resources.model_copy(deep=True)
        request.resolved_resources = peak.model_copy(deep=True)
    grouping_payload = [[item.item_id for item in group] for group in grouped]
    identity = {
        "request_hash": request.request_hash,
        # Solver approvals bind an operational execution environment. They
        # must participate in plan identity so a re-approved candidate cannot
        # reuse a confirmed plan/job from a different runtime.
        "solver_approval_id": request.solver_approval_id,
        "solver_compatibility_fingerprint": request.solver_compatibility_fingerprint,
        "groups": grouping_payload,
        "target_unit_s": request.target_unit_s,
        "preferred_max_unit_s": request.preferred_max_unit_s,
        "allowed_solver_variants": sorted(item.value for item in request.allowed_solver_variants),
        "solver_policy": request.solver_policy.value,
        "resource_mode": request.resource_mode.value,
        "partition_constraints": request.partition_constraints.model_dump(mode="json"),
        "resources": request.resources.model_dump(mode="json"),
    }
    if request.disk_estimate is not None:
        identity["disk_estimate"] = request.disk_estimate.model_dump(mode="json")
        identity["unit_resources"] = [item.resources.model_dump(mode="json") for item in disk_decisions]
    plan_hash = sha256_value(identity)
    work_units: list[WorkUnit] = []
    for ordinal, group in enumerate(grouped):
        estimates = [
            item.estimated_duration_s or request.estimated_seconds_per_item
            for item in group
        ]
        estimated_s = sum(float(value) for value in estimates if value is not None)
        if estimated_s <= 0:
            estimated_s = request.target_unit_s
        preferred_machine = (
            request.initial_machine_spread[ordinal]
            if ordinal < len(request.initial_machine_spread)
            else None
        )
        work_units.append(WorkUnit(
            work_unit_id=f"unit-{plan_hash[:16]}-{ordinal:04d}",
            ordinal=ordinal,
            payload={
                "kind": request.unit_payload_kind,
                "items": [item.model_dump(mode="json") for item in group],
            },
            atomic_item_ids=[item.item_id for item in group],
            expected_duration_s=max(1, min(86400, math.ceil(estimated_s))),
            resources=disk_decisions[ordinal].resources.model_copy(deep=True) if disk_decisions else request.resources,
            resolved_resources=disk_decisions[ordinal].model_copy(deep=True) if disk_decisions else request.resolved_resources,
            required_capabilities=set(request.required_capabilities),
            allowed_solver_variants=set(request.allowed_solver_variants),
            solver_policy=request.solver_policy,
            resource_mode=request.resource_mode,
            solver_policy_explicit=request.solver_policy_explicit,
            solver_approval_id=request.solver_approval_id,
            preferred_machine_id=preferred_machine,
        ))
    return PartitionPlan(
        plan_id=f"plan-{plan_hash[:24]}",
        plan_hash=plan_hash,
        request=request,
        work_units=work_units,
        atomic_item_count=len(request.items),
    )


def job_from_confirmed_plan(plan: PartitionPlan) -> JobEnvelope:
    if plan.status != "confirmed":
        raise ValueError("partition plan must be confirmed before it can become a job")
    request = plan.request
    return JobEnvelope(
        schema_version=2,
        job_id=plan.confirmed_job_id or f"job-{plan.plan_hash[:24]}",
        origin_submitter_id=request.origin_submitter_id,
        origin_adapter_id=request.origin_adapter_id,
        user_id=request.user_id,
        project_id=request.project_id,
        execution_profile_id=request.execution_profile_id,
        campaign_id=request.campaign_id,
        campaign_task_id=request.campaign_task_id,
        recipe_kind=request.recipe_kind,
        study_kind=request.study_kind,
        template_role=request.template_role,
        template_sha256=request.template_sha256,
        template_parameter_evidence=request.template_parameter_evidence,
        output_contract_sha256=request.output_contract_sha256,
        estimated_output_bytes=request.estimated_output_bytes,
        planning_warnings=list(request.planning_warnings),
        source_spec_sha256=request.source_spec_sha256,
        request_hash=(sha256_value({"base_request_hash": request.request_hash,
            "disk_estimate_plan_hash": plan.plan_hash}) if request.disk_estimate is not None else request.request_hash),
        input_manifest=request.input_manifest,
        work_units=[unit.model_copy(deep=True) for unit in plan.work_units],
        partition_plan_id=plan.plan_id,
        atomic_item_count=plan.atomic_item_count,
        solver_approval_id=request.solver_approval_id,
        solver_compatibility_fingerprint=request.solver_compatibility_fingerprint,
        solver_policy=request.solver_policy,
        resource_mode=request.resource_mode,
        solver_policy_explicit=request.solver_policy_explicit,
        timeout_s=request.timeout_s,
        retry_policy=request.retry_policy,
        priority=request.priority,
        priority_explicit=(request.priority_explicit if request.priority_explicit is not None
                           else 'priority' in request.model_fields_set),
        duration_estimate_complete=all(
            value is not None and math.isfinite(value) and value > 0
            for item in request.items
            for value in [item.estimated_duration_s or request.estimated_seconds_per_item]
        ),
    )


def confirm_partition_plan(plan: PartitionPlan) -> PartitionPlan:
    if plan.status == "confirmed":
        return plan
    confirmed = plan.model_copy(deep=True)
    confirmed.status = "confirmed"
    confirmed.confirmed_job_id = f"job-{confirmed.plan_hash[:24]}"
    confirmed.confirmed_at = datetime.now(timezone.utc)
    return confirmed
