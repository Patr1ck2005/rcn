"""Network-owned resource resolution and bounded adaptive recommendations."""

from __future__ import annotations

import math
from collections.abc import Sequence

from .models import (
    ExecutionProfile,
    ResolvedResources,
    ResourcePolicy,
    ResourceRequest,
    UnitDiskEstimate,
)


def default_resource_policy(profile: ExecutionProfile) -> ResourcePolicy:
    baseline = profile.default_resources.model_copy(deep=True)
    minimum = ResourceRequest(
        cpus=min(1, baseline.cpus),
        memory_mb=min(256, baseline.memory_mb),
        disk_mb=0,
        gpus=0,
    )
    maximum = ResourceRequest(
        cpus=max(64, baseline.cpus),
        memory_mb=max(262144, baseline.memory_mb),
        disk_mb=max(1048576, baseline.disk_mb),
        gpus=max(8, baseline.gpus),
    )
    return ResourcePolicy(
        profile_id=profile.profile_id,
        baseline=baseline,
        minimum=minimum,
        maximum=maximum,
    )


def _bounded(value: int, low: int, high: int) -> int:
    return min(high, max(low, value))


def resolve_resources(
    *,
    profile: ExecutionProfile,
    schema_version: int,
    requested: ResourceRequest | None,
    policy: ResourcePolicy | None = None,
) -> ResolvedResources:
    """Resolve an origin request into the concrete Network execution contract."""

    selected = policy or default_resource_policy(profile)
    if selected.profile_id != profile.profile_id:
        raise ValueError("resource policy does not match the execution profile")

    if schema_version == 1:
        resources = (requested or ResourceRequest()).model_copy(deep=True)
        source = "origin_legacy"
    elif requested is not None:
        resources = ResourceRequest(
            cpus=_bounded(requested.cpus, selected.minimum.cpus, selected.maximum.cpus),
            memory_mb=_bounded(
                requested.memory_mb,
                selected.minimum.memory_mb,
                selected.maximum.memory_mb,
            ),
            disk_mb=_bounded(requested.disk_mb, selected.minimum.disk_mb, selected.maximum.disk_mb),
            gpus=_bounded(requested.gpus, selected.minimum.gpus, selected.maximum.gpus),
        )
        source = "origin_requested"
    else:
        resources = selected.baseline.model_copy(deep=True)
        source = "network_policy" if policy is not None else "network_profile_default"

    return ResolvedResources(
        resources=resources,
        source=source,
        policy_revision=selected.revision,
        evidence_sample_count=0,
    )


def resolve_partition_disk(
    estimate: UnitDiskEstimate, *, atom_count: int,
    base: ResolvedResources, policy: ResourcePolicy,
) -> ResolvedResources:
    """Keep CPU/memory decisions; freeze an integer-ceiling per-unit disk bound.

    Profile baseline disk and task-wide output totals are deliberately not floors.
    A planning bound above the policy maximum must fail, never truncate downward.
    """
    if atom_count < 1:
        raise ValueError("disk estimate requires at least one atom")
    size = atom_count * estimate.bytes_per_atom + estimate.shared_input_bytes
    disk_mb = max((size + 1048575) // 1048576, estimate.minimum_disk_mb, policy.minimum.disk_mb)
    if disk_mb > policy.maximum.disk_mb:
        raise ValueError(
            f"unit_disk_estimate_exceeds_policy: {disk_mb} MiB exceeds "
            f"{policy.maximum.disk_mb} MiB; increase the explicit Unit count or seek policy approval"
        )
    return base.model_copy(deep=True, update={
        "resources": base.resources.model_copy(update={"disk_mb": disk_mb}),
        "source": "origin_requested",
        "policy_revision": policy.revision,
    })


def _nearest_rank(values: Sequence[int], percentile: float) -> int:
    ordered = sorted(int(value) for value in values)
    if not ordered:
        raise ValueError("percentile requires at least one sample")
    rank = max(1, math.ceil(percentile / 100.0 * len(ordered)))
    return ordered[rank - 1]


def _adaptive_value(
    *,
    current: int,
    observed: int,
    margin_percent: float,
    margin_floor: int,
    minimum: int,
    maximum: int,
    downward_step_percent: float,
) -> tuple[int, int]:
    margin = max(math.ceil(observed * margin_percent / 100.0), margin_floor)
    target = _bounded(observed + margin, minimum, maximum)
    if target >= current:
        return target, margin
    floor_for_this_revision = math.ceil(current * (1.0 - downward_step_percent / 100.0))
    return max(target, floor_for_this_revision, minimum), margin


def recommend_adaptive_policy(
    policy: ResourcePolicy,
    *,
    memory_peak_mb: Sequence[int],
    disk_peak_mb: Sequence[int],
) -> tuple[ResourcePolicy, ResolvedResources]:
    """Return one bounded revision after enough comparable successful Attempts."""

    sample_count = min(len(memory_peak_mb), len(disk_peak_mb))
    if sample_count < policy.minimum_success_samples or not policy.automatic_adjustment:
        resolved = ResolvedResources(
            resources=policy.baseline.model_copy(deep=True),
            source="network_policy",
            policy_revision=policy.revision,
            evidence_sample_count=sample_count,
        )
        return policy.model_copy(deep=True), resolved

    memory_p99 = _nearest_rank(memory_peak_mb, policy.memory_percentile)
    disk_p99 = _nearest_rank(disk_peak_mb, policy.disk_percentile)
    memory_mb, memory_margin = _adaptive_value(
        current=policy.baseline.memory_mb,
        observed=memory_p99,
        margin_percent=policy.memory_margin_percent,
        margin_floor=policy.memory_margin_floor_mb,
        minimum=policy.minimum.memory_mb,
        maximum=policy.maximum.memory_mb,
        downward_step_percent=policy.downward_step_percent,
    )
    disk_mb, disk_margin = _adaptive_value(
        current=policy.baseline.disk_mb,
        observed=disk_p99,
        margin_percent=policy.disk_margin_percent,
        margin_floor=policy.disk_margin_floor_mb,
        minimum=policy.minimum.disk_mb,
        maximum=policy.maximum.disk_mb,
        downward_step_percent=policy.downward_step_percent,
    )
    baseline = policy.baseline.model_copy(
        update={"memory_mb": memory_mb, "disk_mb": disk_mb}
    )
    changed = baseline != policy.baseline
    updated = policy.model_copy(
        deep=True,
        update={
            "baseline": baseline,
            "revision": policy.revision + (1 if changed else 0),
        },
    )
    resolved = ResolvedResources(
        resources=baseline.model_copy(deep=True),
        source="network_adaptive" if changed else "network_policy",
        policy_revision=updated.revision,
        evidence_sample_count=sample_count,
        memory_safety_margin_mb=memory_margin,
        disk_safety_margin_mb=disk_margin,
    )
    return updated, resolved
