"""Optional integration discovery without reverse source dependencies."""

from __future__ import annotations

from importlib.metadata import entry_points
from pathlib import Path
from typing import Callable

from .models import JobEnvelope, PartitionRequest
from .partitioning import confirm_partition_plan, create_partition_plan, job_from_confirmed_plan


WORKBENCH_ENTRY_POINT_GROUP = "research_compute_network.workbench"
WORKBENCH_PLANNER_NAME = "scan_planner"
WORKBENCH_SOURCE_NAME = "runtime_source"


def load_workbench_scan_planner() -> Callable:
    matches = entry_points(group=WORKBENCH_ENTRY_POINT_GROUP)
    planners = [entry for entry in matches if entry.name == WORKBENCH_PLANNER_NAME]
    if len(planners) != 1:
        raise RuntimeError(
            "Workbench Scan planning requires exactly one installed "
            f"{WORKBENCH_ENTRY_POINT_GROUP}:{WORKBENCH_PLANNER_NAME} adapter"
        )
    return planners[0].load()


def load_workbench_runtime_source():
    matches = entry_points(group=WORKBENCH_ENTRY_POINT_GROUP)
    providers = [entry for entry in matches if entry.name == WORKBENCH_SOURCE_NAME]
    if len(providers) != 1:
        raise RuntimeError(
            "Workbench runtime packaging requires exactly one installed "
            f"{WORKBENCH_ENTRY_POINT_GROUP}:{WORKBENCH_SOURCE_NAME} adapter"
        )
    return providers[0].load()()


def resolve_workbench_workspace_root(runtime_source: str | Path | None = None) -> Path:
    """Resolve the Workbench checkout root from its registered package source."""
    source = Path(runtime_source or load_workbench_runtime_source()).resolve()
    if source.name != "research_agent_workbench" or source.parent.name != "src":
        raise RuntimeError(f"unexpected Workbench runtime source layout: {source}")
    workspace = source.parents[1]
    if not (workspace / "projects").is_dir():
        raise RuntimeError(f"Workbench projects directory is unavailable: {workspace}")
    return workspace


def materialize_workbench_probe_job(value) -> JobEnvelope:
    """Adapt the Workbench 0.5 planner contract for bounded local probes."""
    if isinstance(value, JobEnvelope):
        return value
    request = PartitionRequest.model_validate(value)
    plan = confirm_partition_plan(create_partition_plan(request))
    return job_from_confirmed_plan(plan)


def workbench_unit_item_count(unit) -> int:
    """Read v2 atomic coverage with a v1 pre-grouped payload fallback."""
    if unit.atomic_item_ids:
        return len(unit.atomic_item_ids)
    return len(unit.payload.get("k_indices", []))
