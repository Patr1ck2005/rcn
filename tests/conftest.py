from __future__ import annotations

from datetime import datetime, timezone
import os

import pytest

from research_compute_network.models import (
    ApprovalRecord,
    ApprovalScope,
    JobEnvelope,
    MachineMetrics,
    MachineHeartbeat,
    MachineMode,
    MachinePolicy,
    MachineState,
    ProjectGrant,
    ResourceRequest,
    TimeWindow,
    WorkUnit,
)
from research_compute_network.profiles import WORKBENCH_COMSOL_SCAN_V1
from research_compute_network.repository import MetadataRepository
from research_compute_network.service import NetworkService


def pytest_collection_modifyitems(config, items) -> None:
    if os.environ.get("RCN_RUN_WORKBENCH_INTEGRATION") == "1":
        return
    skipped = pytest.mark.skip(
        reason=(
            "Workbench integration is explicit; set "
            "RCN_RUN_WORKBENCH_INTEGRATION=1 with a selected Workbench source or wheel"
        )
    )
    for item in items:
        if "workbench_integration" in item.keywords:
            item.add_marker(skipped)


@pytest.fixture
def service(tmp_path, monkeypatch) -> NetworkService:
    repository = MetadataRepository(f"sqlite:///{(tmp_path / 'pilot.db').as_posix()}")
    from runtime_fixture import configure_external_runtime
    from research_compute_network.runtime_policy import runtime_policy_from_environment
    configure_external_runtime(tmp_path, monkeypatch)
    result = NetworkService(repository, runtime_policy=runtime_policy_from_environment())
    result.initialize()
    return result


def approved_grant(project_id: str = "demo-analysis", user_id: str = "user-a") -> ProjectGrant:
    return ProjectGrant(
        project_id=project_id,
        owner_user_id=user_id,
        approved=True,
        allowed_profiles={WORKBENCH_COMSOL_SCAN_V1.profile_id},
    )


def open_machine(machine_id: str = "worker-1", owner: str = "owner-1") -> tuple[MachineState, MachinePolicy]:
    now = datetime.now(timezone.utc)
    machine = MachineState(
        machine_id=machine_id,
        owner_user_id=owner,
        hostname=machine_id,
        labels={"group-trusted"},
        capabilities={"comsol-6.4", "python-mph"},
        total_cpus=16,
        total_memory_mb=65536,
        metrics=MachineMetrics(
            keyboard_idle_s=7200,
            non_pool_cpu_percent=2,
            available_memory_mb=56000,
            free_disk_mb=200000,
            running_units=0,
            observed_at=now,
        ),
        last_heartbeat_at=now,
    )
    policy = MachinePolicy(
        machine_id=machine_id,
        owner_user_id=owner,
        weekly_windows={day: [TimeWindow(start="00:00", end="00:00")] for day in range(7)},
        owner_mode=MachineMode.OPEN,
        max_cpus=12,
        max_memory_mb=48000,
        max_concurrent_units=2,
    )
    return machine, policy


def project_approval(machine_id: str = "worker-1", project_id: str = "demo-analysis") -> ApprovalRecord:
    return ApprovalRecord(
        machine_id=machine_id,
        scope=ApprovalScope.PROJECT,
        subject_id=project_id,
        approved_by="owner-1",
    )


def register_live_machine(service, machine: MachineState, policy: MachinePolicy) -> None:
    service.register_machine(machine, policy, actor_id="admin")
    service.record_heartbeat(
        MachineHeartbeat(machine_id=machine.machine_id, metrics=machine.metrics),
        actor_id="test-machine-agent",
    )


def simple_job(
    *,
    request_hash: str = "a" * 64,
    user_id: str = "user-a",
    project_id: str = "demo-analysis",
) -> JobEnvelope:
    return JobEnvelope(
        origin_submitter_id="submitter-a",
        user_id=user_id,
        project_id=project_id,
        execution_profile_id=WORKBENCH_COMSOL_SCAN_V1.profile_id,
        request_hash=request_hash,
        work_units=[
            WorkUnit(
                work_unit_id=f"unit-{request_hash[:8]}-0000",
                ordinal=0,
                payload={"kind": "test"},
                # Scheduling tests exercise eligibility and lifecycle state;
                # keep them independent of the wall-clock position within a
                # recurring owner window.
                expected_duration_s=1,
                resources=ResourceRequest(cpus=4, memory_mb=16000, disk_mb=1000),
                required_capabilities={"comsol-6.4", "python-mph"},
            )
        ],
    )
