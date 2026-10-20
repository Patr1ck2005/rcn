from __future__ import annotations

from datetime import datetime, timezone

import pytest

from research_compute_network.hashing import sha256_value
from research_compute_network.models import (
    AtomicComputeItem,
    ComsolStudyKind,
    FailureClass,
    GpuMetric,
    JobEnvelope,
    MachinePolicy,
    PartitionConstraints,
    PartitionRequest,
    ResourceRequest,
    ResourceMode,
    SolverCompatibilityApproval,
    SolverMeshPolicy,
    SolverPolicy,
    SolverVariant,
    WorkUnit,
    WorkUnitAttempt,
    WorkUnitStatus,
)
from research_compute_network.placement import PlacementBlocker
from research_compute_network.profiles import (
    WORKBENCH_COMSOL_EIGEN_V3,
    WORKBENCH_COMSOL_SCAN_V1,
    WORKBENCH_COMSOL_STUDY_V1,
)
from runtime_fixture import TEST_RUNTIME_VERSION

from conftest import (
    approved_grant,
    open_machine,
    project_approval,
    register_live_machine,
)


def atomic_items(count: int) -> list[AtomicComputeItem]:
    return [
        AtomicComputeItem(
            item_id=f"point-{index:03d}",
            ordinal=index,
            payload={"k_idx": index, "m1": index / max(1, count - 1), "m2": 0.0},
            estimated_duration_s=30,
        )
        for index in range(count)
    ]


def test_solver_blocker_accepts_capability_list_evidence() -> None:
    blocker = PlacementBlocker(
        code="cudss_capability_missing",
        category="solver",
        message="cuDSS capability is unavailable",
        required="solver-cudss",
        available=["comsol-6.4", "python-mph"],
    )

    assert blocker.available == ["comsol-6.4", "python-mph"]


def request(count: int, units: int, **overrides) -> PartitionRequest:
    payload = dict(
        origin_submitter_id="submitter-a",
        user_id="user-a",
        project_id="demo-analysis",
        execution_profile_id=WORKBENCH_COMSOL_SCAN_V1.profile_id,
        request_hash=sha256_value({"count": count, "units": units, **overrides}),
        items=atomic_items(count),
        requested_unit_count=units,
        resources=ResourceRequest(cpus=1, memory_mb=1024, disk_mb=16),
        required_capabilities=set(WORKBENCH_COMSOL_SCAN_V1.required_capabilities),
        unit_payload_kind="workbench_comsol_scan_items",
    )
    payload.update(overrides)
    return PartitionRequest(**payload)


def test_explicit_partition_is_deterministic_and_exact(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")

    plan_a = service.plan_partition(request(30, 5), actor_id="user-a")
    plan_b = service.plan_partition(request(60, 10), actor_id="user-a")

    assert [len(unit.atomic_item_ids) for unit in plan_a.work_units] == [6] * 5
    assert [len(unit.atomic_item_ids) for unit in plan_b.work_units] == [6] * 10
    assert len({item for unit in plan_b.work_units for item in unit.atomic_item_ids}) == 60
    assert service.plan_partition(request(30, 5), actor_id="user-a").plan_id == plan_a.plan_id


def test_confirmed_plan_creates_v2_job_while_v1_remains_readable(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")
    plan = service.plan_partition(request(6, 2), actor_id="user-a")

    job = service.confirm_partition(plan.plan_id, actor_id="user-a")

    assert job.schema_version == 2
    assert job.partition_plan_id == plan.plan_id
    assert job.atomic_item_count == 6
    legacy = JobEnvelope.model_validate({
        "schema_version": 1,
        "origin_submitter_id": "legacy",
        "user_id": "user-a",
        "project_id": "demo-analysis",
        "execution_profile_id": WORKBENCH_COMSOL_SCAN_V1.profile_id,
        "request_hash": "f" * 64,
        "work_units": [{"ordinal": 0, "payload": {"kind": "legacy"}}],
    })
    assert legacy.schema_version == 1


def _mixed_solver_request(service, *, initial_machine_spread=None):
    approval = SolverCompatibilityApproval(
        project_id="demo-analysis",
        execution_profile_id=WORKBENCH_COMSOL_SCAN_V1.profile_id,
        comsol_version="6.4",
        template_sha256="b" * 64,
        approved_by="admin",
    )
    service.approve_solver(approval, actor_id="admin")
    return request(
        6,
        1,
        allowed_solver_variants={SolverVariant.MUMPS, SolverVariant.CUDSS},
        solver_approval_id=approval.approval_id,
        solver_compatibility_fingerprint=approval.fingerprint,
        initial_machine_spread=initial_machine_spread or [],
    )


def _structured_solver_request(approval, *, template_sha256=None, mesh_policy=None):
    template_hash = template_sha256 or approval.template_sha256
    policy = mesh_policy or approval.mesh_policy.model_dump(mode="json")
    item = AtomicComputeItem(
        item_id="structured-000",
        ordinal=0,
        setup_fingerprint="a" * 64,
        coordinates={"m1": 0, "m2": 0},
        payload={
            "template_sha256": template_hash,
            "recipe_config": {"mesh_policy": policy},
        },
    )
    return PartitionRequest(
        origin_submitter_id="submitter-a",
        user_id="user-a",
        project_id="demo-analysis",
        execution_profile_id=WORKBENCH_COMSOL_EIGEN_V3.profile_id,
        request_hash=sha256_value({"template": template_hash, "mesh": policy}),
        items=[item],
        requested_unit_count=1,
        allowed_solver_variants={SolverVariant.MUMPS, SolverVariant.CUDSS},
        solver_approval_id=approval.approval_id,
        solver_compatibility_fingerprint=approval.fingerprint,
        partition_constraints=PartitionConstraints(prohibit_mixed_setup_fingerprints=True),
    )


def test_private_structured_profile_cannot_be_enabled_by_solver_approval(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")
    approval = SolverCompatibilityApproval(
        project_id="demo-analysis",
        execution_profile_id=WORKBENCH_COMSOL_EIGEN_V3.profile_id,
        comsol_version="6.4", template_sha256="b" * 64,
        mesh_policy=SolverMeshPolicy(mode="template_features", mesh_tag="mesh1"),
        approved_by="admin",
    )
    with pytest.raises(KeyError, match="execution profile not found"):
        service.approve_solver(approval, actor_id="admin")
    assert service.repository.get_solver_approval(approval.approval_id) is None


def test_generic_study_approval_binds_template_and_mesh_policy(service) -> None:
    grant = approved_grant()
    grant.allowed_profiles.add(WORKBENCH_COMSOL_STUDY_V1.profile_id)
    service.register_project(grant, actor_id="admin")
    approval = SolverCompatibilityApproval(
        project_id=grant.project_id, execution_profile_id=WORKBENCH_COMSOL_STUDY_V1.profile_id,
        comsol_version="6.4", runtime_version=TEST_RUNTIME_VERSION,
        template_sha256="b" * 64, template_role="example-template",
        allowed_study_kinds={ComsolStudyKind.STATIONARY},
        mesh_policy=SolverMeshPolicy(mode="auto_size", mesh_tag="mesh1", size="normal"),
        approved_by="admin",
    )
    service.approve_solver(approval, actor_id="admin")
    item = {"template_sha256": approval.template_sha256, "template_role": approval.template_role,
            "study": {"kind": "stationary", "mesh_policy": approval.mesh_policy.model_dump(mode="json")}}
    validate = service._validate_solver_approval_evidence
    validate(approval, approval.execution_profile_id, [item])
    with pytest.raises(ValueError, match="template hash"):
        validate(approval, approval.execution_profile_id, [{**item, "template_sha256": "c" * 64}])
    with pytest.raises(ValueError, match="MeshPolicy"):
        validate(approval, approval.execution_profile_id, [{**item,
            "study": {"kind": "stationary", "mesh_policy": {"mode": "auto_size", "mesh_tag": "mesh1", "size": "fine"}}}])

def test_gpu_prefers_cudss_and_failed_retry_falls_back_to_mumps(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")
    machine, policy = open_machine("gpu-worker")
    machine.total_gpus = 1
    machine.capabilities.add("solver-cudss")
    machine.metrics.gpu = [GpuMetric(index=0, name="GPU")]
    policy.max_gpus = 1
    register_live_machine(service, machine, policy)
    service.approve(project_approval(machine.machine_id), actor_id="owner-1")
    plan = service.plan_partition(
        _mixed_solver_request(service, initial_machine_spread=[machine.machine_id]),
        actor_id="user-a",
    )
    job = service.confirm_partition(plan.plan_id, actor_id="user-a")

    first = service.schedule_once()
    assert first is not None and first.solver_variant == SolverVariant.CUDSS
    service.fail_unit(
        job.job_id,
        first.work_unit_id,
        error="GPU runtime interrupted",
        failure_class=FailureClass.INFRASTRUCTURE,
        actor_id="dispatcher",
    )
    second = service.schedule_once()
    assert second is not None and second.solver_variant == SolverVariant.MUMPS


def test_gpu_keeps_cudss_after_prelaunch_idempotency_failure(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")
    machine, policy = open_machine("gpu-idempotency")
    machine.total_gpus = 1
    machine.capabilities.add("solver-cudss")
    machine.metrics.gpu = [GpuMetric(index=0, name="GPU")]
    policy.max_gpus = 1
    register_live_machine(service, machine, policy)
    service.approve(project_approval(machine.machine_id), actor_id="owner-1")
    request_payload = _mixed_solver_request(service, initial_machine_spread=[machine.machine_id])
    request_payload.solver_policy = SolverPolicy.AUTO_FAST
    request_payload.solver_policy_explicit = True
    plan = service.plan_partition(request_payload, actor_id="user-a")
    job = service.confirm_partition(plan.plan_id, actor_id="user-a")
    first = service.schedule_once()
    assert first is not None and first.solver_variant == SolverVariant.CUDSS
    service.fail_unit(
        job.job_id,
        first.work_unit_id,
        error="bundle rejected: idempotency conflict for existing run",
        failure_class=FailureClass.INFRASTRUCTURE,
        actor_id="dispatcher",
    )
    second = service.schedule_once()
    assert second is not None and second.solver_variant == SolverVariant.CUDSS


def test_explicit_auto_fast_blocks_after_cudss_failure_without_mumps_fallback(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")
    machine, policy = open_machine("gpu-auto-fast")
    machine.total_gpus = 1
    machine.capabilities.add("solver-cudss")
    machine.metrics.gpu = [GpuMetric(index=0, name="GPU")]
    policy.max_gpus = 1
    register_live_machine(service, machine, policy)
    service.approve(project_approval(machine.machine_id), actor_id="owner-1")
    request_payload = _mixed_solver_request(service, initial_machine_spread=[machine.machine_id])
    request_payload.solver_policy = SolverPolicy.AUTO_FAST
    request_payload.allowed_solver_variants = {SolverVariant.CUDSS}
    request_payload.solver_policy_explicit = True
    plan = service.plan_partition(request_payload, actor_id="user-a")
    job = service.confirm_partition(plan.plan_id, actor_id="user-a")

    first = service.schedule_once()
    assert first is not None and first.solver_variant == SolverVariant.CUDSS
    service.fail_unit(
        job.job_id,
        first.work_unit_id,
        error="cuDSS prelaunch unavailable",
        failure_class=FailureClass.INFRASTRUCTURE,
        actor_id="dispatcher",
    )
    assert service.schedule_once() is None


def test_explicit_auto_fast_accepts_mixed_solver_variants(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")
    request_payload = _mixed_solver_request(service)
    request_payload.solver_policy = SolverPolicy.AUTO_FAST
    request_payload.solver_policy_explicit = True
    plan = service.plan_partition(request_payload, actor_id="user-a")

    assert plan.request.allowed_solver_variants == {
        SolverVariant.CUDSS,
        SolverVariant.MUMPS,
    }


def test_auto_fast_uses_mumps_on_cpu_only_machine(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")
    machine, policy = open_machine("cpu-worker")
    register_live_machine(service, machine, policy)
    service.approve(project_approval(machine.machine_id), actor_id="owner-1")
    request_payload = _mixed_solver_request(
        service,
        initial_machine_spread=[machine.machine_id],
    )
    request_payload.solver_policy = SolverPolicy.AUTO_FAST
    request_payload.solver_policy_explicit = True
    # A mixed dynamic request may advertise one GPU for cuDSS-capable hosts.
    # That preference must not exclude CPU-only hosts that resolve to MUMPS.
    request_payload.resources = request_payload.resources.model_copy(update={"gpus": 1})
    plan = service.plan_partition(request_payload, actor_id="user-a")
    service.confirm_partition(plan.plan_id, actor_id="user-a")

    assignment = service.schedule_once()

    assert assignment is not None
    assert assignment.machine_id == machine.machine_id
    assert assignment.solver_variant == SolverVariant.MUMPS


def test_solver_contract_migration_changes_only_unstarted_units(service) -> None:
    grant = approved_grant()
    grant.allowed_profiles.add(WORKBENCH_COMSOL_STUDY_V1.profile_id)
    service.register_project(grant, actor_id="admin")
    approval = SolverCompatibilityApproval(
        approval_id="approval-current",
        project_id=grant.project_id,
        execution_profile_id=WORKBENCH_COMSOL_STUDY_V1.profile_id,
        comsol_version="6.4",
        runtime_version=TEST_RUNTIME_VERSION,
        template_sha256="d" * 64,
        template_role="spectrum",
        allowed_study_kinds={ComsolStudyKind.FREQUENCY_DOMAIN},
        mesh_policy=SolverMeshPolicy(mode="auto_size", mesh_tag="mesh1", size="fine"),
        approved_by="admin",
    )
    service.approve_solver(approval, actor_id="admin")
    completed = WorkUnit(
        ordinal=0,
        payload={"kind": "study"},
        status=WorkUnitStatus.COMPLETED,
        allowed_solver_variants={SolverVariant.CUDSS},
        attempts=[WorkUnitAttempt(attempt_id="done-1", state="completed", execution_started=True)],
    )
    queued = WorkUnit(
        ordinal=1,
        payload={"kind": "study"},
        allowed_solver_variants={SolverVariant.CUDSS},
    )
    job = JobEnvelope(
        origin_submitter_id="submitter-a",
        user_id="user-a",
        project_id=grant.project_id,
        execution_profile_id=WORKBENCH_COMSOL_STUDY_V1.profile_id,
        study_kind=ComsolStudyKind.FREQUENCY_DOMAIN,
        template_role="spectrum",
        template_sha256="d" * 64,
        request_hash="e" * 64,
        work_units=[completed, queued],
    )
    service.repository.put_job(job)

    migrated = service.migrate_unstarted_solver_contract(
        job.job_id,
        approval_id=approval.approval_id,
        actor_id="admin",
    )

    assert migrated.work_units[0].allowed_solver_variants == {SolverVariant.CUDSS}
    assert migrated.work_units[0].attempts[0].execution_started is True
    assert migrated.work_units[1].allowed_solver_variants == {
        SolverVariant.CUDSS,
        SolverVariant.MUMPS,
    }
    assert migrated.work_units[1].resource_mode == ResourceMode.DYNAMIC
    assert migrated.solver_compatibility_fingerprint == approval.fingerprint


def _multi_unit_job(hash_char: str) -> JobEnvelope:
    return JobEnvelope(
        origin_submitter_id="submitter-a",
        user_id="user-a",
        project_id="demo-analysis",
        execution_profile_id=WORKBENCH_COMSOL_SCAN_V1.profile_id,
        request_hash=hash_char * 64,
        work_units=[
            WorkUnit(
                work_unit_id=f"unit-{hash_char}-{index}",
                ordinal=index,
                payload={"kind": "test"},
                expected_duration_s=1,
                resources=ResourceRequest(cpus=1, memory_mb=512, disk_mb=1),
                required_capabilities=set(WORKBENCH_COMSOL_SCAN_V1.required_capabilities),
            )
            for index in range(2)
        ],
    )


def test_equal_priority_jobs_rotate_and_collecting_does_not_hold_compute_slot(service) -> None:
    service.register_project(approved_grant(), actor_id="admin")
    machine, policy = open_machine("worker")
    policy.max_concurrent_units = 2
    policy.max_cpus = 16
    register_live_machine(service, machine, policy)
    service.approve(project_approval(machine.machine_id), actor_id="owner-1")
    first_job = service.submit(_multi_unit_job("a"), actor_id="user-a")
    second_job = service.submit(_multi_unit_job("b"), actor_id="user-a")

    first_assignment = service.schedule_once()
    second_assignment = service.schedule_once()

    assert first_assignment is not None and second_assignment is not None
    assert first_assignment.job_id != second_assignment.job_id

    stored_first = service.repository.get_job(first_job.job_id)
    assert stored_first is not None
    assigned = next(unit for unit in stored_first.work_units if unit.status == WorkUnitStatus.ASSIGNED)
    assigned.status = WorkUnitStatus.COLLECTING
    assigned.attempts[-1].state = "collecting"
    service.repository.put_job(stored_first)
    stored_second = service.repository.get_job(second_job.job_id)
    assert stored_second is not None
    other_assigned = next(unit for unit in stored_second.work_units if unit.status == WorkUnitStatus.ASSIGNED)
    other_assigned.status = WorkUnitStatus.COLLECTING
    other_assigned.attempts[-1].state = "collecting"
    service.repository.put_job(stored_second)

    third = service.schedule_once()
    assert third is not None
