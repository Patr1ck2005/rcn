"""Public platform behavior, exercised without private science ZIPs or services."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest
from fastapi.testclient import TestClient

from research_compute_network.member_release_catalog import (
    RuntimeNotConfigured, approved_release_descriptor, current_member_release,
    selected_center_release, approved_scientific_equivalence,
)
from research_compute_network.runtime_policy import (
    RuntimePolicy, UNCONFIGURED_RUNTIME_VERSION, runtime_policy_from_environment,
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    for key in ("RCN_RUNTIME_DESCRIPTOR", "RCN_MEMBER_RELEASE_RUNTIME",
                "RCN_MEMBER_APPROVED_RUNTIME_ARCHIVE", "RCN_CANARY_RUNTIME_VERSIONS",
                "RCN_DATABASE_URL", "RCN_PILOT_DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("RCN_HOME", str(tmp_path / "home"))


from runtime_fixture import configure_external_runtime as approved_external_archive


def test_no_private_runtime_is_implicitly_approved():
    release = current_member_release()
    assert not release.configured
    assert release.archive_sha256 == release.supervisor_sha256 == ""
    assert release.runtime_version == UNCONFIGURED_RUNTIME_VERSION
    assert RuntimePolicy().worker_runtime_versions == frozenset()
    assert not RuntimePolicy().accepts_new_approval(release.runtime_version)
    with pytest.raises(RuntimeNotConfigured, match="^runtime_not_configured$"):
        _ = release.archive_path


def test_runtime_configuration_requires_local_approval_not_an_api_hash():
    with pytest.raises(ValueError, match="member_release_descriptor_changed"):
        approved_release_descriptor({"runtime_version": "1" * 24, "archive_sha256": "2" * 64})


def test_operator_archive_verified_and_no_scientific_equivalence_inferred(tmp_path, monkeypatch):
    path, descriptor, archive = approved_external_archive(tmp_path, monkeypatch)
    release = selected_center_release()
    assert release.configured and release.owner_session_required
    assert release.archive_path == archive
    assert runtime_policy_from_environment().accepts_new_approval(release.runtime_version)
    from research_compute_network.member_runtime import approved_runtime
    assert "remote-agent/member_session_gate.py" in approved_runtime(archive)
    with pytest.raises(ValueError, match="scientific_equivalence_not_configured"):
        approved_scientific_equivalence(release)
    archive.write_bytes(archive.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="runtime_archive_integrity"):
        selected_center_release()


@pytest.mark.parametrize("field,value", [("owner_session_required", False), ("actor_id", ""),
    ("reason", ""), ("runtime_version", "not-a-fingerprint"), ("unexpected", "field")])
def test_operator_descriptor_rejects_unsafe_or_unattributed_configuration(tmp_path, monkeypatch, field, value):
    path, descriptor, archive = approved_external_archive(tmp_path, monkeypatch)
    descriptor[field] = value
    path.write_text(json.dumps(descriptor), encoding="utf-8")
    with pytest.raises(ValueError):
        selected_center_release()


def test_removed_research_contracts_fail_closed():
    from research_compute_network.remote_agent.template_build_contracts import (
        TEMPLATE_BUILD_PRESETS, template_build_preset_contract)
    from research_compute_network.remote_agent.saved_readout_contracts import (
        SAVED_READOUT_DIAGNOSTICS, saved_readout_contract)
    from research_compute_network.remote_agent.comsol_recipe_contracts import (
        FIXED_COMSOL_RECIPE_CONTRACTS, RECIPE_CAPABILITIES)
    assert not TEMPLATE_BUILD_PRESETS and not SAVED_READOUT_DIAGNOSTICS and not RECIPE_CAPABILITIES
    assert set(FIXED_COMSOL_RECIPE_CONTRACTS) == {"workbench-comsol-study-v1", "workbench-comsol-study-v2"}
    for function in (template_build_preset_contract, saved_readout_contract):
        with pytest.raises(ValueError, match="private_profile_not_available"):
            function("unregistered")


def test_generic_comsol_study_keeps_declarative_validation():
    from research_compute_network.remote_agent.comsol_recipe_contracts import validate_fixed_recipe_items
    output = {"schema_version": 1, "expressions": [{"name": "value", "expression": "T"}],
              "fields": [], "semantic_outputs": []}
    item = {"coordinates": {"step": 0}, "setup_fingerprint": "1" * 64, "payload": {
        "kind": "workbench_comsol_study_point", "project_id": "example-project",
        "template_role": "example-template", "template_sha256": "2" * 64,
        "scan_spec_sha256": "3" * 64, "template_inspection_sha256": "4" * 64,
        "output_contract_sha256": "5" * 64,
        "study": {"tag": "std1", "kind": "stationary", "mesh_policy": {
            "mode": "auto_size", "mesh_tag": "mesh1", "size": "normal"}},
        "parameters": {"input": 1}, "setup_parameters": {"input": 1}, "sweep_parameters": {},
        "output_request": output}}
    kwargs = {"profile_id": "workbench-comsol-study-v1", "recipe_kind": "comsol_study", "solver_variant": "mumps"}
    assert validate_fixed_recipe_items(items=[item], **kwargs).profile_id == kwargs["profile_id"]
    unsafe = deepcopy(item)
    unsafe["payload"]["command"] = "arbitrary shell"
    with pytest.raises(ValueError, match="unsupported fields"):
        validate_fixed_recipe_items(items=[unsafe], **kwargs)
    with pytest.raises(ValueError):
        validate_fixed_recipe_items(items=[item], **{**kwargs, "profile_id": "workbench-comsol-template-build-v1"})


def test_scientific_probes_and_compute_fail_explicitly_before_effects():
    from research_compute_network.scientific_acceptance_contract import capsule_bytes, scientific_acceptance_capability
    from research_compute_network.ssh_acceptance_inputs import PackagedAcceptanceInputs, packaged_acceptance_capability
    from research_compute_network.member_runtime import approved_runtime
    assert scientific_acceptance_capability()["reason_code"] == "runtime_not_configured"
    assert packaged_acceptance_capability()["available"] is False
    for function in (capsule_bytes, lambda: PackagedAcceptanceInputs(Path("missing")),
                     lambda: approved_runtime(Path("missing.zip"))):
        with pytest.raises(RuntimeNotConfigured, match="^runtime_not_configured$"):
            function()


def test_owner_pause_and_logout_continue_to_block_worker_launch(tmp_path):
    from research_compute_network.remote_agent.member_session_gate import launch_permission
    root = tmp_path / "worker"
    owner, execution = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
    config = {"remote_root": str(root), "root_uuid": "example-root"}
    (tmp_path / "execution-identity.json").write_text(json.dumps({"schema_version": 1,
        "worker_root": str(root), "root_uuid": "example-root", "owner_sid": owner, "execution_sid": execution}))
    control = tmp_path / "owner-control"
    control.mkdir()
    value = {"schema_version": 1, "root_uuid": "example-root", "owner_sid": owner,
             "revision": 1, "paused": False, "retired": False}
    def check(signed_in):
        (control / "state.json").write_text(json.dumps(value))
        return launch_permission(config, required=True, sid_reader=lambda: execution,
                                 sessions_reader=lambda: [owner] if signed_in else [])
    assert check(True)["allowed"]
    assert check(False)["reason"] == "owner-logged-out"
    value["paused"] = True
    assert check(True)["reason"] == "owner-paused"
    value["retired"] = True
    assert check(True)["reason"] == "member-retiring"


def test_real_control_plane_demo_and_owner_stop_remain_functional():
    from research_compute_network.repository import MetadataRepository
    from research_compute_network.service import NetworkService
    from research_compute_network.simulator import DemoSimulator
    from research_compute_network.models import MachineMode
    service = NetworkService(MetadataRepository("sqlite:///:memory:"))
    service.initialize(dataset_mode="demo")
    simulator = DemoSimulator(service)
    simulator.bootstrap()
    simulator.tick()
    assert len(service.repository.list_machines()) == 6
    assert len(service.repository.list_jobs()) == 3
    active = next(unit for job in service.repository.list_jobs() for unit in job.work_units
                  if unit.assigned_machine_id == "sim-worker-01" and unit.status.value in {"assigned", "running"})
    service.set_machine_mode("sim-worker-01", MachineMode.EMERGENCY_STOP, actor_id="demo-member")
    simulator.tick()
    stored = next(unit for job in service.repository.list_jobs() for unit in job.work_units if unit.work_unit_id == active.work_unit_id)
    assert stored.status.value == "failed_terminal"


def test_api_import_health_and_authentication_without_science():
    from research_compute_network.api import create_app
    app = create_app(database_url="sqlite:///:memory:", allow_local_trusted=False)
    client = TestClient(app)
    assert client.get("/health").status_code == 401
    assert client.get("/v1/member-release").status_code == 401
    public = create_app(database_url="sqlite:///:memory:", allow_local_trusted=True)
    client = TestClient(public)
    assert client.get("/health").status_code == 200
    result = client.get("/v1/member-release")
    assert result.status_code == 200
    assert result.json()["runtime_configured"] is False
    assert result.json()["scientific_equivalence"] is None
    assert client.get("/v1/acceptance/scientific/capability").json()["reason_code"] == "runtime_not_configured"
    runtime = client.get("/v1/execution-runtime").json()
    assert runtime["state"] == "runtime_not_configured" and runtime["runtime_configured"] is False


@pytest.mark.parametrize("corruption", ["supervisor_pin", "manifest_hash", "version", "missing_gate", "undeclared_python", "duplicate_path", "traversal"])
def test_catalogue_checks_actual_supervisor_manifest_and_archive_inventory(tmp_path, monkeypatch, corruption):
    path, descriptor, archive = approved_external_archive(tmp_path, monkeypatch)
    with zipfile.ZipFile(archive) as source:
        members = {item.filename: source.read(item) for item in source.infolist()}
    manifest = json.loads(members["runtime-manifest.json"])
    if corruption == "supervisor_pin":
        descriptor["supervisor_sha256"] = "0" * 64
    elif corruption == "manifest_hash":
        manifest["files"]["remote-agent/supervisor.py"] = "0" * 64
    elif corruption == "version":
        manifest["version"] = "2" * 24
    elif corruption == "missing_gate":
        del members["remote-agent/member_session_gate.py"]
        del manifest["files"]["remote-agent/member_session_gate.py"]
    elif corruption == "undeclared_python":
        members["remote-agent/unlisted.py"] = b"# unlisted Python"
    elif corruption == "duplicate_path":
        members["remote-agent/SUPERVISOR.py"] = members["remote-agent/supervisor.py"]
    else:
        members["remote-agent/../escape.py"] = b"# unsafe path"
    members["runtime-manifest.json"] = json.dumps(manifest).encode()
    with zipfile.ZipFile(archive, "w") as output:
        for name, raw in members.items():
            output.writestr(name, raw)
    descriptor["archive_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    path.write_text(json.dumps(descriptor), encoding="utf-8")
    # Even a matching operator ZIP hash cannot bypass the inner manifest.
    with pytest.raises(ValueError, match="runtime_archive_invalid"):
        selected_center_release()


def test_external_runtime_boots_without_inventing_scientific_successors(tmp_path, monkeypatch):
    approved_external_archive(tmp_path, monkeypatch)
    from research_compute_network.repository import MetadataRepository
    from research_compute_network.service import NetworkService
    from research_compute_network.member_runtime import approved_runtime
    service = NetworkService(MetadataRepository("sqlite:///:memory:"))
    service.initialize()
    release = service.member_release
    assert "remote-agent/operator_worker.py" in approved_runtime(release.archive_path)
    assert service.runtime_policy.accepts_worker_runtime(release.runtime_version)
    assert service.register_member_runtime_successors(actor_id="operator") == []
    assert service.repository.list_solver_approvals() == []
    assert not any(event.event_type == "member_release.runtime_equivalence_registered"
                   for event in service.repository.list_events())


def test_formal_control_plane_schedules_executes_and_collects_safe_fake_task(tmp_path, monkeypatch):
    import subprocess
    import sys
    from conftest import open_machine, register_live_machine
    from research_compute_network.models import (
        ArtifactManifest, FileRecord, JobEnvelope, ProjectGrant, ApprovalRecord, ApprovalScope,
        MachineExecutionConfig, ResourceRequest, WorkUnit)
    from research_compute_network.profiles import SAFE_FAKE_TASK_V1
    from research_compute_network.repository import MetadataRepository
    from research_compute_network.service import NetworkService
    from research_compute_network.remote_agent import fake_worker
    approved_external_archive(tmp_path, monkeypatch)
    service = NetworkService(MetadataRepository("sqlite:///:memory:"))
    service.initialize(dataset_mode="formal")
    profile = SAFE_FAKE_TASK_V1
    service.register_project(ProjectGrant(project_id="example-project", owner_user_id="example-member",
        approved=True, allowed_profiles={profile.profile_id}), actor_id="operator")
    machine, policy = open_machine("example-worker", "example-owner")
    machine.runtime_version = service.member_release.runtime_version
    register_live_machine(service, machine, policy)
    config = MachineExecutionConfig(machine_id=machine.machine_id,
        runtime_version=machine.runtime_version, enabled=True)
    service.repository.put_machine_execution_config(config)
    service.approve(ApprovalRecord(machine_id=machine.machine_id, scope=ApprovalScope.PROJECT,
        subject_id="example-project", approved_by="example-owner"), actor_id="example-owner")
    service.submit(JobEnvelope(job_id="example-fake-job", origin_submitter_id="example-origin",
        user_id="example-member", project_id="example-project", execution_profile_id=profile.profile_id,
        request_hash="a" * 64, work_units=[WorkUnit(work_unit_id="example-unit", ordinal=0,
            payload={"kind": "safe_fake_task", "acceptance_nonce": "example-nonce", "duration_seconds": 0.1},
            resources=ResourceRequest(cpus=1, memory_mb=256, disk_mb=16), expected_duration_s=1)]),
        actor_id="example-member")
    assignment = service.schedule_once()
    assert assignment is not None and assignment.machine_id == machine.machine_id
    service.mark_unit_started(assignment.job_id, assignment.work_unit_id, actor_id="fixed-fake-worker",
                              expected_attempt_id=assignment.attempt_id)
    run = tmp_path / "safe-fake-run"
    run.mkdir()
    result_path = run / "output/safe-fake-result.json"
    job_path = run / "job.json"
    job_path.write_text(json.dumps({"schema_version": 1, "profile_id": profile.profile_id,
        "acceptance_nonce": "example-nonce", "duration_seconds": 0.1, "out_manifest": str(result_path)}), encoding="utf-8")
    subprocess.run([sys.executable, str(Path(fake_worker.__file__).resolve()), "--job", str(job_path)],
                   cwd=run, check=True, capture_output=True, timeout=10)
    raw = result_path.read_bytes()
    assert json.loads(raw)["acceptance_nonce"] == "example-nonce"
    manifest = ArtifactManifest(job_id=assignment.job_id, work_unit_id=assignment.work_unit_id,
        output_schema=profile.output_schema,
        files=[FileRecord(relative_path="safe-fake-result.json", size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())],
        producer={"attempt_id": assignment.attempt_id})
    completed = service.complete_unit(assignment.job_id, assignment.work_unit_id, manifest=manifest,
        duration_s=0.1, actor_id="fixed-fake-worker", attempt_id=assignment.attempt_id)
    assert completed.work_units[0].status.value == "completed"
    assert service.repository.get_artifact_manifest(assignment.work_unit_id) == manifest
    assert len(service.repository.list_jobs()) == 1
