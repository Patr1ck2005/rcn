import json
import errno
import stat
import subprocess
import os
import sys
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from research_compute_network.hashing import sha256_file, sha256_value
from research_compute_network.origin import OriginSpool
from research_compute_network.runtime_policy import STABLE_RUNTIME_VERSION
from research_compute_network.submission_packages import (
    MANIFEST_NAME, SubmissionPackageManifest, build_submission_package,
    inspect_submission_package, extract_submission_package, prepare_submission_bundles,
)
from research_compute_network.submission_operations import put_submission_operation, confirm_submission_operation
from test_member_submission_operations import package
from conftest import approved_grant


def rewrite_package(source, target, change):
    with zipfile.ZipFile(source) as archive:
        members = {info.filename: archive.read(info) for info in archive.infolist()}
    change(members)
    with zipfile.ZipFile(target, "w") as archive:
        for name, value in members.items():
            archive.writestr(name, value)


def rehash_manifest(payload):
    request = payload["request"]
    payload["request_sha256"] = sha256_value(request)
    from research_compute_network.models import PartitionRequest
    from research_compute_network.submission_packages import science_contract
    payload["science_contract_sha256"] = sha256_value(science_contract(PartitionRequest.model_validate(request)))
    payload["input_manifest_sha256"] = sha256_value(payload["files"])
    payload["package_contents_sha256"] = sha256_value({key: value for key, value in payload.items() if key != "package_contents_sha256"})
    return payload


def test_deterministic_data_only_package_and_extract_resume(tmp_path):
    payload, root = package(tmp_path)
    first = tmp_path / "request-user-a-demo-analysis-2.zip"
    second = tmp_path / "same.zip"
    manifest = build_submission_package(second, payload.package_manifest.request, root)
    assert sha256_file(first) == sha256_file(second)
    assert manifest.package_contents_sha256 == payload.package_manifest.package_contents_sha256
    extracted = tmp_path / "member-data"
    extract_submission_package(first, extracted, expected_actor_id="user-a")
    extract_submission_package(first, extracted, expected_actor_id="user-a")
    for record in manifest.files:
        assert sha256_file(extracted / record.relative_path) == record.sha256
    assert sorted(path.name for path in extracted.iterdir()) == ["inputs"]
    (extracted / "inputs/scan.yaml").write_text("changed", encoding="utf-8")
    with pytest.raises(FileExistsError):
        extract_submission_package(first, extracted)
    with pytest.raises(PermissionError):
        inspect_submission_package(first, expected_actor_id="other-member")


def test_package_identity_survives_fresh_process_hash_seeds(tmp_path):
    payload, root = package(tmp_path)
    request = payload.package_manifest.request.model_copy(deep=True)
    request.required_capabilities = {"comsol-6.4", "python-mph", "solver-mumps"}
    target = tmp_path / "multi-capability.zip"
    manifest = build_submission_package(target, request, root)
    # pytest's pythonpath applies only to the test interpreter. Resolve the
    # actual imported package so the child also tests this source/installation,
    # even when a different editable checkout is registered in the environment.
    import research_compute_network.submission_packages as imported_package
    imported_source = str(Path(imported_package.__file__).resolve().parent.parent)
    for seed in ("1", "42", "987"):
        result = subprocess.run([sys.executable, "-c", "import sys;from research_compute_network.submission_packages import inspect_submission_package;print(inspect_submission_package(sys.argv[1]).package_contents_sha256)", str(target)],
            env={**os.environ, "PYTHONPATH": imported_source, "PYTHONHASHSEED": seed}, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == manifest.package_contents_sha256


@pytest.mark.skipif(os.name != "nt", reason="Windows no-overwrite rename semantics")
def test_public_package_can_publish_without_ntfs_links(tmp_path, monkeypatch):
    payload, root = package(tmp_path)
    def unavailable_link(*args, **kwargs):
        raise OSError(errno.ENOTSUP, "selected USB filesystem does not support hardlinks")
    monkeypatch.setattr(os, "link", unavailable_link)
    target = tmp_path / "usb-request.zip"
    built = build_submission_package(target, payload.package_manifest.request, root)
    extracted = tmp_path / "usb-data"
    assert extract_submission_package(target, extracted).package_contents_sha256 == built.package_contents_sha256
    assert sha256_file(extracted / "inputs/template.mph") == next(record.sha256 for record in built.files if record.relative_path.endswith(".mph"))


@pytest.mark.parametrize("tamper", ["bytes", "undeclared", "traversal", "case_collision", "request", "contract"])
def test_package_tampering_is_rejected(tmp_path, tamper):
    package(tmp_path)
    source = tmp_path / "request-user-a-demo-analysis-2.zip"
    target = tmp_path / "bad.zip"
    def change(members):
        if tamper == "bytes":
            members["inputs/template.mph"] = b"tampered"
        elif tamper == "undeclared":
            members["inputs/extra.txt"] = b"extra"
        elif tamper == "traversal":
            members["../escape.txt"] = b"escape"
        elif tamper == "case_collision":
            members["INPUTS/template.mph"] = members["inputs/template.mph"]
        else:
            manifest = json.loads(members[MANIFEST_NAME])
            if tamper == "request":
                manifest["request"]["items"][0]["payload"]["kind"] = "changed-science"
            else:
                manifest["science_contract_sha256"] = "0" * 64
            members[MANIFEST_NAME] = json.dumps(manifest).encode()
    rewrite_package(source, target, change)
    with pytest.raises(ValueError):
        inspect_submission_package(target)


def test_zip_symlink_is_rejected(tmp_path):
    package(tmp_path)
    source = tmp_path / "request-user-a-demo-analysis-2.zip"
    target = tmp_path / "link.zip"
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(target, "w") as archive:
        for old_info in old.infolist():
            info = zipfile.ZipInfo(old_info.filename)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16 if info.filename.endswith("template.mph") else (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, old.read(old_info))
    with pytest.raises(ValueError, match="linked"):
        inspect_submission_package(target)


@pytest.mark.parametrize("content", [b"MZexecutabledisguised", b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\nsynthetic-not-a-key"])
def test_disguised_executable_or_private_key_is_rejected(tmp_path, content):
    payload, root = package(tmp_path)
    path = root / "inputs/template.mph"
    path.write_bytes(content)
    request = payload.package_manifest.request.model_copy(deep=True)
    record = next(record for record in request.input_manifest if record.relative_path.endswith(".mph"))
    record.size_bytes = len(content)
    record.sha256 = sha256_file(path)
    with pytest.raises(ValueError):
        build_submission_package(tmp_path / "bad.zip", request, root)


def test_secret_field_and_non_comsol_profile_are_rejected(tmp_path):
    payload, _ = package(tmp_path)
    manifest = payload.package_manifest.model_dump(mode="json")
    manifest["request"]["items"][0]["payload"]["password"] = "fixture-not-a-real-secret"
    with pytest.raises(ValueError, match="credential"):
        SubmissionPackageManifest.model_validate(rehash_manifest(manifest))
    manifest = payload.package_manifest.model_dump(mode="json")
    manifest["request"]["execution_profile_id"] = "project-worker-v1"
    with pytest.raises(ValueError, match="fixed COMSOL"):
        SubmissionPackageManifest.model_validate(rehash_manifest(manifest))


def test_confirmed_package_seals_into_existing_origin_protocol(service, tmp_path):
    service.register_project(approved_grant(), actor_id="admin")
    payload, _ = package(tmp_path)
    operation = put_submission_operation(service, str(uuid4()), payload, actor_id="user-a")
    with pytest.raises(ValueError, match="confirmed"):
        prepare_submission_bundles(tmp_path / "request-user-a-demo-analysis-2.zip", operation, tmp_path / "spool", STABLE_RUNTIME_VERSION)
    operation = confirm_submission_operation(service, operation.operation_id, actor_id="user-a")
    paths = prepare_submission_bundles(tmp_path / "request-user-a-demo-analysis-2.zip", operation, tmp_path / "spool", STABLE_RUNTIME_VERSION)
    job = service.repository.get_job(operation.job_id)
    spool = OriginSpool(tmp_path / "spool")
    descriptor = spool.validate(job, job.work_units[0])
    assert descriptor.runtime_version == STABLE_RUNTIME_VERSION
    assert descriptor.job_request_hash == operation.job_request_hash
    assert descriptor.profile_id == payload.package_manifest.request.execution_profile_id
    assert {record.sha256 for record in descriptor.files} == {record.sha256 for record in payload.package_manifest.files}
    assert prepare_submission_bundles(tmp_path / "request-user-a-demo-analysis-2.zip", operation, tmp_path / "spool", STABLE_RUNTIME_VERSION) == paths


def test_private_frequency_profile_cannot_be_enabled_by_solver_approval(service):
    from research_compute_network.models import SolverCompatibilityApproval
    service.register_project(approved_grant(), actor_id="admin")
    approval = SolverCompatibilityApproval(project_id="demo-analysis",
        execution_profile_id="workbench-comsol-frequency-v1", comsol_version="6.4",
        template_sha256="a" * 64, approved_by="operator")
    with pytest.raises(KeyError, match="execution profile not found"):
        service.approve_solver(approval, actor_id="operator")
    assert service.repository.get_solver_approval(approval.approval_id) is None


def test_generic_study_package_materializes_without_workbench_or_user_code(service, tmp_path):
    from research_compute_network.models import (
        Assignment, MachineExecutionConfig, ProjectGrant, SolverCompatibilityApproval,
        SolverMeshPolicy, ComsolStudyKind, TemplateParameterEvidence)
    from runtime_fixture import TEST_RUNTIME_VERSION
    payload, root = package(tmp_path)
    request = payload.package_manifest.request.model_copy(deep=True)
    request.execution_profile_id = "workbench-comsol-study-v1"
    request.unit_payload_kind = "workbench_comsol_recipe_items"
    request.recipe_kind = "comsol_study"
    request.study_kind = ComsolStudyKind.STATIONARY
    request.template_role = "example-template"
    request.output_contract_sha256 = "5" * 64
    request.template_sha256 = next(record.sha256 for record in request.input_manifest if record.relative_path.endswith(".mph"))
    request.source_spec_sha256 = next(record.sha256 for record in request.input_manifest if record.relative_path.endswith("scan.yaml"))
    request.template_parameter_evidence = TemplateParameterEvidence(template_sha256=request.template_sha256,
        inspection_sha256="4" * 64, global_parameter_names=["input"])
    mesh = {"mode": "auto_size", "mesh_tag": "mesh1", "size": "normal"}
    for index, item in enumerate(request.items):
        item.setup_fingerprint = "a" * 64
        item.coordinates = {"step": index}
        item.payload = {"kind": "workbench_comsol_study_point", "project_id": request.project_id,
            "template_role": request.template_role, "template_sha256": request.template_sha256,
            "scan_spec_sha256": request.source_spec_sha256, "template_inspection_sha256": "4" * 64,
            "output_contract_sha256": request.output_contract_sha256,
            "study": {"tag": "std1", "kind": "stationary", "mesh_policy": mesh},
            "parameters": {"input": index}, "setup_parameters": {"input": index}, "sweep_parameters": {},
            "output_request": {"schema_version": 1, "expressions": [{"name": "value", "expression": "T"}],
                               "fields": [], "semantic_outputs": []}}
    target = tmp_path / "study-package.zip"
    manifest = build_submission_package(target, request, root)
    service.register_project(ProjectGrant(project_id=request.project_id, owner_user_id="user-a", approved=True,
        allowed_profiles={request.execution_profile_id}), actor_id="operator")
    service.approve_solver(SolverCompatibilityApproval(project_id=request.project_id, execution_profile_id=request.execution_profile_id,
        comsol_version="6.4", template_sha256=request.template_sha256, runtime_version=TEST_RUNTIME_VERSION,
        template_role=request.template_role, allowed_study_kinds={ComsolStudyKind.STATIONARY},
        mesh_policy=SolverMeshPolicy(**mesh), approved_by="operator"), actor_id="operator")
    from research_compute_network.submission_operations import SubmissionOperationRequest
    operation = put_submission_operation(service, str(uuid4()), SubmissionOperationRequest(package_manifest=manifest), actor_id="user-a")
    operation = confirm_submission_operation(service, operation.operation_id, actor_id="user-a")
    prepare_submission_bundles(target, operation, tmp_path / "spool", TEST_RUNTIME_VERSION)
    job = service.repository.get_job(operation.job_id)
    unit = job.work_units[0]
    assert [item["payload"] for item in unit.payload["items"]] == [item.payload for item in request.items]
    spool = OriginSpool(tmp_path / "spool")
    assignment = Assignment(job_id=job.job_id, work_unit_id=unit.work_unit_id, machine_id="worker", scheduler="ssh", attempt_id="attempt")
    bundle = spool.materialize_execution_bundle(job=job, assignment=assignment, external_run_id="ssh-worker-attempt",
        config=MachineExecutionConfig(machine_id="worker"), runtime_version=TEST_RUNTIME_VERSION,
        output_zip=tmp_path / "sealed-worker.zip", cache_uploader=lambda path, digest: None)
    with zipfile.ZipFile(bundle) as archive:
        sealed = json.loads(archive.read("input/job.json"))
        assert sealed["recipe_kind"] == request.recipe_kind
        assert [item["payload"] for item in sealed["items"]] == [item.payload for item in request.items]
        assert "entrypoint" not in sealed and "command" not in sealed


def test_missing_partition_choice_does_not_invent_duration(service, tmp_path):
    service.register_project(approved_grant(), actor_id="admin")
    payload, root = package(tmp_path)
    request = payload.package_manifest.request.model_copy(deep=True)
    request.requested_unit_count = None
    manifest = build_submission_package(tmp_path / "unpartitioned.zip", request, root)
    from research_compute_network.submission_operations import SubmissionOperationRequest
    from research_compute_network.partitioning import PartitionConfirmationRequired
    operation_id = str(uuid4())
    payload = SubmissionOperationRequest(package_manifest=manifest)
    with pytest.raises(PartitionConfirmationRequired):
        put_submission_operation(service, operation_id, payload, actor_id="user-a")
    assert service.repository.get_submission_operation(operation_id) is None
    payload.requested_unit_count = 2
    operation = put_submission_operation(service, operation_id, payload, actor_id="user-a")
    assert len(operation.plan.work_units) == 2
