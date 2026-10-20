from concurrent.futures import ThreadPoolExecutor
import copy
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import delete

from research_compute_network.api import create_app
from research_compute_network.models import AtomicComputeItem, FileRecord, PartitionRequest, ResourceRequest, JobStatus, WorkUnitStatus, UserAccount, UserRole, ProjectStatus
from research_compute_network.hashing import sha256_file
from research_compute_network.repository import MetadataRepository, JobRow, ProjectGrantRow
from research_compute_network.service import NetworkService, ExecutionCompatibilityError
from research_compute_network.submission_packages import build_submission_package
from research_compute_network.submission_operations import SubmissionOperationRequest, SubmissionOperationConflict, put_submission_operation, confirm_submission_operation
from conftest import approved_grant, simple_job


def package(tmp_path, *, actor="user-a", project="demo-analysis", items=2):
    root = tmp_path / "source"
    (root / "inputs").mkdir(parents=True, exist_ok=True)
    (root / "inputs/project.yaml").write_text("project_id: demo-analysis\n", encoding="utf-8")
    (root / "inputs/scan.yaml").write_text("scan: existing-scientific-spec\n", encoding="utf-8")
    (root / "inputs/template.mph").write_bytes(b"frozen-scientific-template")
    files = [FileRecord(relative_path=path.relative_to(root).as_posix(), size_bytes=path.stat().st_size, sha256=sha256_file(path)) for path in sorted((root / "inputs").iterdir())]
    request = PartitionRequest(origin_submitter_id="member-origin-a", user_id=actor, project_id=project,
        execution_profile_id="workbench-comsol-scan-v1", request_hash="a" * 64, input_manifest=files,
        requested_unit_count=1, unit_payload_kind="workbench_comsol_scan_items", resources=ResourceRequest(cpus=1, memory_mb=2048, disk_mb=200),
        items=[AtomicComputeItem(item_id=f"item-{index}", ordinal=index, payload={"scan_spec": "scan.yaml", "kind": "comsol_scan"}) for index in range(items)])
    manifest = build_submission_package(tmp_path / f"request-{actor}-{project}-{items}.zip", request, root)
    return SubmissionOperationRequest(package_manifest=manifest), root


def test_confirm_repeat_after_terminal_and_explicit_recompute(service, tmp_path):
    service.register_project(approved_grant(), actor_id="admin")
    payload, _ = package(tmp_path)
    op_id = str(uuid4())
    planned = put_submission_operation(service, op_id, payload, actor_id="user-a")
    confirmed = confirm_submission_operation(service, op_id, actor_id="user-a")
    original = service.repository.get_job(confirmed.job_id)
    original.status = JobStatus.COMPLETED
    for unit in original.work_units:
        unit.status = WorkUnitStatus.COMPLETED
    service.repository.put_job(original)
    assert confirm_submission_operation(service, op_id, actor_id="user-a").job_id == original.job_id
    assert put_submission_operation(service, op_id, payload, actor_id="user-a").job_id == original.job_id
    assert planned.source_request_hash == "a" * 64
    assert original.request_hash != planned.source_request_hash
    another = put_submission_operation(service, str(uuid4()), payload, actor_id="user-a")
    recomputed = confirm_submission_operation(service, another.operation_id, actor_id="user-a")
    assert recomputed.job_id != original.job_id
    assert len(service.repository.list_jobs()) == 2


def test_changed_payload_and_other_actor_do_not_reuse_operation(service, tmp_path):
    service.register_project(approved_grant(), actor_id="admin")
    payload, _ = package(tmp_path)
    op_id = str(uuid4())
    put_submission_operation(service, op_id, payload, actor_id="user-a")
    altered = payload.model_copy(update={"requested_unit_count": 2})
    with pytest.raises(SubmissionOperationConflict):
        put_submission_operation(service, op_id, altered, actor_id="user-a")
    with pytest.raises(PermissionError):
        confirm_submission_operation(service, op_id, actor_id="user-b")
    assert service.repository.list_jobs() == []


def test_atomic_job_and_operation_crash_roll_back(service, tmp_path, monkeypatch):
    service.register_project(approved_grant(), actor_id="admin")
    payload, _ = package(tmp_path)
    op_id = str(uuid4())
    put_submission_operation(service, op_id, payload, actor_id="user-a")
    original = MetadataRepository.put_submission_operation
    def fail_receipt(repository, operation):
        if operation.job_id:
            raise RuntimeError("simulated failure after Job insert before receipt commit")
        return original(repository, operation)
    monkeypatch.setattr(MetadataRepository, "put_submission_operation", fail_receipt)
    with pytest.raises(RuntimeError, match="simulated"):
        confirm_submission_operation(service, op_id, actor_id="user-a")
    assert service.repository.list_jobs() == []
    receipt = service.repository.get_submission_operation(op_id)
    assert receipt.job_id is None
    assert service.repository.get_partition_plan(receipt.plan.plan_id).status == "draft"
    assert not any(event.event_type == "job.submitted" for event in service.repository.list_events())
    monkeypatch.setattr(MetadataRepository, "put_submission_operation", original)
    recovered = confirm_submission_operation(service, op_id, actor_id="user-a")
    assert recovered.job_id is not None
    assert len(service.repository.list_jobs()) == 1


def test_concurrent_confirm_across_repositories_has_one_job(service, tmp_path):
    service.register_project(approved_grant(), actor_id="admin")
    payload, _ = package(tmp_path)
    op_id = str(uuid4())
    put_submission_operation(service, op_id, payload, actor_id="user-a")
    database_url = str(service.repository.engine.url)
    services = [NetworkService(MetadataRepository(database_url)) for _ in range(4)]
    def confirm(index):
        return confirm_submission_operation(services[index % 4], op_id, actor_id="user-a").job_id
    with ThreadPoolExecutor(max_workers=8) as executor:
        receipts = list(executor.map(confirm, range(16)))
    assert len(set(receipts)) == 1
    assert len(service.repository.list_jobs()) == 1
    assert sum(event.event_type == "submission_operation.confirmed" for event in service.repository.list_events()) == 1


@pytest.mark.parametrize("changed", ["user_id", "project_id", "origin_submitter_id", "origin_adapter_id", "execution_profile_id"])
def test_legacy_hash_reuse_checks_member_project_origin(service, changed):
    service.register_project(approved_grant(), actor_id="admin")
    original = service.submit(simple_job(), actor_id="user-a")
    request = simple_job()
    setattr(request, changed, "other-identity")
    with pytest.raises(ExecutionCompatibilityError, match="different member"):
        service.submit(request, actor_id="other-identity")
    assert service.repository.get_job(original.job_id).user_id == "user-a"


def test_api_unknown_response_recovery_and_actor_permissions(tmp_path):
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'api.db').as_posix()}", allow_local_trusted=False)
    service = app.state.service
    service.register_project(approved_grant(), actor_id="admin")
    for actor in ("user-a", "user-b"):
        service.repository.put_user(UserAccount(user_id=actor, display_name=actor, roles={UserRole.MEMBER}))
    tokens = {actor: service.issue_token(actor, actor_id="admin").token for actor in ("user-a", "user-b")}
    headers = {actor: {"Authorization": f"Bearer {token}"} for actor, token in tokens.items()}
    client = TestClient(app)
    payload, _ = package(tmp_path)
    op_id = str(uuid4())
    assert client.get("/v1/execution-runtime", headers=headers["user-a"]).json()["submission_operation_schema"] == 1
    assert client.put(f"/v1/submission-operations/{op_id}", json=payload.model_dump(mode="json"), headers=headers["user-b"]).status_code == 403
    response = client.put(f"/v1/submission-operations/{op_id}", json=payload.model_dump(mode="json"), headers=headers["user-a"])
    assert response.status_code == 200, response.text
    confirmed = client.post(f"/v1/submission-operations/{op_id}/confirm", headers=headers["user-a"])
    assert confirmed.status_code == 200, confirmed.text
    # Ignore the first response, as if its body were lost, and recover via GET.
    recovered = client.get(f"/v1/submission-operations/{op_id}", headers=headers["user-a"]).json()
    assert recovered["job_id"] == confirmed.json()["job_id"]
    assert recovered["package_contents_sha256"] == payload.package_manifest.package_contents_sha256
    assert client.post(f"/v1/submission-operations/{op_id}/confirm", headers=headers["user-a"]).json()["job_id"] == recovered["job_id"]
    assert client.get(f"/v1/submission-operations/{op_id}", headers=headers["user-b"]).status_code == 403
    assert client.post(f"/v1/submission-operations/{op_id}/confirm", headers=headers["user-b"]).status_code == 403
    altered = payload.model_dump(mode="json")
    altered["requested_unit_count"] = 2
    assert client.put(f"/v1/submission-operations/{op_id}", json=altered, headers=headers["user-a"]).status_code == 409


@pytest.mark.parametrize("restriction", ["member_revoked", "project_frozen", "profile_revoked", "grant_missing"])
def test_api_original_receipt_recovery_survives_grant_changes_without_new_execution(tmp_path, restriction):
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'recovery.db').as_posix()}", allow_local_trusted=False)
    service = app.state.service
    service.register_project(approved_grant(), actor_id="admin")
    headers = {}
    for actor in ("user-a", "user-b", "other-admin"):
        roles = {UserRole.MEMBER, UserRole.ADMIN} if actor == "other-admin" else {UserRole.MEMBER}
        service.repository.put_user(UserAccount(user_id=actor, display_name=actor, roles=roles))
        headers[actor] = {"Authorization": f"Bearer {service.issue_token(actor, actor_id='admin').token}"}
    client = TestClient(app)
    payload, _ = package(tmp_path)
    body = payload.model_dump(mode="json")
    op_id, pending_id = str(uuid4()), str(uuid4())
    for identity in (op_id, pending_id):
        response = client.put(f"/v1/submission-operations/{identity}", json=body, headers=headers["user-a"])
        assert response.status_code == 200, response.text
    confirmed = client.post(f"/v1/submission-operations/{op_id}/confirm", headers=headers["user-a"])
    assert confirmed.status_code == 200, confirmed.text
    receipt = confirmed.json()
    original = service.repository.get_job(receipt["job_id"])
    original.status = JobStatus.COMPLETED
    for unit in original.work_units:
        unit.status = WorkUnitStatus.COMPLETED
    service.repository.put_job(original)

    grant = service.repository.get_project_grant(original.project_id)
    if restriction == "member_revoked":
        grant.owner_user_id = "user-b"
        grant.authorized_user_ids.clear()
    elif restriction == "project_frozen":
        grant.status = ProjectStatus.FROZEN
    elif restriction == "profile_revoked":
        grant.allowed_profiles.clear()
    else:
        # This branch exercises optional legacy project restrictions. In the
        # default personal mode, deleting project metadata alone is not a
        # revocation of the person's right to create another own project.
        from research_compute_network.submission_policy import SubmissionPolicyStore
        policies = SubmissionPolicyStore(service.repository)
        policy = policies.get_policy("user-a")
        if policy is not None:
            policies.set_policy(policy.model_copy(update={"auto_project": False}), actor_id="local-pilot")
        with service.repository.engine.begin() as connection:
            connection.execute(delete(ProjectGrantRow).where(ProjectGrantRow.project_id == grant.project_id))
        grant = None
    if grant is not None:
        service.repository.put_project_grant(grant)

    # These are receipt recovery only: even an ended Job is never recreated.
    for response in (
        client.get(f"/v1/submission-operations/{op_id}", headers=headers["user-a"]),
        client.put(f"/v1/submission-operations/{op_id}", json=body, headers=headers["user-a"]),
        client.post(f"/v1/submission-operations/{op_id}/confirm", headers=headers["user-a"]),
    ):
        assert response.status_code == 200, response.text
        assert response.json() == receipt
    assert client.put(f"/v1/submission-operations/{pending_id}", json=body, headers=headers["user-a"]).status_code == 200
    assert client.get(f"/v1/submission-operations/{pending_id}", headers=headers["user-a"]).status_code == 200
    assert client.post(f"/v1/submission-operations/{pending_id}/confirm", headers=headers["user-a"]).status_code == 403
    new_id = str(uuid4())
    assert client.put(f"/v1/submission-operations/{new_id}", json=body, headers=headers["user-a"]).status_code == 403
    assert service.repository.get_submission_operation(new_id) is None
    altered = dict(body, requested_unit_count=2)
    assert client.put(f"/v1/submission-operations/{op_id}", json=altered, headers=headers["user-a"]).status_code == 409
    for actor in ("user-b", "other-admin"):
        assert client.get(f"/v1/submission-operations/{op_id}", headers=headers[actor]).status_code == 403
        assert client.put(f"/v1/submission-operations/{op_id}", json=body, headers=headers[actor]).status_code == 403
        assert client.post(f"/v1/submission-operations/{op_id}/confirm", headers=headers[actor]).status_code == 403
    assert len(service.repository.list_jobs()) == 1
    assert len(service.repository.list_partition_plans()) == 2
    events = service.repository.list_events()
    assert sum(event.event_type == "submission_operation.planned" for event in events) == 2
    assert sum(event.event_type == "submission_operation.confirmed" for event in events) == 1


def test_missing_original_job_is_a_conflict_even_after_project_freeze(service, tmp_path):
    service.register_project(approved_grant(), actor_id="admin")
    payload, _ = package(tmp_path)
    op_id = str(uuid4())
    put_submission_operation(service, op_id, payload, actor_id="user-a")
    confirmed = confirm_submission_operation(service, op_id, actor_id="user-a")
    grant = service.repository.get_project_grant(confirmed.project_id)
    grant.status = ProjectStatus.FROZEN
    service.repository.put_project_grant(grant)
    with service.repository.engine.begin() as connection:
        connection.execute(delete(JobRow).where(JobRow.job_id == confirmed.job_id))
    with pytest.raises(SubmissionOperationConflict, match="durable Job receipt is missing"):
        confirm_submission_operation(service, op_id, actor_id="user-a")
    assert service.repository.list_jobs() == []
    assert service.repository.get_submission_operation(op_id).job_id == confirmed.job_id
