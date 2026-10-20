import hashlib

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from research_compute_network.auth import PilotAuthenticator
from research_compute_network.models import (
    ApiTokenRecord, ExecutionProfile, JobEnvelope, JobStatus, ProjectGrant, ProjectStatus,
    UserAccount, UserRole, WorkUnit, WorkUnitStatus,
)
from research_compute_network.personal_access_api import build_personal_access_router
from research_compute_network.repository import MetadataRepository
from research_compute_network.submission_policy import PersonSubmissionPolicy, SubmissionPolicyError, SubmissionPolicyStore


@pytest.fixture
def access(tmp_path):
    repo = MetadataRepository("sqlite:///" + (tmp_path / "access.db").as_posix())
    repo.init_schema()
    for person, roles in [("admin", {UserRole.ADMIN}), ("alice", {UserRole.MEMBER}),
                          ("bob", {UserRole.MEMBER}), ("owner", {UserRole.MACHINE_OWNER})]:
        repo.put_user(UserAccount(user_id=person, display_name=person, roles=roles))
    for profile in ("cpu", "gpu"):
        repo.put_profile(ExecutionProfile(profile_id=profile, version="1", executor_kind="fake", output_schema="fake"))
    store = SubmissionPolicyStore(repo)
    return repo, store


def approve(store, **updates):
    return store.set_policy(PersonSubmissionPolicy(person_id="alice", approved=True,
        allowed_profiles={"cpu", "gpu"}, priority_ceiling=100, **updates), actor_id="admin")


def test_missing_policy_retains_existing_grants_and_does_not_open_projects(access):
    repo, store = access
    grant = ProjectGrant(project_id="legacy", owner_user_id="alice", approved=True, allowed_profiles={"cpu"})
    repo.put_project_grant(grant)
    assert store.authorize("alice", "cpu", "legacy") == grant
    assert store.effective_project_grant("alice", "new") is None
    assert store.effective_policy("alice")["source"] == "legacy_project_grants"


def test_approved_person_registers_project_without_grant_review(access):
    repo, store = access
    approve(store)
    grant = store.auto_register_project("alice", "new-project", profile_id="cpu")
    assert grant.status == ProjectStatus.ACTIVE and grant.owner_user_id == "alice"
    assert store.authorize("alice", "cpu", "new-project", priority=100).approved
    assert store.auto_register_project("alice", "new-project") == grant
    assert len([e for e in repo.list_events() if e.event_type == "project.auto_registered"]) == 1
    assert repo.list_approvals() == []


def test_policy_cannot_create_roles_or_be_set_by_member(access):
    repo, store = access
    with pytest.raises(SubmissionPolicyError, match="admin_required"):
        store.set_policy(PersonSubmissionPolicy(person_id="alice"), actor_id="alice")
    with pytest.raises(SubmissionPolicyError, match="not_active_member"):
        store.set_policy(PersonSubmissionPolicy(person_id="owner", approved=True), actor_id="admin")
    assert repo.get_user("owner").roles == {UserRole.MACHINE_OWNER}


@pytest.mark.parametrize("change, reason", [({"approved": False}, "not_approved"), ({"paused": True}, "paused")])
def test_person_restriction_blocks_even_existing_project(access, change, reason):
    repo, store = access
    repo.put_project_grant(ProjectGrant(project_id="legacy", owner_user_id="alice", approved=True, allowed_profiles={"cpu"}))
    store.set_policy(PersonSubmissionPolicy(person_id="alice", allowed_profiles={"cpu"}, approved=True)
                     .model_copy(update=change), actor_id="admin")
    with pytest.raises(SubmissionPolicyError, match=reason):
        store.authorize("alice", "cpu", "legacy")


def test_person_policy_does_not_unfreeze_or_expand_explicit_project(access):
    repo, store = access
    approve(store)
    grant = ProjectGrant(project_id="restricted", owner_user_id="alice", allowed_profiles={"cpu"},
                         status=ProjectStatus.FROZEN, frozen_reason="operator", priority_ceiling=0)
    repo.put_project_grant(grant)
    with pytest.raises(SubmissionPolicyError, match="project_submission_not_allowed"):
        store.authorize("alice", "cpu", "restricted")
    grant.status, grant.approved = ProjectStatus.ACTIVE, True
    repo.put_project_grant(grant)
    with pytest.raises(SubmissionPolicyError, match="project_profile_not_allowed"):
        store.authorize("alice", "gpu", "restricted")
    with pytest.raises(SubmissionPolicyError, match="project_priority_ceiling"):
        store.authorize("alice", "cpu", "restricted", priority=1)
    assert store.authorize("alice", "cpu", "restricted", priority=0).priority_ceiling == 0


def test_auto_project_cannot_claim_another_persons_project(access):
    repo, store = access
    approve(store)
    repo.put_project_grant(ProjectGrant(project_id="bobs", owner_user_id="bob", approved=True, allowed_profiles={"cpu"}))
    with pytest.raises(SubmissionPolicyError, match="project_submission_not_allowed"):
        store.auto_register_project("alice", "bobs")
    assert repo.get_project_grant("bobs").owner_user_id == "bob"


def test_aggregate_caps_span_projects_and_exclude_other_people(access):
    repo, store = access
    approve(store, max_queued_units=2, max_running_units=1)
    for project, person, statuses in [("a", "alice", [WorkUnitStatus.QUEUED]),
                                      ("b", "alice", [WorkUnitStatus.QUEUED, WorkUnitStatus.RUNNING]),
                                      ("c", "bob", [WorkUnitStatus.RUNNING, WorkUnitStatus.QUEUED])]:
        repo.put_job(JobEnvelope(job_id=project, origin_submitter_id="origin", user_id=person, project_id=project,
            execution_profile_id="cpu", request_hash=hashlib.sha256(project.encode()).hexdigest(),
            status=JobStatus.RUNNING if WorkUnitStatus.RUNNING in statuses else JobStatus.QUEUED,
            work_units=[WorkUnit(ordinal=i, payload={}, status=s) for i, s in enumerate(statuses)]))
    assert store.aggregate_usage("alice") == {"queued_units": 2, "running_units": 1, "prepared_units": 0}
    with pytest.raises(SubmissionPolicyError, match="queued_unit_cap"):
        store.authorize("alice", "cpu", "new", queued_units=1)
    with pytest.raises(SubmissionPolicyError, match="running_unit_cap"):
        store.check_running_capacity("alice")
    store.authorize("alice", "cpu", "new", queued_units=1, exclude_job_id="a")
    store.check_running_capacity("alice", additional_units=0)


def test_zero_caps_are_denials_and_unlimited_does_not_disable_concurrency(access):
    _, store = access
    approve(store, max_queued_units=0, max_running_units=0, quota_mode="unlimited")
    with pytest.raises(SubmissionPolicyError, match="queued_unit_cap"):
        store.authorize("alice", "cpu", "new", queued_units=1)
    with pytest.raises(SubmissionPolicyError, match="running_unit_cap"):
        store.check_running_capacity("alice")


def test_person_profile_and_priority_ceiling(access):
    _, store = access
    store.set_policy(PersonSubmissionPolicy(person_id="alice", approved=True, allowed_profiles={"cpu"},
                                            priority_ceiling=5), actor_id="admin")
    with pytest.raises(SubmissionPolicyError, match="person_profile_not_allowed"):
        store.authorize("alice", "gpu", "new")
    with pytest.raises(SubmissionPolicyError, match="person_priority_ceiling_exceeded"):
        store.authorize("alice", "cpu", "new", priority=6)


def test_api_uses_person_identity_for_multiple_tokens_and_denies_escalation(access):
    repo, store = access
    approve(store)
    for token_id, user_id in [("person", "alice"), ("agent", "alice"), ("admin-token", "admin")]:
        repo.put_token(ApiTokenRecord(token_id=token_id, user_id=user_id,
            token_hash=hashlib.sha256(token_id.encode()).hexdigest()))
    app = FastAPI()
    app.include_router(build_personal_access_router(repository=repo,
        auth=PilotAuthenticator(repo, allow_local_trusted=False), policies=store))
    client = TestClient(app)
    for token in ["person", "agent"]:
        response = client.get("/v1/me/submission-policy", headers={"Authorization": "Bearer " + token})
        assert response.status_code == 200 and response.json()["person_id"] == "alice"
    body = PersonSubmissionPolicy(person_id="alice", approved=True).model_dump(mode="json")
    assert client.put("/v1/admin/people/alice/submission-policy", json=body,
        headers={"Authorization": "Bearer person"}).status_code == 403
    body["roles"] = ["admin"]
    assert client.put("/v1/admin/people/alice/submission-policy", json=body,
        headers={"Authorization": "Bearer admin-token"}).status_code == 422
    assert repo.get_user("alice").roles == {UserRole.MEMBER}


def test_policy_audit_rolls_back_with_policy_write(access, monkeypatch):
    repo, store = access
    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr("research_compute_network.submission_policy._append_audit", fail)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        approve(store)
    assert store.get_policy("alice") is None


def test_policy_and_project_join_outer_transaction_without_early_commit(access):
    repo, store = access
    with pytest.raises(RuntimeError):
        with repo.atomic_write():
            approve(store)
            store.auto_register_project("alice", "rolled-back")
            raise RuntimeError("submission rejected")
    assert store.get_policy("alice") is None
    assert repo.get_project_grant("rolled-back") is None


def test_inherited_project_follows_policy_updates_but_explicit_freeze_stays(access):
    repo, store = access
    store.set_policy(PersonSubmissionPolicy(person_id="alice", approved=True, allowed_profiles={"cpu"}), actor_id="admin")
    original = store.auto_register_project("alice", "inherited")
    assert original.person_policy_inherited
    approve(store, max_running_units=8)
    effective = store.authorize("alice", "gpu", "inherited", priority=100)
    assert effective.max_running_units == 8
    repo.put_project_grant(original.model_copy(update={"status": ProjectStatus.FROZEN, "approved": False,
                                                      "frozen_reason": "operator decision"}))
    with pytest.raises(SubmissionPolicyError, match="project_submission_not_allowed"):
        store.authorize("alice", "gpu", "inherited")


def test_collaborator_policy_cannot_expand_inherited_owner_scope(access):
    repo, store = access
    store.set_policy(PersonSubmissionPolicy(person_id="alice", approved=True, allowed_profiles={"cpu"}), actor_id="admin")
    grant = store.auto_register_project("alice", "shared")
    repo.put_project_grant(grant.model_copy(update={"authorized_user_ids": {"bob"}}))
    store.set_policy(PersonSubmissionPolicy(person_id="bob", approved=True, allowed_profiles={"cpu", "gpu"},
                                            priority_ceiling=100), actor_id="admin")
    with pytest.raises(SubmissionPolicyError, match="project_profile_not_allowed"):
        store.authorize("bob", "gpu", "shared")
    approve(store, max_running_units=8)
    assert store.authorize("bob", "gpu", "shared").allowed_profiles == {"cpu", "gpu"}
