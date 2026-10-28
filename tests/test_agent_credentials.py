from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from research_compute_network.api import create_app
from research_compute_network.models import (UserAccount, UserRole, PartitionRequest,
    AtomicComputeItem, ResourceRequest)
from research_compute_network.mutation_receipts import CredentialAlreadyIssued
from research_compute_network.submission_policy import SubmissionPolicyStore, PersonSubmissionPolicy
from conftest import approved_grant


def test_agent_token_is_independently_revocable_and_never_inherits_admin(tmp_path, monkeypatch):
    monkeypatch.setenv("RCN_HOME", str(tmp_path / "home"))
    app = create_app(database_url="sqlite:///" + (tmp_path / "tokens.db").as_posix(), allow_local_trusted=False)
    service = app.state.service
    service.create_user(UserAccount(user_id="owner", display_name="Owner",
        roles={UserRole.ADMIN, UserRole.MEMBER, UserRole.MACHINE_OWNER}), actor_id="local-pilot")
    desktop = service.issue_token("owner", actor_id="local-pilot")
    parent = {"Authorization": "Bearer " + desktop.token}
    client = TestClient(app)
    key = str(uuid4())
    response = client.post("/v1/users/owner/tokens", json={"agent": True},
        headers={**parent, "X-RCN-Request-ID": key})
    assert response.status_code == 200, response.text
    issued = response.json()
    agent = {"Authorization": "Bearer " + issued["token"]}
    me = client.get("/v1/me", headers=agent).json()
    assert me["actor_id"] == "owner" and me["roles"] == ["member"]
    assert set(me["scopes"]) == {"api", "agent"}
    assert me["credential_id"] == issued["token_id"]
    assert client.get("/v1/users", headers=agent).status_code == 403
    assert client.post("/v1/users/owner/tokens", json={"agent": True}, headers=agent).status_code == 403
    assert client.get("/v1/me/submission-policy", headers=agent).json() == client.get(
        "/v1/me/submission-policy", headers=parent).json()
    replay = client.post("/v1/users/owner/tokens", json={"agent": True},
        headers={**parent, "X-RCN-Request-ID": key})
    assert replay.status_code == 409 and issued["token"] not in replay.text
    assert client.delete(f'/v1/users/owner/tokens/{issued["token_id"]}', headers=parent).status_code == 200
    assert client.get("/v1/me", headers=agent).status_code == 401
    assert client.get("/v1/users", headers=parent).status_code == 200
    app.state.insights_reader.close()


def test_scope_is_frozen_in_token_request_and_concurrent_delivery_is_once(service):
    service.create_user(UserAccount(user_id="member", display_name="Member"), actor_id="local-pilot")
    key = str(uuid4())
    def issue(_):
        try:
            return service.issue_token("member", actor_id="local-pilot", request_id=key, agent=True)
        except CredentialAlreadyIssued as exc:
            return exc.receipt
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(issue, range(4)))
    assert sum(hasattr(item, "token") for item in results) == 1
    tokens = service.repository.list_tokens(user_id="member")
    assert len(tokens) == 1 and tokens[0].scopes == {"api", "agent"}
    with pytest.raises(ValueError, match="scope"):
        service.issue_token("member", actor_id="local-pilot", request_id=key, agent=False)


def test_agent_token_audit_failure_cannot_leave_an_unreceipted_active_credential(service, monkeypatch):
    service.create_user(UserAccount(user_id="member", display_name="Member"), actor_id="local-pilot")
    monkeypatch.setattr(service, "_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit failed")))
    with pytest.raises(RuntimeError, match="audit failed"):
        service.issue_token("member", actor_id="local-pilot", request_id=str(uuid4()), agent=True)
    assert service.repository.list_tokens(user_id="member") == []


def test_credential_revoke_audit_failure_rolls_back_and_repeat_is_a_noop(service, monkeypatch):
    service.create_user(UserAccount(user_id="member", display_name="Member"), actor_id="local-pilot")
    issued = service.issue_token("member", actor_id="local-pilot", agent=True)
    original = service._event
    monkeypatch.setattr(service, "_event", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit failed")))
    with pytest.raises(RuntimeError, match="audit failed"):
        service.revoke_token(issued.token_id, actor_id="local-pilot")
    assert service.repository.get_token(issued.token_id).active
    monkeypatch.setattr(service, "_event", original)
    service.revoke_token(issued.token_id, actor_id="local-pilot")
    service.revoke_token(issued.token_id, actor_id="local-pilot")
    assert len([e for e in service.repository.list_events() if e.event_type == "api_token.revoked"]) == 1


@pytest.mark.parametrize("restriction,reason", [
    ({"paused": True}, "person_submission_paused"),
    ({"allowed_profiles": set()}, "person_profile_not_allowed"),
    ({"max_queued_units": 0}, "person_queued_unit_cap"),
])
def test_admin_owned_agent_cannot_recover_admin_override_through_person_lookup(tmp_path, monkeypatch, restriction, reason):
    monkeypatch.setenv("RCN_HOME", str(tmp_path / "home"))
    app = create_app(database_url="sqlite:///" + (tmp_path / "limits.db").as_posix(), allow_local_trusted=False)
    service = app.state.service
    service.create_user(UserAccount(user_id="owner", display_name="Owner", roles={UserRole.ADMIN}), actor_id="local-pilot")
    service.repository.put_project_grant(approved_grant(project_id="existing", user_id="owner"))
    token = service.issue_token("owner", actor_id="local-pilot", agent=True)
    headers = {"Authorization": "Bearer " + token.token}
    store = SubmissionPolicyStore(service.repository)
    base = PersonSubmissionPolicy(person_id="owner", approved=True,
        allowed_profiles={"workbench-comsol-scan-v1"}, max_queued_units=20)
    store.set_policy(base, actor_id="local-pilot")
    request = PartitionRequest(origin_submitter_id="agent", user_id="owner", project_id="existing",
        execution_profile_id="workbench-comsol-scan-v1", request_hash="a" * 64,
        items=[AtomicComputeItem(item_id="one", ordinal=0, payload={"k_idx": 0})],
        requested_unit_count=1, resources=ResourceRequest(cpus=1, memory_mb=512, disk_mb=1))
    client = TestClient(app)
    plan = client.post("/v1/partition-plans", json=request.model_dump(mode="json"), headers=headers)
    assert plan.status_code == 200, plan.text
    store.set_policy(base.model_copy(update=restriction), actor_id="local-pilot")
    # Planning can remain read-only at a zero queue cap. Confirmation must
    # recheck the person's limit before admitting its first queued Unit.
    if "max_queued_units" not in restriction:
        denied = client.post("/v1/partition-plans", json=request.model_dump(mode="json"), headers=headers)
        assert denied.status_code == 400 and reason in denied.text, denied.text
    denied = client.post(f'/v1/partition-plans/{plan.json()["plan_id"]}/confirm', headers=headers)
    assert denied.status_code == 400 and reason in denied.text, denied.text
    assert service.repository.count_jobs() == 0
    app.state.insights_reader.close()
