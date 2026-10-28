import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
import pytest

from research_compute_network.agent_credentials import (
    AgentCredentialRequest, AgentCredentialStore, build_agent_credentials_router,
)
from research_compute_network.auth import AuthContext, PilotAuthenticator
from research_compute_network.models import (
    ApiTokenRecord, ExecutionProfile, ProjectGrant, UserAccount, UserRole, utc_now,
)
from research_compute_network.repository import MetadataRepository
from research_compute_network.submission_policy import PersonSubmissionPolicy, SubmissionPolicyStore

AGENT = "11111111-2222-4333-8444-555555555555"
OTHER = "11111111-2222-4333-8444-666666666666"


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def credentials(tmp_path):
    repo = MetadataRepository("sqlite:///" + (tmp_path / "agents.db").as_posix())
    repo.init_schema()
    for person, roles in [("alice", {UserRole.MEMBER}), ("bob", {UserRole.MEMBER}),
                          ("owner", {UserRole.MACHINE_OWNER}), ("admin", {UserRole.ADMIN})]:
        repo.put_user(UserAccount(user_id=person, display_name=person, roles=roles))
        repo.put_token(ApiTokenRecord(token_id=person + "-desktop", user_id=person,
                                      token_hash=digest(person + "-login")))
    repo.put_profile(ExecutionProfile(profile_id="cpu", version="1", executor_kind="fake", output_schema="fake"))
    policies = SubmissionPolicyStore(repo)
    for person in ("alice", "bob"):
        policies.set_policy(PersonSubmissionPolicy(person_id=person, approved=True, allowed_profiles={"cpu"}),
                            actor_id="admin")
    auth = PilotAuthenticator(repo, allow_local_trusted=False)
    app = FastAPI()
    app.include_router(build_agent_credentials_router(repository=repo, auth=auth))

    @app.get("/v1/me")
    def me(context: AuthContext = Depends(auth.actor)):
        return {"actor_id": context.actor_id, "roles": sorted(context.roles),
                "scopes": sorted(context.scopes), "credential_id": context.credential_id}

    return SimpleNamespace(repo=repo, policies=policies, app=app, client=TestClient(app),
                           store=AgentCredentialStore(repo), auth=auth)


def headers(person="alice"):
    return {"Authorization": "Bearer " + person + "-login"}


def payload(secret="generated-agent-credential", **changes):
    return {"label": "My research Agent", "target": "generic", "token_hash": digest(secret), **changes}


def put(f, agent=AGENT, body=None, person="alice"):
    return f.client.put("/v1/me/agent-credentials/" + agent, json=body or payload(), headers=headers(person))


def test_register_replay_is_one_existing_hashed_token_and_audit(credentials):
    f = credentials
    first = put(f)
    assert first.status_code == 200, first.text
    result = first.json()
    assert result["state"] == "active" and result["owner_id"] == "alice"
    assert "generated-agent-credential" not in first.text and "token_hash" not in first.text
    assert result == put(f).json()
    token = f.repo.get_token(result["credential_id"])
    assert token.token_hash == payload()["token_hash"] and token.scopes == {"api", "agent"}
    assert len(f.repo.list_tokens("alice")) == 2
    audits = [e for e in f.repo.list_events() if e.event_type == "personal_agent_credential.registered"]
    assert len(audits) == 1 and "token_hash" not in str(audits)
    assert f.client.get("/v1/me", headers={"Authorization": "Bearer generated-agent-credential"}).json() == {
        "actor_id": "alice", "roles": ["member"], "scopes": ["agent", "api"],
        "credential_id": token.token_id}
    # The original binding survives an independently opened repository.
    reopened = MetadataRepository(str(f.repo.engine.url))
    assert AgentCredentialStore(reopened).get(f.auth.actor("Bearer alice-login"), UUID(AGENT)) == result


@pytest.mark.parametrize("change", [{"label": "changed"}, {"target": "codex"}, {"token_hash": "f" * 64}])
def test_changed_payload_conflicts_without_second_token(credentials, change):
    assert put(credentials).status_code == 200
    assert put(credentials, body=payload(**change)).status_code == 409
    assert len(credentials.repo.list_tokens("alice")) == 2


@pytest.mark.parametrize("field,value", [("owner_id", "bob"), ("roles", ["admin"]), ("scopes", ["api"])])
def test_request_cannot_choose_identity_or_permissions(credentials, field, value):
    assert put(credentials, body=payload(**{field: value})).status_code == 422
    assert len(credentials.repo.list_tokens("alice")) == 1


def test_validation_never_echoes_accidentally_pasted_secret(credentials):
    for body in [payload(token="secret-pasted-by-mistake"), payload(token_hash="secret-pasted-by-mistake"),
                 "secret-pasted-by-mistake"]:
        result = put(credentials, body=body)
        assert result.status_code == 422 and "secret-pasted-by-mistake" not in result.text


def test_no_self_promotion_or_role_only_eligibility(credentials):
    f = credentials
    assert put(f, person="owner").status_code == 403
    assert f.repo.get_user("owner").roles == {UserRole.MACHINE_OWNER}
    assert put(f, person="admin").status_code == 403
    f.policies.set_policy(PersonSubmissionPolicy(person_id="alice", approved=False), actor_id="admin")
    assert put(f).status_code == 403
    f.policies.set_policy(PersonSubmissionPolicy(person_id="alice", approved=True, allowed_profiles={"cpu"},
                                                max_queued_units=0), actor_id="admin")
    assert put(f).status_code == 403


def test_existing_legacy_submission_grant_is_eligible(credentials):
    f = credentials
    f.repo.put_project_grant(ProjectGrant(project_id="old", owner_user_id="admin", approved=True,
                                         allowed_profiles={"cpu"}))
    assert put(f, person="admin").status_code == 200


def test_agent_credential_cannot_manage_or_create_agents(credentials):
    f = credentials
    put(f)
    auth = {"Authorization": "Bearer generated-agent-credential"}
    base = "/v1/me/agent-credentials"
    for method, route in [("GET", base), ("GET", base + "/" + AGENT),
                          ("DELETE", base + "/" + AGENT), ("PUT", base + "/" + OTHER)]:
        assert f.client.request(method, route, headers=auth,
                                json=payload("second") if method == "PUT" else None).status_code == 403


def test_owner_scoping_and_duplicate_hash_never_adopts_another_credential(credentials):
    f = credentials
    assert put(f).status_code == 200
    assert put(f, person="bob").status_code == 409
    for method in ("get", "delete"):
        assert getattr(f.client, method)("/v1/me/agent-credentials/" + AGENT, headers=headers("bob")).status_code == 404
    assert f.client.get("/v1/me/agent-credentials", headers=headers("bob")).json() == {"agents": []}
    assert put(f, OTHER).status_code == 409
    assert put(f, OTHER, person="bob").status_code == 409
    assert put(f, OTHER, body=payload("alice-login")).status_code == 409
    assert len(f.repo.list_tokens("alice")) == 2 and len(f.repo.list_tokens("bob")) == 1


def test_revoke_tombstone_replay_and_expiration_return_current_state(credentials):
    f = credentials
    first = put(f).json()
    # Administrative revocation must be observed by a repeated original PUT.
    token = f.repo.get_token(first["credential_id"])
    token.active = False
    f.repo.put_token(token)
    assert put(f).json()["state"] == "revoked"
    revoked = f.client.delete("/v1/me/agent-credentials/" + AGENT, headers=headers()).json()
    assert revoked["state"] == "revoked" and revoked["credential_id"] == first["credential_id"]
    assert revoked == f.client.delete("/v1/me/agent-credentials/" + AGENT, headers=headers()).json()
    assert revoked == put(f).json()
    assert f.client.get("/v1/me", headers={"Authorization": "Bearer generated-agent-credential"}).status_code == 401
    # Losing submission approval does not hide management/reconciliation.
    f.policies.set_policy(PersonSubmissionPolicy(person_id="alice", approved=False), actor_id="admin")
    assert put(f).json() == revoked
    assert put(f, OTHER, body=payload("new")).status_code == 403
    assert f.client.get("/v1/me", headers=headers()).status_code == 200


def test_expired_original_token_is_not_reissued(credentials):
    f = credentials
    original = put(f).json()
    token = f.repo.get_token(original["credential_id"])
    token.expires_at = utc_now() - timedelta(seconds=1)
    f.repo.put_token(token)
    current = put(f).json()
    assert current["state"] == "expired" and current["active"] is False
    assert current["credential_id"] == original["credential_id"]


def test_concurrent_duplicate_puts_and_hash_collision_are_atomic(credentials):
    f = credentials
    context = f.auth.actor("Bearer alice-login")
    def register(agent):
        try:
            return f.store.register(context, UUID(agent), AgentCredentialRequest(**payload()))
        except Exception as exc:
            return exc
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(register, [AGENT] * 6))
    assert all(isinstance(result, dict) and result == results[0] for result in results)
    # A second UUID cannot grab that winning hash, including concurrent calls.
    with ThreadPoolExecutor(max_workers=2) as pool:
        losers = list(pool.map(register, [OTHER] * 2))
    assert all(getattr(result, "status_code", None) == 409 for result in losers)
    assert len(f.repo.list_tokens("alice")) == 2


def test_audit_failure_rolls_back_token_and_uuid_binding(credentials, monkeypatch):
    f = credentials
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic audit unavailable")
    monkeypatch.setattr("research_compute_network.agent_credentials._append_audit", fail)
    with pytest.raises(RuntimeError):
        put(f)
    assert len(f.repo.list_tokens("alice")) == 1
    assert f.client.get("/v1/me/agent-credentials", headers=headers()).json() == {"agents": []}
