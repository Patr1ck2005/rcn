import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest

from research_compute_network import member_pairing as module
from research_compute_network.auth import AuthContext, PilotAuthenticator
from research_compute_network.member_pairing import (
    MemberPairingStore, PairingApproval, PairingRequest, PairingRow, build_member_pairing_router,
)
from research_compute_network.models import ApiTokenRecord, ExecutionProfile, UserAccount, UserRole, utc_now
from research_compute_network.repository import MetadataRepository
from research_compute_network.submission_policy import SubmissionPolicyStore

SECRET = "synthetic-high-entropy-pairing-secret"


def digest(value=SECRET):
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def pairings(tmp_path):
    repo = MetadataRepository("sqlite:///" + (tmp_path / "pairings.db").as_posix())
    repo.init_schema()
    for identifier, roles in [("admin", {UserRole.ADMIN}), ("alice", {UserRole.MEMBER}), ("bob", {UserRole.MEMBER})]:
        repo.put_user(UserAccount(user_id=identifier, display_name="Same name", roles=roles))
        repo.put_token(ApiTokenRecord(token_id=identifier + "-login", user_id=identifier, token_hash=digest(identifier)))
    repo.put_profile(ExecutionProfile(profile_id="cpu", version="1", executor_kind="fake", output_schema="fake"))
    auth = PilotAuthenticator(repo, allow_local_trusted=False)
    app = FastAPI()
    app.include_router(build_member_pairing_router(repository=repo, auth=auth))

    @app.get("/v1/me")
    def me(context: AuthContext = Depends(auth.actor)):
        return {"actor_id": context.actor_id, "roles": sorted(context.roles), "scopes": sorted(context.scopes),
                "credential_id": context.credential_id}

    return SimpleNamespace(repo=repo, app=app, client=TestClient(app), store=MemberPairingStore(repo),
        admin={"Authorization": "Bearer admin"}, member={"Authorization": "Bearer " + SECRET}, key=str(uuid4()))


def request(**changes):
    return {"name": "Same name", "device_name": "My PC", "token_hash": digest(), **changes}


def apply(f, **changes):
    return f.client.put("/v1/member-pairings/" + f.key, json=request(**changes))


def approve(f, body=None):
    return f.client.post("/v1/admin/member-pairings/" + f.key + "/approve",
        json=body or {"create_new": True}, headers=f.admin)


def status(f, headers=None):
    return f.client.get("/v1/member-pairings/" + f.key, headers=headers or f.member)


def test_request_replay_approval_and_current_actor_are_one_credential(pairings):
    f = pairings
    first = apply(f)
    assert first.status_code == 200, first.text
    assert apply(f).json() == first.json()
    assert first.json()["state"] == "pending"
    assert f.client.get("/v1/member-pairings/" + f.key).status_code == 401
    assert status(f, {"Authorization": "Bearer " + first.json()["short_code"]}).status_code == 401
    assert f.client.get("/v1/admin/member-pairings", headers={"Authorization": "Bearer alice"}).status_code == 403
    result = approve(f)
    assert result.status_code == 200, result.text
    approved = result.json()
    assert approved["member_id"] not in {"alice", "bob"}  # no name-based merge
    assert approved == approve(f).json()
    assert status(f).json()["state"] == "approved"
    me = f.client.get("/v1/me", headers=f.member).json()
    assert me["actor_id"] == approved["member_id"] and me["scopes"] == ["api"]
    tokens = f.repo.list_tokens(user_id=approved["member_id"])
    assert len(tokens) == 1 and tokens[0].expires_at is None
    policy = SubmissionPolicyStore(f.repo).get_policy(approved["member_id"])
    assert policy.approved and policy.allowed_profiles == {"cpu"} and policy.auto_project
    for output in [first.text, result.text, status(f).text, str([e.model_dump() for e in f.repo.list_events()])]:
        assert SECRET not in output and digest() not in output


def test_existing_member_explicit_binding_preserves_existing_policy(pairings):
    f = pairings
    apply(f)
    assert approve(f, {"member_id": "alice"}).json()["member_id"] == "alice"
    assert len(f.repo.list_users()) == 3
    assert approve(f, {"member_id": "bob"}).status_code == 409
    assert f.client.get("/v1/me", headers={"Authorization": "Bearer alice"}).status_code == 200


def test_content_and_hash_conflicts_cannot_issue_or_rebind(pairings):
    f = pairings
    apply(f)
    assert apply(f, token_hash=digest("other")).status_code == 409
    assert apply(f, name="changed").status_code == 409
    assert f.client.put("/v1/member-pairings/" + str(uuid4()), json=request()).status_code == 409
    assert f.client.put("/v1/member-pairings/" + str(uuid4()), json=request(token_hash=digest("alice"))).status_code == 409
    bad = f.client.put("/v1/member-pairings/" + str(uuid4()), json=request(token_hash=SECRET))
    assert bad.status_code == 422 and SECRET not in bad.text


@pytest.mark.parametrize("terminal", ["reject", "expired", "revoke", "external_revoke"])
def test_terminal_requests_survive_restart_and_never_reactivate(pairings, terminal):
    f = pairings
    apply(f)
    if terminal in {"revoke", "external_revoke"}:
        receipt = approve(f).json()
        if terminal == "revoke":
            assert f.client.post("/v1/admin/member-pairings/" + f.key + "/revoke", headers=f.admin).status_code == 200
        else:
            token = f.repo.get_token(receipt["credential_id"])
            f.repo.put_token(token.model_copy(update={"active": False}))
    elif terminal == "reject":
        f.client.post("/v1/admin/member-pairings/" + f.key + "/reject", headers=f.admin)
    else:
        with f.repo.atomic_write(), f.repo._session() as session:
            row = session.get(PairingRow, f.key)
            row.payload = {**row.payload, "expires_at": (utc_now() - timedelta(seconds=1)).isoformat()}
    store = MemberPairingStore(MetadataRepository(str(f.repo.engine.url)))
    observed = store.get(UUID(f.key), "Bearer " + SECRET)
    assert observed["state"] == {"reject": "rejected", "revoke": "revoked", "external_revoke": "revoked"}.get(terminal, terminal)
    replay = apply(f)
    assert replay.status_code == 200
    result = approve(f)
    assert result.status_code == 409 or result.json()["state"] == "revoked"
    assert status(f).json()["state"] == observed["state"]


def test_concurrent_approval_issues_once_and_audit_failure_rolls_back(pairings, monkeypatch):
    f = pairings
    apply(f)
    context = AuthContext("admin", frozenset({UserRole.ADMIN}), frozenset({"api"}), "admin-login")
    original = module._append_audit
    monkeypatch.setattr(module, "_append_audit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit failed")))
    with pytest.raises(RuntimeError, match="audit failed"):
        f.store.decide(UUID(f.key), context, PairingApproval(create_new=True))
    assert len(f.repo.list_users()) == 3
    assert status(f).json()["state"] == "pending"
    monkeypatch.setattr(module, "_append_audit", original)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: f.store.decide(UUID(f.key), context, PairingApproval(create_new=True)), range(4)))
    assert len({result["credential_id"] for result in results}) == 1
    assert len([event for event in f.repo.list_events() if event.event_type == "member_pairing.approve"]) == 1


def test_bad_read_rate_limit_does_not_block_the_legitimate_pairing(pairings):
    f = pairings
    apply(f)
    for _ in range(30):
        assert status(f, {"Authorization": "Bearer wrong"}).status_code == 401
    assert status(f, {"Authorization": "Bearer wrong"}).status_code == 429
    assert status(f).status_code == 200
    assert apply(f).status_code == 200
    assert f.client.get("/v1/member-pairings/group").json()["poll_interval_seconds"] == 5
