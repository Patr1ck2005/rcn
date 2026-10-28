"""Personal, replay-safe Agent credentials in the existing control-plane DB.

Only hashes cross this boundary. The original UUID/content binding and revoked
tombstones are durable; an uncertain PUT can be repeated without issuing again.
"""
from __future__ import annotations

from uuid import UUID
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import JSON, String, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from .auth import AuthContext
from .models import ApiTokenRecord, UserRole, utc_now
from .repository import Base, TokenRow
from .submission_policy import SubmissionPolicyError, SubmissionPolicyStore, _append_audit, _serialized_write


class AgentCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=80)
    target: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)

    @field_validator("label")
    @classmethod
    def clean_label(cls, value):
        if value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid Agent label")
        return value


class AgentCredentialRow(Base):
    __tablename__ = "personal_agent_credentials"
    agent_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    credential_id: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


def _denied(code, status=403):
    raise HTTPException(status, {"reason_code": code})


class AgentCredentialStore:
    def __init__(self, repository):
        self.repository = repository
        self.policies = SubmissionPolicyStore(repository)
        if not repository._transaction_session():
            Base.metadata.create_all(repository.engine, tables=[AgentCredentialRow.__table__])

    def _personal(self, context):
        # Recheck the real credential inside mutations, rather than trusting a
        # token that was revoked after the request dependency ran.
        token = self.repository.get_token(context.credential_id) if context.credential_id else None
        if ("api" not in context.scopes or "agent" in context.scopes or not token
                or not token.is_active() or token.user_id != context.actor_id
                or "api" not in token.scopes or "agent" in token.scopes):
            _denied("personal_login_required")
        user = self.repository.get_user(context.actor_id)
        if not user or not user.active:
            _denied("inactive_token_owner")

    def _submission_eligible(self, context):
        self._personal(context)
        user = self.repository.get_user(context.actor_id)
        if not ({UserRole.MEMBER, UserRole.ADMIN} & user.roles):
            _denied("submission_person_not_active_member")
        registered = {item.profile_id for item in self.repository.list_profiles()}
        policy = self.policies.get_policy(context.actor_id)
        if policy is not None:
            if (not policy.approved or policy.paused or policy.max_queued_units == 0
                    or policy.max_running_units == 0 or not (policy.allowed_profiles & registered)):
                _denied("agent_submission_not_eligible")
            if policy.auto_project:
                return
        for grant in self.repository.list_project_grants():
            if not grant.permits_submission(context.actor_id):
                continue
            for profile in grant.allowed_profiles & registered:
                try:
                    self.policies.authorize(context.actor_id, profile, grant.project_id)
                    return
                except SubmissionPolicyError:
                    continue
        _denied("agent_submission_not_eligible")

    @staticmethod
    def _owned(session, agent_id, owner_id):
        row = session.get(AgentCredentialRow, str(agent_id))
        if row is None or row.owner_id != owner_id:
            _denied("agent_credential_not_found", 404)
        return row

    @staticmethod
    def _present(session, row):
        token_row = session.get(TokenRow, row.credential_id)
        token = ApiTokenRecord.model_validate(token_row.payload) if token_row else None
        binding_valid = bool(token and token.user_id == row.owner_id and token.token_hash == row.token_hash
                             and token.scopes == {"api", "agent"})
        active = bool(not row.payload.get("revoked_at") and binding_valid and token.is_active())
        state = "active" if active else "revoked" if (row.payload.get("revoked_at") or not binding_valid or not token.active) else "expired"
        return {"schema_version": 1, "agent_id": row.agent_id, "owner_id": row.owner_id,
                "actor_id": row.owner_id, "credential_id": row.credential_id,
                "label": row.payload["label"], "target": row.payload["target"],
                "created_at": row.payload["created_at"], "revoked_at": row.payload.get("revoked_at"),
                "active": active, "state": state, "scopes": ["api", "agent"], "roles": ["member"]}

    def register(self, context: AuthContext, agent_id: UUID, request: AgentCredentialRequest):
        try:
            with _serialized_write(self.repository) as session:
                self._personal(context)
                row = session.get(AgentCredentialRow, str(agent_id))
                if row is not None:
                    if (row.owner_id != context.actor_id or row.token_hash != request.token_hash
                            or row.payload["label"] != request.label or row.payload["target"] != request.target):
                        _denied("agent_credential_content_conflict", 409)
                    return self._present(session, row)
                self._submission_eligible(context)
                # Never adopt another Agent's or a desktop login's hash, even
                # if the authenticated owner happens to be the same person.
                if session.scalar(select(TokenRow).where(TokenRow.token_hash == request.token_hash)):
                    _denied("agent_credential_hash_already_bound", 409)
                token = ApiTokenRecord(user_id=context.actor_id, token_hash=request.token_hash,
                                       scopes={"api", "agent"})
                session.add(TokenRow(token_id=token.token_id, user_id=token.user_id,
                    token_hash=token.token_hash, active=True, payload=token.model_dump(mode="json")))
                row = AgentCredentialRow(agent_id=str(agent_id), owner_id=context.actor_id,
                    credential_id=token.token_id, token_hash=request.token_hash,
                    payload={"label": request.label, "target": request.target,
                             "created_at": token.created_at.isoformat(), "revoked_at": None})
                session.add(row)
                session.flush()
                _append_audit(session, "personal_agent_credential.registered", context.actor_id,
                              "agent", str(agent_id), credential_id=token.token_id,
                              target=request.target, label=request.label)
                return self._present(session, row)
        except IntegrityError as exc:
            # The writer gate serializes ordinary calls. A separate concurrent
            # token issuer is still constrained by the existing UNIQUE hash.
            raise HTTPException(409, {"reason_code": "agent_credential_content_conflict"}) from exc

    def list(self, context):
        self._personal(context)
        with self.repository._session() as session:
            rows = session.scalars(select(AgentCredentialRow).where(
                AgentCredentialRow.owner_id == context.actor_id).order_by(AgentCredentialRow.agent_id))
            return {"agents": [self._present(session, row) for row in rows]}

    def get(self, context, agent_id):
        self._personal(context)
        with self.repository._session() as session:
            return self._present(session, self._owned(session, agent_id, context.actor_id))

    def revoke(self, context, agent_id):
        with _serialized_write(self.repository) as session:
            self._personal(context)
            row = self._owned(session, agent_id, context.actor_id)
            if not row.payload.get("revoked_at"):
                row.payload = {**row.payload, "revoked_at": utc_now().isoformat()}
                token = session.get(TokenRow, row.credential_id)
                if token:
                    token.active = False
                    token.payload = {**token.payload, "active": False}
                _append_audit(session, "personal_agent_credential.revoked", context.actor_id,
                              "agent", row.agent_id, credential_id=row.credential_id)
            return self._present(session, row)


def build_agent_credentials_router(*, repository, auth):
    router = APIRouter()
    credentials = AgentCredentialStore(repository)

    @router.put("/v1/me/agent-credentials/{agent_id}")
    def register(agent_id: UUID, payload: Any = Body(...), context: AuthContext = Depends(auth.actor)):
        try:
            request = AgentCredentialRequest.model_validate(payload)
        except ValidationError:
            # Never echo an accidentally pasted secret via validation inputs.
            _denied("invalid_agent_credential_request", 422)
        return credentials.register(context, agent_id, request)

    @router.get("/v1/me/agent-credentials")
    def list_credentials(context: AuthContext = Depends(auth.actor)):
        return credentials.list(context)

    @router.get("/v1/me/agent-credentials/{agent_id}")
    def get_credential(agent_id: UUID, context: AuthContext = Depends(auth.actor)):
        return credentials.get(context, agent_id)

    @router.delete("/v1/me/agent-credentials/{agent_id}")
    def revoke(agent_id: UUID, context: AuthContext = Depends(auth.actor)):
        return credentials.revoke(context, agent_id)

    return router
