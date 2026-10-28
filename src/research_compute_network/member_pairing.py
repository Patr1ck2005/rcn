"""Online person admission. Only credential digests are stored or returned."""
from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timedelta
import hashlib
import os
import secrets
import threading
import time
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import JSON, String, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from .auth import AuthContext, require_role
from .models import ApiTokenRecord, UserAccount, UserRole, utc_now
from .repository import Base, TokenRow, UserRow
from .submission_policy import (PersonSubmissionPolicy, PersonSubmissionPolicyRow,
    SubmissionPolicyStore, _append_audit, _serialized_write)


def denied(code, status=409):
    raise HTTPException(status, {"reason_code": code})


class PairingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    device_name: str = Field(min_length=1, max_length=80)
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)

    @field_validator("name", "device_name")
    @classmethod
    def clean(cls, value):
        if value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid pairing label")
        return value


class PairingApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    create_new: bool = Field(default=False, strict=True)
    member_id: str | None = Field(default=None, min_length=1, max_length=160)

    @model_validator(mode="after")
    def explicit_choice(self):
        if self.create_new == (self.member_id is not None):
            raise ValueError("choose a new member or an explicit existing member")
        return self


class PairingRow(Base):
    __tablename__ = "member_pairings"
    pairing_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


class _AdmissionLimiter:
    """Bounded per-source buckets; successful authenticated reads cost nothing."""
    def __init__(self):
        self.lock = threading.Lock()
        self.buckets = OrderedDict()

    def check(self, source, kind, limit):
        now = time.monotonic()
        with self.lock:
            key = (source, kind)
            bucket = self.buckets.pop(key, deque())
            while bucket and now - bucket[0] >= 60:
                bucket.popleft()
            self.buckets[key] = bucket
            while len(self.buckets) > 4096:
                self.buckets.popitem(last=False)
            if len(bucket) >= limit:
                raise HTTPException(429, {"reason_code": "member_pairing_rate_limited"}, headers={"Retry-After": "60"})
            bucket.append(now)


class MemberPairingStore:
    def __init__(self, repository):
        self.repository = repository
        self.policies = SubmissionPolicyStore(repository)
        self.limiter = _AdmissionLimiter()
        Base.metadata.create_all(repository.engine, tables=[PairingRow.__table__])

    @staticmethod
    def _expire(row):
        if row.payload["state"] == "pending" and datetime.fromisoformat(row.payload["expires_at"]) <= utc_now():
            row.payload = {**row.payload, "state": "expired"}

    def _present(self, session, row, *, admin=False):
        value = dict(row.payload)
        if value["state"] == "approved":
            token_row = session.get(TokenRow, value["credential_id"])
            user_row = session.get(UserRow, value["member_id"])
            token = ApiTokenRecord.model_validate(token_row.payload) if token_row else None
            if (not token or not token.is_active() or token.user_id != value["member_id"]
                    or token.token_hash != row.token_hash or token.scopes != {"api"}
                    or not user_row or not user_row.active):
                value["state"] = "revoked"
        result = {"schema_version": 1, "pairing_id": row.pairing_id,
            **{key: value.get(key) for key in ("name", "device_name", "short_code", "state",
                "created_at", "expires_at", "member_id", "credential_id", "approved_at")}}
        if admin:
            result["approval"] = value.get("approval")
        return result

    def register(self, pairing_id, request, *, source="unknown"):
        try:
            with _serialized_write(self.repository) as session:
                row = session.get(PairingRow, str(pairing_id))
                if row:
                    if (row.token_hash != request.token_hash or row.payload["name"] != request.name
                            or row.payload["device_name"] != request.device_name):
                        self.limiter.check(source, "conflict", 20)
                        denied("member_pairing_content_conflict")
                    self._expire(row)
                    # A PUT does not authenticate ownership. Return only the
                    # original public application receipt; GET needs the secret.
                    return {key: value for key, value in self._present(session, row).items()
                            if key not in {"member_id", "credential_id", "approved_at"}}
                self.limiter.check(source, "create", 10)
                if (session.scalar(select(PairingRow).where(PairingRow.token_hash == request.token_hash))
                        or session.scalar(select(TokenRow).where(TokenRow.token_hash == request.token_hash))):
                    denied("member_pairing_hash_already_bound")
                now = utc_now()
                row = PairingRow(pairing_id=str(pairing_id), token_hash=request.token_hash,
                    payload={"name": request.name, "device_name": request.device_name,
                        "short_code": secrets.token_hex(3).upper(), "state": "pending",
                        "created_at": now.isoformat(), "expires_at": (now + timedelta(hours=24)).isoformat()})
                session.add(row)
                session.flush()
                _append_audit(session, "member_pairing.requested", "anonymous", "member_pairing", row.pairing_id)
                return {key: value for key, value in self._present(session, row).items()
                        if key not in {"member_id", "credential_id", "approved_at"}}
        except IntegrityError as exc:
            raise HTTPException(409, {"reason_code": "member_pairing_content_conflict"}) from exc

    def get(self, pairing_id, authorization, *, source="unknown"):
        supplied = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
        digest = hashlib.sha256(supplied.encode()).hexdigest()
        # Failed probes must not acquire SQLite's write gate or consume a
        # bucket belonging to the actual member/pairing.
        with self.repository._session() as session:
            row = session.get(PairingRow, str(pairing_id))
            if not row or not supplied or not secrets.compare_digest(digest, row.token_hash):
                self.limiter.check(source, "unauthorized", 30)
                denied("member_pairing_authentication_required", 401)
        with _serialized_write(self.repository) as session:
            row = session.scalar(select(PairingRow).where(PairingRow.pairing_id == str(pairing_id)).with_for_update())
            self._expire(row)
            return self._present(session, row)

    def list(self):
        with _serialized_write(self.repository) as session:
            rows = list(session.scalars(select(PairingRow)))
            for row in rows:
                self._expire(row)
            return {"pairings": [self._present(session, row, admin=True) for row in rows]}

    def decide(self, pairing_id, context, approval=None, *, action="approve"):
        with _serialized_write(self.repository) as session:
            # Recheck authoritative admin state within the admission transaction.
            require_role(context, UserRole.ADMIN)
            user = self.repository.get_user(context.actor_id)
            if context.actor_id != "local-pilot" and (not user or not user.active or UserRole.ADMIN not in user.roles):
                denied("admin_required", 403)
            if context.credential_id:
                token = self.repository.get_token(context.credential_id)
                if (not token or not token.is_active() or token.user_id != context.actor_id
                        or "api" not in token.scopes or "agent" in token.scopes):
                    denied("admin_required", 403)
            row = session.scalar(select(PairingRow).where(PairingRow.pairing_id == str(pairing_id)).with_for_update())
            if not row:
                denied("member_pairing_not_found", 404)
            self._expire(row)
            current = self._present(session, row, admin=True)
            if action == "approve":
                choice = approval.model_dump()
                if row.payload["state"] == "approved":
                    if row.payload.get("approval") != choice:
                        denied("member_pairing_approval_conflict")
                    return current
                if row.payload["state"] != "pending":
                    denied("member_pairing_terminal")
                if approval.create_new:
                    # Deliberately no display-name lookup or automatic merge.
                    member = UserAccount(user_id="member-" + uuid4().hex, display_name=row.payload["name"])
                    session.add(UserRow(user_id=member.user_id, active=True, payload=member.model_dump(mode="json")))
                else:
                    member = self.repository.get_user(approval.member_id)
                    if not member or not member.active or UserRole.MEMBER not in member.roles:
                        denied("member_pairing_existing_member_invalid")
                if session.get(PersonSubmissionPolicyRow, member.user_id) is None:
                    policy = PersonSubmissionPolicy(person_id=member.user_id, approved=True,
                        allowed_profiles={p.profile_id for p in self.repository.list_profiles()})
                    session.add(PersonSubmissionPolicyRow(person_id=member.user_id, payload=policy.model_dump(mode="json")))
                if session.scalar(select(TokenRow).where(TokenRow.token_hash == row.token_hash)):
                    denied("member_pairing_hash_already_bound")
                token = ApiTokenRecord(user_id=member.user_id, token_hash=row.token_hash, scopes={"api"})
                session.add(TokenRow(token_id=token.token_id, user_id=member.user_id, token_hash=token.token_hash,
                    active=True, payload=token.model_dump(mode="json")))
                row.payload = {**row.payload, "state": "approved", "member_id": member.user_id,
                    "credential_id": token.token_id, "approved_at": utc_now().isoformat(), "approval": choice}
            elif action == "reject":
                if row.payload["state"] == "rejected":
                    return current
                if row.payload["state"] != "pending":
                    denied("member_pairing_terminal")
                row.payload = {**row.payload, "state": "rejected"}
            else:
                if row.payload["state"] == "revoked":
                    return current
                if row.payload["state"] != "approved":
                    denied("member_pairing_terminal")
                token = session.get(TokenRow, row.payload["credential_id"])
                if token:
                    token.active = False
                    token.payload = {**token.payload, "active": False}
                row.payload = {**row.payload, "state": "revoked"}
            session.flush()
            _append_audit(session, "member_pairing." + action, context.actor_id, "member_pairing", row.pairing_id,
                member_id=row.payload.get("member_id"))
            return self._present(session, row, admin=True)


def build_member_pairing_router(*, repository, auth, state_root=None):
    router = APIRouter()
    store = MemberPairingStore(repository)

    @router.get("/v1/member-pairings/group")
    @router.get("/v1/member-pairing-info")
    def group():
        settings = {}
        if state_root is not None:
            from .public_member_ingress import member_ingress_settings
            settings = member_ingress_settings(state_root)
        return {"schema_version": 1, "group_name": settings.get("group_name") or os.environ.get("RCN_GROUP_NAME", "Research Compute Network"),
            "public_url": settings.get("public_url"),
            "online_member_pairing": True, "pending_lifetime_seconds": 86400, "poll_interval_seconds": 5}

    @router.put("/v1/member-pairings/{pairing_id}")
    def register(pairing_id: UUID, request: Request, payload: Any = Body(...)):
        try:
            value = PairingRequest.model_validate(payload)
        except ValidationError:
            denied("invalid_member_pairing_request", 422)
        return store.register(pairing_id, value, source=request.client.host if request.client else "unknown")

    @router.get("/v1/member-pairings/{pairing_id}")
    def status(pairing_id: UUID, request: Request, authorization: str | None = Header(default=None)):
        return store.get(pairing_id, authorization, source=request.client.host if request.client else "unknown")

    @router.get("/v1/admin/member-pairings")
    def listing(context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return store.list()

    @router.post("/v1/admin/member-pairings/{pairing_id}/approve")
    def approve(pairing_id: UUID, payload: Any = Body(...), context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        try:
            value = PairingApproval.model_validate(payload)
        except ValidationError:
            denied("invalid_member_pairing_approval", 422)
        return store.decide(pairing_id, context, value)

    @router.post("/v1/admin/member-pairings/{pairing_id}/reject")
    def reject(pairing_id: UUID, context: AuthContext = Depends(auth.actor)):
        return store.decide(pairing_id, context, action="reject")

    @router.post("/v1/admin/member-pairings/{pairing_id}/revoke")
    def revoke(pairing_id: UUID, context: AuthContext = Depends(auth.actor)):
        return store.decide(pairing_id, context, action="revoke")

    return router
