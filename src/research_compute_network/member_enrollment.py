"""Resumable member registration, separate from Worker acceptance and protocol.

Clients persist a random machine credential BEFORE exchange. The center stores
only hashes and atomically consumes the invite, creates a paused node/policy,
binds that credential and appends audit evidence. A lost response is retried with
the exact same request; no recovery endpoint returns or rotates a secret.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import re
import secrets
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError

from .models import (AuditEvent, EnrollmentRecord, MachineAgentCredential, MachineMetrics,
                     MachineMode, MachinePolicy, MachineState, UserAccount, UserRole, new_id)
from .repository import (EnrollmentRow, EventRow, EventSequenceRow, MachineCredentialRow,
                         MachineRow, MetadataRepository, PolicyRow, TokenRow, UserRow)

MODE = "resumable-v1"
EXCHANGE_PATH = "/v1/member-enrollment/exchange"
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$"


def https_origin(value: str) -> str:
    """Only an explicit HTTPS origin; no token URL, proxy path or loopback gateway."""
    if not isinstance(value, str) or len(value) > 512 or any(c.isspace() for c in value):
        raise ValueError("an HTTPS origin is required")
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path not in {"", "/"} or url.query or url.fragment or "\\" in value):
        raise ValueError("an HTTPS origin without credentials or path is required")
    host = url.hostname.lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", host) or host.rstrip(".").endswith("localhost"):
            raise ValueError("invalid enrollment hostname")
    else:
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError("an independent enrollment endpoint is required")
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError("invalid enrollment port")
    authority = f"[{host}]" if ":" in host else host
    return "https://" + authority + (f":{url.port}" if url.port and url.port != 443 else "")


def secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def invite_hash(value: str) -> str:
    # Legacy /v1/node/enroll hashes the raw code, and therefore cannot redeem a
    # new invitation even when a control-plane rollback hides these new routes.
    return secret_hash("rcn-member-invite-v2\0" + value)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class DeviceFacts(StrictModel):
    hostname: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    total_cpus: int = Field(ge=1, le=4096, strict=True)
    total_memory_mb: int = Field(ge=256, le=1073741824, strict=True)
    package_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+!-]{0,99}$")
    protocol_version: Literal["1"] = "1"


class MemberInvitationRequest(StrictModel):
    owner_user_id: str = Field(pattern=ID_PATTERN)
    control_plane_url: str
    worker: bool = Field(default=False, strict=True)
    ttl_minutes: int = Field(default=60, ge=1, le=1440, strict=True)
    _url = field_validator("control_plane_url")(https_origin)


class MemberInvitation(StrictModel):
    schema_version: Literal[2] = 2
    enrollment_id: str = Field(pattern=ID_PATTERN)
    machine_id: str = Field(pattern=ID_PATTERN)
    owner_user_id: str = Field(pattern=ID_PATTERN)
    control_plane_url: str
    worker: bool = Field(strict=True)
    enrollment_code: SecretStr
    expires_at: datetime
    _url = field_validator("control_plane_url")(https_origin)

    @field_validator("enrollment_code")
    @classmethod
    def valid_code(cls, value: SecretStr) -> SecretStr:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value.get_secret_value()):
            raise ValueError("invalid invitation credential")
        return value

    @field_validator("expires_at")
    @classmethod
    def aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expiry must include a timezone")
        return value

    def private_document(self) -> dict:
        # Call only for authorized HTTPS delivery / protected local storage.
        return {**self.model_dump(mode="json"), "enrollment_code": self.enrollment_code.get_secret_value()}


class MemberExchangeRequest(StrictModel):
    schema_version: Literal[1] = 1
    enrollment_id: str = Field(pattern=ID_PATTERN)
    enrollment_code: SecretStr
    device_credential: SecretStr
    facts: DeviceFacts

    @field_validator("enrollment_code", "device_credential")
    @classmethod
    def valid_secret(cls, value: SecretStr) -> SecretStr:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value.get_secret_value()):
            raise ValueError("invalid registration credential")
        return value

    def request_hash(self) -> str:
        payload = self.model_dump(mode="json", exclude={"enrollment_code", "device_credential"})
        payload["device_credential_sha256"] = secret_hash(self.device_credential.get_secret_value())
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def private_document(self) -> dict:
        return {**self.model_dump(mode="json"),
                "enrollment_code": self.enrollment_code.get_secret_value(),
                "device_credential": self.device_credential.get_secret_value()}


class MemberRegistrationReceipt(StrictModel):
    schema_version: Literal[1] = 1
    enrollment_id: str = Field(pattern=ID_PATTERN)
    machine_id: str = Field(pattern=ID_PATTERN)
    owner_user_id: str = Field(pattern=ID_PATTERN)
    credential_id: str = Field(pattern=ID_PATTERN)
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    registered_at: datetime
    registration_state: Literal["registered"] = "registered"
    # A registration receipt is never a current health/capacity/approval claim.
    grants_execution: Literal[False] = False
    next_step: Literal["machine_acceptance"] = "machine_acceptance"


class EnrollmentUnavailable(ValueError):
    """Public error is intentionally independent of which identity check failed."""

    def __init__(self):
        super().__init__("invitation or device binding unavailable")


class MemberEnrollmentService:
    def __init__(self, repository: MetadataRepository):
        self.repository = repository

    def _lock(self, session, enrollment_id: str) -> None:
        if self.repository.engine.dialect.name == "sqlite":
            if self.repository._transaction_session() is None:
                session.execute(text("BEGIN IMMEDIATE"))
        else:
            session.execute(select(EnrollmentRow.enrollment_id).where(
                EnrollmentRow.enrollment_id == enrollment_id).with_for_update())

    @staticmethod
    def _audit(session, event_type: str, actor: str, subject: str, **details) -> None:
        event = AuditEvent(event_type=event_type, actor_id=actor, subject_type="enrollment",
                           subject_id=subject, details=details)
        sequence = session.execute(update(EventSequenceRow).where(EventSequenceRow.sequence_id == "global")
            .values(next_sequence=EventSequenceRow.next_sequence + 1)
            .returning(EventSequenceRow.next_sequence)).scalar_one()
        event.sequence = sequence - 1
        session.add(EventRow(event_id=event.event_id, event_type=event.event_type,
            subject_type=event.subject_type, subject_id=event.subject_id, created_at=event.created_at,
            sequence=event.sequence, payload=event.model_dump(mode="json")))

    @staticmethod
    def _user(session, user_id: str) -> UserAccount:
        row = session.scalar(select(UserRow).where(UserRow.user_id == user_id).with_for_update())
        if row is None or not row.active:
            raise EnrollmentUnavailable()
        user = UserAccount.model_validate(row.payload)
        if not user.active:
            raise EnrollmentUnavailable()
        return user

    def issue(self, request: MemberInvitationRequest, *, actor_id: str) -> MemberInvitation:
        secret = secrets.token_urlsafe(32)
        record = EnrollmentRecord(registration_mode=MODE, code_hash=invite_hash(secret),
            owner_user_id=request.owner_user_id, issued_by=actor_id,
            invited_machine_id=new_id("MEMBER"), registration_url=request.control_plane_url,
            requested_capabilities={"submitter", *({"worker"} if request.worker else set())},
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=request.ttl_minutes))
        def write():
            with self.repository._session() as session, session.begin():
                self._lock(session, record.enrollment_id)
                if UserRole.ADMIN not in self._user(session, actor_id).roles:
                    raise EnrollmentUnavailable()
                owner = self._user(session, request.owner_user_id)
                if request.worker and UserRole.MACHINE_OWNER not in owner.roles:
                    raise EnrollmentUnavailable()
                session.add(EnrollmentRow(enrollment_id=record.enrollment_id, code_hash=record.code_hash,
                    owner_user_id=record.owner_user_id, expires_at=record.expires_at, used=False,
                    payload=record.model_dump(mode="json")))
                self._audit(session, "member.invitation_issued", actor_id, record.enrollment_id,
                    machine_id=record.invited_machine_id, owner_user_id=record.owner_user_id,
                    worker=request.worker, expires_at=record.expires_at.isoformat())
        self.repository._retry_sqlite_write(write)
        return MemberInvitation(enrollment_id=record.enrollment_id, machine_id=record.invited_machine_id,
            owner_user_id=record.owner_user_id, control_plane_url=record.registration_url,
            enrollment_code=secret, expires_at=record.expires_at, worker=request.worker)

    def revoke(self, enrollment_id: str, *, actor_id: str) -> dict:
        def write():
            with self.repository._session() as session, session.begin():
                self._lock(session, enrollment_id)
                row = session.get(EnrollmentRow, enrollment_id)
                if row is None or UserRole.ADMIN not in self._user(session, actor_id).roles:
                    raise EnrollmentUnavailable()
                record = EnrollmentRecord.model_validate(row.payload)
                if record.registration_mode != MODE:
                    raise EnrollmentUnavailable()
                if record.revoked_at is None:
                    record.revoked_at = datetime.now(timezone.utc)
                    row.payload = record.model_dump(mode="json")
                    self._audit(session, "member.invitation_revoked", actor_id, enrollment_id,
                                registered=record.used_at is not None)
                return {"enrollment_id": enrollment_id, "revoked": True,
                        "existing_machine_revoked": False}
        # Revoke blocks redemption/recovery; a registered device uses the existing
        # dedicated machine-credential revocation control, not implicit job killing.
        return self.repository._retry_sqlite_write(write)

    @staticmethod
    def _receipt(record: EnrollmentRecord) -> MemberRegistrationReceipt:
        return MemberRegistrationReceipt(enrollment_id=record.enrollment_id, machine_id=record.machine_id,
            owner_user_id=record.owner_user_id, credential_id=record.exchange_credential_id,
            request_sha256=record.exchange_request_sha256, registered_at=record.used_at)

    def exchange(self, request: MemberExchangeRequest) -> MemberRegistrationReceipt:
        digest = request.request_hash()
        token_hash = secret_hash(request.device_credential.get_secret_value())
        code_hash = invite_hash(request.enrollment_code.get_secret_value())
        def write():
            with self.repository._session() as session, session.begin():
                self._lock(session, request.enrollment_id)
                now = datetime.now(timezone.utc)
                row = session.get(EnrollmentRow, request.enrollment_id)
                if row is None or not secrets.compare_digest(row.code_hash, code_hash):
                    raise EnrollmentUnavailable()
                record = EnrollmentRecord.model_validate(row.payload)
                if (record.registration_mode != MODE or record.revoked_at is not None
                        or record.code_hash != row.code_hash or record.owner_user_id != row.owner_user_id
                        or not record.requested_capabilities.issubset({'submitter', 'worker'})
                        or 'submitter' not in record.requested_capabilities):
                    raise EnrollmentUnavailable()
                # A machine credential must not be an invitation or existing
                # personal API credential, even when the caller knows that secret.
                if session.scalar(select(TokenRow.token_id).where(TokenRow.token_hash == token_hash)) is not None:
                    raise EnrollmentUnavailable()
                invitation_collision = session.scalar(select(EnrollmentRow.enrollment_id).where(
                    EnrollmentRow.code_hash.in_((token_hash, invite_hash(request.device_credential.get_secret_value())))))
                if invitation_collision is not None:
                    raise EnrollmentUnavailable()
                owner = self._user(session, record.owner_user_id)
                if "worker" in record.requested_capabilities and UserRole.MACHINE_OWNER not in owner.roles:
                    raise EnrollmentUnavailable()
                if record.used_at is not None:
                    credential_row = session.scalar(select(MachineCredentialRow).where(
                        MachineCredentialRow.credential_id == record.exchange_credential_id).with_for_update())
                    machine = session.get(MachineRow, record.machine_id)
                    policy = session.get(PolicyRow, record.machine_id)
                    if (not row.used or record.machine_id != record.invited_machine_id
                            or record.exchange_request_sha256 != digest or credential_row is None
                            or not credential_row.active or not secrets.compare_digest(credential_row.token_hash, token_hash)
                            or credential_row.machine_id != record.machine_id or machine is None or policy is None
                            or machine.owner_user_id != record.owner_user_id):
                        raise EnrollmentUnavailable()
                    if not MachineAgentCredential.model_validate(credential_row.payload).is_active(now):
                        raise EnrollmentUnavailable()
                    # Exact replay after invite expiry is safe only with the still
                    # active bound device secret. Never rewrite metrics or policy.
                    return self._receipt(record)
                stored_expiry = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
                if row.used or stored_expiry <= now or not record.is_available(now) or not record.invited_machine_id:
                    raise EnrollmentUnavailable()
                if session.get(MachineRow, record.invited_machine_id) is not None:
                    raise EnrollmentUnavailable()
                machine = MachineState(machine_id=record.invited_machine_id, owner_user_id=record.owner_user_id,
                    hostname=request.facts.hostname, total_cpus=request.facts.total_cpus,
                    total_memory_mb=request.facts.total_memory_mb, labels={"member-node"},
                    capabilities=set(record.requested_capabilities), package_version=request.facts.package_version,
                    protocol_version=request.facts.protocol_version, runtime_version=None,
                    metrics=MachineMetrics(available=False, source="registration-unverified"),
                    capability_report={"registration_only": True, "acceptance_verified": False},
                    last_heartbeat_at=now)
                policy = MachinePolicy(machine_id=machine.machine_id, owner_user_id=machine.owner_user_id,
                    owner_mode=MachineMode.PAUSED, max_cpus=1,
                    max_memory_mb=min(8192, machine.total_memory_mb),
                    external_comsol_termination_authorized=False)
                credential = MachineAgentCredential(machine_id=machine.machine_id, token_hash=token_hash,
                    issued_by=f"enrollment:{record.enrollment_id}")
                session.add(MachineRow(machine_id=machine.machine_id, owner_user_id=machine.owner_user_id,
                    last_heartbeat_at=machine.last_heartbeat_at, payload=machine.model_dump(mode="json")))
                session.add(PolicyRow(machine_id=machine.machine_id, payload=policy.model_dump(mode="json")))
                session.add(MachineCredentialRow(credential_id=credential.credential_id, machine_id=machine.machine_id,
                    token_hash=token_hash, active=True, payload=credential.model_dump(mode="json")))
                record.used_at = now
                record.machine_id = machine.machine_id
                record.hostname = machine.hostname
                record.exchange_request_sha256 = digest
                record.exchange_credential_id = credential.credential_id
                row.used = True
                row.payload = record.model_dump(mode="json")
                self._audit(session, "member.registered", f"enrollment:{record.enrollment_id}", record.enrollment_id,
                    machine_id=machine.machine_id, credential_id=credential.credential_id,
                    owner_user_id=machine.owner_user_id, grants_execution=False)
                return self._receipt(record)
        try:
            return self.repository._retry_sqlite_write(write)
        except IntegrityError:
            # Concurrent conflicting identities/tokens are not overwritten.
            raise EnrollmentUnavailable() from None
