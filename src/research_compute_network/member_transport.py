"""Bind a possession-proven SSH key to an already registered member device.

This is management metadata, not SSH authorization, a heartbeat or Worker
acceptance. The proof has a fixed namespace and immutable enrollment context;
replay can only confirm the same key while all existing authority is still valid.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import threading
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from sqlalchemy import select

from .member_enrollment import (EnrollmentUnavailable, ID_PATTERN, MODE,
    MemberEnrollmentService, MemberRegistrationReceipt, StrictModel, https_origin, secret_hash)
from .models import EnrollmentRecord, MachineAgentCredential, MachinePolicy, MachineState, UserRole
from .repository import EnrollmentRow, EventSequenceRow, MachineCredentialRow, MachineRow, PolicyRow
from . import ssh_identity


# Bounded per-process native verification, no unbounded subprocess fan-out.
_VERIFIER_SLOTS = threading.BoundedSemaphore(2)


class TransportIdentityRequest(StrictModel):
    enrollment_id: str = Field(pattern=ID_PATTERN)
    device_credential: SecretStr
    public_key: str
    signature: str = Field(max_length=8192, repr=False)
    _public_key = field_validator('public_key')(ssh_identity.public_key)
    _signature = field_validator('signature')(ssh_identity.signature_text)

    @field_validator('device_credential')
    @classmethod
    def credential(cls, value: SecretStr) -> SecretStr:
        import re
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', value.get_secret_value()):
            raise ValueError('invalid_device_credential')
        return value


class TransportIdentityReceipt(StrictModel):
    schema_version: Literal[1] = 1
    enrollment_id: str = Field(pattern=ID_PATTERN)
    machine_id: str = Field(pattern=ID_PATTERN)
    owner_user_id: str = Field(pattern=ID_PATTERN)
    credential_id: str = Field(pattern=ID_PATTERN)
    registration_request_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    public_key: str
    public_key_fingerprint: str
    statement_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    bound_at: datetime
    control_plane_heartbeat_url: str
    possession_verified: Literal[True] = True
    heartbeat_verified: Literal[False] = False
    configuration_installed: Literal[False] = False
    transport_authorized: Literal[False] = False
    grants_execution: Literal[False] = False
    _public_key = field_validator('public_key')(ssh_identity.public_key)
    _origin = field_validator('control_plane_heartbeat_url')(https_origin)

    @field_validator('bound_at')
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError('binding time must include timezone')
        return value


def statement(receipt: MemberRegistrationReceipt, key: str, origin: str) -> bytes:
    # Never sign user commands, a caller namespace, a bearer token, or arbitrary data.
    return (json.dumps({'purpose': ssh_identity.NAMESPACE, 'schema_version': 1,
        'enrollment_id': receipt.enrollment_id, 'machine_id': receipt.machine_id,
        'owner_user_id': receipt.owner_user_id, 'credential_id': receipt.credential_id,
        'registration_request_sha256': receipt.request_sha256,
        'control_plane_heartbeat_url': https_origin(origin), 'public_key': ssh_identity.public_key(key)},
        sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


class MemberTransportService:
    def __init__(self, repository, *, verification_root: Path):
        self.repository = repository
        self.verification_root = Path(verification_root)
        self.enrollment = MemberEnrollmentService(repository)

    def _authorized(self, session, request: TransportIdentityRequest) -> EnrollmentRecord:
        row = session.get(EnrollmentRow, request.enrollment_id)
        if row is None or not row.used:
            raise EnrollmentUnavailable()
        record = EnrollmentRecord.model_validate(row.payload)
        if (record.enrollment_id != row.enrollment_id or record.enrollment_id != request.enrollment_id
                or record.registration_mode != MODE or record.revoked_at is not None or record.used_at is None
                or not record.machine_id or record.machine_id != record.invited_machine_id
                or record.owner_user_id != row.owner_user_id or record.code_hash != row.code_hash
                or record.requested_capabilities != {'submitter', 'worker'}):
            raise EnrollmentUnavailable()
        owner = self.enrollment._user(session, record.owner_user_id)
        if UserRole.MACHINE_OWNER not in owner.roles:
            raise EnrollmentUnavailable()
        token = session.scalar(select(MachineCredentialRow).where(
            MachineCredentialRow.credential_id == record.exchange_credential_id).with_for_update())
        machine = session.get(MachineRow, record.machine_id)
        policy = session.get(PolicyRow, record.machine_id)
        if (token is None or not token.active or token.machine_id != record.machine_id
                or not secrets.compare_digest(token.token_hash, secret_hash(request.device_credential.get_secret_value()))
                or machine is None or machine.owner_user_id != record.owner_user_id or policy is None):
            raise EnrollmentUnavailable()
        credential = MachineAgentCredential.model_validate(token.payload)
        machine_state = MachineState.model_validate(machine.payload)
        policy_state = MachinePolicy.model_validate(policy.payload)
        if (credential.machine_id != record.machine_id or credential.credential_id != token.credential_id
                or credential.token_hash != token.token_hash or not credential.is_active()
                or policy_state.owner_user_id != record.owner_user_id or policy_state.machine_id != record.machine_id
                or machine_state.owner_user_id != record.owner_user_id or machine_state.machine_id != record.machine_id):
            raise EnrollmentUnavailable()
        return record

    @staticmethod
    def _statement(record: EnrollmentRecord, key: str) -> bytes:
        return statement(MemberEnrollmentService._receipt(record), key, record.registration_url)

    @staticmethod
    def _receipt(record: EnrollmentRecord) -> TransportIdentityReceipt:
        return TransportIdentityReceipt(enrollment_id=record.enrollment_id,
            machine_id=record.machine_id, owner_user_id=record.owner_user_id,
            credential_id=record.exchange_credential_id, registration_request_sha256=record.exchange_request_sha256,
            public_key=record.ssh_transport_public_key,
            public_key_fingerprint=ssh_identity.fingerprint(record.ssh_transport_public_key),
            statement_sha256=record.ssh_transport_statement_sha256, bound_at=record.ssh_transport_bound_at,
            control_plane_heartbeat_url=record.registration_url)

    def verify_possession(self, request: TransportIdentityRequest, message: bytes) -> None:
        """Bounded verifier shared by fixed, server-reconstructed management proofs."""
        if not _VERIFIER_SLOTS.acquire(blocking=False):
            raise ssh_identity.SshIdentityError('ssh_identity_verifier_busy')
        try:
            if not ssh_identity.verify(request.public_key, request.signature, message, scratch_root=self.verification_root):
                raise EnrollmentUnavailable()
        finally:
            _VERIFIER_SLOTS.release()

    def bind(self, request: TransportIdentityRequest) -> TransportIdentityReceipt:
        # Native verification occurs outside the write transaction. Authenticate
        # before invoking it, then recheck authority under lock before any mutation.
        with self.repository._session() as session:
            snapshot = self._authorized(session, request)
            message = self._statement(snapshot, request.public_key)
        self.verify_possession(request, message)
        digest = hashlib.sha256(message).hexdigest()
        def write():
            with self.repository._session() as session, session.begin():
                self.enrollment._lock(session, request.enrollment_id)
                record = self._authorized(session, request)
                if self._statement(record, request.public_key) != message:
                    raise EnrollmentUnavailable()
                # SQLite's write lock already serializes bindings. Other backends
                # use the existing audit-sequence row before checking key uniqueness.
                if self.repository.engine.dialect.name != 'sqlite':
                    session.execute(select(EventSequenceRow).where(
                        EventSequenceRow.sequence_id == 'global').with_for_update()).scalar_one()
                duplicate = session.scalar(select(EnrollmentRow.enrollment_id).where(
                    EnrollmentRow.enrollment_id != record.enrollment_id,
                    EnrollmentRow.payload['ssh_transport_public_key'].as_string() == request.public_key))
                if duplicate is not None:
                    raise EnrollmentUnavailable()
                existing = (record.ssh_transport_public_key, record.ssh_transport_statement_sha256, record.ssh_transport_bound_at)
                if any(value is not None for value in existing):
                    if (record.ssh_transport_public_key != request.public_key or record.ssh_transport_statement_sha256 != digest
                            or record.ssh_transport_bound_at is None):
                        raise EnrollmentUnavailable()
                    return self._receipt(record)
                record.ssh_transport_public_key = request.public_key
                record.ssh_transport_statement_sha256 = digest
                record.ssh_transport_bound_at = datetime.now(timezone.utc)
                session.get(EnrollmentRow, record.enrollment_id).payload = record.model_dump(mode='json')
                self.enrollment._audit(session, 'member.transport_identity_bound',
                    f'machine-agent:{record.machine_id}', record.enrollment_id,
                    machine_id=record.machine_id, public_key_fingerprint=ssh_identity.fingerprint(request.public_key),
                    grants_execution=False, transport_authorized=False)
                return self._receipt(record)
        return self.repository._retry_sqlite_write(write)
