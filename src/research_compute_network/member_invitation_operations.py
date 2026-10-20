"""Retryable administrator issuance without storing recoverable invitation secrets.

The browser retains random delivery material only in memory. Exact retries supply
it again; the database stores only a request digest. Cancellation is persistent,
including when it arrives before the first issuance. Existing v2 member files and
Worker contracts are unchanged. Losing delivery material permits cancellation,
not secret retrieval from an operation ID alone.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re

from pydantic import Field, SecretStr, field_validator
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from .member_enrollment import (EnrollmentUnavailable, MODE, MemberEnrollmentService,
    MemberInvitation, MemberInvitationRequest, StrictModel, invite_hash, secret_hash)
from .models import EnrollmentRecord, UserAccount, UserRole, new_id
from .member_admission_contract import ConditionalAdmissionRequest
from .member_admission_invitation import checked_offer, make_offer, validate_scope
from .repository import (EnrollmentRow, MachineCredentialRow, MemberInvitationOperationRow,
    TokenRow, UserRow)

OPERATIONS_PATH = '/v1/admin/member-invitation-operations'


def operation_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{32}', value):
        raise EnrollmentUnavailable()
    return value


class InvitationOperationRequest(MemberInvitationRequest):
    delivery_secret: SecretStr
    new_member_display_name: str | None = Field(default=None, min_length=1, max_length=160)
    conditional_admission: ConditionalAdmissionRequest | None = None

    @field_validator('new_member_display_name')
    @classmethod
    def display_name(cls, value):
        if value is not None and (value != value.strip() or any(ord(c)<32 for c in value)):
            raise ValueError('invalid_new_member_name')
        return value

    @field_validator('delivery_secret')
    @classmethod
    def validate_secret(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', raw):
            raise ValueError('invalid_delivery_secret')
        decoded = base64.urlsafe_b64decode(raw + '=')
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip('=') != raw:
            raise ValueError('invalid_delivery_secret')
        return value

    def digest(self) -> str:
        data = self.model_dump(mode='json', exclude={'delivery_secret'})
        if self.conditional_admission is not None and 'admission_policy' not in self.conditional_admission.model_fields_set:
            data['conditional_admission'].pop('admission_policy', None)
        # Preserve pre-extension hashes for uncertain older issuance operations.
        for name in ('new_member_display_name', 'conditional_admission'):
            if data[name] is None:
                del data[name]
        data['delivery_sha256'] = secret_hash(self.delivery_secret.get_secret_value())
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class CancelInvitationOperation(StrictModel):
    """An explicitly empty JSON body, not an arbitrary management command."""


def _code(request: InvitationOperationRequest, enrollment_id: str) -> str:
    key = base64.urlsafe_b64decode(request.delivery_secret.get_secret_value() + '=')
    digest = hmac.digest(key, ('rcn-invitation-delivery-v1\0' + enrollment_id).encode('ascii'), 'sha256')
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')


class MemberInvitationOperations:
    def __init__(self, repository):
        self.repository = repository
        self.enrollment = MemberEnrollmentService(repository)

    def _lock(self, session, identity: str):
        if self.repository.engine.dialect.name == 'sqlite':
            session.execute(text('BEGIN IMMEDIATE'))
        return session.scalar(select(MemberInvitationOperationRow).where(
            MemberInvitationOperationRow.operation_id == identity).with_for_update())

    def _admin(self, session, actor: str, row) -> None:
        if UserRole.ADMIN not in self.enrollment._user(session, actor).roles:
            raise EnrollmentUnavailable()
        if row is not None and row.actor_id != actor:
            raise EnrollmentUnavailable()

    @staticmethod
    def _record(session, operation) -> tuple[EnrollmentRow | None, EnrollmentRecord | None]:
        if operation.enrollment_id is None:
            if not operation.cancelled or operation.request_sha256 is not None:
                raise EnrollmentUnavailable()
            return None, None
        row = session.scalar(select(EnrollmentRow).where(
            EnrollmentRow.enrollment_id == operation.enrollment_id).with_for_update())
        if row is None:
            raise EnrollmentUnavailable()
        try:
            record = EnrollmentRecord.model_validate(row.payload)
        except ValueError:
            raise EnrollmentUnavailable() from None
        expiry = row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
        if (not operation.request_sha256 or not re.fullmatch(r'[a-f0-9]{64}', operation.request_sha256)
                or record.expires_at != expiry or (operation.cancelled and record.revoked_at is None)
                or record.enrollment_id != row.enrollment_id or record.registration_mode != MODE
                or record.issued_by != operation.actor_id or record.code_hash != row.code_hash
                or record.owner_user_id != row.owner_user_id
                or row.used != (record.used_at is not None) or not record.invited_machine_id):
            raise EnrollmentUnavailable()
        return row, record

    def _transaction(self, action, identity):
        try:
            return self.repository._retry_sqlite_write(action)
        except IntegrityError:
            # A competing first creation may have won on a non-SQLite backend.
            # Re-observe the SAME operation once, never invent a retry identity.
            with self.repository._session() as session:
                if session.get(MemberInvitationOperationRow, identity) is None:
                    raise EnrollmentUnavailable() from None
            try:
                return self.repository._retry_sqlite_write(action)
            except IntegrityError:
                raise EnrollmentUnavailable() from None

    def issue(self, identity: str, request: InvitationOperationRequest, *, actor_id: str) -> MemberInvitation:
        identity, digest = operation_id(identity), request.digest()
        def write():
            with self.repository._session() as session, session.begin():
                operation = self._lock(session, identity)
                row, record = self._record(session, operation) if operation else (None, None)
                self._admin(session, actor_id, operation)
                if operation is not None and (operation.cancelled or operation.request_sha256 != digest):
                    raise EnrollmentUnavailable()
                if request.conditional_admission is not None:
                    if not request.worker:
                        raise EnrollmentUnavailable()
                    validate_scope(session, request.conditional_admission)
                existing_owner = session.get(UserRow, request.owner_user_id)
                if request.new_member_display_name is not None and operation is None:
                    if existing_owner is not None:
                        raise EnrollmentUnavailable()  # never turn a name collision into a role upgrade
                    owner = UserAccount(user_id=request.owner_user_id, display_name=request.new_member_display_name,
                        roles={UserRole.MEMBER, *({UserRole.MACHINE_OWNER} if request.worker else set())})
                    session.add(UserRow(user_id=owner.user_id, active=True, payload=owner.model_dump(mode='json')))
                    session.flush()
                else:
                    owner = self.enrollment._user(session, request.owner_user_id)
                if request.worker and UserRole.MACHINE_OWNER not in owner.roles:
                    raise EnrollmentUnavailable()
                # Delivery material must not reuse a personal/machine/invitation credential.
                raw = request.delivery_secret.get_secret_value()
                hashed = secret_hash(raw)
                if (session.scalar(select(TokenRow.token_id).where(TokenRow.token_hash == hashed)) is not None
                        or session.scalar(select(MachineCredentialRow.credential_id).where(
                            MachineCredentialRow.token_hash == hashed)) is not None
                        or session.scalar(select(EnrollmentRow.enrollment_id).where(
                            EnrollmentRow.code_hash.in_((hashed, invite_hash(raw))))) is not None):
                    raise EnrollmentUnavailable()
                now = datetime.now(timezone.utc)
                if operation is not None:
                    code = _code(request, record.enrollment_id)
                    expiry = row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
                    if (not record.is_available(now) or expiry <= now
                            or record.owner_user_id != request.owner_user_id
                            or record.registration_url != request.control_plane_url
                            or record.requested_capabilities != {'submitter', *({'worker'} if request.worker else set())}
                            or not hmac.compare_digest(invite_hash(code), record.code_hash)):
                        raise EnrollmentUnavailable()
                else:
                    enrollment_id = new_id('enrollment')
                    code = _code(request, enrollment_id)
                    record = EnrollmentRecord(enrollment_id=enrollment_id, registration_mode=MODE,
                        code_hash=invite_hash(code), issued_by=actor_id, owner_user_id=request.owner_user_id,
                        invited_machine_id=new_id('MEMBER'), registration_url=request.control_plane_url,
                        requested_capabilities={'submitter', *({'worker'} if request.worker else set())},
                        expires_at=now + timedelta(minutes=request.ttl_minutes))
                    if request.conditional_admission is not None:
                        record.conditional_admission_offer = make_offer(session, request.conditional_admission,
                            enrollment_id=record.enrollment_id, machine_id=record.invited_machine_id,
                            owner_user_id=record.owner_user_id, actor_id=actor_id, now=now)
                    if request.new_member_display_name is not None:
                        self.enrollment._audit(session, 'member.invited_user_created', actor_id, record.enrollment_id,
                            user_id=owner.user_id, roles=sorted(role.value for role in owner.roles))
                    session.add(EnrollmentRow(enrollment_id=record.enrollment_id, code_hash=record.code_hash,
                        owner_user_id=record.owner_user_id, expires_at=record.expires_at, used=False,
                        payload=record.model_dump(mode='json')))
                    session.add(MemberInvitationOperationRow(operation_id=identity, actor_id=actor_id,
                        request_sha256=digest, enrollment_id=record.enrollment_id, cancelled=False, created_at=now))
                    self.enrollment._audit(session, 'member.invitation_issued', actor_id, record.enrollment_id,
                        operation_id=identity, machine_id=record.invited_machine_id, owner_user_id=record.owner_user_id,
                        worker=request.worker, expires_at=record.expires_at.isoformat())
                if request.conditional_admission is not None:
                    stored_scope = checked_offer(record)['scope']
                    requested_scope = request.conditional_admission.model_dump(mode='json')
                    if 'admission_policy' not in stored_scope and 'admission_policy' not in request.conditional_admission.model_fields_set:
                        requested_scope.pop('admission_policy', None)
                    if stored_scope != requested_scope:
                        raise EnrollmentUnavailable()
                elif record.conditional_admission_offer is not None:
                    raise EnrollmentUnavailable()
                return MemberInvitation(enrollment_id=record.enrollment_id, machine_id=record.invited_machine_id,
                    owner_user_id=record.owner_user_id, control_plane_url=record.registration_url,
                    worker=request.worker, enrollment_code=code, expires_at=record.expires_at)
        return self._transaction(write, identity)

    def cancel(self, identity: str, *, actor_id: str) -> dict:
        identity = operation_id(identity)
        def write():
            with self.repository._session() as session, session.begin():
                operation = self._lock(session, identity)
                row, record = self._record(session, operation) if operation else (None, None)
                self._admin(session, actor_id, operation)
                result = {'operation_id': identity, 'enrollment_id': operation.enrollment_id if operation else None,
                          'cancelled': True, 'state': 'cancelled', 'existing_machine_revoked': False}
                if record is not None and record.used_at is not None:
                    # Lost-delivery recovery may not revoke a registered device's
                    # enrollment/recovery authority or undo an in-flight calculation.
                    return {**result, 'cancelled': False, 'state': 'registered'}
                if operation is not None and operation.cancelled:
                    if record is not None and record.revoked_at is None:
                        raise EnrollmentUnavailable()
                    return result
                now = datetime.now(timezone.utc)
                if operation is None:
                    session.add(MemberInvitationOperationRow(operation_id=identity, actor_id=actor_id,
                        request_sha256=None, enrollment_id=None, cancelled=True, created_at=now))
                else:
                    operation.cancelled = True
                    if record.revoked_at is None:
                        record.revoked_at = now
                        row.payload = record.model_dump(mode='json')
                self.enrollment._audit(session, 'member.invitation_operation_cancelled', actor_id,
                    record.enrollment_id if record else identity, operation_id=identity,
                    existing_invitation=record is not None, existing_machine_revoked=False)
                return result
        return self._transaction(write, identity)
