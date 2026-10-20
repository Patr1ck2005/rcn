"""Allocate a fixed, restricted relay channel to a possession-proven member.

The operator configures ONE dedicated relay policy. Individual invitations and
original device/root proofs are sufficient; no new per-machine administrator
approval. This grants neither a login session nor any right to execute a Job.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import threading
from typing import Literal

from pydantic import Field, field_validator
from sqlalchemy import select

from . import member_registration as storage, ssh_identity
from .member_enrollment import EnrollmentUnavailable, ID_PATTERN, StrictModel
from .member_relay_policy import RelayPolicy, RelayUnavailable, load_policy
from .member_worker_root_contract import (MemberWorkerRoots, WorkerRootReceipt, WorkerRootRequest,
    manifest, manifest_hash)
from .models import (EnrollmentRecord, MachineAgentCredential, MachineMode, MachinePolicy,
    MachineState, UserRole)
from .repository import (EnrollmentRow, EventSequenceRow, MachineCredentialRow, MachineExecutionConfigRow,
    MachineRow, PolicyRow)

RELAY_PATH = '/v1/member-enrollment/relay'
RELAY_PURPOSE = 'rcn-member-reverse-relay-v1'
MAX_RESERVATIONS = 1024
_PROVISION_SLOTS = threading.BoundedSemaphore(2)


class RelayRequest(WorkerRootRequest):
    """Only a signed root identity; endpoint, account and port are server-owned."""


class RelayReservation(StrictModel):
    schema_version: Literal[1] = 1
    endpoint_id: str
    policy_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    enrollment_id: str = Field(pattern=ID_PATTERN)
    machine_id: str = Field(pattern=ID_PATTERN)
    credential_id: str = Field(pattern=ID_PATTERN)
    root_manifest_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    public_key: str
    listener_port: int = Field(strict=True, ge=1024, le=65535)
    allocated_at: datetime
    _key = field_validator('public_key')(ssh_identity.public_key)

    @field_validator('allocated_at')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError('relay allocation requires timezone')
        return value


def relay_statement(descriptor: dict) -> bytes:
    # The fixed purpose distinguishes this from the existing root-claim signature.
    return storage._json_bytes({'purpose': RELAY_PURPOSE, 'root_manifest': descriptor})


def _root_claim(record: EnrollmentRecord) -> dict:
    try:
        saved = record.worker_root_binding
        if not isinstance(saved, dict) or set(saved) != {'manifest', 'receipt'}:
            raise ValueError('missing root')
        canonical_receipt = MemberWorkerRoots._receipt
        from .member_enrollment import MemberEnrollmentService
        expected = manifest(MemberEnrollmentService._receipt(record), record.ssh_transport_public_key,
            record.registration_url, saved['manifest']['remote_root'], saved['manifest']['root_uuid'])
        receipt = WorkerRootReceipt.model_validate(saved['receipt'])
        canonical = canonical_receipt(record, expected, receipt.registered_at).model_dump(mode='json')
        if (storage._json_bytes(saved['manifest']) != storage._json_bytes(expected)
                or storage._json_bytes(saved['receipt']) != storage._json_bytes(canonical)
                or receipt.registered_at < record.used_at):
            raise ValueError('inconsistent root')
        return expected
    except (ValueError, TypeError, KeyError, AttributeError):
        raise EnrollmentUnavailable() from None


def _reservation(record: EnrollmentRecord, policy: RelayPolicy) -> RelayReservation:
    try:
        raw = record.member_relay_binding
        item = RelayReservation.model_validate(raw)
        if (storage._json_bytes(raw) != storage._json_bytes(item.model_dump(mode='json'))
                or item.endpoint_id != policy.endpoint_id or item.policy_sha256 != policy.digest()
                or item.enrollment_id != record.enrollment_id or item.machine_id != record.machine_id
                or item.credential_id != record.exchange_credential_id
                or item.public_key != record.ssh_transport_public_key
                or item.root_manifest_sha256 != manifest_hash(_root_claim(record))
                or item.listener_port not in policy.listener_ports):
            raise ValueError('inconsistent relay reservation')
        return item
    except (ValueError, TypeError, KeyError, AttributeError):
        raise RelayUnavailable('relay_reservation_requires_review') from None


class MemberRelays:
    def __init__(self, repository, *, authorization_root: Path, verification_root: Path):
        self.repository = repository
        self.root = Path(authorization_root).absolute()
        self.roots = MemberWorkerRoots(repository, verification_root=verification_root)

    def _context(self, session, request: RelayRequest, policy: RelayPolicy):
        record, descriptor = self.roots._context(session, request)
        if (record.registration_url != policy.registration_origin
                or storage._json_bytes(_root_claim(record)) != storage._json_bytes(descriptor)):
            raise EnrollmentUnavailable()
        return record, descriptor

    def _allocation_rows(self, session):
        rows = list(session.scalars(select(EnrollmentRow).where(
            EnrollmentRow.payload['member_relay_binding']['endpoint_id'].as_string().is_not(None)
        ).limit(MAX_RESERVATIONS + 1)))
        if len(rows) > MAX_RESERVATIONS:
            raise RelayUnavailable('relay_reservation_scan_limit')
        return rows

    def reserve(self, request: RelayRequest, policy: RelayPolicy) -> RelayReservation:
        if not policy.admission_enabled:
            raise RelayUnavailable('member_relay_not_enabled')
        with self.repository._session() as session:
            _, descriptor = self._context(session, request, policy)
        self.roots.transport.verify_possession(request, relay_statement(descriptor))
        def write():
            with self.repository._session() as session, session.begin():
                self.roots.transport.enrollment._lock(session, request.enrollment_id)
                record, latest = self._context(session, request, policy)
                if latest != descriptor:
                    raise EnrollmentUnavailable()
                if self.repository.engine.dialect.name != 'sqlite':
                    session.execute(select(EventSequenceRow).where(
                        EventSequenceRow.sequence_id == 'global').with_for_update()).scalar_one()
                if record.member_relay_binding is not None:
                    return _reservation(record, policy)
                machine = MachineState.model_validate(session.get(MachineRow, record.machine_id).payload)
                owner_policy = MachinePolicy.model_validate(session.get(PolicyRow, record.machine_id).payload)
                if (session.get(MachineExecutionConfigRow, record.machine_id) is not None
                        or owner_policy.owner_mode != MachineMode.PAUSED or machine.metrics.running_units != 0):
                    raise EnrollmentUnavailable()
                # Never release/reuse a revoked reservation: an old live listener may
                # still exist until the separate exact-session retirement gate.
                occupied = {policy.coordinator_port}
                for row in self._allocation_rows(session):
                    previous = EnrollmentRecord.model_validate(row.payload)
                    binding = previous.member_relay_binding
                    if binding['endpoint_id'] == policy.endpoint_id:
                        occupied.add(_reservation(previous, policy).listener_port)
                # Avoid taking a port belonging to ANY existing execution config.
                for row in session.scalars(select(MachineExecutionConfigRow)):
                    for name in ('reverse_forward_port', 'ssh_port'):
                        port = row.payload.get(name)
                        if type(port) is int:
                            occupied.add(port)
                available = next((port for port in policy.listener_ports if port not in occupied), None)
                if available is None:
                    raise RelayUnavailable('relay_port_pool_exhausted')
                allocation = RelayReservation(endpoint_id=policy.endpoint_id, policy_sha256=policy.digest(),
                    enrollment_id=record.enrollment_id, machine_id=record.machine_id,
                    credential_id=record.exchange_credential_id, root_manifest_sha256=manifest_hash(descriptor),
                    public_key=record.ssh_transport_public_key, listener_port=available,
                    allocated_at=datetime.now(timezone.utc))
                record.member_relay_binding = allocation.model_dump(mode='json')
                session.get(EnrollmentRow, record.enrollment_id).payload = record.model_dump(mode='json')
                self.roots.transport.enrollment._audit(session, 'member.relay_reserved',
                    f'machine-agent:{record.machine_id}', record.enrollment_id,
                    endpoint_id=policy.endpoint_id, policy_sha256=policy.digest(), listener_port=available,
                    machine_id=record.machine_id, scope='loopback-reverse-forward-only', grants_execution=False)
                return allocation
        return self.repository._retry_sqlite_write(write)

    def active(self, policy: RelayPolicy) -> list[RelayReservation]:
        """Read fresh authority. No native commands or file writes under this transaction."""
        selected = []
        with self.repository._session() as session:
            for row in self._allocation_rows(session):
                record = EnrollmentRecord.model_validate(row.payload)
                if record.member_relay_binding['endpoint_id'] != policy.endpoint_id:
                    continue
                reservation = _reservation(record, policy)
                if (not policy.admission_enabled or not row.used or record.used_at is None or record.revoked_at is not None
                        or record.registration_mode != 'resumable-v1' or record.registration_url != policy.registration_origin
                        or record.enrollment_id != row.enrollment_id or record.owner_user_id != row.owner_user_id
                        or record.code_hash != row.code_hash or record.machine_id != record.invited_machine_id
                        or record.requested_capabilities != {'worker', 'submitter'}):
                    continue
                try:
                    user = self.roots.transport.enrollment._user(session, record.owner_user_id)
                except EnrollmentUnavailable:
                    continue
                token = session.get(MachineCredentialRow, record.exchange_credential_id)
                machine = session.get(MachineRow, record.machine_id)
                owner_policy = session.get(PolicyRow, record.machine_id)
                if (user.user_id != record.owner_user_id or UserRole.MACHINE_OWNER not in user.roles or token is None or not token.active
                        or token.machine_id != record.machine_id or machine is None or owner_policy is None
                        or machine.owner_user_id != record.owner_user_id):
                    continue
                credential = MachineAgentCredential.model_validate(token.payload)
                machine_state = MachineState.model_validate(machine.payload)
                policy_state = MachinePolicy.model_validate(owner_policy.payload)
                if (machine_state.machine_id != record.machine_id or machine_state.owner_user_id != record.owner_user_id
                        or policy_state.machine_id != record.machine_id
                        or record.ssh_transport_bound_at is None
                        or record.ssh_transport_statement_sha256 != hashlib.sha256(
                            self.roots.transport._statement(record, record.ssh_transport_public_key)).hexdigest()
                        or not credential.is_active() or credential.token_hash != token.token_hash
                        or credential.credential_id != token.credential_id or credential.machine_id != record.machine_id
                        or policy_state.owner_user_id != record.owner_user_id):
                    continue
                selected.append(reservation)
        if len({v.listener_port for v in selected}) != len(selected) or len({v.public_key for v in selected}) != len(selected):
            raise RelayUnavailable('duplicate_relay_authority')
        return sorted(selected, key=lambda item: item.listener_port)

    def synchronize(self) -> dict:
        from .member_relay_keys import synchronize_keys
        policy = load_policy(self.root, require_enabled=False)
        return synchronize_keys(self, policy)

    def request(self, request: RelayRequest) -> dict:
        # Authenticate before native configuration/account checks or any file IO.
        with self.repository._session() as session:
            record, _ = self.roots._context(session, request)
            _root_claim(record)
        if not _PROVISION_SLOTS.acquire(blocking=False):
            raise RelayUnavailable('member_relay_provisioner_busy')
        try:
            return self._request(request)
        finally:
            _PROVISION_SLOTS.release()

    def _request(self, request: RelayRequest) -> dict:
        from .member_relay_keys import synchronize_keys
        policy = load_policy(self.root)
        reserved = self.reserve(request, policy)
        applied = synchronize_keys(self, policy)
        with self.repository._session() as session:
            record, _ = self._context(session, request, policy)
            if _reservation(record, policy) != reserved:
                raise RelayUnavailable('relay_reservation_changed')
        if reserved.enrollment_id not in applied['authorized_enrollments']:
            raise EnrollmentUnavailable()
        return {'schema_version': 1, 'enrollment_id': reserved.enrollment_id, 'machine_id': reserved.machine_id,
            'root_manifest_sha256': reserved.root_manifest_sha256, 'policy_sha256': reserved.policy_sha256,
            'endpoint_id': policy.endpoint_id, 'coordinator_host': policy.coordinator_host,
            'coordinator_port': policy.coordinator_port, 'coordinator_user': policy.coordinator_user,
            'host_public_key': policy.host_public_key, 'reverse_forward_bind': 'localhost',
            'reverse_forward_port': reserved.listener_port, 'reverse_target_host': '127.0.0.1',
            'reverse_target_port': 22, 'relay_key_published': True,
            'new_connection_authorization_expires_at': applied['expires_at'],
            'ssh_verified': False, 'heartbeat_verified': False, 'runtime_accepted': False,
            'existing_sessions_revoked': False, 'grants_execution': False}
