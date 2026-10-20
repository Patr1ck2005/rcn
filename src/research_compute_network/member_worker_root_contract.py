"""Fixed member bootstrap-root contract, not a runtime or SSH authorization.

A claim binds a planned local root to the existing enrollment/key. The server
never executes a submitted path, accepts client health, or enables computation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import PureWindowsPath
import re
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator
from sqlalchemy import select

from .member_enrollment import EnrollmentUnavailable, ID_PATTERN, MemberRegistrationReceipt, StrictModel
from .member_transport import MemberTransportService, TransportIdentityRequest
from .models import MachineMode, MachinePolicy, MachineState
from .remote_storage import validate_remote_root_path
from .repository import (EnrollmentRow, EventSequenceRow, MachineExecutionConfigRow, MachineRow, PolicyRow)
from .ssh_identity import fingerprint

ROOT_PATH = '/v1/member-enrollment/worker-root'
ROOT_PURPOSE = 'rcn-member-worker-root-v1'
TOKEN_RELATIVE = 'agent/credentials/machine-token'
KEY_RELATIVE = 'agent/tunnel/member_ed25519'
CONFIG_RELATIVE = 'agent/member-bootstrap.json'
MARKER = '.rcn-root.json'


def canonical_root(value: str) -> str:
    if not isinstance(value, str) or len(value) > 1024 or value != value.strip():
        raise ValueError('invalid_worker_root')
    normalized = value.replace('/', '\\')
    if not re.match(r'^[A-Za-z]:\\', normalized):
        raise ValueError('absolute_windows_worker_root_required')
    parts = normalized[3:].split('\\')
    for part in parts:
        if (not part or part in {'.', '..'} or part.endswith((' ', '.'))
                or any(ord(char) < 32 for char in part) or re.search(r'[<>:"|?*]', part)
                or part.casefold() in {'control-plane', '.git', 'raw'}
                or re.fullmatch(r'(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part, re.I)):
            raise ValueError('unsafe_worker_root')
    root = validate_remote_root_path(normalized)
    return str(root)[0].upper() + str(root)[1:]


def root_uuid(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError('invalid_worker_root_uuid')
    parsed = UUID(value)
    if str(parsed) != value or parsed.version != 4:
        raise ValueError('invalid_worker_root_uuid')
    return value


class WorkerRootRequest(TransportIdentityRequest):
    remote_root: str
    root_uuid: str
    _root = field_validator('remote_root')(canonical_root)
    _uuid = field_validator('root_uuid')(root_uuid)


class WorkerRootReceipt(StrictModel):
    schema_version: Literal[1] = 1
    enrollment_id: str = Field(pattern=ID_PATTERN)
    machine_id: str = Field(pattern=ID_PATTERN)
    credential_id: str = Field(pattern=ID_PATTERN)
    remote_root: str
    root_uuid: str
    manifest_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    registered_at: datetime
    root_claim_registered: Literal[True] = True
    ssh_verified: Literal[False] = False
    heartbeat_verified: Literal[False] = False
    runtime_accepted: Literal[False] = False
    grants_execution: Literal[False] = False
    _root = field_validator('remote_root')(canonical_root)
    _uuid = field_validator('root_uuid')(root_uuid)

    @field_validator('registered_at')
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError('root registration time requires timezone')
        return value


def manifest(receipt: MemberRegistrationReceipt, key: str, origin: str, path: str, identity: str) -> dict:
    from .member_enrollment import https_origin
    root = canonical_root(path)
    return {'schema_version': 1, 'kind': ROOT_PURPOSE, 'enrollment_id': receipt.enrollment_id,
        'machine_id': receipt.machine_id, 'owner_user_id': receipt.owner_user_id,
        'credential_id': receipt.credential_id, 'registration_request_sha256': receipt.request_sha256,
        'remote_root': root, 'root_uuid': root_uuid(identity), 'public_key_fingerprint': fingerprint(key),
        'control_plane_heartbeat_url': https_origin(origin),
        'machine_token_file': str(PureWindowsPath(root) / TOKEN_RELATIVE),
        'identity_file': str(PureWindowsPath(root) / KEY_RELATIVE),
        'target_concurrent_units': 0, 'runtime_installed': False, 'grants_execution': False}


def root_statement(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def manifest_hash(value: dict) -> str:
    return hashlib.sha256(root_statement(value)).hexdigest()


class MemberWorkerRoots:
    def __init__(self, repository, *, verification_root):
        self.repository = repository
        self.transport = MemberTransportService(repository, verification_root=verification_root)

    def _context(self, session, request: WorkerRootRequest):
        record = self.transport._authorized(session, request)
        if (record.ssh_transport_public_key != request.public_key or record.ssh_transport_bound_at is None
                or record.ssh_transport_statement_sha256 != hashlib.sha256(
                    self.transport._statement(record, request.public_key)).hexdigest()):
            raise EnrollmentUnavailable()
        receipt = self.transport.enrollment._receipt(record)
        value = manifest(receipt, request.public_key, record.registration_url, request.remote_root, request.root_uuid)
        return record, value

    @staticmethod
    def _receipt(record, value: dict, registered_at: datetime) -> WorkerRootReceipt:
        return WorkerRootReceipt(enrollment_id=record.enrollment_id, machine_id=record.machine_id,
            credential_id=record.exchange_credential_id, remote_root=value['remote_root'], root_uuid=value['root_uuid'],
            manifest_sha256=manifest_hash(value), registered_at=registered_at)

    def register(self, request: WorkerRootRequest) -> WorkerRootReceipt:
        with self.repository._session() as session:
            _, initial = self._context(session, request)
        self.transport.verify_possession(request, root_statement(initial))
        def write():
            with self.repository._session() as session, session.begin():
                self.transport.enrollment._lock(session, request.enrollment_id)
                record, value = self._context(session, request)
                if value != initial:
                    raise EnrollmentUnavailable()
                if self.repository.engine.dialect.name != 'sqlite':
                    session.execute(select(EventSequenceRow).where(
                        EventSequenceRow.sequence_id == 'global').with_for_update()).scalar_one()
                duplicate = session.scalar(select(EnrollmentRow.enrollment_id).where(
                    EnrollmentRow.enrollment_id != record.enrollment_id,
                    EnrollmentRow.payload['worker_root_binding']['manifest']['root_uuid'].as_string() == request.root_uuid))
                if duplicate is not None:
                    raise EnrollmentUnavailable()
                saved = record.worker_root_binding
                if saved is not None:
                    try:
                        if set(saved) != {'manifest', 'receipt'} or saved['manifest'] != value:
                            raise ValueError('conflicting root claim')
                        raw_receipt = saved['receipt']
                        if (not isinstance(raw_receipt, dict) or set(raw_receipt) != set(WorkerRootReceipt.model_fields)
                                or type(raw_receipt['schema_version']) is not int or raw_receipt['schema_version'] != 1
                                or raw_receipt['root_claim_registered'] is not True
                                or any(raw_receipt[name] is not False for name in
                                    ('ssh_verified', 'heartbeat_verified', 'runtime_accepted', 'grants_execution'))):
                            raise ValueError('incomplete root receipt')
                        receipt = WorkerRootReceipt.model_validate(raw_receipt)
                        if (receipt.registered_at < record.used_at
                                or receipt != self._receipt(record, value, receipt.registered_at)):
                            raise ValueError('conflicting root receipt')
                    except (ValueError, TypeError, KeyError):
                        raise EnrollmentUnavailable() from None
                    return receipt
                # Bootstrap is only for new paused nodes. Never replace an existing
                # execution root, interrupt running work, or change machine policy.
                policy = MachinePolicy.model_validate(session.get(PolicyRow, record.machine_id).payload)
                machine = MachineState.model_validate(session.get(MachineRow, record.machine_id).payload)
                if (session.get(MachineExecutionConfigRow, record.machine_id) is not None
                        or policy.owner_mode != MachineMode.PAUSED or machine.metrics.running_units != 0):
                    raise EnrollmentUnavailable()
                receipt = self._receipt(record, value, datetime.now(timezone.utc))
                record.worker_root_binding = {'manifest': value, 'receipt': receipt.model_dump(mode='json')}
                session.get(EnrollmentRow, record.enrollment_id).payload = record.model_dump(mode='json')
                self.transport.enrollment._audit(session, 'member.worker_root_claimed',
                    f'machine-agent:{record.machine_id}', record.enrollment_id,
                    machine_id=record.machine_id, root_uuid=receipt.root_uuid,
                    manifest_sha256=receipt.manifest_sha256, grants_execution=False)
                return receipt
        return self.repository._retry_sqlite_write(write)
