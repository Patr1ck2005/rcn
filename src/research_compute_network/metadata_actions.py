"""Actor-bound metadata receipts; replay never re-applies a mutable setting."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from uuid import UUID, uuid4

from fastapi import HTTPException, Request
from sqlalchemy import DateTime, String, Text, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from .repository import Base


class MetadataActionRow(Base):
    __tablename__ = 'metadata_actions'
    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    kind: Mapped[str] = mapped_column(String(128), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(512), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_salt: Mapped[str | None] = mapped_column(String(32), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    claim_owner: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


_PROCESS_CLAIM = str(uuid4())


class MetadataActionConflict(ValueError):
    pass


class MetadataActionForbidden(PermissionError):
    pass


def _request_id(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise MetadataActionConflict('metadata request ID must be a UUID') from exc


async def metadata_action_request(request: Request):
    """Bind the actual JSON intent, without model-generated defaults/set order."""
    raw = await request.body()
    try:
        body = await request.json() if raw else {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(400, 'metadata action requires valid JSON') from exc
    return (request.headers.get('X-RCN-Request-ID'), {
        'method': request.method, 'path': request.url.path,
        'body': body,
    })


def _encoded(value):
    # Strict JSON also ensures the saved value is precisely an HTTP JSON value.
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode('utf-8')


def _digest(payload, salt):
    try:
        encoded = _encoded(payload)
    except (ValueError, TypeError) as exc:
        raise MetadataActionConflict('metadata action payload must be finite JSON') from exc
    if salt is None:
        return hashlib.sha256(encoded).hexdigest()
    # Low-entropy secrets (the break-glass PIN) must not become fast offline
    # dictionary targets just because the operation has a durable identity.
    return hashlib.scrypt(encoded, salt=bytes.fromhex(salt), n=32768, r=8, p=1,
        maxmem=128*1024*1024, dklen=32).hex()


def _match(row, *, actor_id, kind, subject_id, payload, sensitive_payload):
    if row.actor_id != actor_id:
        raise MetadataActionForbidden('metadata operation belongs to another actor')
    if ((row.kind, row.subject_id) != (kind, subject_id)
            or (row.payload_salt is not None) != sensitive_payload
            or not hmac.compare_digest(row.payload_digest, _digest(payload, row.payload_salt))):
        raise MetadataActionConflict('metadata operation identity conflicts with original request')


def _row(repository, request_id):
    with repository._session() as session:
        statement = select(MetadataActionRow).where(MetadataActionRow.request_id == request_id)
        if repository._transaction_session() is not None:
            statement = statement.with_for_update()
        return session.scalar(statement)


def _receipt(row):
    state = row.state
    if state == 'running' and row.claim_owner != _PROCESS_CLAIM:
        state = 'reconciliation_required'
    return {'request_id': row.request_id, 'kind': row.kind, 'subject_id': row.subject_id,
        'state': state, 'result': json.loads(row.result_json) if row.result_json is not None else None}


def metadata_action_receipt(repository, request_id, actor_id):
    request_id = _request_id(request_id)
    row = _row(repository, request_id)
    if row is None:
        return None
    if row.actor_id != actor_id:
        raise MetadataActionForbidden('metadata operation belongs to another actor')
    if row.kind == 'onboarding_preflight' and row.state != 'completed':
        with repository.atomic_write():
            row = _row(repository, request_id)
            _recover_preflight(repository, row)
    return _receipt(row)


def _new(request_id, actor_id, kind, subject_id, payload, sensitive_payload, *, state):
    salt = os.urandom(16).hex() if sensitive_payload else None
    return MetadataActionRow(request_id=request_id, actor_id=actor_id, kind=kind,
        subject_id=subject_id, payload_digest=_digest(payload, salt), payload_salt=salt,
        state=state, created_at=datetime.now(timezone.utc))


def _complete(row, value):
    row.result_json = _encoded(value).decode('utf-8')
    row.state = 'completed'
    row.completed_at = datetime.now(timezone.utc)
    return json.loads(row.result_json)


def execute_metadata_action(repository, *, request_id, actor_id, kind, subject_id,
                            payload, mutate, sensitive_payload=False):
    """Persist intent, mutation, audit and exact safe result in one transaction.

    The caller authorizes the current actor before invoking this function, and
    supplies only JSON-safe results (never credentials or PIN material). Missing
    request IDs preserve the legacy API while retaining atomic mutation/audit.
    """
    if request_id is None:
        with repository.atomic_write():
            return json.loads(_encoded(mutate()))
    request_id = _request_id(request_id)
    try:
        with repository.atomic_write():
            old = _row(repository, request_id)
            if old is not None:
                _match(old, actor_id=actor_id, kind=kind, subject_id=subject_id,
                    payload=payload, sensitive_payload=sensitive_payload)
                if old.state != 'completed':
                    raise MetadataActionConflict('metadata operation requires reconciliation')
                return json.loads(old.result_json)
            with repository._session() as session:
                row = _new(request_id, actor_id, kind, subject_id, payload, sensitive_payload, state='accepted')
                session.add(row)
                session.flush()  # Claim the unique ID before any mutation.
                result = _complete(row, mutate())
                session.flush()
                return result
    except IntegrityError:
        # On databases with row-level locking, two first inserts can race.
        # Losing the unique claim rolls back before mutate and reads the winner.
        old = _row(repository, request_id)
        if old is None:
            raise
        _match(old, actor_id=actor_id, kind=kind, subject_id=subject_id,
            payload=payload, sensitive_payload=sensitive_payload)
        if old.state != 'completed':
            raise MetadataActionConflict('metadata operation requires reconciliation')
        return json.loads(old.result_json)


def run_preflight_metadata_action(repository, *, request_id, actor_id, subject_id,
                                  payload, mutate):
    """Claim a remote read once, outside its transaction; never replay its I/O."""
    if request_id is None:
        return mutate(None)
    request_id = _request_id(request_id)
    run_id = 'ssh-preflight-'+request_id
    if repository._transaction_session() is not None:
        raise RuntimeError('preflight cannot run inside a metadata transaction')
    try:
        with repository.atomic_write():
            old = _row(repository, request_id)
            if old is not None:
                _match(old, actor_id=actor_id, kind='onboarding_preflight', subject_id=subject_id,
                    payload=payload, sensitive_payload=False)
                _recover_preflight(repository, old)
                return json.loads(old.result_json) if old.state == 'completed' else _receipt(old)
            with repository._session() as session:
                row = _new(request_id, actor_id, 'onboarding_preflight', subject_id,
                    payload, False, state='running')
                row.claim_owner = _PROCESS_CLAIM
                row.result_json = _encoded({'run_id': run_id, 'machine_id': subject_id}).decode('utf-8')
                session.add(row)
                session.flush()
    except IntegrityError:
        old = _row(repository, request_id)
        if old is None:
            raise
        _match(old, actor_id=actor_id, kind='onboarding_preflight', subject_id=subject_id,
            payload=payload, sensitive_payload=False)
        receipt = metadata_action_receipt(repository, request_id, actor_id)
        return receipt['result'] if receipt['state'] == 'completed' else receipt
    try:
        value = mutate(run_id)
        if value.get('run_id') != run_id or value.get('machine_id') != subject_id:
            raise MetadataActionConflict('preflight result differs from the original Run identity')
        # Validate before the final transaction; serialization failure is an
        # uncertain external outcome just like an interrupted caller.
        _encoded(value)
    except Exception:
        with repository.atomic_write():
            row = _row(repository, request_id)
            _match(row, actor_id=actor_id, kind='onboarding_preflight', subject_id=subject_id,
                payload=payload, sensitive_payload=False)
            if row.state != 'completed' and row.claim_owner == _PROCESS_CLAIM:
                row.state = 'reconciliation_required'
        raise
    with repository.atomic_write():
        row = _row(repository, request_id)
        _match(row, actor_id=actor_id, kind='onboarding_preflight', subject_id=subject_id,
            payload=payload, sensitive_payload=False)
        if row.state == 'completed':
            return json.loads(row.result_json)
        if row.claim_owner != _PROCESS_CLAIM:
            raise MetadataActionConflict('preflight execution claim requires reconciliation')
        return _complete(row, value)


def _recover_preflight(repository, row):
    """Recover only the uniquely bound final Run, never execute another probe."""
    if row.state == 'completed':
        return
    bound = json.loads(row.result_json) if row.result_json else {}
    if bound != {'run_id': 'ssh-preflight-'+row.request_id, 'machine_id': row.subject_id}:
        raise MetadataActionConflict('preflight Run binding requires reconciliation')
    run = repository.get_machine_preflight_run(bound['run_id'])
    if (run is not None and run.machine_id == row.subject_id
            and str(run.status) not in {'pending', 'running'}):
        _complete(row, run.model_dump(mode='json'))
