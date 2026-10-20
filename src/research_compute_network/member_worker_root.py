"""Prepare one new Windows Worker root using the member's existing identity.

Everything is staged under a protected sibling, checked, then renamed without
replacement. Existing compute roots are never adopted by name. No processes,
services, scheduled tasks, runtime files, or execution policies are changed.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from . import member_registration as storage, member_transport_client as transport, ssh_identity
from .member_enrollment import MemberInvitation
from .member_worker_root_contract import (CONFIG_RELATIVE, KEY_RELATIVE, MARKER, ROOT_PATH,
    TOKEN_RELATIVE, WorkerRootReceipt, WorkerRootRequest, canonical_root, manifest, manifest_hash, root_statement)

JOURNAL = 'worker-root-state.json'
_PHASES = {'prepared', 'reserved', 'published', 'confirmed'}


def _fail(reason: str) -> None:
    raise storage.MemberRegistrationError(reason)


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sources(source: Path, invitation: MemberInvitation):
    receipt, credential, journal_raw, token_raw = transport._registered(source, invitation)
    state_path = source / transport.STATE_FILE
    private_path = source / transport.KEY_DIRECTORY / transport.KEY_FILE
    for path in (state_path, private_path):
        storage._check_private_file(path)
    state_raw = storage._read_bytes(state_path)
    state = storage._json_document(state_raw)
    if state.get('state') != 'bound':
        _fail('worker_root_requires_bound_transport')
    private = storage._read_bytes(private_path)
    key = ssh_identity.derive_public(private_path)
    bound = transport._check_receipt(state.get('receipt'), receipt, key, invitation.control_plane_url)
    if (set(state) != {'schema_version', 'context', 'state', 'public_key', 'private_key_sha256', 'receipt'}
            or type(state['schema_version']) is not int or state['schema_version'] != 1
            or state['context'] != {'enrollment_id': receipt.enrollment_id, 'machine_id': receipt.machine_id,
                'credential_id': receipt.credential_id, 'registration_request_sha256': receipt.request_sha256,
                'control_plane_heartbeat_url': invitation.control_plane_url}
            or state['public_key'] != bound.public_key or state['private_key_sha256'] != _hash(private)):
        _fail('worker_root_source_identity_changed')
    snapshots = {'registration.json': journal_raw, 'machine-token': token_raw,
                 transport.STATE_FILE: state_raw, f'{transport.KEY_DIRECTORY}/{transport.KEY_FILE}': private}
    return receipt, credential, key, snapshots


def _check_sources(source: Path, snapshots: dict[str, bytes]) -> None:
    for relative, raw in snapshots.items():
        path = source / relative
        storage._check_private_file(path)
        if storage._read_bytes(path) != raw:
            _fail('worker_root_source_identity_changed')


def _receipt(value: dict, descriptor: dict) -> WorkerRootReceipt:
    try:
        if not isinstance(value, dict) or set(value) != set(WorkerRootReceipt.model_fields):
            raise ValueError('incomplete root receipt')
        if type(value['schema_version']) is not int or value['schema_version'] != 1:
            raise ValueError('invalid root receipt schema')
        for field, expected in {'root_claim_registered': True, 'ssh_verified': False,
            'heartbeat_verified': False, 'runtime_accepted': False, 'grants_execution': False}.items():
            if value[field] is not expected:
                raise ValueError('root receipt is not an execution grant')
        result = WorkerRootReceipt.model_validate(value)
        for field in ('enrollment_id', 'machine_id', 'credential_id', 'remote_root', 'root_uuid'):
            if getattr(result, field) != descriptor[field]:
                raise ValueError('root receipt context mismatch')
        if result.manifest_sha256 != manifest_hash(descriptor):
            raise ValueError('root manifest mismatch')
        return result
    except (ValueError, TypeError, KeyError):
        _fail('worker_root_receipt_mismatch')


def _exchange(invitation, descriptor, key, credential, private_path: Path):
    proof = ssh_identity.sign(private_path, root_statement(descriptor))
    request = WorkerRootRequest(enrollment_id=invitation.enrollment_id, device_credential=credential,
        public_key=key, signature=proof, remote_root=descriptor['remote_root'], root_uuid=descriptor['root_uuid'])
    payload = {**request.model_dump(mode='json'), 'device_credential': credential.get_secret_value()}
    response = storage._post_management(invitation.control_plane_url, payload, path=ROOT_PATH)
    return _receipt(response, descriptor)


def _payloads(descriptor, marker, snapshots, key):
    return {MARKER: storage._json_bytes(marker), CONFIG_RELATIVE: storage._json_bytes(descriptor),
        TOKEN_RELATIVE: snapshots['machine-token'],
        KEY_RELATIVE: snapshots[f'{transport.KEY_DIRECTORY}/{transport.KEY_FILE}'],
        KEY_RELATIVE + '.pub': (key + '\n').encode('ascii')}


def _directories(payloads):
    result = set()
    for name in payloads:
        parent = Path(name).parent
        while parent != Path('.'):
            result.add(parent.as_posix())
            parent = parent.parent
    return sorted(result, key=lambda name: (len(Path(name).parts), name))


def _publish_leaf(path: Path, raw: bytes, *, maximum: int = 16384) -> None:
    """Exact deterministic scratch file, resumable even after a partial local write."""
    if not 1 <= maximum <= 262144 or len(raw) > maximum:
        _fail('worker_root_payload_too_large')
    temporary = path.with_name(path.name + '.rcn-preparing')
    for item in (path, temporary):
        storage._check_private_file(item)
    if path.exists():
        if storage._read_bytes(path, maximum=maximum) != raw:
            _fail('worker_root_existing_file_conflict')
        if temporary.exists():
            if storage._read_bytes(temporary, maximum=maximum) != raw:
                _fail('worker_root_temporary_conflict')
            temporary.unlink()
        return
    offset = 0
    if temporary.exists():
        partial = storage._read_bytes(temporary, maximum=maximum)
        if not raw.startswith(partial):
            _fail('worker_root_temporary_conflict')
        offset = len(partial)
    with temporary.open('ab' if temporary.exists() else 'xb') as stream:
        stream.write(raw[offset:])
        stream.flush()
        os.fsync(stream.fileno())
    if storage._read_bytes(temporary, maximum=maximum) != raw:
        _fail('worker_root_staged_file_changed')
    os.rename(temporary, path)  # Windows refuses ANY existing destination.


def _inventory(root: Path, payloads, *, strict: bool) -> None:
    storage._private_directory(root, create=False)
    for name in _directories(payloads):
        path = root / name
        if not path.is_dir():
            _fail('worker_root_directory_missing')
        storage._private_directory(path, create=False)
    for name, expected in payloads.items():
        path = root / name
        storage._check_private_file(path)
        if not path.is_file() or storage._read_bytes(path) != expected:
            _fail('worker_root_file_changed')
    if strict:
        allowed = set(payloads) | set(_directories(payloads))
        for path in root.rglob('*'):
            storage._unlinked(path)
            if path.relative_to(root).as_posix() not in allowed:
                _fail('worker_root_unowned_staging_content')


def _materialize(root: Path, stage: Path, state: dict, payloads) -> None:
    for path in (root, stage, root.parent):
        storage._unlinked(path)
    if root.exists():
        if stage.exists():
            _fail('worker_root_destination_conflict')
        _inventory(root, payloads, strict=state['phase'] == 'reserved')
        return
    if state['phase'] in {'published', 'confirmed'}:
        _fail('worker_root_missing_after_publication')
    storage._private_directory(stage)
    allowed = set(payloads) | set(_directories(payloads)) | {name + '.rcn-preparing' for name in payloads}
    for path in stage.rglob('*'):
        storage._unlinked(path)
        if path.relative_to(stage).as_posix() not in allowed:
            _fail('worker_root_unowned_staging_content')
    for name in _directories(payloads):
        storage._private_directory(stage / name)
    for name, raw in payloads.items():
        _publish_leaf(stage / name, raw)
    _inventory(stage, payloads, strict=True)
    storage._unlinked(root)
    os.rename(stage, root)  # Same-volume atomic no-replacement directory publication.
    _inventory(root, payloads, strict=True)


def prepare_worker_root(invitation_path: Path, *, state_root: Path,
                        expected_invitation_sha256: str, worker_root: Path | None = None,
                        root_uuid_override: str | None = None) -> dict:
    """Prepare and register a root, without enabling SSH, services or computation."""
    try:
        if os.name != 'nt':
            _fail('worker_root_requires_windows')
        raw = storage._read_bytes(Path(invitation_path))
        if _hash(raw) != expected_invitation_sha256:
            _fail('invitation_changed_after_confirmation')
        invitation = MemberInvitation.model_validate(storage._json_document(raw))
        if not invitation.worker:
            _fail('worker_root_requires_worker_invitation')
        source = Path(state_root).absolute()
        if not source.is_dir():
            _fail('worker_root_registration_missing')
        storage._private_directory(source, create=False)
        with storage._exclusive(source):
            registered, credential, key, snapshots = _sources(source, invitation)
            journal = source / JOURNAL
            storage._check_private_file(journal)
            state_raw = storage._read_bytes(journal) if journal.exists() else None
            state = storage._json_document(state_raw) if state_raw is not None else None
            selected = worker_root if worker_root is not None else (Path(state['manifest']['remote_root']) if state else source.parent / 'worker')
            root = Path(canonical_root(str(selected)))
            if root == source or root.is_relative_to(source) or source.is_relative_to(root):
                _fail('worker_root_overlaps_registration')
            if not root.parent.is_dir():
                _fail('worker_root_parent_missing')
            storage._unlinked(root)
            hashes = {name: _hash(value) for name, value in snapshots.items()}
            if state is None:
                if root.exists():
                    _fail('worker_root_already_exists_requires_migration')
                if root_uuid_override is not None:
                    from .member_worker_root_contract import root_uuid as validate_uuid
                    validate_uuid(root_uuid_override)
                identity = root_uuid_override or str(uuid4())
                descriptor = manifest(registered, key, invitation.control_plane_url, str(root), identity)
                stage = root.parent / ('.rcn-preparing-' + identity)
                if stage.exists() or stage.is_symlink():
                    _fail('worker_root_staging_conflict')
                marker = {'schema_version': 1, 'machine_id': registered.machine_id, 'root_uuid': identity,
                          'created_at': datetime.now(timezone.utc).isoformat()}
                state = {'schema_version': 1, 'phase': 'prepared', 'manifest': descriptor, 'marker': marker,
                    'stage_path': str(stage), 'source_sha256': hashes, 'receipt': None}
                state_raw = storage._json_bytes(state)
                storage._publish(journal, state_raw)
            else:
                if (set(state) != {'schema_version', 'phase', 'manifest', 'marker', 'stage_path', 'source_sha256', 'receipt'}
                        or type(state['schema_version']) is not int or state['schema_version'] != 1
                        or state['phase'] not in _PHASES or state['source_sha256'] != hashes):
                    _fail('worker_root_journal_requires_review')
                descriptor = manifest(registered, key, invitation.control_plane_url, str(root), state['manifest']['root_uuid'])
                if root_uuid_override is not None and root_uuid_override != descriptor['root_uuid']:
                    _fail('worker_root_identity_changed')
                stage = root.parent / ('.rcn-preparing-' + descriptor['root_uuid'])
                if state['manifest'] != descriptor or state['stage_path'] != str(stage):
                    _fail('worker_root_identity_changed')
                marker = state['marker']
                if (set(marker) != {'schema_version', 'machine_id', 'root_uuid', 'created_at'}
                        or type(marker['schema_version']) is not int or marker['schema_version'] != 1
                        or marker['machine_id'] != registered.machine_id or marker['root_uuid'] != descriptor['root_uuid']
                        or datetime.fromisoformat(marker['created_at']).tzinfo is None):
                    _fail('worker_root_marker_requires_review')
                if state['phase'] == 'prepared':
                    if state['receipt'] is not None or root.exists():
                        _fail('worker_root_journal_requires_review')
                else:
                    _receipt(state['receipt'], descriptor)
            def save(phase, receipt):
                nonlocal state_raw
                if storage._read_bytes(journal) != state_raw:
                    _fail('worker_root_journal_changed')
                state.update(phase=phase, receipt=receipt.model_dump(mode='json'))
                updated = storage._json_bytes(state)
                if updated != state_raw:
                    storage._publish(journal, updated, expected=state_raw)
                    state_raw = updated
            payloads = _payloads(descriptor, marker, snapshots, key)
            # Recheck authority before EVERY initial/resumed materialization. A
            # saved reservation is not permission to continue after revocation.
            # Published roots are inspected first, then checked from deployed files.
            if state['phase'] in {'prepared', 'reserved'}:
                _check_sources(source, snapshots)
                result = _exchange(invitation, descriptor, key, credential,
                    source / transport.KEY_DIRECTORY / transport.KEY_FILE)
                _check_sources(source, snapshots)
                if state['receipt'] is not None and result != _receipt(state['receipt'], descriptor):
                    _fail('worker_root_receipt_changed')
                save('reserved', result)
            _materialize(root, stage, state, payloads)
            saved = _receipt(state['receipt'], descriptor)
            if state['phase'] == 'reserved':
                save('published', saved)
            _check_sources(source, snapshots)
            deployed_token = storage._read_bytes(root / TOKEN_RELATIVE).decode('ascii').strip()
            if deployed_token != credential.get_secret_value():
                _fail('worker_root_credential_changed')
            from pydantic import SecretStr
            result = _exchange(invitation, descriptor, key, SecretStr(deployed_token), root / KEY_RELATIVE)
            if result != saved:
                _fail('worker_root_receipt_changed')
            _inventory(root, payloads, strict=False)
            _check_sources(source, snapshots)
            save('confirmed', result)
            return {'worker_root_prepared': True, 'worker_root_claim_registered': True,
                'worker_root': str(root), 'root_uuid': descriptor['root_uuid'],
                'bootstrap_manifest_sha256': manifest_hash(descriptor),
                'management_check_at': datetime.now(timezone.utc).isoformat(),
                'heartbeat_verified': False, 'transport_authorized': False,
                'configuration_installed': False, 'grants_execution': False}
    except storage.MemberRegistrationError:
        raise
    except ssh_identity.SshIdentityError as exc:
        raise storage.MemberRegistrationError(str(exc)) from None
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        _fail('worker_root_local_state_requires_review')
