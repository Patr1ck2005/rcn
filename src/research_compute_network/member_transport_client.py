"""Member-local transport identity preparation after confirmed v2 registration.

Only the existing member-private directory and fixed HTTPS enrollment endpoint
are used. No authorized_keys, services, tasks, managed compute roots or heartbeat
state are changed. Private keys never leave this directory or enter a request.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
import stat
import subprocess
from pathlib import Path
import secrets

from . import member_registration as registration, ssh_identity
from .member_enrollment import MemberExchangeRequest, MemberInvitation, MemberRegistrationReceipt
from .member_transport import TransportIdentityReceipt, TransportIdentityRequest, statement

STATE_FILE = 'transport-state.json'
KEY_DIRECTORY = 'transport'
KEY_FILE = 'identity'


def _fail(reason: str) -> None:
    raise registration.MemberRegistrationError(reason)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _registered(root: Path, invitation: MemberInvitation):
    journal_path, token_path = root / 'registration.json', root / 'machine-token'
    for path in (journal_path, token_path):
        registration._check_private_file(path)
    journal_raw = registration._read_bytes(journal_path)
    token_raw = registration._read_bytes(token_path)
    try:
        journal = registration._json_document(journal_raw)
        if (set(journal) != {'schema_version', 'invitation_sha256', 'state', 'request', 'receipt'}
                or type(journal['schema_version']) is not int or journal['schema_version'] != 1
                or journal['state'] != 'registered'
                or journal['invitation_sha256'] != _digest(registration._json_bytes(invitation.private_document()))):
            raise ValueError('unconfirmed registration')
        request = MemberExchangeRequest.model_validate(journal['request'])
        receipt = MemberRegistrationReceipt.model_validate(journal['receipt'])
        if (receipt.enrollment_id != invitation.enrollment_id
                or request.enrollment_id != invitation.enrollment_id
                or request.enrollment_code != invitation.enrollment_code
                or receipt.machine_id != invitation.machine_id
                or receipt.owner_user_id != invitation.owner_user_id
                or receipt.request_sha256 != request.request_hash()
                or receipt.registered_at.tzinfo is None
                or not secrets.compare_digest(token_raw, request.device_credential.get_secret_value().encode('ascii') + b'\n')):
            raise ValueError('registration binding mismatch')
    except (ValueError, KeyError, TypeError, RecursionError):
        _fail('transport_registration_requires_review')
    return receipt, request.device_credential, journal_raw, token_raw


def _check_receipt(value: dict, receipt: MemberRegistrationReceipt, key: str, origin: str) -> TransportIdentityReceipt:
    try:
        if not isinstance(value, dict) or type(value.get('schema_version')) is not int or value['schema_version'] != 1:
            raise ValueError('invalid receipt schema')
        result = TransportIdentityReceipt.model_validate(value)
        expected = {
            'enrollment_id': receipt.enrollment_id, 'machine_id': receipt.machine_id,
            'owner_user_id': receipt.owner_user_id, 'credential_id': receipt.credential_id,
            'registration_request_sha256': receipt.request_sha256, 'public_key': key,
            'public_key_fingerprint': ssh_identity.fingerprint(key),
            'statement_sha256': _digest(statement(receipt, key, origin)),
            'control_plane_heartbeat_url': origin,
        }
        if (any(getattr(result, name) != item for name, item in expected.items())
                or result.bound_at < receipt.registered_at
                or (result.bound_at - datetime.now(timezone.utc)).total_seconds() > 60):
            raise ValueError('binding receipt mismatch')
        # Do not let coercion of 0/1 or missing false flags become an authority claim.
        for name, flag in {'possession_verified': True, 'heartbeat_verified': False,
                           'configuration_installed': False, 'transport_authorized': False,
                           'grants_execution': False}.items():
            if value.get(name) is not flag:
                raise ValueError('invalid binding authority flags')
        return result
    except (ValueError, TypeError, KeyError, RecursionError):
        _fail('transport_receipt_mismatch')


def _check_public_file(path: Path) -> None:
    """OpenSSH public files may be world-readable, never world-writable."""
    registration._unlinked(path)
    if not path.exists():
        return
    if os.name != 'nt':
        info = path.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            _fail('transport_public_key_permissions')
        return
    script = r"""$ErrorActionPreference='Stop';$env:PSModulePath=(Join-Path $PSHOME 'Modules');$p=__PATH__
$allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
$acl=Get-Acl -LiteralPath $p
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Unknown owner'}
$write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
foreach($rule in $acl.Access){
 if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed -and ($rule.FileSystemRights -band $write)){throw 'Other writer'}
}
""".replace('__PATH__', "'" + str(path).replace("'", "''") + "'")
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        _fail('transport_public_key_permissions')


def _key(root: Path, state: dict) -> tuple[str, str]:
    key_root = root / KEY_DIRECTORY
    if state['state'] != 'preparing' and not key_root.is_dir():
        _fail('transport_private_key_missing')
    registration._private_directory(key_root)
    path = key_root / KEY_FILE
    public_path = path.with_name(path.name + '.pub')
    registration._check_private_file(path)
    _check_public_file(public_path)
    if not path.exists():
        if state['state'] != 'preparing' or public_path.exists():
            _fail('transport_private_key_missing')
        ssh_identity.generate(path)
    registration._check_private_file(path)
    private_digest = _digest(registration._read_bytes(path))
    key = ssh_identity.derive_public(path)
    if state['state'] != 'preparing' and (state['public_key'] != key or state['private_key_sha256'] != private_digest):
        _fail('transport_private_key_changed')
    if public_path.exists():
        _check_public_file(public_path)
        parts = registration._read_bytes(public_path).decode('ascii').strip().split()
        if parts not in [key.split(), [*key.split(), ssh_identity.NAMESPACE]]:
            _fail('transport_public_key_changed')
    else:
        # A killed key generator may have published the private file only. Restore
        # its public counterpart, never generate another private identity.
        registration._publish(public_path, (key + '\n').encode('ascii'))
    # Windows _commit requires a writable descriptor. r+b does not truncate or
    # rewrite the private bytes; they are checked again before any HTTPS request.
    with path.open('r+b') as stream:
        os.fsync(stream.fileno())
    return key, private_digest


def _unchanged(root: Path, journal_raw: bytes, token_raw: bytes, state_raw: bytes, private_digest: str) -> None:
    for path in (root / 'registration.json', root / 'machine-token', root / STATE_FILE,
                 root / KEY_DIRECTORY / KEY_FILE):
        registration._check_private_file(path)
    if (registration._read_bytes(root / 'registration.json') != journal_raw
            or registration._read_bytes(root / 'machine-token') != token_raw
            or registration._read_bytes(root / STATE_FILE) != state_raw
            or _digest(registration._read_bytes(root / KEY_DIRECTORY / KEY_FILE)) != private_digest):
        _fail('transport_state_changed')


def bind_member_transport(invitation_path: Path, *, state_root: Path,
                          expected_invitation_sha256: str) -> dict:
    """One resumable identity exchange; every call rechecks current server authority."""
    try:
        raw = registration._read_bytes(Path(invitation_path))
        if _digest(raw) != expected_invitation_sha256:
            _fail('invitation_changed_after_confirmation')
        invitation = MemberInvitation.model_validate(registration._json_document(raw))
        if not invitation.worker:
            _fail('transport_worker_invitation_required')
        root = Path(state_root).absolute()
        if not root.is_dir():
            _fail('transport_registration_required')
        registration._private_directory(root)
        with registration._exclusive(root):
            receipt, credential, journal_raw, token_raw = _registered(root, invitation)
            origin = invitation.control_plane_url
            context = {'enrollment_id': receipt.enrollment_id, 'machine_id': receipt.machine_id,
                       'credential_id': receipt.credential_id, 'registration_request_sha256': receipt.request_sha256,
                       'control_plane_heartbeat_url': origin}
            path = root / STATE_FILE
            registration._check_private_file(path)
            resumed = path.exists()
            if resumed:
                state_raw = registration._read_bytes(path)
                state = registration._json_document(state_raw)
                if (set(state) != {'schema_version', 'context', 'state', 'public_key', 'private_key_sha256', 'receipt'}
                        or type(state['schema_version']) is not int or state['schema_version'] != 1
                        or state['context'] != context or state['state'] not in {'preparing', 'prepared', 'bound'}):
                    _fail('transport_state_requires_review')
                if state['state'] == 'preparing':
                    if any(state[name] is not None for name in ('public_key', 'private_key_sha256', 'receipt')):
                        _fail('transport_state_requires_review')
                elif state['state'] == 'prepared' and state['receipt'] is not None:
                    _fail('transport_state_requires_review')
            else:
                if (root / KEY_DIRECTORY).exists():
                    _fail('transport_key_without_journal')
                state = {'schema_version': 1, 'context': context, 'state': 'preparing',
                         'public_key': None, 'private_key_sha256': None, 'receipt': None}
                state_raw = registration._json_bytes(state)
                registration._publish(path, state_raw)
            key, private_digest = _key(root, state)
            if state['state'] == 'preparing':
                state.update(state='prepared', public_key=key, private_key_sha256=private_digest)
                prepared = registration._json_bytes(state)
                registration._publish(path, prepared, expected=state_raw)
                state_raw = prepared
            previous = None
            if state['state'] == 'bound':
                previous = _check_receipt(state['receipt'], receipt, key, origin)
            message = statement(receipt, key, origin)
            proof = ssh_identity.sign(root / KEY_DIRECTORY / KEY_FILE, message)
            request = TransportIdentityRequest(enrollment_id=receipt.enrollment_id,
                device_credential=credential, public_key=key, signature=proof)
            payload = {**request.model_dump(mode='json'), 'device_credential': credential.get_secret_value()}
            _unchanged(root, journal_raw, token_raw, state_raw, private_digest)
            response = registration._post_management(origin, payload, path=ssh_identity.TRANSPORT_PATH)
            result = _check_receipt(response, receipt, key, origin)
            if previous is not None and result != previous:
                _fail('transport_receipt_changed')
            _unchanged(root, journal_raw, token_raw, state_raw, private_digest)
            state.update(state='bound', receipt=result.model_dump(mode='json'))
            bound = registration._json_bytes(state)
            if bound != state_raw:
                registration._publish(path, bound, expected=state_raw)
            return {'transport_identity_bound': True, 'transport_identity_resumed': resumed,
                    'transport_public_key_fingerprint': result.public_key_fingerprint,
                    'heartbeat_verified': False, 'configuration_installed': False,
                    'transport_authorized': False, 'grants_execution': False}
    except registration.MemberRegistrationError:
        raise
    except ssh_identity.SshIdentityError as exc:
        raise registration.MemberRegistrationError(str(exc)) from None
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        _fail('transport_local_state_requires_review')
