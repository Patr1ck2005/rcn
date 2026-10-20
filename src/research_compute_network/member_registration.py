"""Member-side resumable HTTPS registration, not machine acceptance.

The protected journal and machine-token precede the first request. Network errors
never rotate the identity or fall back to the legacy enrollment endpoint. This
entry point deliberately does not install services, start tasks or open compute.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

from pydantic import ValidationError

from .member_enrollment import (DeviceFacts, EXCHANGE_PATH, MemberExchangeRequest,
    MemberInvitation, MemberRegistrationReceipt, https_origin)


class MemberRegistrationError(RuntimeError):
    """Bounded public message; never include invitation, token, or HTTP body."""


def _json_document(raw: bytes) -> dict:
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate registration key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('registration document must be an object')
    return value


def _unlinked(path: Path) -> None:
    for item in (path, *path.parents):
        if item.is_symlink():
            raise MemberRegistrationError('linked_registration_path')
        if item.exists():
            info = item.lstat()
            if getattr(info, 'st_file_attributes', 0) & 0x400:
                raise MemberRegistrationError('linked_registration_path')
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise MemberRegistrationError('linked_registration_file')


def _read_bytes(path: Path, maximum: int = 16384) -> bytes:
    _unlinked(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise MemberRegistrationError('invalid_registration_file')
    with path.open('rb') as stream:
        actual = os.fstat(stream.fileno())
        if actual.st_ino != info.st_ino or actual.st_nlink != 1:
            raise MemberRegistrationError('registration_file_changed')
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise MemberRegistrationError('registration_file_too_large')
    return raw


def _managed_worker_acl(path: Path) -> str:
    """Only a fixed ProgramData worker may share files with its execution SID.

    The identity record is admin-owned and non-writable to both local users;
    registration journals elsewhere retain their original private ACL policy.
    """
    if os.name != 'nt':
        return ''
    for parent in (Path(path), *Path(path).parents):
        if parent.name.casefold() not in {'worker', 'owner-control'}:
            continue
        binding = parent.parent / 'execution-identity.json'
        if not binding.exists():
            return ''
        try:
            _unlinked(binding)
            value = _json_document(_read_bytes(binding))
            expected = Path(os.environ.get('ProgramData', r'C:\ProgramData'))/'ResearchComputeNetwork/Members'/value['root_uuid']
            if (parent.parent != expected or value['member_root'] != str(expected)
                    or value['worker_root'] != str(expected/'worker') or value['schema_version'] != 1):
                raise ValueError('member identity mismatch')
            from .member_tunnel_identity import member_sid
            member_sid(value['owner_sid']);member_sid(value['execution_sid'])
            literal = str(binding).replace("'", "''")
            return r"""
$bindingPath='__BINDING__';$binding=Get-Content -LiteralPath $bindingPath -Raw|ConvertFrom-Json
$bAcl=Get-Acl -LiteralPath $bindingPath
if(-not $bAcl.AreAccessRulesProtected -or $bAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Unprotected member identity'}
foreach($rule in $bAcl.Access){$sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;if($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18','S-1-5-32-544') -and ($sid -notin @($binding.owner_sid,$binding.execution_sid) -or ($rule.FileSystemRights -band ([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions)))){throw 'Writable member identity'}}
if($identity.User.Value -notin @($binding.owner_sid,$binding.execution_sid)){throw 'Member worker caller changed'}
$allowed=@($binding.owner_sid,$binding.execution_sid,'S-1-5-18','S-1-5-32-544')
""".replace('__BINDING__', literal)
        except (ValueError, KeyError, TypeError):
            raise MemberRegistrationError('member_worker_identity_invalid') from None
    return ''


def _private_directory(root: Path, *, create: bool = True) -> None:
    _unlinked(root)
    created = False
    if create:
        try:
            root.mkdir(parents=True, mode=0o700)
            created = True
        except FileExistsError:
            if not root.is_dir():
                raise MemberRegistrationError('registration_root_not_directory') from None
    elif not root.is_dir():
        raise MemberRegistrationError('registration_root_not_directory')
    if os.name != 'nt':
        info = root.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise MemberRegistrationError('registration_root_permissions')
        return
    # Change ACL only on the new, still-empty directory. Existing roots must
    # already be private; never repair an unknown shared directory in place.
    script = r"""
$ErrorActionPreference='Stop';$env:PSModulePath=(Join-Path $PSHOME 'Modules')
$root=__ROOT__
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$allowed=@($identity.User.Value,'S-1-5-18','S-1-5-32-544')
__MEMBER_ACL__
if(__CREATE__){
 $acl=[Security.AccessControl.DirectorySecurity]::new()
 $acl.SetOwner($identity.User);$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in $allowed){
  $principal=[Security.Principal.SecurityIdentifier]::new($sid)
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
 }
 Set-Acl -LiteralPath $root -AclObject $acl
}
$acl=Get-Acl -LiteralPath $root
if(-not $acl.AreAccessRulesProtected){throw 'Unprotected root'}
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Unknown owner'}
foreach($rule in $acl.Access){
 if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Other reader or writer'}
}
"""
    script = script.replace('__ROOT__', "'" + str(root).replace("'", "''") + "'")
    script = script.replace('__MEMBER_ACL__', _managed_worker_acl(root))
    script = script.replace('__CREATE__', '$true' if created else '$false')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise MemberRegistrationError('registration_root_permissions')


def _check_private_file(path: Path) -> None:
    """Existing credentials must not gain readers through a file-specific ACL."""
    _unlinked(path)
    if not path.exists():
        return
    if os.name != 'nt':
        info = path.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise MemberRegistrationError('registration_file_permissions')
        return
    script = r"""$ErrorActionPreference='Stop';$env:PSModulePath=(Join-Path $PSHOME 'Modules');$p=__PATH__
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$who=$identity.User.Value
$allowed=@($who,'S-1-5-18','S-1-5-32-544');$acl=Get-Acl -LiteralPath $p
__MEMBER_ACL__
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Unknown file owner'}
foreach($rule in $acl.Access){if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Other reader or writer'}}
""".replace('__PATH__', "'" + str(path).replace("'", "''") + "'")
    script = script.replace('__MEMBER_ACL__', _managed_worker_acl(path))
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise MemberRegistrationError('registration_file_permissions')


@contextmanager
def _exclusive(root: Path):
    path = root / 'registration.lock'
    _check_private_file(path)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        if os.name == 'nt':
            import msvcrt
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise MemberRegistrationError('registration_already_running') from None
        else:
            import fcntl
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise MemberRegistrationError('registration_already_running') from None
        locked = True
        yield
    finally:
        if locked and os.name == 'nt':
            import msvcrt
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        os.close(descriptor)


def _publish(path: Path, data: bytes, *, expected: bytes | None = None, maximum: int = 16384) -> None:
    if not 1 <= maximum <= 262144 or len(data) > maximum:
        raise MemberRegistrationError('publication_size_exceeded')
    _check_private_file(path)
    fd, name = tempfile.mkstemp(prefix='registration-', suffix='.tmp', dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if expected is None:
            if os.name == 'nt':
                # Native rename refuses an existing target and is atomic. Unlike
                # link/unlink it cannot leave two secret links after process exit.
                os.rename(temp, path)
            else:
                os.link(temp, path)  # POSIX no-clobber fallback; not Windows acceptance.
        else:
            if _read_bytes(path, maximum=maximum) != expected:
                raise MemberRegistrationError('registration_journal_changed')
            # Same-directory replace; retry only bounded Windows sharing failures.
            deadline = time.monotonic() + 3
            while True:
                try:
                    os.replace(temp, path)
                    break
                except OSError as exc:
                    if getattr(exc, 'winerror', None) not in {5, 32} or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
    finally:
        temp.unlink(missing_ok=True)


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')


def _post_exchange(origin: str, payload: dict, *, timeout_s: float = 10) -> dict:
    return _post_management(origin, payload, path=EXCHANGE_PATH, timeout_s=timeout_s)


def _post_management(origin: str, payload: dict, *, path: str, timeout_s: float = 10) -> dict:
    """Only fixed enrollment operations; never an arbitrary HTTP client."""
    from .ssh_identity import TRANSPORT_PATH
    from .member_worker_root_contract import ROOT_PATH
    from .member_relay import RELAY_PATH
    from .member_admission import OFFER_PATH, CONSENT_PATH, STATUS_PATH
    from .member_ssh_bootstrap import BOOTSTRAP_PATH
    from .member_ssh_access import ACCESS_PATH
    if path not in {EXCHANGE_PATH, TRANSPORT_PATH, ROOT_PATH, RELAY_PATH, OFFER_PATH, CONSENT_PATH, STATUS_PATH, BOOTSTRAP_PATH, ACCESS_PATH}:
        raise MemberRegistrationError('invalid_registration_endpoint')
    body = _json_bytes(payload)
    if len(body) > 16384:
        raise MemberRegistrationError('registration_request_too_large')
    url = urlsplit(https_origin(origin))
    if not 0.1 <= timeout_s <= 60:
        raise MemberRegistrationError('invalid_registration_timeout')
    connection = http.client.HTTPSConnection(url.hostname, url.port or 443,
        context=ssl.create_default_context(), timeout=timeout_s)
    timer = None
    response = None
    try:
        connection.connect()  # OS DNS resolution is not a wall-clock SLA claim.
        transport_socket = connection.sock
        def abort():
            try:
                transport_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        # Includes headers AND trickling body. Closing only the connection object
        # would not necessarily interrupt an HTTPResponse holding its own reader.
        timer = threading.Timer(timeout_s, abort)
        timer.daemon = True
        timer.start()
        connection.request('POST', path, body=body,
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            if response.status in {400, 401, 403, 409, 422}:
                raise MemberRegistrationError('registration_rejected')
            raise MemberRegistrationError('registration_response_unavailable')
        if response.getheader('Content-Type', '').split(';', 1)[0].lower() != 'application/json':
            raise MemberRegistrationError('invalid_registration_response')
        body = response.read(16385)
        if len(body) > 16384:
            raise MemberRegistrationError('registration_response_too_large')
        return _json_document(body)
    except ssl.SSLCertVerificationError:
        raise MemberRegistrationError('registration_tls_verification_failed') from None
    except (OSError, http.client.HTTPException, ValueError, RecursionError):
        raise MemberRegistrationError('registration_connection_failed_retry_same_invitation') from None
    finally:
        if timer is not None:
            timer.cancel()
            timer.join(timeout=1)
        if response is not None:
            response.close()
        connection.close()


def _facts() -> DeviceFacts:
    import psutil
    from .service import PACKAGE_VERSION
    return DeviceFacts(hostname=socket.gethostname(), total_cpus=psutil.cpu_count(logical=True) or 1,
        total_memory_mb=int(psutil.virtual_memory().total / (1024 * 1024)), package_version=PACKAGE_VERSION)


def register_member(invitation_path: Path, *, state_root: Path | None = None,
                    expected_invitation_sha256: str | None = None) -> dict:
    """One bounded exchange; repeat this command after any uncertain response."""
    try:
        raw = _read_bytes(Path(invitation_path))
        invitation = MemberInvitation.model_validate(_json_document(raw))
    except (OSError, ValidationError, ValueError, RecursionError):
        raise MemberRegistrationError('invalid_member_invitation') from None
    if expected_invitation_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_invitation_sha256:
        raise MemberRegistrationError('invitation_changed_after_confirmation')
    if state_root is None:
        from .node import default_node_root
        state_root = default_node_root() / 'member-registration'
    root = Path(state_root).absolute()
    _private_directory(root)
    fingerprint = hashlib.sha256(_json_bytes(invitation.private_document())).hexdigest()
    journal_path = root / 'registration.json'
    token_path = root / 'machine-token'
    with _exclusive(root):
        for file in (journal_path, token_path):
            _check_private_file(file)
        reused_identity = journal_path.exists()
        if journal_path.exists():
            try:
                journal_raw = _read_bytes(journal_path)
                journal = _json_document(journal_raw)
                if (set(journal) != {'schema_version', 'invitation_sha256', 'state', 'request', 'receipt'}
                        or journal['schema_version'] != 1 or journal['invitation_sha256'] != fingerprint
                        or journal['state'] not in {'prepared', 'registered'}):
                    raise ValueError('conflicting journal')
                request = MemberExchangeRequest.model_validate(journal['request'])
                if (request.enrollment_id != invitation.enrollment_id
                        or request.enrollment_code != invitation.enrollment_code):
                    raise ValueError('conflicting invitation')
                if journal['state'] == 'registered':
                    previous = MemberRegistrationReceipt.model_validate(journal['receipt'])
                    if (previous.request_sha256 != request.request_hash()
                            or previous.machine_id != invitation.machine_id
                            or previous.owner_user_id != invitation.owner_user_id
                            or previous.enrollment_id != invitation.enrollment_id):
                        raise ValueError('conflicting saved receipt')
                elif journal['receipt'] is not None:
                    raise ValueError('unexpected prepared receipt')
            except (OSError, ValueError, KeyError, TypeError, RecursionError):
                raise MemberRegistrationError('registration_state_requires_review') from None
        else:
            if token_path.exists():
                raise MemberRegistrationError('existing_credential_without_journal')
            request = MemberExchangeRequest(enrollment_id=invitation.enrollment_id,
                enrollment_code=invitation.enrollment_code, device_credential=secrets.token_urlsafe(32), facts=_facts())
            journal = {'schema_version': 1, 'invitation_sha256': fingerprint, 'state': 'prepared',
                       'request': request.private_document(), 'receipt': None}
            journal_raw = _json_bytes(journal)
            _publish(journal_path, journal_raw)
        credential = request.device_credential.get_secret_value().encode('ascii') + b'\n'
        if token_path.exists():
            if _read_bytes(token_path) != credential:
                raise MemberRegistrationError('registration_credential_conflict')
        else:
            _publish(token_path, credential)
        # Verify both surviving files before consuming the one-time authority.
        if _read_bytes(journal_path) != journal_raw or _read_bytes(token_path) != credential:
            raise MemberRegistrationError('registration_state_changed')
        result = _post_exchange(invitation.control_plane_url, request.private_document())
        try:
            receipt = MemberRegistrationReceipt.model_validate(result)
            if (receipt.machine_id != invitation.machine_id or receipt.owner_user_id != invitation.owner_user_id
                    or receipt.enrollment_id != invitation.enrollment_id or receipt.request_sha256 != request.request_hash()):
                raise ValueError('wrong receipt binding')
        except (ValueError, ValidationError):
            raise MemberRegistrationError('registration_receipt_mismatch') from None
        journal['state'] = 'registered'
        journal['receipt'] = receipt.model_dump(mode='json')
        updated = _json_bytes(journal)
        if updated != journal_raw:
            _publish(journal_path, updated, expected=journal_raw)
        return {**receipt.model_dump(mode='json'), 'machine_token_file': str(token_path),
                'state_root': str(root), 'reused_local_identity': reused_identity,
                'message': '设备登记已确认；机器验收、隧道与运行时配置尚待完成，未授权计算。'}
