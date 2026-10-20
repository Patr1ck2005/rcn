"""Install the already-approved sealed runtime locally, at zero capacity.

No rebuilding, downloads, scientific package installation, center database or
implicit task start. Installation is serialized with the original member setup.
Only the original release archive is accepted; test fixtures replace the pin,
never expose a command-line bypass. A completed installation is read-only.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import subprocess
import zipfile

from . import member_registration as storage, member_worker_root as worker
from . import member_admission_client as identity
from .member_worker_root_contract import KEY_RELATIVE, TOKEN_RELATIVE, manifest_hash
from .models import MachineExecutionConfig
from .runtime_policy import STABLE_RUNTIME_VERSION

# Release identity is supplied only by the local operator approval descriptor.
APPROVED_ARCHIVE_SHA256 = ""  # No archive is approved by the public source distribution.
JOURNAL = 'member-runtime.json'
CONFIG = 'agent/machine.json'
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_FILE = 262144


def _fail(code: str):
    raise storage.MemberRegistrationError(code)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def approved_runtime(path: Path, *, release_descriptor=None) -> dict[str, bytes]:
    """Read one bounded snapshot; validate names BEFORE any filesystem writes."""
    from .member_release_catalog import approved_release_descriptor
    release = approved_release_descriptor(release_descriptor).require_configured()
    version, archive_sha = release.runtime_version, release.archive_sha256
    storage._unlinked(path)
    with path.open('rb') as stream:
        raw = stream.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE or _sha(raw) != archive_sha:
        _fail('member_runtime_release_not_approved')
    return validate_runtime_archive(raw, release=release)


def validate_runtime_archive(raw: bytes, *, release) -> dict[str, bytes]:
    """Validate a single pinned snapshot without consulting policy or writing files."""
    if len(raw) > MAX_ARCHIVE or _sha(raw) != release.archive_sha256:
        _fail('member_runtime_release_not_approved')
    version = release.runtime_version
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= 2048 or sum(i.file_size for i in infos) > MAX_EXPANDED:
                raise ValueError('archive bounds')
            files = {}
            folded = set()
            for item in infos:
                name = item.orig_filename
                parts = name.split('/')
                mode = (item.external_attr >> 16) & 0o170000
                if (item.is_dir() or item.file_size > MAX_FILE or mode not in {0, 0o100000}
                        or item.flag_bits & 1 or name != item.filename or '\\' in name
                        or any(not p or p in {'.', '..'} or p.endswith((' ', '.'))
                            or re.search(r'[<>:"|?*\x00-\x1f]', p)
                            or re.fullmatch(r'(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', p, re.I)
                            for p in parts) or name.casefold() in folded):
                    raise ValueError('unsafe archive path')
                folded.add(name.casefold())
                files[name] = archive.read(item)
            description = storage._json_document(files['runtime-manifest.json'])
            if (description.get('schema_version') != 1 or type(description.get('schema_version')) is not int
                    or description.get('version') != version
                    or not isinstance(description.get('files'), dict)
                    or description['files'].get('__runtime_layout_version__') != '2'):
                raise ValueError('wrong runtime identity')
            expected = {'runtime-manifest.json'}
            for name, digest in description['files'].items():
                if name == '__runtime_layout_version__':
                    continue
                if name.startswith('workbench/'):
                    target = 'workbench-src/research_agent_workbench/' + name[len('workbench/'):]
                elif name.startswith('remote-agent/'):
                    target = name
                else:
                    raise ValueError('unexpected manifest path')
                if (target in expected or not target.endswith('.py')
                        or not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest)
                        or target not in files or _sha(files[target]) != digest):
                    raise ValueError('manifest hash mismatch')
                expected.add(target)
            required = {'remote-agent/supervisor.py', 'remote-agent/remote_metrics.py',
                        'remote-agent/windows_job.py', 'remote-agent/worker_storage.py',
                        'remote-agent/member_session_gate.py'}
            # The original build_runtime_package fingerprints Python sources but
            # _copy_selected_tree also carries package resources. Their trust is
            # supplied by the exact approved whole-archive SHA, not a new manifest.
            extras = set(files) - expected
            if (not required.issubset(files) or any(
                    not name.startswith(('remote-agent/', 'workbench-src/research_agent_workbench/'))
                    or name.lower().endswith(('.py', '.pyw', '.pyc', '.pyo')) for name in extras)):
                raise ValueError('runtime file inventory mismatch')
            if _sha(files['remote-agent/supervisor.py']) != release.supervisor_sha256:
                raise ValueError('supervisor identity mismatch')
            return files
    except (KeyError, ValueError, TypeError, zipfile.BadZipFile, RuntimeError):
        _fail('member_runtime_archive_invalid')


def _interpreter(root: Path, *, execution_identity=None) -> Path:
    """Use the same public installer's interpreter, never system/user Python."""
    path = root.parent / 'runtime/python/python.exe'
    storage._unlinked(path)
    if execution_identity is None and (path != Path(sys.executable).absolute() or sys.version_info[:3] != (3, 11, 9)):
        _fail('member_runtime_requires_installer_python')
    if execution_identity is not None:
        from .member_execution_identity import observe_identity
        actual = observe_identity(execution_identity['root_uuid'], owner_sid=execution_identity['owner_sid'])
        if actual != execution_identity or str(root) != actual['worker_root'] or not path.is_file():
            _fail('member_runtime_execution_identity_changed')
    for parent in (path.parent, path.parent.parent):
        storage._unlinked(parent)
    return path


def _verify_tree(directory: Path, files: dict[str, bytes], *, staging=False):
    storage._private_directory(directory, create=False)
    allowed = set(files) | set(worker._directories(files))
    if staging:
        allowed |= {name + '.rcn-preparing' for name in files}
    for base, dirs, leaves in os.walk(directory, followlinks=False):
        for name in dirs + leaves:
            path = Path(base) / name
            storage._unlinked(path)
            if path.relative_to(directory).as_posix() not in allowed:
                _fail('member_runtime_unowned_content')
    if not staging:
        for name, raw in files.items():
            path = directory / name
            storage._check_private_file(path)
            if not path.is_file() or storage._read_bytes(path, maximum=MAX_FILE) != raw:
                _fail('member_runtime_installed_bytes_changed')


def _lock_runtime_tree(directory: Path, *, apply: bool) -> dict:
    """Keep sealed version bytes readable/executable but non-writable to the member."""
    if os.name!='nt':
        _fail('member_runtime_requires_windows')
    storage._unlinked(directory)
    if not directory.is_dir():
        _fail('member_runtime_published_directory_missing')
    from .member_ssh_service import _powershell
    literal=str(directory).replace("'","''")
    script=r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$env:PSModulePath=(Join-Path $PSHOME 'Modules')
$root='__ROOT__';$apply=__APPLY__
if($apply){
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class RcnRuntimeDaclOnly {
 [DllImport("advapi32.dll", SetLastError=true)]
 static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint="SetNamedSecurityInfoW")]
 static extern uint SetNamedSecurityInfo(string path, int kind, uint information,
     IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
 public static void Set(string path, byte[] descriptor) {
  GCHandle pinned=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
  try {
   bool present, defaulted; IntPtr dacl;
   if(!GetSecurityDescriptorDacl(pinned.AddrOfPinnedObject(),out present,out dacl,out defaulted))
       throw new Win32Exception(Marshal.GetLastWin32Error());
   if(!present || dacl==IntPtr.Zero) throw new InvalidOperationException("A protected non-null DACL is required");
   // DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
   // No owner, group, SACL, token privilege, or machine-wide policy mutation.
   uint result=SetNamedSecurityInfo(path,1,0x80000004u,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero);
   if(result!=0) throw new Win32Exception((int)result);
  } finally { pinned.Free(); }
 }
}
'@
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$member=$identity.User
$allowed=@($member.Value,'S-1-5-18','S-1-5-32-544')
$writeMask=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
$items=@(Get-Item -LiteralPath $root -Force)+@(Get-ChildItem -LiteralPath $root -Recurse -Force)
foreach($item in $items){
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked runtime item'}
 if($apply){
  if($item.PSIsContainer){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit='ContainerInherit,ObjectInherit'}else{$acl=[Security.AccessControl.FileSecurity]::new();$inherit='None'}
  $acl.SetAccessRuleProtection($true,$false)
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($member,'ReadAndExecute',$inherit,'None','Allow'))
  foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl',$inherit,'None','Allow'))}
  [RcnRuntimeDaclOnly]::Set($item.FullName,$acl.GetSecurityDescriptorBinaryForm())
 }
 $seen=Get-Acl -LiteralPath $item.FullName
 if(-not $seen.AreAccessRulesProtected -or $seen.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Runtime ACL identity changed'}
 foreach($rule in $seen.Access){
  $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  if($rule.AccessControlType -eq 'Allow' -and $sid -notin $allowed){throw 'Foreign runtime access'}
  if($rule.AccessControlType -eq 'Allow' -and $sid -eq $member.Value -and ([int64]$rule.FileSystemRights -band [int64]$writeMask)){throw 'Member runtime remains writable'}
 }
}
@{schema_version=1;item_count=$items.Count;member_sid=$member.Value;member_write=$false}|ConvertTo-Json -Compress
'''.replace('__ROOT__',literal).replace('__APPLY__','$true' if apply else '$false')
    result=subprocess.run([_powershell(),'-NoProfile','-NonInteractive','-Command',script],
        capture_output=True,timeout=60,check=False)
    try:
        value=storage._json_document(result.stdout)
        if (result.returncode or set(value)!={'schema_version','item_count','member_sid','member_write'}
                or type(value['schema_version']) is not int or value['schema_version']!=1
                or type(value['item_count']) is not int or value['item_count']<2
                or value['member_write'] is not False
                or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',value['member_sid'])):
            raise ValueError('runtime ACL receipt invalid')
        return value
    except (ValueError,TypeError,KeyError,json.JSONDecodeError):
        _fail('member_runtime_readonly_acl_unconfirmed')


def install_member_runtime(invitation_path: Path, *, state_root: Path,
        expected_invitation_sha256: str, runtime_archive: Path, accept_runtime: bool = False,
        release_descriptor=None, execution_identity=None) -> dict:
    """Atomic new-version installation; repeat verifies, never resets live config."""
    if accept_runtime is not True:
        _fail('member_runtime_consent_required')
    if os.name != 'nt':
        _fail('member_runtime_requires_windows')
    try:
        files = approved_runtime(Path(runtime_archive), release_descriptor=release_descriptor)
        from .member_release_catalog import approved_release_descriptor
        release = approved_release_descriptor(release_descriptor).require_configured()
        version, archive_sha = release.runtime_version, release.archive_sha256
        if release.owner_session_required and execution_identity is None:
            _fail('member_runtime_execution_identity_required')
        source = Path(state_root).absolute()
        storage._private_directory(source, create=False)
        with storage._exclusive(source):
            c = identity._context(Path(invitation_path), source, expected_invitation_sha256)
            interpreter = _interpreter(c.root) if execution_identity is None else _interpreter(c.root, execution_identity=execution_identity)
            # Root exchange rechecks current authorization, including on recovery.
            receipt = worker._exchange(c.invitation, c.descriptor, c.key, c.credential, c.root / KEY_RELATIVE)
            if receipt != worker._receipt(storage._json_document(c.root_raw)['receipt'], c.descriptor):
                _fail('member_runtime_root_receipt_changed')
            identity._unchanged(c)
            destination = c.root / 'agent/versions' / version
            stage = destination.with_name('.member-install-' + version)
            config_path = c.root / CONFIG
            journal = source / JOURNAL
            storage._check_private_file(journal)
            old = storage._read_bytes(journal) if journal.exists() else None
            binding = {'machine_id': c.receipt.machine_id, 'root_uuid': c.descriptor['root_uuid'],
                'root_manifest_sha256': manifest_hash(c.descriptor), 'runtime_version': version,
                'archive_sha256': archive_sha, 'python_executable': str(interpreter)}
            state = storage._json_document(old) if old is not None else None
            if state is None:
                # Never turn an established/live root into an installation target.
                if any(p.exists() for p in (destination, stage, config_path,
                        c.root/'agent/status.json', c.root/'spool', c.root/'runs')):
                    _fail('member_runtime_existing_installation_requires_migration')
                config = MachineExecutionConfig(machine_id=c.receipt.machine_id, remote_root=str(c.root),
                    root_uuid=c.descriptor['root_uuid'], python_executable=str(interpreter),
                    runtime_version=version, enabled=False, max_concurrent_units=1,
                    target_concurrent_units=0, supervisor_startup='logon',
                    control_plane_heartbeat_url=c.invitation.control_plane_url,
                    machine_token_file=str(c.root/TOKEN_RELATIVE),
                    tunnel_task_name='RCN-Member-' + c.descriptor['root_uuid'])
                state = {'schema_version': 1, 'phase': 'installing', 'binding': binding,
                         'config': config.model_dump(mode='json'),
                         'created_at': datetime.now(timezone.utc).isoformat()}
                old = storage._json_bytes(state)
                storage._publish(journal, old)
            if (set(state) != {'schema_version','phase','binding','config','created_at'}
                    or type(state['schema_version']) is not int or state['schema_version'] != 1
                    or state['phase'] not in {'installing','installed'} or state['binding'] != binding):
                _fail('member_runtime_journal_changed')
            config = MachineExecutionConfig.model_validate(state['config'])
            if (config.machine_id != binding['machine_id'] or config.root_uuid != binding['root_uuid']
                    or config.remote_root != str(c.root) or config.python_executable != str(interpreter)
                    or config.runtime_version != version or config.enabled
                    or config.max_concurrent_units != 1 or config.target_concurrent_units != 0
                    or config.control_plane_heartbeat_url != c.invitation.control_plane_url
                    or config.machine_token_file != str(c.root/TOKEN_RELATIVE)):
                _fail('member_runtime_config_changed')
            if state['phase'] == 'installing':
                if (c.root/'agent/status.json').exists():
                    _fail('member_runtime_installation_has_running_state')
                storage._private_directory(destination.parent)
                if not destination.exists():
                    storage._private_directory(stage)
                    _verify_tree(stage, files, staging=True)
                    for name in worker._directories(files):
                        storage._private_directory(stage/name)
                    for name, raw in files.items():
                        worker._publish_leaf(stage/name, raw, maximum=MAX_FILE)
                    _verify_tree(stage, files)
                    identity._unchanged(c)
                    os.rename(stage, destination)  # Windows atomic no-replacement.
                elif stage.exists():
                    _fail('member_runtime_publication_conflict')
                _verify_tree(destination, files)
                worker._publish_leaf(config_path, storage._json_bytes(state['config']), maximum=MAX_FILE)
                if execution_identity is None:
                    _lock_runtime_tree(destination,apply=True)
                else:
                    from .member_execution_identity import lock_runtime_tree
                    lock_runtime_tree(execution_identity, destination, state_root=source/'native-runtime-lock')
                identity._unchanged(c)
                state['phase'] = 'installed'
                storage._publish(journal, storage._json_bytes(state), expected=old)
            else:
                if stage.exists() or not destination.is_dir():
                    _fail('member_runtime_published_directory_missing')
                _verify_tree(destination, files)
                storage._check_private_file(config_path)
                if execution_identity is None:
                    _lock_runtime_tree(destination,apply=False)
                current = MachineExecutionConfig.model_validate(storage._json_document(storage._read_bytes(config_path)))
                if any(getattr(current, k) != getattr(config, k) for k in (
                        'machine_id','root_uuid','remote_root','python_executable','runtime_version',
                        'machine_token_file','control_plane_heartbeat_url')):
                    _fail('member_runtime_live_identity_changed')
                # An accepted configuration may change capacity; do not overwrite it.
            identity._unchanged(c)
            return {'worker_runtime_installed': True, 'runtime_version': version,
                    'runtime_archive_sha256': archive_sha, 'worker_root': str(c.root),
                    'supervisor_config_path': str(config_path), 'python_executable': str(interpreter),
                    'runtime_directory': str(destination), 'configuration_preserved': True,
                    'supervisor_started': False, 'heartbeat_verified': False, 'grants_execution': False,
                    **({'execution_identity': execution_identity} if execution_identity is not None else {})}
    except storage.MemberRegistrationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        _fail('member_runtime_installation_unconfirmed_preserve_state')
