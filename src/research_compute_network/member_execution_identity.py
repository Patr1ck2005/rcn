"""Reviewed native provisioning for one dedicated standard execution identity.

Public helpers contain no password. Password generation, DPAPI machine recovery
and Password-logon Task Scheduler registration happen only inside the elevated
Windows helper. Member Python is never executed as administrator.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import tempfile
from uuid import UUID
from xml.etree import ElementTree as ET

from . import member_registration as storage
from .member_tunnel_identity import member_sid

IDENTITY = "execution-identity.json"
NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def _uuid(value):
    if str(UUID(value)) != value:
        raise ValueError("member_root_uuid_invalid")
    return value


def current_owner():
    from .member_ssh_service import _powershell
    script = r"""$ErrorActionPreference='Stop';$env:PSModulePath=(Join-Path $PSHOME 'Modules');$i=[Security.Principal.WindowsIdentity]::GetCurrent()
$u=Get-LocalUser -SID $i.User
@{sid=$u.SID.Value;username=$u.Name;enabled=[bool]$u.Enabled;administrator=(@($i.Groups|Where-Object {$_.Value -eq 'S-1-5-32-544'}).Count -gt 0)}|ConvertTo-Json -Compress
"""
    result = subprocess.run([_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, timeout=15, check=False)
    if result.returncode or len(result.stdout) > 4096:
        raise storage.MemberRegistrationError("member_owner_local_account_unavailable")
    value = storage._json_document(result.stdout)
    member_sid(value["sid"])
    if value.get("enabled") is not True or type(value.get("administrator")) is not bool:
        raise storage.MemberRegistrationError("member_owner_local_account_unavailable")
    return value


def member_root(root_uuid):
    _uuid(root_uuid)
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ResearchComputeNetwork" / "Members" / root_uuid


def _public_spec(root_uuid, owner):
    root = member_root(root_uuid)
    member_sid(owner["sid"])
    return {"root_uuid": root_uuid, "owner_sid": owner["sid"],
        "username": "rcn_" + root_uuid.replace("-", "")[:12], "member_root": str(root),
        "worker_root": str(root / "worker")}


def _elevate(spec, body, state_root):
    from .member_ssh_service import run_elevated_snapshot
    root = Path(state_root)
    storage._private_directory(root)
    script = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';\n$c='" +
        json.dumps(spec, separators=(",", ":")).replace("'", "''") + "'|ConvertFrom-Json\n" + NATIVE_COMMON + body).encode("utf-8-sig")
    digest = hashlib.sha256(script).hexdigest()
    helper = root / ("native-" + digest + ".ps1")
    if not helper.exists():
        storage._publish(helper, script, maximum=262144)
    elif storage._read_bytes(helper, maximum=262144) != script:
        raise storage.MemberRegistrationError("member_identity_helper_changed")
    result = run_elevated_snapshot(helper, script, timeout_s=300)
    if result.returncode:
        raise storage.MemberRegistrationError("member_identity_native_unconfirmed_preserve_state")


def install_identity(root_uuid, *, owner=None, state_root, accept_install=False):
    if accept_install is not True:
        raise storage.MemberRegistrationError("member_execution_identity_consent_required")
    owner = current_owner() if owner is None else owner
    if current_owner()["sid"] != owner["sid"]:
        raise storage.MemberRegistrationError("member_execution_owner_changed")
    spec = _public_spec(root_uuid, owner)
    _elevate(spec, INSTALL, state_root)
    return observe_identity(root_uuid, owner_sid=owner["sid"])


def observe_identity(root_uuid, *, owner_sid=None):
    path = member_root(root_uuid) / IDENTITY
    storage._unlinked(path)
    value = storage._json_document(storage._read_bytes(path))
    expected = _public_spec(root_uuid, {"sid": value.get("owner_sid")})
    if (set(value) != set(expected) | {"schema_version", "execution_sid"}
            or value.get("schema_version") != 1 or any(value[k] != v for k, v in expected.items())
            or owner_sid is not None and value["owner_sid"] != owner_sid):
        raise storage.MemberRegistrationError("member_execution_identity_changed")
    member_sid(value["execution_sid"])
    from .member_ssh_service import _powershell
    script = "$ErrorActionPreference='Stop';$env:PSModulePath=(Join-Path $PSHOME 'Modules');$p='" + str(path).replace("'", "''") + "';$c=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json\n" + OBSERVE
    result = subprocess.run([_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, timeout=15, check=False)
    if result.returncode or len(result.stdout) > 4096:
        raise storage.MemberRegistrationError("member_execution_identity_unconfirmed")
    observed = storage._json_document(result.stdout)
    if observed != {"sid": value["execution_sid"], "enabled": True, "administrator": False}:
        raise storage.MemberRegistrationError("member_execution_account_changed")
    return value


def _task_xml(identity, xml):
    identity = _validated(identity)
    tree = ET.fromstring(xml)
    principals = tree.findall("{" + NS + "}Principals/{" + NS + "}Principal")
    if len(principals) != 1:
        raise ValueError("member_execution_task_principal_invalid")
    principal = principals[0]
    principal.find("{" + NS + "}UserId").text = identity["execution_sid"]
    logon = principal.find("{" + NS + "}LogonType")
    if logon is None:
        logon = ET.SubElement(principal, "{" + NS + "}LogonType")
    logon.text = "Password"
    principal.find("{" + NS + "}RunLevel").text = "LeastPrivilege"
    for trigger in tree.findall("{" + NS + "}Triggers/{" + NS + "}LogonTrigger"):
        trigger.find("{" + NS + "}UserId").text = identity["owner_sid"]
    return ET.tostring(tree, encoding="unicode")


def _validated(identity):
    if not isinstance(identity, dict):
        raise ValueError("member_execution_identity_invalid")
    expected = _public_spec(identity["root_uuid"], {"sid": identity["owner_sid"]})
    member_sid(identity["execution_sid"])
    if identity != {**expected, "schema_version": 1, "execution_sid": identity["execution_sid"]}:
        raise ValueError("member_execution_identity_invalid")
    return identity


def register_execution_task(identity, task_name, xml, *, state_root, start=False):
    identity = _validated(identity)
    if not re.fullmatch(r"RCN-Member-" + re.escape(identity["root_uuid"]) + r"(?:-(?:Supervisor|Guard|RecoveryRequest))?", task_name):
        raise ValueError("member_execution_task_name_invalid")
    if type(start) is not bool:
        raise ValueError("member_execution_task_start_invalid")
    reviewed = _task_xml(identity, xml)
    spec = {**identity, "task_name": task_name, "xml": reviewed, "start": start}
    _elevate(spec, REGISTER_TASK, state_root)
    return {"task_registered": True, "task_name": task_name, "execution_sid": identity["execution_sid"],
        "owner_logon_sid": identity["owner_sid"], "logon_type": "Password", "launch_requested": start}


def provision_runtime(identity, source_runtime, *, file_hashes, state_root):
    """Copy only the exact public runtime snapshot; no privileged Python execution."""
    identity = _validated(identity)
    source = Path(source_runtime).absolute()
    actual = {}
    for path in source.rglob("*"):
        storage._unlinked(path)
        if path.is_file():
            actual[path.relative_to(source).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != file_hashes or not {"python/python.exe", "python/pythonw.exe"}.issubset(actual):
        raise ValueError("member_public_runtime_snapshot_changed")
    if any(not re.fullmatch(r"[a-f0-9]{64}", sha) or PureWindowsPath(name).is_absolute()
        or ".." in PureWindowsPath(name).parts for name, sha in actual.items()):
        raise ValueError("member_public_runtime_manifest_invalid")
    # Scientific offline closures contain thousands of files. Keep the reviewed
    # helper small; bind its separate public manifest by exact bytes instead.
    manifest = storage._json_bytes(actual)
    digest = hashlib.sha256(manifest).hexdigest()
    manifest_path = Path(state_root)/('runtime-files-'+digest+'.json')
    storage._private_directory(manifest_path.parent)
    if not manifest_path.exists():
        _publish_public_manifest(manifest_path, manifest)
    elif storage._read_bytes(manifest_path, maximum=4194304) != manifest:
        raise ValueError('member_public_runtime_manifest_changed')
    _elevate({**identity, "source_runtime": str(source), 'manifest_path': str(manifest_path),
        'manifest_sha256': digest}, PROVISION, state_root)
    return {"runtime_provisioned": True, "runtime_root": str(Path(identity["member_root"]) / "runtime"),
        "file_count": len(actual), "manifest_sha256": digest}


def _publish_public_manifest(path, raw):
    """Atomic no-replacement publication scoped to large public software hashes."""
    if len(raw) > 4194304:
        raise ValueError('member_public_runtime_manifest_too_large')
    storage._check_private_file(path)
    descriptor, temporary = tempfile.mkstemp(prefix='runtime-files-', suffix='.tmp', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.rename(temporary, path)  # Windows refuses an existing destination.
    finally:
        temporary.unlink(missing_ok=True)


def lock_runtime_tree(identity, directory, *, state_root):
    identity = _validated(identity)
    path = Path(directory).absolute()
    if not path.is_relative_to(Path(identity["worker_root"])/'agent/versions'):
        raise ValueError('member_sealed_runtime_path_invalid')
    _elevate({**identity, 'directory': str(path)}, LOCK_RUNTIME, state_root)
    return {'member_write': False, 'execution_write': False, 'administrator_owned': True}


def finalize_worker_access(identity, *, state_root):
    """Grant the fixed worker access once; give OpenSSH an EXEC-only key copy."""
    identity = _validated(identity)
    from .member_worker_root_contract import KEY_RELATIVE
    key = Path(identity['worker_root'])/KEY_RELATIVE
    key_sha = hashlib.sha256(storage._read_bytes(key)).hexdigest()
    _elevate({**identity, 'key_sha256': key_sha}, WORKER_ACCESS, state_root)
    receipt = storage._json_document(storage._read_bytes(Path(identity['member_root'])/'worker-access.json'))
    if receipt != {'schema_version': 1, 'root_uuid': identity['root_uuid'],
            'execution_sid': identity['execution_sid'], 'key_sha256': key_sha,
            'execution_key_path': str(Path(identity['worker_root'])/'agent/tunnel/execution/member_ed25519')}:
        raise storage.MemberRegistrationError('member_worker_access_unconfirmed')
    return receipt


def run_tunnel_action(identity, installer_path, *, installer_sha256, manifest_sha256,
        action, confirmation=None, state_root):
    """Run one fixed native tunnel action; its task credentials never leave Windows."""
    identity = _validated(identity)
    if action not in {'Preview','Stage','Verify','Rollback','PreviewActivation','Activate','ActivationStatus'}:
        raise ValueError('member_tunnel_action_invalid')
    path = Path(installer_path).absolute()
    expected = Path(identity['worker_root'])/'agent/tunnel/relay-bundle/install-coordinated-tunnel.ps1'
    if path != expected or not re.fullmatch(r'[a-f0-9]{64}', installer_sha256) or not re.fullmatch(r'[a-f0-9]{64}', manifest_sha256):
        raise ValueError('member_tunnel_action_identity_invalid')
    if confirmation is not None and not re.fullmatch(r'[a-f0-9]{64}', confirmation):
        raise ValueError('member_tunnel_confirmation_invalid')
    root = Path(state_root)
    storage._private_directory(root)
    receipt = root/('tunnel-'+action+'.json')
    _elevate({**identity, 'installer_path': str(path), 'installer_sha256': installer_sha256,
        'manifest_sha256': manifest_sha256, 'action': action, 'confirmation': confirmation or '',
        'receipt_path': str(receipt)}, TUNNEL_ACTION, root)
    value = storage._json_document(storage._read_bytes(receipt))
    if not isinstance(value, dict):
        raise storage.MemberRegistrationError('member_tunnel_receipt_invalid')
    return value


def set_owner_pause(identity, paused):
    identity = _validated(identity)
    if type(paused) is not bool or current_owner()["sid"] != identity["owner_sid"]:
        raise ValueError("member_owner_control_identity_invalid")
    path = Path(identity["member_root"]) / "owner-control/state.json"
    with storage._exclusive(path.parent):
        old = storage._read_bytes(path)
        state = storage._json_document(old)
        if (state["root_uuid"] != identity["root_uuid"] or state["owner_sid"] != identity["owner_sid"]
                or state["retired"] and (not paused or state['paused'] is not True)):
            raise ValueError("member_owner_control_changed")
        if state["paused"] != paused:
            state.update(paused=paused, revision=state["revision"] + 1)
            storage._publish(path, storage._json_bytes(state), expected=old)
    return {"paused": paused, "revision": state["revision"], "inflight_drains": True}


def set_owner_retirement(identity, operation_id):
    """Bind the irreversible local drain to the already accepted center intent."""
    identity = _validated(identity)
    _uuid(operation_id)
    if current_owner()['sid'] != identity['owner_sid']:
        raise ValueError('member_owner_control_identity_invalid')
    path = Path(identity['member_root'])/'owner-control/state.json'
    with storage._exclusive(path.parent):
        old = storage._read_bytes(path)
        state = storage._json_document(old)
        if state['root_uuid'] != identity['root_uuid'] or state['owner_sid'] != identity['owner_sid']:
            raise ValueError('member_owner_control_changed')
        if state.get('retirement_operation_id') not in (None, operation_id):
            raise ValueError('member_retirement_operation_changed')
        if not state['retired']:
            state.update(paused=True, retired=True, retirement_operation_id=operation_id,
                revision=state['revision']+1)
            storage._publish(path, storage._json_bytes(state), expected=old)
        elif state.get('retirement_operation_id') != operation_id:
            raise ValueError('member_retirement_operation_changed')
    return {'operation_id': operation_id, 'state': 'draining', 'inflight_drains': True}


def uninstall_member(identity, *, state_root, retirement_receipt=None):
    """Stop new work now; disable owned tasks/account only after original runs drain."""
    identity = _validated(identity)
    if not isinstance(retirement_receipt, dict):
        raise ValueError('member_center_retirement_receipt_required')
    operation_id = _uuid(retirement_receipt.get('operation_id'))
    set_owner_retirement(identity, operation_id)
    if (retirement_receipt.get('schema_version') != 1
            or retirement_receipt.get('root_uuid') != identity['root_uuid']
            or retirement_receipt.get('state') != 'ready_to_uninstall'):
        return {'state': 'draining', 'data_preserved': True, 'account_disabled': False}
    worker = Path(identity["worker_root"])
    status_path = worker / "agent/status.json"
    status = storage._json_document(storage._read_bytes(status_path, maximum=65536)) if status_path.exists() else {}
    if status.get("active_run_ids") or any((worker / "runs/active").glob("*/*/*/.rcn-run.json")):
        return {"state": "draining", "data_preserved": True, "account_disabled": False}
    progress = storage._json_document(storage._read_bytes(worker/'agent/member-retirement.json', maximum=4194304))
    if (progress.get('operation_id') != operation_id or progress.get('root_uuid') != identity['root_uuid']
            or progress.get('machine_id') != retirement_receipt.get('machine_id')
            or progress.get('runtime_version') != retirement_receipt.get('runtime_version')
            or progress.get('active_run_ids') or progress.get('pending_run_ids')):
        return {'state': 'draining', 'data_preserved': True, 'account_disabled': False}
    _elevate({**identity, 'operation_id': operation_id,
        'machine_id': progress['machine_id'], 'runtime_version': progress['runtime_version']}, RETIRE, state_root)
    return {"state": "retired-local", "data_preserved": True, "identity_preserved": True,
        "account_disabled": True, "personal_token_revoked": False, "center_machine_revoked": False}


NATIVE_COMMON = r"""
$env:PSModulePath=(Join-Path $PSHOME 'Modules')
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevation required'}
function Unlinked([string]$p){$q=[IO.Path]::GetFullPath($p);while($q){if((Test-Path -LiteralPath $q) -and ((Get-Item -LiteralPath $q -Force).Attributes -band 1024)){throw 'Linked member path'};$q=[IO.Path]::GetDirectoryName($q)}}
function Protect([string]$p,[string]$ownerRights,[string]$execRights){
 Unlinked $p;$d=Get-Item -LiteralPath $p -Force
 if($d.PSIsContainer){$a=[Security.AccessControl.DirectorySecurity]::new();$inherit='ContainerInherit,ObjectInherit'}else{$a=[Security.AccessControl.FileSecurity]::new();$inherit='None'}
 $a.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$a.SetAccessRuleProtection($true,$false)
 foreach($s in @('S-1-5-18','S-1-5-32-544')){$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s),'FullControl',$inherit,'None','Allow'))}
 if($ownerRights){$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($c.owner_sid),$ownerRights,$inherit,'None','Allow'))}
 if($execRights -and $c.execution_sid){$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($c.execution_sid),$execRights,$inherit,'None','Allow'))}
 Set-Acl -LiteralPath $p -AclObject $a
}
function Save([string]$p,$v){$tmp=$p+'.'+[Guid]::NewGuid().ToString('N')+'.tmp';$raw=[Text.UTF8Encoding]::new($false).GetBytes(($v|ConvertTo-Json -Depth 20 -Compress));$f=[IO.File]::Open($tmp,1,2,0);try{$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()};if(Test-Path -LiteralPath $p){[IO.File]::Replace($tmp,$p,$null)}else{[IO.File]::Move($tmp,$p)}}
function Read([string]$p,[int]$maximum=1048576){Unlinked $p;if((Get-Item -LiteralPath $p).Length -gt $maximum){throw 'Large member state'};return [IO.File]::ReadAllText($p)|ConvertFrom-Json}
function Assert-Identity([bool]$allowDisabled=$false) {
 $v=Read (Join-Path $c.member_root 'execution-identity.json')
 foreach($n in @('root_uuid','owner_sid','execution_sid','username','member_root','worker_root')){if($v.$n -cne $c.$n){throw 'Member identity changed'}}
 $u=Get-LocalUser -SID $c.execution_sid
 if($u.Name -cne $c.username -or (-not $u.Enabled -and -not $allowDisabled) -or $u.Description -cne ('RCN execution '+$c.root_uuid) -or @(Get-LocalGroupMember -SID 'S-1-5-32-544'|Where-Object {$_.SID.Value -eq $c.execution_sid}).Count){throw 'Execution account changed'}
}
"""

INSTALL = r"""
$owner=Get-LocalUser -SID $c.owner_sid;if(-not $owner.Enabled){throw 'Local owner unavailable'}
$expected=Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ResearchComputeNetwork\Members') $c.root_uuid
if($c.member_root -cne $expected -or $c.worker_root -cne (Join-Path $expected 'worker') -or $c.username -cne ('rcn_'+$c.root_uuid.Replace('-','').Substring(0,12))){throw 'Invalid managed root'}
Unlinked $c.member_root
if((Test-Path -LiteralPath $c.member_root) -and -not(Test-Path -LiteralPath (Join-Path $c.member_root 'private\account-recovery.json')) -and @(Get-ChildItem -LiteralPath $c.member_root -Force).Count){throw 'Unowned member root'}
$null=[IO.Directory]::CreateDirectory($c.member_root)
$public=Join-Path $c.member_root 'execution-identity.json';$private=Join-Path $c.member_root 'private';$null=[IO.Directory]::CreateDirectory($private);Protect $private '' ''
$secret=Join-Path $private 'account-recovery.json';$description='RCN execution '+$c.root_uuid
Add-Type -AssemblyName System.Security
$entropy=[Text.Encoding]::UTF8.GetBytes('rcn-member-execution:'+ $c.root_uuid+':'+$c.owner_sid)
if(Test-Path -LiteralPath $secret){$journal=Read $secret;if($journal.root_uuid -cne $c.root_uuid -or $journal.owner_sid -cne $c.owner_sid -or $journal.username -cne $c.username){throw 'Account journal changed'}}else{
 if(Get-LocalUser -Name $c.username -ErrorAction SilentlyContinue){throw 'Unowned account'}
 $random=New-Object byte[] 48;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($random)}finally{$rng.Dispose()}
 $password='Rcn!'+[Convert]::ToBase64String($random)+'7a'
 $encrypted=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($password),$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
 $journal=@{schema_version=1;root_uuid=$c.root_uuid;owner_sid=$c.owner_sid;username=$c.username;password_dpapi=[Convert]::ToBase64String($encrypted)};Save $secret $journal;Protect $secret '' ''
}
$raw=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($journal.password_dpapi),$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
try{$password=[Text.Encoding]::UTF8.GetString($raw);$u=Get-LocalUser -Name $c.username -ErrorAction SilentlyContinue
 if($null -eq $u){$u=New-LocalUser -Name $c.username -Password (ConvertTo-SecureString $password -AsPlainText -Force) -Description $description -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword;Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $u.SID}
 if($u.Description -cne $description -or -not $u.Enabled){throw 'Execution account changed'}
 $c|Add-Member -NotePropertyName execution_sid -NotePropertyValue $u.SID.Value -Force
 if(@(Get-LocalGroupMember -SID 'S-1-5-32-544'|Where-Object {$_.SID.Value -eq $c.execution_sid}).Count){throw 'Execution account is administrator'}
 $value=@{schema_version=1;root_uuid=$c.root_uuid;owner_sid=$c.owner_sid;execution_sid=$c.execution_sid;username=$c.username;member_root=$c.member_root;worker_root=$c.worker_root}
 if(Test-Path -LiteralPath $public){$v=Read $public;foreach($n in $value.Keys){if($v.$n -cne $value[$n]){throw 'Identity record changed'}}}else{Save $public $value}
 Protect $public 'ReadAndExecute' 'ReadAndExecute'
 Protect $c.member_root 'ReadAndExecute,AppendData' 'ReadAndExecute'
 $control=Join-Path $c.member_root 'owner-control';$null=[IO.Directory]::CreateDirectory($control);Protect $control 'FullControl' 'ReadAndExecute'
 $controlPath=Join-Path $control 'state.json'
 if(-not(Test-Path -LiteralPath $controlPath)){Save $controlPath @{schema_version=1;root_uuid=$c.root_uuid;owner_sid=$c.owner_sid;revision=0;paused=$false;retired=$false};Protect $controlPath 'FullControl' 'ReadAndExecute'}
}finally{[Array]::Clear($raw,0,$raw.Length);$password=$null}
"""

OBSERVE = r"""
$a=Get-Acl -LiteralPath $p;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544') -or -not $a.AreAccessRulesProtected){throw 'Unprotected identity'}
$allowed=@('S-1-5-18','S-1-5-32-544',$c.owner_sid,$c.execution_sid)
foreach($r in $a.Access){$sid=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;if($r.AccessControlType -eq 'Allow' -and ($sid -notin $allowed -or ($sid -in @($c.owner_sid,$c.execution_sid) -and ($r.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)))){throw 'Writable identity'}}
$u=Get-LocalUser -SID $c.execution_sid;if($u.Name -cne $c.username -or $u.Description -cne ('RCN execution '+$c.root_uuid)){throw 'Account mismatch'}
@{sid=$u.SID.Value;enabled=[bool]$u.Enabled;administrator=(@(Get-LocalGroupMember -SID 'S-1-5-32-544'|Where-Object {$_.SID.Value -eq $c.execution_sid}).Count -gt 0)}|ConvertTo-Json -Compress
"""

REGISTER_TASK = r"""
Assert-Identity
$tree=[xml]::new();$tree.XmlResolver=$null;$tree.LoadXml($c.xml)
$principal=$tree.SelectSingleNode("//*[local-name()='Principals']/*[local-name()='Principal']")
if($principal.UserId -cne $c.execution_sid -or $principal.LogonType -cne 'Password' -or $principal.RunLevel -cne 'LeastPrivilege'){throw 'Task identity changed'}
$entropy=[Text.Encoding]::UTF8.GetBytes('rcn-member-execution:'+ $c.root_uuid+':'+$c.owner_sid)
Add-Type -AssemblyName System.Security
$secret=Read (Join-Path $c.member_root 'private\account-recovery.json');$raw=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($secret.password_dpapi),$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
$scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect();$folder=$scheduler.GetFolder('\')
function Canonical($text){$x=[xml]::new();$x.XmlResolver=$null;$x.LoadXml($text);foreach($name in @('URI','Author','Date')){foreach($n in @($x.SelectNodes("/*[local-name()='Task']/*[local-name()='RegistrationInfo']/*[local-name()='$name']"))){$null=$n.ParentNode.RemoveChild($n)}};return $x.OuterXml}
try{
 $password=[Text.Encoding]::UTF8.GetString($raw);$task=$null;try{$task=$folder.GetTask($c.task_name)}catch{if($_.Exception.HResult -ne -2147024894){throw}}
 $definition=$scheduler.NewTask(0);$definition.XmlText=$c.xml
 if($null -eq $task){$sddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;'+$c.owner_sid+')';$task=$folder.RegisterTaskDefinition($c.task_name,$definition,34,$c.execution_sid,$password,1,$sddl)}
 if((Canonical $task.Xml) -cne (Canonical $definition.XmlText)){throw 'Existing task changed'}
 if($c.start -and $task.Enabled -and $task.State -ne 4){$null=$task.Run($null)}
}finally{[Array]::Clear($raw,0,$raw.Length);$password=$null}
"""

PROVISION = r"""
Assert-Identity
Unlinked $c.manifest_path
$manifest=[IO.File]::Open($c.manifest_path,3,1,1)
try {
 if($manifest.Length -gt 4194304){throw 'Large public runtime manifest'}
 $h=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($h.ComputeHash($manifest))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
 if($sha -cne $c.manifest_sha256){throw 'Public runtime manifest changed'}
 $manifest.Position=0;$reader=[IO.StreamReader]::new($manifest,[Text.Encoding]::UTF8,$true,4096,$true);try{$files=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
$destination=Join-Path $c.member_root 'runtime';$null=[IO.Directory]::CreateDirectory($destination)
foreach($prop in $files.PSObject.Properties){
 $name=$prop.Name;if($name -match '(^/|\\|(^|/)\.\.(/|$)|:)' -or $prop.Value -notmatch '^[a-f0-9]{64}$'){throw 'Unsafe runtime manifest'}
 $source=Join-Path $c.source_runtime $name;$target=Join-Path $destination $name;Unlinked $source;Unlinked $target
 $f=[IO.File]::Open($source,3,1,1);try{$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};if($actual -cne $prop.Value){throw 'Runtime snapshot changed'}
  if(Test-Path -LiteralPath $target){if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $prop.Value){throw 'Published runtime changed'}}else{
   $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target));$tmp=$target+'.preparing';if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force};$out=[IO.File]::Open($tmp,1,2,0);try{$f.Position=0;$f.CopyTo($out);$out.Flush($true)}finally{$out.Dispose()};[IO.File]::Move($tmp,$target)
  }
 }finally{$f.Dispose()}
}
$expected=@($files.PSObject.Properties.Name)
foreach($file in Get-ChildItem -LiteralPath $destination -Recurse -File -Force){$relative=$file.FullName.Substring($destination.Length+1).Replace('\','/');if($relative -notin $expected){throw 'Unknown published runtime content'}}
foreach($item in @(Get-Item -LiteralPath $destination)+@(Get-ChildItem -LiteralPath $destination -Recurse -Force)){Protect $item.FullName 'ReadAndExecute' 'ReadAndExecute'}
}finally{$manifest.Dispose()}
"""

LOCK_RUNTIME = r"""
Assert-Identity
foreach($item in @(Get-Item -LiteralPath $c.directory)+@(Get-ChildItem -LiteralPath $c.directory -Recurse -Force)){Protect $item.FullName 'ReadAndExecute' 'ReadAndExecute'}
"""

WORKER_ACCESS = r"""
Assert-Identity
$root=$c.worker_root;Unlinked $root
$marker=Read (Join-Path $root '.rcn-root.json');if($marker.root_uuid -cne $c.root_uuid){throw 'Worker root changed'}
$receiptPath=Join-Path $c.member_root 'worker-access.json'
$source=Join-Path $root 'agent\tunnel\member_ed25519';$destination=Join-Path $root 'agent\tunnel\execution\member_ed25519'
if(Test-Path -LiteralPath $receiptPath){
 $receipt=Read $receiptPath
 if($receipt.root_uuid -cne $c.root_uuid -or $receipt.execution_sid -cne $c.execution_sid -or $receipt.key_sha256 -cne $c.key_sha256 -or $receipt.execution_key_path -cne $destination){throw 'Worker access receipt changed'}
 if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $c.key_sha256){throw 'Execution identity key changed'}
 $acl=Get-Acl -LiteralPath $destination;if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $c.execution_sid -or -not $acl.AreAccessRulesProtected){throw 'Execution identity key ACL changed'}
 foreach($r in $acl.Access){if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544',$c.execution_sid)){throw 'Execution key has another reader'}}
 exit 0
}
if((Test-Path -LiteralPath (Join-Path $root 'agent\status.json')) -or (Test-Path -LiteralPath (Join-Path $root 'agent\machine.json'))){throw 'Worker ACL publication requires original unstarted root'}
foreach($item in @(Get-Item -LiteralPath $root)+@(Get-ChildItem -LiteralPath $root -Recurse -Force)){
 if($item.FullName -cne $source -and -not $item.FullName.StartsWith((Split-Path -Parent $destination)+'\',[StringComparison]::OrdinalIgnoreCase)){Protect $item.FullName 'FullControl' 'FullControl'}
}
$f=[IO.File]::Open($source,3,1,1);try{
 $hash=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($hash.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 if($sha -cne $c.key_sha256){throw 'Original member key changed'}
 $dir=Split-Path -Parent $destination;$null=[IO.Directory]::CreateDirectory($dir);Protect $dir '' 'FullControl'
 if(Test-Path -LiteralPath $destination){if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){throw 'Execution identity key changed'}}else{
  $out=[IO.File]::Open($destination,1,2,0);try{$f.Position=0;$f.CopyTo($out);$out.Flush($true)}finally{$out.Dispose()}
 }
}finally{$f.Dispose()}
Protect $destination '' 'FullControl'
Protect $source 'FullControl' ''
# Setting ownership to the standard execution SID requires a process-local
# restore privilege. Enable it only for this known file, then restore the token.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class RcnMemberRestoreOwner {
 [StructLayout(LayoutKind.Sequential)] struct Luid {public uint Low;public int High;}
 [StructLayout(LayoutKind.Sequential)] struct Privilege {public uint Count;public Luid Id;public uint Attributes;}
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid id);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool all,ref Privilege requested,uint size,out Privilege previous,out uint needed);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint SetNamedSecurityInfo(string name,uint kind,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 public static void Set(string path,byte[] sid) {
  IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
  var requested=new Privilege();var previous=new Privilege();uint needed;bool enabled=false;
  try {
   if(!LookupPrivilegeValue(null,"SeRestorePrivilege",out requested.Id))throw new Win32Exception(Marshal.GetLastWin32Error());
   requested.Count=1;requested.Attributes=2;
   if(!AdjustTokenPrivileges(token,false,ref requested,(uint)Marshal.SizeOf(typeof(Privilege)),out previous,out needed))throw new Win32Exception(Marshal.GetLastWin32Error());
   if(Marshal.GetLastWin32Error()==1300)throw new InvalidOperationException("Restore privilege unavailable");enabled=true;
   var pinned=GCHandle.Alloc(sid,GCHandleType.Pinned);try{uint result=SetNamedSecurityInfo(path,1,1,pinned.AddrOfPinnedObject(),IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);if(result!=0)throw new Win32Exception((int)result);}finally{pinned.Free();}
  } finally {if(enabled){Privilege ignored;AdjustTokenPrivileges(token,false,ref previous,0,out ignored,out needed);}CloseHandle(token);}
 }
}
'@
$sid=[Security.Principal.SecurityIdentifier]::new($c.execution_sid);$bytes=New-Object byte[] $sid.BinaryLength;$sid.GetBinaryForm($bytes,0);[RcnMemberRestoreOwner]::Set($destination,$bytes)
$sid=[Security.Principal.SecurityIdentifier]::new($c.owner_sid);$bytes=New-Object byte[] $sid.BinaryLength;$sid.GetBinaryForm($bytes,0);[RcnMemberRestoreOwner]::Set($source,$bytes)
$receipt=@{schema_version=1;root_uuid=$c.root_uuid;execution_sid=$c.execution_sid;key_sha256=$c.key_sha256;execution_key_path=$destination}
Save $receiptPath $receipt;Protect $receiptPath 'ReadAndExecute' 'ReadAndExecute'
"""

TUNNEL_ACTION = r"""
Assert-Identity
Unlinked $c.installer_path
$f=[IO.File]::Open($c.installer_path,3,1,1)
$raw=$null;$global:rcnMemberExecutionPassword=$null
try{
 $hash=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($hash.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 if($sha -cne $c.installer_sha256){throw 'Tunnel installer changed'}
 Add-Type -AssemblyName System.Security
 $journal=Read (Join-Path $c.member_root 'private\account-recovery.json')
 $entropy=[Text.Encoding]::UTF8.GetBytes('rcn-member-execution:'+ $c.root_uuid+':'+$c.owner_sid)
 $raw=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($journal.password_dpapi),$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
 $global:rcnMemberExecutionPassword=[Text.Encoding]::UTF8.GetString($raw)
 $text=& $c.installer_path -Action $c.action -ExpectedManifestSha256 $c.manifest_sha256 -ConfirmationHash $c.confirmation | Out-String
 $value=$text|ConvertFrom-Json;Save $c.receipt_path $value
 # Receipt is public operational state. Permit only the initiating owner to replace it.
 Protect $c.receipt_path 'FullControl' ''
}finally{$f.Dispose();if($raw){[Array]::Clear($raw,0,$raw.Length)};$global:rcnMemberExecutionPassword=$null}
"""

RETIRE = r"""
Assert-Identity $true
$control=Read (Join-Path $c.member_root 'owner-control\state.json');$progress=Read (Join-Path $c.worker_root 'agent\member-retirement.json') 4194304
if(-not $control.retired -or -not $control.paused -or $control.retirement_operation_id -cne $c.operation_id -or $progress.operation_id -cne $c.operation_id -or $progress.machine_id -cne $c.machine_id -or $progress.root_uuid -cne $c.root_uuid -or $progress.runtime_version -cne $c.runtime_version -or @($progress.active_run_ids).Count -or @($progress.pending_run_ids).Count){throw 'Retirement not reconciled'}
$active=Join-Path $c.worker_root 'runs\active';if(Test-Path -LiteralPath $active){if(@(Get-ChildItem -LiteralPath $active -Filter '.rcn-run.json' -Recurse -File).Count){throw 'Work still draining'}}
foreach($suffix in @('','-Supervisor','-Guard','-RecoveryRequest')){$name='RCN-Member-'+$c.root_uuid+$suffix;$task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue;if($task){if($task.Principal.UserId -notin @($c.execution_sid,$c.username)){throw 'Task identity changed'};Disable-ScheduledTask -TaskName $name|Out-Null;if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $name}}}
$serviceName='RCN-Member-'+$c.root_uuid+'-SSHD';$service=Get-Service -Name $serviceName -ErrorAction SilentlyContinue;if($service){if($service.Status -ne 'Stopped'){Stop-Service -Name $serviceName};Set-Service -Name $serviceName -StartupType Disabled}
if((Get-LocalUser -SID $c.execution_sid).Enabled){Disable-LocalUser -SID $c.execution_sid}
"""
