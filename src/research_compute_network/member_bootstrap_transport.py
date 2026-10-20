"""Fixed SSH bootstrap inspection and CAS of ONE root-local config.

No service/task installation, arbitrary remote path, cleanup or runtime change.
Only target=0 -> target=1, enabled=false is permitted for isolated acceptance.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
import time
from pathlib import PureWindowsPath
import re

from . import member_registration as storage
from .member_worker_root_contract import canonical_root
from .models import MachineCommand, MachineControlAction
from .runtime_policy import STABLE_RUNTIME_VERSION
from .schedulers.ssh import OpenSshTransport

SUPERVISOR_SHA256 = ""  # Supplied only by the operator-approved descriptor.
MAX_REPLY = 32768


class BootstrapUnavailable(RuntimeError):
    """Fixed public reason only; native stderr and contents never escape."""


class BootstrapSshTransport(OpenSshTransport):
    """No user/system SSH config, proxy, agent or multiplexed connection reuse."""
    def _ssh_base(self):
        if self.config.ssh_host != '127.0.0.1' or self.identity_file is None:
            raise BootstrapUnavailable('member_bootstrap_fixed_route_required')
        base=super()._ssh_base()
        return [base[0],'-F','none','-S','none','-T','-o','ProxyCommand=none','-o','ProxyJump=none',
                '-o','GlobalKnownHostsFile=none','-o','IdentityAgent=none','-o','HostKeyAlgorithms=ssh-ed25519',*base[1:]]


def _contract(config, nonce):
    if not re.fullmatch(r'[a-f0-9]{32}', nonce):
        raise ValueError('invalid bootstrap challenge')
    root = PureWindowsPath(canonical_root(config.remote_root))
    from .member_release_catalog import release_for_runtime
    release = release_for_runtime(config.runtime_version or STABLE_RUNTIME_VERSION).require_configured()
    return {'root': str(root), 'machine': config.machine_id, 'uuid': config.root_uuid,
            'user': config.ssh_user, 'nonce': nonce, 'runtime': release.runtime_version,
            'python': str(root.parent / 'runtime/python/python.exe'),
            'supervisor_hash': release.supervisor_sha256}


def _script(contract, body):
    literal = storage._json_bytes(contract).decode().strip().replace("'", "''")
    return "$c='" + literal + "'|ConvertFrom-Json\n" + COMMON + body


def _call(transport, script):
    try:
        completed = transport._powershell(script, timeout=25)
        if completed.returncode or len(completed.stdout.encode('utf-8')) > MAX_REPLY:
            raise BootstrapUnavailable('member_bootstrap_remote_unconfirmed')
        value = storage._json_document(completed.stdout.encode('utf-8'))
        if not isinstance(value, dict):
            raise ValueError('invalid response')
        return value
    except BootstrapUnavailable:
        raise
    except Exception:
        raise BootstrapUnavailable('member_bootstrap_remote_unconfirmed') from None


def inspect_bootstrap(transport, config, nonce):
    return _call(transport, _script(_contract(config, nonce), INSPECT))


def activate_bootstrap(transport, config, nonce, before_sha256, desired):
    raw = storage._json_bytes(desired)
    if (len(raw) > 16384 or not re.fullmatch(r'[a-f0-9]{64}', before_sha256)
            or desired.get('enabled') is not False or type(desired.get('target_concurrent_units')) is not int
            or desired['target_concurrent_units'] != 1):
        raise ValueError('invalid bootstrap config snapshot')
    contract = _contract(config, nonce)
    contract.update(before=before_sha256, after=hashlib.sha256(raw).hexdigest(),
                    payload=base64.b64encode(raw).decode('ascii'))
    return _call(transport, _script(contract, ACTIVATE))


def synchronize_bootstrap_capacity(transport, config, *, operation_nonce: str, created_at, expires_at) -> dict:
    """Make the already-running zero-capacity supervisor consume target=1 exactly once."""
    if not re.fullmatch(r'[a-f0-9]{32}', operation_nonce):
        raise ValueError('invalid bootstrap capacity nonce')
    created = datetime.fromisoformat(str(created_at).replace('Z','+00:00'))
    expires = datetime.fromisoformat(str(expires_at).replace('Z','+00:00'))
    now = datetime.now(timezone.utc)
    if created.tzinfo is None or expires.tzinfo is None:
        raise BootstrapUnavailable('member_bootstrap_capacity_authority_expired')
    command = MachineCommand(
        command_id='member-bootstrap-capacity-' + operation_nonce,
        machine_id=config.machine_id,
        action=MachineControlAction.SET_TARGET_CAPACITY,
        root_uuid=config.root_uuid,
        runtime_version=config.runtime_version,
        nonce='member-bootstrap-capacity-' + operation_nonce,
        reason='self-service acceptance capacity',
        target_concurrent_units=1,
        created_at=created,
        expires_at=expires,
    ).model_dump(mode='json')
    expected={'schema_version':1,'command_id':command['command_id'],'machine_id':config.machine_id,
              'action':'set_target_capacity','state':'completed'}
    def validate(value):
        if value is None:return None
        if (not isinstance(value,dict) or any(value.get(k)!=v for k,v in expected.items())
                or value.get('affected_network_runs')!=0 or value.get('affected_comsol_processes')!=0
                or value.get('message')!='target capacity synchronized'):
            raise BootstrapUnavailable('member_bootstrap_capacity_result_changed')
        return value
    existing=validate(transport.read_machine_command_result(command['command_id']))
    if existing is None:
        if expires <= now:
            raise BootstrapUnavailable('member_bootstrap_capacity_authority_expired')
        transport.submit_machine_command(command)
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            existing=validate(transport.read_machine_command_result(command['command_id']))
            if existing is not None:break
            time.sleep(.25)
    if existing is None:
        raise BootstrapUnavailable('member_bootstrap_capacity_pending_retry_same_identity')
    observed=inspect_bootstrap(transport,config,operation_nonce)
    if observed.get('status',{}).get('max_concurrent_units')!=1:
        raise BootstrapUnavailable('member_bootstrap_capacity_not_observed')
    return {'command_id':command['command_id'],'target_concurrent_units':1,'verified':True}


COMMON = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Read-Fixed([string]$path){
 $item=Get-Item -LiteralPath $path -Force
 if($item.PSIsContainer -or $item.Length -gt 262144){throw 'Invalid bootstrap file'}
 $ancestor=$item.FullName
 while($ancestor){
  if((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked bootstrap path'}
  $ancestor=[IO.Path]::GetDirectoryName($ancestor)
 }
 $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
 try{
  $buffer=New-Object byte[] 262145;$count=0
  while($count -lt $buffer.Length){$n=$f.Read($buffer,$count,$buffer.Length-$count);if($n -eq 0){break};$count+=$n}
  if($count -gt 262144){throw 'Bootstrap file grew'}
  $raw=New-Object byte[] $count;[Array]::Copy($buffer,$raw,$count);return ,$raw
 }finally{$f.Dispose()}
}
function Hash([byte[]]$raw){
 $h=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($h.ComputeHash($raw))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
}
function Decode-Object([byte[]]$raw){return [Text.Encoding]::UTF8.GetString($raw).TrimStart([char]0xfeff)|ConvertFrom-Json}
$configPath=Join-Path $c.root 'agent\machine.json'
function Inspect {
 foreach($name in @('intentional-stop.marker','security-block.marker')){
  if(Test-Path -LiteralPath (Join-Path $c.root ('agent\transport\'+$name))){throw 'Bootstrap blocked by operator or security marker'}
 }
 $marker=Decode-Object (Read-Fixed (Join-Path $c.root '.rcn-root.json'))
 $raw=Read-Fixed $configPath;$cfg=Decode-Object $raw
 $status=Decode-Object (Read-Fixed (Join-Path $c.root 'agent\status.json'))
 foreach($v in @($marker,$cfg,$status)){
  if($v.machine_id -cne $c.machine -or $v.root_uuid -cne $c.uuid){throw 'Bootstrap root identity changed'}
 }
 if($cfg.remote_root -cne $c.root -or $cfg.python_executable -cne $c.python -or
    $cfg.runtime_version -cne $c.runtime -or $status.runtime_version -cne $c.runtime -or
    $cfg.enabled -isnot [bool] -or $cfg.enabled -or $cfg.max_concurrent_units -isnot [int] -or $cfg.max_concurrent_units -ne 1 -or
    $cfg.target_concurrent_units -isnot [int] -or $cfg.target_concurrent_units -notin @(0,1)) {throw 'Not a bootstrap configuration'}
 if([string]$status.updated_at -notmatch '(Z|[+-]\d\d:\d\d)$'){throw 'Invalid bootstrap time'}
 $age=([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($status.updated_at)).TotalSeconds
 if($age -lt 0 -or $age -gt 30 -or $status.active_run_ids -isnot [array] -or $status.active_run_ids.Count -ne 0 -or
    $status.max_concurrent_units -isnot [int] -or $status.max_concurrent_units -notin @(0,1) -or
    $status.pid -isnot [int] -or $status.pid -le 0){throw 'Bootstrap supervisor is not freshly idle'}
 foreach($relative in @('spool\incoming','spool\ready','spool\activations','runs\active')){
  $dir=Join-Path $c.root $relative
  if(Test-Path -LiteralPath $dir){
   if((Get-Item -LiteralPath $dir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked spool'}
   if(@(Get-ChildItem -LiteralPath $dir -Force | Select-Object -First 1).Count){throw 'Bootstrap has pending work'}
  }
 }
 $supervisor=Join-Path $c.root ('agent\versions\'+$c.runtime+'\remote-agent\supervisor.py')
 $sourceHash=Hash (Read-Fixed $supervisor)
 if($sourceHash -cne $c.supervisor_hash){throw 'Supervisor source mismatch'}
 # RCN bootstrap native identity begin
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $username=($identity.Name -split '\\')[-1].ToLowerInvariant()
 if($username -cne $c.user){throw 'SSH login identity mismatch'}
 $sid=$identity.User.Value
 $admin=@($identity.Groups | Where-Object {$_.Value -eq 'S-1-5-32-544'}).Count -gt 0
 $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$status.pid)
 $pythonw=[IO.Path]::Combine([IO.Path]::GetDirectoryName($c.python),'pythonw.exe')
 $arguments='^\s*"?'+[regex]::Escape($pythonw)+'"?\s+-B\s+"?'+[regex]::Escape($supervisor)+'"?\s+--config\s+"?'+[regex]::Escape($configPath)+'"?\s+run\s*$'
 if($null -eq $process -or $process.ExecutablePath -ine $pythonw -or $process.CommandLine -notmatch $arguments -or
    $process.CreationDate.ToUniversalTime() -gt ([DateTimeOffset]::Parse($status.updated_at)).UtcDateTime){throw 'Supervisor process mismatch'}
 $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
 if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid){throw 'Supervisor owner mismatch'}
 # RCN bootstrap native identity end
 return @{schema_version=1;nonce=$c.nonce;hostname=$env:COMPUTERNAME;username=$username;sid=$sid;
  administrator=[bool]$admin;config=$cfg;config_sha256=(Hash $raw);supervisor_sha256=$sourceHash;
  status=@{machine_id=$status.machine_id;root_uuid=$status.root_uuid;runtime_version=$status.runtime_version;
   pid=$status.pid;updated_at=$status.updated_at;max_concurrent_units=$status.max_concurrent_units;active_run_ids=@()}}
}
'''
INSPECT = r'''
Inspect | ConvertTo-Json -Depth 12 -Compress
'''
ACTIVATE = r'''
$lock=$null;$temporary=Join-Path $c.root 'agent\.member-bootstrap-config.tmp'
try{
 $lockPath=Join-Path $c.root 'agent\.member-bootstrap.lock'
 foreach($p in @($temporary,$lockPath)){
  if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked bootstrap transaction'}}
 }
 $lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 $observed=Inspect
 if($observed.config_sha256 -cne $c.after){
  if($observed.config_sha256 -cne $c.before -or $observed.config.target_concurrent_units -ne 0){throw 'Bootstrap compare-and-swap conflict'}
  $payload=[Convert]::FromBase64String($c.payload)
  if((Hash $payload) -cne $c.after){throw 'Bootstrap payload changed'}
  $offset=0
  if(Test-Path -LiteralPath $temporary){
   $partial=Read-Fixed $temporary
   if($partial.Length -gt $payload.Length){throw 'Unknown bootstrap temporary file'}
   for($i=0;$i -lt $partial.Length;$i++){if($partial[$i] -ne $payload[$i]){throw 'Unknown bootstrap temporary file'}}
   $offset=$partial.Length
  }
  $mode=if($offset -gt 0){[IO.FileMode]::Open}else{[IO.FileMode]::OpenOrCreate}
  $f=[IO.File]::Open($temporary,$mode,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$null=$f.Seek($offset,[IO.SeekOrigin]::Begin);$f.Write($payload,$offset,$payload.Length-$offset);$f.Flush($true)}finally{$f.Dispose()}
  if((Hash (Read-Fixed $temporary)) -cne $c.after){throw 'Bootstrap temporary changed'}
  if((Hash (Read-Fixed $configPath)) -cne $c.before){throw 'Config changed before publication'}
  [IO.File]::Replace($temporary,$configPath,[System.Management.Automation.Language.NullString]::Value)
 }
 $verified=Inspect
 if($verified.config_sha256 -cne $c.after){throw 'Bootstrap publication unconfirmed'}
 $verified | ConvertTo-Json -Depth 12 -Compress
}finally{if($lock){$lock.Dispose()}}
'''
