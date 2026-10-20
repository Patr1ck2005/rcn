"""Dedicated loopback-only member SSH service installer.

The elevated action runs only Windows' signed sshd/ssh-keygen, never member Python
or a Worker script. Service configuration is under an administrator-owned private
ProgramData directory. Existing sshd, firewall, accounts and services are untouched.
This initial mode requires an enabled standard LOCAL member account; no automatic
administrator downgrade, account impersonation or credential transfer is allowed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from . import member_registration as storage, ssh_identity
from .member_tunnel_identity import member_sid

DEPLOYMENT_FOLDER = 'RCN-Member-SSH'


def _fail(code):
    raise storage.MemberRegistrationError(code)


def current_account() -> dict:
    script = r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$env:PSModulePath=(Join-Path $PSHOME 'Modules')
$i=[Security.Principal.WindowsIdentity]::GetCurrent();$u=Get-LocalUser -SID $i.User
$admin=(@($i.Groups|Where-Object {$_.Value -eq 'S-1-5-32-544'}).Count -gt 0)
@{username=$u.Name.ToLowerInvariant();sid=$u.SID.Value;enabled=[bool]$u.Enabled;administrator=[bool]$admin}|ConvertTo-Json -Compress
'''
    try:
        result = subprocess.run([_powershell(),'-NoProfile','-NonInteractive','-Command',script],
                                capture_output=True,timeout=15,check=False)
        if result.returncode or len(result.stdout)>4096:
            _fail('member_ssh_local_account_unavailable')
        value=storage._json_document(result.stdout)
        if (set(value)!={'username','sid','enabled','administrator'} or value['enabled'] is not True
                or value['administrator'] is not False
                or not re.fullmatch(r'[a-z][a-z0-9_.-]{0,31}',value['username'])):
            _fail('member_ssh_requires_managed_nonadmin_account')
        member_sid(value['sid'])
        return value
    except storage.MemberRegistrationError:
        raise
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):
        _fail('member_ssh_local_account_unavailable')


def _powershell() -> str:
    if os.name!='nt':
        _fail('member_ssh_requires_windows')
    import ctypes
    buffer=ctypes.create_unicode_buffer(32768)
    count=ctypes.windll.kernel32.GetSystemDirectoryW(buffer,len(buffer))
    if not 0<count<len(buffer):
        _fail('member_ssh_system_directory_unavailable')
    return str(Path(buffer.value)/'WindowsPowerShell/v1.0/powershell.exe')


def build_service_installer(plan: dict, account: dict) -> str:
    member_sid(account['sid'])
    if (account.get('administrator') is not False or account.get('enabled') is not True
            or not re.fullmatch(r'[a-z][a-z0-9_.-]{0,31}',account['username'])
            or not re.fullmatch(r'[a-f0-9-]{36}',plan['root_uuid'])
            or not re.fullmatch(r'[a-f0-9]{64}',plan['plan_sha256'])
            or plan['listen_address']!='127.0.0.1' or type(plan['listen_port']) is not int or plan['listen_port']!=22):
        raise ValueError('invalid_member_ingress_plan')
    ssh_identity.public_key(plan['operator_public_key'])
    literal=storage._json_bytes({'plan':plan,'account':account}).decode().strip().replace("'","''")
    return "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n$c='"+literal+"'|ConvertFrom-Json\n"+SERVICE_SCRIPT


def run_elevated_snapshot(helper: Path, script: bytes, *, timeout_s: int = 180) -> subprocess.CompletedProcess:
    """Execute one hash-fenced public helper with visible UAC; no file reopen after verification."""
    if not 1 <= timeout_s <= 900:
        raise ValueError("invalid elevated helper timeout")
    quoted=str(helper).replace("'","''")
    digest=hashlib.sha256(script).hexdigest()
    # The elevated child verifies and executes one locked snapshot, rather than
    # reopening a member-writable -File after the original hash check.
    elevation = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
        "$env:PSModulePath=(Join-Path $PSHOME 'Modules');$env:PATH=([Environment]::SystemDirectory+';'+$PSHOME);"
        "Set-Location -LiteralPath ([Environment]::SystemDirectory);$f=$null;try{"
        "$p='"+quoted+"';$a=$p;while($a){if((Get-Item -LiteralPath $a -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked installer'};$a=[IO.Path]::GetDirectoryName($a)};"
        "$f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);"
        "if($f.Length -gt 262144){throw 'Oversize installer'};$b=New-Object byte[] ([int]$f.Length);$n=0;"
        "while($n -lt $b.Length){$r=$f.Read($b,$n,$b.Length-$n);if($r -le 0){throw 'Incomplete installer'};$n+=$r};"
        "$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};"
        "if($actual -cne '"+digest+"'){throw 'Installer digest changed'};"
        "& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($b).TrimStart([char]0xfeff)));exit 0"
        "}catch{exit 2}finally{if($f){$f.Dispose()}}")
    elevated_encoded=base64.b64encode(elevation.encode('utf-16-le')).decode('ascii')
    command=("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
             "$args='-NoProfile -NonInteractive -EncodedCommand "+elevated_encoded+"';"
             "$child=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $args -Verb RunAs -Wait -PassThru;exit $child.ExitCode")
    encoded=base64.b64encode(command.encode('utf-16-le')).decode('ascii')
    completed=subprocess.run([_powershell(),'-NoProfile','-NonInteractive','-EncodedCommand',encoded],
                             capture_output=True,timeout=timeout_s,check=False)
    return completed


def install_service(plan: dict, account: dict, *, state_root: Path, accept_install: bool=False) -> dict:
    """Explicit local UAC once; subsequent calls inspect the same protected service."""
    if accept_install is not True:
        _fail('member_ssh_install_consent_required')
    script=build_service_installer(plan,account).encode('utf-8-sig')
    root=Path(state_root)/'ssh-service'
    storage._private_directory(root)
    with storage._exclusive(root):
        helper=root/'install-member-ssh.ps1'
        storage._check_private_file(helper)
        if helper.exists():
            if storage._read_bytes(helper,maximum=262144)!=script:
                _fail('member_ssh_service_plan_changed_requires_migration')
        else:
            storage._publish(helper,script,maximum=262144)
        receipt_path=Path(os.environ.get('ProgramData',r'C:\ProgramData'))/DEPLOYMENT_FOLDER/plan['root_uuid']/'receipt.json'
        if receipt_path.exists():
            return observe_service(plan,account)
        # The helper is a reviewed release component and contains no private material.
        # UAC remains visible and requires the installing member's local approval.
        completed=run_elevated_snapshot(helper,script)
        if completed.returncode:
            _fail('member_ssh_service_install_unconfirmed_preserve_state')
        return observe_service(plan,account)


def observe_service(plan: dict, account: dict) -> dict:
    """Read public receipt and current service status, not a private host key."""
    contract=storage._json_bytes({'plan':plan,'account':account}).decode().strip().replace("'","''")
    script="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$c='"+contract+"'|ConvertFrom-Json\n"+OBSERVE_SCRIPT
    result=subprocess.run([_powershell(),'-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=20,check=False)
    if result.returncode or len(result.stdout)>8192:
        _fail('member_ssh_service_observation_unavailable')
    value=storage._json_document(result.stdout)
    keys={'schema_version','machine_id','root_uuid','plan_sha256','sid','username','host_public_key',
          'service_name','running','grants_execution'}
    if (set(value)!=keys or type(value['schema_version']) is not int or value['schema_version']!=1
            or any(value[k]!=plan[k] for k in ('machine_id','root_uuid','plan_sha256'))
            or value['sid']!=account['sid'] or value['username']!=account['username']
            or value['service_name']!='RCN-Member-'+plan['root_uuid']+'-SSHD'
            or type(value['running']) is not bool or value['grants_execution'] is not False):
        _fail('member_ssh_service_receipt_invalid')
    ssh_identity.public_key(value['host_public_key'])
    return value


SERVICE_SCRIPT=r'''
# RCN ingress native begin
function Assert-Authority {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 if(-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Explicit elevation required'}
 $u=Get-LocalUser -SID $c.account.sid
 $admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544')
 if(-not $u.Enabled -or $u.Name.ToLowerInvariant() -cne $c.account.username -or @($admins|Where-Object {$_.SID.Value -eq $u.SID.Value}).Count){throw 'A matching standard local member is required'}
}
function Protected-Directory([string]$Path,[bool]$MemberRead){
 if(-not(Test-Path -LiteralPath $Path)){
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
  if($MemberRead){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($c.account.sid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))}
  if($MemberRead -and $c.account.owner_sid){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($c.account.owner_sid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))}
  $null=[IO.Directory]::CreateDirectory($Path,$acl)
 }
 Assert-Private $Path
 if(-not $MemberRead){Assert-Secret $Path}
}
function Assert-Secret([string]$Path){
 Assert-Private $Path
 $acl=Get-Acl -LiteralPath $Path
 foreach($r in $acl.Access){if($r.AccessControlType -eq 'Allow' -and
   $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Host secrets must not be member-readable'}}
}
function Assert-Private([string]$Path){
 $p=[IO.Path]::GetFullPath($Path)
 while($p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked ingress path'};$p=[IO.Path]::GetDirectoryName($p)}
 $acl=Get-Acl -LiteralPath $Path
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Ingress requires an administrative owner'}
 foreach($r in $acl.Access){
  $sid=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  if($r.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18','S-1-5-32-544') -and
    ($sid -notin @($c.account.sid,$c.account.owner_sid) -or ($r.FileSystemRights -band (-bnot ([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize))))){throw 'Untrusted ingress access'}
 }
}
function Native-Paths {
 $base=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RCN-Member-SSH'
 return @{base=$base;deploy=(Join-Path $base $c.plan.root_uuid);sshd=(Join-Path ([Environment]::SystemDirectory) 'OpenSSH\sshd.exe');keygen=(Join-Path ([Environment]::SystemDirectory) 'OpenSSH\ssh-keygen.exe')}
}
function Assert-Signed([string]$Path){
 $sig=Get-AuthenticodeSignature -LiteralPath $Path
 if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)'){throw 'Windows signed OpenSSH required'}
}
function Protect-HostKey([string]$Key){
 $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))}
 [IO.File]::SetAccessControl($Key,$acl)
}
function Read-Service {
 return Get-CimInstance Win32_Service -Filter ("Name='"+$serviceName+"'")
}
function New-OwnedService {
 if(@(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue).Count){throw 'Port 22 belongs to another service; no changes made to it'}
 $null=New-Service -Name $serviceName -BinaryPathName $image -DisplayName $serviceName -Description $description -StartupType Manual
}
function Start-OwnedService {
 Set-Service -Name $serviceName -StartupType Automatic
 & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') failure $serviceName reset= 86400 actions= restart/15000/restart/15000/restart/60000 | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Service recovery configuration unconfirmed'}
 Start-Service -Name $serviceName
}
# RCN ingress native end
function Read-Json([string]$Path){Assert-Private $Path;if((Get-Item -LiteralPath $Path).Length -gt 16384){throw 'Oversized ingress state'};return [IO.File]::ReadAllText($Path)|ConvertFrom-Json}
function Save-Json([string]$Path,$Value){
 $temp=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
 try{
  $raw=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 8 -Compress))
  $f=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()}
  if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temp,$Path,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temp,$Path)}
 }finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
}
function Exact-File([string]$Path,[string]$Text){
 if(Test-Path -LiteralPath $Path){Assert-Private $Path;if((Get-Item -LiteralPath $Path).Length -gt 16384 -or [IO.File]::ReadAllText($Path) -cne $Text){throw 'Foreign ingress file'};return}
 $raw=[Text.Encoding]::ASCII.GetBytes($Text);$temporary=$Path+'.preparing';$offset=0
 if(Test-Path -LiteralPath $temporary){
  Assert-Private $temporary;if((Get-Item -LiteralPath $temporary).Length -gt 16384){throw 'Oversized ingress temporary file'};$prior=[IO.File]::ReadAllBytes($temporary)
  if($prior.Length -gt $raw.Length){throw 'Unknown ingress temporary file'}
  for($i=0;$i -lt $prior.Length;$i++){if($prior[$i] -ne $raw[$i]){throw 'Unknown ingress temporary file'}}
  $offset=$prior.Length
 }
 $f=[IO.File]::Open($temporary,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$null=$f.Seek($offset,[IO.SeekOrigin]::Begin);$f.Write($raw,$offset,$raw.Length-$offset);$f.Flush($true)}finally{$f.Dispose()}
 [IO.File]::Move($temporary,$Path)
}
Assert-Authority
$paths=Native-Paths
foreach($p in @($paths.sshd,$paths.keygen)){if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw 'OpenSSH optional component is not installed'};Assert-Signed $p}
Protected-Directory $paths.base $false;Protected-Directory $paths.deploy $true
$deploy=$paths.deploy;$serviceName='RCN-Member-'+$c.plan.root_uuid+'-SSHD'
$description='RCN member ingress '+$c.plan.plan_sha256
$config=Join-Path $deploy 'sshd_config';$secrets=Join-Path $deploy 'private';$key=Join-Path $secrets 'host_ed25519'
$statePath=Join-Path $deploy 'installation.json';$lockPath=Join-Path $deploy 'install.lock'
if(Test-Path -LiteralPath $lockPath){Assert-Private $lockPath}
$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try{
 $image='"'+$paths.sshd+'" -f "'+$config+'"'
 $state=if(Test-Path -LiteralPath $statePath){Read-Json $statePath}else{$null}
 if($null -eq $state){
  if($null -ne (Read-Service) -or @(Get-ChildItem -LiteralPath $deploy -Force|Where-Object {$_.Name -ne 'install.lock'}).Count){throw 'Unowned ingress deployment'}
  $state=[pscustomobject]@{schema_version=1;plan_sha256=$c.plan.plan_sha256;sid=$c.account.sid;phase='preparing';host_public_key=$null}
  Save-Json $statePath $state
 }
 if(@($state.PSObject.Properties).Count -ne 5 -or $state.schema_version -isnot [int] -or $state.schema_version -ne 1 -or $state.plan_sha256 -cne $c.plan.plan_sha256 -or
    $state.sid -cne $c.account.sid -or $state.phase -notin @('preparing','service-intent','started')){throw 'Ingress journal changed'}
 if($state.phase -ne 'preparing'){
  foreach($name in @('sshd_config','authorized_keys','private\host_ed25519')){if(-not(Test-Path -LiteralPath (Join-Path $deploy $name) -PathType Leaf)){throw 'Published ingress file missing'}}
 }
 Protected-Directory $secrets $false
 if(-not(Test-Path -LiteralPath $key)){
  if($state.phase -ne 'preparing' -or $state.host_public_key){throw 'Published ingress identity missing'}
  & $paths.keygen -q -t ed25519 -N '""' -C 'rcn-member-host' -f $key
  if($LASTEXITCODE -ne 0){throw 'Host identity generation failed'}
  Protect-HostKey $key
 }
 Assert-Secret $key
 $public=(& $paths.keygen -y -P '""' -f $key)|Out-String
 if($LASTEXITCODE -ne 0){throw 'Invalid ingress host key'}
 $parts=$public.Trim() -split '\s+';$public=($parts|Select-Object -First 2) -join ' '
 if($public -cnotmatch '^ssh-ed25519 [A-Za-z0-9+/]{68}$'){throw 'Invalid ingress host key'}
 if($state.host_public_key -and $state.host_public_key -cne $public){throw 'Ingress host identity changed'}
 $state.host_public_key=$public
 $keys=Join-Path $deploy 'authorized_keys'
 $text=@('# Dedicated RCN member ingress, loopback only.','Port 22','ListenAddress 127.0.0.1',
  ('HostKey "'+$key.Replace('\','/')+'"'),('AllowUsers '+$c.account.username),('AuthorizedKeysFile "'+$keys.Replace('\','/')+'"'),
  'AuthenticationMethods publickey','PubkeyAuthentication yes','PubkeyAcceptedAlgorithms ssh-ed25519','PasswordAuthentication no',
  'AllowAgentForwarding no','AllowTcpForwarding no','GatewayPorts no','PermitOpen none','PermitListen none',
  'MaxSessions 4','PermitTTY yes','ClientAliveInterval 15','ClientAliveCountMax 3','LoginGraceTime 15','MaxAuthTries 3','LogLevel VERBOSE',
  ('Subsystem sftp "'+(Join-Path ([IO.Path]::GetDirectoryName($paths.sshd)) 'sftp-server.exe').Replace('\','/')+'"'),'') -join "`n"
 Exact-File $config $text
 Exact-File $keys ('from="127.0.0.1",no-agent-forwarding,no-port-forwarding '+$c.plan.operator_public_key+"`n")
 & $paths.sshd -t -f $config
 if($LASTEXITCODE -ne 0){throw 'Dedicated SSH configuration invalid'}
 $state.phase=if($state.phase -eq 'started'){'started'}else{'service-intent'};Save-Json $statePath $state
 $svc=Read-Service
 if($null -eq $svc){if($state.phase -eq 'started'){throw 'Operator removed ingress service'};New-OwnedService;$svc=Read-Service}
 if($null -eq $svc -or $svc.PathName -cne $image -or $svc.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM') -or $svc.Description -cne $description){throw 'Existing service differs from original ingress'}
 if($state.phase -ne 'started'){
  if($svc.StartMode -eq 'Disabled'){throw 'Ingress service disabled by operator'}
  if($svc.State -ne 'Running'){Start-OwnedService}
  $svc=Read-Service;if($svc.State -ne 'Running'){throw 'Ingress startup not observed'}
  $state.phase='started';Save-Json $statePath $state
 }
 $receipt=@{schema_version=1;machine_id=$c.plan.machine_id;root_uuid=$c.plan.root_uuid;plan_sha256=$c.plan.plan_sha256;
  sid=$c.account.sid;username=$c.account.username;host_public_key=$public;service_name=$serviceName}
 Save-Json (Join-Path $deploy 'receipt.json') $receipt
}finally{$lock.Dispose()}
'''

OBSERVE_SCRIPT=r'''
$base=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RCN-Member-SSH'
$deploy=Join-Path $base $c.plan.root_uuid;$path=Join-Path $deploy 'receipt.json'
$p=$path
while($p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked ingress receipt'};$p=[IO.Path]::GetDirectoryName($p)}
if((Get-Item -LiteralPath $path).Length -gt 8192){throw 'Invalid ingress receipt'}
$acl=Get-Acl -LiteralPath $path
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Untrusted ingress receipt'}
foreach($r in $acl.Access){if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544') -and ($r.FileSystemRights -band ([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership))){throw 'Writable ingress receipt'}}
$v=[IO.File]::ReadAllText($path)|ConvertFrom-Json
$name='RCN-Member-'+$c.plan.root_uuid+'-SSHD'
$svc=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'")
$expected='"'+(Join-Path ([Environment]::SystemDirectory) 'OpenSSH\sshd.exe')+'" -f "'+(Join-Path $deploy 'sshd_config')+'"'
if($null -eq $svc -or $svc.PathName -cne $expected -or $svc.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')){throw 'Ingress service identity changed'}
$v|Add-Member running ([bool]($svc.State -eq 'Running'))
$v|Add-Member grants_execution $false
$v|ConvertTo-Json -Compress
'''
