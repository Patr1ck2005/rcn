"""Explicit Windows Feature-on-Demand supply before member key preparation.

No package URLs, registry/WSUS edits, service starts, account changes or reboot.
The OS installation transaction is serialized and journaled under ProgramData.
Only a newly created, exactly checked default OpenSSH rule may be disabled;
pre-existing rules/services are never taken over. An interrupted caller does not
cancel Windows servicing or erase its original intent.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

from . import member_registration as storage
from .member_ssh_service import _powershell, run_elevated_snapshot

BINARIES = ('ssh.exe', 'ssh-keygen.exe', 'scp.exe', 'sshd.exe', 'sftp-server.exe')
CAPABILITIES = ('OpenSSH.Client~~~~0.0.1.0', 'OpenSSH.Server~~~~0.0.1.0')


def inspect_openssh() -> dict:
    """Unprivileged, read-only probe; a historical receipt never substitutes for files."""
    try:
        result = subprocess.run([_powershell(), '-NoProfile', '-NonInteractive', '-Command', PROBE_SCRIPT],
                                capture_output=True, timeout=30, check=False,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode or len(result.stdout) > 8192:
            raise ValueError('probe failed')
        value = storage._json_document(result.stdout)
        if (set(value) != {'schema_version', 'state', 'missing', 'openssh_ready', 'grants_execution'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['state'] not in {'ready', 'missing', 'resume-required', 'restart-required'}
                or type(value['openssh_ready']) is not bool or value['grants_execution'] is not False
                or not isinstance(value['missing'], list)
                or any(x not in BINARIES for x in value['missing'])
                or len(set(value['missing'])) != len(value['missing'])
                or value['openssh_ready'] != (value['state'] == 'ready')
                or (value['openssh_ready'] and value['missing'])):
            raise ValueError('invalid probe')
        return value
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise storage.MemberRegistrationError('member_openssh_probe_unconfirmed') from None


def ensure_member_openssh(*, state_root: Path, accept_supply: bool = False) -> dict:
    """Use Windows servicing only after explicit connection consent and registration."""
    if accept_supply is not True:
        raise storage.MemberRegistrationError('member_openssh_supply_consent_required')
    observed = inspect_openssh()
    if observed['openssh_ready']:
        return observed
    if observed['state'] == 'restart-required':
        raise storage.MemberRegistrationError('member_openssh_restart_required_rerun_original_installer')
    root = Path(state_root) / 'openssh-prerequisite'
    try:
        storage._private_directory(root)
        with storage._exclusive(root):
            helper = root / 'install-windows-openssh.ps1'
            raw = INSTALL_SCRIPT.encode('utf-8-sig')
            storage._check_private_file(helper)
            if helper.exists():
                if storage._read_bytes(helper, maximum=262144) != raw:
                    raise storage.MemberRegistrationError('member_openssh_supply_helper_changed')
            else:
                storage._publish(helper, raw, maximum=262144)
            # A timeout does NOT kill the elevated servicing process. Its global
            # exclusive handle prevents another caller starting parallel servicing.
            result = run_elevated_snapshot(helper, raw, timeout_s=600)
            if result.returncode == 3010:
                raise storage.MemberRegistrationError('member_openssh_restart_required_rerun_original_installer')
            if result.returncode == 75:
                raise storage.MemberRegistrationError('member_openssh_original_installation_running')
            if result.returncode:
                raise storage.MemberRegistrationError('member_openssh_supply_unconfirmed_preserve_state')
            verified = inspect_openssh()
            if not verified['openssh_ready']:
                raise storage.MemberRegistrationError('member_openssh_supply_unconfirmed_preserve_state')
            return verified
    except storage.MemberRegistrationError:
        raise
    except subprocess.TimeoutExpired:
        raise storage.MemberRegistrationError('member_openssh_installation_outcome_pending') from None
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        raise storage.MemberRegistrationError('member_openssh_supply_unconfirmed_preserve_state') from None


def ensure_member_ssh_client(*, state_root: Path, accept_supply: bool = False) -> dict:
    """Submit-only onboarding needs the inbox client, never an SSH server."""
    if accept_supply is not True:
        raise storage.MemberRegistrationError('member_openssh_supply_consent_required')
    root = Path(state_root) / 'openssh-client-prerequisite'
    storage._private_directory(root)
    raw = CLIENT_INSTALL_SCRIPT.encode('utf-8-sig')
    helper = root / 'install-windows-openssh-client.ps1'
    with storage._exclusive(root):
        storage._check_private_file(helper)
        if helper.exists():
            if storage._read_bytes(helper, maximum=262144) != raw:
                raise storage.MemberRegistrationError('member_openssh_supply_helper_changed')
        else:
            storage._publish(helper, raw, maximum=262144)
        try:
            result = run_elevated_snapshot(helper, raw, timeout_s=600)
        except subprocess.TimeoutExpired:
            raise storage.MemberRegistrationError('member_openssh_installation_outcome_pending') from None
        if result.returncode == 3010:
            raise storage.MemberRegistrationError('member_openssh_restart_required_rerun_original_installer')
        if result.returncode == 75:
            raise storage.MemberRegistrationError('member_openssh_original_installation_running')
        if result.returncode:
            raise storage.MemberRegistrationError('member_openssh_supply_unconfirmed_preserve_state')
    return {'openssh_ready': True, 'client_only': True, 'grants_execution': False}


CLIENT_INSTALL_SCRIPT = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 5}
$mutex=[Threading.Mutex]::new($false,'Global\RCN-Windows-OpenSSH-Client-Supply')
$locked=$false
try {
 try{$locked=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$locked=$true}
 if(-not $locked){exit 75}
 $name='OpenSSH.Client~~~~0.0.1.0'
 $state=Get-WindowsCapability -Online -Name $name
 if($state.State -in @('InstallPending','UninstallPending')){exit 3010}
 if($state.State -eq 'NotPresent'){
  $result=Add-WindowsCapability -Online -Name $name
  if($result.RestartNeeded){exit 3010}
 }
 if((Get-WindowsCapability -Online -Name $name).State -ne 'Installed'){exit 1}
 $path=Join-Path ([Environment]::SystemDirectory) 'OpenSSH\ssh.exe'
 $signature=Get-AuthenticodeSignature -LiteralPath $path
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)'){exit 1}
 exit 0
}finally{if($locked){$mutex.ReleaseMutex()};$mutex.Dispose()}
'''


COMMON = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$capabilities=@('OpenSSH.Client~~~~0.0.1.0','OpenSSH.Server~~~~0.0.1.0')
# RCN prerequisite native begin
function Store-Path {return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RCN-OpenSSH-Prerequisite'}
function Assert-Unlinked([string]$Path){
 $p=[IO.Path]::GetFullPath($Path)
 while($p){if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked prerequisite path'}};$p=[IO.Path]::GetDirectoryName($p)}
}
function Assert-Store([string]$Path){
 Assert-Unlinked $Path;$acl=Get-Acl -LiteralPath $Path
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Untrusted component state owner'}
 foreach($r in $acl.Access){
  if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544') -and
   ($r.FileSystemRights -band ([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership))){throw 'Writable component state'}
 }
}
function Ensure-Store([string]$Path){
 Assert-Unlinked $Path
 if(-not(Test-Path -LiteralPath $Path)){
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
  $null=[IO.Directory]::CreateDirectory($Path,$acl)
 }
 Assert-Store $Path
}
function Assert-Authority {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 if(-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Visible administrative approval required'}
}
function Boot-Id {return (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}
function Missing-Binaries {
 $base=Join-Path ([Environment]::SystemDirectory) 'OpenSSH'
 foreach($name in @('ssh.exe','ssh-keygen.exe','scp.exe','sshd.exe','sftp-server.exe')){
  $p=Join-Path $base $name;Assert-Unlinked $p
  if(-not(Test-Path -LiteralPath $p -PathType Leaf)){$name;continue}
  $sig=Get-AuthenticodeSignature -LiteralPath $p
  if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)'){throw 'Invalid Windows OpenSSH signature'}
 }
}
function Capability-State([string]$Name){
 if($Name -cnotin $capabilities){throw 'Unknown component'}
 $items=@(Get-WindowsCapability -Online -Name $Name -ErrorAction Stop)
 if($items.Count -ne 1 -or $items[0].Name -cne $Name){throw 'Ambiguous component state'}
 return [string]$items[0].State
}
function Add-Capability([string]$Name){
 if($Name -cnotin $capabilities){throw 'Unknown component'}
 # Fixed inbox packages; respect the system's Windows Update/WSUS policy.
 # This cmdlet returns RestartNeeded. There is no automatic reboot invocation.
 $r=Add-WindowsCapability -Online -Name $Name -ErrorAction Stop
 if($r.RestartNeeded -isnot [bool]){throw 'Component result unconfirmed'}
 return [bool]$r.RestartNeeded
}
function Default-Service {
 $s=Get-CimInstance Win32_Service -Filter "Name='sshd'"
 if($null -eq $s){return $null}
 return [ordered]@{path=[string]$s.PathName;account=[string]$s.StartName;mode=[string]$s.StartMode;state=[string]$s.State}
}
function Check-NewDefaultService($Service){
 if($null -eq $Service){return}
 $expected=Join-Path ([Environment]::SystemDirectory) 'OpenSSH\sshd.exe'
 if($Service.path.Trim('"') -ine $expected -or $Service.account -notin @('LocalSystem','NT AUTHORITY\SYSTEM') -or $Service.state -ne 'Stopped' -or $Service.mode -notin @('Manual','Disabled')){throw 'Default service changed outside component installation'}
}
function Rule-Snapshot {
 $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.Name -ceq 'OpenSSH-Server-In-TCP'})
 if($rules.Count -eq 0){return $null};if($rules.Count -ne 1){throw 'Ambiguous default rule'}
 $r=$rules[0];$p=@($r|Get-NetFirewallPortFilter);$a=@($r|Get-NetFirewallApplicationFilter);$s=@($r|Get-NetFirewallServiceFilter)
 if($p.Count -ne 1 -or $a.Count -ne 1 -or $s.Count -ne 1){throw 'Ambiguous default rule filters'}
 return [ordered]@{id=[string]$r.InstanceID;name=[string]$r.Name;source=[string]$r.PolicyStoreSourceType;
  direction=[string]$r.Direction;action=[string]$r.Action;enabled=([string]$r.Enabled -eq 'True');
  profile=[string]$r.Profile;edge=[string]$r.EdgeTraversalPolicy;protocol=[string]$p[0].Protocol;
  local_port=(@($p[0].LocalPort)-join ',');remote_port=(@($p[0].RemotePort)-join ',');
  program=[string]$a[0].Program;service=[string]$s[0].Service}
}
function Disable-SupplyRule($Expected){
 if((Json (Rule-Snapshot)) -cne (Json $Expected)){throw 'Default rule changed before restriction'}
 $rule=Get-NetFirewallRule -PolicyStore PersistentStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop
 $null=$rule|Disable-NetFirewallRule -ErrorAction Stop
}
# RCN prerequisite native end
function Json($Value){return ConvertTo-Json -InputObject $Value -Depth 8 -Compress}
$store=Store-Path;$journal=Join-Path $store 'installation.json'
function Read-State {
 if(-not(Test-Path -LiteralPath $journal)){return $null}
 Assert-Store $store;Assert-Store $journal
 if((Get-Item -LiteralPath $journal).Length -gt 16384){throw 'Oversized component state'}
 $v=[IO.File]::ReadAllText($journal)|ConvertFrom-Json
 $fields=@('schema_version','contract','phase','active_capability','reboot_boot','server_intent','rule_before','rule_observed')
 if(@($v.PSObject.Properties).Count -ne $fields.Count -or @($fields|Where-Object {$v.PSObject.Properties.Name -cnotcontains $_}).Count -or
  $v.schema_version -isnot [int] -or $v.schema_version -ne 1 -or $v.contract -cne 'rcn-openssh-components-v1' -or
  $v.phase -cnotin @('checking','servicing','verifying','restart-required','ready','failed') -or
  ($null -ne $v.active_capability -and $v.active_capability -cnotin $capabilities) -or $v.server_intent -isnot [bool]){throw 'Invalid component state'}
 if($null -ne $v.reboot_boot -and ($v.reboot_boot -isnot [string] -or $v.reboot_boot -notmatch '(Z|[+-]\d\d:\d\d)$')){throw 'Invalid reboot evidence'}
 return $v
}
function Save-State {
 $tmp=Join-Path $store ('state-'+[Guid]::NewGuid().ToString('N')+'.tmp')
 try{
  $raw=[Text.UTF8Encoding]::new($false).GetBytes((Json $state))
  $f=[IO.File]::Open($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()}
  if(Test-Path -LiteralPath $journal){Assert-Store $journal;[IO.File]::Replace($tmp,$journal,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$journal)}
 }finally{if(Test-Path -LiteralPath $tmp){[IO.File]::Delete($tmp)}}
}
function Restrict-NewRule {
 if(-not $state.server_intent){return}
 Check-NewDefaultService (Default-Service)
 $rule=Rule-Snapshot
 if($null -ne $state.rule_before){
  if((Json $rule) -cne (Json $state.rule_before)){throw 'Pre-existing firewall rule changed'}
  return
 }
 if($null -eq $rule){if($null -ne $state.rule_observed){throw 'Recorded rule removed'};return}
 # Only the exact local Windows-generated SSH/TCP22 allow rule is eligible.
 if($rule.name -cne 'OpenSSH-Server-In-TCP' -or $rule.id -cne 'OpenSSH-Server-In-TCP' -or
  $rule.source -cne 'Local' -or $rule.direction -cne 'Inbound' -or $rule.action -cne 'Allow' -or
  $rule.protocol -notin @('TCP','6') -or $rule.local_port -cne '22' -or $rule.remote_port -cne 'Any' -or
  $rule.program -cne 'Any' -or $rule.service -notin @('Any','sshd') -or $rule.edge -cne 'Block'){throw 'Unknown firewall rule cannot be changed'}
 if($null -eq $state.rule_observed){$state.rule_observed=$rule;Save-State}
 $after=Json $state.rule_observed|ConvertFrom-Json;$after.enabled=$false
 if((Json $rule) -cne (Json $state.rule_observed) -and (Json $rule) -cne (Json $after)){throw 'Recorded firewall rule changed'}
 if($rule.enabled){Disable-SupplyRule $rule}
 if((Json (Rule-Snapshot)) -cne (Json $after)){throw 'Default firewall restriction not observed'}
}
'''

PROBE_SCRIPT = COMMON + r'''
$state=Read-State;$missing=@(Missing-Binaries)
$kind=if($missing.Count){'missing'}else{'ready'}
if($null -ne $state -and $state.phase -ne 'ready'){
 $kind=if($state.reboot_boot -and $state.reboot_boot -ceq (Boot-Id)){'restart-required'}else{'resume-required'}
}
if($null -ne $state -and $state.phase -eq 'ready' -and $missing.Count){throw 'Previously installed component missing; preserve state'}
@{schema_version=1;state=$kind;missing=$missing;openssh_ready=($kind -eq 'ready');grants_execution=$false}|ConvertTo-Json -Compress
'''

INSTALL_SCRIPT = COMMON + r'''
Assert-Authority;Ensure-Store $store
$lockPath=Join-Path $store 'servicing.lock'
if(Test-Path -LiteralPath $lockPath){Assert-Store $lockPath}
try{$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch [IO.IOException]{exit 75}
try{
 $state=Read-State
 if($null -eq $state){
  $state=[pscustomobject]@{schema_version=1;contract='rcn-openssh-components-v1';phase='checking';active_capability=$null;
   reboot_boot=$null;server_intent=$false;rule_before=$null;rule_observed=$null};Save-State
 }
 if($state.phase -eq 'ready'){
  if(@(Missing-Binaries).Count){throw 'Previously installed component missing'};exit 0
 }
 Restrict-NewRule
 if($state.reboot_boot -and $state.reboot_boot -ceq (Boot-Id)){$state.phase='restart-required';Save-State;exit 3010}
 $state.reboot_boot=$null
 foreach($name in $capabilities){
  $observed=Capability-State $name
  if($observed -eq 'Installed'){continue}
  if($observed -in @('InstallPending','UninstallPending')){
   $state.reboot_boot=Boot-Id;$state.phase='restart-required';Save-State;exit 3010
  }
  if($observed -ne 'NotPresent'){throw 'Component not ready for safe installation'}
  if($name -eq $capabilities[1] -and -not $state.server_intent){
   if($null -ne (Default-Service)){throw 'Existing default SSH service cannot be adopted'}
   $state.rule_before=Rule-Snapshot;$state.server_intent=$true
  }
  $state.active_capability=$name;$state.phase='servicing';Save-State
  try{$restart=Add-Capability $name}finally{if($name -eq $capabilities[1]){Restrict-NewRule}}
  if($restart){$state.reboot_boot=Boot-Id;$state.phase='restart-required';Save-State;exit 3010}
  if((Capability-State $name) -ne 'Installed'){throw 'Component installation outcome unconfirmed'}
 }
 $state.phase='verifying';Save-State;Restrict-NewRule
 if(@(Missing-Binaries).Count){throw 'Installed component files unavailable'}
 $state.phase='ready';$state.active_capability=$null;Save-State
 exit 0
}catch{
 if($null -ne $state){$state.phase='failed';Save-State}
 throw 'Windows OpenSSH component supply unconfirmed; retain original state'
}finally{$lock.Dispose()}
'''
