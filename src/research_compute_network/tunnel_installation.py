"""Generate disabled installation plus explicitly confirmed transport activation.

Stage/Verify/Rollback retain their disabled-only behavior. Separate activation
is resumable, never grants computation, and never restarts a Worker or sshd.
The installer is shipped with the bundle and needs only Windows PowerShell.
"""
from __future__ import annotations

import json
from pathlib import PureWindowsPath

import re


def build_task_installer(bundle, payload_hashes: dict[str, str], *, include_activation: bool = False) -> str:
    if type(include_activation) is not bool:
        raise ValueError('activation support must be explicitly selected')
    expected = {'managed-reverse-ssh.ps1', 'guard-task.xml', 'recovery-request-task.xml'}
    if set(payload_hashes) != expected or any(not re.fullmatch(r'[a-f0-9]{64}', h) for h in payload_hashes.values()):
        raise ValueError('installer requires the exact three reviewed payload hashes')
    contract = {
        "machine_id": bundle.machine_id,
        "root_uuid": bundle.root_uuid,
        "root": str(PureWindowsPath(bundle.script_path).parent.parent.parent),
        "script_path": bundle.script_path,
        "guard_name": bundle.guard_task_name,
        "request_name": bundle.request_task_name,
        "payload_hashes": payload_hashes,
        "coordinator_host": bundle.coordinator_host,
        "coordinator_port": bundle.coordinator_port,
        "coordinator_user": bundle.coordinator_user,
        "reverse_forward_host": bundle.reverse_forward_host,
        "reverse_forward_port": bundle.reverse_forward_port,
        "identity_file": bundle.identity_file,
        "known_hosts_file": bundle.known_hosts_file,
    }
    # Escape the JSON as a PowerShell literal, never interpolate raw metadata.
    prefix = """param(
 [ValidateSet('Preview','Stage','Verify','Rollback')][string]$Action='Preview',
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedManifestSha256,
 [ValidatePattern('^$|^[a-f0-9]{64}$')][string]$ConfirmationHash=''
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
"""
    literal = "'" + json.dumps(contract, ensure_ascii=True).replace("'", "''") + "'"
    if not include_activation:
        # Keep existing prepared bundles byte-identical on ordinary retry.
        script = prefix + "$contract=" + literal + "|ConvertFrom-Json\n" + INSTALL_SCRIPT
        if getattr(bundle, 'member_sid', None):
            from .member_tunnel_identity import member_installer, execution_installer
            script = (execution_installer(script, bundle.member_sid, bundle.member_owner_sid)
                if getattr(bundle, "member_owner_sid", None) else member_installer(script, bundle.member_sid))
        return script
    prefix = prefix.replace("'Verify','Rollback'", "'Verify','Rollback','PreviewActivation','Activate','ActivationStatus'")
    from .tunnel_activation import ACTIVATION_SCRIPT
    anchor = "if($Action -eq 'Preview'){"
    if INSTALL_SCRIPT.count(anchor) != 1:
        raise ValueError('task installation dispatch changed; activation needs review')
    body = INSTALL_SCRIPT.replace(anchor, ACTIVATION_SCRIPT + '\n' + anchor)
    script = prefix + "$contract=" + literal + "|ConvertFrom-Json\n" + body
    if getattr(bundle, 'member_sid', None):
        from .member_tunnel_identity import member_installer, execution_installer
        script = (execution_installer(script, bundle.member_sid, bundle.member_owner_sid)
            if getattr(bundle, "member_owner_sid", None) else member_installer(script, bundle.member_sid))
    return script


INSTALL_SCRIPT = r'''
function Hash-Bytes([byte[]]$Bytes){
 $hash=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
}
function Hash-Text([string]$Text){return Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($Text))}
function Assert-Unlinked([string]$Path){
 $p=[IO.Path]::GetFullPath($Path)
 while($p){
  if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked installation path forbidden'}}
  $p=[IO.Path]::GetDirectoryName($p)
 }
}
function Read-Bounded([string]$Path,[int]$Maximum=1048576){
 Assert-Unlinked $Path
 $file=Get-Item -LiteralPath $Path -Force
 if($file.PSIsContainer -or $file.Length -gt $Maximum){throw 'Invalid or oversized installation file'}
 $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  $buffer=New-Object byte[] ($Maximum+1);$count=0
  while($count -lt $buffer.Length){$n=$stream.Read($buffer,$count,$buffer.Length-$count);if($n -eq 0){break};$count+=$n}
  if($count -gt $Maximum){throw 'Installation file grew beyond bound'}
  $bytes=New-Object byte[] $count;[Array]::Copy($buffer,$bytes,$count);return ,$bytes
 }finally{$stream.Dispose()}
}
function Xml-Document([string]$Text){
 if($Text.Length -gt 131072 -or $Text -match '<!DOCTYPE|<!ENTITY'){throw 'Unsafe task XML'}
 $xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null;$xml.PreserveWhitespace=$false;$xml.LoadXml($Text)
 return ,$xml
}
function Canonical-Xml([string]$Text){
 $xml=Xml-Document $Text
 # Task Scheduler adds descriptive URI/author/date metadata. Do not discard
 # actions, triggers, principal, settings, ACLs or execution-related fields.
 foreach($name in @('URI','Author','Date')){
  $nodes=@($xml.SelectNodes("/*[local-name()='Task']/*[local-name()='RegistrationInfo']/*[local-name()='$name']"))
  foreach($node in $nodes){$null=$node.ParentNode.RemoveChild($node)}
 }
 return $xml.OuterXml
}
# RCN native task boundary begin
function Assert-InstallerAuthority {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if(-not $admin -and $identity.User.Value -ne 'S-1-5-18'){throw 'Elevated administrator required for task installation'}
}
function Assert-Protected([string]$Path){
 $allowed=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
 $acl=Get-Acl -LiteralPath $Path
 foreach($rule in $acl.Access){
  $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  $writeMask=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeMask) -and $sid -notin $allowed){throw 'Untrusted writer on installation path'}
 }
}
function Connect-TaskStore {
 $script:taskService=New-Object -ComObject 'Schedule.Service';$script:taskService.Connect()
 $script:taskFolder=$script:taskService.GetFolder('\')
}
function Normalize-Task([string]$Text){
 $definition=$script:taskService.NewTask(0);$definition.XmlText=$Text
 $definition.Principal.UserId='SYSTEM';$definition.Principal.LogonType=5
 return [string]$definition.XmlText
}
function Read-Task([string]$Name){
 try{$task=$script:taskFolder.GetTask($Name)}catch{
  $exception=$_.Exception
  while($exception){if($exception.HResult -eq -2147024894){return $null};$exception=$exception.InnerException}
  throw
 }
 return @{xml=[string]$task.Xml;state=[int]$task.State;enabled=[bool]$task.Enabled;sddl=[string]$task.GetSecurityDescriptor(7)}
}
function Write-Task([string]$Name,[string]$Text,[string]$Sddl){
 # CREATE_OR_UPDATE | DONT_ADD_PRINCIPAL_ACE | IGNORE_REGISTRATION_TRIGGERS.
 # Preserve reviewed task security explicitly rather than accepting new defaults.
 $null=$script:taskFolder.RegisterTask($Name,$Text,54,'SYSTEM',$null,5,$Sddl)
}
function Remove-Task([string]$Name){$script:taskFolder.DeleteTask($Name,0)}
# RCN native task boundary end

Assert-InstallerAuthority
$root=[string]$contract.root;$destination=[string]$contract.script_path
$directory=Split-Path -Parent $destination
foreach($path in @($PSScriptRoot,$root,$directory)){Assert-Unlinked $path}
$manifestPath=Join-Path $PSScriptRoot 'manifest.json'
$manifestBytes=Read-Bounded $manifestPath
if((Hash-Bytes $manifestBytes) -cne $ExpectedManifestSha256){throw 'Reviewed manifest SHA256 mismatch'}
$manifest=[Text.Encoding]::UTF8.GetString($manifestBytes)|ConvertFrom-Json
if($manifest.kind -cne 'coordinated-member-tunnel' -or $manifest.machine_id -cne $contract.machine_id -or $manifest.root_uuid -cne $contract.root_uuid){throw 'Bundle identity mismatch'}
$selfName='install-coordinated-tunnel.ps1'
if((Hash-Bytes (Read-Bounded $PSCommandPath)) -cne $manifest.files_sha256.$selfName){throw 'Installer hash mismatch'}
$payload=@{}
foreach($property in $contract.payload_hashes.PSObject.Properties){
 $bytes=Read-Bounded (Join-Path $PSScriptRoot $property.Name)
 if((Hash-Bytes $bytes) -cne $property.Value -or $manifest.files_sha256.($property.Name) -cne $property.Value){throw 'Bundle payload hash mismatch'}
 $payload[$property.Name]=$bytes
}
$rootMarkerPath=Join-Path $root '.rcn-root.json'
$rootMarker=[Text.Encoding]::UTF8.GetString((Read-Bounded $rootMarkerPath 65536))|ConvertFrom-Json
if($rootMarker.root_uuid -cne $contract.root_uuid -or $rootMarker.machine_id -cne $contract.machine_id){throw 'Managed root identity mismatch'}
if(-not(Test-Path -LiteralPath $directory -PathType Container)){throw 'Managed tunnel directory must be provisioned first'}
foreach($path in @($root,(Join-Path $root 'agent'),$directory,$rootMarkerPath)){Assert-Protected $path}
$journalPath=Join-Path $directory 'coordinated-install.json'
$lockPath=Join-Path $directory 'coordinated-install.lock'
foreach($path in @($destination,$journalPath,$lockPath)){
 Assert-Unlinked $path
 if(Test-Path -LiteralPath $path){Assert-Protected $path}
}
Connect-TaskStore
$names=@([string]$contract.guard_name,[string]$contract.request_name)
$desired=@{}
for($i=0;$i -lt 2;$i++){
 $filename=if($i -eq 0){'guard-task.xml'}else{'recovery-request-task.xml'}
 $xml=Xml-Document ([Text.Encoding]::Unicode.GetString($payload[$filename]).TrimStart([char]0xfeff))
 $settings=$xml.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Settings']")
 $enabled=$settings.SelectSingleNode("*[local-name()='Enabled']")
 if(-not $enabled){$enabled=$xml.CreateElement('Enabled',$xml.DocumentElement.NamespaceURI);$null=$settings.AppendChild($enabled)}
 $enabled.InnerText='false'
 $desired[$names[$i]]=Normalize-Task $xml.OuterXml
}
$newTaskSddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
function Task-Hash($Task){
 if($null -eq $Task){return 'absent'}
 if(-not $Task.sddl){throw 'Missing task security descriptor'}
 $security=[Security.AccessControl.RawSecurityDescriptor]::new([string]$Task.sddl)
 $sddl=$security.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
 return Hash-Text ((Canonical-Xml $Task.xml)+"`n"+$sddl)
}
function Candidate-Task([string]$Name,$Prior){
 $sddl=if($null -eq $Prior){$newTaskSddl}else{[string]$Prior.sddl}
 return @{xml=$desired[$Name];sddl=$sddl;state=1;enabled=$false}
}
function Assert-InactiveOwnedTask($Task){
 if($null -eq $Task){return}
 if($Task.enabled -or $Task.state -notin @(1,3)){throw 'Existing task must already be disabled and stopped through the maintenance gate'}
 $xml=Xml-Document $Task.xml
 if($xml.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Settings']/*[local-name()='Enabled']").InnerText -ne 'false'){throw 'Task XML must also be disabled'}
 $principals=@($xml.SelectNodes("/*[local-name()='Task']/*[local-name()='Principals']/*[local-name()='Principal']"))
 $actions=@($xml.SelectNodes("/*[local-name()='Task']/*[local-name()='Actions']/*"))
 $triggers=@($xml.SelectNodes("/*[local-name()='Task']/*[local-name()='Triggers']/*"))
 if($principals.Count -ne 1 -or $principals[0].UserId -notin @('SYSTEM','S-1-5-18') -or $actions.Count -ne 1 -or $actions[0].LocalName -ne 'Exec'){throw 'Existing task is not a managed SYSTEM transport task'}
 if(@($triggers|Where-Object {$_.LocalName -ne 'BootTrigger'}).Count){throw 'Unexpected task trigger'}
 if($actions[0].Command -notin @('powershell.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')){throw 'Unexpected task executable'}
 $legacy=Join-Path $directory 'reverse-ssh.ps1'
 $allowed=@(
  ('-NoProfile -ExecutionPolicy Bypass -File "'+$legacy+'"'),
  ('-NoProfile -ExecutionPolicy Bypass -File '+$legacy),
  ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$destination+'" -Action Run'),
  ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$destination+'" -Action RequestRecovery')
 )
 if([string]$actions[0].Arguments -cnotin $allowed){throw 'Existing task action is not the exact managed transport entry'}
}
function Assert-Quiescent {
 $statusPath=Join-Path $root 'agent\status.json'
 $status=[Text.Encoding]::UTF8.GetString((Read-Bounded $statusPath 65536))|ConvertFrom-Json
 if($status.machine_id -cne $contract.machine_id -or $status.root_uuid -cne $contract.root_uuid){throw 'Supervisor identity mismatch'}
 if([string]$status.updated_at -notmatch '(Z|[+-]\d\d:\d\d)$'){throw 'Supervisor observation lacks timezone'}
 $age=([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($status.updated_at)).TotalSeconds
 if($age -lt 0 -or $age -gt 45 -or ($status.max_concurrent_units -isnot [int] -and $status.max_concurrent_units -isnot [long]) -or $status.max_concurrent_units -ne 0 -or $status.active_run_ids -isnot [array] -or $status.active_run_ids.Count -ne 0){throw 'Fresh zero-capacity idle supervisor required'}
}
function Capture-Plan {
 Assert-Quiescent
 $before=@{};$hashes=@()
 foreach($name in $names){$task=Read-Task $name;Assert-InactiveOwnedTask $task;$before[$name]=$task;$hashes+=Task-Hash $task}
 $installed=if(Test-Path -LiteralPath $destination){Hash-Bytes (Read-Bounded $destination)}else{'absent'}
 if($installed -ne 'absent' -and $installed -cne $contract.payload_hashes.'managed-reverse-ssh.ps1'){throw 'Existing guard script differs; version migration needs separate review'}
 $markerHash=Hash-Bytes (Read-Bounded $rootMarkerPath)
 $identity=@($ExpectedManifestSha256,$markerHash,$contract.machine_id,$contract.root_uuid,$installed)+$hashes
 return @{hash=(Hash-Text ($identity|ConvertTo-Json -Compress));before=$before;script_before=$installed}
}
function Save-Journal($Record){
 $temporary=$journalPath+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
 try{
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 10))
  $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
  Move-Item -LiteralPath $temporary -Destination $journalPath -Force
 }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
function Read-Journal {
 if(-not(Test-Path -LiteralPath $journalPath)){return $null}
 $record=[Text.Encoding]::UTF8.GetString((Read-Bounded $journalPath 1048576))|ConvertFrom-Json
 if($record.schema_version -ne 1 -or $record.bundle_sha256 -cne $ExpectedManifestSha256 -or $record.root_uuid -cne $contract.root_uuid){throw 'Different or invalid pending installation journal; do not overwrite'}
 if($record.state -notin @('applying','staged','rolling-back','rollback-needed','rolled-back') -or
    $record.script_before -notin @('absent',$contract.payload_hashes.'managed-reverse-ssh.ps1') -or
    $null -eq $record.before -or @($record.before.PSObject.Properties).Count -ne 2){throw 'Incomplete installation journal; preserve for review'}
 foreach($name in $names){
  if($record.before.PSObject.Properties.Name -cnotcontains $name){throw 'Missing task snapshot in installation journal'}
  if($null -ne $record.before.$name){Assert-InactiveOwnedTask $record.before.$name;$null=Task-Hash $record.before.$name}
 }
 return $record
}
function Verify-Staged($Record) {
 if((Hash-Bytes (Read-Bounded $destination)) -cne $contract.payload_hashes.'managed-reverse-ssh.ps1'){throw 'Installed script verification failed'}
 foreach($name in $names){
  $task=Read-Task $name;Assert-InactiveOwnedTask $task
  if((Task-Hash $task) -cne (Task-Hash (Candidate-Task $name $Record.before.$name))){throw 'Registered disabled task or ACL verification failed'}
 }
}
function Verify-RolledBack($Record){
 foreach($name in $names){
  $task=Read-Task $name;Assert-InactiveOwnedTask $task
  if((Task-Hash $task) -cne (Task-Hash $Record.before.$name)){throw 'Recovered task snapshot changed'}
 }
 $hash=if(Test-Path -LiteralPath $destination){Hash-Bytes (Read-Bounded $destination)}else{'absent'}
 if($hash -cne $Record.script_before){throw 'Recovered script snapshot changed'}
}
function Rollback-Record($Record){
 # Inspect the entire rollback set first. Never overwrite a third party's
 # replacement, delete a foreign task or stop an already running process.
 foreach($name in $names){
  $task=Read-Task $name;Assert-InactiveOwnedTask $task
  $old=$Record.before.$name;Assert-InactiveOwnedTask $old
  if((Task-Hash $task) -notin @((Task-Hash $old),(Task-Hash (Candidate-Task $name $old)))){throw 'Rollback conflict: task differs from both snapshots'}
 }
 if(Test-Path -LiteralPath $destination){
  if((Hash-Bytes (Read-Bounded $destination)) -cne $contract.payload_hashes.'managed-reverse-ssh.ps1'){throw 'Rollback conflict: script changed'}
 }elseif($Record.script_before -ne 'absent'){throw 'Rollback conflict: original script is missing'}
 # Persist the transition BEFORE any compensation, including explicit rollback.
 # Process death must never leave partially restored tasks labelled staged.
 $Record.state='rolling-back';Save-Journal $Record
 foreach($name in $names){
  $task=Read-Task $name;$old=$Record.before.$name;Assert-InactiveOwnedTask $task
  if((Task-Hash $task) -notin @((Task-Hash $old),(Task-Hash (Candidate-Task $name $old)))){throw 'Rollback conflict during recovery'}
  if((Task-Hash $task) -ceq (Task-Hash $old)){continue}
  if($null -eq $old){Remove-Task $name}else{Write-Task $name $old.xml $old.sddl}
  if((Task-Hash (Read-Task $name)) -cne (Task-Hash $old)){throw 'Rollback readback failed'}
 }
 if($Record.script_before -eq 'absent' -and (Test-Path -LiteralPath $destination)){
  if((Hash-Bytes (Read-Bounded $destination)) -cne $contract.payload_hashes.'managed-reverse-ssh.ps1'){throw 'Rollback conflict: script changed'}
  Remove-Item -LiteralPath $destination -Force
 }
 Verify-RolledBack $Record
 $Record.state='rolled-back';Save-Journal $Record
}
if($Action -eq 'Preview'){
 $plan=Capture-Plan
 @{state='preview';confirmation_hash=$plan.hash;machine_id=$contract.machine_id;task_names=$names;installs_disabled=$true;activates=$false}|ConvertTo-Json -Compress
 exit 0
}
if($Action -eq 'Verify'){
 $record=Read-Journal
 if($null -eq $record){throw 'No installation journal'}
 if($record.state -eq 'staged'){Verify-Staged $record}
 if($record.state -eq 'rolled-back'){Verify-RolledBack $record}
 @{state=$record.state;machine_id=$contract.machine_id;activates=$false;rollback_confirmation_hash=(Hash-Bytes (Read-Bounded $journalPath))}|ConvertTo-Json -Compress
 exit 0
}
$lock=$null
try{
 $lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 $record=Read-Journal
 if($Action -eq 'Rollback'){
  if($null -eq $record -or $ConfirmationHash -cne (Hash-Bytes (Read-Bounded $journalPath))){throw 'Rollback journal confirmation mismatch'}
  try{Rollback-Record $record}catch{
   if($record.state -eq 'rolling-back'){$record.state='rollback-needed';Save-Journal $record}
   throw
  }
  @{state='rolled-back';activates=$false}|ConvertTo-Json -Compress;exit 0
 }
 if($record){
  if($record.state -eq 'staged'){Verify-Staged $record;@{state='staged';idempotent=$true;activates=$false}|ConvertTo-Json -Compress;exit 0}
  if($record.state -ne 'rolled-back'){throw 'Installation journal requires explicit recovery; no blind replay'}
  Verify-RolledBack $record
 }
 $plan=Capture-Plan
 if(-not $ConfirmationHash -or $ConfirmationHash -cne $plan.hash){throw 'Installation preview changed or confirmation missing'}
 if($record){
  # A completed rollback is not a permanent stop latch. Preserve its evidence,
  # then accept a freshly confirmed attempt without deleting the old journal.
  $history=Join-Path $directory ('coordinated-install-history-'+[Guid]::NewGuid().ToString('N')+'.json')
  [IO.File]::Copy($journalPath,$history,$false)
  if((Hash-Bytes (Read-Bounded $history)) -cne (Hash-Bytes (Read-Bounded $journalPath))){throw 'Journal archive verification failed'}
 }
 $record=[pscustomobject]@{schema_version=1;bundle_sha256=$ExpectedManifestSha256;root_uuid=$contract.root_uuid;state='applying';before=$plan.before;script_before=$plan.script_before}
 Save-Journal $record
 try{
  if($plan.script_before -eq 'absent'){
   $file=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$bytes=$payload['managed-reverse-ssh.ps1'];$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
  }
  foreach($name in $names){
   Assert-Quiescent
   $current=Read-Task $name;Assert-InactiveOwnedTask $current
   if((Task-Hash $current) -cne (Task-Hash $plan.before[$name])){throw 'Task changed after preview'}
   $candidate=Candidate-Task $name $plan.before[$name]
   Write-Task $name $candidate.xml $candidate.sddl
  }
  Verify-Staged $record;$record.state='staged';Save-Journal $record
 }catch{
  try{Rollback-Record $record}catch{$record.state='rollback-needed';Save-Journal $record;throw 'Install failed and rollback needs review; journal retained'}
  throw 'Install failed; disabled task snapshots restored; no task started'
 }
 @{state='staged';machine_id=$contract.machine_id;task_names=$names;activates=$false;next_gate='independent-heartbeat-and-legacy-session-migration'}|ConvertTo-Json -Compress
}finally{if($lock){$lock.Dispose()}}
'''
