"""Resumable activation of the exact staged transport pair, not compute admission.

Shares the installer's verified manifest, task XML/ACL and exclusive lock. Never
stops/replaces a live task, clears a stop marker, or retries an uncertain Run call.
Task Scheduler liveness is reported separately from actual SSH/heartbeat health.
"""
from __future__ import annotations


ACTIVATION_SCRIPT = r'''
# RCN activation native boundary begin
function Set-ActivationEnabled([string]$Name){
 $task=$script:taskFolder.GetTask($Name);$task.Enabled=$true
}
function Get-ActivationInstances([string]$Name){
 $task=$script:taskFolder.GetTask($Name)
 return @($task.GetInstances(0)|ForEach-Object {
  $_.Refresh();[pscustomobject]@{guid=[string]$_.InstanceGuid;state=[int]$_.State}
 })
}
function Start-ActivationGuard([string]$Name){
 $task=$script:taskFolder.GetTask($Name)
 $instance=$task.Run($null)
 return [string]$instance.InstanceGuid
}
function Get-LegacyTransportProcesses {
 $legacy=Join-Path $directory 'reverse-ssh.ps1';$managed=[string]$contract.script_path
 $target=if([string]$contract.reverse_forward_host -eq '::1'){'[::1]'}else{[string]$contract.reverse_forward_host}
 $forward='localhost:'+([string]$contract.reverse_forward_port)+':'+$target+':22'
 $all=@(Get-CimInstance Win32_Process);$byId=@{};foreach($p in $all){$byId[[int]$p.ProcessId]=$p}
 $result=@()
 foreach($p in $all){
  $cmd=[string]$p.CommandLine;if(-not $cmd){continue};$kind=$null
  if([string]$p.Name -ieq 'powershell.exe' -and $cmd.IndexOf($legacy,[StringComparison]::OrdinalIgnoreCase) -ge 0){$kind='legacy-wrapper'}
  elseif([string]$p.Name -ieq 'ssh.exe'){
   $parent=$byId[[int]$p.ParentProcessId];$parentCmd=if($parent){[string]$parent.CommandLine}else{''}
   if($parentCmd.IndexOf($managed,[StringComparison]::OrdinalIgnoreCase) -ge 0){continue}
   $parts=@($forward,[string]$contract.coordinator_host,[string]$contract.coordinator_user,
            [string]$contract.identity_file,[string]$contract.known_hosts_file)
   if(@($parts|Where-Object {$cmd.IndexOf($_,[StringComparison]::OrdinalIgnoreCase) -lt 0}).Count -eq 0){$kind='legacy-ssh'}
  }
  if($kind){
   $created=([DateTime]$p.CreationDate).ToUniversalTime().ToString('o')
   $commandHash=Hash-Text ($cmd.ToLowerInvariant())
   $identity=Hash-Text ($kind+'|'+[string]$p.ProcessId+'|'+[string]$p.ParentProcessId+'|'+$created+'|'+$commandHash)
   $result += [pscustomobject]@{pid=[int]$p.ProcessId;kind=$kind;created_at=$created;identity=$identity}
  }
 }
 return @($result|Sort-Object kind,pid)
}
function Stop-LegacyTransportProcess($Expected){
 $current=@(Get-LegacyTransportProcesses|Where-Object {$_.pid -eq [int]$Expected.pid})
 if($current.Count -ne 1 -or $current[0].identity -cne [string]$Expected.identity){throw 'Legacy transport process identity changed before retirement'}
 $process=[Diagnostics.Process]::GetProcessById([int]$Expected.pid)
 $started=$process.StartTime.ToUniversalTime().ToString('o')
 if($started -cne [string]$Expected.created_at){$process.Dispose();throw 'Legacy transport PID was reused'}
 try{$process.Kill();if(-not $process.WaitForExit(5000)){throw 'Legacy transport process did not exit'}}finally{$process.Dispose()}
}
# RCN activation native boundary end

function Activation-Task([string]$Name,$Prior,[bool]$Enabled){
 $candidate=Candidate-Task $Name $Prior
 $xml=Xml-Document $candidate.xml
 $xml.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Settings']/*[local-name()='Enabled']").InnerText=$Enabled.ToString().ToLowerInvariant()
 $candidate.xml=Normalize-Task $xml.OuterXml;$candidate.enabled=$Enabled
 return $candidate
}
function Assert-ActivationTask([string]$Name,$Stage){
 $task=Read-Task $Name
 if($null -eq $task -or $task.enabled -isnot [bool]){throw 'Activation task missing or invalid'}
 $expected=Activation-Task $Name $Stage.before.$Name ([bool]$task.enabled)
 if((Task-Hash $task) -cne (Task-Hash $expected)){throw 'Activation task definition or security changed'}
 $security=[Security.AccessControl.RawSecurityDescriptor]::new([string]$task.sddl)
 $allowed=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
 if($null -eq $security.DiscretionaryAcl -or $security.Owner.Value -notin $allowed){throw 'Activation task ACL is not protected'}
 foreach($ace in $security.DiscretionaryAcl){
  if($ace.AceType.ToString() -notin @('AccessAllowed','AccessDenied')){throw 'Unsupported activation task ACE'}
  if($ace.AceType.ToString() -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -notin $allowed -and
     ($ace.AccessMask -band (-bnot 0x120089))){throw 'Untrusted writer or executor on activation task'}
 }
 return $task
}
function Get-ActivationInputs {
 foreach($p in @($root,(Join-Path $root 'agent'),$directory,$destination,$rootMarkerPath,$journalPath)){Assert-Unlinked $p;Assert-Protected $p}
 $pins=@{}
 # The two exact literal references come from our hash-verified generated script,
 # never from an arbitrary command or a member-supplied activation request.
 $guard=[Text.Encoding]::UTF8.GetString((Read-Bounded $destination)).TrimStart([char]0xfeff)
 foreach($name in @('identity','knownHosts')){
  $pattern='(?m)^\$'+$name+"='((?:[^'\r\n]|'')*)'\r?$"
  $matches=[regex]::Matches($guard,$pattern)
  if($matches.Count -ne 1){throw 'Activation requires explicit protected transport files'}
  $p=$matches[0].Groups[1].Value.Replace("''", "'")
  if(-not [IO.Path]::GetFullPath($p).StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Transport file outside managed root'}
  Assert-Unlinked $p;Assert-Protected $p
  $parent=Split-Path -Parent $p
  while($parent -ne $root){Assert-Protected $parent;$parent=Split-Path -Parent $parent;if(-not $parent){throw 'Invalid transport ancestry'}}
  $pins[$name]=Hash-Bytes (Read-Bounded $p 65536)
 }
 $legacy=@(Get-LegacyTransportProcesses)
 return [ordered]@{installation_sha256=(Hash-Bytes (Read-Bounded $journalPath));root_sha256=(Hash-Bytes (Read-Bounded $rootMarkerPath));
  script_sha256=(Hash-Bytes (Read-Bounded $destination));identity_sha256=$pins.identity;known_hosts_sha256=$pins.knownHosts;
  legacy_processes=$legacy}
}
function Get-ActivationBlock {
 $transport=Join-Path $root 'agent\transport'
 foreach($name in @('intentional-stop.marker','security-block.marker')){
  $p=Join-Path $transport $name;Assert-Unlinked $p
  if(Test-Path -LiteralPath $p){return $name}
 }
 return $null
}
function Read-Activation {
 if(-not(Test-Path -LiteralPath $activationPath)){return $null}
 Assert-Protected $activationPath
 $value=[Text.Encoding]::UTF8.GetString((Read-Bounded $activationPath 65536))|ConvertFrom-Json
 $fields=@('schema_version','bundle_sha256','confirmation_hash','inputs','launch_requested','instance_guid','state','legacy_retirement_requested','legacy_retired_count')
 if(@($value.PSObject.Properties).Count -ne $fields.Count -or @($fields|Where-Object {$value.PSObject.Properties.Name -cnotcontains $_}).Count -or
    $value.schema_version -isnot [int] -or $value.schema_version -ne 1 -or $value.bundle_sha256 -cne $ExpectedManifestSha256 -or
    $value.launch_requested -isnot [bool] -or $value.legacy_retirement_requested -isnot [bool] -or
    $value.legacy_retired_count -isnot [int] -or $value.legacy_retired_count -lt 0 -or
    (-not $value.legacy_retirement_requested -and $value.legacy_retired_count -ne 0) -or
    $value.state -notin @('enabling','launch-requested') -or
    ($value.state -eq 'enabling' -and $value.launch_requested) -or ($value.state -eq 'launch-requested' -and -not $value.launch_requested) -or
    [string]$value.confirmation_hash -cnotmatch '^[a-f0-9]{64}$' -or ($value.instance_guid -and [string]$value.instance_guid -notmatch '^\{?[0-9a-fA-F-]{36}\}?$')){
  throw 'Invalid activation journal; preserve original operation'
 }
 return $value
}
function Save-Activation($Value){
 $temporary=$activationPath+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
 try{
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 6 -Compress))
  $f=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
  if([IO.File]::Exists($activationPath)){[IO.File]::Replace($temporary,$activationPath,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temporary,$activationPath)}
 }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
function Activation-Confirmation($Inputs){
 return Hash-Text (@($ExpectedManifestSha256,$contract.machine_id,$contract.root_uuid,($Inputs|ConvertTo-Json -Compress))|ConvertTo-Json -Compress)
}
function Legacy-Key($Value){
 if($null -eq $Value -or ($Value.pid -isnot [int] -and $Value.pid -isnot [long]) -or $Value.pid -le 0 -or
    [string]$Value.kind -notin @('legacy-wrapper','legacy-ssh') -or
    [string]$Value.created_at -notmatch '(Z|[+-]\d\d:\d\d)$' -or
    [string]$Value.identity -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid legacy transport process evidence'}
 return ([string]$Value.pid+'|'+[string]$Value.kind+'|'+[string]$Value.created_at+'|'+[string]$Value.identity)
}
function Assert-LegacySet($Saved,$Current,[bool]$AllowSubset){
 $expected=@{};foreach($item in @($Saved)){$key=Legacy-Key $item;if($expected.ContainsKey($key)){throw 'Duplicate legacy transport evidence'};$expected[$key]=$true}
 $seen=@{};foreach($item in @($Current)){$key=Legacy-Key $item;if(-not $expected.ContainsKey($key) -or $seen.ContainsKey($key)){throw 'Legacy transport process set changed'};$seen[$key]=$true}
 if(-not $AllowSubset -and $seen.Count -ne $expected.Count){throw 'Legacy transport process set changed'}
}
function Assert-ActivationInputs($Value,$Inputs){
 $fields=@('installation_sha256','root_sha256','script_sha256','identity_sha256','known_hosts_sha256','legacy_processes')
 $fixed=@('installation_sha256','root_sha256','script_sha256','identity_sha256','known_hosts_sha256')
 if(@($Value.inputs.PSObject.Properties).Count -ne $fields.Count -or
    @($fixed|Where-Object {[string]$Value.inputs.$_ -cne [string]$Inputs.$_}).Count){throw 'Activation inputs changed; no blind replay'}
 Assert-LegacySet @($Value.inputs.legacy_processes) @($Inputs.legacy_processes) ([bool]$Value.legacy_retirement_requested)
 if($Value.confirmation_hash -cne (Activation-Confirmation $Value.inputs)){throw 'Activation confirmation changed'}
}
function Retire-LegacyTransport($Value){
 $saved=@($Value.inputs.legacy_processes);Assert-LegacySet $saved @(Get-LegacyTransportProcesses) $true
 $ordered=@($saved|Where-Object {$_.kind -eq 'legacy-wrapper'})+@($saved|Where-Object {$_.kind -eq 'legacy-ssh'})
 foreach($expected in $ordered){
  $current=@(Get-LegacyTransportProcesses|Where-Object {$_.pid -eq [int]$expected.pid})
  if(-not $current.Count){continue}
  if($current.Count -ne 1 -or (Legacy-Key $current[0]) -cne (Legacy-Key $expected)){throw 'Legacy transport process changed during retirement'}
  Stop-LegacyTransportProcess $expected
 }
 $after=@(Get-LegacyTransportProcesses);Assert-LegacySet $saved $after $true
 if($after.Count){throw 'Verified legacy transport process remains after retirement'}
 return [int]$saved.Count
}
function Get-ActivationStatus($Value,$Stage){
 $enabled=$true
 foreach($name in $names){$task=Assert-ActivationTask $name $Stage;$enabled=$enabled -and $task.enabled}
 $instances=@(Get-ActivationInstances $contract.guard_name)
 if($instances.Count -gt 1){throw 'Multiple guard instances require review'}
 foreach($instance in $instances){
  if([string]$instance.guid -notmatch '^\{?[0-9a-fA-F-]{36}\}?$' -or $instance.state -notin @(2,4)){throw 'Invalid guard instance observation'}
 }
 $block=Get-ActivationBlock
 $state=if($block){'blocked-by-marker'}elseif(-not $enabled){'disabled-by-operator'}elseif($instances.Count -eq 1 -and $instances[0].state -eq 4){'task-running'}else{'awaiting-task-observation'}
 return @{state=$state;machine_id=$contract.machine_id;root_uuid=$contract.root_uuid;task_name=$contract.guard_name;
  task_enabled=[bool]$enabled;launch_requested=[bool]$Value.launch_requested;instance_guid=$(if($instances.Count){$instances[0].guid}else{$null});
  legacy_retired_count=[int]$Value.legacy_retired_count;transport_verified=$false;heartbeat_verified=$false;grants_execution=$false;stop_marker=$block}
}
if($Action -in @('PreviewActivation','Activate','ActivationStatus')){
 $activationPath=Join-Path $directory 'coordinated-activation.json'
 Assert-Unlinked $activationPath
 $activationLock=$null
 try{
  # Stage/Rollback and activation share the same lock and cannot race each other.
  $activationLock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  $stage=Read-Journal
  if($null -eq $stage -or $stage.state -ne 'staged'){throw 'Verified staged installation required before activation'}
  $inputs=Get-ActivationInputs
  if($inputs.script_sha256 -cne $contract.payload_hashes.'managed-reverse-ssh.ps1'){throw 'Installed activation script changed'}
  $record=Read-Activation
  if($record){Assert-ActivationInputs $record $inputs}
  if($Action -eq 'ActivationStatus'){
   if($null -eq $record){@{state='not-requested';grants_execution=$false;transport_verified=$false}|ConvertTo-Json -Compress;exit 0}
   Get-ActivationStatus $record $stage|ConvertTo-Json -Compress;exit 0
  }
  if($record -and $record.launch_requested){
   # This is observation, not permission to undo a subsequent operator pause.
   Get-ActivationStatus $record $stage|ConvertTo-Json -Compress;exit 0
  }
  if(Get-ActivationBlock){throw 'Stop or security marker blocks activation; marker preserved'}
  Assert-Quiescent
  foreach($name in $names){$null=Assert-ActivationTask $name $stage}
  if($Action -eq 'PreviewActivation'){
   if(-not $record){Verify-Staged $stage}
   $previewHash=if($record){[string]$record.confirmation_hash}else{Activation-Confirmation $inputs}
   @{state='activation-preview';confirmation_hash=$previewHash;machine_id=$contract.machine_id;
    root_uuid=$contract.root_uuid;task_names=$names;legacy_process_count=@($inputs.legacy_processes).Count;grants_execution=$false;transport_verified=$false}|ConvertTo-Json -Compress;exit 0
  }
  $requiredConfirmation=if($record){[string]$record.confirmation_hash}else{Activation-Confirmation $inputs}
  if(-not $ConfirmationHash -or $ConfirmationHash -cne $requiredConfirmation){throw 'Exact activation confirmation required'}
  if(-not $record){
   Verify-Staged $stage
   $record=[pscustomobject]@{schema_version=1;bundle_sha256=$ExpectedManifestSha256;confirmation_hash=$ConfirmationHash;
    inputs=$inputs;launch_requested=$false;instance_guid=$null;state='enabling';legacy_retirement_requested=$false;legacy_retired_count=0}
   Save-Activation $record
   # Read back the canonical saved shape before any OS mutation.
   $record=Read-Activation
  }
  if(-not $record.legacy_retirement_requested){$record.legacy_retirement_requested=$true;Save-Activation $record;$record=Read-Activation}
  Assert-ActivationInputs $record (Get-ActivationInputs)
  $retired=Retire-LegacyTransport $record
  if([int]$record.legacy_retired_count -ne $retired){$record.legacy_retired_count=$retired;Save-Activation $record;$record=Read-Activation}
  Assert-ActivationInputs $record (Get-ActivationInputs)
  foreach($name in @($contract.request_name,$contract.guard_name)){
   if(Get-ActivationBlock){throw 'Stop or security marker appeared during activation'}
   Assert-Quiescent;Assert-ActivationInputs $record (Get-ActivationInputs)
   $task=Assert-ActivationTask $name $stage
   if(-not $task.enabled){Set-ActivationEnabled $name}
   $task=Assert-ActivationTask $name $stage
   if(-not $task.enabled){throw 'Task enablement not confirmed'}
  }
  if(Get-ActivationBlock){throw 'Stop or security marker appeared before launch'}
  Assert-Quiescent;Assert-ActivationInputs $record (Get-ActivationInputs)
  $instances=@(Get-ActivationInstances $contract.guard_name)
  if($instances.Count -gt 1){throw 'Multiple guard instances require review'}
  $record.launch_requested=$true;$record.state='launch-requested';Save-Activation $record
  # Intent is durable BEFORE Run. On a lost response, subsequent calls inspect
  # the same task; they never invent a second Run or stop an unrelated instance.
  if($instances.Count -eq 1){$record.instance_guid=$instances[0].guid}else{$record.instance_guid=Start-ActivationGuard $contract.guard_name}
  Save-Activation $record
  Get-ActivationStatus $record $stage|ConvertTo-Json -Compress;exit 0
 }finally{if($activationLock){$activationLock.Dispose()}}
}
'''
