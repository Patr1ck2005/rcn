"""Fixed Windows root initialization preserving a previously established identity.

Used by the existing SSH acceptance harness. Never rewrites a marker, starts a
process, repairs an unknown directory, or replaces a running Worker instance.
"""
from __future__ import annotations

import json
import re
from uuid import uuid4

from .member_worker_root_contract import canonical_root

IDENTITY = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$')


def build_root_initialization(config) -> str:
    root = canonical_root(config.remote_root)
    if not IDENTITY.fullmatch(config.machine_id):
        raise ValueError('invalid root machine identity')
    if config.root_uuid is not None and not IDENTITY.fullmatch(config.root_uuid):
        raise ValueError('invalid existing root identity')
    contract = {'root': root, 'machine_id': config.machine_id,
                'expected_uuid': config.root_uuid, 'new_uuid': config.root_uuid or str(uuid4())}
    literal = "'" + json.dumps(contract, ensure_ascii=True).replace("'", "''") + "'"
    return "$contract=" + literal + "|ConvertFrom-Json\n" + ROOT_SCRIPT


ROOT_SCRIPT = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Assert-Path([string]$Path){
 $current=[IO.Path]::GetFullPath($Path)
 while($current){
  if(Test-Path -LiteralPath $current){
   if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked root path'}
  }
  $current=[IO.Path]::GetDirectoryName($current)
 }
}
function Read-Object([string]$Path){
 Assert-Path $Path
 $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  if($file.Length -gt 65536){throw 'Oversized root evidence'}
  $buffer=New-Object byte[] ([int]$file.Length);$count=0
  while($count -lt $buffer.Length){$read=$file.Read($buffer,$count,$buffer.Length-$count);if($read -le 0){throw 'Incomplete root evidence'};$count+=$read}
  return [Text.Encoding]::UTF8.GetString($buffer).TrimStart([char]0xfeff)|ConvertFrom-Json
 }finally{$file.Dispose()}
}
$root=[string]$contract.root;$markerPath=Join-Path $root '.rcn-root.json';$marker=$null
Assert-Path $root
if(Test-Path -LiteralPath $root){
 if(-not(Test-Path -LiteralPath $root -PathType Container)){throw 'Root is not a directory'}
 if(Test-Path -LiteralPath $markerPath){
  $marker=Read-Object $markerPath
  if(($marker.schema_version -isnot [int] -and $marker.schema_version -isnot [long]) -or $marker.schema_version -ne 1 -or
     $marker.machine_id -cne $contract.machine_id -or $marker.root_uuid -isnot [string] -or
     $marker.root_uuid -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$'){throw 'Root identity mismatch'}
  if($contract.expected_uuid -and $marker.root_uuid -cne $contract.expected_uuid){throw 'Configured root UUID mismatch'}
 }elseif(@(Get-ChildItem -LiteralPath $root -Force).Count -gt 0){throw 'Nonempty unmarked root'}
}else{
 if(-not(Test-Path -LiteralPath (Split-Path -Parent $root) -PathType Container)){throw 'Root parent unavailable'}
}
$relative=@('agent\versions','cache\objects','spool\incoming','spool\ready','spool\cancel','spool\status','runs\active','runs\retained\success','runs\retained\failed','logs','quarantine')
foreach($name in $relative){
 $destination=Join-Path $root $name;Assert-Path $destination
 if((Test-Path -LiteralPath $destination) -and -not(Test-Path -LiteralPath $destination -PathType Container)){throw 'Root child is not a directory'}
}
$statusPath=Join-Path $root 'agent\status.json'
if(Test-Path -LiteralPath $statusPath){
 $status=Read-Object $statusPath
 if($null -eq $marker -or $status.machine_id -cne $contract.machine_id -or $status.root_uuid -cne $marker.root_uuid -or
    $status.active_run_ids -isnot [array] -or $status.active_run_ids.Count -ne 0 -or
    ($status.max_concurrent_units -isnot [int] -and $status.max_concurrent_units -isnot [long]) -or $status.max_concurrent_units -ne 0 -or
    [string]$status.updated_at -notmatch '(Z|[+-]\d\d:\d\d)$'){throw 'Root runtime is not verifiably idle'}
 $age=([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($status.updated_at)).TotalSeconds
 if($age -lt 0 -or $age -gt 45){throw 'Root runtime evidence is stale'}
}elseif((Test-Path -LiteralPath (Join-Path $root 'runs\active')) -and
         @(Get-ChildItem -LiteralPath (Join-Path $root 'runs\active') -Force).Count -gt 0){
 throw 'Existing work requires reconciliation before initialization'
}
$created=$false
if($null -eq $marker){
 if(-not(Test-Path -LiteralPath $root)){$null=New-Item -ItemType Directory -Path $root}
 if(@(Get-ChildItem -LiteralPath $root -Force).Count -gt 0){throw 'Root changed before identity publication'}
 $marker=[ordered]@{schema_version=1;root_uuid=[string]$contract.new_uuid;machine_id=[string]$contract.machine_id;created_at=[DateTimeOffset]::UtcNow.ToString('o')}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($marker|ConvertTo-Json -Compress))
 $file=[IO.File]::Open($markerPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 $created=$true
}
foreach($name in $relative){
 $destination=Join-Path $root $name;Assert-Path $destination
 $null=New-Item -ItemType Directory -Force -Path $destination
}
$verified=Read-Object $markerPath
if($verified.root_uuid -cne $marker.root_uuid -or $verified.machine_id -cne $contract.machine_id){throw 'Root identity changed'}
@{schema_version=1;machine_id=$contract.machine_id;root_uuid=$verified.root_uuid;remote_root=$root;marker_created=$created}|ConvertTo-Json -Compress
'''
