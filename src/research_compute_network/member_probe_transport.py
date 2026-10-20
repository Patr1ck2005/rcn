"""Size-bounded read-only output collection for the two fixed member probes.

Paths are derived from the server-owned probe ID, not a Worker-supplied path.
Only four known output names can cross SSH. No recursive download, arbitrary
command, production cleanup or change to the sealed Worker protocol.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path, PureWindowsPath
import re

from . import member_registration as storage
from .member_worker_root_contract import canonical_root
from .schedulers.ssh import OpenSshTransport

OUTPUT_NAMES = {'artifact-manifest.json', 'safe-fake-result.json', 'result.json', 'project-worker-manifest.json'}
MAX_FILE_BYTES = 65536
MAX_WIRE_BYTES = 400000


def build_output_read(config, external_run_id: str) -> str:
    if not re.fullmatch(r'ssh-member-probe-[a-f0-9]{40}', external_run_id):
        raise ValueError('fixed_probe_id_required')
    for value in (config.machine_id, config.root_uuid):
        if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}',value):
            raise ValueError('fixed_probe_machine_identity_required')
    nonce=external_run_id.removeprefix('ssh-member-probe-')
    relative='runs/retained/success/compute-network-pilot/jp-'+nonce+'/up-'+nonce
    contract={'root':canonical_root(config.remote_root),'machine_id':config.machine_id,'root_uuid':config.root_uuid,
        'external':external_run_id,'job':'jp-'+nonce,'unit':'up-'+nonce,'relative':relative}
    literal="'"+json.dumps(contract,ensure_ascii=True).replace("'","''")+"'"
    return '$c='+literal+'|ConvertFrom-Json\n'+OUTPUT_SCRIPT


OUTPUT_SCRIPT=r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Read-Fixed([string]$Path){
 $p=[IO.Path]::GetFullPath($Path)
 while($p){
  $item=Get-Item -LiteralPath $p -Force
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked probe output forbidden'}
  $p=[IO.Path]::GetDirectoryName($p)
 }
 $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  if($file.Length -gt 65536){throw 'Probe output exceeds bound'}
  $buffer=New-Object byte[] ([int]$file.Length);$count=0
  while($count -lt $buffer.Length){$n=$file.Read($buffer,$count,$buffer.Length-$count);if($n -le 0){throw 'Incomplete output'};$count+=$n}
  return ,$buffer
 }finally{$file.Dispose()}
}
function Decode-Object([byte[]]$Bytes){return [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xfeff)|ConvertFrom-Json}
$marker=Decode-Object (Read-Fixed (Join-Path $c.root '.rcn-root.json'))
if($marker.machine_id -cne $c.machine_id -or $marker.root_uuid -cne $c.root_uuid){throw 'Root identity mismatch'}
$status=Decode-Object (Read-Fixed (Join-Path $c.root ('spool\status\'+$c.external+'.json')))
if($status.external_run_id -cne $c.external -or $status.machine_id -cne $c.machine_id -or
   $status.job_id -cne $c.job -or $status.work_unit_id -cne $c.unit -or $status.state -cne 'completed' -or
   ([string]$status.remote_relative_path).Replace('\','/') -cne $c.relative){throw 'Completed fixed output identity mismatch'}
$output=Join-Path (Join-Path $c.root $c.relative) 'output'
$result=[ordered]@{}
foreach($name in @('artifact-manifest.json','safe-fake-result.json','result.json','project-worker-manifest.json')){
 $path=Join-Path $output $name
 if(Test-Path -LiteralPath $path){$result[$name]=[Convert]::ToBase64String((Read-Fixed $path))}
}
if(-not $result.Contains('artifact-manifest.json')){throw 'Missing fixed result manifest'}
@{schema_version=1;external_run_id=$c.external;files=$result}|ConvertTo-Json -Depth 4 -Compress
'''


class MemberProbeTransport(OpenSshTransport):
    def download_outputs(self, external_run_id: str, destination: Path) -> None:
        completed=self._powershell(build_output_read(self.config,external_run_id),timeout=30)
        self._require_success(completed,'read bounded fixed-probe outputs')
        if len(completed.stdout.encode('utf-8'))>MAX_WIRE_BYTES:
            raise ValueError('fixed_probe_response_exceeds_bound')
        result=storage._json_document(completed.stdout.strip().encode('utf-8'))
        if (set(result)!={'schema_version','external_run_id','files'} or type(result['schema_version']) is not int
                or result['schema_version']!=1 or result['external_run_id']!=external_run_id
                or not isinstance(result['files'],dict) or not result['files']
                or not set(result['files']).issubset(OUTPUT_NAMES) or 'artifact-manifest.json' not in result['files']):
            raise ValueError('fixed_probe_output_response_invalid')
        decoded={}
        for name,value in result['files'].items():
            if not isinstance(value,str) or len(value)>90000:
                raise ValueError('fixed_probe_output_exceeds_bound')
            decoded[name]=base64.b64decode(value,validate=True)
            if len(decoded[name])>MAX_FILE_BYTES:
                raise ValueError('fixed_probe_output_exceeds_bound')
        destination=Path(destination).absolute()
        storage._unlinked(destination)
        if destination.exists():
            raise FileExistsError('fixed_probe_output_destination_exists')
        storage._private_directory(destination)
        for name,raw in decoded.items():
            storage._publish(destination/name,raw,maximum=MAX_FILE_BYTES)
