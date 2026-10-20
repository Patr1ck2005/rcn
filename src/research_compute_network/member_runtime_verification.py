"""Read-only whole-runtime verification against the originally approved archive.

Only center-selected archive bytes can supply the expected inventory. The remote
operation reads the registered root, never installs, starts, cancels or deletes.
A matching inventory is one acceptance check, not overall machine approval.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from uuid import uuid4

from . import member_registration as storage
from .member_admission import acceptance_execution_config_digest
from .member_runtime import approved_runtime, APPROVED_ARCHIVE_SHA256
from .member_worker_root_contract import canonical_root, root_uuid
from .runtime_policy import STABLE_RUNTIME_VERSION


class RuntimeVerificationUnavailable(RuntimeError):
    """Fixed public reason only; no remote stdout or secret is exposed."""


def inventory_digest(files: dict[str, bytes]) -> str:
    lines=[]
    for name,raw in sorted(files.items()):
        if not name.isascii() or any(ch in name for ch in '\x00\r\n'):
            raise ValueError('unsupported_runtime_inventory_name')
        lines.append(name+'\0'+str(len(raw))+'\0'+hashlib.sha256(raw).hexdigest()+'\n')
    return hashlib.sha256(''.join(lines).encode('ascii')).hexdigest()


# This program stays below the legacy Windows SSH command-length ceiling. It
# returns only bounded digests and identities, not a remotely selected file list.
READ_SCRIPT = r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function U($p){$a=[IO.Path]::GetFullPath($p);while($a){if((Get-Item -LiteralPath $a -Force).Attributes -band 1024){throw 'Linked runtime'};$a=[IO.Path]::GetDirectoryName($a)}}
function B($p){U $p;$f=[IO.File]::Open($p,3,1,1);try{if($f.Length -gt 262144){throw 'Large file'};$m=[IO.MemoryStream]::new();$f.CopyTo($m);return ,$m.ToArray()}finally{$f.Dispose()}}
function RH([byte[]]$b){$s=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($s.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function J($p){return [Text.Encoding]::UTF8.GetString((B $p)).TrimStart([char]0xfeff)|ConvertFrom-Json}
$marker=J (Join-Path $c.root '.rcn-root.json');$status=J (Join-Path $c.root 'agent\status.json')
if($marker.machine_id -cne $c.machine -or $marker.root_uuid -cne $c.uuid -or $status.machine_id -cne $c.machine -or $status.root_uuid -cne $c.uuid -or $status.runtime_version -cne $c.version){throw 'Identity mismatch'}
$base=Join-Path $c.root ('agent\versions\'+$c.version);U $base
$manifest=B (Join-Path $base 'runtime-manifest.json');if((RH $manifest) -cne $c.manifest){throw 'Manifest mismatch'}
$q=[Collections.Generic.Queue[string]]::new();$q.Enqueue($base)
$map=[Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal);$count=0;$size=0
while($q.Count){$d=$q.Dequeue();U $d;foreach($path in [IO.Directory]::EnumerateFileSystemEntries($d)){
$count++;if($count -gt 2048){throw 'Inventory bound'};$item=Get-Item -LiteralPath $path -Force;if($item.Attributes -band 1024){throw 'Linked inventory'}
if($item.PSIsContainer){$q.Enqueue($path);continue};$b=B $path;$size+=$b.Length;if($size -gt 33554432){throw 'Size bound'}
$n=$path.Substring($base.Length+1).Replace('\','/');$map.Add($n,($n+[char]0+[string]$b.Length+[char]0+(RH $b)+"`n"))
}}
$raw=[Text.Encoding]::UTF8.GetBytes([string]::Join('',@($map.Values)))
@{schema_version=1;nonce=$c.nonce;machine_id=$c.machine;root_uuid=$c.uuid;runtime_version=$c.version;manifest_sha256=(RH $manifest);inventory_sha256=(RH $raw);file_count=$map.Count;total_bytes=$size;supervisor_at=$status.updated_at}|ConvertTo-Json -Compress
"""


class MemberRuntimeVerifier:
    def __init__(self, archive: Path, *, release_descriptor=None):
        self.archive=Path(archive).absolute()
        self.files=approved_runtime(self.archive, release_descriptor=release_descriptor)
        from .member_release_catalog import approved_release_descriptor
        release=approved_release_descriptor(release_descriptor).require_configured()
        self.runtime_version=release.runtime_version
        self.archive_sha256=release.archive_sha256
        self.manifest_sha256=hashlib.sha256(self.files['runtime-manifest.json']).hexdigest()
        self.inventory_sha256=inventory_digest(self.files)
        self.total_bytes=sum(map(len,self.files.values()))

    def script(self, config, nonce: str) -> str:
        if (not re.fullmatch(r'[a-f0-9]{32}',nonce) or config.runtime_version!=self.runtime_version
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}',config.machine_id)):
            raise RuntimeVerificationUnavailable('runtime_verification_identity_invalid')
        context={'root':canonical_root(config.remote_root),'uuid':root_uuid(config.root_uuid),
            'machine':config.machine_id,'version':self.runtime_version,'nonce':nonce,'manifest':self.manifest_sha256}
        literal=storage._json_bytes(context).decode('ascii').strip().replace("'","''")
        script="$c='"+literal+"'|ConvertFrom-Json\n"+READ_SCRIPT
        # Fail before connecting instead of relying on remote command truncation.
        if len(base64.b64encode(script.encode('utf-16-le')))>7500:
            raise RuntimeVerificationUnavailable('runtime_verification_command_exceeds_bound')
        return script

    def verify(self, config, transport) -> dict:
        nonce=uuid4().hex
        script=self.script(config,nonce)
        try:
            result=transport._powershell(script,timeout=30)
            if result.returncode or len(result.stdout.encode('utf-8'))>4096:
                raise ValueError('unconfirmed remote inventory')
            value=storage._json_document(result.stdout.encode('utf-8'))
            fields={'schema_version','nonce','machine_id','root_uuid','runtime_version','manifest_sha256',
                    'inventory_sha256','file_count','total_bytes','supervisor_at'}
            if (set(value)!=fields or type(value['schema_version']) is not int or value['schema_version']!=1
                    or value['nonce']!=nonce or value['machine_id']!=config.machine_id or value['root_uuid']!=config.root_uuid
                    or value['runtime_version']!=self.runtime_version or value['manifest_sha256']!=self.manifest_sha256
                    or value['inventory_sha256']!=self.inventory_sha256 or type(value['file_count']) is not int
                    or value['file_count']!=len(self.files) or type(value['total_bytes']) is not int or value['total_bytes']!=self.total_bytes):
                raise ValueError('runtime inventory mismatch')
            at=datetime.fromisoformat(value['supervisor_at'].replace('Z','+00:00'))
            now=datetime.now(timezone.utc)
            if at.tzinfo is None or not 0<=(now-at).total_seconds()<=45:
                raise ValueError('runtime observation stale')
        except Exception:
            raise RuntimeVerificationUnavailable('member_runtime_verification_unconfirmed') from None
        return {**self.expected_evidence(config),'verified_at':now.isoformat()}

    def expected_evidence(self, config):
        return {'schema_version':1,'verification_kind':'sealed-runtime-inventory-v1','machine_id':config.machine_id,'root_uuid':config.root_uuid,
            'runtime_version':self.runtime_version,'approved_archive_sha256':self.archive_sha256,
            'inventory_sha256':self.inventory_sha256,'manifest_sha256':self.manifest_sha256,
            'file_count':len(self.files),'total_bytes':self.total_bytes,
            'execution_config_sha256':acceptance_execution_config_digest(config),'read_only':True}
