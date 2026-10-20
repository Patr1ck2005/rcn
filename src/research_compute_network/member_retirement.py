"""Fixed authenticated SSH read of member supervisor retirement evidence."""
from __future__ import annotations

from uuid import UUID

from . import member_registration as storage
from .member_bootstrap_transport import BootstrapSshTransport, COMMON, _contract, _script
from .member_release_catalog import release_for_runtime


class MemberRetirementTransport(BootstrapSshTransport):
    """Read one bound operation; never issue cancel, shell or account mutations."""
    def read_progress(self, operation_id):
        if str(UUID(operation_id)) != operation_id:
            raise ValueError('member_retirement_operation_invalid')
        release = release_for_runtime(self.config.runtime_version)
        if not release.owner_session_required:
            raise ValueError('member_retirement_release_required')
        contract = _contract(self.config, UUID(operation_id).hex)
        contract['operation_id'] = operation_id
        try:
            completed = self._powershell(_script(contract, READ_PROGRESS), timeout=30)
            if completed.returncode or len(completed.stdout.encode('utf-8')) > 4194304:
                raise ValueError('unconfirmed retirement reply')
            value = storage._json_document(completed.stdout.encode('utf-8'))
            if not isinstance(value, dict) or any(value.get(key) != expected for key, expected in {
                    'schema_version': 1, 'operation_id': operation_id,
                    'machine_id': self.config.machine_id, 'root_uuid': self.config.root_uuid,
                    'runtime_version': release.runtime_version}.items()):
                raise ValueError('changed retirement reply')
            return value
        except Exception:
            raise RuntimeError('member_retirement_remote_unconfirmed') from None


# Reuse the reviewed bounded readers, hash verifier and native process identity
# checks from bootstrap, but none of bootstrap's capacity changes or conditions.
_PROCESS_IDENTITY = COMMON.split('# RCN bootstrap native identity begin', 1)[1].split(
    '# RCN bootstrap native identity end', 1)[0]

READ_PROGRESS = r'''
$env:PSModulePath=(Join-Path $PSHOME 'Modules')
function Read-Retirement {
 $path=Join-Path $c.root 'agent\member-retirement.json'
 $item=Get-Item -LiteralPath $path -Force
 if($item.PSIsContainer -or $item.Length -gt 4194304){throw 'Large retirement receipt'}
 $ancestor=$item.FullName;while($ancestor){if((Get-Item -LiteralPath $ancestor -Force).Attributes -band 1024){throw 'Linked retirement receipt'};$ancestor=[IO.Path]::GetDirectoryName($ancestor)}
 $f=[IO.File]::Open($path,3,1,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
 try{$buffer=New-Object byte[] 4194305;$count=0;while($count -lt $buffer.Length){$n=$f.Read($buffer,$count,$buffer.Length-$count);if($n -eq 0){break};$count+=$n};if($count -gt 4194304){throw 'Retirement receipt grew'};return [Text.Encoding]::UTF8.GetString($buffer,0,$count)|ConvertFrom-Json}finally{$f.Dispose()}
}
$marker=Decode-Object (Read-Fixed (Join-Path $c.root '.rcn-root.json'))
$cfg=Decode-Object (Read-Fixed $configPath)
$status=Decode-Object (Read-Fixed (Join-Path $c.root 'agent\status.json'))
foreach($v in @($marker,$cfg,$status)){
 if($v.machine_id -cne $c.machine -or $v.root_uuid -cne $c.uuid){throw 'Retirement identity changed'}
}
if($cfg.remote_root -cne $c.root -or $cfg.python_executable -cne $c.python -or $cfg.runtime_version -cne $c.runtime -or $status.runtime_version -cne $c.runtime){throw 'Retirement runtime changed'}
$age=([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($status.updated_at)).TotalSeconds
if($age -lt -15 -or $age -gt 30 -or $status.pid -isnot [int] -or $status.pid -le 0){throw 'Retirement supervisor stale'}
$supervisor=Join-Path $c.root ('agent\versions\'+$c.runtime+'\remote-agent\supervisor.py')
if((Hash (Read-Fixed $supervisor)) -cne $c.supervisor_hash){throw 'Retirement supervisor changed'}
''' + _PROCESS_IDENTITY + r'''
$member=[IO.Path]::GetDirectoryName($c.root)
$binding=Decode-Object (Read-Fixed (Join-Path $member 'execution-identity.json'))
$control=Decode-Object (Read-Fixed (Join-Path $member 'owner-control\state.json'))
if($binding.root_uuid -cne $c.uuid -or $binding.worker_root -cne $c.root -or $binding.execution_sid -cne $sid -or $admin -or $control.root_uuid -cne $c.uuid -or $control.owner_sid -cne $binding.owner_sid -or $control.retired -isnot [bool] -or -not $control.retired -or $control.paused -isnot [bool] -or -not $control.paused -or $control.retirement_operation_id -cne $c.operation_id){throw 'Retirement owner condition changed'}
$progress=Read-Retirement
if($progress.schema_version -ne 1 -or $progress.machine_id -cne $c.machine -or $progress.root_uuid -cne $c.uuid -or $progress.runtime_version -cne $c.runtime -or $progress.operation_id -cne $c.operation_id){throw 'Retirement progress changed'}
$age=([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($progress.updated_at)).TotalSeconds
if($age -lt -15 -or $age -gt 30 -or $progress.active_run_ids -isnot [array] -or $progress.pending_run_ids -isnot [array] -or $progress.withdrawals -isnot [array]){throw 'Retirement progress stale'}
if((ConvertTo-Json -Compress @($progress.active_run_ids|Sort-Object)) -cne (ConvertTo-Json -Compress @($status.active_run_ids|Sort-Object))){throw 'Retirement heartbeat disagrees'}
$progress|ConvertTo-Json -Depth 10 -Compress
'''
