"""Fixed read-only legacy-worker volume probe appended to the SSH status poll.

This conservatively covers default per-user COMSOL storage in addition to the
managed root and user temp volumes. It does not read COMSOL preferences, any
credentials or user file contents, nor claim to discover arbitrary custom paths.
"""
from pathlib import PureWindowsPath
import base64
import gzip


def supervisor_status_with_disk_probe(status_path: PureWindowsPath) -> str:
    path = str(status_path).replace("'", "''")
    root = str(status_path.parent.parent).replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue';\n"
        f"if (-not (Test-Path -LiteralPath '{path}')) {{ exit 44 }}\n"
        f"$diskStatus = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes('{path}')) | ConvertFrom-Json\n"
        f"$diskWorkRoot = '{root}'\n"
        + r'''
$diskProbe = [ordered]@{source='ssh-worker-default-volumes'; observed_at=[DateTime]::UtcNow.ToString('o'); available=$false; volumes=@(); reason_code='disk_probe_unavailable'}
try {
    # The login account must really own the supervisor; another user's TEMP
    # or profile is not evidence about this worker's write volumes.
    $diskProcessId = [int]$diskStatus.pid
    if ($diskProcessId -le 0) { throw 'identity unavailable' }
    $diskProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$diskProcessId"
    if (-not $diskProcess) { throw 'supervisor unavailable' }
    $diskOwner = Invoke-CimMethod -InputObject $diskProcess -MethodName GetOwnerSid
    if ($diskOwner.ReturnValue -ne 0 -or $diskOwner.Sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw 'identity mismatch' }
    $diskTargets = @(
        @{role='work_root'; path=$diskWorkRoot},
        @{role='temp'; path=$env:TEMP},
        @{role='tmp'; path=$env:TMP},
        @{role='comsol_user'; path=(Join-Path $env:USERPROFILE '.comsol')}
    )
    if ($env:COMSOL_TMPDIR) { $diskTargets += @{role='comsol_tmp'; path=$env:COMSOL_TMPDIR} }
    $diskVolumes = @()
    foreach ($diskTarget in $diskTargets) {
        if ([string]::IsNullOrWhiteSpace($diskTarget.path) -or $diskTarget.path -notmatch '^[A-Za-z]:[\\/]') { throw 'unsupported storage location' }
        $diskFull = [IO.Path]::GetFullPath($diskTarget.path)
        # Do not mistake a junction target for its enclosing drive.
        $diskAncestor = $diskFull
        while ($diskAncestor) {
            if (Test-Path -LiteralPath $diskAncestor) {
                $diskItem = Get-Item -LiteralPath $diskAncestor -Force
                if (($diskItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'redirected storage location' }
            }
            $diskParent = [IO.Directory]::GetParent($diskAncestor)
            if (-not $diskParent) { break }
            $diskAncestor = $diskParent.FullName
        }
        $diskDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($diskFull))
        if (-not $diskDrive.IsReady -or $diskDrive.DriveType -ne [IO.DriveType]::Fixed) { throw 'storage unavailable' }
        $diskVolumes += [ordered]@{role=$diskTarget.role; volume=$diskDrive.Name.Substring(0,2).ToUpperInvariant(); free_mb=[long][Math]::Floor($diskDrive.AvailableFreeSpace / 1MB)}
    }
    $diskProbe.volumes = $diskVolumes
    $diskProbe.available = $true
    $diskProbe.reason_code = ''
} catch {
    # Never serialize exception messages: they can contain private paths.
    $diskProbe.volumes = @()
}
if ($null -ne $diskStatus.metrics) {
    $diskStatus.metrics | Add-Member -NotePropertyName execution_disk -NotePropertyValue $diskProbe -Force
}
$diskJson = $diskStatus | ConvertTo-Json -Depth 30 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($diskJson))
'''
    )
    # Windows sshd commonly invokes cmd.exe with an 8191-character limit.
    # Encode the fixed, read-only probe compactly, without a remote script file.
    packed = base64.b64encode(gzip.compress(script.encode("utf-8"), mtime=0)).decode("ascii")
    return (
        f"$diskBytes=[Convert]::FromBase64String('{packed}');"
        "$diskStream=[IO.MemoryStream]::new([byte[]]$diskBytes);"
        "$diskZip=[IO.Compression.GZipStream]::new($diskStream,[IO.Compression.CompressionMode]::Decompress);"
        "$diskReader=[IO.StreamReader]::new($diskZip,[Text.Encoding]::UTF8);"
        "try { & ([scriptblock]::Create($diskReader.ReadToEnd())) } finally { $diskReader.Dispose() }"
    )
