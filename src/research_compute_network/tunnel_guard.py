"""Self-contained Windows transport guard, outside the sealed Worker runtime.

Generated scripts require no installed RCN Python package. The process lifetime
Job owns the dedicated PowerShell wrapper before it launches children, closing
the create/attach orphan race without enumerating or killing unrelated PIDs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import PureWindowsPath

from .windows_advisory_state import ADVISORY_STATE_SCRIPT


def _literal(value: str) -> str:
    if any(ord(c) < 32 for c in value) or '"' in value:
        raise ValueError("transport configuration contains an unsafe character")
    return "'" + value.replace("'", "''") + "'"


def _host(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", value):
            raise ValueError("invalid coordinator host")
    return value


def build_guard_script(config, *, identity_file=None, known_hosts_file=None, allow_sshd_restart=False,
                       guard_task_name=None, require_remote_observation=False) -> str:
    if type(allow_sshd_restart) is not bool:
        raise ValueError("sshd recovery consent must be an explicit boolean")
    if type(require_remote_observation) is not bool:
        raise ValueError("remote observation requirement must be boolean")
    if guard_task_name is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,180}", guard_task_name):
        raise ValueError("unsafe guard task name")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", config.coordinator_user):
        raise ValueError("invalid coordinator user")
    if config.reverse_forward_host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("member reverse target must be loopback")
    root = PureWindowsPath(config.remote_root)
    if not root.is_absolute() or str(root) == root.anchor:
        raise ValueError("transport requires an explicit non-volume Windows root")
    target = "[::1]" if config.reverse_forward_host == "::1" else config.reverse_forward_host
    contract = {
        "machine": config.machine_id, "root": str(root),
        "host": _host(config.coordinator_host), "port": config.coordinator_port,
        "user": config.coordinator_user, "reverse_port": config.reverse_forward_port,
        "target": target, "identity_file": identity_file, "known_hosts_file": known_hosts_file,
        "allow_sshd_restart": allow_sshd_restart,
        "guard_task_name": guard_task_name, "require_remote_observation": require_remote_observation,
    }
    digest = hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest()
    values = [
        "param([ValidateSet('Run','Status','Stop','Resume','RequestRecovery')][string]$Action='Run')",
        "$ErrorActionPreference='Stop'", "$ProgressPreference='SilentlyContinue'",
        "$workerRoot=" + _literal(str(root)),
        "$guardRoot=" + _literal(str(root / "agent" / "transport")),
        "$observation=" + _literal(str(root / "agent" / "control-plane-observation.json")),
        "$knownHosts=" + (_literal(str(known_hosts_file)) if known_hosts_file else "(Join-Path $env:USERPROFILE '.ssh\\known_hosts')"),
        "$identity=" + (_literal(str(identity_file)) if identity_file else "$null"),
        "$coordinatorHost=" + _literal(config.coordinator_host),
        "$coordinatorPort=" + str(config.coordinator_port),
        "$coordinatorUser=" + _literal(config.coordinator_user),
        "$targetHost = " + _literal(config.reverse_forward_host), "$targetPort = 22",
        "$forward=" + _literal(f"localhost:{config.reverse_forward_port}:{target}:22"),
        "$configHash=" + _literal(digest),
        "$restartSshdAllowed=" + ("$true" if allow_sshd_restart else "$false"),
        "$guardTaskName=" + (_literal(guard_task_name) if guard_task_name else "$null"),
        "$requireRemoteObservation=" + ("$true" if require_remote_observation else "$false"),
        "$installedGuardScript=" + _literal(str(root / "agent" / "tunnel" / "managed-reverse-ssh.ps1")),
    ]
    return "\n".join(values) + "\n" + ADVISORY_STATE_SCRIPT + RECOVERY_SCRIPT


RECOVERY_SCRIPT = r'''# RCN recovery functions begin
function Get-RcnRetryDelay([int]$Failures, [int]$Jitter=0) {
    return [int][Math]::Min(60, [Math]::Pow(2,[Math]::Min(6,[Math]::Max(0,$Failures))) + [Math]::Max(0,[Math]::Min(3,$Jitter)))
}
function Test-RcnLocalSshBanner([int]$TimeoutMs=3000) {
    $client=[Net.Sockets.TcpClient]::new()
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try {
        $connect=$client.ConnectAsync($targetHost, $targetPort)
        if(-not $connect.Wait($TimeoutMs)){return $false}
        $stream=$client.GetStream();$buffer=New-Object byte[] 4;$read=0
        while($read -lt 4 -and $clock.ElapsedMilliseconds -lt $TimeoutMs){
            if($stream.DataAvailable){
                $n=$stream.Read($buffer,$read,4-$read)
                if($n -eq 0){return $false};$read+=$n
            }else{Start-Sleep -Milliseconds 25}
        }
        return $read -eq 4 -and [Text.Encoding]::ASCII.GetString($buffer) -eq 'SSH-'
    } catch {return $false} finally {$client.Dispose()}
}
function Get-RcnObservation([string]$Path,[DateTimeOffset]$Now,[DateTimeOffset]$GenerationStart) {
    $unknown=@{state='unknown';stamp=$null}
    try {
        if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return $unknown}
        $item=Get-Item -LiteralPath $Path
        if($item.Length -gt 65536 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){return $unknown}
        # Read a bounded snapshot and close the handle BEFORE JSON parsing.
        # Share deletion where supported; the sealed writer already retries
        # transient Windows rename failures, so no zero-contention claim is made.
        $buffer=New-Object char[] 65537
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true,4096,$true)
            try {
                $count=$reader.ReadBlock($buffer,0,$buffer.Length)
                if($count -gt 65536){return $unknown}
                $raw=[string]::new($buffer,0,$count)
            }finally{$reader.Dispose()}
        }finally{$stream.Dispose()}
        $seen=$raw|ConvertFrom-Json
        if([string]$seen.observed_at -notmatch '(Z|[+-]\d\d:\d\d)$'){return $unknown}
        $at=[DateTimeOffset]::Parse($seen.observed_at)
        $age=($Now-$at).TotalSeconds
        if($age -lt 0 -or $age -gt 45 -or $at -lt $GenerationStart){return $unknown}
        if($seen.transport_state -notin @('connected','disconnected')){return $unknown}
        return @{state=[string]$seen.transport_state;stamp=$at.ToUniversalTime().ToString('o')}
    } catch {return $unknown}
}
function Get-RcnRecoveryDecision([bool]$Stopped,[bool]$SecurityFailure,[int]$LocalFailures,[string]$Transport,[int]$TransportFailures,[bool]$FeedbackExpired=$false) {
    if($Stopped){return 'stop'}
    if($SecurityFailure){return 'blocked-security'}
    if($LocalFailures -ge 2){return 'replace-local-unhealthy'}
    if($Transport -eq 'disconnected' -and $TransportFailures -ge 2){return 'replace-transport-unhealthy'}
    if($FeedbackExpired){return 'replace-feedback-expired'}
    return 'observe'
}
function ConvertTo-RcnNativeArgument([string]$Value) {
    if($Value -match '["\r\n\x00]'){throw 'Unsafe native argument'}
    return '"' + [regex]::Replace($Value,'(\\+)$','$1$1') + '"'
}
function Assert-RcnUnlinkedPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    $item=$full
    while($item){
        if(Test-Path -LiteralPath $item){
            if((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked transport path forbidden'}
        }
        $item=[IO.Path]::GetDirectoryName($item)
    }
}
# RCN recovery functions end
if($MyInvocation.InvocationName -eq '.'){throw 'Transport guard must run in a dedicated PowerShell process'}
Assert-RcnUnlinkedPath $workerRoot
Assert-RcnUnlinkedPath $guardRoot
if(-not(Test-Path -LiteralPath $workerRoot -PathType Container)){throw 'Managed Worker root is missing'}
$statePath=Join-Path $guardRoot 'state.json'
$stopPath=Join-Path $guardRoot 'intentional-stop.marker'
$securityPath=Join-Path $guardRoot 'security-block.marker'
$lockPath=Join-Path $guardRoot 'guard.lock'
foreach($p in @($statePath,$stopPath,$securityPath,$lockPath)){Assert-RcnUnlinkedPath $p}
if($Action -eq 'Status'){
    if(Test-Path -LiteralPath $statePath){[IO.File]::ReadAllText($statePath)}else{'{"state":"not-started"}'}
    exit 0
}
New-Item -ItemType Directory -Force -Path $guardRoot|Out-Null
if($Action -eq 'Stop'){
    [IO.File]::WriteAllText($stopPath,'intentional-stop',[Text.UTF8Encoding]::new($false));exit 0
}
# The sealed supervisor's /End then /Run targets this short request task,
# never the separately registered long-lived guard. A request only ensures it
# is running; it cannot reset its recovery clock or clear safety/stop markers.
if($Action -eq 'RequestRecovery'){
    if(-not $guardTaskName){throw 'Coordinated guard task is not configured'}
    if((Test-Path -LiteralPath $stopPath) -or (Test-Path -LiteralPath $securityPath)){exit 0}
    $task=Get-ScheduledTask -TaskName $guardTaskName -TaskPath '\' -ErrorAction Stop
    $expectedArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$installedGuardScript+'" -Action Run'
    if($task.TaskName -cne $guardTaskName -or $task.TaskPath -ne '\' -or @($task.Actions).Count -ne 1 -or
       $task.Actions[0].Execute -ine (Join-Path $PSHOME 'powershell.exe') -or
       $task.Actions[0].Arguments -cne $expectedArgs -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18')){
        throw 'Registered guard identity or action differs from the approved bundle'
    }
    # No mailbox/temp file per request: interrupted request tasks leave no
    # durable command or orphan SSH child behind. The guard checks periodically.
    # Repeated requests preserve the running guard and its bounded recovery.
    if($task.State -ne 'Running'){Start-ScheduledTask -InputObject $task -ErrorAction Stop}
    exit 0
}
$lock=$null
try {$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
catch [IO.IOException] {if($Action -eq 'Resume'){throw 'Stop the active guard before explicit resume'};exit 0}
if($Action -eq 'Resume'){
    try {
        # Security and intentional stop are distinct. A normal resume never
        # clears a host-key/credential failure that needs reviewed re-provisioning.
        if(Test-Path -LiteralPath $securityPath){throw 'Security block requires reviewed credential or host-pin repair'}
        if(Test-Path -LiteralPath $stopPath){Remove-Item -LiteralPath $stopPath -Force}
    } finally {$lock.Dispose()}
    exit 0
}
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
public sealed class RcnTunnelLifetime {
    [StructLayout(LayoutKind.Sequential)] struct Basic {public long a,b;public uint flags;public UIntPtr c,d;public uint e;public UIntPtr f;public uint g,h;}
    [StructLayout(LayoutKind.Sequential)] struct IO {public ulong a,b,c,d,e,f;}
    [StructLayout(LayoutKind.Sequential)] struct Extended {public Basic basic;public IO io;public UIntPtr a,b,c,d;}
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr p,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr h,int c,IntPtr p,uint n);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr h,IntPtr p);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    IntPtr handle;
    public RcnTunnelLifetime() {
        handle=CreateJobObject(IntPtr.Zero,null);
        if(handle==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();
        var e=new Extended();e.basic.flags=0x2000;
        int size=Marshal.SizeOf(typeof(Extended));var p=Marshal.AllocHGlobal(size);
        try {Marshal.StructureToPtr(e,p,false);if(!SetInformationJobObject(handle,9,p,(uint)size)){
            int error=Marshal.GetLastWin32Error();CloseHandle(handle);handle=IntPtr.Zero;throw new System.ComponentModel.Win32Exception(error);
        }} finally {Marshal.FreeHGlobal(p);}
    }
    public void AttachCurrentProcess() {
        if(!AssignProcessToJobObject(handle,Process.GetCurrentProcess().Handle)){
            int error=Marshal.GetLastWin32Error();CloseHandle(handle);handle=IntPtr.Zero;throw new System.ComponentModel.Win32Exception(error);
        }
        // Deliberately process-lifetime, non-inheritable handle. Do NOT close
        // while the wrapper is alive. Windows closes it on every exit/crash,
        // killing this wrapper's children, including the spawn/attach window.
    }
}
public sealed class RcnTunnelChild : IDisposable {
    Process process;
    int securityFailure, bindFailure;
    public bool SecurityFailure {get {return Interlocked.CompareExchange(ref securityFailure,0,0)!=0;}}
    public bool BindFailure {get {return Interlocked.CompareExchange(ref bindFailure,0,0)!=0;}}
    public int Id {get {return process.Id;}}
    public bool HasExited {get {return process.HasExited;}}
    public int ExitCode {get {return process.ExitCode;}}
    public RcnTunnelChild(string executable,string arguments) {
        var info=new ProcessStartInfo(executable,arguments);
        info.UseShellExecute=false;info.CreateNoWindow=true;
        info.RedirectStandardInput=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;
        process=new Process();process.StartInfo=info;
        process.OutputDataReceived+=(s,e)=>{};
        process.ErrorDataReceived+=(s,e)=>{
            if(e.Data==null)return;
            if(Regex.IsMatch(e.Data,@"permission denied|bad permissions|unprotected private key|host key verification failed|remote host identification has changed",RegexOptions.IgnoreCase))Interlocked.Exchange(ref securityFailure,1);
            if(Regex.IsMatch(e.Data,@"remote port forwarding failed|cannot listen to port",RegexOptions.IgnoreCase))Interlocked.Exchange(ref bindFailure,1);
        };
        try {
            if(!process.Start())throw new InvalidOperationException("Child start failed");
            process.StandardInput.Close();process.BeginOutputReadLine();process.BeginErrorReadLine();
        }catch {Dispose();throw;}
    }
    public void Dispose() {
        if(process==null)return;
        try {
            if(!process.HasExited)process.Kill();
            if(!process.WaitForExit(5000))throw new TimeoutException("Owned child did not exit");
            // Wait for asynchronous readers after the process has exited.
            process.WaitForExit();
        }finally{process.Dispose();process=null;}
    }
}
'@
$child=$null
$record=[ordered]@{schema_version=1;config_sha256=$configHash;state='starting';wrapper_pid=$PID;ssh_pid=$null;generation=0;consecutive_failures=0;next_retry_at=$null;transport_verified_at=$null;local_ssh='unknown';last_reason=$null}
function Save-RcnState([string]$State) {
    $record.state=$State;$record.updated_at=[DateTimeOffset]::UtcNow.ToString('o')
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 4))
    $null=Write-RcnAdvisoryState $statePath $bytes
}
function Wait-RcnEnabled([int]$Seconds) {
    $wait=[Diagnostics.Stopwatch]::StartNew()
    while($wait.Elapsed.TotalSeconds -lt $Seconds){
        if((Test-Path -LiteralPath $stopPath) -or (Test-Path -LiteralPath $securityPath)){return $false}
        Start-Sleep -Milliseconds 250
    }
    return $true
}
try {
    $lifetime=[RcnTunnelLifetime]::new();$lifetime.AttachCurrentProcess()
    if(Test-Path -LiteralPath $securityPath){Save-RcnState 'blocked-security';exit 0}
    if(Test-Path -LiteralPath $stopPath){Save-RcnState 'intentionally-stopped';exit 0}
    Assert-RcnUnlinkedPath $knownHosts
    if(-not(Test-Path -LiteralPath $knownHosts -PathType Leaf)){throw 'Pinned known-hosts file unavailable'}
    if($identity){Assert-RcnUnlinkedPath $identity;if(-not(Test-Path -LiteralPath $identity -PathType Leaf)){throw 'SSH identity file unavailable'}}
    $ssh=Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if(-not(Test-Path -LiteralPath $ssh -PathType Leaf)){throw 'Windows OpenSSH client unavailable'}
    $sshArgs=@('-N','-T','-R',$forward,'-p',[string]$coordinatorPort,
        '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ExitOnForwardFailure=yes',
        '-o','StrictHostKeyChecking=yes','-o','ConnectionAttempts=1','-o','ConnectTimeout=5',
        '-o','TCPKeepAlive=yes','-o','IPQoS=none','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',
        '-o',('UserKnownHostsFile='+$knownHosts),'-o','ForwardAgent=no','-o','ForwardX11=no')
    if($identity){$sshArgs+=@('-i',$identity)}
    $sshArgs+=@('-l',$coordinatorUser,$coordinatorHost)
    $arguments=($sshArgs|ForEach-Object {ConvertTo-RcnNativeArgument $_}) -join ' '
    $failureCount=0
    while(-not(Test-Path -LiteralPath $stopPath)){
        $record.generation++;$record.transport_verified_at=$null;$record.next_retry_at=$null
        Save-RcnState 'connecting'
        $generationStart=[DateTimeOffset]::UtcNow
        $clock=[Diagnostics.Stopwatch]::StartNew();$nextProbe=0.0
        $localFailures=0;$transportFailures=0;$lastObservation=$null;$verifiedSince=$null;$lastConnectedClock=0.0
        $child=[RcnTunnelChild]::new($ssh,$arguments);$record.ssh_pid=$child.Id
        $decision='observe'
        while (-not $child.HasExited) {
            if(Test-Path -LiteralPath $stopPath){$decision='stop';break}
            if($child.SecurityFailure){$decision='blocked-security';break}
            if($clock.Elapsed.TotalSeconds -ge $nextProbe){
                $localOk=Test-RcnLocalSshBanner
                $localFailures=if($localOk){0}else{$localFailures+1}
                $record.local_ssh=if($localOk){'responding'}else{'unavailable'}
                $seen=Get-RcnObservation $observation ([DateTimeOffset]::UtcNow) $generationStart
                if($seen.stamp -and $seen.stamp -ne $lastObservation){
                    $transportFailures=if($seen.state -eq 'disconnected'){$transportFailures+1}else{0}
                    $lastObservation=$seen.stamp
                    if($seen.state -eq 'connected'){$lastConnectedClock=$clock.Elapsed.TotalSeconds}
                }
                $feedbackExpired=$requireRemoteObservation -and ($clock.Elapsed.TotalSeconds-$lastConnectedClock -ge 120)
                $decision=Get-RcnRecoveryDecision (Test-Path -LiteralPath $stopPath) $child.SecurityFailure $localFailures $seen.state $transportFailures $feedbackExpired
                if($decision -ne 'observe'){break}
                if($localOk -and $seen.state -eq 'connected'){
                    $record.transport_verified_at=$seen.stamp
                    if($null -eq $verifiedSince){$verifiedSince=$clock.Elapsed.TotalSeconds}
                    if($clock.Elapsed.TotalSeconds-$verifiedSince -ge 60){$failureCount=0}
                    Save-RcnState 'healthy'
                }else{
                    $verifiedSince=$null
                    Save-RcnState 'client-running-health-unverified'
                }
                $nextProbe=$clock.Elapsed.TotalSeconds+10
            }
            Start-Sleep -Milliseconds 250
        }
        # Readers flush during Dispose, so a fast host-key rejection cannot
        # disappear between HasExited and classification. Cache flags afterwards.
        $owned=$child;$child=$null
        $owned.Dispose();$securityFailure=$owned.SecurityFailure;$bindFailure=$owned.BindFailure
        $record.ssh_pid=$null;$record.last_reason=$decision
        if(Test-Path -LiteralPath $stopPath){break}
        if($securityFailure -or $decision -eq 'blocked-security'){
            [IO.File]::WriteAllText($securityPath,'security-failure-needs-reviewed-reprovision',[Text.UTF8Encoding]::new($false))
            Save-RcnState 'blocked-security';exit 0
        }
        if($decision -eq 'replace-local-unhealthy' -and $restartSshdAllowed){
            # Explicit generation-time owner consent only. Bounded fixed action;
            # never restart a service just because the center is unreachable.
            $serviceChild=[RcnTunnelChild]::new((Join-Path $PSHOME 'powershell.exe'),'-NoProfile -NonInteractive -Command "Restart-Service -Name ''sshd'' -Force -ErrorAction Stop"')
            try {
                $serviceClock=[Diagnostics.Stopwatch]::StartNew()
                while(-not $serviceChild.HasExited -and $serviceClock.Elapsed.TotalSeconds -lt 15){Start-Sleep -Milliseconds 250}
            }finally{$serviceChild.Dispose()}
        }
        $failureCount=[Math]::Min(6,$failureCount+1)
        $delay=Get-RcnRetryDelay $failureCount (Get-Random -Minimum 0 -Maximum 4)
        $record.consecutive_failures=$failureCount
        $record.last_reason=if($bindFailure){'reverse-bind-unavailable'}else{$decision}
        $record.next_retry_at=[DateTimeOffset]::UtcNow.AddSeconds($delay).ToString('o')
        Save-RcnState 'reconnect-backoff'
        if(-not(Wait-RcnEnabled $delay)){break}
    }
    $record.ssh_pid=$null;$record.next_retry_at=$null
    if(Test-Path -LiteralPath $securityPath){Save-RcnState 'blocked-security'}else{Save-RcnState 'intentionally-stopped'}
} catch {
    $record.last_reason=$_.Exception.GetType().Name
    $record.ssh_pid=$null
    Save-RcnState 'wrapper-error'
    exit 1
} finally {
    if($child){$child.Dispose()}
    if($lock){$lock.Dispose()}
    # The process-lifetime Job handle is closed by Windows, not manually here.
}
'''
